import os
import uuid
import hashlib
import json
import secrets
import base64
import io
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException

from app.models.user import User
from app.models.session import Session
from app.models.email_otp import EmailOTP, TOTPPending
from app.models.totp_backup_code import TOTPBackupCode
from app.models.password_reset_token import PasswordResetToken
from app.security.hmac_impl import hmac_sha256
from app.security.pbkdf2 import PBKDF2
from app.security.aes import AESCBC
from app.security.rsa_impl import RSAImpl
from app.security.totp import TOTP, generate_backup_codes
from app.security.jwt_handler import JWTHandler
from app.security.crypto_utils import encode_iv_ct, decode_iv_ct, secure_random_hex, constant_time_compare
from app.services.email_service import EmailService
from app.config import settings
from app.utils.validation import InputValidator, ValidationError


class AuthService:
    """Handles all the authentication-related business logic.
    
    This is where we handle user registration, login, password resets,
    TOTP setup, and all that security-related stuff. The crypto operations
    happen here, but the actual crypto implementations are in the security folder.
    """
    def __init__(self, db: AsyncSession):
        self.db = db
        self.jwt_handler = JWTHandler(settings.JWT_SECRET)
        self.server_key = settings.server_master_key_bytes

    # ── User Registration ──────────────────────────────────────────────

    async def register_user(
        self, full_name: str, email: str, password: str, ip_hmac: str, user_agent: str
    ):
        """Register a new user account.
        
        This does several security things:
        1. Validates and normalizes input
        2. Hashes the password with PBKDF2 (so we never store the actual password)
        3. Generates a vault key for encrypting the user's private RSA key
        4. Creates an RSA keypair for digital signatures
        5. Sends an email verification code
        """
        # Validate inputs
        email_lower = InputValidator.validate_email(email)
        validated_name = InputValidator.validate_full_name(full_name)
        validated_password = InputValidator.validate_password(password)

        existing = (
            await self.db.execute(select(User).where(User.email == email_lower))
        ).scalars().first()
        if existing:
            raise HTTPException(400, "An account with this email already exists")

        password_salt = os.urandom(32)
        key_salt = os.urandom(32)

        # Hash the password - we store the hash, not the password itself
        password_hash = PBKDF2(password.encode(), password_salt, settings.PBKDF2_ITERATIONS, 32).derive().hex()
        # Derive a vault key from the password for encrypting the RSA private key
        vault_key = PBKDF2(password.encode(), key_salt, settings.PBKDF2_OTP_ITERATIONS, 32).derive()

        # Generate RSA keypair for digital signatures
        public_key, private_key = RSAImpl.generate_keypair(settings.RSA_KEY_SIZE)
        # Encrypt the private key with the vault key
        iv, enc_priv = RSAImpl.encrypt_private_key(private_key, vault_key)

        new_user = User(
            id=uuid.uuid4(),
            full_name=validated_name,
            email=email_lower,
            password_hash=password_hash,
            password_salt=password_salt.hex(),
            key_salt=key_salt.hex(),
            rsa_public_key=json.dumps(public_key),
            rsa_private_enc=encode_iv_ct(iv, enc_priv),
        )
        self.db.add(new_user)
        await self.db.flush()

        # OTP for email verification; single commit
        otp = f"{secrets.randbelow(1_000_000):06d}"
        otp_hash = PBKDF2(otp.encode(), str(new_user.id).encode(), settings.PBKDF2_OTP_ITERATIONS, 32).derive().hex()
        self.db.add(
            EmailOTP(
                user_id=new_user.id,
                otp_hash=otp_hash,
                purpose="verify",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.EMAIL_OTP_EXPIRE_HOURS),
            )
        )
        await self.db.commit()

        # Send the verification code via email
        await EmailService.send_email(
            email_lower,
            "AegisVault: Verify your email",
            f"Your AegisVault verification code is {otp}. It expires in 24 hours.",
        )

        return {
            "success": True,
            "message": "Account created. Please check your email for a verification code.",
        }

    # ── User Login (step 1: email + password) ───────────────────────────

    async def login_step1(self, email: str, password: str, ip_hmac: str, user_agent: str):
        """First step of login - verify email and password.
        
        If the password is correct and TOTP is enabled, we return a partial token
        that gets used in step 2 with the TOTP code. If TOTP isn't enabled,
        we go straight to issuing the full session token.
        """
        email_lower = email.strip().lower()
        user = (
            await self.db.execute(select(User).where(User.email == email_lower))
        ).scalars().first()

        # We always do the password hash computation to prevent timing attacks
        # (even if the user doesn't exist, we still compute a hash)
        dummy_salt = os.urandom(32)
        target_hash = bytes.fromhex(user.password_hash) if user else os.urandom(32)
        salt_to_use = bytes.fromhex(user.password_salt) if user else dummy_salt

        computed_hash = PBKDF2(password.encode(), salt_to_use, settings.PBKDF2_ITERATIONS, 32).derive()
        is_valid = constant_time_compare(computed_hash, target_hash) if user else False

        if not user or not is_valid:
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(hours=settings.ACCOUNT_LOCKOUT_HOURS)
                await self.db.commit()
            raise HTTPException(401, "Invalid credentials")

        if user.locked_until and user.locked_until.tzinfo is None:
            user.locked_until = user.locked_until.replace(tzinfo=timezone.utc)

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise HTTPException(401, "Account locked. Try again later.")

        if not user.email_verified:
            raise HTTPException(403, "Please verify your email before logging in")

        user.failed_attempts = 0

        if user.totp_enabled:
            jti = secure_random_hex(8)
            pending = TOTPPending(
                user_id=user.id,
                token_jti=jti,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.PARTIAL_TOKEN_EXPIRE_SECONDS),
            )
            self.db.add(pending)
            await self.db.commit()

            partial_token = self.jwt_handler.encode(
                {"sub": str(user.id), "jti": jti, "type": "partial"}, settings.PARTIAL_TOKEN_EXPIRE_SECONDS
            )
            return {"totp_required": True, "partial_token": partial_token}

        return await self._generate_session(user, ip_hmac, user_agent)

    # ── Login step 2 (TOTP verification) ──────────────────────────

    async def login_step2(self, partial_token: str, code: str, vault_key: bytes, ip_hmac: str, user_agent: str):
        try:
            payload = self.jwt_handler.decode(partial_token)
            if payload.get("type") != "partial":
                raise ValueError()
        except Exception:
            raise HTTPException(401, "Invalid token")

        pending = (
            await self.db.execute(
                select(TOTPPending).where(TOTPPending.token_jti == payload["jti"])
            )
        ).scalars().first()
        if not pending or pending.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(401, "Token expired")

        user = (
            await self.db.execute(select(User).where(User.id == pending.user_id))
        ).scalars().first()

        secret = self._decrypt_totp_secret(user, vault_key)
        # First try the standard TOTP verification
        if TOTP(secret).verify(code):
            await self.db.delete(pending)
            return await self._generate_session(user, ip_hmac, user_agent)

        # If TOTP failed, check one-time backup codes stored hashed in DB
        computed = PBKDF2(code.encode(), str(user.id).encode(), settings.PBKDF2_OTP_ITERATIONS, 32).derive()
        backup_record = (
            await self.db.execute(
                select(TOTPBackupCode).where(
                    TOTPBackupCode.user_id == user.id,
                    TOTPBackupCode.used.is_(False),
                )
            )
        ).scalars().all()

        matched = None
        for br in backup_record:
            try:
                if constant_time_compare(bytes.fromhex(br.code_hash), computed):
                    matched = br
                    break
            except Exception:
                continue

        if matched:
            # consume code and allow login
            matched.used = True
            await self.db.delete(pending)
            await self.db.commit()
            return await self._generate_session(user, ip_hmac, user_agent)

        raise HTTPException(401, "Invalid TOTP code or backup code")

    # ── Backup code verification for login (standalone) ──────────────────────────

    async def verify_backup_code_login(self, partial_token: str, backup_code: str, ip_hmac: str, user_agent: str):
        """Verify a backup code during login as an alternative to TOTP.
        
        This allows users to log in if they lose their authenticator device
        by using one of their pre-generated backup codes.
        """
        try:
            payload = self.jwt_handler.decode(partial_token)
            if payload.get("type") != "partial":
                raise ValueError()
        except Exception:
            raise HTTPException(401, "Invalid token")

        pending = (
            await self.db.execute(
                select(TOTPPending).where(TOTPPending.token_jti == payload["jti"])
            )
        ).scalars().first()
        if not pending or pending.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(401, "Token expired")

        user = (
            await self.db.execute(select(User).where(User.id == pending.user_id))
        ).scalars().first()

        # Hash the provided backup code and compare with stored hashes
        computed = PBKDF2(backup_code.encode(), str(user.id).encode(), settings.PBKDF2_OTP_ITERATIONS, 32).derive()
        backup_record = (
            await self.db.execute(
                select(TOTPBackupCode).where(
                    TOTPBackupCode.user_id == user.id,
                    TOTPBackupCode.used.is_(False),
                )
            )
        ).scalars().all()

        matched = None
        for br in backup_record:
            try:
                if constant_time_compare(bytes.fromhex(br.code_hash), computed):
                    matched = br
                    break
            except Exception:
                continue

        if matched:
            # consume the backup code (one-time use)
            matched.used = True
            await self.db.delete(pending)
            await self.db.commit()
            return await self._generate_session(user, ip_hmac, user_agent)

        raise HTTPException(401, "Invalid backup code")

    # ── Email verification ────────────────────────────────────────

    async def verify_email(self, email: str, code: str, ip_hmac: str, user_agent: str):
        email_lower = email.strip().lower()
        user = (
            await self.db.execute(select(User).where(User.email == email_lower))
        ).scalars().first()
        if not user:
            raise HTTPException(404, "User not found")

        if user.email_verified:
            return {"success": True, "message": "Email already verified"}

        otp_record = (
            await self.db.execute(
                select(EmailOTP).where(
                    EmailOTP.user_id == user.id,
                    EmailOTP.purpose == "verify",
                    EmailOTP.used_at.is_(None),
                )
            )
        ).scalars().first()

        if not otp_record:
            raise HTTPException(400, "No verification code found. Please request a new one.")

        if otp_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(400, "Verification code expired")

        otp_hash = PBKDF2(code.encode(), str(user.id).encode(), settings.PBKDF2_OTP_ITERATIONS, 32).derive().hex()
        if not constant_time_compare(bytes.fromhex(otp_hash), bytes.fromhex(otp_record.otp_hash)):
            otp_record.attempts += 1
            if otp_record.attempts >= settings.MAX_OTP_ATTEMPTS:
                await self.db.delete(otp_record)
            await self.db.commit()
            raise HTTPException(400, "Invalid verification code")

        otp_record.used_at = datetime.now(timezone.utc)
        user.email_verified = True
        await self.db.commit()

        return {"success": True, "message": "Email verified successfully"}

    # ── Resend verification OTP ───────────────────────────────────

    async def resend_verification_otp(self, email: str):
        email_lower = email.strip().lower()
        user = (
            await self.db.execute(select(User).where(User.email == email_lower))
        ).scalars().first()
        if not user:
            # Don't reveal whether the email exists
            return {"success": True, "message": "If the account exists, a new code has been sent."}

        if user.email_verified:
            return {"success": True, "message": "Email is already verified. You can log in."}

        # Invalidate any existing unused OTPs
        old_otps = (
            await self.db.execute(
                select(EmailOTP).where(
                    EmailOTP.user_id == user.id,
                    EmailOTP.purpose == "verify",
                    EmailOTP.used_at.is_(None),
                )
            )
        ).scalars().all()
        for old in old_otps:
            await self.db.delete(old)

        # Generate new OTP
        otp = f"{secrets.randbelow(1_000_000):06d}"
        otp_hash = PBKDF2(otp.encode(), str(user.id).encode(), settings.PBKDF2_OTP_ITERATIONS, 32).derive().hex()
        self.db.add(
            EmailOTP(
                user_id=user.id,
                otp_hash=otp_hash,
                purpose="verify",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.EMAIL_OTP_EXPIRE_HOURS),
            )
        )
        await self.db.commit()

        await EmailService.send_email(
            email_lower,
            "AegisVault: Verify your email",
            f"Your AegisVault verification code is {otp}. It expires in 24 hours.",
        )

        return {"success": True, "message": "If the account exists, a new code has been sent."}

    # Password reset: request

    async def request_password_reset(self, email: str, ip_hmac: str, user_agent: str):
        email_lower = email.strip().lower()
        user = (
            await self.db.execute(select(User).where(User.email == email_lower))
        ).scalars().first()

        if user:
            raw_token = secrets.token_urlsafe(32)
            # The reset token is high-entropy random data generated with
            # `secrets.token_urlsafe`. Using a fast hash (SHA-256) here to
            # store a fingerprint is acceptable.
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

            self.db.add(
                PasswordResetToken(
                    user_id=user.id,
                    token_hash=token_hash,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
                )
            )
            await self.db.commit()

            await EmailService.send_email(
                email_lower,
                "AegisVault: Password Reset",
                f"Your password reset token is: {raw_token}\n\nIt expires in 15 minutes.",
            )

        return {"success": True, "message": "If the email exists, a reset link has been sent"}

    # Password reset: complete

    async def complete_password_reset(
        self, token: str, new_password: str, ip_hmac: str, user_agent: str
    ):
        validated_password = InputValidator.validate_password(new_password)
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        reset = (
            await self.db.execute(
                select(PasswordResetToken).where(
                    PasswordResetToken.token_hash == token_hash,
                    PasswordResetToken.used.is_(False),
                )
            )
        ).scalars().first()
        if not reset or reset.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(400, "Invalid or expired reset token")

        user = (
            await self.db.execute(select(User).where(User.id == reset.user_id))
        ).scalars().first()
        if not user:
            raise HTTPException(400, "Invalid reset token")

        # Only update password; preserve existing RSA keys
        password_salt = os.urandom(32)
        user.password_hash = PBKDF2(validated_password.encode(), password_salt, settings.PBKDF2_ITERATIONS, 32).derive().hex()
        user.password_salt = password_salt.hex()

        reset.used = True

        # Invalidate all other reset tokens for this user
        all_tokens = (
            await self.db.execute(
                select(PasswordResetToken).where(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.used.is_(False),
                )
            )
        ).scalars().all()
        for t in all_tokens:
            t.used = True

        await self.db.commit()
        return {"success": True, "message": "Password has been reset successfully."}

    # ── TOTP setup & enable ───────────────────────────────────────

    async def setup_totp(self, user: User, vault_key: bytes):
        import qrcode

        totp = TOTP()
        # Encrypt TOTP secret with user's vault key for better security isolation
        # This way, even if server master key is compromised, TOTP secrets remain protected
        iv, ct = AESCBC(vault_key).encrypt(totp.secret_base32.encode())
        user.totp_secret_enc = encode_iv_ct(iv, ct)
        user.totp_enabled = False
        await self.db.commit()

        uri = totp.generate_uri(user.email)
        image = qrcode.make(uri)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        qr_data_url = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
        return {
            "success": True,
            "secret": totp.secret_base32,
            "otpauth_uri": uri,
            "qr_code_data_url": qr_data_url,
        }

    async def enable_totp(self, user: User, code: str, vault_key: bytes, ip_hmac: str, user_agent: str):
        if not user.totp_secret_enc:
            raise HTTPException(400, "TOTP setup has not been started")
        secret = self._decrypt_totp_secret(user, vault_key)
        if not TOTP(secret).verify(code):
            raise HTTPException(401, "Invalid TOTP code")
        user.totp_enabled = True
        # Persist one-time backup codes and return plaintext list for the user to store
        codes = generate_backup_codes()
        for c in codes:
            code_hash = PBKDF2(c.encode(), str(user.id).encode(), settings.PBKDF2_OTP_ITERATIONS, 32).derive().hex()
            self.db.add(TOTPBackupCode(user_id=user.id, code_hash=code_hash))
        await self.db.commit()
        return {"success": True, "message": "TOTP enabled successfully", "backup_codes": codes}

    # ── Step-up token ─────────────────────────────────────────────

    async def issue_step_up_token(
        self, user: User, request_id: str, action_type: str, code: str, vault_key: bytes, ip_hmac: str, user_agent: str
    ):
        if not user.totp_enabled:
            raise HTTPException(403, "TOTP must be enabled for step-up verification")
        secret = self._decrypt_totp_secret(user, vault_key)
        if not TOTP(secret).verify(code):
            raise HTTPException(401, "Invalid TOTP code")
        token = self.jwt_handler.encode(
            {
                "sub": str(user.id),
                "type": "step_up",
                "request_id": str(request_id),
                "action_type": action_type,
                "jti": secure_random_hex(8),
            },
            settings.STEP_UP_TOKEN_EXPIRE_SECONDS,
        )
        await self.db.commit()
        return {"success": True, "step_up_token": token, "expires_in": 300}

    # ── Session management ────────────────────────────────────────

    async def refresh_session(self, refresh_token: str, ip_hmac: str, user_agent: str):
        refresh_hmac = hmac_sha256(self.server_key, refresh_token.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        session = (
            await self.db.execute(
                select(Session).where(
                    Session.refresh_token_hmac == refresh_hmac,
                    Session.revoked_at.is_(None),
                    Session.expires_at >= now,
                )
            )
        ).scalars().first()
        if not session:
            raise HTTPException(401, "Invalid refresh token")
        user = (
            await self.db.execute(select(User).where(User.id == session.user_id))
        ).scalars().first()
        if not user:
            raise HTTPException(401, "User not found")
        session.last_active_at = now
        access_token = self.jwt_handler.encode(
            {"sub": str(user.id), "sid": str(session.id), "type": "access"}, settings.ACCESS_TOKEN_EXPIRE_SECONDS
        )
        await self.db.commit()
        return {"success": True, "access_token": access_token}

    async def logout_session(self, user: User, session_id: str | None, ip_hmac: str, user_agent: str):
        if not session_id:
            return {"success": True}
        session = (
            await self.db.execute(
                select(Session).where(Session.id == uuid.UUID(session_id), Session.user_id == user.id)
            )
        ).scalars().first()
        if session and not session.revoked_at:
            session.revoked_at = datetime.now(timezone.utc)
            await self.db.commit()
        return {"success": True}

    # ── Private helpers ───────────────────────────────────────────

    async def _generate_session(self, user: User, ip_hmac: str, user_agent: str):
        refresh_token = secure_random_hex(32)
        session_id = uuid.uuid4()
        access_token = self.jwt_handler.encode(
            {"sub": str(user.id), "sid": str(session_id), "type": "access"}, settings.ACCESS_TOKEN_EXPIRE_SECONDS
        )
        refresh_hmac = hmac_sha256(self.server_key, refresh_token.encode()).hexdigest()

        session = Session(
            id=session_id,
            user_id=user.id,
            refresh_token_hmac=refresh_hmac,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            device_label=user_agent[:50] if user_agent else "Unknown",
            ip_country="XX",
            last_active_at=datetime.now(timezone.utc),
        )
        self.db.add(session)
        user.last_login_at = datetime.now(timezone.utc)
        await self.db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": str(user.id),
                "full_name": user.full_name,
                "email": user.email,
                "key_salt": user.key_salt,
                "totp_enabled": user.totp_enabled,
                "role": user.role,
                "department": user.department,
                "manager_id": str(user.manager_id) if user.manager_id else None,
            },
        }

    def _decrypt_totp_secret(self, user: User, vault_key: bytes) -> str:
        iv, ct = decode_iv_ct(user.totp_secret_enc)
        return AESCBC(vault_key).decrypt(iv, ct).decode()
