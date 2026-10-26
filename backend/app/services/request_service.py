import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.action_nonce import ActionNonce
from app.models.approval import Approval
from app.models.delegation import Delegation
from app.models.request import Request
from app.models.user import User
from app.security.aes import AESCBC
from app.security.crypto_utils import decode_iv_ct, encode_iv_ct, secure_random_hex
from app.security.hmac_impl import hmac_sha256
from app.security.rsa_impl import RSAImpl
from app.security.totp import TOTP
from app.services.audit_service import AuditService
from app.utils.validation import InputValidator, ValidationError


# Payload schemas per request type
REQUEST_TYPE_FIELDS = {
    "ANNUAL_LEAVE": ["start_date", "end_date", "reason"],
    "SICK_LEAVE": ["start_date", "days", "fit_note"],
    "EXPENSE": ["amount", "currency", "category", "description"],
    "IT_ACCESS": ["system", "access_level", "justification"],
    "ANON_HR": ["category", "description"],
}

VALID_TYPES = set(REQUEST_TYPE_FIELDS.keys())
VALID_STATUSES = {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}


class RequestService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.server_key = settings.server_master_key_bytes

    # ── Create request ────────────────────────────────────────────

    async def create_request(
        self,
        user: User,
        request_type: str,
        payload: dict[str, Any],
        is_anonymous: bool,
        ip_hmac: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        # Validate request type and payload
        validated_type = InputValidator.validate_request_type(request_type)
        validated_payload = InputValidator.validate_request_payload(validated_type, payload)

        if validated_type == "ANON_HR":
            is_anonymous = True

        # Resolve approver
        approver = await self._resolve_approver(user, validated_type, is_anonymous)
        if not approver:
            raise HTTPException(400, "No approver available for this request type")

        # Generate DEK and encrypt payload
        dek = os.urandom(32)
        payload_json = json.dumps(validated_payload, sort_keys=True)
        iv, ct = AESCBC(dek).encrypt(payload_json.encode("utf-8"))
        payload_enc = encode_iv_ct(iv, ct)

        # Wrap DEK for each party
        wrapped_keys = []
        requester_id = user.id

        if is_anonymous:
            requester_id = None
            # Wrap for requester (anonymous reporter) so they can track
            wrapped_keys.append(self._wrap_dek(dek, user, "reporter"))
        else:
            wrapped_keys.append(self._wrap_dek(dek, user, "requester"))

        wrapped_keys.append(self._wrap_dek(dek, approver, "approver"))

        # Add delegates of the approver
        delegates = await self._active_delegates(approver.id)
        for delegate in delegates:
            wrapped_keys.append(self._wrap_dek(dek, delegate, "delegate"))

        # Encrypt anonymous identity
        identity_enc = None
        if is_anonymous:
            identity_data = json.dumps({"user_id": str(user.id), "email": user.email})
            id_iv, id_ct = AESCBC(self.server_key).encrypt(identity_data.encode("utf-8"))
            identity_enc = encode_iv_ct(id_iv, id_ct)

        request = Request(
            id=uuid.uuid4(),
            requester_id=requester_id,
            type=validated_type,
            payload_enc=payload_enc,
            dek_enc=wrapped_keys,
            status="PENDING",
            is_anonymous=is_anonymous,
            identity_enc=identity_enc,
        )
        self.db.add(request)
        await self.db.flush()

        # Audit chain
        audit = AuditService(self.db)
        await audit.log(request.id, user.id, "SUBMITTED")
        await self.db.commit()

        return {
            "success": True,
            "id": str(request.id),
            "type": request_type,
            "status": "PENDING",
        }

    # ── List requests ─────────────────────────────────────────────

    async def list_mine(self, user: User) -> list[dict[str, Any]]:
        """List requests submitted by the current user."""
        result = await self.db.execute(
            select(Request)
            .where(Request.requester_id == user.id)
            .order_by(Request.submitted_at.desc())
        )
        return [self._request_summary(r) for r in result.scalars().all()]

    async def list_inbox(self, user: User) -> list[dict[str, Any]]:
        """List requests pending this user's approval (direct or delegated)."""
        # Get IDs where this user is the manager/approver
        requests = await self.db.execute(
            select(Request).where(Request.status == "PENDING")
        )
        inbox = []
        for req in requests.scalars().all():
            if await self._can_approve(req, user):
                inbox.append(self._request_summary(req))
        return inbox

    async def get_detail(
        self, request_id: str, user: User, vault_key: bytes
    ) -> dict[str, Any]:
        request = await self._get_request(request_id)

        # Browser-encrypted content is decrypted by an authorized approver in the browser.
        is_encrypted = self._is_client_encrypted(request)
        payload = None
        if not is_encrypted:
            dek = await self._decrypt_dek(request, user, vault_key)
            iv, ct = decode_iv_ct(request.payload_enc)
            payload = json.loads(AESCBC(dek).decrypt(iv, ct).decode("utf-8"))

        # Get approvals
        approvals = (
            await self.db.execute(
                select(Approval)
                .where(Approval.request_id == request.id)
                .order_by(Approval.acted_at.asc())
            )
        ).scalars().all()

        # Get nonce for potential actions
        nonce = await self.issue_nonce(request.id, user.id)

        return {
            "id": str(request.id),
            "requester_id": str(request.requester_id) if request.requester_id else None,
            "type": request.type,
            "payload": payload,
            "status": request.status,
            "is_anonymous": request.is_anonymous,
            "is_encrypted": is_encrypted,
            "submitted_at": str(request.submitted_at),
            "updated_at": str(request.updated_at),
            "can_act": await self._can_approve(request, user),
            "nonce": nonce,
            "approvals": [
                {
                    "id": str(a.id),
                    "approver_id": str(a.approver_id),
                    "action": a.action,
                    "acted_at": str(a.acted_at),
                    "step_nonce": a.step_nonce,
                }
                for a in approvals
            ],
        }

    # ── Approve / Reject ──────────────────────────────────────────

    async def perform_action(
        self,
        request_id: str,
        user: User,
        vault_key: bytes,
        step_up_payload: dict[str, Any],
        action: str,
        nonce: str,
        notes: str | None,
        ip_hmac: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        action = action.upper()
        if action not in ("APPROVED", "REJECTED"):
            raise HTTPException(400, "Action must be APPROVED or REJECTED")

        # Validate step-up token
        if step_up_payload.get("type") != "step_up":
            raise HTTPException(403, "Step-up token is required")
        if step_up_payload.get("sub") != str(user.id):
            raise HTTPException(403, "Step-up token was issued for another user")

        request = await self._get_request(request_id)
        if request.status != "PENDING":
            raise HTTPException(400, "Request is not pending")

        if not await self._can_approve(request, user):
            raise HTTPException(403, "You are not authorized to act on this request")

        # Consume nonce
        await self._consume_nonce(request.id, user.id, nonce)

        # Decrypt private key for signing
        try:
            iv, ct = decode_iv_ct(user.rsa_private_enc)
            private_key = RSAImpl.decrypt_private_key(iv, ct, vault_key)
        except Exception:
            raise HTTPException(400, "Invalid vault key")

        # Create digital signature
        now = datetime.now(timezone.utc)
        step_nonce = secure_random_hex(16)
        message = f"{request_id}|{action}|{now.isoformat()}|{step_nonce}".encode()
        signature = RSAImpl.sign_message(private_key, message)

        # Encrypt notes if provided
        notes_enc = None
        if notes:
            validated_notes = InputValidator.validate_notes(notes)
            dek = await self._decrypt_dek(request, user, vault_key)
            n_iv, n_ct = AESCBC(dek).encrypt(validated_notes.encode("utf-8"))
            notes_enc = encode_iv_ct(n_iv, n_ct)

        approval = Approval(
            id=uuid.uuid4(),
            request_id=request.id,
            approver_id=user.id,
            action=action,
            notes_enc=notes_enc,
            digital_sig=signature,
            step_nonce=step_nonce,
            acted_at=now,
        )
        self.db.add(approval)

        # Update request status
        request.status = action
        request.updated_at = now

        # Audit chain
        audit = AuditService(self.db)
        await audit.log(request.id, user.id, action)
        await self.db.commit()

        return {
            "success": True,
            "id": str(request.id),
            "status": request.status,
            "approval_id": str(approval.id),
        }

    # ── Bulk approve ──────────────────────────────────────────────

    async def bulk_approve(
        self,
        user: User,
        vault_key: bytes,
        request_ids: list[str],
        totp_code: str,
        ip_hmac: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        if len(request_ids) > settings.MAX_BULK_APPROVAL_REQUESTS:
            raise HTTPException(400, f"Bulk approval is limited to {settings.MAX_BULK_APPROVAL_REQUESTS} requests")

        await self._verify_totp(user, totp_code, vault_key)

        approved = []
        rejected = []

        for raw_id in request_ids:
            try:
                request = await self._get_request(raw_id)
                if request.status != "PENDING":
                    raise HTTPException(400, "Request is not pending")
                if not await self._can_approve(request, user):
                    raise HTTPException(403, "Not authorized")

                # Sign and create approval
                iv, ct = decode_iv_ct(user.rsa_private_enc)
                private_key = RSAImpl.decrypt_private_key(iv, ct, vault_key)
                now = datetime.now(timezone.utc)
                step_nonce = secure_random_hex(16)
                message = f"{raw_id}|APPROVED|{now.isoformat()}|{step_nonce}".encode()
                signature = RSAImpl.sign_message(private_key, message)

                approval = Approval(
                    id=uuid.uuid4(),
                    request_id=request.id,
                    approver_id=user.id,
                    action="APPROVED",
                    digital_sig=signature,
                    step_nonce=step_nonce,
                    acted_at=now,
                )
                self.db.add(approval)
                request.status = "APPROVED"
                request.updated_at = now

                audit = AuditService(self.db)
                await audit.log(request.id, user.id, "APPROVED")
                approved.append(str(request.id))

            except HTTPException as exc:
                rejected.append({"id": raw_id, "reason": str(exc.detail)})

        await self.db.commit()
        return {"approved": approved, "rejected": rejected}

    # ── Dashboard stats ───────────────────────────────────────────

    async def dashboard_stats(self, user: User) -> dict[str, Any]:
        all_pending = (
            await self.db.execute(select(Request).where(Request.status == "PENDING"))
        ).scalars().all()

        inbox_count = 0
        for req in all_pending:
            if await self._can_approve(req, user):
                inbox_count += 1

        my_requests = (
            await self.db.execute(
                select(Request).where(Request.requester_id == user.id)
            )
        ).scalars().all()

        approved_count = len([r for r in my_requests if r.status == "APPROVED"])

        return {
            "pending_approvals": inbox_count,
            "my_requests": len(my_requests),
            "approved": approved_count,
            "security_score": 100 if user.totp_enabled else 65,
        }

    # ── Nonce management ──────────────────────────────────────────

    async def issue_nonce(self, request_id: uuid.UUID, user_id: uuid.UUID) -> str:
        nonce = secure_random_hex(16)
        self.db.add(
            ActionNonce(
                request_id=request_id,
                user_id=user_id,
                action_type="any",
                nonce=nonce,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.ACTION_NONCE_EXPIRE_MINUTES),
            )
        )
        await self.db.flush()
        return nonce

    # ── Audit chain access ────────────────────────────────────────

    async def request_chain(self, request_id: str, user: User) -> list[dict[str, Any]]:
        request = await self._get_request(request_id)
        audit = AuditService(self.db)
        chain = await audit.get_chain(request.id)
        return [
            {
                "id": str(entry.id),
                "step_index": entry.step_index,
                "actor_id": str(entry.actor_id) if entry.actor_id else None,
                "action": entry.action,
                "prev_hash": entry.prev_hash,
                "chain_hash": entry.chain_hash,
                "recorded_at": str(entry.recorded_at),
            }
            for entry in chain
        ]

    async def verify_request_chain(self, request_id: str, user: User) -> dict[str, Any]:
        request = await self._get_request(request_id)
        audit = AuditService(self.db)
        return await audit.verify_chain(request.id)

    # ── Private helpers ───────────────────────────────────────────

    def _wrap_dek(self, dek: bytes, user: User, role: str) -> dict[str, str]:
        public_key = json.loads(user.rsa_public_key)
        return {
            "user_id": str(user.id),
            "wrapped_dek": RSAImpl.encrypt_symmetric_key(dek, public_key),
            "role": role,
        }

    async def _resolve_approver(self, user: User, request_type: str, is_anonymous: bool) -> User | None:
        if is_anonymous or request_type == "ANON_HR":
            return await self._first_user_by_role("HR_ADMIN")
        if user.manager_id:
            manager = await self._get_user(user.manager_id)
            if manager:
                return manager
        return await self._first_user_by_role("MANAGER")

    async def _can_approve(self, request: Request, user: User) -> bool:
        if request.requester_id and request.requester_id == user.id:
            return False
        # Direct manager check
        if request.requester_id:
            requester = await self._get_user(request.requester_id)
            if requester and requester.manager_id == user.id:
                return True
        # HR_ADMIN can approve anonymous reports
        if request.is_anonymous and user.role == "HR_ADMIN":
            return True
        # Check if user has a wrapped key as approver (server-side encryption)
        for key_entry in (request.dek_enc or []):
            if key_entry.get("user_id") == str(user.id) and key_entry.get("role") in ("approver", "delegate"):
                return True
        # Check if user has a wrapped key for client-side encrypted requests
        for key_entry in (request.dek_enc or []):
            if key_entry.get("user_id") == str(user.id) and "role" not in key_entry:
                return True
        # Check delegations
        delegates = await self._active_delegates_of(user.id)
        for del_user_id in delegates:
            for key_entry in (request.dek_enc or []):
                if key_entry.get("user_id") == str(del_user_id):
                    return True
        return False

    async def _active_delegates(self, delegator_id: uuid.UUID) -> list[User]:
        now = datetime.now(timezone.utc).date()
        result = await self.db.execute(
            select(Delegation).where(
                Delegation.delegator_id == delegator_id,
                Delegation.is_active.is_(True),
                Delegation.valid_from <= now,
                Delegation.valid_until >= now,
            )
        )
        users = []
        for d in result.scalars().all():
            u = await self._get_user(d.delegatee_id)
            if u:
                users.append(u)
        return users

    async def _active_delegates_of(self, delegate_id: uuid.UUID) -> list[uuid.UUID]:
        """Get delegator IDs for whom this user is a delegate."""
        now = datetime.now(timezone.utc).date()
        result = await self.db.execute(
            select(Delegation).where(
                Delegation.delegatee_id == delegate_id,
                Delegation.is_active.is_(True),
                Delegation.valid_from <= now,
                Delegation.valid_until >= now,
            )
        )
        return [d.delegator_id for d in result.scalars().all()]

    async def _decrypt_dek(self, request: Request, user: User, vault_key: bytes) -> bytes:
        wrapped = None
        for entry in (request.dek_enc or []):
            if entry.get("user_id") == str(user.id):
                wrapped = entry
                break
        if not wrapped:
            raise HTTPException(403, "You do not have access to this request's content")
        try:
            iv, ct = decode_iv_ct(user.rsa_private_enc)
            private_key = RSAImpl.decrypt_private_key(iv, ct, vault_key)
            return RSAImpl.decrypt_symmetric_key(wrapped["wrapped_dek"], private_key)
        except Exception:
            raise HTTPException(400, "Invalid vault key")

    async def _consume_nonce(self, request_id: uuid.UUID, user_id: uuid.UUID, nonce: str) -> None:
        now = datetime.now(timezone.utc)
        item = (
            await self.db.execute(
                select(ActionNonce)
                .where(
                    ActionNonce.request_id == request_id,
                    ActionNonce.user_id == user_id,
                    ActionNonce.nonce == nonce,
                    ActionNonce.used_at.is_(None),
                    ActionNonce.expires_at >= now,
                )
                .with_for_update()
            )
        ).scalars().first()
        if not item:
            raise HTTPException(400, "Action nonce is invalid or expired")
        item.used_at = now

    async def _verify_totp(self, user: User, code: str, vault_key: bytes) -> None:
        if not user.totp_enabled or not user.totp_secret_enc:
            raise HTTPException(403, "TOTP must be enabled for this action")
        iv, ct = decode_iv_ct(user.totp_secret_enc)
        secret = AESCBC(vault_key).decrypt(iv, ct).decode()
        if not TOTP(secret).verify(code):
            raise HTTPException(401, "Invalid TOTP code")

    async def _get_request(self, request_id: str) -> Request:
        try:
            parsed = uuid.UUID(str(request_id))
        except ValueError:
            raise HTTPException(404, "Request not found")
        request = (
            await self.db.execute(select(Request).where(Request.id == parsed))
        ).scalars().first()
        if not request:
            raise HTTPException(404, "Request not found")
        return request

    async def _get_user(self, user_id) -> User | None:
        if not user_id:
            return None
        return (await self.db.execute(select(User).where(User.id == user_id))).scalars().first()

    async def _first_user_by_role(self, role: str) -> User | None:
        return (
            await self.db.execute(
                select(User).where(User.role == role, User.is_active.is_(True)).order_by(User.created_at.asc())
            )
        ).scalars().first()

    def _request_summary(self, request: Request) -> dict[str, Any]:
        return {
            "id": str(request.id),
            "type": request.type,
            "status": request.status,
            "is_anonymous": request.is_anonymous,
            "is_encrypted": self._is_client_encrypted(request),
            "submitted_at": str(request.submitted_at),
            "updated_at": str(request.updated_at),
            "requester_id": str(request.requester_id) if request.requester_id else None,
        }

    @staticmethod
    def _is_client_encrypted(request: Request) -> bool:
        """Read the browser-encryption marker, including the original hex-encoded JSON form."""
        if not request.identity_enc:
            return False
        try:
            metadata = json.loads(request.identity_enc)
        except (TypeError, json.JSONDecodeError):
            try:
                metadata = json.loads(bytes.fromhex(request.identity_enc).decode("utf-8"))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                return False
        return isinstance(metadata, dict) and metadata.get("clientEncryption") is True
