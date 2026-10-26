"""
Integration tests for security improvements.

These tests verify that the security enhancements work correctly
in an integrated environment with the full application stack.
"""

# Resolve test database URL safely
import logging
import os
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings
from app.database import Base, get_db
from app.main import app

logger = logging.getLogger(__name__)


if os.environ.get("TEST_DATABASE_URL"):
    TEST_DATABASE_URL = os.environ["TEST_DATABASE_URL"]
elif "/aegisvault_test" in settings.DATABASE_URL:
    TEST_DATABASE_URL = settings.DATABASE_URL
elif "/aegisvault" in settings.DATABASE_URL:
    TEST_DATABASE_URL = settings.DATABASE_URL.replace("/aegisvault", "/aegisvault_test")
else:
    TEST_DATABASE_URL = settings.DATABASE_URL

_db_available: bool | None = None


@pytest_asyncio.fixture(scope="function")
async def test_db():
    """Create a fresh database for each test."""
    global _db_available
    if _db_available is False:
        pytest.skip("Test database not available")

    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _db_available = True
    except (SQLAlchemyError, OSError, RuntimeError) as e:
        _db_available = False
        await engine.dispose()
        pytest.skip(f"Test database not available: {e}")

    async with session_factory() as session:
        yield session

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    except (SQLAlchemyError, OSError, RuntimeError) as exc:
        logger.debug("Failed to drop test database tables: %s", exc)
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def client(test_db):
    """Create a test client with the test database."""

    async def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db

    with patch(
        "app.services.email_service.EmailService.send_email",
        new_callable=AsyncMock,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac

    app.dependency_overrides.clear()


class TestSecurityIntegration:
    """Integration tests for security features."""

    @pytest.mark.asyncio
    async def test_password_complexity_validation(self, client):
        """Test that password complexity requirements are enforced."""
        weak_passwords = [
            "password",  # Too simple, < 12 chars
            "Password1",  # Too short (< 12 chars)
            "password12345",  # No uppercase
            "PASSWORD12345",  # No lowercase
            "PasswordPassword",  # No digits
            "123456789012",  # No letters
        ]

        for idx, weak_pwd in enumerate(weak_passwords):
            response = await client.post(
                "/api/v1/auth/signup",
                json={
                    "full_name": "Test User",
                    "email": f"test_weak_{idx}@example.com",
                    "password": weak_pwd,
                },
            )
            assert response.status_code in (400, 422)
            detail_str = str(response.json().get("detail", "")).lower()
            assert "password" in detail_str

    @pytest.mark.asyncio
    async def test_strong_password_acceptance(self, client):
        """Test that strong passwords are accepted."""
        strong_password = "SecureP@ssw0rd123!"

        response = await client.post(
            "/api/v1/auth/signup",
            json={
                "full_name": "Test User",
                "email": "strongpass@example.com",
                "password": strong_password,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("success") is True

    @pytest.mark.asyncio
    async def test_email_validation(self, client):
        """Test that email validation is enforced."""
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "user@",
            "user@.com",
            "user name@example.com",
        ]

        for invalid_email in invalid_emails:
            response = await client.post(
                "/api/v1/auth/signup",
                json={
                    "full_name": "Test User",
                    "email": invalid_email,
                    "password": "SecureP@ssw0rd123!",
                },
            )
            assert response.status_code in (400, 422)
            detail_str = str(response.json().get("detail", "")).lower()
            assert "email" in detail_str

    @pytest.mark.asyncio
    async def test_request_size_limit(self, client):
        """Test that request size limits are enforced."""
        large_payload = "x" * (settings.MAX_REQUEST_SIZE_BYTES + 1000)

        response = await client.post(
            "/api/v1/auth/signup",
            json={
                "full_name": large_payload,
                "email": "test_oversize@example.com",
                "password": "SecureP@ssw0rd123!",
            },
        )
        assert response.status_code == 413  # Payload Too Large

    @pytest.mark.asyncio
    async def test_security_headers(self, client):
        """Test that security headers are properly set."""
        response = await client.get("/health")
        assert response.status_code == 200
        headers = response.headers

        # Check security headers
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert "X-XSS-Protection" in headers
        assert "Strict-Transport-Security" in headers
        assert "Content-Security-Policy" in headers

    @pytest.mark.asyncio
    async def test_cors_configuration(self, client):
        """Test that CORS is properly configured."""
        response = await client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

    @pytest.mark.asyncio
    async def test_input_sanitization(self, client):
        """Test that inputs are properly sanitized."""
        # Test with potential XSS attempts
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
        ]

        for idx, xss_attempt in enumerate(xss_attempts):
            response = await client.post(
                "/api/v1/auth/signup",
                json={
                    "full_name": xss_attempt,
                    "email": f"test_xss_{idx}@example.com",
                    "password": "SecureP@ssw0rd123!",
                },
            )
            assert response.status_code in (400, 422)
            detail_str = str(response.json().get("detail", "")).lower()
            assert any(word in detail_str for word in ("invalid", "name", "character"))

    @pytest.mark.asyncio
    async def test_request_type_validation(self, client):
        """Test that request types are properly validated."""
        from app.utils.validation import InputValidator, ValidationError

        invalid_types = ["INVALID_TYPE", "hacking", "admin", "DROP TABLE", ""]
        for invalid_type in invalid_types:
            with pytest.raises(ValidationError):
                InputValidator.validate_request_type(invalid_type)

        for valid_type in [
            "ANNUAL_LEAVE",
            "SICK_LEAVE",
            "EXPENSE",
            "IT_ACCESS",
            "ANON_HR",
        ]:
            result = InputValidator.validate_request_type(valid_type)
            assert result == valid_type

    @pytest.mark.asyncio
    async def test_rate_limiting(self, client):
        """Test that rate limiting is enforced."""
        # Make multiple rapid requests with a dedicated test IP
        responses = []
        headers = {"X-Forwarded-For": "198.51.100.99"}
        for _ in range(settings.RATE_LIMIT_REQUESTS_PER_WINDOW + 10):
            response = await client.get("/health", headers=headers)
            responses.append(response)

        # Should eventually be rate limited
        assert any(r.status_code == 429 for r in responses)

    @pytest.mark.asyncio
    async def test_otp_validation(self, client):
        """Test that OTP codes are properly validated."""
        from app.utils.validation import InputValidator, ValidationError

        invalid_otps = [
            "12345",  # Too short
            "1234567",  # Too long
            "abcdef",  # Not digits
            "12 345",  # Contains space
            "",  # Empty
            "12345a",  # Alphanumeric
        ]

        for invalid_otp in invalid_otps:
            with pytest.raises(ValidationError):
                InputValidator.validate_otp_code(invalid_otp)

        # Valid OTP code
        valid_otp = "123456"
        result = InputValidator.validate_otp_code(valid_otp)
        assert result == valid_otp


class TestCryptoIntegration:
    """Integration tests for cryptographic implementations."""

    def test_aes_encryption_roundtrip(self):
        """Test AES encryption and decryption."""
        import os

        from app.security.aes import AESCBC

        key = os.urandom(32)
        plaintext = b"Test message for encryption"

        iv, ciphertext = AESCBC(key).encrypt(plaintext)
        decrypted = AESCBC(key).decrypt(iv, ciphertext)

        assert decrypted == plaintext

    def test_rsa_key_generation(self):
        """Test RSA key generation with new implementation."""
        from app.security.rsa_impl import RSAImpl

        # Test 3072-bit key generation
        public, private = RSAImpl.generate_keypair(3072)

        assert "pem" in public
        assert "pem" in private
        assert public["format"] == "PEM"
        assert private["format"] == "PEM"

    def test_rsa_key_encryption(self):
        """Test RSA key encryption and decryption."""
        import os

        from app.security.rsa_impl import RSAImpl

        public, private = RSAImpl.generate_keypair(2048)  # Use 2048 for speed
        aes_key = os.urandom(32)

        encrypted = RSAImpl.encrypt_symmetric_key(aes_key, public)
        decrypted = RSAImpl.decrypt_symmetric_key(encrypted, private)

        assert decrypted == aes_key

    def test_rsa_signatures(self):
        """Test RSA digital signatures."""
        from app.security.rsa_impl import RSAImpl

        public, private = RSAImpl.generate_keypair(2048)
        message = b"Test message for signing"

        signature = RSAImpl.sign_message(private, message)
        is_valid = RSAImpl.verify_signature(public, message, signature)

        assert is_valid

    def test_pbkdf2_derivation(self):
        """Test PBKDF2 key derivation."""
        import os

        from app.security.pbkdf2 import PBKDF2

        password = b"test_password"
        salt = os.urandom(32)

        derived = PBKDF2(password, salt, 1000, 32).derive()

        assert len(derived) == 32
        assert derived != password  # Should be different

    def test_hmac_generation(self):
        """Test HMAC generation."""
        from app.security.hmac_impl import hmac_sha256

        key = b"test_key"
        message = b"test_message"

        hmac_result = hmac_sha256(key, message)

        assert len(hmac_result.digest()) == 32
        assert hmac_result.hexdigest() is not None

    def test_totp_generation(self):
        """Test TOTP code generation."""
        from app.security.totp import TOTP

        totp = TOTP()
        code = totp.totp.now()

        assert len(code) == 6
        assert code.isdigit()
        assert totp.verify(code)


class TestConfigurationValidation:
    """Tests for configuration validation."""

    def test_placeholder_detection(self):
        """Test that placeholder secrets are rejected."""

        from app.config import _validate_hex_secret

        placeholder_values = [
            "REPLACE_WITH_SECRET",
            "your_secret_here",
            "CHANGE_ME",
            "placeholder_value",
        ]

        for placeholder in placeholder_values:
            with pytest.raises(ValueError):
                _validate_hex_secret("TEST_SECRET", placeholder)

    def test_valid_secret_acceptance(self):
        """Test that valid secrets are accepted."""
        import secrets

        from app.config import _validate_hex_secret

        valid_secret = secrets.token_hex(32)
        result = _validate_hex_secret("TEST_SECRET", valid_secret)

        assert result == valid_secret.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
