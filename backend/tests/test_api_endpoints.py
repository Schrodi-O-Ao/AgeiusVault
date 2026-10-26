"""
API endpoint tests using httpx.AsyncClient with FastAPI's TestClient.
Tests all major API endpoints for correct responses and error handling.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
class TestHealthEndpoint:
    """Test health check endpoint."""

    async def test_health_check(self):
        """Test that health endpoint returns OK status."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
class TestAuthEndpoints:
    """Test authentication endpoints."""

    async def test_signup_missing_fields(self):
        """Test signup with missing required fields."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Missing full_name
            response = await client.post(
                "/api/v1/auth/signup",
                json={"email": "test@example.com", "password": "SecurePass123!"},
            )
            assert response.status_code == 422  # Validation error

    async def test_signup_invalid_email(self):
        """Test signup with invalid email format."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/signup",
                json={
                    "full_name": "Test User",
                    "email": "invalid-email",
                    "password": "SecurePass123!",
                },
            )
            assert response.status_code == 422  # Validation error

    async def test_signup_weak_password(self):
        """Test signup with weak password."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/signup",
                json={
                    "full_name": "Test User",
                    "email": "test@example.com",
                    "password": "weak",  # Too short
                },
            )
            assert response.status_code == 422  # Validation error

    async def test_login_missing_fields(self):
        """Test login with missing required fields."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Missing password
            response = await client.post(
                "/api/v1/auth/login", json={"email": "test@example.com"}
            )
            assert response.status_code == 422  # Validation error

    async def test_verify_totp_missing_vault_key(self):
        """Test TOTP verification without vault key header."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/verify-totp",
                json={"partial_token": "test-token", "totp_code": "123456"},
            )
            assert response.status_code == 400  # Missing header

    async def test_verify_totp_invalid_vault_key(self):
        """Test TOTP verification with invalid vault key format."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/verify-totp",
                json={"partial_token": "test-token", "totp_code": "123456"},
                headers={"X-Vault-Key": "invalid-hex-format"},
            )
            assert response.status_code == 400  # Invalid format

    async def test_email_verify_missing_fields(self):
        """Test email verification with missing fields."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/email-verify",
                json={
                    "email": "test@example.com"
                    # Missing code
                },
            )
            assert response.status_code == 422  # Validation error

    async def test_forgot_password_missing_email(self):
        """Test forgot password without email."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/auth/forgot-password", json={})
            assert response.status_code == 422  # Validation error

    async def test_reset_password_missing_token(self):
        """Test password reset without token."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/reset-password",
                json={"new_password": "NewSecurePass123!"},
            )
            assert response.status_code == 422  # Validation error

    async def test_refresh_missing_token(self):
        """Test token refresh without refresh token."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/auth/refresh", json={})
            assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
class TestUserEndpoints:
    """Test user endpoints."""

    async def test_get_profile_unauthorized(self):
        """Test getting profile without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/users/me")
            assert response.status_code == 401  # Unauthorized

    async def test_get_sessions_unauthorized(self):
        """Test getting sessions without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/users/me/sessions")
            assert response.status_code == 401  # Unauthorized

    async def test_revoke_session_unauthorized(self):
        """Test revoking session without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/users/me/sessions/test-id/revoke")
            assert response.status_code == 401  # Unauthorized

    async def test_get_team_unauthorized(self):
        """Test getting team without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/users/team")
            assert response.status_code == 401  # Unauthorized


@pytest.mark.asyncio
class TestRequestEndpoints:
    """Test request endpoints."""

    async def test_create_request_unauthorized(self):
        """Test creating request without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/requests")
            assert response.status_code == 401  # Unauthorized

    async def test_get_requests_unauthorized(self):
        """Test getting requests without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/requests/outbox")
            assert response.status_code == 401  # Unauthorized

    async def test_get_request_by_id_unauthorized(self):
        """Test getting specific request without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/requests/test-id")
            assert response.status_code == 401  # Unauthorized


@pytest.mark.asyncio
class TestEncryptedRequestEndpoints:
    """Test encrypted request endpoints."""

    async def test_create_encrypted_request_unauthorized(self):
        """Test creating encrypted request without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/encrypted/encrypted")
            assert response.status_code == 401  # Unauthorized

    async def test_get_encrypted_requests_unauthorized(self):
        """Test getting encrypted requests without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/encrypted/test-id/encrypted")
            assert response.status_code == 401  # Unauthorized


@pytest.mark.asyncio
class TestDelegationEndpoints:
    """Test delegation endpoints."""

    async def test_create_delegation_unauthorized(self):
        """Test creating delegation without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/delegations")
            assert response.status_code == 401  # Unauthorized

    async def test_get_delegations_unauthorized(self):
        """Test getting delegations without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/delegations")
            assert response.status_code == 401  # Unauthorized


@pytest.mark.asyncio
class TestAuditEndpoints:
    """Test audit endpoints."""

    async def test_get_audit_log_unauthorized(self):
        """Test getting audit log without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/audit/logs")
            assert response.status_code == 401  # Unauthorized

    async def test_get_audit_trail_unauthorized(self):
        """Test getting audit trail without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/audit/test-id/chain")
            assert response.status_code == 401  # Unauthorized


@pytest.mark.asyncio
class TestAnomalyDetectionEndpoints:
    """Test anomaly detection endpoints."""

    async def test_get_anomalies_unauthorized(self):
        """Test getting anomalies without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/anomaly/user-analysis")
            assert response.status_code == 401  # Unauthorized

    async def test_train_model_unauthorized(self):
        """Test training model without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/api/v1/anomaly/train-model")
            assert response.status_code == 401  # Unauthorized


@pytest.mark.asyncio
class TestBlockchainEndpoints:
    """Test blockchain audit endpoints."""

    async def test_get_chain_unauthorized(self):
        """Test getting blockchain without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/blockchain/status")
            assert response.status_code == 401  # Unauthorized

    async def test_verify_chain_unauthorized(self):
        """Test verifying chain without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/blockchain/verify/test-id")
            assert response.status_code == 401  # Unauthorized


@pytest.mark.asyncio
class TestErrorHandling:
    """Test general error handling."""

    async def test_404_not_found(self):
        """Test that non-existent endpoints return 404."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/non-existent-endpoint")
            assert response.status_code == 404

    async def test_method_not_allowed(self):
        """Test that wrong HTTP methods return 405."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # GET on POST endpoint
            response = await client.get("/api/v1/auth/signup")
            assert response.status_code == 405

    async def test_invalid_json(self):
        """Test that invalid JSON returns 422."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/auth/signup",
                content="invalid json",
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 422
