import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.dependencies import get_current_user
from app.main import app
from app.models.audit_chain import AuditChain
from app.models.request import Request
from app.services.request_service import RequestService


@pytest.fixture
def fake_db():
    db = Mock()
    db.add = Mock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_team_endpoint_role_restrictions(fake_db):
    staff_user = SimpleNamespace(id=uuid.uuid4(), role="STAFF")
    manager_user = SimpleNamespace(id=uuid.uuid4(), role="MANAGER")

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db

    # Mock db.execute for team query
    mock_result = Mock()
    mock_result.scalars.return_value.all.return_value = []
    fake_db.execute = AsyncMock(return_value=mock_result)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # STAFF user should receive 403 Forbidden
            app.dependency_overrides[get_current_user] = lambda: staff_user
            res_staff = await client.get("/api/v1/users/team")
            assert res_staff.status_code == 403

            # MANAGER user should be permitted
            app.dependency_overrides[get_current_user] = lambda: manager_user
            res_manager = await client.get("/api/v1/users/team")
            assert res_manager.status_code == 200
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_audit_logs_role_restrictions(fake_db):
    staff_user = SimpleNamespace(id=uuid.uuid4(), role="STAFF")
    manager_user = SimpleNamespace(id=uuid.uuid4(), role="MANAGER")
    admin_user = SimpleNamespace(id=uuid.uuid4(), role="SYS_ADMIN")

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db

    mock_result = Mock()
    mock_result.scalars.return_value.all.return_value = []
    fake_db.execute = AsyncMock(return_value=mock_result)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # STAFF should receive 403
            app.dependency_overrides[get_current_user] = lambda: staff_user
            res_staff = await client.get("/api/v1/audit/logs")
            assert res_staff.status_code == 403

            # MANAGER should receive 403
            app.dependency_overrides[get_current_user] = lambda: manager_user
            res_mgr = await client.get("/api/v1/audit/logs")
            assert res_mgr.status_code == 403

            # SYS_ADMIN should be permitted
            app.dependency_overrides[get_current_user] = lambda: admin_user
            res_admin = await client.get("/api/v1/audit/logs")
            assert res_admin.status_code == 200
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_audit_chain_endpoint_authorization(fake_db):
    req_id = uuid.uuid4()
    owner_id = uuid.uuid4()
    other_user = SimpleNamespace(id=uuid.uuid4(), role="STAFF")
    admin_user = SimpleNamespace(id=uuid.uuid4(), role="SYS_ADMIN")

    req_obj = Request(
        id=req_id,
        requester_id=owner_id,
        type="ANNUAL_LEAVE",
        payload_enc="00" * 12 + ":" + "00" * 16,
        dek_enc=[],
        status="PENDING",
    )

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db

    async def mock_execute(stmt):
        mock_res = Mock()
        # If querying Request, return req_obj
        if "FROM requests" in str(stmt):
            mock_res.scalars.return_value.first.return_value = req_obj
        else:
            mock_res.scalars.return_value.first.return_value = None
            mock_res.scalars.return_value.all.return_value = []
        return mock_res

    fake_db.execute = AsyncMock(side_effect=mock_execute)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Unrelated STAFF user cannot view another user's request chain
            app.dependency_overrides[get_current_user] = lambda: other_user
            res_other = await client.get(f"/api/v1/audit/{req_id}/chain")
            assert res_other.status_code == 403

            # SYS_ADMIN can view request chain
            app.dependency_overrides[get_current_user] = lambda: admin_user
            res_admin = await client.get(f"/api/v1/audit/{req_id}/chain")
            assert res_admin.status_code == 200
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_step_up_token_bound_to_request():
    service = RequestService(db=Mock())
    user = SimpleNamespace(id=uuid.uuid4())
    req_id_1 = str(uuid.uuid4())
    req_id_2 = str(uuid.uuid4())

    # Step-up token issued for req_id_1
    step_up_payload = {
        "type": "step_up",
        "sub": str(user.id),
        "request_id": req_id_1,
    }

    # Attempting action on req_id_2 with token for req_id_1 should raise 403
    with pytest.raises(Exception) as exc_info:
        await service.perform_action(
            request_id=req_id_2,
            user=user,
            vault_key=b"0" * 32,
            step_up_payload=step_up_payload,
            action="APPROVED",
            nonce="test-nonce",
            notes=None,
            ip_hmac=None,
            user_agent=None,
        )
    assert exc_info.value.status_code == 403
    assert "another request" in exc_info.value.detail
