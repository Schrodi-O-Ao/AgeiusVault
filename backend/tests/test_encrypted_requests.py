"""Focused tests for the browser-encrypted request API contract."""

import hashlib
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.dependencies import get_current_user
from app.main import app
from app.routers import encrypted_requests


class StoredRequest:
    def __init__(self, **values):
        self.__dict__.update(values)
        self.submitted_at = "2026-01-01T00:00:00+00:00"


class AuditStub:
    def __init__(self, _db):
        self.log = AsyncMock()


@pytest.fixture
def fake_db():
    db = Mock()
    db.add = Mock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    return db


@pytest.fixture
def users():
    return (
        SimpleNamespace(id=uuid.uuid4(), manager_id=None, role="STAFF"),
        SimpleNamespace(id=uuid.uuid4(), manager_id=None, role="MANAGER"),
    )


@pytest.mark.asyncio
async def test_encrypted_submission_and_approver_decryption_contract(monkeypatch, fake_db, users):
    requester, approver = users
    aes_key = AESGCM.generate_key(bit_length=256)
    iv = bytes.fromhex("00112233445566778899aabb")
    plaintext = b'{"reason":"annual leave"}'
    ciphertext = AESGCM(aes_key).encrypt(iv, plaintext, None)
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    wrapped_key = rsa_private.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    body = {
        "encryptedPayload": ciphertext.hex(),
        "iv": iv.hex(),
        "keyHash": hashlib.sha256(aes_key).hexdigest(),
        "requestType": "ANNUAL_LEAVE",
        "isAnonymous": False,
        "wrappedKeys": [{"userId": str(approver.id), "wrappedKey": wrapped_key.hex()}],
    }

    monkeypatch.setattr(encrypted_requests, "Request", StoredRequest)
    monkeypatch.setattr(encrypted_requests, "AuditService", AuditStub)
    monkeypatch.setattr(encrypted_requests, "_resolve_approver", AsyncMock(return_value=approver))

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: requester
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            submitted = await client.post("/api/v1/encrypted/encrypted", json=body)
            assert submitted.status_code == 200
            request = fake_db.add.call_args.args[0]
            assert request.payload_enc == f"{iv.hex()}:{ciphertext.hex()}"
            assert request.requester_id == requester.id
            assert request.identity_enc is not None

            app.dependency_overrides[get_current_user] = lambda: approver
            monkeypatch.setattr(encrypted_requests, "_get_request", AsyncMock(return_value=request))
            retrieved = await client.get(f"/api/v1/encrypted/{request.id}/encrypted")

        assert retrieved.status_code == 200
        envelope = retrieved.json()
        assert envelope["iv"] == iv.hex()
        assert envelope["encryptedData"] == ciphertext.hex()
        assert envelope["wrappedKey"] == wrapped_key.hex()

        recovered_key = rsa_private.decrypt(
            bytes.fromhex(envelope["wrappedKey"]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        assert AESGCM(recovered_key).decrypt(
            bytes.fromhex(envelope["iv"]), bytes.fromhex(envelope["encryptedData"]), None
        ) == plaintext
        fake_db.commit.assert_awaited_once()
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"iv": "abc"},
        {"encryptedPayload": "zz"},
        {"keyHash": "0" * 63},
        {"isAnonymous": "false"},
        {"requestType": 7},
        {"wrappedKeys": [{"userId": "someone", "wrappedKey": "abcd"}]},
    ],
)
async def test_invalid_envelope_is_rejected_before_database_write(change, fake_db, users):
    requester, _approver = users
    body = {
        "encryptedPayload": "00" * 32,
        "iv": "00" * 12,
        "keyHash": "00" * 32,
        "requestType": "ANNUAL_LEAVE",
        "isAnonymous": False,
        "wrappedKeys": [{"userId": str(uuid.uuid4()), "wrappedKey": "00" * 384}],
    }
    body.update(change)

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: requester
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1/encrypted/encrypted", json=body)
        assert response.status_code == 400
        fake_db.add.assert_not_called()
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_requester_and_users_without_wrapped_key_cannot_retrieve_envelope(monkeypatch, fake_db, users):
    requester, approver = users
    request = StoredRequest(
        id=uuid.uuid4(), requester_id=requester.id, type="ANNUAL_LEAVE",
        payload_enc="00" * 12 + ":" + "00" * 16,
        dek_enc=[{"user_id": str(approver.id), "wrapped_key": "ab" * 384}],
        is_anonymous=False, status="PENDING",
    )
    monkeypatch.setattr(encrypted_requests, "_get_request", AsyncMock(return_value=request))

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            for current_user in (requester, SimpleNamespace(id=uuid.uuid4(), role="STAFF")):
                app.dependency_overrides[get_current_user] = lambda user=current_user: user
                response = await client.get(f"/api/v1/encrypted/{request.id}/encrypted")
                assert response.status_code == 403
    finally:
        app.dependency_overrides.clear()
