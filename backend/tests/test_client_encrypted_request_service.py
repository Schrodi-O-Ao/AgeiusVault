"""Tests that request details route browser-encrypted bodies back to the browser."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.services.request_service import RequestService


class EmptyApprovals:
    def scalars(self):
        return self

    def all(self):
        return []


@pytest.mark.asyncio
@pytest.mark.parametrize("metadata_format", ["plain", "hex"])
async def test_client_encrypted_detail_skips_server_decryption(monkeypatch, metadata_format):
    metadata = json.dumps({"clientEncryption": True, "encryptionVersion": "1.0"})
    if metadata_format == "hex":
        metadata = metadata.encode().hex()
    request = SimpleNamespace(
        id="request-id", requester_id=None, type="ANON_HR", status="PENDING",
        is_anonymous=True, identity_enc=metadata, submitted_at="submitted", updated_at="updated",
        payload_enc="unused", approvals=[],
    )
    user = SimpleNamespace(id="approver-id")
    db = Mock()
    db.execute = AsyncMock(return_value=EmptyApprovals())
    service = RequestService(db)
    monkeypatch.setattr(service, "_get_request", AsyncMock(return_value=request))
    monkeypatch.setattr(service, "_decrypt_dek", AsyncMock(side_effect=AssertionError("server must not decrypt")))
    monkeypatch.setattr(service, "issue_nonce", AsyncMock(return_value="nonce"))
    monkeypatch.setattr(service, "_can_approve", AsyncMock(return_value=True))

    detail = await service.get_detail("request-id", user, b"vault-key")
    assert detail["is_encrypted"] is True
    assert detail["payload"] is None
    assert detail["can_act"] is True


def test_request_summary_recognizes_hex_encoded_client_metadata():
    metadata = json.dumps({"clientEncryption": True}).encode().hex()
    request = SimpleNamespace(
        id="request-id", type="ANNUAL_LEAVE", status="PENDING", is_anonymous=False,
        identity_enc=metadata, submitted_at="submitted", updated_at="updated", requester_id="requester-id",
    )
    service = RequestService(Mock())
    assert service._request_summary(request)["is_encrypted"] is True
