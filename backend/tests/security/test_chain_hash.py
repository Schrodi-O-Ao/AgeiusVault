from datetime import UTC, datetime
from uuid import uuid4

from app.security.chain_hash import GENESIS_HASH, compute_hash, verify_chain


def make_row(previous_hash: str):
    row = {
        "id": uuid4(),
        "user_id": uuid4(),
        "action": "REQUEST_APPROVED",
        "request_id": uuid4(),
        "resource_id": uuid4(),
        "ip_hmac": "abc",
        "user_agent": "pytest",
        "meta_json": None,
        "created_at": datetime.now(UTC),
        "previous_hash": previous_hash,
    }
    row["current_hash"] = compute_hash(**row)
    return row


def test_chain_verifies_valid_rows():
    first = make_row(GENESIS_HASH)
    second = make_row(first["current_hash"])
    is_valid, violations = verify_chain([first, second])
    assert is_valid is True
    assert violations == []


def test_chain_detects_modified_row():
    first = make_row(GENESIS_HASH)
    first["action"] = "REQUEST_REJECTED"
    is_valid, violations = verify_chain([first])
    assert is_valid is False
    assert violations[0].violation_type == "row_modified"


def test_chain_detects_gap_or_deletion():
    first = make_row(GENESIS_HASH)
    second = make_row("f" * 64)
    is_valid, violations = verify_chain([first, second])
    assert is_valid is False
    assert violations[0].violation_type == "gap_or_deletion"
