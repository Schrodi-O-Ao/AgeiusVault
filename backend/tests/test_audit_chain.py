"""
Audit chain integrity verification tests.
Tests that the audit chain maintains cryptographic integrity and detects tampering.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime

from app.security.chain_hash import ChainHash


class TestChainHashIntegrity:
    """Test cryptographic chain hash integrity."""

    def test_chain_hash_basic(self):
        """Test basic chain hash computation."""
        previous_hash = "0" * 64  # Genesis block
        data = b"test audit entry"

        chain_hash = ChainHash.compute(previous_hash, data)

        # Should be a valid SHA-256 hash (64 hex characters)
        assert len(chain_hash) == 64
        assert all(c in "0123456789abcdef" for c in chain_hash)

    def test_chain_hash_deterministic(self):
        """Test that chain hash is deterministic."""
        previous_hash = "a" * 64
        data = b"deterministic test"

        hash1 = ChainHash.compute(previous_hash, data)
        hash2 = ChainHash.compute(previous_hash, data)

        assert hash1 == hash2

    def test_chain_hash_previous_depends(self):
        """Test that chain hash depends on previous hash."""
        data = b"same data"
        previous1 = "1" * 64
        previous2 = "2" * 64

        hash1 = ChainHash.compute(previous1, data)
        hash2 = ChainHash.compute(previous2, data)

        assert hash1 != hash2

    def test_chain_hash_data_depends(self):
        """Test that chain hash depends on data."""
        previous_hash = "0" * 64
        data1 = b"different data 1"
        data2 = b"different data 2"

        hash1 = ChainHash.compute(previous_hash, data1)
        hash2 = ChainHash.compute(previous_hash, data2)

        assert hash1 != hash2

    def test_chain_hash_empty_data(self):
        """Test chain hash with empty data."""
        previous_hash = "0" * 64
        data = b""

        chain_hash = ChainHash.compute(previous_hash, data)

        assert len(chain_hash) == 64
        assert all(c in "0123456789abcdef" for c in chain_hash)

    def test_chain_hash_large_data(self):
        """Test chain hash with large data."""
        previous_hash = "0" * 64
        data = b"A" * 10000  # 10KB of data

        chain_hash = ChainHash.compute(previous_hash, data)

        assert len(chain_hash) == 64


class TestAuditChainIntegrity:
    """Test audit chain integrity verification."""

    def test_audit_chain_genesis(self):
        """Test genesis block creation."""
        genesis_data = b"genesis audit entry"
        genesis_hash = ChainHash.compute("0" * 64, genesis_data)

        # Genesis block should have a valid hash
        assert len(genesis_hash) == 64
        assert genesis_hash != "0" * 64

    def test_audit_chain_linking(self):
        """Test that audit chain entries are properly linked."""
        entries = [b"entry 1", b"entry 2", b"entry 3"]

        previous_hash = "0" * 64
        chain = []

        for entry in entries:
            chain_hash = ChainHash.compute(previous_hash, entry)
            chain.append(
                {"data": entry, "previous_hash": previous_hash, "hash": chain_hash}
            )
            previous_hash = chain_hash

        # Verify chain integrity
        for i in range(len(chain)):
            if i == 0:
                assert chain[i]["previous_hash"] == "0" * 64
            else:
                assert chain[i]["previous_hash"] == chain[i - 1]["hash"]

    def test_audit_chain_tampering_detection(self):
        """Test that tampering is detected in audit chain."""
        entries = [b"entry 1", b"entry 2", b"entry 3"]

        previous_hash = "0" * 64
        chain = []

        # Build chain
        for entry in entries:
            chain_hash = ChainHash.compute(previous_hash, entry)
            chain.append(
                {"data": entry, "previous_hash": previous_hash, "hash": chain_hash}
            )
            previous_hash = chain_hash

        # Tamper with middle entry
        original_data = chain[1]["data"]
        chain[1]["data"] = b"tampered entry"

        # Recompute hash for tampered entry
        chain[1]["hash"] = ChainHash.compute(
            chain[1]["previous_hash"], chain[1]["data"]
        )

        # Verify that chain is now broken
        # The next entry's previous_hash should not match the tampered entry's hash
        assert chain[2]["previous_hash"] != chain[1]["hash"]

        # Restore original data
        chain[1]["data"] = original_data
        chain[1]["hash"] = ChainHash.compute(
            chain[1]["previous_hash"], chain[1]["data"]
        )

        # Chain should be valid again
        assert chain[2]["previous_hash"] == chain[1]["hash"]

    def test_audit_chain_verification(self):
        """Test complete audit chain verification."""
        entries = [b"entry 1", b"entry 2", b"entry 3", b"entry 4"]

        previous_hash = "0" * 64
        chain = []

        # Build chain
        for entry in entries:
            chain_hash = ChainHash.compute(previous_hash, entry)
            chain.append(
                {"data": entry, "previous_hash": previous_hash, "hash": chain_hash}
            )
            previous_hash = chain_hash

        # Verify entire chain
        is_valid = True
        for i in range(len(chain)):
            if i == 0:
                if chain[i]["previous_hash"] != "0" * 64:
                    is_valid = False
                    break
            else:
                if chain[i]["previous_hash"] != chain[i - 1]["hash"]:
                    is_valid = False
                    break

            # Verify hash computation
            computed_hash = ChainHash.compute(
                chain[i]["previous_hash"], chain[i]["data"]
            )
            if computed_hash != chain[i]["hash"]:
                is_valid = False
                break

        assert is_valid is True

    def test_audit_chain_branch_detection(self):
        """Test that chain branching is detected."""
        entries = [b"entry 1", b"entry 2"]

        # Build main chain
        previous_hash = "0" * 64
        main_chain = []

        for entry in entries:
            chain_hash = ChainHash.compute(previous_hash, entry)
            main_chain.append(
                {"data": entry, "previous_hash": previous_hash, "hash": chain_hash}
            )
            previous_hash = chain_hash

        # Create a branch from entry 1
        branch_entry = b"branch entry"
        branch_hash = ChainHash.compute(main_chain[0]["hash"], branch_entry)

        # Branch should have different hash than main chain entry 2
        assert branch_hash != main_chain[1]["hash"]

        # Both should have same previous hash
        assert main_chain[1]["previous_hash"] == main_chain[0]["hash"]
        # Branch's previous hash should also point to entry 1
        # (This would be verified in the branch entry's previous_hash field)


class TestAuditChainWithMetadata:
    """Test audit chain with structured metadata."""

    def test_chain_hash_with_json_metadata(self):
        """Test chain hash with JSON metadata."""
        previous_hash = "0" * 64
        metadata = {
            "user_id": str(uuid.uuid4()),
            "action": "create_request",
            "timestamp": datetime.now(UTC).isoformat(),
            "ip_address": "192.168.1.1",
        }

        data = json.dumps(metadata).encode()
        chain_hash = ChainHash.compute(previous_hash, data)

        assert len(chain_hash) == 64

    def test_chain_hash_with_mixed_data(self):
        """Test chain hash with mixed data types."""
        previous_hash = "0" * 64

        # Test with different data types
        test_cases = [
            b"binary data",
            b"unicode string",
            json.dumps({"key": "value"}).encode(),
            hashlib.sha256(b"pre-hashed").digest(),
        ]

        for data in test_cases:
            chain_hash = ChainHash.compute(previous_hash, data)
            assert len(chain_hash) == 64
            assert all(c in "0123456789abcdef" for c in chain_hash)


class TestAuditChainPerformance:
    """Test audit chain performance with larger chains."""

    def test_large_chain_integrity(self):
        """Test integrity verification with a large chain."""
        # Create a chain with 100 entries
        previous_hash = "0" * 64
        chain = []

        for i in range(100):
            data = f"entry {i}".encode()
            chain_hash = ChainHash.compute(previous_hash, data)
            chain.append(
                {"data": data, "previous_hash": previous_hash, "hash": chain_hash}
            )
            previous_hash = chain_hash

        # Verify chain integrity
        is_valid = True
        for i in range(len(chain)):
            if i > 0 and chain[i]["previous_hash"] != chain[i - 1]["hash"]:
                is_valid = False
                break

            computed_hash = ChainHash.compute(
                chain[i]["previous_hash"], chain[i]["data"]
            )
            if computed_hash != chain[i]["hash"]:
                is_valid = False
                break

        assert is_valid is True

    def test_chain_hash_consistency(self):
        """Test that chain hash produces consistent results across multiple calls."""
        previous_hash = "a" * 64
        data = b"consistency test"

        # Compute hash multiple times
        hashes = [ChainHash.compute(previous_hash, data) for _ in range(10)]

        # All hashes should be identical
        assert all(h == hashes[0] for h in hashes)
