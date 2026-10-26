import hashlib
from dataclasses import dataclass

GENESIS_HASH = "0" * 64

class ChainHash:
    @staticmethod
    def compute(previous_hash: str, data: bytes) -> str:
        return hashlib.sha256(previous_hash.encode('utf-8') + b"\x00" + data).hexdigest()

def _field(val) -> bytes:
    """Encode one audit field as UTF-8 bytes, using a fixed marker for null values."""
    if val is None:
        return b"<null>"
    return str(val).encode('utf-8')

def compute_hash(id, user_id, action, request_id, resource_id, ip_hmac, user_agent, meta_json, created_at, previous_hash) -> str:
    """Hash the canonical audit fields and prior hash so verification can detect changed or missing links."""
    sep = b"\x00"
    canonical = sep.join([
        _field(id), _field(user_id), _field(action), _field(request_id), _field(resource_id),
        _field(ip_hmac), _field(user_agent), _field(meta_json),
        _field(created_at), _field(previous_hash),
    ])
    return hashlib.sha256(canonical).hexdigest()

@dataclass
class ChainViolation:
    """Details about a problem found in the audit chain."""
    entry_id: str
    violation_type: str
    expected_previous_hash: str
    stored_previous_hash: str
    expected_current_hash: str
    stored_current_hash: str

def verify_chain(rows: list[dict]) -> tuple[bool, list[ChainViolation]]:
    """Check each stored link and recomputed entry hash, returning validity and any mismatches."""
    violations = []
    expected_prev = GENESIS_HASH  # The first entry should point to this
    
    for row in rows:
        stored_prev = row['previous_hash']
        stored_curr = row['current_hash']
        
        # Compute what the hash should be based on the data
        expected_curr = compute_hash(
            id=row['id'],
            user_id=row['user_id'],
            action=row['action'],
            request_id=row.get('request_id'),
            resource_id=row['resource_id'],
            ip_hmac=row['ip_hmac'],
            user_agent=row['user_agent'],
            meta_json=row['meta_json'],
            created_at=row['created_at'],
            previous_hash=stored_prev
        )
        
        # Check if anything's wrong
        if expected_prev != stored_prev or expected_curr != stored_curr:
            violation_type = "gap_or_deletion" if expected_prev != stored_prev else "row_modified"
            violations.append(ChainViolation(
                entry_id=str(row['id']),
                violation_type=violation_type,
                expected_previous_hash=expected_prev,
                stored_previous_hash=stored_prev,
                expected_current_hash=expected_curr,
                stored_current_hash=stored_curr
            ))
            
        expected_prev = stored_curr
        
    return len(violations) == 0, violations
