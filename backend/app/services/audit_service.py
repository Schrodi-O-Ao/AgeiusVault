import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_chain import AuditChain


GENESIS_HASH = "0" * 64


def _compute_chain_hash(
    prev_hash: str,
    request_id: str,
    actor_id: str | None,
    action: str,
    timestamp: str,
) -> str:
    raw = f"{prev_hash}|{request_id}|{actor_id or 'NULL'}|{action}|{timestamp}"
    return hashlib.sha256(raw.encode()).hexdigest()


class AuditService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        request_id: uuid.UUID,
        actor_id: uuid.UUID | None,
        action: str,
    ) -> AuditChain:
        """Append an entry to the audit chain for a given request."""
        # Get the last entry for this request to compute chain
        last = (
            await self.db.execute(
                select(AuditChain)
                .where(AuditChain.request_id == request_id)
                .order_by(AuditChain.step_index.desc())
                .limit(1)
            )
        ).scalars().first()

        step_index = (last.step_index + 1) if last else 0
        prev_hash = last.chain_hash if last else GENESIS_HASH
        now = datetime.now(timezone.utc)

        chain_hash = _compute_chain_hash(
            prev_hash=prev_hash,
            request_id=str(request_id),
            actor_id=str(actor_id) if actor_id else None,
            action=action,
            timestamp=now.isoformat(),
        )

        entry = AuditChain(
            id=uuid.uuid4(),
            request_id=request_id,
            step_index=step_index,
            actor_id=actor_id,
            action=action,
            prev_hash=prev_hash,
            chain_hash=chain_hash,
            recorded_at=now,
        )
        self.db.add(entry)
        await self.db.flush()
        return entry

    async def get_chain(self, request_id: uuid.UUID) -> list[AuditChain]:
        """Retrieve the full audit chain for a request."""
        result = await self.db.execute(
            select(AuditChain)
            .where(AuditChain.request_id == request_id)
            .order_by(AuditChain.step_index.asc())
        )
        return list(result.scalars().all())

    async def verify_chain(self, request_id: uuid.UUID) -> dict[str, Any]:
        """Replay the chain and verify integrity."""
        chain = await self.get_chain(request_id)
        violations: list[dict[str, str]] = []
        expected_prev = GENESIS_HASH

        for entry in chain:
            # Check previous hash link
            if entry.prev_hash != expected_prev:
                violations.append({
                    "entry_id": str(entry.id),
                    "type": "gap_or_deletion",
                    "expected_prev": expected_prev,
                    "stored_prev": entry.prev_hash,
                })

            # Recompute and verify current hash
            expected_hash = _compute_chain_hash(
                prev_hash=entry.prev_hash,
                request_id=str(entry.request_id),
                actor_id=str(entry.actor_id) if entry.actor_id else None,
                action=entry.action,
                timestamp=entry.recorded_at.isoformat(),
            )
            if entry.chain_hash != expected_hash:
                violations.append({
                    "entry_id": str(entry.id),
                    "type": "row_modified",
                    "expected_hash": expected_hash,
                    "stored_hash": entry.chain_hash,
                })

            expected_prev = entry.chain_hash

        return {
            "is_valid": len(violations) == 0,
            "entries_checked": len(chain),
            "violations": violations,
        }
