import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.audit_chain import AuditChain
from app.models.user import User
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("/logs")
async def list_audit_logs(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List recent audit chain entries across all requests."""
    result = await db.execute(
        select(AuditChain).order_by(AuditChain.recorded_at.desc()).limit(50)
    )
    entries = result.scalars().all()
    return {
        "data": [
            {
                "id": str(e.id),
                "request_id": str(e.request_id),
                "step_index": e.step_index,
                "actor_id": str(e.actor_id) if e.actor_id else None,
                "action": e.action,
                "chain_hash": e.chain_hash,
                "prev_hash": e.prev_hash,
                "recorded_at": str(e.recorded_at),
            }
            for e in entries
        ]
    }


@router.get("/{request_id}/chain")
async def get_request_chain(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    audit = AuditService(db)
    chain = await audit.get_chain(uuid.UUID(request_id))
    return {
        "data": [
            {
                "id": str(e.id),
                "step_index": e.step_index,
                "actor_id": str(e.actor_id) if e.actor_id else None,
                "action": e.action,
                "chain_hash": e.chain_hash,
                "prev_hash": e.prev_hash,
                "recorded_at": str(e.recorded_at),
            }
            for e in chain
        ]
    }


@router.post("/{request_id}/verify")
async def verify_chain(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    audit = AuditService(db)
    result = await audit.verify_chain(uuid.UUID(request_id))
    return result
