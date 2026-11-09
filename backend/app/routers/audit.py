import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.models.audit_chain import AuditChain
from app.models.request import Request
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.request_service import RequestService

router = APIRouter()


@router.get("/logs")
async def list_audit_logs(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("HR_ADMIN", "SYS_ADMIN")),
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
    try:
        req_uuid = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(404, "Invalid request ID")

    req = (
        (await db.execute(select(Request).where(Request.id == req_uuid)))
        .scalars()
        .first()
    )
    if not req:
        raise HTTPException(404, "Request not found")

    service = RequestService(db)
    if (
        user.role not in ("HR_ADMIN", "SYS_ADMIN")
        and req.requester_id != user.id
        and not await service._can_approve(req, user)
    ):
        raise HTTPException(403, "You are not authorized to view this audit chain")

    audit = AuditService(db)
    chain = await audit.get_chain(req_uuid)
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
    try:
        req_uuid = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(404, "Invalid request ID")

    req = (
        (await db.execute(select(Request).where(Request.id == req_uuid)))
        .scalars()
        .first()
    )
    if not req:
        raise HTTPException(404, "Request not found")

    service = RequestService(db)
    if (
        user.role not in ("HR_ADMIN", "SYS_ADMIN")
        and req.requester_id != user.id
        and not await service._can_approve(req, user)
    ):
        raise HTTPException(403, "You are not authorized to verify this audit chain")

    audit = AuditService(db)
    result = await audit.verify_chain(req_uuid)
    return result
