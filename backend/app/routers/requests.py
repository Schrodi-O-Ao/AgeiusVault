from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, get_ip_hmac, get_user_agent
from app.models.user import User
from app.schemas.request import BulkApprovalCreate, RequestAction, RequestCreate
from app.security.jwt_handler import JWTHandler
from app.config import settings
from app.services.request_service import RequestService

router = APIRouter()
jwt_handler = JWTHandler(settings.JWT_SECRET)


def _get_vault_key(request: Request) -> bytes:
    hex_key = request.headers.get("X-Vault-Key")
    if not hex_key:
        raise HTTPException(400, "X-Vault-Key header is required")
    try:
        return bytes.fromhex(hex_key)
    except ValueError:
        raise HTTPException(400, "Invalid X-Vault-Key format")


def _get_step_up_payload(request: Request) -> dict:
    token = request.headers.get("X-Step-Up-Token")
    if not token:
        raise HTTPException(403, "X-Step-Up-Token header is required")
    try:
        return jwt_handler.decode(token)
    except Exception:
        raise HTTPException(403, "Invalid or expired step-up token")


@router.post("")
async def create_request(
    body: RequestCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = RequestService(db)
    return await service.create_request(
        user=user,
        request_type=body.request_type,
        payload=body.payload,
        is_anonymous=body.is_anonymous,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.get("/types")
async def list_request_types(user: User = Depends(get_current_user)):
    return {
        "data": [
            {"id": t, "name": t.replace("_", " ").title(), "slug": t.lower()}
            for t in ["ANNUAL_LEAVE", "SICK_LEAVE", "EXPENSE", "IT_ACCESS", "ANON_HR"]
        ]
    }


@router.get("/stats")
async def request_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = RequestService(db)
    data = await service.dashboard_stats(user)
    return {"data": data}


@router.get("/outbox")
async def my_requests(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = RequestService(db)
    data = await service.list_mine(user)
    return {"data": data}


@router.get("/inbox")
async def pending_inbox(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = RequestService(db)
    data = await service.list_inbox(user)
    return {"data": data}


@router.get("/{request_id}")
async def request_detail(
    request_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vault_key = _get_vault_key(request)
    service = RequestService(db)
    return await service.get_detail(request_id, user, vault_key)


@router.post("/{request_id}/action")
async def request_action(
    request_id: str,
    body: RequestAction,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vault_key = _get_vault_key(request)
    step_up = _get_step_up_payload(request)
    service = RequestService(db)
    return await service.perform_action(
        request_id=request_id,
        user=user,
        vault_key=vault_key,
        step_up_payload=step_up,
        action=body.action,
        nonce=body.nonce,
        notes=body.notes,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/bulk-approve")
async def bulk_approve(
    body: BulkApprovalCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vault_key = _get_vault_key(request)
    service = RequestService(db)
    return await service.bulk_approve(
        user=user,
        vault_key=vault_key,
        request_ids=body.request_ids,
        totp_code=body.totp_code,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.get("/{request_id}/chain")
async def request_chain(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = RequestService(db)
    data = await service.request_chain(request_id, user)
    return {"data": data}


@router.post("/{request_id}/verify")
async def verify_chain(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = RequestService(db)
    return await service.verify_request_chain(request_id, user)
