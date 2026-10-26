from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, get_ip_hmac, get_user_agent
from app.models.user import User
from app.schemas.delegation import DelegationCreate, DelegationRevoke
from app.security.jwt_handler import JWTHandler
from app.config import settings
from app.services.delegation_service import DelegationService

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
        raise HTTPException(403, "X-Step-Up-Token header is required for delegation creation")
    try:
        return jwt_handler.decode(token)
    except Exception:
        raise HTTPException(403, "Invalid or expired step-up token")


@router.post("")
async def create_delegation(
    body: DelegationCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vault_key = _get_vault_key(request)
    step_up = _get_step_up_payload(request)
    service = DelegationService(db)
    data = await service.create_delegation(
        delegator=user,
        vault_key=vault_key,
        step_up_payload=step_up,
        delegatee_id=body.delegatee_id,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )
    return data


@router.get("")
async def list_delegations(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = DelegationService(db)
    data = await service.list_delegations(user)
    return {"data": data}


@router.post("/{delegation_id}/revoke")
async def revoke_delegation(
    delegation_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = DelegationService(db)
    await service.revoke_delegation(
        delegation_id=delegation_id,
        user=user,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )
    return {"success": True}
