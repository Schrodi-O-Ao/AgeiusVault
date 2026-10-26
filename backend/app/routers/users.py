from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.dependencies import get_current_user, get_ip_hmac, get_user_agent
from app.models.session import Session
from app.models.user import User
from datetime import datetime, timezone

router = APIRouter()


@router.get("/me")
async def get_profile(user: User = Depends(get_current_user)):
    return {
        "id": str(user.id),
        "full_name": user.full_name,
        "email": user.email,
        "key_salt": user.key_salt,
        "totp_enabled": user.totp_enabled,
        "role": user.role,
        "department": user.department,
        "manager_id": str(user.manager_id) if user.manager_id else None,
    }


@router.get("/me/sessions")
async def get_sessions(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    sessions = (
        await db.execute(
            select(Session)
            .where(
                Session.user_id == user.id,
                Session.revoked_at.is_(None),
                Session.expires_at >= datetime.now(timezone.utc),
            )
            .order_by(Session.created_at.desc())
        )
    ).scalars().all()

    return {
        "data": [
            {
                "id": str(s.id),
                "device_label": s.device_label,
                "ip_country": s.ip_country,
                "created_at": str(s.created_at),
                "expires_at": str(s.expires_at),
                "last_active_at": str(s.last_active_at) if s.last_active_at else None,
            }
            for s in sessions
        ]
    }


@router.post("/me/sessions/{session_id}/revoke")
async def revoke_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    import uuid as _uuid

    session = (
        await db.execute(
            select(Session).where(
                Session.id == _uuid.UUID(session_id),
                Session.user_id == user.id,
            )
        )
    ).scalars().first()
    if session and not session.revoked_at:
        session.revoked_at = datetime.now(timezone.utc)
        await db.commit()
    return {"success": True}


@router.get("/team")
async def get_team(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    team = (
        await db.execute(
            select(User)
            .where(User.is_active.is_(True))
            .order_by(User.full_name.asc())
        )
    ).scalars().all()

    return {
        "data": [
            {
                "id": str(u.id),
                "full_name": u.full_name,
                "email": u.email,
                "role": u.role,
                "department": u.department,
                "totp_enabled": u.totp_enabled,
            }
            for u in team
        ]
    }
