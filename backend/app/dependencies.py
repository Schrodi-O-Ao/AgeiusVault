import uuid
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.session import Session
from app.models.user import User
from app.security.hmac_impl import hmac_sha256
from app.security.jwt_handler import JWTHandler

security = HTTPBearer()
jwt_handler = JWTHandler(settings.JWT_SECRET)


def get_ip_hmac(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return hmac_sha256(settings.server_master_key_bytes, ip.encode()).hexdigest()


def get_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:200]


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    try:
        payload = jwt_handler.decode(credentials.credentials)
        if payload.get("type") != "access":
            raise ValueError()
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid or expired access token"
        ) from exc

    user = (
        (await db.execute(select(User).where(User.id == uuid.UUID(payload["sub"]))))
        .scalars()
        .first()
    )
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    session_id = payload.get("sid")
    if session_id:
        session = (
            (
                await db.execute(
                    select(Session).where(
                        Session.id == uuid.UUID(session_id),
                        Session.user_id == user.id,
                        Session.revoked_at.is_(None),
                        Session.expires_at >= datetime.now(UTC),
                    )
                )
            )
            .scalars()
            .first()
        )
        if not session:
            raise HTTPException(
                status_code=401, detail="Session has expired or been revoked"
            )
        request.state.session_id = str(session.id)
    request.state.token_payload = payload
    request.state.user_id = user.id  # Set user_id for rate limiting middleware

    return user


def require_role(*roles: str):
    """Dependency factory for role-based access control."""

    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _check
