from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, get_ip_hmac, get_user_agent
from app.models.user import User
from app.schemas.auth import (
    EmailVerifyRequest,
    ForgotPasswordRequest,
    LoginRequest,
    RefreshRequest,
    ResendOTPRequest,
    ResetPasswordRequest,
    SignupRequest,
    TOTPEnableRequest,
    TOTPVerifyRequest,
)
from app.schemas.request import StepUpVerify
from app.services.auth_service import AuthService

router = APIRouter()


def _get_vault_key(request: Request) -> bytes:
    """Extract and validate vault key from request headers."""
    hex_key = request.headers.get("X-Vault-Key")
    if not hex_key:
        raise HTTPException(400, "X-Vault-Key header is required")
    try:
        return bytes.fromhex(hex_key)
    except ValueError:
        raise HTTPException(400, "Invalid X-Vault-Key format")


@router.post("/signup")
async def signup(
    body: SignupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.register_user(
        full_name=body.full_name,
        email=body.email,
        password=body.password,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


# Backwards-compat alias
@router.post("/register")
async def register_alias(
    body: SignupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.register_user(
        full_name=body.full_name,
        email=body.email,
        password=body.password,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/login")
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.login_step1(
        email=body.email,
        password=body.password,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/verify-totp")
async def verify_totp(
    body: TOTPVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    vault_key = _get_vault_key(request)
    service = AuthService(db)
    return await service.login_step2(
        partial_token=body.partial_token,
        code=body.totp_code,
        vault_key=vault_key,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/email-verify")
async def verify_email(
    body: EmailVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.verify_email(
        email=body.email,
        code=body.code,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/resend-otp")
async def resend_otp(
    body: ResendOTPRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.resend_verification_otp(email=body.email)


@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.request_password_reset(
        email=body.email,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/reset-password")
async def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.complete_password_reset(
        token=body.token,
        new_password=body.new_password,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/refresh")
async def refresh(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    return await service.refresh_session(
        refresh_token=body.refresh_token,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/setup-totp")
async def setup_totp(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vault_key = _get_vault_key(request)
    service = AuthService(db)
    return await service.setup_totp(user, vault_key)


@router.post("/enable-totp")
async def enable_totp(
    body: TOTPEnableRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vault_key = _get_vault_key(request)
    service = AuthService(db)
    return await service.enable_totp(
        user=user,
        code=body.totp_code,
        vault_key=vault_key,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/step-up")
async def step_up(
    body: StepUpVerify,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vault_key = _get_vault_key(request)
    service = AuthService(db)
    return await service.issue_step_up_token(
        user=user,
        request_id=body.request_id,
        action_type=body.action_type,
        code=body.totp_code,
        vault_key=vault_key,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = AuthService(db)
    session_id = getattr(request.state, "session_id", None)
    return await service.logout_session(
        user=user,
        session_id=session_id,
        ip_hmac=get_ip_hmac(request),
        user_agent=get_user_agent(request),
    )
