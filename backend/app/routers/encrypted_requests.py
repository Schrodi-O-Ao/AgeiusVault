"""Accept encrypted request payloads and store their ciphertext and routing metadata."""

import json
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.request import Request
from app.models.user import User
from app.security.crypto_utils import encode_iv_ct
from app.services.audit_service import AuditService
from app.utils.validation import InputValidator, ValidationError

router = APIRouter()

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _validate_envelope(encrypted_data: dict[str, Any]) -> None:
    """Reject malformed browser encryption fields before storing them."""
    required_fields = (
        "encryptedPayload",
        "iv",
        "keyHash",
        "requestType",
        "isAnonymous",
        "wrappedKeys",
    )
    for field in required_fields:
        if field not in encrypted_data:
            raise HTTPException(400, f"Missing required field: {field}")

    payload = encrypted_data["encryptedPayload"]
    if (
        not isinstance(payload, str)
        or len(payload) < 32
        or len(payload) % 2
        or not _HEX_RE.fullmatch(payload)
    ):
        raise HTTPException(
            400, "encryptedPayload must be even-length hexadecimal AES-GCM ciphertext"
        )

    iv = encrypted_data["iv"]
    if not isinstance(iv, str) or not re.fullmatch(r"[0-9a-fA-F]{24}", iv):
        raise HTTPException(400, "iv must be a 12-byte hexadecimal AES-GCM IV")

    if not isinstance(encrypted_data["keyHash"], str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", encrypted_data["keyHash"]
    ):
        raise HTTPException(400, "keyHash must be a 32-byte hexadecimal SHA-256 hash")

    if not isinstance(encrypted_data["isAnonymous"], bool):
        raise HTTPException(400, "isAnonymous must be a boolean")
    if not isinstance(encrypted_data["requestType"], str):
        raise HTTPException(400, "requestType must be a string")

    wrapped_keys = encrypted_data["wrappedKeys"]
    if not isinstance(wrapped_keys, list) or not wrapped_keys:
        raise HTTPException(400, "wrappedKeys must be a non-empty list")
    for item in wrapped_keys:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("userId"), str)
            or not item["userId"]
        ):
            raise HTTPException(400, "Each wrapped key must include a userId")
        wrapped_key = item.get("wrappedKey")
        # The browser currently wraps a 256-bit AES key with RSA-3072, producing 384 bytes.
        if not isinstance(wrapped_key, str) or not re.fullmatch(
            r"[0-9a-fA-F]{768}", wrapped_key
        ):
            raise HTTPException(
                400, "Each wrappedKey must be a 384-byte hexadecimal RSA-3072 value"
            )


@router.post("/encrypted")
async def submit_encrypted_request(
    encrypted_data: dict[str, Any],
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Store a browser-encrypted payload with its initialization vector and approver-wrapped keys."""
    try:
        _validate_envelope(encrypted_data)

        # Validate request type
        request_type = InputValidator.validate_request_type(
            encrypted_data["requestType"]
        )

        # Resolve approver to wrap their key
        approver = await _resolve_approver(
            user, request_type, encrypted_data["isAnonymous"], db
        )

        if not approver:
            raise HTTPException(400, "No approver available for this request type")

        # Filter wrapped keys to only include the actual approver
        wrapped_keys = []
        for key_entry in encrypted_data["wrappedKeys"]:
            if key_entry.get("userId") == str(approver.id):
                wrapped_keys.append(
                    {
                        "user_id": str(approver.id),
                        "wrapped_key": key_entry.get("wrappedKey"),
                    }
                )

        if not wrapped_keys:
            raise HTTPException(400, "No wrapped key provided for the approver")

        # Store the encrypted request body without decrypting it on the server.
        request_obj = Request(
            id=uuid.uuid4(),
            requester_id=user.id if not encrypted_data["isAnonymous"] else None,
            type=request_type,
            payload_enc=encode_iv_ct(
                bytes.fromhex(encrypted_data["iv"]),
                bytes.fromhex(encrypted_data["encryptedPayload"]),
            ),
            dek_enc=wrapped_keys,
            status="PENDING",
            is_anonymous=encrypted_data["isAnonymous"],
            identity_enc=json.dumps(
                {
                    "keyHash": encrypted_data["keyHash"],
                    "clientEncryption": True,
                    "encryptionVersion": "1.0",
                }
            )
            .encode()
            .hex(),
        )

        db.add(request_obj)
        await db.flush()

        # Log the submission in audit chain
        audit = AuditService(db)
        await audit.log(request_obj.id, user.id, "SUBMITTED_ENCRYPTED")
        await db.commit()

        return {
            "success": True,
            "id": str(request_obj.id),
            "type": request_type,
            "status": "PENDING",
            "encrypted": True,
        }

    except HTTPException:
        raise
    except ValidationError as e:
        raise HTTPException(400, str(e))
    except (ValueError, KeyError, TypeError, RuntimeError) as e:
        raise HTTPException(500, f"Failed to process encrypted request: {e!s}")


@router.get("/approvers/{request_type}")
async def get_approver_public_keys(
    request_type: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the selected approver's public key so the browser can wrap the request data key."""
    try:
        # Validate request type
        validated_type = InputValidator.validate_request_type(request_type)

        # Resolve approver based on request type
        approver = await _resolve_approver(user, validated_type, False, db)

        if not approver:
            raise HTTPException(400, "No approver available for this request type")

        # Get approver's public key
        if not approver.rsa_public_key:
            raise HTTPException(400, "Approver does not have a public key")

        # Return public key (PEM format from new implementation)
        try:
            public_key_data = json.loads(approver.rsa_public_key)
        except json.JSONDecodeError:
            # Fallback for legacy format
            public_key_data = {"pem": approver.rsa_public_key, "format": "PEM"}

        return {
            "publicKeys": [
                {
                    "userId": str(approver.id),
                    "publicKey": public_key_data.get("pem", approver.rsa_public_key),
                    "format": public_key_data.get("format", "PEM"),
                }
            ]
        }

    except HTTPException:
        raise
    except ValidationError as e:
        raise HTTPException(400, str(e))
    except (ValueError, KeyError, TypeError, RuntimeError) as e:
        raise HTTPException(500, f"Failed to retrieve approver keys: {e!s}")


@router.get("/{request_id}/encrypted")
async def get_encrypted_request(
    request_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return stored ciphertext and this user's wrapped key after checking request access."""
    try:
        request_obj = await _get_request(request_id, db)

        # Check if user can approve this request
        if not await _can_approve(request_obj, user):
            raise HTTPException(403, "You are not authorized to view this request")

        # Find the wrapped key for this user
        wrapped_key = None
        for key_entry in request_obj.dek_enc or []:
            if key_entry.get("user_id") == str(user.id):
                wrapped_key = key_entry.get("wrapped_key")
                break

        if not wrapped_key:
            raise HTTPException(403, "No encryption key wrapped for you")

        iv, encrypted_payload = request_obj.payload_enc.split(":", 1)
        return {
            "id": str(request_obj.id),
            "type": request_obj.type,
            "encryptedData": encrypted_payload,
            "iv": iv,
            "wrappedKey": wrapped_key,
            "isAnonymous": request_obj.is_anonymous,
            "submittedAt": str(request_obj.submitted_at),
            "status": request_obj.status,
        }

    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, RuntimeError) as e:
        raise HTTPException(500, f"Failed to retrieve encrypted request: {e!s}")


async def _resolve_approver(
    user: User, request_type: str, is_anonymous: bool, db: AsyncSession
) -> User | None:
    """Choose HR for anonymous requests, otherwise prefer the requester's manager and then an active manager."""
    if is_anonymous or request_type == "ANON_HR":
        return await _first_user_by_role("HR_ADMIN", user.id, db)
    if user.manager_id:
        manager = await _get_user(user.manager_id, db)
        if manager:
            return manager
    return await _first_user_by_role("MANAGER", user.id, db)


async def _first_user_by_role(
    role: str, exclude_user_id=None, db: AsyncSession = None
) -> User | None:
    """Return the earliest active user with this role, excluding the requester when specified."""
    if not db:
        return None

    query = select(User).where(User.role == role, User.is_active == True)
    if exclude_user_id:
        query = query.where(User.id != exclude_user_id)

    result = await db.execute(query.order_by(User.created_at.asc()))
    return result.scalars().first()


async def _get_user(user_id, db: AsyncSession = None) -> User | None:
    """Load one user by identifier so request submission can resolve its approver."""
    if not db or not user_id:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalars().first()


async def _get_request(request_id: str, db: AsyncSession) -> Request:
    """Load a request by UUID or return a not-found response for an invalid or absent record."""
    try:
        parsed_id = uuid.UUID(str(request_id))
    except ValueError as error:
        raise HTTPException(404, "Request not found") from error

    result = await db.execute(select(Request).where(Request.id == parsed_id))
    request_obj = result.scalars().first()
    if not request_obj:
        raise HTTPException(404, "Request not found")
    return request_obj


async def _can_approve(request_obj: Request, user: User) -> bool:
    """Allow non-requesters to retrieve ciphertext only when their account has a wrapped data key."""
    if request_obj.requester_id and request_obj.requester_id == user.id:
        return False
    return any(
        entry.get("user_id") == str(user.id) for entry in (request_obj.dek_enc or [])
    )
