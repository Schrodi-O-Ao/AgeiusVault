import json
import uuid
from datetime import UTC, date, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.delegation import Delegation
from app.models.user import User
from app.security.crypto_utils import decode_iv_ct
from app.security.rsa_impl import RSAImpl


class DelegationService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_delegation(
        self,
        delegator: User,
        vault_key: bytes,
        step_up_payload: dict[str, Any],
        delegatee_id: str,
        valid_from: date,
        valid_until: date,
        ip_hmac: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        if step_up_payload.get("type") != "step_up" or step_up_payload.get(
            "sub"
        ) != str(delegator.id):
            raise HTTPException(403, "Step-up token is required")

        if valid_until <= valid_from:
            raise HTTPException(400, "Delegation end must be after start")

        delegatee = await self._get_user(delegatee_id)
        if not delegatee:
            raise HTTPException(404, "Delegatee user not found")

        # Sign the delegation with delegator's private key
        private_key = self._decrypt_private_key(delegator, vault_key)
        payload = "|".join(
            [
                str(delegator.id),
                str(delegatee.id),
                valid_from.isoformat(),
                valid_until.isoformat(),
            ]
        ).encode()
        signature = RSAImpl.sign_message(private_key, payload)

        delegation = Delegation(
            id=uuid.uuid4(),
            delegator_id=delegator.id,
            delegatee_id=delegatee.id,
            valid_from=valid_from,
            valid_until=valid_until,
            signature=signature,
            is_active=True,
        )
        self.db.add(delegation)
        await self.db.commit()
        return await self._delegation_to_response(delegation)

    async def list_delegations(self, user: User) -> dict[str, list[dict[str, Any]]]:
        given = (
            (
                await self.db.execute(
                    select(Delegation)
                    .where(Delegation.delegator_id == user.id)
                    .order_by(Delegation.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        received = (
            (
                await self.db.execute(
                    select(Delegation)
                    .where(Delegation.delegatee_id == user.id)
                    .order_by(Delegation.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        return {
            "given": [await self._delegation_to_response(d) for d in given],
            "received": [await self._delegation_to_response(d) for d in received],
        }

    async def revoke_delegation(
        self,
        delegation_id: str,
        user: User,
        ip_hmac: str | None,
        user_agent: str | None,
    ) -> None:
        delegation = (
            (
                await self.db.execute(
                    select(Delegation)
                    .where(Delegation.id == uuid.UUID(delegation_id))
                    .with_for_update()
                )
            )
            .scalars()
            .first()
        )
        if not delegation:
            raise HTTPException(404, "Delegation not found")
        if delegation.delegator_id != user.id:
            raise HTTPException(403, "Only the delegator can revoke this delegation")
        delegation.is_active = False
        await self.db.commit()

    async def _delegation_to_response(self, delegation: Delegation) -> dict[str, Any]:
        delegator = await self._get_user(delegation.delegator_id)
        delegatee = await self._get_user(delegation.delegatee_id)
        today = datetime.now(UTC).date()
        active = (
            delegation.is_active
            and delegation.valid_from <= today
            and delegation.valid_until >= today
        )
        return {
            "id": str(delegation.id),
            "delegator_id": str(delegation.delegator_id),
            "delegator_name": delegator.full_name if delegator else None,
            "delegatee_id": str(delegation.delegatee_id),
            "delegatee_name": delegatee.full_name if delegatee else None,
            "valid_from": str(delegation.valid_from),
            "valid_until": str(delegation.valid_until),
            "is_active": active,
            "created_at": str(delegation.created_at),
        }

    async def _get_user(self, user_id) -> User | None:
        try:
            parsed = uuid.UUID(str(user_id))
        except ValueError:
            return None
        return (
            (await self.db.execute(select(User).where(User.id == parsed)))
            .scalars()
            .first()
        )

    def _decrypt_private_key(self, user: User, vault_key: bytes) -> dict:
        try:
            iv, ct = decode_iv_ct(user.rsa_private_enc)
            return RSAImpl.decrypt_private_key(iv, ct, vault_key)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise HTTPException(400, "Invalid vault key")
