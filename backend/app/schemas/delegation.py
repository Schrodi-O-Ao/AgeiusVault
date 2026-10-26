from datetime import date

from pydantic import BaseModel


class DelegationCreate(BaseModel):
    delegatee_id: str
    valid_from: date
    valid_until: date


class DelegationRevoke(BaseModel):
    reason: str | None = None
