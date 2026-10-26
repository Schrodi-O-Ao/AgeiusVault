from typing import Any

from pydantic import BaseModel, Field


class RequestCreate(BaseModel):
    request_type: str = Field(min_length=1, max_length=30)
    payload: dict[str, Any]
    is_anonymous: bool = False


class RequestAction(BaseModel):
    action: str = Field(min_length=1, max_length=20)
    nonce: str
    notes: str | None = None


class BulkApprovalCreate(BaseModel):
    request_ids: list[str] = Field(min_length=1, max_length=10)
    totp_code: str = Field(min_length=6, max_length=6)


class StepUpVerify(BaseModel):
    request_id: str
    action_type: str
    totp_code: str = Field(min_length=6, max_length=6)
