import uuid

from sqlalchemy import Boolean, Column, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID

from app.database import Base


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash = Column(String(64), nullable=False)  # SHA-256 of the emailed token
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
