import uuid

from sqlalchemy import Column, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID

from app.database import Base


class Session(Base):
    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    refresh_token_hmac = Column(Text, nullable=False)

    created_at = Column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    revoked_at = Column(TIMESTAMP(timezone=True))

    device_label = Column(Text)
    ip_country = Column(Text)
    last_active_at = Column(TIMESTAMP(timezone=True))
