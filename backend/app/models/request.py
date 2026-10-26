import uuid

from sqlalchemy import Boolean, Column, Enum, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID

from app.database import Base


class Request(Base):
    __tablename__ = "requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    requester_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    type = Column(
        Enum(
            "ANNUAL_LEAVE",
            "SICK_LEAVE",
            "EXPENSE",
            "IT_ACCESS",
            "ANON_HR",
            name="requesttype",
        ),
        nullable=False,
    )
    payload_enc = Column(Text, nullable=False)  # AES-encrypted JSON payload (iv:ct hex)
    dek_enc = Column(JSONB, nullable=False)  # JSON list of wrapped DEKs per user
    status = Column(
        Enum("PENDING", "APPROVED", "REJECTED", "CANCELLED", name="requeststatus"),
        nullable=False,
        default="PENDING",
    )
    is_anonymous = Column(Boolean, default=False)
    identity_enc = Column(Text, nullable=True)  # Encrypted identity for anon reports
    submitted_at = Column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
