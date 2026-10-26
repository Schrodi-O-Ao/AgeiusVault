import uuid

from sqlalchemy import Column, Enum, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID

from app.database import Base


class Approval(Base):
    __tablename__ = "approvals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(
        UUID(as_uuid=True),
        ForeignKey("requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    approver_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    action = Column(
        Enum("APPROVED", "REJECTED", name="approvalaction"),
        nullable=False,
    )
    notes_enc = Column(Text, nullable=True)  # AES-encrypted manager notes
    digital_sig = Column(Text, nullable=False)  # RSA signature hex
    step_nonce = Column(String(64), unique=True, nullable=False)
    acted_at = Column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
