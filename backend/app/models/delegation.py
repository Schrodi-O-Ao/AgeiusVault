import uuid
from sqlalchemy import Column, Boolean, Date, Text, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from app.database import Base


class Delegation(Base):
    __tablename__ = "delegations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    delegator_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    delegatee_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    valid_from = Column(Date, nullable=False)
    valid_until = Column(Date, nullable=False)
    signature = Column(Text, nullable=False)            # RSA signature hex by delegator
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
