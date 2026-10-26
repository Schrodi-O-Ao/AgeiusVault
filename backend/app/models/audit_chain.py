import uuid
from sqlalchemy import Column, Integer, String, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from app.database import Base


class AuditChain(Base):
    __tablename__ = "audit_chain"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(UUID(as_uuid=True), ForeignKey("requests.id", ondelete="CASCADE"), nullable=False)
    step_index = Column(Integer, nullable=False)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(50), nullable=False)
    prev_hash = Column(String(64), nullable=False)      # SHA-256 of previous row
    chain_hash = Column(String(64), nullable=False)     # SHA-256(prev_hash | request_id | actor_id | action | timestamp)
    recorded_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
