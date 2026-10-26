import uuid
from sqlalchemy import Column, String, Boolean, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from app.database import Base


class TOTPBackupCode(Base):
    __tablename__ = "totp_backup_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code_hash = Column(String(255), nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
