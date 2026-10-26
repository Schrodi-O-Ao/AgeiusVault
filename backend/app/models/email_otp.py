import uuid
from sqlalchemy import Column, Integer, Text, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from app.database import Base

class EmailOTP(Base):
    __tablename__ = "email_otps"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    otp_hash = Column(Text, nullable=False)
    purpose = Column(Text, nullable=False)
    
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    used_at = Column(TIMESTAMP(timezone=True))
    attempts = Column(Integer, default=0)

class TOTPPending(Base):
    __tablename__ = "totp_pending"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    token_jti = Column(Text, nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
