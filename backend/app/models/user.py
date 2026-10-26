import uuid
from sqlalchemy import Column, String, Boolean, Integer, Text, ForeignKey, Enum, func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String(100), nullable=True)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    password_salt = Column(Text, nullable=True)
    key_salt = Column(Text, nullable=True)

    totp_secret_enc = Column(Text, nullable=True)
    totp_enabled = Column(Boolean, default=False)

    role = Column(
        Enum("STAFF", "MANAGER", "HR_ADMIN", "SYS_ADMIN", name="userrole"),
        nullable=False,
        default="STAFF",
    )
    department = Column(String(100), nullable=True)
    manager_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    rsa_public_key = Column(Text, nullable=True)
    rsa_private_enc = Column(Text, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    last_login_at = Column(TIMESTAMP(timezone=True), nullable=True)

    failed_attempts = Column(Integer, default=0)
    locked_until = Column(TIMESTAMP(timezone=True), nullable=True)
    email_verified = Column(Boolean, default=False)
