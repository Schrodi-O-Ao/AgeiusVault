import os
import re
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


SECRET_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_hex_secret(name: str, value: str) -> str:
    value = value.strip()
    placeholder_patterns = [
        "replace_with", "your_", "placeholder", "change_me", 
        "secret_here", "token_here", "password_here", "example"
    ]
    if any(pattern in value.lower() for pattern in placeholder_patterns):
        raise ValueError(
            f"{name} must be a real secret, not a placeholder. "
            f"Generate it with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if not SECRET_PATTERN.fullmatch(value):
        raise ValueError(
            f"{name} must be exactly 64 hexadecimal characters; "
            'generate it with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return value.lower()


class Settings(BaseSettings):
    DATABASE_URL: str
    SERVER_MASTER_KEY: str
    TOTP_ENCRYPTION_KEY: str = ""  # Separate key for TOTP secrets
    JWT_SECRET: str
    # PBKDF2 iteration policy defaults. These can be overridden in .env for upgrades.
    PBKDF2_ITERATIONS: int = 200_000
    PBKDF2_OTP_ITERATIONS: int = 10_000
    # Rate limiting defaults (per-IP)
    RATE_LIMIT_REQUESTS_PER_WINDOW: int = 60
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_BLOCK_SECONDS: int = 600
    # Rate limiting defaults (per-user)
    RATE_LIMIT_USER_REQUESTS_PER_WINDOW: int = 100
    RATE_LIMIT_USER_WINDOW_SECONDS: int = 60
    RATE_LIMIT_USER_BLOCK_SECONDS: int = 300
    # Token expiration times (in seconds)
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 900  # 15 minutes
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PARTIAL_TOKEN_EXPIRE_SECONDS: int = 300  # 5 minutes
    STEP_UP_TOKEN_EXPIRE_SECONDS: int = 300  # 5 minutes
    # OTP expiration times
    EMAIL_OTP_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_EXPIRE_MINUTES: int = 15
    ACTION_NONCE_EXPIRE_MINUTES: int = 10
    # Security thresholds
    MAX_FAILED_LOGIN_ATTEMPTS: int = 10
    ACCOUNT_LOCKOUT_HOURS: int = 1
    MAX_OTP_ATTEMPTS: int = 5
    MAX_BULK_APPROVAL_REQUESTS: int = 10
    # RSA key size
    RSA_KEY_SIZE: int = 3072  # NIST recommendation for long-term security
    # Request size limits
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10MB
    
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "noreply@aegisvault.local"
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    DEBUG: bool = False

    @field_validator("SERVER_MASTER_KEY")
    @classmethod
    def validate_server_master_key(cls, value: str) -> str:
        return _validate_hex_secret("SERVER_MASTER_KEY", value)

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, value: str) -> str:
        return _validate_hex_secret("JWT_SECRET", value)

    @field_validator("TOTP_ENCRYPTION_KEY")
    @classmethod
    def validate_totp_encryption_key(cls, value: str) -> str:
        if value:  # Optional field
            return _validate_hex_secret("TOTP_ENCRYPTION_KEY", value)
        return value

    @field_validator("SMTP_PASSWORD")
    @classmethod
    def validate_smtp_password(cls, value: str) -> str:
        if not value:
            return value
        placeholder_patterns = [
            "your_", "placeholder", "change_me", "password_here", 
            "app_password_here", "example", "secret"
        ]
        if any(pattern in value.lower() for pattern in placeholder_patterns):
            raise ValueError(
                "SMTP_PASSWORD must be a real password, not a placeholder. "
                "For Gmail, generate an App Password at: https://myaccount.google.com/apppasswords"
            )
        if len(value) < 8:
            raise ValueError("SMTP_PASSWORD must be at least 8 characters long")
        return value

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        placeholder_patterns = [
            "change_me", "dev_password", "password_here", "example",
            "your_", "placeholder", "secret"
        ]
        if any(pattern in value.lower() for pattern in placeholder_patterns):
            raise ValueError(
                "DATABASE_URL contains placeholder password. "
                "Generate a strong password with: openssl rand -base64 32"
            )
        return value

    @property
    def server_master_key_bytes(self) -> bytes:
        return bytes.fromhex(self.SERVER_MASTER_KEY)

    @property
    def jwt_secret_bytes(self) -> bytes:
        return bytes.fromhex(self.JWT_SECRET)

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
        extra="ignore",
    )


settings = Settings()
