import logging
from email.message import EmailMessage

import aiosmtplib

from app.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    @staticmethod
    async def send_email(to_email: str, subject: str, body: str):
        message = EmailMessage()
        message["From"] = settings.SMTP_FROM_EMAIL
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)

        # Check if settings.SMTP_PASSWORD is empty or not configured
        if not settings.SMTP_PASSWORD:
            logger.warning(
                f"SMTP not configured (no password). Would send email to: {to_email}"
            )
            # Don't log email content even in debug mode for security
            return

        try:
            await aiosmtplib.send(
                message,
                hostname=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                username=settings.SMTP_USER,
                password=settings.SMTP_PASSWORD,
                use_tls=True,
            )
            logger.info(f"Email sent successfully to {to_email}")
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            # Don't log email content even in debug mode for security
            raise
