from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enhanced middleware to add comprehensive security headers to all responses.

    This sets production-ready security headers including a proper Content-Security-Policy,
    HSTS, and other security-enhancing headers. The CSP is configurable via environment
    variables for different deployment environments.
    """

    async def dispatch(self, request, call_next):
        response = await call_next(request)

        # Clickjacking protection
        response.headers.setdefault("X-Frame-Options", "DENY")
        
        # Prevent MIME type sniffing
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        
        # Enable browser XSS filter
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        
        # Conservative referrer policy
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        
        # Comprehensive permissions policy (lock down powerful features)
        permissions_policy = [
            "geolocation=()",
            "microphone=()",
            "camera=()",
            "payment=()",
            "usb=()",
            "magnetometer=()",
            "gyroscope=()",
            "accelerometer=()",
        ]
        response.headers.setdefault("Permissions-Policy", ", ".join(permissions_policy))
        
        # Enforce HTTPS for a year (only effective when served over HTTPS)
        # In development, this won't have effect but won't cause issues
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )
        
        # Content-Security-Policy - configurable based on environment
        if settings.DEBUG:
            # Development CSP - more permissive for debugging
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self' http://localhost:* http://127.0.0.1:*; "
                "frame-ancestors 'none';"
            )
        else:
            # Production CSP - strict security
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'nonce-{random}'; "
                "style-src 'self' 'nonce-{random}'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "frame-src 'none';"
            )
        
        response.headers.setdefault("Content-Security-Policy", csp)
        
        # Additional security headers
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        
        return response
