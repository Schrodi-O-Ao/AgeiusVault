from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings


class RequestSizeMiddleware(BaseHTTPMiddleware):
    """Middleware to limit request body size for security.

    This prevents denial-of-service attacks through large payload uploads
    and helps protect against memory exhaustion attacks.
    """

    async def dispatch(self, request: Request, call_next):
        # Get content length if available
        content_length = request.headers.get("content-length")

        if content_length:
            try:
                content_length_int = int(content_length)
                max_size = settings.MAX_REQUEST_SIZE_BYTES

                if content_length_int > max_size:
                    return JSONResponse(
                        {
                            "detail": f"Request body too large. Maximum size is {max_size} bytes"
                        },
                        status_code=413,  # Payload Too Large
                    )
            except (ValueError, TypeError):
                # Invalid content-length header, let the request continue
                # and let other middleware handle it
                pass

        return await call_next(request)
