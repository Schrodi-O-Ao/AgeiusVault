"""Simple per-IP rate-limiting middleware for development use.

This middleware holds an in-memory map of client IP -> counters and blocks
clients that exceed the configured request rate for a window. It's suitable
for local development and tests; for production use a distributed store
(Redis) or API gateway rate-limiting is recommended.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Any,
        max_requests: int | None = None,
        window_seconds: int | None = None,
        block_seconds: int | None = None,
    ):
        super().__init__(app)
        self.max_requests = max_requests or settings.RATE_LIMIT_REQUESTS_PER_WINDOW
        self.window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW_SECONDS
        self.block_seconds = block_seconds or settings.RATE_LIMIT_BLOCK_SECONDS
        self.lock = threading.Lock()
        # clients: ip -> {count:int, window_start:float, blocked_until:float}
        self.clients: dict[str, dict] = {}

    async def dispatch(self, request: Request, call_next):
        # Respect X-Forwarded-For when present (useful in tests/proxies)
        xff = request.headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"

        now = time.time()
        with self.lock:
            rec = self.clients.get(ip)
            if rec:
                # If currently blocked, return 429 with Retry-After
                if rec.get("blocked_until", 0) > now:
                    retry_after = int(rec["blocked_until"] - now)
                    return JSONResponse(
                        {"detail": "Too many requests"},
                        status_code=429,
                        headers={"Retry-After": str(retry_after)},
                    )

                # Reset window if expired
                if now - rec["window_start"] >= self.window_seconds:
                    rec["window_start"] = now
                    rec["count"] = 1
                else:
                    rec["count"] += 1
                    if rec["count"] > self.max_requests:
                        rec["blocked_until"] = now + self.block_seconds
                        return JSONResponse(
                            {"detail": "Too many requests"},
                            status_code=429,
                            headers={"Retry-After": str(self.block_seconds)},
                        )
            else:
                # First request for this IP
                self.clients[ip] = {"count": 1, "window_start": now, "blocked_until": 0}

        return await call_next(request)
