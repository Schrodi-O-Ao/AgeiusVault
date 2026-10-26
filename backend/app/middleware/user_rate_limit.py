"""Per-user rate limiting middleware for enhanced security.

This middleware adds rate limiting on a per-user basis in addition to the
existing per-IP rate limiting. This prevents abuse from specific users even
if they use multiple IP addresses or proxy services.
"""
from __future__ import annotations

import time
import threading
from typing import Any, Optional
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings


class UserRateLimitMiddleware(BaseHTTPMiddleware):
    """Per-user rate limiting middleware.
    
    Tracks request counts per user ID and enforces configurable limits.
    This works in conjunction with per-IP rate limiting for defense in depth.
    """
    
    def __init__(
        self, 
        app: Any, 
        max_requests_per_user: int | None = None,
        window_seconds: int | None = None,
        block_seconds: int | None = None
    ):
        super().__init__(app)
        self.max_requests = max_requests_per_user or getattr(settings, 'RATE_LIMIT_USER_REQUESTS_PER_WINDOW', 100)
        self.window_seconds = window_seconds or getattr(settings, 'RATE_LIMIT_USER_WINDOW_SECONDS', 60)
        self.block_seconds = block_seconds or getattr(settings, 'RATE_LIMIT_USER_BLOCK_SECONDS', 300)
        self.lock = threading.Lock()
        # users: user_id -> {count:int, window_start:float, blocked_until:float}
        self.users: dict[str, dict] = {}
        # Track users who have hit limits for monitoring
        self.violations: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Extract user ID from request state if available (set by auth middleware)
        user_id = getattr(request.state, "user_id", None)
        
        # Only rate limit authenticated users
        if not user_id:
            return await call_next(request)
        
        user_id_str = str(user_id)
        now = time.time()
        
        with self.lock:
            user_data = self.users.get(user_id_str)
            
            if user_data:
                # Check if user is currently blocked
                if user_data.get("blocked_until", 0) > now:
                    retry_after = int(user_data["blocked_until"] - now)
                    return JSONResponse(
                        {"detail": "User rate limit exceeded. Try again later."},
                        status_code=429,
                        headers={"Retry-After": str(retry_after)}
                    )
                
                # Reset window if expired
                if now - user_data["window_start"] >= self.window_seconds:
                    user_data["window_start"] = now
                    user_data["count"] = 1
                else:
                    user_data["count"] += 1
                    
                    # Check if limit exceeded
                    if user_data["count"] > self.max_requests:
                        user_data["blocked_until"] = now + self.block_seconds
                        self.violations[user_id_str].append(now)
                        return JSONResponse(
                            {"detail": "User rate limit exceeded. Try again later."},
                            status_code=429,
                            headers={"Retry-After": str(self.block_seconds)}
                        )
            else:
                # First request for this user
                self.users[user_id_str] = {
                    "count": 1,
                    "window_start": now,
                    "blocked_until": 0
                }
        
        return await call_next(request)
    
    def get_user_status(self, user_id: str) -> dict:
        """Get current rate limit status for a specific user.
        
        Useful for monitoring and debugging.
        
        Args:
            user_id: User ID to check
            
        Returns:
            Dictionary with current count, window status, and block status
        """
        with self.lock:
            user_data = self.users.get(user_id)
            if not user_data:
                return {
                    "count": 0,
                    "window_start": None,
                    "blocked_until": None,
                    "is_blocked": False
                }
            
            now = time.time()
            return {
                "count": user_data["count"],
                "window_start": user_data["window_start"],
                "blocked_until": user_data["blocked_until"],
                "is_blocked": user_data["blocked_until"] > now,
                "window_remaining": max(0, self.window_seconds - (now - user_data["window_start"]))
            }
    
    def reset_user(self, user_id: str) -> bool:
        """Reset rate limit for a specific user.
        
        Useful for administrative purposes or when user limits need to be cleared.
        
        Args:
            user_id: User ID to reset
            
        Returns:
            True if user was found and reset, False otherwise
        """
        with self.lock:
            if user_id in self.users:
                del self.users[user_id]
                return True
            return False
    
    def get_violation_count(self, user_id: str) -> int:
        """Get number of rate limit violations for a user.
        
        Args:
            user_id: User ID to check
            
        Returns:
            Number of violations
        """
        with self.lock:
            return len(self.violations.get(user_id, []))