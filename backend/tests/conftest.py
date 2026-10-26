import os
import sys

import pytest

# Ensure the backend package root is importable for tests
ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.main import app
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.user_rate_limit import UserRateLimitMiddleware


def _clear_rate_limiters():
    curr = getattr(app, "middleware_stack", None)
    while curr is not None and hasattr(curr, "app"):
        if isinstance(curr, RateLimitMiddleware):
            with curr.lock:
                curr.clients.clear()
        elif isinstance(curr, UserRateLimitMiddleware):
            with curr.lock:
                curr.users.clear()
                curr.violations.clear()
        curr = curr.app


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """Reset rate limiter state before and after each test to ensure test isolation."""
    _clear_rate_limiters()
    yield
    _clear_rate_limiters()
