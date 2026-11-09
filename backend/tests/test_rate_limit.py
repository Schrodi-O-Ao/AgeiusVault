from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import settings
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.user_rate_limit import UserRateLimitMiddleware
from app.security.jwt_handler import JWTHandler


def test_rate_limit_blocks_after_threshold():
    app = FastAPI()

    # Use a small threshold for fast tests
    app.add_middleware(
        RateLimitMiddleware, max_requests=5, window_seconds=60, block_seconds=60
    )

    @app.get("/ping")
    def ping():
        return {"ok": True}

    client = TestClient(app)

    for _ in range(5):
        r = client.get("/ping")
        assert r.status_code == 200

    r = client.get("/ping")
    assert r.status_code == 429


def test_user_rate_limit_blocks_after_threshold():
    app = FastAPI()

    # Use a small threshold for fast tests
    app.add_middleware(
        UserRateLimitMiddleware,
        max_requests_per_user=3,
        window_seconds=60,
        block_seconds=60,
    )

    @app.get("/user-ping")
    def user_ping():
        return {"ok": True}

    client = TestClient(app)
    jwt_handler = JWTHandler(settings.JWT_SECRET)
    token_user1 = jwt_handler.encode({"sub": "user-123", "type": "access"}, 3600)
    token_user2 = jwt_handler.encode({"sub": "user-456", "type": "access"}, 3600)

    headers1 = {"Authorization": f"Bearer {token_user1}"}
    headers2 = {"Authorization": f"Bearer {token_user2}"}

    for _ in range(3):
        r = client.get("/user-ping", headers=headers1)
        assert r.status_code == 200

    # 4th request from user1 should be blocked
    r = client.get("/user-ping", headers=headers1)
    assert r.status_code == 429

    # user2 should still be allowed
    r = client.get("/user-ping", headers=headers2)
    assert r.status_code == 200
