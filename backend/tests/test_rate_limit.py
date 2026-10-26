from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware


def test_rate_limit_blocks_after_threshold():
    app = FastAPI()

    # Use a small threshold for fast tests
    app.add_middleware(RateLimitMiddleware, max_requests=5, window_seconds=60, block_seconds=60)

    @app.get("/ping")
    def ping():
        return {"ok": True}

    client = TestClient(app)

    for _ in range(5):
        r = client.get("/ping")
        assert r.status_code == 200

    r = client.get("/ping")
    assert r.status_code == 429
