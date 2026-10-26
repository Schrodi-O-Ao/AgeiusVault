from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, users, audit, requests, delegations, encrypted_requests, anomaly, blockchain
from app.websockets import audit_stream
from app.config import settings
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_size import RequestSizeMiddleware
from app.middleware.user_rate_limit import UserRateLimitMiddleware

app = FastAPI(title="AegisVault API")

# Security middleware stack (order matters)
app.add_middleware(RequestSizeMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(UserRateLimitMiddleware)

# CORS origins are configurable via the CORS_ORIGINS env var.
# Security: Restrict to specific origins in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add a small middleware to set common security headers (CSP, HSTS, etc.)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(requests.router, prefix="/api/v1/requests", tags=["requests"])
app.include_router(encrypted_requests.router, prefix="/api/v1/encrypted", tags=["encrypted_requests"])
app.include_router(delegations.router, prefix="/api/v1/delegations", tags=["delegations"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])
app.include_router(anomaly.router, prefix="/api/v1/anomaly", tags=["anomaly_detection"])
app.include_router(blockchain.router, prefix="/api/v1/blockchain", tags=["blockchain_audit"])

# WebSocket endpoint for real-time audit streaming
app.websocket("/api/v1/audit/stream/{request_id}")(audit_stream.audit_stream_websocket)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
