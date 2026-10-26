"""
WebSocket handler for real-time audit chain streaming.

This enables clients to receive live updates about audit chain entries,
making the system more dynamic and providing immediate visibility into
request processing.
"""

import json
import uuid
from datetime import UTC

from fastapi import (
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    WebSocketException,
)
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.request import Request
from app.models.user import User


class AuditStreamManager:
    """Manages WebSocket connections for audit streaming."""

    def __init__(self):
        # request_id -> set of WebSocket connections
        self.active_connections: dict[str, set[WebSocket]] = {}
        # user_id -> set of WebSocket connections (for user's requests)
        self.user_connections: dict[str, set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, request_id: str, user_id: str):
        """Connect a WebSocket to a specific request's audit stream."""
        await websocket.accept()

        if request_id not in self.active_connections:
            self.active_connections[request_id] = set()
        self.active_connections[request_id].add(websocket)

        if user_id not in self.user_connections:
            self.user_connections[user_id] = set()
        self.user_connections[user_id].add(websocket)

    def disconnect(self, websocket: WebSocket, request_id: str, user_id: str):
        """Disconnect a WebSocket from the audit stream."""
        if request_id in self.active_connections:
            self.active_connections[request_id].discard(websocket)
            if not self.active_connections[request_id]:
                del self.active_connections[request_id]

        if user_id in self.user_connections:
            self.user_connections[user_id].discard(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]

    async def broadcast_to_request(self, request_id: str, message: dict):
        """Broadcast a message to all connections watching a specific request."""
        if request_id in self.active_connections:
            disconnected = set()
            for connection in self.active_connections[request_id]:
                try:
                    await connection.send_json(message)
                except (WebSocketDisconnect, RuntimeError, ConnectionError, OSError):
                    disconnected.add(connection)

            # Clean up disconnected connections
            for connection in disconnected:
                self.active_connections[request_id].discard(connection)

    async def broadcast_to_user(self, user_id: str, message: dict):
        """Broadcast a message to all connections for a specific user."""
        if user_id in self.user_connections:
            disconnected = set()
            for connection in self.user_connections[user_id]:
                try:
                    await connection.send_json(message)
                except (WebSocketDisconnect, RuntimeError, ConnectionError, OSError):
                    disconnected.add(connection)

            # Clean up disconnected connections
            for connection in disconnected:
                self.user_connections[user_id].discard(connection)

    async def broadcast_global(self, message: dict):
        """Broadcast a message to all connected clients."""
        all_connections = set()
        for connections in self.active_connections.values():
            all_connections.update(connections)

        disconnected = set()
        for connection in all_connections:
            try:
                await connection.send_json(message)
            except (WebSocketDisconnect, RuntimeError, ConnectionError, OSError):
                disconnected.add(connection)

        # Clean up disconnected connections
        for request_id, connections in self.active_connections.items():
            self.active_connections[request_id] = connections - disconnected
            if not self.active_connections[request_id]:
                del self.active_connections[request_id]


# Global stream manager instance
stream_manager = AuditStreamManager()


async def get_current_user_from_token(
    token: str = Query(...), db: AsyncSession = Depends(get_db)
) -> User:
    """Get current user from WebSocket token."""
    from app.config import settings
    from app.security.jwt_handler import JWTHandler

    try:
        jwt_handler = JWTHandler(settings.JWT_SECRET)
        payload = jwt_handler.decode(token)

        if payload.get("type") != "access":
            raise ValueError("Invalid token type")

        user = (
            (await db.execute(select(User).where(User.id == uuid.UUID(payload["sub"]))))
            .scalars()
            .first()
        )

        if not user:
            raise ValueError("User not found")

        # Check session validity
        session_id = payload.get("sid")
        if session_id:
            from datetime import datetime

            from app.models.session import Session

            session = (
                (
                    await db.execute(
                        select(Session).where(
                            Session.id == uuid.UUID(session_id),
                            Session.user_id == user.id,
                            Session.revoked_at.is_(None),
                            Session.expires_at >= datetime.now(UTC),
                        )
                    )
                )
                .scalars()
                .first()
            )

            if not session:
                raise ValueError("Session expired or revoked")

        return user
    except (ValueError, KeyError, TypeError, HTTPException) as e:
        raise ValueError(f"Invalid token: {e!s}") from e


async def audit_stream_websocket(
    websocket: WebSocket,
    request_id: str,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """
    WebSocket endpoint for real-time audit chain streaming.

    Clients can connect to receive live updates about audit chain entries
    for a specific request.
    """
    # Authenticate user
    try:
        user = await get_current_user_from_token(token, db)
    except ValueError as e:
        await websocket.close(code=1008, reason=str(e))
        return

    # Verify user has access to this request
    try:
        request = (
            (
                await db.execute(
                    select(Request).where(Request.id == uuid.UUID(request_id))
                )
            )
            .scalars()
            .first()
        )

        if not request:
            await websocket.close(code=1008, reason="Request not found")
            return

        # Check access permissions
        has_access = (
            request.requester_id == user.id  # Requester
            or await _can_approve_request(request, user, db)  # Approver
            or user.role in ["HR_ADMIN", "SYS_ADMIN"]  # Admin
        )

        if not has_access:
            await websocket.close(code=1008, reason="Access denied")
            return

    except (ValueError, TypeError, SQLAlchemyError, RuntimeError) as e:
        await websocket.close(code=1008, reason=f"Access check failed: {e!s}")
        return

    # Connect to stream
    await stream_manager.connect(websocket, request_id, str(user.id))

    try:
        # Send initial audit chain
        await _send_initial_audit_chain(websocket, request_id, db)

        # Keep connection alive and handle incoming messages
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            # Handle client messages (ping/pong, subscribe to updates, etc.)
            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif message.get("type") == "subscribe_updates":
                # Client wants to receive updates (already subscribed by default)
                await websocket.send_json(
                    {"type": "subscribed", "request_id": request_id}
                )

    except WebSocketDisconnect:
        stream_manager.disconnect(websocket, request_id, str(user.id))
    except (
        WebSocketException,
        RuntimeError,
        ConnectionError,
        OSError,
        ValueError,
    ) as e:
        await websocket.close(code=1011, reason=str(e))
        stream_manager.disconnect(websocket, request_id, str(user.id))


async def _can_approve_request(request: Request, user: User, db: AsyncSession) -> bool:
    """Check if user can approve the request."""
    # Check if user has a wrapped key
    for key_entry in request.dek_enc or []:
        if key_entry.get("user_id") == str(user.id):
            return True

    # Additional approval logic
    if request.requester_id:
        requester = (
            (await db.execute(select(User).where(User.id == request.requester_id)))
            .scalars()
            .first()
        )
        if requester and requester.manager_id == user.id:
            return True

    return bool(request.is_anonymous and user.role == "HR_ADMIN")


async def _send_initial_audit_chain(
    websocket: WebSocket, request_id: str, db: AsyncSession
):
    """Send the existing audit chain to a newly connected client."""
    from app.services.audit_service import AuditService

    audit_service = AuditService(db)
    chain = await audit_service.get_chain(uuid.UUID(request_id))

    await websocket.send_json(
        {
            "type": "initial_chain",
            "request_id": request_id,
            "entries": [
                {
                    "id": str(entry.id),
                    "step_index": entry.step_index,
                    "actor_id": str(entry.actor_id) if entry.actor_id else None,
                    "action": entry.action,
                    "prev_hash": entry.prev_hash,
                    "chain_hash": entry.chain_hash,
                    "recorded_at": str(entry.recorded_at),
                }
                for entry in chain
            ],
        }
    )


# Function to broadcast audit updates (called by audit service)
async def broadcast_audit_update(request_id: str, audit_entry: dict):
    """Broadcast a new audit entry to all connected clients."""
    message = {"type": "audit_update", "request_id": request_id, "entry": audit_entry}
    await stream_manager.broadcast_to_request(request_id, message)


# Function to broadcast request status changes
async def broadcast_status_change(request_id: str, old_status: str, new_status: str):
    """Broadcast a status change to all connected clients."""
    message = {
        "type": "status_change",
        "request_id": request_id,
        "old_status": old_status,
        "new_status": new_status,
    }
    await stream_manager.broadcast_to_request(request_id, message)
