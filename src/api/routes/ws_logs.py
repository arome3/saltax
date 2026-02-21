"""WebSocket endpoint for real-time structured log streaming."""

from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory set of connected WebSocket clients
_clients: set[WebSocket] = set()


async def broadcast_log(event: dict) -> None:
    """Push a structured log event to all connected WebSocket clients.

    Called by the log handler; safe to call from any coroutine.
    Silently removes clients that fail to receive.
    """
    for ws in list(_clients):
        try:
            await ws.send_json(event)
        except Exception:
            _clients.discard(ws)


@router.websocket("/ws/logs")
async def websocket_logs(ws: WebSocket) -> None:
    """Accept WebSocket connections for log streaming."""
    await ws.accept()
    _clients.add(ws)
    logger.info("WebSocket log client connected (%d total)", len(_clients))
    try:
        while True:
            await ws.receive_text()  # Keep-alive; ignore client messages
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(ws)
        logger.info("WebSocket log client disconnected (%d remaining)", len(_clients))
