"""Per-IP sliding-window rate limiter — pure ASGI middleware.

Fixes over the original BaseHTTPMiddleware implementation:
- **Race condition**: ``asyncio.Lock`` serializes read-check-append per request.
- **Memory leak**: stale IP entries are evicted when the bucket exceeds
  ``max_ips`` (LRU: oldest-access-first).
- **XFF spoofing**: ``trusted_proxy_depth`` controls how many rightmost
  ``X-Forwarded-For`` hops are trusted.  Default 0 = ignore XFF entirely.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


class RateLimiterMiddleware:
    """Pure ASGI sliding-window rate limiter keyed by client IP.

    Parameters
    ----------
    app:
        The next ASGI application in the stack.
    global_rpm:
        Maximum requests per minute for all endpoints (default 60).
    audit_rpm:
        Stricter limit for ``/api/v1/audit`` paths (default 10).
    max_ips:
        Maximum tracked IPs before LRU eviction (default 10_000).
    trusted_proxy_depth:
        Number of trusted reverse-proxy hops.  ``0`` (default) ignores
        ``X-Forwarded-For`` entirely and uses the TCP peer address.
        ``1`` trusts one proxy (e.g. nginx/ALB) and reads the rightmost
        client-supplied entry.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        global_rpm: int = 60,
        audit_rpm: int = 10,
        max_ips: int = 10_000,
        trusted_proxy_depth: int = 0,
    ) -> None:
        self.app = app
        self.global_rpm = global_rpm
        self.audit_rpm = audit_rpm
        self.max_ips = max_ips
        self.trusted_proxy_depth = trusted_proxy_depth
        self._buckets: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_ip = self._resolve_client_ip(scope)
        path: str = scope.get("path", "")
        limit = self.audit_rpm if path.startswith("/api/v1/audit") else self.global_rpm

        now = time.monotonic()
        window = 60.0

        async with self._lock:
            # Prune expired timestamps
            timestamps = self._buckets.get(client_ip, [])
            timestamps = [t for t in timestamps if now - t < window]

            if len(timestamps) >= limit:
                self._buckets[client_ip] = timestamps
                await self._send_429(send, limit)
                return

            timestamps.append(now)
            self._buckets[client_ip] = timestamps

            # LRU eviction: drop oldest-accessed IPs when over capacity
            if len(self._buckets) > self.max_ips:
                self._evict_stale(now, window)

        await self.app(scope, receive, send)

    def _resolve_client_ip(self, scope: Scope) -> str:
        """Extract client IP with XFF trust-depth handling.

        With ``trusted_proxy_depth=0`` (default): ignores X-Forwarded-For,
        uses the direct TCP peer address.  This is the safe default — XFF
        is a client-settable header.

        With ``trusted_proxy_depth=N`` (N > 0): reads the Nth entry from
        the right in X-Forwarded-For.  E.g. with depth=1 behind one ALB,
        the rightmost entry is the client IP added by the ALB.
        """
        if self.trusted_proxy_depth > 0:
            headers = dict(scope.get("headers", []))
            xff = headers.get(b"x-forwarded-for", b"").decode()
            if xff:
                parts = [p.strip() for p in xff.split(",")]
                # Rightmost N entries are from trusted proxies;
                # the entry just before them is the real client IP
                idx = len(parts) - self.trusted_proxy_depth
                if 0 <= idx < len(parts):
                    return parts[idx]

        # Fall back to TCP peer address
        client: tuple[str, int] | None = scope.get("client")
        return client[0] if client else "unknown"

    def _evict_stale(self, now: float, window: float) -> None:
        """Remove IPs with no recent requests, then oldest if still over capacity."""
        # First pass: remove fully expired buckets
        expired = [ip for ip, ts in self._buckets.items() if not ts or now - ts[-1] >= window]
        for ip in expired:
            del self._buckets[ip]

        # Second pass: if still over capacity, drop IPs with oldest last-request
        if len(self._buckets) > self.max_ips:
            by_age = sorted(self._buckets.items(), key=lambda kv: kv[1][-1])
            to_drop = len(self._buckets) - self.max_ips
            for ip, _ in by_age[:to_drop]:
                del self._buckets[ip]

    @staticmethod
    async def _send_429(send: Send, limit: int) -> None:
        """Send a 429 Too Many Requests response directly on the ASGI channel."""
        body = json.dumps({
            "status_code": 429,
            "error": "Too Many Requests",
            "detail": f"Rate limit exceeded ({limit} req/min)",
        }).encode()

        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
