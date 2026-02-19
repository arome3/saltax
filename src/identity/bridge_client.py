"""HTTP client for the TypeScript identity bridge (Agent0 SDK wrapper).

Encapsulates all HTTP calls to the TS bridge.  Most public methods catch
transport/timeout/HTTP errors and return ``None`` on failure — callers
degrade gracefully without try/except boilerplate.

Exception: ``register_agent`` raises :class:`AlreadyRegisteredError` on
HTTP 409 so the caller can attempt recovery via ``get_agent()``.

Pattern: lazy ``httpx.AsyncClient`` creation (matching ``KMSSealManager``).
"""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_REGISTER_TIMEOUT = 30.0  # IPFS pinning is slow
_DEFAULT_TIMEOUT = 15.0


class AlreadyRegisteredError(Exception):
    """Raised when the bridge returns 409 — agent already registered on-chain."""

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        super().__init__(f"Agent already registered: {detail}")


class IdentityBridgeClient:
    """Thin httpx wrapper for the TS identity bridge endpoints."""

    def __init__(self, base_url: str = "http://127.0.0.1:8081") -> None:
        self._base_url = base_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT)
        return self._client

    async def register_agent(
        self,
        name: str,
        description: str,
        chain_id: int,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Register an agent via the TS bridge.

        Returns the registration result dict on success, ``None`` on
        transport/timeout failure.  Raises :class:`AlreadyRegisteredError`
        on HTTP 409 so the caller can attempt recovery.
        """
        client = self._get_client()
        payload: dict[str, Any] = {
            "name": name,
            "description": description,
            "chainId": chain_id,
        }
        if metadata:
            payload["metadata"] = metadata
        try:
            resp = await client.post(
                f"{self._base_url}/identity/register",
                json=payload,
                timeout=_REGISTER_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 409:
                detail = ""
                with suppress(Exception):
                    detail = exc.response.json().get("detail", "")
                raise AlreadyRegisteredError(detail) from exc
            logger.warning("Bridge register_agent failed: %s", exc)
            return None
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            logger.warning("Bridge register_agent failed: %s", exc)
            return None

    async def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Look up an existing agent.  Returns None on failure."""
        client = self._get_client()
        try:
            resp = await client.get(
                f"{self._base_url}/identity/agent",
                params={"agentId": agent_id},
            )
            resp.raise_for_status()
            return resp.json()
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as exc:
            logger.warning("Bridge get_agent failed: %s", exc)
            return None

    async def give_feedback(
        self,
        agent_id: str,
        value: int,
        tag1: str,
        tag2: str,
    ) -> dict[str, Any] | None:
        """Submit reputation feedback.  Returns None on failure."""
        client = self._get_client()
        try:
            resp = await client.post(
                f"{self._base_url}/identity/feedback",
                json={
                    "agentId": agent_id,
                    "value": value,
                    "tag1": tag1,
                    "tag2": tag2,
                },
            )
            resp.raise_for_status()
            return resp.json()
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as exc:
            logger.warning("Bridge give_feedback failed: %s", exc)
            return None

    async def get_reputation_summary(
        self,
        agent_id: str,
    ) -> dict[str, Any] | None:
        """Fetch on-chain reputation summary.  Returns None on failure."""
        client = self._get_client()
        try:
            resp = await client.get(
                f"{self._base_url}/identity/reputation",
                params={"agentId": agent_id},
            )
            resp.raise_for_status()
            return resp.json()
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as exc:
            logger.warning("Bridge get_reputation_summary failed: %s", exc)
            return None

    async def close(self) -> None:
        """Release HTTP connection resources."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
