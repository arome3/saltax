"""MoltCourt client for subjective dispute resolution.

Same interface as :class:`EigenVerifyClient` plus uses a circuit breaker
to handle MoltCourt's known reliability issues.  Uses ``time.monotonic()``
for NTP-immune timing via the shared :class:`CircuitBreaker`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from src.disputes.eigen_verify import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    ResolutionResult,
    SubmissionResult,
)

if TYPE_CHECKING:
    from src.config import DisputeConfig

logger = logging.getLogger(__name__)


# Re-export for backwards compatibility (scheduler imports from here).
__all__ = ["CircuitBreakerOpenError", "MoltCourtClient"]


class MoltCourtClient:
    """HTTP client for the MoltCourt subjective dispute API.

    Includes a circuit breaker that prevents cascade failures when
    MoltCourt is unreliable or down.

    Lifecycle::

        client = MoltCourtClient(config, api_key="...")
        result = await client.submit_dispute(dispute_id, claim_data)
        status = await client.check_resolution(result.provider_case_id)
        await client.close()
    """

    def __init__(self, config: DisputeConfig, api_key: str = "") -> None:
        self._base_url = config.moltcourt_base_url.rstrip("/")
        self._timeout = config.moltcourt_timeout_seconds
        self._api_key = api_key
        self._client: httpx.AsyncClient | None = None
        self._breaker = CircuitBreaker(
            failure_threshold=config.circuit_breaker_failure_threshold,
            reset_seconds=config.circuit_breaker_reset_seconds,
            label="MoltCourt",
        )

    @property
    def circuit_breaker_state(self) -> str:
        """Current circuit breaker state for monitoring."""
        return self._breaker.state

    def _get_client(self) -> httpx.AsyncClient:
        """Return the httpx client, creating it lazily."""
        if self._client is None:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=self._timeout,
            )
        return self._client

    async def submit_dispute(
        self,
        dispute_id: str,
        claim_data: dict[str, Any],
    ) -> SubmissionResult:
        """Submit a subjective dispute to MoltCourt.

        Checks circuit breaker before making the HTTP call.
        Records success/failure for circuit breaker state.

        Raises ``CircuitBreakerOpenError`` if the breaker is open.
        Raises ``httpx.HTTPStatusError`` on 4xx/5xx.
        """
        self._breaker.check()
        client = self._get_client()
        payload = {
            "client_reference_id": dispute_id,
            "claim_data": claim_data,
        }
        try:
            resp = await client.post("/disputes", json=payload)
            resp.raise_for_status()
        except Exception:
            self._breaker.record_failure()
            raise

        self._breaker.record_success()
        body = resp.json()
        case_id = str(body.get("case_id", body.get("id", "")))
        logger.info(
            "MoltCourt dispute submitted",
            extra={"dispute_id": dispute_id, "provider_case_id": case_id},
        )
        return SubmissionResult(provider_case_id=case_id, accepted=True)

    async def check_resolution(
        self,
        provider_case_id: str,
    ) -> ResolutionResult:
        """Poll MoltCourt for dispute resolution.

        - 404 → case lost/unavailable, record as failure (trips breaker).
        - status="completed" → resolved with verdict.
        - Otherwise → still pending.

        Checks circuit breaker before polling.
        """
        self._breaker.check()
        client = self._get_client()
        try:
            resp = await client.get(f"/disputes/{provider_case_id}")
        except Exception:
            self._breaker.record_failure()
            raise

        if resp.status_code == 404:
            # A 404 on a previously-submitted case means the case is lost.
            # Record as failure so persistent 404s trip the breaker.
            self._breaker.record_failure()
            return ResolutionResult(
                resolved=False, verdict="manual_review",
            )

        try:
            resp.raise_for_status()
        except Exception:
            self._breaker.record_failure()
            raise

        self._breaker.record_success()
        body = resp.json()
        status = str(body.get("status", ""))

        if status == "completed":
            verdict = str(body.get("verdict", ""))
            details = str(body.get("details", ""))
            return ResolutionResult(
                resolved=True, verdict=verdict, details=details,
            )

        return ResolutionResult(resolved=False)

    async def close(self) -> None:
        """Release the httpx client (does NOT reset circuit breaker)."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
