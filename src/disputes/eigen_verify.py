"""EigenVerify client for computational dispute resolution.

Wraps the EigenVerify HTTP API with lazy-initialized httpx, configurable
timeouts, a circuit breaker, and structured result types shared with the
MoltCourt client.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from src.config import DisputeConfig

logger = logging.getLogger(__name__)


# ── Shared result types ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class SubmissionResult:
    """Result of submitting a dispute to an external provider."""

    provider_case_id: str
    accepted: bool


@dataclass(frozen=True)
class ResolutionResult:
    """Result of polling a provider for dispute resolution."""

    resolved: bool
    verdict: str | None = None  # "upheld" | "overturned" | None
    details: str | None = None


# ── Circuit breaker ─────────────────────────────────────────────────────────


class CircuitBreakerOpenError(RuntimeError):
    """Raised when a circuit breaker is open."""


class CircuitBreaker:
    """Simple circuit breaker: closed → open → half_open → closed.

    - **Closed**: requests flow normally.
    - **Open**: all requests fail fast for ``reset_seconds``.
    - **Half-open**: one request is allowed through; success → closed,
      failure → open again.

    Uses ``time.monotonic()`` so NTP adjustments don't affect timing.
    """

    __slots__ = (
        "_failure_count",
        "_failure_threshold",
        "_label",
        "_last_failure_time",
        "_reset_seconds",
        "_state",
    )

    def __init__(
        self, failure_threshold: int, reset_seconds: int, label: str = "",
    ) -> None:
        self._failure_threshold = failure_threshold
        self._reset_seconds = reset_seconds
        self._label = label or "CircuitBreaker"
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._state = "closed"

    @property
    def state(self) -> str:
        return self._state

    def check(self) -> None:
        """Raise ``CircuitBreakerOpenError`` if requests should be blocked."""
        if self._state == "closed":
            return
        if self._state == "open":
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self._reset_seconds:
                self._state = "half_open"
                logger.info("%s circuit breaker → half_open", self._label)
                return
            raise CircuitBreakerOpenError(
                f"{self._label} circuit breaker OPEN "
                f"(resets in {self._reset_seconds - elapsed:.0f}s)"
            )
        # half_open — allow one request through

    def record_success(self) -> None:
        """Record a successful request → reset to closed."""
        self._failure_count = 0
        if self._state != "closed":
            logger.info("%s circuit breaker → closed", self._label)
        self._state = "closed"

    def record_failure(self) -> None:
        """Record a failed request → open if threshold exceeded."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self._failure_threshold:
            self._state = "open"
            logger.warning(
                "%s circuit breaker → OPEN (failures=%d)",
                self._label,
                self._failure_count,
            )
        elif self._state == "half_open":
            self._state = "open"
            logger.warning(
                "%s circuit breaker half_open → OPEN (retry failed)",
                self._label,
            )


# ── EigenVerifyClient ───────────────────────────────────────────────────────


class EigenVerifyClient:
    """HTTP client for the EigenVerify computational dispute API.

    Lazy-initializes the httpx client on first use so that the object
    can be constructed outside an event loop.  Includes a circuit breaker
    to prevent cascade failures when EigenVerify is unreachable.

    Lifecycle::

        client = EigenVerifyClient(config, api_key="...")
        result = await client.submit_dispute(dispute_id, proof_data)
        status = await client.check_resolution(result.provider_case_id)
        await client.close()
    """

    def __init__(self, config: DisputeConfig, api_key: str = "") -> None:
        self._base_url = config.eigenverify_base_url.rstrip("/")
        self._timeout = config.eigenverify_timeout_seconds
        self._api_key = api_key
        self._client: httpx.AsyncClient | None = None
        self._breaker = CircuitBreaker(
            failure_threshold=config.circuit_breaker_failure_threshold,
            reset_seconds=config.circuit_breaker_reset_seconds,
            label="EigenVerify",
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
        proof_data: dict[str, Any],
    ) -> SubmissionResult:
        """Submit a computational dispute to EigenVerify.

        POST /disputes with our dispute_id as client_reference_id.
        Returns the provider's case_id for subsequent polling.

        Raises ``CircuitBreakerOpenError`` if the breaker is open.
        Raises ``httpx.HTTPStatusError`` on 4xx/5xx responses.
        """
        self._breaker.check()
        client = self._get_client()
        payload = {
            "client_reference_id": dispute_id,
            "proof_data": proof_data,
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
            "EigenVerify dispute submitted",
            extra={"dispute_id": dispute_id, "provider_case_id": case_id},
        )
        return SubmissionResult(provider_case_id=case_id, accepted=True)

    async def check_resolution(
        self,
        provider_case_id: str,
    ) -> ResolutionResult:
        """Poll EigenVerify for dispute resolution.

        GET /disputes/{case_id}.
        - 404 → not yet indexed (delayed), return unresolved.
        - status="completed" → resolved with verdict.
        - Otherwise → still pending.

        Raises ``CircuitBreakerOpenError`` if the breaker is open.
        Raises on non-404 HTTP errors.
        """
        self._breaker.check()
        client = self._get_client()
        try:
            resp = await client.get(f"/disputes/{provider_case_id}")
        except Exception:
            self._breaker.record_failure()
            raise

        if resp.status_code == 404:
            self._breaker.record_success()
            return ResolutionResult(resolved=False)

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
        """Release the httpx client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
