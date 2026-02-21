"""Paid audit service endpoint with x402 payment verification."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.api.deps import (
    get_config,
    get_payment_verifier,
    get_pipeline,
    get_treasury_manager,
    get_tx_store,
)
from src.api.middleware.x402 import build_payment_response_header
from src.models.enums import AuditScope

if TYPE_CHECKING:
    from src.api.middleware.tx_store import TxHashStore
    from src.api.middleware.x402 import PaymentVerifier
    from src.config import SaltaXConfig
    from src.pipeline.runner import Pipeline
    from src.treasury.manager import TreasuryManager

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Pricing lookup ───────────────────────────────────────────────────────────

_SCOPE_PRICE_FIELD = {
    AuditScope.SECURITY_ONLY: "security_only_usdc",
    AuditScope.QUALITY_ONLY: "quality_only_usdc",
    AuditScope.FULL: "full_audit_usdc",
}

# ── Facilitator error codes that indicate operational issues ─────────────────

_FACILITATOR_ERRORS = frozenset({
    "facilitator_timeout",
    "facilitator_unavailable",
    "facilitator_unreachable",
    "facilitator_response_invalid",
})

# ── Pruning interval ────────────────────────────────────────────────────────

_PRUNE_INTERVAL_SECONDS = 60.0


# ── Audit dedup ──────────────────────────────────────────────────────────────


class _AuditDedup:
    """Prevent duplicate pipeline runs for the same repo+commit+scope.

    Uses the **reserve-then-verify** pattern: the audit slot is reserved
    *before* calling the facilitator, then released if verification fails.
    This prevents two concurrent requests from both consuming payments.

    .. note::
        The slot cache is **in-memory only** and lost on process restart.
        On restart, a duplicate pipeline run is possible for audits that
        were in-flight.  This is acceptable — duplicate runs waste compute
        but don't compromise financial security.

        Payment replay protection (tx_hash tracking) is handled by
        :class:`TxHashStore`, which is SQLite-backed and durable.
    """

    def __init__(self, *, ttl_seconds: float = 3600.0, max_entries: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._cache: dict[str, tuple[str, float]] = {}  # key → (audit_id, timestamp)
        self._lock = asyncio.Lock()
        self._last_prune: float = 0.0

    async def get_or_create(self, repo: str, commit: str, scope: str) -> tuple[str, bool]:
        """Return ``(audit_id, is_new)``.  ``is_new=True`` → caller owns the slot."""
        key = f"{repo}:{commit}:{scope}"
        async with self._lock:
            self._maybe_prune()
            if key in self._cache:
                return self._cache[key][0], False
            audit_id = f"audit-{uuid.uuid4().hex[:12]}"
            self._cache[key] = (audit_id, time.monotonic())
            return audit_id, True

    async def remove(self, repo: str, commit: str, scope: str) -> None:
        """Release a reserved audit slot (e.g. on verification failure)."""
        key = f"{repo}:{commit}:{scope}"
        async with self._lock:
            self._cache.pop(key, None)

    def _maybe_prune(self) -> None:
        """Prune if enough time has passed or the cache is full."""
        now = time.monotonic()
        if (
            now - self._last_prune < _PRUNE_INTERVAL_SECONDS
            and len(self._cache) < self._max_entries
        ):
            return
        self._prune(now)
        self._last_prune = now

    def _prune(self, now: float | None = None) -> None:
        """Remove expired entries and enforce cap."""
        if now is None:
            now = time.monotonic()
        cutoff = now - self._ttl
        expired = [k for k, (_, ts) in self._cache.items() if ts < cutoff]
        for k in expired:
            del self._cache[k]
        if len(self._cache) > self._max_entries:
            by_age = sorted(self._cache.items(), key=lambda kv: kv[1][1])
            to_drop = len(self._cache) - self._max_entries
            for k, _ in by_age[:to_drop]:
                del self._cache[k]


_audit_dedup = _AuditDedup()


# ── Request model ────────────────────────────────────────────────────────────


class AuditRequestBody(BaseModel):
    """Incoming audit request payload."""

    repository_url: str
    commit_sha: str
    scope: AuditScope


# ── Background task wrapper ──────────────────────────────────────────────────


async def _run_audit_pipeline(
    pipeline: Pipeline,
    audit_state: dict[str, Any],
) -> None:
    """Execute ``pipeline.run`` with error logging.

    BackgroundTasks swallows exceptions silently — this wrapper ensures
    audit failures are logged with full context.
    """
    try:
        await pipeline.run(audit_state)
        logger.info(
            "Audit pipeline completed",
            extra={"audit_id": audit_state.get("audit_id")},
        )
    except Exception:
        logger.exception(
            "Audit pipeline failed",
            extra={
                "audit_id": audit_state.get("audit_id"),
                "tx_hash": audit_state.get("payment_tx_hash"),
            },
        )


# ── Route ────────────────────────────────────────────────────────────────────


@router.post("/audit", status_code=202)
async def request_audit(
    body: AuditRequestBody,
    request: Request,
    background_tasks: BackgroundTasks,
    config: SaltaXConfig = Depends(get_config),  # noqa: B008
    pipeline: Pipeline = Depends(get_pipeline),  # noqa: B008
    verifier: PaymentVerifier = Depends(get_payment_verifier),  # noqa: B008
    treasury_mgr: TreasuryManager = Depends(get_treasury_manager),  # noqa: B008
    tx_store: TxHashStore = Depends(get_tx_store),  # noqa: B008
) -> dict[str, Any]:
    """Accept a paid audit request after x402 payment verification.

    Uses the **reserve-then-verify** pattern to prevent double-payment:

    1. Quick-reject requests with no payment header (402, no external call)
    2. Reserve the audit slot under lock (prevents concurrent duplicates)
    3. Call the facilitator to verify the payment proof
    4. On verification failure → release the slot so the next attempt can try
    5. On success → check tx_hash replay (durable), record revenue, start pipeline
    """
    # ── 1. Price lookup ──────────────────────────────────────────────
    price_field = _SCOPE_PRICE_FIELD[body.scope]
    required_amount: float = getattr(config.audit_pricing, price_field)

    # ── 2. Extract payment header (V2 first, V1 fallback) ───────────
    payment_header = (
        request.headers.get("PAYMENT-SIGNATURE")
        or request.headers.get("X-PAYMENT")
        or ""
    )

    # ── 3. Build requirements ────────────────────────────────────────
    requirements = verifier.build_requirements(
        required_amount,
        "/api/v1/audit",
        f"SaltaX {body.scope} audit",
    )

    # ── 4. Quick reject: no header → 402 (no facilitator call) ──────
    if not payment_header:
        return JSONResponse(  # type: ignore[return-value]
            status_code=402,
            content={
                "status_code": 402,
                "error": "Payment Required",
                "detail": "missing_payment_header",
            },
            headers={"PAYMENT-REQUIRED": requirements.to_header_value()},
        )

    # ── 5. Reserve audit slot BEFORE calling facilitator ─────────────
    audit_id, is_new = await _audit_dedup.get_or_create(
        body.repository_url,
        body.commit_sha,
        body.scope,
    )
    if not is_new:
        return JSONResponse(  # type: ignore[return-value]
            status_code=202,
            content={
                "audit_id": audit_id,
                "status": "already_processing",
                "scope": body.scope,
            },
        )

    # ── 6. Verify payment with facilitator ───────────────────────────
    payment = await verifier.verify(payment_header, requirements)

    # ── 7. Facilitator operational errors → 503 (release slot) ───────
    if payment.error in _FACILITATOR_ERRORS:
        await _audit_dedup.remove(body.repository_url, body.commit_sha, body.scope)
        retry_after = "30" if payment.error != "facilitator_unavailable" else "60"
        return JSONResponse(  # type: ignore[return-value]
            status_code=503,
            content={
                "status_code": 503,
                "error": "Service Unavailable",
                "detail": f"Payment verification temporarily unavailable: {payment.error}",
            },
            headers={"Retry-After": retry_after},
        )

    # ── 8. Payment invalid → 402 (release slot) ─────────────────────
    if not payment.valid:
        await _audit_dedup.remove(body.repository_url, body.commit_sha, body.scope)
        return JSONResponse(  # type: ignore[return-value]
            status_code=402,
            content={
                "status_code": 402,
                "error": "Payment Required",
                "detail": payment.error,
            },
            headers={"PAYMENT-REQUIRED": requirements.to_header_value()},
        )

    # ── 9. Replay protection: reject reused tx_hash (durable) ────────
    if payment.tx_hash and await tx_store.check_and_record(payment.tx_hash, audit_id):
        await _audit_dedup.remove(body.repository_url, body.commit_sha, body.scope)
        return JSONResponse(  # type: ignore[return-value]
            status_code=409,
            content={
                "status_code": 409,
                "error": "Conflict",
                "detail": "Payment transaction already used for a different audit",
            },
        )

    # ── 10. Record revenue ───────────────────────────────────────────
    await treasury_mgr.record_incoming(
        tx_type="audit_fee_usdc",
        amount_wei=payment.amount_atomic,
        counterparty=payment.payer_address,
        currency="USDC",
        tx_hash=payment.tx_hash,
        audit_id=audit_id,
    )

    # ── 11. Queue pipeline ───────────────────────────────────────────
    audit_state: dict[str, Any] = {
        "audit_id": audit_id,
        "repository_url": body.repository_url,
        "commit_sha": body.commit_sha,
        "scope": body.scope,
        "payment_tx_hash": payment.tx_hash,
    }
    background_tasks.add_task(_run_audit_pipeline, pipeline, audit_state)

    # ── 12. Return 202 with receipt ──────────────────────────────────
    return JSONResponse(  # type: ignore[return-value]
        status_code=202,
        content={
            "audit_id": audit_id,
            "status": "accepted",
            "scope": body.scope,
            "payment_amount_usdc": payment.amount_usdc,
            "payment_tx_hash": payment.tx_hash,
            "payment_id": payment.payment_id,
        },
        headers={
            "PAYMENT-RESPONSE": build_payment_response_header(
                payment.payment_id, payment.tx_hash
            ),
        },
    )
