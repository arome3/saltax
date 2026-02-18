"""Paid audit service endpoint with x402 payment verification."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.api.deps import get_config, get_pipeline
from src.api.middleware.x402 import verify_x402_payment
from src.models.audit import AuditRequest
from src.models.enums import AuditScope

if TYPE_CHECKING:
    from src.config import SaltaXConfig
    from src.pipeline.runner import Pipeline

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Pricing lookup ───────────────────────────────────────────────────────────

_SCOPE_PRICE_FIELD = {
    AuditScope.SECURITY_ONLY: "security_only_usdc",
    AuditScope.QUALITY_ONLY: "quality_only_usdc",
    AuditScope.FULL: "full_audit_usdc",
}


# ── Request model ────────────────────────────────────────────────────────────


class AuditRequestBody(BaseModel):
    """Incoming audit request payload."""

    repository_url: str
    commit_sha: str
    scope: AuditScope
    callback_url: str | None = None


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
            extra={"audit_id": audit_state.get("audit_id")},
        )


# ── Route ────────────────────────────────────────────────────────────────────


@router.post("/audit", status_code=202)
async def request_audit(
    body: AuditRequestBody,
    request: Request,
    background_tasks: BackgroundTasks,
    config: SaltaXConfig = Depends(get_config),  # noqa: B008
    pipeline: Pipeline = Depends(get_pipeline),  # noqa: B008
) -> dict[str, Any]:
    """Accept a paid audit request after x402 payment verification."""
    # Look up required price from config
    price_field = _SCOPE_PRICE_FIELD[body.scope]
    required_amount: float = getattr(config.audit_pricing, price_field)

    # Verify payment
    payment_header = request.headers.get("X-PAYMENT", "")
    payment = await verify_x402_payment(payment_header, required_amount)

    if not payment.valid:
        return JSONResponse(  # type: ignore[return-value]
            status_code=402,
            content={
                "status_code": 402,
                "error": "Payment Required",
                "detail": payment.error,
            },
            headers={"PAYMENT-REQUIRED": f"{required_amount} USDC"},
        )

    # Build audit request
    audit_id = f"audit-{uuid.uuid4().hex[:12]}"

    audit_request = AuditRequest(
        audit_id=audit_id,
        repository_url=body.repository_url,
        commit_sha=body.commit_sha,
        scope=body.scope,
        callback_url=body.callback_url,
        payment_amount_usdc=payment.amount_usdc,
        payment_proof=payment.tx_hash,
        requested_at=datetime.now(UTC),
    )

    # Queue error-guarded pipeline processing in background
    audit_state: dict[str, Any] = {
        "audit_id": audit_request.audit_id,
        "repository_url": audit_request.repository_url,
        "commit_sha": audit_request.commit_sha,
        "scope": audit_request.scope,
    }
    background_tasks.add_task(_run_audit_pipeline, pipeline, audit_state)

    return {
        "audit_id": audit_id,
        "status": "accepted",
        "scope": body.scope,
        "payment_amount_usdc": payment.amount_usdc,
    }
