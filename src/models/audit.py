"""Paid audit service models.

``AuditReport`` is frozen — once an audit completes, its report is immutable
and referenced by attestation proofs.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.models.enums import AuditScope

# ── Audit request ───────────────────────────────────────────────────────────


class AuditRequest(BaseModel):
    """Incoming request for a paid code audit."""

    model_config = ConfigDict(extra="forbid")

    audit_id: str
    repository_url: str
    commit_sha: str
    scope: AuditScope
    callback_url: str | None = None
    payment_amount_usdc: float
    payment_proof: str
    requested_at: datetime


# ── Audit report ────────────────────────────────────────────────────────────


class AuditReport(BaseModel):
    """Immutable output of a completed audit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str
    repository_url: str
    commit_sha: str
    scope: AuditScope
    verdict: dict[str, object]
    findings: list[dict[str, object]]
    attestation: dict[str, object]
    completed_at: datetime
    pipeline_duration_seconds: float
