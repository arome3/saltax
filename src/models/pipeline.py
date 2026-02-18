"""Pipeline stage input/output models.

Immutable value objects (``Finding``, ``AIAnalysisResult``, ``TestResult``) are
frozen.  ``Verdict`` is deliberately mutable — the pipeline runner stamps
``attestation_id`` and ``findings_count`` after initial construction.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import Decision, Severity, VulnerabilityCategory

# ── Finding ─────────────────────────────────────────────────────────────────


class Finding(BaseModel):
    """A single vulnerability or code-quality finding from a pipeline stage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    severity: Severity
    category: VulnerabilityCategory
    message: str
    file_path: str
    line_start: int
    line_end: int
    confidence: float = Field(ge=0.0, le=1.0)
    source_stage: str  # "static_scanner" | "ai_analyzer"
    snippet: str | None = None


# ── AI analysis result ──────────────────────────────────────────────────────


class AIAnalysisResult(BaseModel):
    """Aggregate output from the AI analyser stage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    quality_score: float = Field(ge=0.0, le=10.0)
    risk_score: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(ge=0.0, le=1.0)
    concerns: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    architectural_fit: str  # "good" | "acceptable" | "poor"
    findings: list[Finding] = Field(default_factory=list)
    reasoning: str  # Chain-of-thought for attestation
    vision_alignment_score: int | None = None
    vision_concerns: list[str] = Field(default_factory=list)


# ── Test result ─────────────────────────────────────────────────────────────


class TestResult(BaseModel):
    """Summary of a test-executor run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    coverage_percent: float | None = None
    execution_time_seconds: float
    exit_code: int
    stdout_tail: str = Field(default="", max_length=10_000)
    stderr_tail: str = Field(default="", max_length=10_000)
    timed_out: bool = False


# ── Verdict ─────────────────────────────────────────────────────────────────


class Verdict(BaseModel):
    """Final pipeline decision — mutable so the runner can attach attestation info."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    composite_score: float = Field(ge=0.0, le=1.0)
    score_breakdown: dict[str, float]
    is_self_modification: bool = False
    threshold_used: float
    timestamp: datetime
    pipeline_duration_seconds: float
    findings_count: int = 0
    attestation_id: str | None = None
