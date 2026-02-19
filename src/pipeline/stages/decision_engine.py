"""Decision engine stage — aggregates pipeline outputs into a weighted verdict.

Stage 4 computes a composite score from static-scan, AI-analysis, and
test-execution results, applies configurable thresholds, produces an
attested verdict, and stores results in the intelligence database.

The scoring formula and weight redistribution logic follow doc 10 and
Technical Specification §13.  All arithmetic is deterministic — identical
inputs always produce identical verdicts, enabling dispute resolution
via EigenVerify.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.models.enums import Decision, Severity
from src.models.pipeline import Verdict

if TYPE_CHECKING:
    from src.attestation.engine import AttestationEngine
    from src.config import SaltaXConfig
    from src.intelligence.database import IntelligenceDB
    from src.pipeline.state import PipelineState

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_PENALTY_PER_CRITICAL_OR_HIGH = 0.25
_DEGRADED_NEUTRAL = 0.5


# ── Public entry point ───────────────────────────────────────────────────────


async def run_decision(
    state: PipelineState,
    config: SaltaXConfig,
    intel_db: IntelligenceDB,
    attestation_engine: AttestationEngine,
) -> None:
    """Aggregate stage outputs and produce a verdict with attestation.

    Mutates *state* in place.  Never raises — all errors are caught,
    logged, and result in a degraded REJECT verdict.
    """
    state.current_stage = "decision_engine"
    t0 = time.monotonic()
    logger.info("Decision engine started for %s", state.pr_id)

    try:
        # Short-circuit: forced REJECT when static scanner flagged critical issues
        if state.short_circuit:
            logger.warning(
                "Short-circuit active — forcing REJECT for %s", state.pr_id,
            )
            verdict = _build_reject_verdict(state, config, t0)
            proof = await attestation_engine.generate_proof(
                action_id=f"attest-{state.pr_id}-{state.commit_sha[:8]}",
                pr_id=state.pr_id,
                repo=state.repo,
                inputs=_build_inputs(state),
                outputs=_build_outputs(state, verdict),
                ai_seed=state.ai_seed,
                ai_output_hash=state.ai_output_hash,
                ai_system_fingerprint=state.ai_system_fingerprint,
            )
            verdict.attestation_id = proof.attestation_id
            state.verdict = verdict.model_dump()
            state.attestation = proof.model_dump()
            await _ingest_results(intel_db, state, verdict)
            return

        # Compute individual component scores
        static_findings = state.static_findings or []
        ai_analysis = state.ai_analysis
        test_results = state.test_results

        s_static = _compute_s_static(static_findings)
        s_quality = _compute_s_quality(ai_analysis)
        s_security = _compute_s_security(ai_analysis)
        s_tests = _compute_s_tests(test_results)

        # Optional history score (only when configured)
        s_history: float | None = None
        if config.pipeline.history_weight > 0:
            s_history = await _compute_s_history(
                intel_db, state.repo, state.pr_author,
            )

        logger.debug(
            "Component scores: s_static=%.3f s_quality=%.3f "
            "s_security=%.3f s_tests=%.3f",
            s_static, s_quality, s_security, s_tests,
        )

        # Weighted composite score (with optional vision/history redistribution)
        composite, breakdown = _compute_weighted_score(
            config, state, s_static, s_quality, s_security, s_tests,
            s_history=s_history,
        )

        logger.debug(
            "Composite score: %.4f | breakdown: %s", composite, breakdown,
        )

        # Select threshold and decide
        threshold = _select_threshold(config, state.is_self_modification)
        review_threshold = config.pipeline.review_threshold
        decision = _decide(composite, threshold, review_threshold)

        # Count findings
        ai_findings: list[Any] = []
        if ai_analysis and isinstance(ai_analysis.get("findings"), list):
            ai_findings = ai_analysis["findings"]
        findings_count = len(static_findings) + len(ai_findings)

        elapsed = time.monotonic() - t0

        verdict = Verdict(
            decision=decision,
            composite_score=round(composite, 4),
            score_breakdown=breakdown,
            is_self_modification=state.is_self_modification,
            threshold_used=threshold,
            timestamp=datetime.now(UTC),
            pipeline_duration_seconds=round(elapsed, 2),
            findings_count=findings_count,
        )

        proof = await attestation_engine.generate_proof(
            action_id=f"attest-{state.pr_id}-{state.commit_sha[:8]}",
            pr_id=state.pr_id,
            repo=state.repo,
            inputs=_build_inputs(state),
            outputs=_build_outputs(state, verdict),
            ai_seed=state.ai_seed,
            ai_output_hash=state.ai_output_hash,
            ai_system_fingerprint=state.ai_system_fingerprint,
        )
        verdict.attestation_id = proof.attestation_id

        state.verdict = verdict.model_dump()
        state.attestation = proof.model_dump()

        await _ingest_results(intel_db, state, verdict)

        logger.info(
            "Decision engine completed: decision=%s composite=%.4f "
            "threshold=%.2f findings=%d in %.1fs",
            decision.value,
            composite,
            threshold,
            findings_count,
            elapsed,
        )

    except Exception:
        logger.exception("Decision engine failed unexpectedly")
        verdict = _build_reject_verdict(state, config, t0)
        try:
            proof = await attestation_engine.generate_proof(
                action_id=f"attest-{state.pr_id}-{state.commit_sha[:8]}",
                pr_id=state.pr_id,
                repo=state.repo,
                inputs=_build_inputs(state),
                outputs=_build_outputs(state, verdict),
                ai_seed=state.ai_seed,
                ai_output_hash=state.ai_output_hash,
                ai_system_fingerprint=state.ai_system_fingerprint,
            )
            verdict.attestation_id = proof.attestation_id
            state.attestation = proof.model_dump()
        except Exception:
            logger.warning("Attestation also failed during error recovery", exc_info=True)
            state.attestation = None
        state.verdict = verdict.model_dump()
        await _ingest_results(intel_db, state, verdict)


# ── Scoring helpers ──────────────────────────────────────────────────────────


def _compute_s_static(findings: list[dict[str, object]]) -> float:
    """Compute static-clear score: penalize 0.25 per CRITICAL/HIGH finding."""
    count = 0
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        if sev in (Severity.CRITICAL.value, Severity.HIGH.value):
            count += 1
    return _clamp(1.0 - (count * _PENALTY_PER_CRITICAL_OR_HIGH), 0.0, 1.0)


def _compute_s_quality(ai_analysis: dict[str, object] | None) -> float:
    """Compute AI quality score: quality_score / 10, or 0.5 if degraded."""
    if ai_analysis is None:
        return _DEGRADED_NEUTRAL
    confidence = float(ai_analysis.get("confidence", 0.0))
    if confidence == 0.0:
        return _DEGRADED_NEUTRAL
    quality = float(ai_analysis.get("quality_score", 5.0))
    return _clamp(quality / 10.0, 0.0, 1.0)


def _compute_s_security(ai_analysis: dict[str, object] | None) -> float:
    """Compute AI security score: 1 - risk_score / 10, or 0.5 if degraded."""
    if ai_analysis is None:
        return _DEGRADED_NEUTRAL
    confidence = float(ai_analysis.get("confidence", 0.0))
    if confidence == 0.0:
        return _DEGRADED_NEUTRAL
    risk = float(ai_analysis.get("risk_score", 5.0))
    return _clamp(1.0 - (risk / 10.0), 0.0, 1.0)


def _compute_s_tests(test_results: dict[str, object] | None) -> float:
    """Compute test score: 1.0 if passed, 0.0 if failed, 0.5 if unavailable.

    Returns ``_DEGRADED_NEUTRAL`` when test results are absent (test executor
    was not configured or timed out), matching the degraded behavior of
    ``_compute_s_quality`` and ``_compute_s_security``.
    """
    if test_results is None:
        return _DEGRADED_NEUTRAL
    return 1.0 if test_results.get("passed") is True else 0.0


async def _compute_s_history(
    intel_db: IntelligenceDB,
    repo: str,
    author: str,
) -> float | None:
    """Compute history score from contributor acceptance rate.

    Returns ``None`` when the DB has no data for this contributor,
    signalling that history should be excluded from scoring.
    """
    try:
        return await intel_db.get_contributor_acceptance_rate(repo, author)
    except Exception:
        logger.debug("Failed to fetch contributor acceptance rate", exc_info=True)
        return None


def _compute_weighted_score(
    config: SaltaXConfig,
    state: PipelineState,
    s_static: float,
    s_quality: float,
    s_security: float,
    s_tests: float,
    *,
    s_history: float | None = None,
) -> tuple[float, dict[str, float]]:
    """Assemble weights, apply vision/history redistribution, compute composite.

    Returns ``(composite_score, score_breakdown_dict)``.
    """
    w = config.pipeline.weights
    base_weights: dict[str, float] = {
        "static_clear": w.static_clear,
        "ai_quality": w.ai_quality,
        "ai_security": w.ai_security,
        "tests_pass": w.tests_pass,
    }
    scores: dict[str, float] = {
        "static_clear": s_static,
        "ai_quality": s_quality,
        "ai_security": s_security,
        "tests_pass": s_tests,
    }

    # Simultaneous vision + history weight redistribution
    # Compute the total extra weight budget first, then scale base weights
    # by (1 - total_extra) once — prevents sequential scaling from shrinking
    # vision weight when history is also active.
    vision_weight = config.triage.vision.alignment_weight
    ai_analysis = state.ai_analysis
    vision_score_raw = (
        ai_analysis.get("vision_alignment_score")
        if ai_analysis
        else None
    )

    use_vision = vision_weight > 0 and vision_score_raw is not None
    history_weight = config.pipeline.history_weight
    use_history = history_weight > 0 and s_history is not None

    total_extra = (vision_weight if use_vision else 0.0) + (
        history_weight if use_history else 0.0
    )
    scale = 1.0 - total_extra
    weights = {k: v * scale for k, v in base_weights.items()}

    if use_vision:
        weights["vision_alignment"] = vision_weight
        scores["vision_alignment"] = _clamp(float(vision_score_raw) / 10.0, 0.0, 1.0)
    if use_history:
        weights["history"] = history_weight
        scores["history"] = s_history

    # Compute composite
    composite = sum(weights[k] * scores[k] for k in weights)
    composite = _clamp(composite, 0.0, 1.0)

    # Build breakdown (individual scores, not weighted contributions)
    breakdown = {k: round(v, 4) for k, v in scores.items()}

    return composite, breakdown


def _select_threshold(config: SaltaXConfig, is_self_mod: bool) -> float:
    """Return the approval threshold — elevated for self-modification PRs."""
    if is_self_mod:
        return config.pipeline.self_modification_threshold
    return config.pipeline.approval_threshold


def _decide(
    composite: float,
    approval_threshold: float,
    review_threshold: float,
) -> Decision:
    """Map composite score to a Decision enum value.

    Uses ``>=`` (not ``>``) for approval — spec-critical.
    """
    if composite >= approval_threshold:
        return Decision.APPROVE
    if composite >= review_threshold:
        return Decision.REQUEST_CHANGES
    return Decision.REJECT


# ── Input/output builders ────────────────────────────────────────────────────


def _build_inputs(state: PipelineState) -> dict[str, object]:
    """Build the inputs dict for attestation hashing."""
    diff_hash = hashlib.sha256(state.diff.encode()).hexdigest()
    return {"repo": state.repo, "commit_sha": state.commit_sha, "diff_hash": diff_hash}


def _build_outputs(state: PipelineState, verdict: Verdict) -> dict[str, object]:
    """Build the outputs dict for attestation hashing."""
    return {
        "findings_count": verdict.findings_count,
        "ai_analysis": state.ai_analysis,
        "test_results": state.test_results,
        "verdict": verdict.decision.value,
    }


# ── Verdict factories ────────────────────────────────────────────────────────


def _build_reject_verdict(
    state: PipelineState,
    config: SaltaXConfig,
    t0: float,
) -> Verdict:
    """Canonical REJECT verdict for short-circuit or error paths."""
    elapsed = time.monotonic() - t0
    threshold = _select_threshold(config, state.is_self_modification)

    static_findings = state.static_findings or []
    ai_analysis = state.ai_analysis
    ai_findings: list[Any] = []
    if ai_analysis and isinstance(ai_analysis.get("findings"), list):
        ai_findings = ai_analysis["findings"]
    findings_count = len(static_findings) + len(ai_findings)

    return Verdict(
        decision=Decision.REJECT,
        composite_score=0.0,
        score_breakdown={},
        is_self_modification=state.is_self_modification,
        threshold_used=threshold,
        timestamp=datetime.now(UTC),
        pipeline_duration_seconds=round(elapsed, 2),
        findings_count=findings_count,
    )


# ── DB ingestion ─────────────────────────────────────────────────────────────


async def _ingest_results(
    intel_db: IntelligenceDB,
    state: PipelineState,
    verdict: Verdict,
) -> None:
    """Best-effort intelligence DB update — never raises."""
    try:
        ai_findings: list[object] = []
        if state.ai_analysis and isinstance(state.ai_analysis.get("findings"), list):
            ai_findings = state.ai_analysis["findings"]

        await intel_db.ingest_pipeline_results(
            pr_id=state.pr_id,
            repo=state.repo,
            static_findings=state.static_findings or [],
            ai_findings=ai_findings,
            verdict=verdict.model_dump(),
            author=state.pr_author,
        )
    except Exception:
        logger.warning(
            "Failed to ingest pipeline results into intelligence DB", exc_info=True,
        )


# ── Small helpers ────────────────────────────────────────────────────────────


def _clamp(value: float, lo: float, hi: float) -> float:
    """Clamp a numeric value to [lo, hi]."""
    return max(lo, min(hi, value))
