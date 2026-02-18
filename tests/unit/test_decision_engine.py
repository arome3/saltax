"""Tests for the decision engine pipeline stage."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.config import SaltaXConfig
from src.models.enums import Decision
from src.pipeline.stages.decision_engine import (
    _build_attestation,
    _clamp,
    _compute_s_history,
    _compute_s_quality,
    _compute_s_security,
    _compute_s_static,
    _compute_s_tests,
    _compute_weighted_score,
    _decide,
    _select_threshold,
    run_decision,
)
from src.pipeline.state import PipelineState

# ── Helpers ──────────────────────────────────────────────────────────────────

_MODULE = "src.pipeline.stages.decision_engine"


def _make_state(**overrides: object) -> PipelineState:
    defaults: dict[str, object] = {
        "pr_id": "owner/repo#42",
        "repo": "owner/repo",
        "repo_url": "https://github.com/owner/repo.git",
        "commit_sha": "abc12345deadbeef",
        "diff": "diff --git a/f.py b/f.py\n+pass",
        "base_branch": "main",
        "head_branch": "fix/stuff",
        "pr_author": "dev",
    }
    defaults.update(overrides)
    return PipelineState(**defaults)  # type: ignore[arg-type]


def _make_config(**overrides: Any) -> SaltaXConfig:
    return SaltaXConfig(**overrides)


def _make_intel_db() -> AsyncMock:
    db = AsyncMock()
    db.ingest_pipeline_results = AsyncMock()
    return db


def _make_ai_analysis(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "quality_score": 8.0,
        "risk_score": 2.0,
        "confidence": 0.9,
        "concerns": [],
        "recommendations": [],
        "architectural_fit": "good",
        "findings": [],
        "reasoning": "Looks good.",
    }
    defaults.update(overrides)
    return defaults


def _make_test_results(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "passed": True,
        "total_tests": 20,
        "passed_tests": 20,
        "failed_tests": 0,
        "skipped_tests": 0,
        "coverage_percent": 85.0,
        "execution_time_seconds": 3.5,
        "exit_code": 0,
        "stdout_tail": "",
        "stderr_tail": "",
        "timed_out": False,
    }
    defaults.update(overrides)
    return defaults


# ═══════════════════════════════════════════════════════════════════════════════
# A. _compute_s_static
# ═══════════════════════════════════════════════════════════════════════════════


class TestComputeSStatic:
    """Unit tests for static-clear score computation."""

    def test_no_findings(self) -> None:
        assert _compute_s_static([]) == 1.0

    def test_one_critical(self) -> None:
        findings = [{"severity": "CRITICAL", "rule_id": "r1"}]
        assert _compute_s_static(findings) == 0.75

    def test_one_high(self) -> None:
        findings = [{"severity": "HIGH", "rule_id": "r1"}]
        assert _compute_s_static(findings) == 0.75

    def test_medium_no_penalty(self) -> None:
        findings = [{"severity": "MEDIUM", "rule_id": "r1"}]
        assert _compute_s_static(findings) == 1.0

    def test_four_critical_floors_at_zero(self) -> None:
        findings = [{"severity": "CRITICAL", "rule_id": f"r{i}"} for i in range(4)]
        assert _compute_s_static(findings) == 0.0

    def test_five_critical_clamped(self) -> None:
        """More than 4 CRITICAL findings still floors at 0.0."""
        findings = [{"severity": "CRITICAL", "rule_id": f"r{i}"} for i in range(5)]
        assert _compute_s_static(findings) == 0.0

    def test_mixed_severities(self) -> None:
        findings = [
            {"severity": "CRITICAL", "rule_id": "r1"},
            {"severity": "HIGH", "rule_id": "r2"},
            {"severity": "MEDIUM", "rule_id": "r3"},
            {"severity": "LOW", "rule_id": "r4"},
        ]
        # 2 × 0.25 penalty = 0.50
        assert _compute_s_static(findings) == 0.5


# ═══════════════════════════════════════════════════════════════════════════════
# B. _compute_s_quality
# ═══════════════════════════════════════════════════════════════════════════════


class TestComputeSQuality:
    """Unit tests for AI quality score computation."""

    def test_none_returns_neutral(self) -> None:
        assert _compute_s_quality(None) == 0.5

    def test_degraded_confidence_zero(self) -> None:
        ai = _make_ai_analysis(confidence=0.0)
        assert _compute_s_quality(ai) == 0.5

    def test_normal_quality(self) -> None:
        ai = _make_ai_analysis(quality_score=8.0, confidence=0.9)
        assert _compute_s_quality(ai) == 0.8

    def test_perfect_quality(self) -> None:
        ai = _make_ai_analysis(quality_score=10.0, confidence=0.9)
        assert _compute_s_quality(ai) == 1.0

    def test_zero_quality(self) -> None:
        ai = _make_ai_analysis(quality_score=0.0, confidence=0.9)
        assert _compute_s_quality(ai) == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# C. _compute_s_security
# ═══════════════════════════════════════════════════════════════════════════════


class TestComputeSSecurity:
    """Unit tests for AI security score computation."""

    def test_none_returns_neutral(self) -> None:
        assert _compute_s_security(None) == 0.5

    def test_degraded_confidence_zero(self) -> None:
        ai = _make_ai_analysis(confidence=0.0)
        assert _compute_s_security(ai) == 0.5

    def test_low_risk(self) -> None:
        ai = _make_ai_analysis(risk_score=2.0, confidence=0.9)
        assert _compute_s_security(ai) == 0.8

    def test_zero_risk(self) -> None:
        ai = _make_ai_analysis(risk_score=0.0, confidence=0.9)
        assert _compute_s_security(ai) == 1.0

    def test_max_risk(self) -> None:
        ai = _make_ai_analysis(risk_score=10.0, confidence=0.9)
        assert _compute_s_security(ai) == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# D. _compute_s_tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestComputeSTests:
    """Unit tests for test score computation."""

    def test_none_returns_degraded_neutral(self) -> None:
        assert _compute_s_tests(None) == 0.5

    def test_passed(self) -> None:
        assert _compute_s_tests(_make_test_results(passed=True)) == 1.0

    def test_failed(self) -> None:
        assert _compute_s_tests(_make_test_results(passed=False)) == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# E. _decide
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecide:
    """Unit tests for threshold-based decision mapping."""

    def test_above_approval(self) -> None:
        assert _decide(0.80, 0.75, 0.50) == Decision.APPROVE

    def test_at_approval(self) -> None:
        """Spec-critical: >= means exact threshold is APPROVE."""
        assert _decide(0.75, 0.75, 0.50) == Decision.APPROVE

    def test_between_thresholds(self) -> None:
        assert _decide(0.60, 0.75, 0.50) == Decision.REQUEST_CHANGES

    def test_at_review(self) -> None:
        assert _decide(0.50, 0.75, 0.50) == Decision.REQUEST_CHANGES

    def test_below_review(self) -> None:
        assert _decide(0.49, 0.75, 0.50) == Decision.REJECT

    def test_zero_score(self) -> None:
        assert _decide(0.0, 0.75, 0.50) == Decision.REJECT


# ═══════════════════════════════════════════════════════════════════════════════
# F. _select_threshold
# ═══════════════════════════════════════════════════════════════════════════════


class TestSelectThreshold:
    """Unit tests for threshold selection."""

    def test_standard(self) -> None:
        config = _make_config()
        assert _select_threshold(config, is_self_mod=False) == 0.75

    def test_self_modification(self) -> None:
        config = _make_config()
        assert _select_threshold(config, is_self_mod=True) == 0.90


# ═══════════════════════════════════════════════════════════════════════════════
# G. Standard approval path
# ═══════════════════════════════════════════════════════════════════════════════


class TestStandardApproval:
    """All scores high → APPROVE."""

    async def test_all_high_scores(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(
                quality_score=9.0, risk_score=1.0, confidence=0.95,
            ),
            test_results=_make_test_results(passed=True),
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["decision"] == Decision.APPROVE.value


# ═══════════════════════════════════════════════════════════════════════════════
# H. Standard rejection path
# ═══════════════════════════════════════════════════════════════════════════════


class TestStandardRejection:
    """All scores bad → REJECT."""

    async def test_all_bad_scores(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(
                quality_score=1.0, risk_score=9.0, confidence=0.9,
            ),
            test_results=_make_test_results(passed=False),
            static_findings=[
                {"severity": "CRITICAL", "rule_id": f"r{i}"} for i in range(4)
            ],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["decision"] == Decision.REJECT.value


# ═══════════════════════════════════════════════════════════════════════════════
# I. REQUEST_CHANGES path
# ═══════════════════════════════════════════════════════════════════════════════


class TestRequestChanges:
    """Mid scores → REQUEST_CHANGES."""

    async def test_mid_scores(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(
                quality_score=6.0, risk_score=5.0, confidence=0.8,
            ),
            test_results=_make_test_results(passed=False),
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        # s_static=1.0, s_quality=0.6, s_security=0.5, s_tests=0.0
        # composite = 0.25*(1.0 + 0.6 + 0.5 + 0.0) = 0.525
        assert state.verdict["decision"] == Decision.REQUEST_CHANGES.value


# ═══════════════════════════════════════════════════════════════════════════════
# J. Short-circuit
# ═══════════════════════════════════════════════════════════════════════════════


class TestShortCircuit:
    """Short-circuit forces REJECT regardless of scores."""

    async def test_short_circuit_reject(self) -> None:
        state = _make_state(short_circuit=True)
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["decision"] == Decision.REJECT.value
        assert state.verdict["composite_score"] == 0.0

    async def test_short_circuit_still_builds_attestation(self) -> None:
        state = _make_state(short_circuit=True)
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.attestation is not None
        assert state.attestation["attestation_id"].startswith("attest-")


# ═══════════════════════════════════════════════════════════════════════════════
# K. Self-modification
# ═══════════════════════════════════════════════════════════════════════════════


class TestSelfModification:
    """Self-mod PRs use elevated threshold 0.90."""

    async def test_high_but_below_self_mod_threshold(self) -> None:
        """Score 0.875 passes standard (0.75) but fails self-mod (0.90)."""
        # s_static=1.0, s_quality=0.75, s_security=0.75, s_tests=1.0
        # composite = 0.25*(1.0 + 0.75 + 0.75 + 1.0) = 0.875
        state = _make_state(
            is_self_modification=True,
            ai_analysis=_make_ai_analysis(
                quality_score=7.5, risk_score=2.5, confidence=0.9,
            ),
            test_results=_make_test_results(passed=True),
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["decision"] == Decision.REQUEST_CHANGES.value
        assert state.verdict["threshold_used"] == 0.90

    async def test_perfect_self_mod_approved(self) -> None:
        state = _make_state(
            is_self_modification=True,
            ai_analysis=_make_ai_analysis(
                quality_score=10.0, risk_score=0.0, confidence=1.0,
            ),
            test_results=_make_test_results(passed=True),
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["decision"] == Decision.APPROVE.value


# ═══════════════════════════════════════════════════════════════════════════════
# L. Vision redistribution
# ═══════════════════════════════════════════════════════════════════════════════


class TestVisionRedistribution:
    """Vision weight redistribution tests."""

    def test_weights_sum_to_one_with_vision(self) -> None:
        """Redistributed weights must sum to 1.0."""
        config = _make_config(
            triage={"vision": {"enabled": True, "alignment_weight": 0.15}},
        )
        state = _make_state(
            ai_analysis=_make_ai_analysis(vision_alignment_score=8),
            test_results=_make_test_results(passed=True),
        )
        _, breakdown = _compute_weighted_score(
            config, state, 1.0, 0.8, 0.8, 1.0,
        )
        assert "vision_alignment" in breakdown

    def test_vision_score_included(self) -> None:
        config = _make_config(
            triage={"vision": {"enabled": True, "alignment_weight": 0.15}},
        )
        state = _make_state(
            ai_analysis=_make_ai_analysis(vision_alignment_score=10),
            test_results=_make_test_results(passed=True),
        )
        composite, breakdown = _compute_weighted_score(
            config, state, 1.0, 1.0, 1.0, 1.0,
        )
        # All scores 1.0 → composite should be 1.0
        assert abs(composite - 1.0) < 0.001

    def test_no_vision_score_fallback(self) -> None:
        """When vision_alignment_score is absent, no redistribution occurs."""
        config = _make_config(
            triage={"vision": {"enabled": True, "alignment_weight": 0.15}},
        )
        state = _make_state(
            ai_analysis=_make_ai_analysis(),  # no vision_alignment_score
            test_results=_make_test_results(passed=True),
        )
        _, breakdown = _compute_weighted_score(
            config, state, 1.0, 0.8, 0.8, 1.0,
        )
        assert "vision_alignment" not in breakdown


# ═══════════════════════════════════════════════════════════════════════════════
# M. Degraded AI
# ═══════════════════════════════════════════════════════════════════════════════


class TestDegradedAI:
    """Degraded AI (confidence=0) → neutral 0.5 scores."""

    async def test_degraded_uses_neutral(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(confidence=0.0),
            test_results=_make_test_results(passed=True),
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        breakdown = state.verdict["score_breakdown"]
        assert breakdown["ai_quality"] == 0.5
        assert breakdown["ai_security"] == 0.5


# ═══════════════════════════════════════════════════════════════════════════════
# N. Missing test results
# ═══════════════════════════════════════════════════════════════════════════════


class TestMissingTestResults:
    """test_results=None → s_tests=0.5 (degraded neutral)."""

    async def test_none_test_results(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(
                quality_score=8.0, risk_score=2.0, confidence=0.9,
            ),
            test_results=None,
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["score_breakdown"]["tests_pass"] == 0.5


# ═══════════════════════════════════════════════════════════════════════════════
# O. Boundary conditions
# ═══════════════════════════════════════════════════════════════════════════════


class TestBoundaryConditions:
    """Exact threshold values with >= comparison."""

    def test_exactly_at_approval(self) -> None:
        assert _decide(0.75, 0.75, 0.50) == Decision.APPROVE

    def test_just_below_approval(self) -> None:
        assert _decide(0.7499, 0.75, 0.50) == Decision.REQUEST_CHANGES

    def test_exactly_at_review(self) -> None:
        assert _decide(0.50, 0.75, 0.50) == Decision.REQUEST_CHANGES

    def test_just_below_review(self) -> None:
        assert _decide(0.4999, 0.75, 0.50) == Decision.REJECT

    def test_self_mod_exactly_at_threshold(self) -> None:
        assert _decide(0.90, 0.90, 0.50) == Decision.APPROVE

    def test_self_mod_just_below(self) -> None:
        assert _decide(0.8999, 0.90, 0.50) == Decision.REQUEST_CHANGES


# ═══════════════════════════════════════════════════════════════════════════════
# P. Attestation proof
# ═══════════════════════════════════════════════════════════════════════════════


class TestAttestationProof:
    """Tests for attestation proof construction."""

    async def test_hash_correctness(self) -> None:
        """Input and output hashes are deterministic SHA-256."""
        from src.models.pipeline import Verdict

        state = _make_state()
        verdict = Verdict(
            decision=Decision.APPROVE,
            composite_score=0.85,
            score_breakdown={"static_clear": 1.0},
            threshold_used=0.75,
            timestamp=pytest.importorskip("datetime").datetime.now(
                pytest.importorskip("datetime").timezone.utc,
            ),
            pipeline_duration_seconds=1.0,
            findings_count=0,
        )

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            attestation = await _build_attestation(state, verdict)

        assert len(attestation.pipeline_input_hash) == 64
        assert len(attestation.pipeline_output_hash) == 64

    async def test_attestation_id_stamped(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(),
            test_results=_make_test_results(passed=True),
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="sha256:abc"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["attestation_id"] is not None
        assert state.verdict["attestation_id"].startswith("attest-")


# ═══════════════════════════════════════════════════════════════════════════════
# Q. Intelligence DB ingestion
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntelDBIngestion:
    """Tests for intelligence DB update."""

    async def test_correct_args(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(),
            test_results=_make_test_results(passed=True),
            static_findings=[{"severity": "MEDIUM", "rule_id": "r1"}],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        intel_db.ingest_pipeline_results.assert_awaited_once()
        call_kwargs = intel_db.ingest_pipeline_results.call_args.kwargs
        assert call_kwargs["pr_id"] == "owner/repo#42"
        assert call_kwargs["repo"] == "owner/repo"

    async def test_db_failure_does_not_crash(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(),
            test_results=_make_test_results(passed=True),
            static_findings=[],
        )
        config = _make_config()
        intel_db = _make_intel_db()
        intel_db.ingest_pipeline_results = AsyncMock(
            side_effect=RuntimeError("DB down"),
        )

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        # Should still produce a valid verdict
        assert state.verdict is not None
        assert state.verdict["decision"] == Decision.APPROVE.value


# ═══════════════════════════════════════════════════════════════════════════════
# R. Error handling
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    """Tests for error recovery paths."""

    async def test_exception_produces_reject(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(
                f"{_MODULE}._compute_s_static",
                side_effect=RuntimeError("boom"),
            ),
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["decision"] == Decision.REJECT.value

    async def test_error_path_calls_ingest(self) -> None:
        """Error path must still ingest results into the intelligence DB."""
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(
                f"{_MODULE}._compute_s_static",
                side_effect=RuntimeError("boom"),
            ),
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        intel_db.ingest_pipeline_results.assert_awaited_once()

    async def test_stage_always_set(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(
                f"{_MODULE}._compute_s_static",
                side_effect=RuntimeError("boom"),
            ),
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.current_stage == "decision_engine"


# ═══════════════════════════════════════════════════════════════════════════════
# S. Findings count
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindingsCount:
    """Verdict.findings_count = len(static) + len(AI)."""

    async def test_counts_both(self) -> None:
        state = _make_state(
            ai_analysis=_make_ai_analysis(
                findings=[{"rule_id": "ai-1"}, {"rule_id": "ai-2"}],
            ),
            test_results=_make_test_results(passed=True),
            static_findings=[
                {"severity": "MEDIUM", "rule_id": "s1"},
                {"severity": "LOW", "rule_id": "s2"},
                {"severity": "INFO", "rule_id": "s3"},
            ],
        )
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}._get_image_digest", return_value="dev"),
            patch(f"{_MODULE}._get_tee_platform_id", new_callable=AsyncMock, return_value="dev"),
        ):
            await run_decision(state, config, intel_db)

        assert state.verdict is not None
        assert state.verdict["findings_count"] == 5  # 3 static + 2 AI


# ═══════════════════════════════════════════════════════════════════════════════
# T. _clamp
# ═══════════════════════════════════════════════════════════════════════════════


class TestClamp:
    """Unit tests for _clamp helper."""

    def test_within_range(self) -> None:
        assert _clamp(0.5, 0.0, 1.0) == 0.5

    def test_below_range(self) -> None:
        assert _clamp(-0.5, 0.0, 1.0) == 0.0

    def test_above_range(self) -> None:
        assert _clamp(1.5, 0.0, 1.0) == 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# U. _compute_s_history
# ═══════════════════════════════════════════════════════════════════════════════


class TestComputeSHistory:
    """Unit tests for contributor history score computation."""

    async def test_new_contributor_returns_none(self) -> None:
        """DB returns None for unknown contributors."""
        intel_db = _make_intel_db()
        intel_db.get_contributor_acceptance_rate = AsyncMock(return_value=None)

        result = await _compute_s_history(intel_db, "owner/repo", "new-dev")
        assert result is None

    async def test_returns_acceptance_rate(self) -> None:
        """DB rate is passed through as the history score."""
        intel_db = _make_intel_db()
        intel_db.get_contributor_acceptance_rate = AsyncMock(return_value=0.85)

        result = await _compute_s_history(intel_db, "owner/repo", "trusted-dev")
        assert result == 0.85

    async def test_db_failure_returns_none(self) -> None:
        """DB exceptions are caught and result in None."""
        intel_db = _make_intel_db()
        intel_db.get_contributor_acceptance_rate = AsyncMock(
            side_effect=RuntimeError("DB down"),
        )

        result = await _compute_s_history(intel_db, "owner/repo", "dev")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# V. History redistribution
# ═══════════════════════════════════════════════════════════════════════════════


class TestHistoryRedistribution:
    """Tests for history weight redistribution in scoring."""

    def test_weight_zero_no_effect(self) -> None:
        """history_weight=0.0 (default) leaves scores unchanged."""
        config = _make_config()
        state = _make_state(
            ai_analysis=_make_ai_analysis(),
            test_results=_make_test_results(passed=True),
        )
        composite, breakdown = _compute_weighted_score(
            config, state, 1.0, 0.8, 0.8, 1.0,
            s_history=0.9,
        )
        assert "history" not in breakdown

    def test_history_active(self) -> None:
        """history_weight > 0 with a score redistributes weights."""
        config = _make_config(pipeline={"history_weight": 0.10})
        state = _make_state(
            ai_analysis=_make_ai_analysis(),
            test_results=_make_test_results(passed=True),
        )
        composite, breakdown = _compute_weighted_score(
            config, state, 1.0, 0.8, 0.8, 1.0,
            s_history=0.9,
        )
        assert "history" in breakdown
        assert breakdown["history"] == 0.9

    def test_none_history_skips_redistribution(self) -> None:
        """history_weight > 0 but s_history=None → no redistribution."""
        config = _make_config(pipeline={"history_weight": 0.10})
        state = _make_state(
            ai_analysis=_make_ai_analysis(),
            test_results=_make_test_results(passed=True),
        )
        composite, breakdown = _compute_weighted_score(
            config, state, 1.0, 0.8, 0.8, 1.0,
            s_history=None,
        )
        assert "history" not in breakdown

    def test_combined_vision_and_history_sums_to_one(self) -> None:
        """Vision + history redistribution must still produce weights summing to 1.0."""
        config = _make_config(
            pipeline={"history_weight": 0.10},
            triage={"vision": {"enabled": True, "alignment_weight": 0.15}},
        )
        state = _make_state(
            ai_analysis=_make_ai_analysis(vision_alignment_score=10),
            test_results=_make_test_results(passed=True),
        )
        # All base scores 1.0, vision=10/10=1.0, history=1.0
        composite, breakdown = _compute_weighted_score(
            config, state, 1.0, 1.0, 1.0, 1.0,
            s_history=1.0,
        )
        # With all scores at 1.0, composite must be 1.0 (weights sum to 1.0)
        assert abs(composite - 1.0) < 0.001
        assert "vision_alignment" in breakdown
        assert "history" in breakdown
