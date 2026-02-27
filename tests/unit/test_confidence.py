"""Tests for confidence scoring, tiering, calibration, and display integration.

Covers:
- Core functions in src/feedback/confidence.py
- Confidence column in format_pipeline_result (src/github/comments.py)
- Findings section in _build_advisory_body (src/triage/advisory.py)
- Badge display in _build_findings_detail (src/github/summary.py)
- min_display_confidence config default
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.config import PipelineConfig
from src.feedback.confidence import (
    _safe_confidence,
    calibrated_confidence,
    confidence_badge,
    confidence_badge_compact,
    confidence_tier,
    filter_findings_by_confidence,
)
from src.github.comments import format_pipeline_result
from src.github.summary import _build_findings_detail
from src.pipeline.state import PipelineState
from src.triage.advisory import _build_advisory_body

_ = pytest  # ensure pytest is used (fixture injection)


# =============================================================================
# A. confidence_tier
# =============================================================================


class TestConfidenceTier:
    def test_high(self) -> None:
        assert confidence_tier(0.95) == "High"

    def test_medium(self) -> None:
        assert confidence_tier(0.65) == "Medium"

    def test_low(self) -> None:
        assert confidence_tier(0.30) == "Low"

    def test_boundary_080(self) -> None:
        assert confidence_tier(0.80) == "High"

    def test_boundary_050(self) -> None:
        assert confidence_tier(0.50) == "Medium"

    def test_zero(self) -> None:
        assert confidence_tier(0.0) == "Low"

    def test_one(self) -> None:
        assert confidence_tier(1.0) == "High"


# =============================================================================
# B. confidence_badge (full)
# =============================================================================


class TestConfidenceBadge:
    def test_high_badge(self) -> None:
        result = confidence_badge(0.85)
        assert ":green_circle:" in result
        assert "**High**" in result
        assert "(85%)" in result

    def test_low_badge(self) -> None:
        result = confidence_badge(0.20)
        assert ":white_circle:" in result
        assert "**Low**" in result
        assert "(20%)" in result

    def test_medium_badge(self) -> None:
        result = confidence_badge(0.60)
        assert ":yellow_circle:" in result
        assert "**Medium**" in result
        assert "(60%)" in result


# =============================================================================
# C. confidence_badge_compact
# =============================================================================


class TestConfidenceBadgeCompact:
    def test_high_compact(self) -> None:
        assert confidence_badge_compact(0.85) == "High (85%)"

    def test_medium_compact(self) -> None:
        assert confidence_badge_compact(0.70) == "Medium (70%)"

    def test_low_compact(self) -> None:
        assert confidence_badge_compact(0.30) == "Low (30%)"

    def test_non_float_returns_dash(self) -> None:
        result = confidence_badge_compact("HIGH")  # type: ignore[arg-type]
        assert result == "\u2014"

    def test_none_returns_dash(self) -> None:
        result = confidence_badge_compact(None)  # type: ignore[arg-type]
        assert result == "\u2014"

    def test_int_input(self) -> None:
        assert confidence_badge_compact(1) == "High (100%)"


# =============================================================================
# D. _safe_confidence
# =============================================================================


class TestSafeConfidence:
    def test_float_passthrough(self) -> None:
        assert _safe_confidence(0.85) == 0.85

    def test_int_coercion(self) -> None:
        assert _safe_confidence(1) == 1.0

    def test_string_number(self) -> None:
        assert _safe_confidence("0.85") == 0.85

    def test_string_tier_name(self) -> None:
        assert _safe_confidence("HIGH") is None

    def test_none(self) -> None:
        assert _safe_confidence(None) is None

    def test_negative_clamped(self) -> None:
        assert _safe_confidence(-0.5) == 0.0

    def test_above_one_clamped(self) -> None:
        assert _safe_confidence(1.5) == 1.0

    def test_string_zero(self) -> None:
        assert _safe_confidence("0.0") == 0.0

    def test_empty_string(self) -> None:
        assert _safe_confidence("") is None

    def test_bool_treated_as_int(self) -> None:
        # bool is subclass of int in Python
        assert _safe_confidence(True) == 1.0
        assert _safe_confidence(False) == 0.0


# =============================================================================
# E. calibrated_confidence
# =============================================================================


class TestCalibratedConfidence:
    async def test_no_feedback(self) -> None:
        """No pattern found -> returns raw confidence unchanged."""
        intel_db = AsyncMock()
        intel_db.get_rule_feedback_stats = AsyncMock(return_value=None)

        result = await calibrated_confidence(
            raw_confidence=0.85,
            rule_id="test-rule",
            intel_db=intel_db,
        )
        assert result == 0.85

    async def test_few_signals(self) -> None:
        """< 3 feedback signals -> returns raw confidence unchanged."""
        intel_db = AsyncMock()
        intel_db.get_rule_feedback_stats = AsyncMock(
            return_value={"confirmed_true_positive": 1, "confirmed_false_positive": 1},
        )

        result = await calibrated_confidence(
            raw_confidence=0.85,
            rule_id="test-rule",
            intel_db=intel_db,
        )
        assert result == 0.85

    async def test_calibration_formula(self) -> None:
        """60/40 blend with known TP/FP counts."""
        intel_db = AsyncMock()
        # TP rate = 8 / (8 + 2) = 0.8
        intel_db.get_rule_feedback_stats = AsyncMock(
            return_value={"confirmed_true_positive": 8, "confirmed_false_positive": 2},
        )

        result = await calibrated_confidence(
            raw_confidence=0.90,
            rule_id="test-rule",
            intel_db=intel_db,
        )
        # 0.60 * 0.90 + 0.40 * 0.80 = 0.54 + 0.32 = 0.86
        assert abs(result - 0.86) < 0.001

    async def test_100_percent_fp(self) -> None:
        """All feedback is FP -> confidence decays toward 0."""
        intel_db = AsyncMock()
        intel_db.get_rule_feedback_stats = AsyncMock(
            return_value={"confirmed_true_positive": 0, "confirmed_false_positive": 10},
        )

        result = await calibrated_confidence(
            raw_confidence=0.80,
            rule_id="test-rule",
            intel_db=intel_db,
        )
        # 0.60 * 0.80 + 0.40 * 0.0 = 0.48
        assert abs(result - 0.48) < 0.001

    async def test_100_percent_tp(self) -> None:
        """All feedback is TP -> confidence stays high."""
        intel_db = AsyncMock()
        intel_db.get_rule_feedback_stats = AsyncMock(
            return_value={"confirmed_true_positive": 10, "confirmed_false_positive": 0},
        )

        result = await calibrated_confidence(
            raw_confidence=0.70,
            rule_id="test-rule",
            intel_db=intel_db,
        )
        # 0.60 * 0.70 + 0.40 * 1.0 = 0.42 + 0.40 = 0.82
        assert abs(result - 0.82) < 0.001

    async def test_clamped_0_1(self) -> None:
        """Result never exceeds [0.0, 1.0]."""
        intel_db = AsyncMock()
        intel_db.get_rule_feedback_stats = AsyncMock(
            return_value={"confirmed_true_positive": 100, "confirmed_false_positive": 0},
        )

        result = await calibrated_confidence(
            raw_confidence=1.0,
            rule_id="test-rule",
            intel_db=intel_db,
        )
        assert 0.0 <= result <= 1.0


# =============================================================================
# F. filter_findings_by_confidence
# =============================================================================


class TestFilterFindings:
    def test_no_filter(self) -> None:
        """min=0.0 -> all findings returned."""
        findings = [
            {"confidence": 0.1, "message": "low"},
            {"confidence": 0.9, "message": "high"},
        ]
        result = filter_findings_by_confidence(findings, min_confidence=0.0)
        assert len(result) == 2

    def test_filters_low(self) -> None:
        """min=0.5 -> low-confidence excluded."""
        findings = [
            {"confidence": 0.3, "message": "low"},
            {"confidence": 0.7, "message": "high"},
        ]
        result = filter_findings_by_confidence(findings, min_confidence=0.5)
        assert len(result) == 1
        assert result[0]["message"] == "high"

    def test_missing_confidence_defaults_to_half(self) -> None:
        """Missing key treated as 0.5 — survives moderate threshold."""
        findings = [{"message": "no confidence key"}]
        result = filter_findings_by_confidence(findings, min_confidence=0.4)
        assert len(result) == 1

    def test_missing_confidence_filtered_by_strict_threshold(self) -> None:
        """Missing key at 0.5 filtered by 0.6 threshold."""
        findings = [{"message": "no confidence key"}]
        result = filter_findings_by_confidence(findings, min_confidence=0.6)
        assert len(result) == 0

    def test_string_confidence_treated_as_none(self) -> None:
        """String tier name -> None -> defaults to 0.5."""
        findings = [{"confidence": "HIGH", "message": "string conf"}]
        result = filter_findings_by_confidence(findings, min_confidence=0.4)
        assert len(result) == 1

    def test_empty_list(self) -> None:
        assert filter_findings_by_confidence([], min_confidence=0.5) == []


# =============================================================================
# G. format_pipeline_result confidence column
# =============================================================================


class TestFormatPipelineResultConfidence:
    def _make_finding(self, **overrides):
        """Build a Finding-like object for comments.py (typed Pydantic model)."""
        from src.models.enums import Severity, VulnerabilityCategory
        from src.models.pipeline import Finding

        defaults = {
            "rule_id": "test-rule",
            "severity": Severity.HIGH,
            "category": VulnerabilityCategory.INJECTION,
            "message": "Test finding",
            "file_path": "src/test.py",
            "line_start": 10,
            "line_end": 10,
            "confidence": 0.85,
            "source_stage": "static_scanner",
        }
        defaults.update(overrides)
        return Finding(**defaults)

    def _make_verdict(self):
        from datetime import datetime

        from src.models.enums import Decision
        from src.models.pipeline import Verdict

        return Verdict(
            decision=Decision.APPROVE,
            composite_score=0.85,
            score_breakdown={"static_clear": 0.9},
            threshold_used=0.75,
            timestamp=datetime.now(),
            pipeline_duration_seconds=1.0,
        )

    def test_confidence_column_present(self) -> None:
        verdict = self._make_verdict()
        findings = [self._make_finding()]
        result = format_pipeline_result(verdict, findings)
        assert "Confidence" in result
        assert "High (85%)" in result

    def test_sorted_by_confidence_desc(self) -> None:
        """Highest confidence finding first in output."""
        verdict = self._make_verdict()
        findings = [
            self._make_finding(confidence=0.30, message="low conf"),
            self._make_finding(confidence=0.95, message="high conf"),
            self._make_finding(confidence=0.60, message="med conf"),
        ]
        result = format_pipeline_result(verdict, findings)
        # Extract only the findings section rows (contain confidence badges)
        lines = result.split("\n")
        finding_rows = [
            ln for ln in lines
            if ln.startswith("| ") and "High (" in ln or "Medium (" in ln or "Low (" in ln
        ]
        assert len(finding_rows) == 3
        assert "high conf" in finding_rows[0]
        assert "low conf" in finding_rows[-1]


# =============================================================================
# H. Advisory findings section
# =============================================================================


def _make_pipeline_state(**overrides) -> PipelineState:
    """Build a PipelineState with sensible defaults."""
    defaults = {
        "pr_id": "owner/repo#42",
        "repo": "owner/repo",
        "repo_url": "https://github.com/owner/repo",
        "commit_sha": "abc123",
        "diff": "diff --git a/foo.py b/foo.py",
        "base_branch": "main",
        "head_branch": "fix-bug",
        "pr_author": "alice",
        "pr_number": 42,
        "installation_id": 1,
        "verdict": {
            "decision": "APPROVE",
            "composite_score": 0.85,
            "threshold_used": 0.75,
            "score_breakdown": {},
        },
        "attestation": {"attestation_id": "att-001"},
    }
    defaults.update(overrides)
    return PipelineState(**defaults)


class TestAdvisoryFindingsSection:
    def test_findings_section_present(self) -> None:
        """Advisory body should have a '### Findings' section when findings exist."""
        state = _make_pipeline_state(static_findings=[
            {"severity": "HIGH", "file_path": "src/foo.py", "message": "SQL injection",
             "confidence": 0.85},
        ])
        body = _build_advisory_body(state)
        assert "### Findings" in body

    def test_confidence_in_advisory(self) -> None:
        """Confidence column should appear in the advisory findings table."""
        state = _make_pipeline_state(static_findings=[
            {"severity": "HIGH", "file_path": "src/foo.py", "message": "SQL injection",
             "confidence": 0.85},
        ])
        body = _build_advisory_body(state)
        assert "Confidence" in body
        assert "High (85%)" in body

    def test_no_findings_no_section(self) -> None:
        """Empty findings -> no Findings section in advisory."""
        state = _make_pipeline_state(static_findings=[])
        body = _build_advisory_body(state)
        assert "### Findings" not in body

    def test_string_confidence_shows_dash(self) -> None:
        """String confidence values like 'HIGH' should show '—'."""
        state = _make_pipeline_state(static_findings=[
            {"severity": "HIGH", "file_path": "src/foo.py", "message": "issue",
             "confidence": "HIGH"},
        ])
        body = _build_advisory_body(state)
        assert "### Findings" in body
        # Should contain the em-dash fallback, not 'HIGH' in the confidence column
        assert "\u2014" in body

    def test_ai_findings_included(self) -> None:
        """AI analysis findings should also appear in the findings section."""
        state = _make_pipeline_state(
            static_findings=[
                {"severity": "HIGH", "file_path": "a.py", "message": "static",
                 "confidence": 0.90},
            ],
            ai_analysis={
                "quality_score": 8.0,
                "risk_score": 2.0,
                "findings": [
                    {"severity": "MEDIUM", "file_path": "b.py", "message": "ai-found",
                     "confidence": 0.70},
                ],
            },
        )
        body = _build_advisory_body(state)
        assert "static" in body
        assert "ai-found" in body

    def test_findings_capped_at_20(self) -> None:
        """Advisory findings table should cap at 20 with overflow message."""
        many_findings = [
            {"severity": "LOW", "file_path": f"f{i}.py", "message": f"msg{i}",
             "confidence": 0.5}
            for i in range(25)
        ]
        state = _make_pipeline_state(static_findings=many_findings)
        body = _build_advisory_body(state)
        assert "and 5 more findings" in body


# =============================================================================
# I. Summary confidence badge
# =============================================================================


class TestSummaryConfidenceBadge:
    def test_badge_formatting(self) -> None:
        """Uses compact badge, not raw value."""
        findings = [
            {"file_path": "src/foo.py", "severity": "HIGH", "rule_id": "S101",
             "line_start": 10, "message": "Issue", "confidence": 0.85},
        ]
        result = _build_findings_detail(findings)
        assert "High (85%)" in result
        # Should NOT contain raw 0.85 in the confidence column
        # (it may appear elsewhere in percentage form, which is fine)

    def test_string_confidence_handled(self) -> None:
        """'HIGH' string -> '—' (graceful fallback)."""
        findings = [
            {"file_path": "src/foo.py", "severity": "HIGH", "rule_id": "S101",
             "line_start": 10, "message": "Issue", "confidence": "HIGH"},
        ]
        result = _build_findings_detail(findings)
        assert "\u2014" in result

    def test_missing_confidence_handled(self) -> None:
        """Missing confidence key -> '—'."""
        findings = [
            {"file_path": "src/foo.py", "severity": "HIGH", "rule_id": "S101",
             "line_start": 10, "message": "Issue"},
        ]
        result = _build_findings_detail(findings)
        assert "\u2014" in result

    def test_sorted_by_confidence_desc(self) -> None:
        """Highest confidence finding should appear first."""
        findings = [
            {"file_path": "src/a.py", "severity": "LOW", "rule_id": "R1",
             "line_start": 1, "message": "low-conf", "confidence": 0.30},
            {"file_path": "src/b.py", "severity": "HIGH", "rule_id": "R2",
             "line_start": 1, "message": "high-conf", "confidence": 0.95},
        ]
        result = _build_findings_detail(findings)
        lines = result.split("\n")
        data_lines = [
            ln for ln in lines
            if ln.startswith("| ") and "---" not in ln and "#" not in ln
        ]
        assert "high-conf" in data_lines[0]


# =============================================================================
# J. PipelineConfig default
# =============================================================================


class TestPipelineConfigDefault:
    def test_min_display_confidence_default(self) -> None:
        config = PipelineConfig()
        assert config.min_display_confidence == 0.0

    def test_min_display_confidence_custom(self) -> None:
        config = PipelineConfig(min_display_confidence=0.3)
        assert config.min_display_confidence == 0.3

    def test_min_display_confidence_bounds(self) -> None:
        """Should reject values outside [0.0, 1.0]."""
        with pytest.raises(ValueError):
            PipelineConfig(min_display_confidence=1.5)
        with pytest.raises(ValueError):
            PipelineConfig(min_display_confidence=-0.1)
