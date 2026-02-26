"""Tests for triage advisory mode: body builder, labels, comment posting, dispatch."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.config import AdvisoryConfig, SaltaXConfig, TriageConfig
from src.pipeline.state import PipelineState
from src.triage.advisory import (
    _build_advisory_body,
    _manage_advisory_labels,
    dispatch_decision,
    post_advisory_review,
)

_ = pytest  # ensure pytest is used (fixture injection)


# -- Helpers -------------------------------------------------------------------


def _make_state(**overrides) -> PipelineState:
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
            "score_breakdown": {
                "static_clear": 0.90,
                "ai_quality": 0.80,
                "ai_security": 0.85,
                "tests_pass": 0.85,
            },
        },
        "attestation": {"attestation_id": "att-001"},
    }
    defaults.update(overrides)
    return PipelineState(**defaults)


def _advisory_config(**overrides) -> AdvisoryConfig:
    defaults = {
        "review_type": "COMMENT",
        "label_recommends_merge": "saltax-recommends-merge",
        "label_recommends_reject": "saltax-recommends-reject",
    }
    defaults.update(overrides)
    return AdvisoryConfig(**defaults)


def _make_config(*, mode: str = "advisory", triage_enabled: bool = True) -> SaltaXConfig:
    """Build a SaltaXConfig with triage settings."""
    return SaltaXConfig(
        triage=TriageConfig(
            enabled=triage_enabled,
            mode=mode,
            advisory=_advisory_config(),
        ),
    )


def _mock_client(*, existing_comments: list[dict] | None = None) -> AsyncMock:
    """Build an AsyncMock GitHubClient with list_issue_comments pre-configured."""
    client = AsyncMock()
    client.list_issue_comments = AsyncMock(
        return_value=existing_comments if existing_comments is not None else [],
    )
    return client


# =============================================================================
# A. _build_advisory_body
# =============================================================================


class TestBuildAdvisoryBody:
    """Markdown structure, decision mapping, all sections, missing data safety."""

    def test_contains_html_marker(self) -> None:
        state = _make_state()
        body = _build_advisory_body(state)
        assert "<!-- saltax-advisory:owner/repo:42 -->" in body

    def test_approve_maps_to_recommends_merge(self) -> None:
        state = _make_state(verdict={"decision": "APPROVE", "composite_score": 0.85,
                                     "threshold_used": 0.75, "score_breakdown": {}})
        body = _build_advisory_body(state)
        assert "Recommends Merge" in body

    def test_reject_maps_to_recommends_reject(self) -> None:
        state = _make_state(verdict={"decision": "REJECT", "composite_score": 0.40,
                                     "threshold_used": 0.75, "score_breakdown": {}})
        body = _build_advisory_body(state)
        assert "Recommends Reject" in body

    def test_request_changes_maps_to_recommends_reject(self) -> None:
        state = _make_state(verdict={"decision": "REQUEST_CHANGES", "composite_score": 0.40,
                                     "threshold_used": 0.75, "score_breakdown": {}})
        body = _build_advisory_body(state)
        assert "Recommends Reject" in body

    def test_contains_composite_score(self) -> None:
        state = _make_state()
        body = _build_advisory_body(state)
        assert "0.85" in body

    def test_contains_attestation_id(self) -> None:
        state = _make_state()
        body = _build_advisory_body(state)
        assert "att-001" in body

    def test_score_breakdown_table(self) -> None:
        state = _make_state()
        body = _build_advisory_body(state)
        assert "Score Breakdown" in body
        assert "static_clear" in body

    def test_static_findings_count(self) -> None:
        state = _make_state(static_findings=[
            {"severity": "high", "message": "SQL injection"},
            {"severity": "medium", "message": "XSS"},
            {"severity": "high", "message": "Path traversal"},
        ])
        body = _build_advisory_body(state)
        assert "3 findings" in body
        assert "high: 2" in body

    def test_duplicate_candidates_section(self) -> None:
        state = _make_state(duplicate_candidates=[
            {"pr_number": 10, "similarity": 0.92},
            {"pr_number": 15, "similarity": 0.87},
        ])
        body = _build_advisory_body(state)
        assert "Potential Duplicates" in body
        assert "PR #10" in body
        assert "0.92" in body

    def test_self_modification_disclaimer(self) -> None:
        state = _make_state(is_self_modification=True)
        body = _build_advisory_body(state)
        assert "modifies SaltaX's own code" in body

    def test_no_self_mod_disclaimer_when_false(self) -> None:
        state = _make_state(is_self_modification=False)
        body = _build_advisory_body(state)
        assert "modifies SaltaX's own code" not in body

    def test_missing_verdict_defaults_gracefully(self) -> None:
        state = _make_state(verdict={})
        body = _build_advisory_body(state)
        assert "Recommends Reject" in body  # empty decision -> not APPROVE
        assert "0.00" in body  # default composite

    def test_missing_ai_analysis_shows_na(self) -> None:
        state = _make_state(ai_analysis=None)
        body = _build_advisory_body(state)
        assert "AI Analysis | N/A" in body

    def test_test_results_present(self) -> None:
        state = _make_state(test_results={"passed": 45, "total_tests": 50})
        body = _build_advisory_body(state)
        assert "45/50 passed" in body

    def test_test_results_missing_shows_na(self) -> None:
        state = _make_state(test_results=None)
        body = _build_advisory_body(state)
        assert "Tests | N/A" in body

    def test_pipe_in_component_name_escaped(self) -> None:
        """Pipe characters in component names must be escaped for Markdown tables."""
        state = _make_state(verdict={
            "decision": "APPROVE",
            "composite_score": 0.85,
            "threshold_used": 0.75,
            "score_breakdown": {"pipe|test": 0.90},
        })
        body = _build_advisory_body(state)
        assert "pipe\\|test" in body

    def test_string_composite_score_defaults_to_zero(self) -> None:
        """String value for composite_score should not crash — falls back to 0."""
        state = _make_state(verdict={
            "decision": "APPROVE",
            "composite_score": "bad",
            "threshold_used": "also_bad",
            "score_breakdown": {},
        })
        body = _build_advisory_body(state)
        assert "0.00" in body


# =============================================================================
# B. _manage_advisory_labels
# =============================================================================


class TestManageAdvisoryLabels:
    """Mutual exclusion, idempotency, ensure-before-add, failure isolation."""

    async def test_approve_adds_merge_removes_reject(self) -> None:
        state = _make_state()
        client = AsyncMock()
        config = _advisory_config()

        await _manage_advisory_labels(state, "APPROVE", config, client)

        client.ensure_label.assert_any_await(
            "owner/repo", 1, "saltax-recommends-merge",
            color="0e8a16", description="SaltaX recommends merge",
        )
        client.add_label.assert_awaited_once_with(
            "owner/repo", 42, 1, "saltax-recommends-merge",
        )
        client.remove_label.assert_awaited_once_with(
            "owner/repo", 42, 1, "saltax-recommends-reject",
        )

    async def test_reject_adds_reject_removes_merge(self) -> None:
        state = _make_state()
        client = AsyncMock()
        config = _advisory_config()

        await _manage_advisory_labels(state, "REJECT", config, client)

        client.add_label.assert_awaited_once_with(
            "owner/repo", 42, 1, "saltax-recommends-reject",
        )
        client.remove_label.assert_awaited_once_with(
            "owner/repo", 42, 1, "saltax-recommends-merge",
        )

    async def test_ensure_label_failure_aborts_add_remove(self) -> None:
        """If ensure_label fails, add/remove should not be attempted."""
        state = _make_state()
        client = AsyncMock()
        client.ensure_label = AsyncMock(side_effect=RuntimeError("API error"))
        config = _advisory_config()

        await _manage_advisory_labels(state, "APPROVE", config, client)

        client.add_label.assert_not_awaited()
        client.remove_label.assert_not_awaited()

    async def test_add_label_failure_does_not_raise(self) -> None:
        """add_label failure should be logged, not propagated."""
        state = _make_state()
        client = AsyncMock()
        client.add_label = AsyncMock(side_effect=RuntimeError("API error"))
        config = _advisory_config()

        # Should not raise
        await _manage_advisory_labels(state, "APPROVE", config, client)

    async def test_missing_pr_number_skips(self) -> None:
        state = _make_state(pr_number=None)
        client = AsyncMock()
        config = _advisory_config()

        await _manage_advisory_labels(state, "APPROVE", config, client)

        client.ensure_label.assert_not_awaited()

    async def test_missing_installation_id_skips(self) -> None:
        state = _make_state(installation_id=None)
        client = AsyncMock()
        config = _advisory_config()

        await _manage_advisory_labels(state, "APPROVE", config, client)

        client.ensure_label.assert_not_awaited()

    async def test_ensures_both_labels(self) -> None:
        """Both merge and reject labels must be ensured before any add/remove."""
        state = _make_state()
        client = AsyncMock()
        config = _advisory_config()

        await _manage_advisory_labels(state, "APPROVE", config, client)

        assert client.ensure_label.await_count == 2
        label_names = [call.args[2] for call in client.ensure_label.call_args_list]
        assert "saltax-recommends-merge" in label_names
        assert "saltax-recommends-reject" in label_names

    async def test_custom_label_names(self) -> None:
        """Custom label names from config should be used."""
        state = _make_state()
        client = AsyncMock()
        config = _advisory_config(
            label_recommends_merge="custom-merge",
            label_recommends_reject="custom-reject",
        )

        await _manage_advisory_labels(state, "APPROVE", config, client)

        client.add_label.assert_awaited_once_with(
            "owner/repo", 42, 1, "custom-merge",
        )
        client.remove_label.assert_awaited_once_with(
            "owner/repo", 42, 1, "custom-reject",
        )


# =============================================================================
# C. post_advisory_review
# =============================================================================


class TestPostAdvisoryReview:
    """Update-or-create comment, 422 handling, labels-run-even-if-comment-fails."""

    async def test_creates_comment_when_none_exists(self) -> None:
        """No existing advisory comment -> create_comment called."""
        state = _make_state()
        client = _mock_client(existing_comments=[])
        config = _advisory_config()

        await post_advisory_review(state, config, client)

        client.list_issue_comments.assert_awaited_once()
        client.create_comment.assert_awaited_once()
        client.update_comment.assert_not_awaited()
        body = client.create_comment.call_args.args[3]
        assert "Recommends Merge" in body

    async def test_updates_comment_when_marker_exists(self) -> None:
        """Existing comment with our marker -> update_comment called."""
        state = _make_state()
        existing = [
            {"id": 100, "body": "unrelated comment"},
            {"id": 200, "body": "<!-- saltax-advisory:owner/repo:42 -->\nold body"},
        ]
        client = _mock_client(existing_comments=existing)
        config = _advisory_config()

        await post_advisory_review(state, config, client)

        client.update_comment.assert_awaited_once()
        assert client.update_comment.call_args.args[1] == 200
        client.create_comment.assert_not_awaited()

    async def test_422_logged_as_warning(self) -> None:
        """422 (PR closed/merged) should be a warning, not an error."""
        state = _make_state()
        client = _mock_client()
        exc = Exception("Unprocessable Entity")
        exc.status_code = 422  # type: ignore[attr-defined]
        client.create_comment = AsyncMock(side_effect=exc)
        config = _advisory_config()

        # Should not raise
        await post_advisory_review(state, config, client)

        # Labels should still run
        client.ensure_label.assert_awaited()

    async def test_labels_run_even_if_comment_fails(self) -> None:
        state = _make_state()
        client = _mock_client()
        client.create_comment = AsyncMock(side_effect=RuntimeError("Network error"))
        config = _advisory_config()

        await post_advisory_review(state, config, client)

        # Labels should still be applied
        client.ensure_label.assert_awaited()
        client.add_label.assert_awaited()

    async def test_missing_pr_number_skips(self) -> None:
        state = _make_state(pr_number=None)
        client = _mock_client()
        config = _advisory_config()

        await post_advisory_review(state, config, client)

        client.list_issue_comments.assert_not_awaited()

    async def test_runtime_guard_rejects_non_comment(self) -> None:
        """If review_type is somehow not COMMENT, raise RuntimeError."""
        state = _make_state()
        client = _mock_client()
        # Bypass pydantic validation for test — simulate config schema relaxation
        config = _advisory_config()
        object.__setattr__(config, "review_type", "APPROVE")

        with pytest.raises(RuntimeError, match="must be 'COMMENT'"):
            await post_advisory_review(state, config, client)

    async def test_list_comments_failure_falls_back_to_create(self) -> None:
        """If list_issue_comments fails, the error propagates to the except block."""
        state = _make_state()
        client = _mock_client()
        client.list_issue_comments = AsyncMock(side_effect=RuntimeError("API down"))
        config = _advisory_config()

        # Should not raise — caught by the outer try/except
        await post_advisory_review(state, config, client)

        # Labels still run
        client.ensure_label.assert_awaited()


# =============================================================================
# D. dispatch_decision
# =============================================================================


class TestDispatchDecision:
    """Advisory/autonomous routing, self-mod override, hard constraint, no-verdict."""

    async def test_advisory_mode_posts_comment(self) -> None:
        state = _make_state()
        client = _mock_client()
        config = _make_config(mode="advisory")
        intel_db = AsyncMock()

        await dispatch_decision(state, config, client, intel_db=intel_db)

        client.list_issue_comments.assert_awaited_once()
        # Either create_comment or update_comment called (create for empty list)
        client.create_comment.assert_awaited_once()

    async def test_autonomous_mode_creates_window(self) -> None:
        state = _make_state()
        client = _mock_client()
        config = _make_config(mode="autonomous")
        intel_db = AsyncMock()

        with patch("src.verification.window.create_window", new_callable=AsyncMock) as mock_window:
            await dispatch_decision(state, config, client, intel_db=intel_db)

        mock_window.assert_awaited_once()
        client.create_comment.assert_not_awaited()

    async def test_autonomous_reject_does_not_create_window(self) -> None:
        state = _make_state(verdict={"decision": "REJECT", "composite_score": 0.40,
                                     "threshold_used": 0.75, "score_breakdown": {}})
        client = _mock_client()
        config = _make_config(mode="autonomous")
        intel_db = AsyncMock()

        with patch("src.verification.window.create_window", new_callable=AsyncMock) as mock_window:
            await dispatch_decision(state, config, client, intel_db=intel_db)

        mock_window.assert_not_awaited()

    async def test_self_mod_forces_advisory_even_in_autonomous(self) -> None:
        """Self-modification override: autonomous mode + self-mod -> advisory."""
        state = _make_state(is_self_modification=True)
        client = _mock_client()
        config = _make_config(mode="autonomous")
        intel_db = AsyncMock()

        with patch("src.verification.window.create_window", new_callable=AsyncMock) as mock_window:
            await dispatch_decision(state, config, client, intel_db=intel_db)

        # Advisory comment posted, NOT verification window
        client.create_comment.assert_awaited_once()
        mock_window.assert_not_awaited()

    async def test_hard_constraint_merge_never_called(self) -> None:
        """HARD CONSTRAINT: merge_pr must never be called from advisory dispatch."""
        state = _make_state()
        client = _mock_client()
        client.merge_pr = AsyncMock(
            side_effect=AssertionError("HARD CONSTRAINT VIOLATED: merge_pr called"),
        )
        config = _make_config(mode="advisory")
        intel_db = AsyncMock()

        # If merge_pr were called, it would raise AssertionError
        await dispatch_decision(state, config, client, intel_db=intel_db)

        client.merge_pr.assert_not_awaited()

    async def test_no_verdict_returns_early(self) -> None:
        state = _make_state(verdict=None)
        client = _mock_client()
        config = _make_config(mode="advisory")
        intel_db = AsyncMock()

        await dispatch_decision(state, config, client, intel_db=intel_db)

        client.create_comment.assert_not_awaited()

    async def test_advisory_failure_does_not_propagate(self) -> None:
        """Dispatch should catch advisory errors and not propagate."""
        state = _make_state()
        client = _mock_client()
        client.list_issue_comments = AsyncMock(side_effect=RuntimeError("Network down"))
        config = _make_config(mode="advisory")
        intel_db = AsyncMock()

        # Should not raise — dispatch catches errors
        await dispatch_decision(state, config, client, intel_db=intel_db)

    async def test_autonomous_create_window_failure_does_not_propagate(self) -> None:
        """Verification window failure in autonomous mode should be caught."""
        state = _make_state()
        client = _mock_client()
        config = _make_config(mode="autonomous")
        intel_db = AsyncMock()

        with patch(
            "src.verification.window.create_window",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Window creation failed"),
        ):
            # Should not raise
            await dispatch_decision(state, config, client, intel_db=intel_db)


# =============================================================================
# E. Findings marker in advisory body (feedback learning)
# =============================================================================


class TestFindingsMarker:
    """Verify saltax-findings HTML comment embedding for feedback learning."""

    def test_advisory_body_contains_findings_marker(self) -> None:
        state = _make_state(static_findings=[
            {"rule_id": "semgrep.sqli", "severity": "HIGH", "message": "SQL injection"},
            {"rule_id": "semgrep.xss", "severity": "MEDIUM", "message": "XSS"},
        ])
        body = _build_advisory_body(state)
        assert "<!-- saltax-findings:semgrep.sqli,semgrep.xss -->" in body

    def test_advisory_body_no_marker_without_findings(self) -> None:
        state = _make_state(static_findings=[])
        body = _build_advisory_body(state)
        assert "saltax-findings" not in body

    def test_deduplicates_rule_ids(self) -> None:
        state = _make_state(static_findings=[
            {"rule_id": "rule-a", "severity": "HIGH", "message": "msg1"},
            {"rule_id": "rule-a", "severity": "HIGH", "message": "msg2"},
        ])
        body = _build_advisory_body(state)
        assert "<!-- saltax-findings:rule-a -->" in body

    def test_findings_without_rule_id_ignored(self) -> None:
        state = _make_state(static_findings=[
            {"severity": "HIGH", "message": "no rule_id"},
        ])
        body = _build_advisory_body(state)
        assert "saltax-findings" not in body

    def test_ai_findings_included_in_marker(self) -> None:
        state = _make_state(
            static_findings=[{"rule_id": "static-rule", "severity": "HIGH", "message": "m"}],
            ai_analysis={
                "quality_score": 0.8,
                "risk_score": 0.2,
                "findings": [
                    {"rule_id": "ai-rule", "message": "AI found issue"},
                ],
            },
        )
        body = _build_advisory_body(state)
        assert "ai-rule" in body
        assert "static-rule" in body
