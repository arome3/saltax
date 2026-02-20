"""Integration tests for triage advisory/autonomous dispatch in handle_pr_event."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.api.handlers import handle_pr_event
from src.config import (
    AdvisoryConfig,
    SaltaXConfig,
    TriageConfig,
)
from src.pipeline.state import PipelineState

_ = pytest  # ensure pytest is used (fixture injection)


# -- Helpers -------------------------------------------------------------------


def _pr_data(**overrides) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "action": "opened",
        "pr_id": "owner/repo#42",
        "repo_full_name": "owner/repo",
        "repo_url": "https://github.com/owner/repo",
        "head_sha": "abc123",
        "pr_number": 42,
        "author_login": "alice",
        "base_branch": "main",
        "head_branch": "fix-bug",
        "installation_id": 1,
        "labels": [],
        "title": "Fix bug",
        "body": "Fixes a small bug",
    }
    defaults.update(overrides)
    return defaults


def _make_pipeline_state(**overrides) -> PipelineState:
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


def _make_config(*, mode: str = "advisory", triage_enabled: bool = True) -> SaltaXConfig:
    return SaltaXConfig(
        triage=TriageConfig(
            enabled=triage_enabled,
            mode=mode,
            advisory=AdvisoryConfig(),
        ),
    )


def _mock_client(*, existing_comments: list[dict] | None = None) -> AsyncMock:
    """Build an AsyncMock GitHubClient with list_issue_comments pre-configured."""
    client = AsyncMock()
    client.get_pr_diff = AsyncMock(return_value="diff")
    client.list_issue_comments = AsyncMock(
        return_value=existing_comments if existing_comments is not None else [],
    )
    return client


# =============================================================================
# A. Advisory flow
# =============================================================================


class TestHandlerAdvisoryFlow:
    """Full webhook -> dispatch, advisory mode posts comment, autonomous opens window."""

    async def test_advisory_mode_posts_comment(self, monkeypatch) -> None:
        """Advisory mode should post an issue comment via dispatch_decision."""
        state = _make_pipeline_state()
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(mode="advisory")

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        client.list_issue_comments.assert_awaited_once()
        client.create_comment.assert_awaited_once()

    async def test_autonomous_mode_creates_window(self, monkeypatch) -> None:
        """Autonomous mode + APPROVE should create a verification window."""
        state = _make_pipeline_state()
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(mode="autonomous")

        mock_window = AsyncMock()
        monkeypatch.setattr("src.verification.window.create_window", mock_window)

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        mock_window.assert_awaited_once()
        client.create_comment.assert_not_awaited()

    async def test_triage_disabled_fallback_creates_window(self, monkeypatch) -> None:
        """When triage is disabled, APPROVE should fall back to direct verification."""
        state = _make_pipeline_state()
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(triage_enabled=False)

        mock_window = AsyncMock()
        monkeypatch.setattr("src.verification.window.create_window", mock_window)

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        mock_window.assert_awaited_once()
        client.create_comment.assert_not_awaited()

    async def test_self_mod_forces_advisory_in_handler(self, monkeypatch) -> None:
        """Self-modification should force advisory even in autonomous mode."""
        state = _make_pipeline_state(is_self_modification=True)
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(mode="autonomous")
        # Set agent.repo to match so self-mod detection triggers
        config.agent.repo = "owner/repo"

        # Mock self-mod detection to return True
        monkeypatch.setattr(
            "src.selfmerge.detector.extract_modified_files",
            lambda diff: ["src/main.py"],
        )
        monkeypatch.setattr(
            "src.selfmerge.detector.is_self_modification",
            lambda files: True,
        )

        mock_window = AsyncMock()
        monkeypatch.setattr("src.verification.window.create_window", mock_window)

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        # Advisory comment posted, NOT window
        client.create_comment.assert_awaited_once()
        mock_window.assert_not_awaited()


# =============================================================================
# B. Ordering
# =============================================================================


class TestHandlerOrdering:
    """Verify step ordering: pipeline -> ranking -> dispatch."""

    async def test_pipeline_runs_before_dispatch(self) -> None:
        """Pipeline must run before dispatch — dispatch reads pipeline state."""
        call_order: list[str] = []

        async def mock_run(state_dict):
            call_order.append("pipeline")
            return _make_pipeline_state()

        pipeline = AsyncMock()
        pipeline.run = mock_run
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        # Track dispatch via create_comment (the new comment path)
        orig_create_comment = client.create_comment

        async def tracked_create_comment(*args, **kwargs):
            call_order.append("dispatch")
            return await orig_create_comment(*args, **kwargs)

        client.create_comment = tracked_create_comment

        config = _make_config(mode="advisory")

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        assert call_order == ["pipeline", "dispatch"]

    async def test_no_verdict_skips_dispatch(self) -> None:
        """If pipeline produces no verdict, dispatch should not run."""
        state = _make_pipeline_state(verdict=None)
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(mode="advisory")

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        client.create_comment.assert_not_awaited()


# =============================================================================
# C. Partial failure
# =============================================================================


class TestHandlerPartialFailure:
    """Dispatch failure -> handler doesn't crash."""

    async def test_dispatch_failure_does_not_crash_handler(self) -> None:
        """If dispatch_decision raises, the handler's outer except catches it."""
        state = _make_pipeline_state()
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        client.list_issue_comments = AsyncMock(side_effect=RuntimeError("Network error"))
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(mode="advisory")

        # Should not raise
        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

    async def test_pipeline_failure_does_not_crash(self) -> None:
        """Pipeline failure should be caught by handler's outer except."""
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(side_effect=RuntimeError("Pipeline crashed"))
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(mode="advisory")

        # Should not raise
        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

    async def test_reject_verdict_in_advisory_mode(self) -> None:
        """REJECT verdict in advisory mode should post comment with reject label."""
        state = _make_pipeline_state(
            verdict={
                "decision": "REJECT",
                "composite_score": 0.40,
                "threshold_used": 0.75,
                "score_breakdown": {},
            },
        )
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(mode="advisory")

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        client.create_comment.assert_awaited_once()
        body = client.create_comment.call_args.args[3]
        assert "Recommends Reject" in body

    async def test_triage_disabled_window_failure_does_not_crash(self, monkeypatch) -> None:
        """Verification window failure in triage-disabled fallback should be caught."""
        state = _make_pipeline_state()
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)
        client = _mock_client()
        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        config = _make_config(triage_enabled=False)

        mock_window = AsyncMock(side_effect=RuntimeError("Window failed"))
        monkeypatch.setattr("src.verification.window.create_window", mock_window)

        # Should not raise — handler catches all errors
        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )
