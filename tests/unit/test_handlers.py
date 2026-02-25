"""Tests for handler helper logic: wallet lookups, bounty computation, and event dispatch."""

from __future__ import annotations

import os

import hashlib
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.api.handlers import (
    _resolve_bounty_from_linked_issue,
    handle_issue_event,
    handle_pr_event,
)
from src.config import SaltaXConfig, TriageConfig
from src.intelligence.database import IntelligenceDB
from src.pipeline.state import PipelineState

_ = pytest  # ensure pytest is used (fixture injection)

_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
async def intel_db():
    """Provide a fresh IntelligenceDB backed by PostgreSQL."""
    db = IntelligenceDB(database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3)
    await db.initialize()
    try:
        yield db
    finally:
        try:
            pool = db.pool
            async with pool.connection() as conn:
                tables = await (
                    await conn.execute(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                    )
                ).fetchall()
                for t in tables:
                    await conn.execute(f'TRUNCATE TABLE "{t["tablename"]}" CASCADE')
        except Exception:
            pass
        await db.close()


async def _insert_contributor(
    intel_db: IntelligenceDB,
    github_login: str,
    wallet_address: str = "",
) -> None:
    """Insert a contributor profile directly."""
    now = datetime.now(UTC).isoformat()
    cp_id = hashlib.sha256(github_login.encode()).hexdigest()[:16]
    async with intel_db.pool.connection() as conn:
        await conn.execute(
            "INSERT INTO contributor_profiles "
            "(id, github_login, wallet_address, total_submissions, "
            "approved_submissions, rejected_submissions, first_seen, last_active) "
            "VALUES (%s, %s, %s, 1, 1, 0, %s, %s)",
            (cp_id, github_login, wallet_address, now, now),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# A. get_contributor_wallet
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetContributorWallet:
    """Test IntelligenceDB.get_contributor_wallet()."""

    async def test_wallet_exists(self, intel_db) -> None:
        """Returns wallet address when profile exists with a wallet."""
        await _insert_contributor(intel_db, "alice", "0xAliceWallet")
        wallet = await intel_db.get_contributor_wallet("alice")
        assert wallet == "0xAliceWallet"

    async def test_no_profile(self, intel_db) -> None:
        """Returns None when no contributor profile exists."""
        wallet = await intel_db.get_contributor_wallet("unknown")
        assert wallet is None

    async def test_empty_wallet(self, intel_db) -> None:
        """Returns None when wallet_address is empty string."""
        await _insert_contributor(intel_db, "bob", "")
        wallet = await intel_db.get_contributor_wallet("bob")
        assert wallet is None


# ═══════════════════════════════════════════════════════════════════════════════
# B. Bounty computation from PR labels
# ═══════════════════════════════════════════════════════════════════════════════


class TestBountyFromLabels:
    """Test bounty amount computation from PR label matching.

    The logic lives in handle_pr_event() — tested here as a unit by
    replicating the label-matching algorithm.
    """

    def _compute_bounty(
        self, labels: list[str], bounty_labels: dict[str, float],
    ) -> int | None:
        """Replicate the handler's label-to-bounty logic."""
        for label in labels:
            if label.startswith("bounty-"):
                eth_amount = bounty_labels.get(label)
                if eth_amount is not None:
                    return int(eth_amount * 10**18)
        return None

    def test_bounty_sm(self) -> None:
        """bounty-sm label → 0.05 ETH in wei."""
        labels = {"bounty-sm": 0.05, "bounty-md": 0.10}
        result = self._compute_bounty(["bounty-sm"], labels)
        assert result == 50000000000000000  # 0.05 * 10^18

    def test_no_bounty_label(self) -> None:
        """No bounty label → None."""
        labels = {"bounty-sm": 0.05}
        result = self._compute_bounty(["enhancement", "bug"], labels)
        assert result is None

    def test_unknown_bounty_label(self) -> None:
        """Unknown bounty-xxx label → None."""
        labels = {"bounty-sm": 0.05}
        result = self._compute_bounty(["bounty-unknown"], labels)
        assert result is None

    def test_first_matching_label_wins(self) -> None:
        """When multiple bounty labels exist, first match wins."""
        labels = {"bounty-sm": 0.05, "bounty-md": 0.10}
        result = self._compute_bounty(["bounty-md", "bounty-sm"], labels)
        assert result == 100000000000000000  # 0.10 * 10^18 (bounty-md first)


# ═══════════════════════════════════════════════════════════════════════════════
# C. handle_pr_event failure paths (Doc 27)
# ═══════════════════════════════════════════════════════════════════════════════


def _pr_data(**overrides: Any) -> dict[str, Any]:
    """Build realistic PR event data matching webhook parser output."""
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


class TestHandlePrEventFailurePaths:
    """Verify handle_pr_event resilience to subsystem failures (Doc 27)."""

    async def test_diff_fetch_failure(self) -> None:
        """github_client.get_pr_diff raises → handler catches, does not crash."""
        client = AsyncMock()
        client.get_pr_diff = AsyncMock(side_effect=RuntimeError("HTTP 500"))

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)
        pipeline = AsyncMock()
        config = SaltaXConfig()

        # Should not raise — handler's outer except catches all errors
        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        # Pipeline should not have been called (diff fetch failed first)
        pipeline.run.assert_not_awaited()

    async def test_self_mod_detection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When repo matches config.agent.repo, is_self_modification is set."""
        state = PipelineState(
            pr_id="my-org/saltax#42",
            repo="my-org/saltax",
            repo_url="https://github.com/my-org/saltax",
            commit_sha="abc123",
            diff="diff",
            base_branch="main",
            head_branch="fix-x",
            pr_author="alice",
            is_self_modification=True,
        )
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)

        client = AsyncMock()
        client.get_pr_diff = AsyncMock(return_value="diff content")
        client.list_issue_comments = AsyncMock(return_value=[])
        client.create_comment = AsyncMock(return_value=None)

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        config = SaltaXConfig()
        config.agent.repo = "my-org/saltax"

        monkeypatch.setattr(
            "src.selfmerge.detector.extract_modified_files",
            lambda diff: ["src/pipeline/runner.py"],
        )
        monkeypatch.setattr(
            "src.selfmerge.detector.is_self_modification",
            lambda files: True,
        )

        await handle_pr_event(
            _pr_data(
                repo_full_name="my-org/saltax",
                pr_id="my-org/saltax#42",
                installation_id=1,
            ),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        # Pipeline was called
        pipeline.run.assert_awaited_once()
        # The state dict passed to pipeline should have is_self_modification=True
        call_dict = pipeline.run.call_args[0][0]
        assert call_dict["is_self_modification"] is True

    async def test_bounty_from_labels_in_handler(self) -> None:
        """PR labels containing bounty-md → bounty_amount_wei set in state dict."""
        state = PipelineState(
            pr_id="owner/repo#42",
            repo="owner/repo",
            repo_url="https://github.com/owner/repo",
            commit_sha="abc",
            diff="diff",
            base_branch="main",
            head_branch="fix",
            pr_author="alice",
        )
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)

        client = AsyncMock()
        client.get_pr_diff = AsyncMock(return_value="diff")
        client.list_issue_comments = AsyncMock(return_value=[])

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        config = SaltaXConfig()

        await handle_pr_event(
            _pr_data(labels=["enhancement", "bounty-md"]),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        pipeline.run.assert_awaited_once()
        call_dict = pipeline.run.call_args[0][0]
        assert call_dict["bounty_amount_wei"] == int(0.10 * 10**18)

    async def test_handle_issue_event_closed(self) -> None:
        """Closed action triggers update_issue_status on intel_db."""
        intel_db = AsyncMock()
        intel_db.update_issue_status = AsyncMock()

        client = AsyncMock()
        config = SaltaXConfig()

        issue_data: dict[str, Any] = {
            "action": "closed",
            "issue_number": 7,
            "repo_full_name": "owner/repo",
            "repo": "owner/repo",
            "labels": [],
            "title": "Bug",
            "body": "broken",
            "state": "closed",
        }

        await handle_issue_event(
            issue_data,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        intel_db.update_issue_status.assert_awaited_once_with("owner/repo", 7, "closed")

    async def test_dedup_gate_runs_when_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When triage.dedup.enabled, run_dedup_check is called before pipeline."""
        state = PipelineState(
            pr_id="owner/repo#42",
            repo="owner/repo",
            repo_url="https://github.com/owner/repo",
            commit_sha="abc",
            diff="diff",
            base_branch="main",
            head_branch="fix",
            pr_author="alice",
            verdict={"decision": "APPROVE", "composite_score": 0.9,
                     "threshold_used": 0.75, "score_breakdown": {}},
            attestation={"attestation_id": "att-1"},
        )
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)

        client = AsyncMock()
        client.get_pr_diff = AsyncMock(return_value="diff")
        client.list_issue_comments = AsyncMock(return_value=[])
        client.create_comment = AsyncMock(return_value=None)

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        config = SaltaXConfig(triage=TriageConfig(enabled=True))
        env = AsyncMock()

        mock_dedup = AsyncMock(return_value=[])
        monkeypatch.setattr("src.triage.dedup.run_dedup_check", mock_dedup)
        monkeypatch.setattr(
            "src.triage.dedup.post_dedup_comment", AsyncMock(),
        )

        await handle_pr_event(
            _pr_data(),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
            env=env,
        )

        mock_dedup.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════════════════
# D. Bounty resolution from linked issues
# ═══════════════════════════════════════════════════════════════════════════════


def _github_issue(*, labels: list[str]) -> dict[str, Any]:
    """Build a GitHub issue API response with the given label names."""
    return {
        "number": 11,
        "title": "Test issue",
        "state": "open",
        "labels": [{"name": lbl, "color": "0e8a16"} for lbl in labels],
    }


class TestResolveBountyFromLinkedIssue:
    """Test _resolve_bounty_from_linked_issue() helper."""

    async def test_linked_issue_with_bounty_label(self) -> None:
        """PR body has 'Closes #11', issue #11 has bounty-md → 0.10 ETH."""
        client = AsyncMock()
        client.get_issue = AsyncMock(return_value=_github_issue(labels=["bounty-md"]))

        config = SaltaXConfig()
        result = await _resolve_bounty_from_linked_issue(
            pr_data=_pr_data(body="Closes #11"),
            config=config,
            github_client=client,
            installation_id=1,
            repo="owner/repo",
        )

        assert result == int(0.10 * 10**18)
        client.get_issue.assert_awaited_once_with("owner/repo", 11, 1)

    async def test_no_linked_issue(self) -> None:
        """PR body has no 'Closes #N' → returns None, no API call."""
        client = AsyncMock()

        config = SaltaXConfig()
        result = await _resolve_bounty_from_linked_issue(
            pr_data=_pr_data(body="Just a regular PR"),
            config=config,
            github_client=client,
            installation_id=1,
            repo="owner/repo",
        )

        assert result is None
        client.get_issue.assert_not_awaited()

    async def test_linked_issue_no_bounty_label(self) -> None:
        """Issue exists but has no bounty label → returns None."""
        client = AsyncMock()
        client.get_issue = AsyncMock(
            return_value=_github_issue(labels=["enhancement", "help-wanted"]),
        )

        config = SaltaXConfig()
        result = await _resolve_bounty_from_linked_issue(
            pr_data=_pr_data(body="Fixes #11"),
            config=config,
            github_client=client,
            installation_id=1,
            repo="owner/repo",
        )

        assert result is None

    async def test_api_error_returns_none(self) -> None:
        """GitHub API failure → returns None (fail-open)."""
        client = AsyncMock()
        client.get_issue = AsyncMock(side_effect=RuntimeError("HTTP 500"))

        config = SaltaXConfig()
        result = await _resolve_bounty_from_linked_issue(
            pr_data=_pr_data(body="Closes #11"),
            config=config,
            github_client=client,
            installation_id=1,
            repo="owner/repo",
        )

        assert result is None

    async def test_unknown_bounty_label_returns_none(self) -> None:
        """Issue has bounty-xxx not in config → returns None."""
        client = AsyncMock()
        client.get_issue = AsyncMock(
            return_value=_github_issue(labels=["bounty-mega"]),
        )

        config = SaltaXConfig()
        result = await _resolve_bounty_from_linked_issue(
            pr_data=_pr_data(body="Closes #11"),
            config=config,
            github_client=client,
            installation_id=1,
            repo="owner/repo",
        )

        assert result is None

    async def test_branch_name_extraction(self) -> None:
        """Issue number from branch name (e.g. feat/issue-11) also resolves."""
        client = AsyncMock()
        client.get_issue = AsyncMock(
            return_value=_github_issue(labels=["bounty-sm"]),
        )

        config = SaltaXConfig()
        result = await _resolve_bounty_from_linked_issue(
            pr_data=_pr_data(body="No issue ref here", head_branch="fix/issue-11"),
            config=config,
            github_client=client,
            installation_id=1,
            repo="owner/repo",
        )

        assert result == int(0.05 * 10**18)


class TestBountyResolutionInHandler:
    """Integration: bounty from linked issue flows through handle_pr_event."""

    async def test_pr_no_bounty_label_issue_has_bounty(self) -> None:
        """PR has no bounty label; linked issue has bounty-md → state gets bounty."""
        state = PipelineState(
            pr_id="owner/repo#42",
            repo="owner/repo",
            repo_url="https://github.com/owner/repo",
            commit_sha="abc",
            diff="diff",
            base_branch="main",
            head_branch="fix",
            pr_author="alice",
        )
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)

        client = AsyncMock()
        client.get_pr_diff = AsyncMock(return_value="diff")
        client.list_issue_comments = AsyncMock(return_value=[])
        client.get_issue = AsyncMock(
            return_value=_github_issue(labels=["bounty-md", "enhancement"]),
        )

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        config = SaltaXConfig()

        await handle_pr_event(
            _pr_data(labels=[], body="Closes #11"),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        pipeline.run.assert_awaited_once()
        call_dict = pipeline.run.call_args[0][0]
        assert call_dict["bounty_amount_wei"] == int(0.10 * 10**18)

    async def test_pr_bounty_takes_precedence_over_issue(self) -> None:
        """PR has bounty-sm, linked issue has bounty-lg → PR wins (0.05 ETH)."""
        state = PipelineState(
            pr_id="owner/repo#42",
            repo="owner/repo",
            repo_url="https://github.com/owner/repo",
            commit_sha="abc",
            diff="diff",
            base_branch="main",
            head_branch="fix",
            pr_author="alice",
        )
        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=state)

        client = AsyncMock()
        client.get_pr_diff = AsyncMock(return_value="diff")
        client.list_issue_comments = AsyncMock(return_value=[])

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        config = SaltaXConfig()

        await handle_pr_event(
            _pr_data(labels=["bounty-sm"], body="Closes #11"),
            pipeline=pipeline,
            github_client=client,
            intel_db=intel_db,
            config=config,
        )

        pipeline.run.assert_awaited_once()
        call_dict = pipeline.run.call_args[0][0]
        assert call_dict["bounty_amount_wei"] == int(0.05 * 10**18)
        # Issue should NOT have been fetched (PR label takes precedence)
        client.get_issue.assert_not_awaited()
