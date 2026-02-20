"""Tests for handler helper logic: wallet lookups, bounty computation, and event dispatch."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.api.handlers import handle_issue_event, handle_pr_event
from src.config import SaltaXConfig, TriageConfig
from src.intelligence.database import IntelligenceDB
from src.pipeline.state import PipelineState

_ = pytest  # ensure pytest is used (fixture injection)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
async def intel_db(tmp_path, monkeypatch):
    """Provide a fresh IntelligenceDB with schema v3."""
    monkeypatch.setattr("src.intelligence.database.DB_PATH", tmp_path / "test.db")
    kms = AsyncMock()
    kms.unseal = AsyncMock(side_effect=Exception("no sealed data"))
    db = IntelligenceDB(kms=kms)
    await db.initialize()
    yield db
    await db.close()


async def _insert_contributor(
    intel_db: IntelligenceDB,
    github_login: str,
    wallet_address: str = "",
) -> None:
    """Insert a contributor profile directly."""
    db = intel_db._require_db()
    now = datetime.now(UTC).isoformat()
    cp_id = hashlib.sha256(github_login.encode()).hexdigest()[:16]
    async with intel_db._write_lock:
        await db.execute(
            "INSERT INTO contributor_profiles "
            "(id, github_login, wallet_address, total_submissions, "
            "approved_submissions, rejected_submissions, first_seen, last_active) "
            "VALUES (?, ?, ?, 1, 1, 0, ?, ?)",
            (cp_id, github_login, wallet_address, now, now),
        )
        await db.commit()


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
