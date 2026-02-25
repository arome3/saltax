"""Tests for the CI status gate in the verification scheduler.

Covers the _check_ci_status() method (unit) and its integration with
the scheduler's merge sites (integration).
"""

from __future__ import annotations

import os

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.config import SaltaXConfig, VerificationConfig
from src.intelligence.database import IntelligenceDB
from src.verification.scheduler import CIGateResult, VerificationScheduler

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


@pytest.fixture()
def sample_config() -> SaltaXConfig:
    return SaltaXConfig()


@pytest.fixture()
def ci_disabled_config() -> SaltaXConfig:
    """Config with CI gate disabled."""
    return SaltaXConfig(
        verification=VerificationConfig(require_ci_pass=False),
    )


def _make_github_client(
    *,
    check_runs: list[dict] | None = None,
    combined_state: str = "",
    combined_count: int = 0,
    check_suites: list[dict] | None = None,
    pr_head_sha: str = "abc123",
    get_pr_error: bool = False,
    ci_fetch_error: bool = False,
    check_suites_error: bool = False,
) -> AsyncMock:
    """Build a mock GitHubClient with configurable CI responses."""
    client = AsyncMock()
    client.merge_pr = AsyncMock(return_value={"merged": True})

    if get_pr_error:
        client.get_pr = AsyncMock(side_effect=RuntimeError("API down"))
    else:
        client.get_pr = AsyncMock(
            return_value={"head": {"sha": pr_head_sha}},
        )

    if ci_fetch_error:
        client.list_check_runs_for_ref = AsyncMock(
            side_effect=RuntimeError("API down"),
        )
        client.get_combined_status_for_ref = AsyncMock(
            side_effect=RuntimeError("API down"),
        )
    else:
        client.list_check_runs_for_ref = AsyncMock(
            return_value=check_runs if check_runs is not None else [],
        )
        client.get_combined_status_for_ref = AsyncMock(
            return_value={"state": combined_state, "total_count": combined_count},
        )

    if check_suites_error:
        client.list_check_suites_for_ref = AsyncMock(
            side_effect=RuntimeError("API down"),
        )
    else:
        client.list_check_suites_for_ref = AsyncMock(
            return_value=check_suites if check_suites is not None else [],
        )

    return client


@pytest.fixture()
def mock_treasury_mgr():
    mgr = AsyncMock()
    mgr.send_payout = AsyncMock(
        return_value=MagicMock(tx_hash="0xdeadbeef", amount_wei=1000),
    )
    return mgr


def _make_scheduler(
    config: SaltaXConfig,
    intel_db: IntelligenceDB,
    github_client: AsyncMock,
    treasury_mgr: AsyncMock,
) -> VerificationScheduler:
    return VerificationScheduler(
        config, intel_db, github_client, treasury_mgr,
    )


async def _store_window(
    intel_db: IntelligenceDB,
    *,
    window_id: str = "win-1",
    pr_id: str = "owner/repo#1",
    repo: str = "owner/repo",
    pr_number: int = 1,
    installation_id: int = 12345,
    bounty_amount_wei: str = "1000",
    stake_amount_wei: str = "500",
    window_hours: int = 24,
    opens_at: str | None = None,
    closes_at: str | None = None,
    contributor_address: str | None = "0xcontrib",
) -> None:
    """Insert a verification window directly for testing."""
    now = datetime.now(UTC)
    await intel_db.store_verification_window(
        window_id=window_id,
        pr_id=pr_id,
        repo=repo,
        pr_number=pr_number,
        installation_id=installation_id,
        attestation_id="attest-1",
        verdict_json='{"decision": "APPROVE"}',
        attestation_json='{"attestation_id": "attest-1"}',
        contributor_address=contributor_address,
        bounty_amount_wei=bounty_amount_wei,
        stake_amount_wei=stake_amount_wei,
        window_hours=window_hours,
        opens_at=opens_at or now.isoformat(),
        closes_at=closes_at or (now + timedelta(hours=window_hours)).isoformat(),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# A. Unit tests for _check_ci_status()
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckCIStatusUnit:
    """Test _check_ci_status() logic in isolation."""

    async def test_all_checks_pass(self, sample_config, intel_db, mock_treasury_mgr):
        """All check runs successful → PASSED."""
        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "completed", "conclusion": "success"},
                {"name": "Lint", "status": "completed", "conclusion": "success"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PASSED

    async def test_check_run_failed(self, sample_config, intel_db, mock_treasury_mgr):
        """A failing check run → FAILED."""
        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "completed", "conclusion": "success"},
                {"name": "Lint", "status": "completed", "conclusion": "failure"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.FAILED

    async def test_check_run_in_progress(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """An in-progress check run → PENDING."""
        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "in_progress", "conclusion": None},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PENDING

    async def test_check_run_queued(self, sample_config, intel_db, mock_treasury_mgr):
        """A queued check run → PENDING."""
        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "queued", "conclusion": None},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PENDING

    async def test_own_check_excluded(self, sample_config, intel_db, mock_treasury_mgr):
        """SaltaX's own check run is filtered out → NO_CI if no others."""
        client = _make_github_client(
            check_runs=[
                {
                    "name": "SaltaX Pipeline",
                    "status": "completed",
                    "conclusion": "success",
                },
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.NO_CI

    async def test_own_check_excluded_others_pass(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Own check is filtered out but other checks pass → PASSED."""
        client = _make_github_client(
            check_runs=[
                {
                    "name": "SaltaX Pipeline",
                    "status": "completed",
                    "conclusion": "success",
                },
                {"name": "Tests", "status": "completed", "conclusion": "success"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PASSED

    async def test_no_ci_at_all(self, sample_config, intel_db, mock_treasury_mgr):
        """No check runs and no status checks → NO_CI."""
        client = _make_github_client(check_runs=[], combined_count=0)
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.NO_CI

    async def test_gate_disabled(
        self, ci_disabled_config, intel_db, mock_treasury_mgr,
    ):
        """Gate disabled in config → GATE_DISABLED without any API calls."""
        client = _make_github_client()
        scheduler = _make_scheduler(
            ci_disabled_config, intel_db, client, mock_treasury_mgr,
        )
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.GATE_DISABLED
        client.get_pr.assert_not_awaited()

    async def test_api_error_get_pr(self, sample_config, intel_db, mock_treasury_mgr):
        """API error fetching PR → API_ERROR (fail-open)."""
        client = _make_github_client(get_pr_error=True)
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.API_ERROR

    async def test_api_error_ci_fetch(self, sample_config, intel_db, mock_treasury_mgr):
        """API error fetching CI status → API_ERROR (fail-open)."""
        client = _make_github_client(ci_fetch_error=True)
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.API_ERROR

    async def test_status_api_pending(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Combined status API pending → PENDING."""
        client = _make_github_client(
            check_runs=[],
            combined_state="pending",
            combined_count=1,
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PENDING

    async def test_status_api_failure(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Combined status API failure → FAILED."""
        client = _make_github_client(
            check_runs=[],
            combined_state="failure",
            combined_count=1,
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.FAILED

    async def test_status_api_error(self, sample_config, intel_db, mock_treasury_mgr):
        """Combined status API error state → FAILED."""
        client = _make_github_client(
            check_runs=[],
            combined_state="error",
            combined_count=1,
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.FAILED

    async def test_status_api_success(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Combined status API success → PASSED."""
        client = _make_github_client(
            check_runs=[],
            combined_state="success",
            combined_count=1,
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PASSED

    async def test_neutral_conclusion_is_passing(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """A check with neutral conclusion → PASSED (not failure)."""
        client = _make_github_client(
            check_runs=[
                {"name": "Optional", "status": "completed", "conclusion": "neutral"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PASSED

    async def test_skipped_conclusion_is_passing(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """A check with skipped conclusion → PASSED (not failure)."""
        client = _make_github_client(
            check_runs=[
                {"name": "Deploy", "status": "completed", "conclusion": "skipped"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PASSED

    async def test_mixed_check_runs_and_status_api(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Check runs pass but status API fails → FAILED."""
        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "completed", "conclusion": "success"},
            ],
            combined_state="failure",
            combined_count=1,
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.FAILED

    async def test_action_required_conclusion_is_failing(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """A check with action_required conclusion → FAILED."""
        client = _make_github_client(
            check_runs=[
                {
                    "name": "Review",
                    "status": "completed",
                    "conclusion": "action_required",
                },
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.FAILED

    # -- Race condition: pending check suites with no check runs ---------------

    async def test_pending_check_suites_no_runs_returns_pending(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Queued check suite + zero check runs → PENDING (not NO_CI).

        Regression test for the race condition where a newly-pushed commit
        has check suites created but check runs haven't been provisioned yet.
        """
        client = _make_github_client(
            check_runs=[],
            combined_count=0,
            check_suites=[{"status": "queued", "app": {"slug": "github-actions"}}],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PENDING

    async def test_in_progress_check_suite_no_runs_returns_pending(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """In-progress check suite + zero check runs → PENDING."""
        client = _make_github_client(
            check_runs=[],
            combined_count=0,
            check_suites=[
                {"status": "in_progress", "app": {"slug": "github-actions"}},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PENDING

    async def test_completed_check_suite_no_runs_returns_no_ci(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Completed check suite + zero check runs → NO_CI.

        A completed suite with no runs means the suite finished without
        producing any meaningful checks (e.g. a skipped workflow).
        """
        client = _make_github_client(
            check_runs=[],
            combined_count=0,
            check_suites=[{"status": "completed", "app": {"slug": "github-actions"}}],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.NO_CI

    async def test_check_suites_api_error_falls_back_to_no_ci(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Check suites API failure → falls back to NO_CI (fail-open)."""
        client = _make_github_client(
            check_runs=[],
            combined_count=0,
            check_suites_error=True,
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.NO_CI

    async def test_own_check_excluded_pending_suite_returns_pending(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Only SaltaX's own check run + queued suite → PENDING.

        Even though we filter out our own check, a pending suite means
        external CI is still spinning up.
        """
        client = _make_github_client(
            check_runs=[
                {
                    "name": "SaltaX Pipeline",
                    "status": "completed",
                    "conclusion": "success",
                },
            ],
            combined_count=0,
            check_suites=[{"status": "queued", "app": {"slug": "github-actions"}}],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        result = await scheduler._check_ci_status("owner/repo", 1, 12345)
        assert result == CIGateResult.PENDING


# ═══════════════════════════════════════════════════════════════════════════════
# B. Integration tests — CI gate + scheduler merge sites
# ═══════════════════════════════════════════════════════════════════════════════


class TestCIGateIntegration:
    """Test that the CI gate correctly blocks/allows merges in the scheduler."""

    async def test_pending_ci_blocks_merge(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """PENDING CI → window stays 'open', merge_pr not called."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "in_progress", "conclusion": None},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "open"
        client.merge_pr.assert_not_awaited()

    async def test_failed_ci_blocks_merge(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """FAILED CI → window stays 'open', merge_pr not called."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        client = _make_github_client(
            check_runs=[
                {"name": "Lint", "status": "completed", "conclusion": "failure"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "open"
        client.merge_pr.assert_not_awaited()

    async def test_passed_ci_allows_merge(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """PASSED CI → merge proceeds normally."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "completed", "conclusion": "success"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"
        client.merge_pr.assert_awaited_once()

    async def test_no_ci_allows_merge(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """NO_CI → merge proceeds (don't block repos without CI)."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        client = _make_github_client(check_runs=[], combined_count=0)
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"
        client.merge_pr.assert_awaited_once()

    async def test_gate_disabled_allows_merge(
        self, ci_disabled_config, intel_db, mock_treasury_mgr,
    ):
        """GATE_DISABLED → merge proceeds without CI check."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "completed", "conclusion": "failure"},
            ],
        )
        scheduler = _make_scheduler(
            ci_disabled_config, intel_db, client, mock_treasury_mgr,
        )
        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"
        # CI APIs should not even be called
        client.get_pr.assert_not_awaited()

    async def test_api_error_allows_merge(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """API_ERROR → merge proceeds (fail-open)."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        client = _make_github_client(get_pr_error=True)
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"
        client.merge_pr.assert_awaited_once()

    async def test_upheld_challenge_blocked_by_ci(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """PENDING CI on upheld challenge → reverts to challenged."""
        await _store_window(intel_db)
        await intel_db.transition_window_status(
            "win-1", "open", "challenged",
            challenge_id="ch-1",
            challenger_address="0xchallenger",
            challenger_stake_wei="1000",
            challenge_rationale="Suspicious",
        )

        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "in_progress", "conclusion": None},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        ok, msg = await scheduler.resolve_challenge("win-1", upheld=True)

        assert ok is False
        assert "ci gate" in msg.lower()
        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "challenged"
        client.merge_pr.assert_not_awaited()

    async def test_upheld_challenge_passes_ci(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """PASSED CI on upheld challenge → merge proceeds."""
        await _store_window(intel_db, bounty_amount_wei="1000")
        await intel_db.transition_window_status(
            "win-1", "open", "challenged",
            challenge_id="ch-1",
            challenger_address="0xchallenger",
            challenger_stake_wei="1000",
            challenge_rationale="Suspicious",
        )

        client = _make_github_client(
            check_runs=[
                {"name": "Tests", "status": "completed", "conclusion": "success"},
            ],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        ok, msg = await scheduler.resolve_challenge("win-1", upheld=True)

        assert ok is True
        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "resolved"
        client.merge_pr.assert_awaited_once()

    # -- Race condition integration tests --------------------------------------

    async def test_pending_check_suite_blocks_merge(
        self, sample_config, intel_db, mock_treasury_mgr,
    ):
        """Queued check suite + zero runs → PENDING → window stays open.

        Regression test for the race condition: a new commit was pushed,
        check suites are queued but check runs haven't appeared yet.
        The scheduler must NOT merge.
        """
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        client = _make_github_client(
            check_runs=[],
            combined_count=0,
            check_suites=[{"status": "queued", "app": {"slug": "github-actions"}}],
        )
        scheduler = _make_scheduler(sample_config, intel_db, client, mock_treasury_mgr)
        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "open"
        client.merge_pr.assert_not_awaited()
