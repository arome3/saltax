"""Tests for the optimistic verification system.

Covers window creation, expiry, challenge validation, staking bonuses,
state transitions, scheduler execution, crash recovery, and concurrency.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.config import SaltaXConfig, StakingConfig, VerificationConfig
from src.intelligence.database import IntelligenceDB
from src.verification.scheduler import VerificationScheduler
from src.verification.window import (
    compute_staking_bonus,
    create_window,
    is_expired,
    is_valid_transition,
    validate_challenge_stake,
)

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


@pytest.fixture()
def verification_config() -> VerificationConfig:
    return VerificationConfig(
        standard_window_hours=24,
        self_modification_window_hours=72,
        min_challenge_stake_multiplier=1.0,
        check_interval_seconds=60,
    )


@pytest.fixture()
def staking_config() -> StakingConfig:
    return StakingConfig(
        enabled=True,
        bonus_rate_no_challenge=0.10,
        bonus_rate_challenged_upheld=0.20,
        slash_rate_challenged_overturned=0.50,
    )


@pytest.fixture()
def sample_config() -> SaltaXConfig:
    return SaltaXConfig()


@pytest.fixture()
def mock_github_client():
    client = AsyncMock()
    client.merge_pr = AsyncMock(return_value={"merged": True})
    # CI gate defaults — no external CI → NO_CI → merge proceeds
    client.get_pr = AsyncMock(return_value={"head": {"sha": "abc123"}})
    client.list_check_runs_for_ref = AsyncMock(return_value=[])
    client.get_combined_status_for_ref = AsyncMock(
        return_value={"state": "", "total_count": 0},
    )
    return client


@pytest.fixture()
def mock_treasury_mgr():
    mgr = AsyncMock()
    mgr.send_payout = AsyncMock(
        return_value=MagicMock(tx_hash="0xdeadbeef", amount_wei=1000),
    )
    return mgr


@pytest.fixture()
def scheduler(sample_config, intel_db, mock_github_client, mock_treasury_mgr):
    return VerificationScheduler(
        sample_config, intel_db, mock_github_client, mock_treasury_mgr,
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
    """Helper to insert a verification window directly."""
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
# A. Window creation
# ═══════════════════════════════════════════════════════════════════════════════


class TestWindowCreation:
    """Test create_window() with standard and self-modification durations."""

    async def test_standard_window_24h(
        self, intel_db, verification_config,
    ) -> None:
        """Standard PRs get a 24-hour window."""
        window_id = await create_window(
            intel_db=intel_db,
            config=verification_config,
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict={"decision": "APPROVE"},
            attestation={"attestation_id": "attest-1"},
            contributor_address="0xabc",
            bounty_amount_wei=1000,
            is_self_modification=False,
        )
        window = await intel_db.get_verification_window(window_id)
        assert window is not None
        assert window["window_hours"] == 24
        assert window["status"] == "open"

    async def test_self_modification_window_72h(
        self, intel_db, verification_config,
    ) -> None:
        """Self-modification PRs get a 72-hour window."""
        window_id = await create_window(
            intel_db=intel_db,
            config=verification_config,
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict={"decision": "APPROVE"},
            attestation={"attestation_id": "attest-1"},
            contributor_address="0xabc",
            bounty_amount_wei=1000,
            is_self_modification=True,
        )
        window = await intel_db.get_verification_window(window_id)
        assert window is not None
        assert window["window_hours"] == 72

    async def test_none_bounty_stored_as_zero(
        self, intel_db, verification_config,
    ) -> None:
        """None bounty amount should be stored as '0'."""
        window_id = await create_window(
            intel_db=intel_db,
            config=verification_config,
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict={"decision": "APPROVE"},
            attestation={},
            contributor_address=None,
            bounty_amount_wei=None,
            is_self_modification=False,
        )
        window = await intel_db.get_verification_window(window_id)
        assert window is not None
        assert window["bounty_amount_wei"] == "0"


# ═══════════════════════════════════════════════════════════════════════════════
# B. Window expiry
# ═══════════════════════════════════════════════════════════════════════════════


class TestWindowExpiry:
    """Test is_expired() boundary conditions."""

    def test_not_expired_future_close(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        window = {"closes_at": future}
        assert is_expired(window) is False

    def test_expired_past_close(self) -> None:
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        window = {"closes_at": past}
        assert is_expired(window) is True

    def test_expired_exactly_at_close(self) -> None:
        """Boundary: at exactly closes_at, window is expired (>=)."""
        now = datetime.now(UTC)
        window = {"closes_at": now.isoformat()}
        # Due to time passing between creation and check, this should be expired
        assert is_expired(window) is True


# ═══════════════════════════════════════════════════════════════════════════════
# C. Challenge stake validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestChallengeStake:
    """Test validate_challenge_stake()."""

    def test_valid_stake(self, verification_config) -> None:
        window = {"bounty_amount_wei": "1000"}
        ok, msg = validate_challenge_stake(window, 1000, verification_config)
        assert ok is True
        assert msg == "ok"

    def test_insufficient_stake(self, verification_config) -> None:
        window = {"bounty_amount_wei": "1000"}
        ok, msg = validate_challenge_stake(window, 500, verification_config)
        assert ok is False
        assert "below minimum" in msg

    def test_zero_bounty_any_stake_valid(self, verification_config) -> None:
        """When bounty is 0, required stake is 0 — any non-negative stake works."""
        window = {"bounty_amount_wei": "0"}
        ok, msg = validate_challenge_stake(window, 0, verification_config)
        assert ok is True

    def test_stake_above_minimum(self, verification_config) -> None:
        window = {"bounty_amount_wei": "1000"}
        ok, msg = validate_challenge_stake(window, 2000, verification_config)
        assert ok is True


# ═══════════════════════════════════════════════════════════════════════════════
# D. Staking bonus
# ═══════════════════════════════════════════════════════════════════════════════


class TestStakingBonus:
    """Test compute_staking_bonus()."""

    def test_no_challenge_bonus(self, staking_config) -> None:
        """Unchallenged window with 10% bonus rate."""
        window = {"stake_amount_wei": "10000", "resolution": None}
        bonus = compute_staking_bonus(window, staking_config)
        assert bonus == 1000  # 10000 * 0.10

    def test_challenged_upheld_bonus(self, staking_config) -> None:
        """Upheld challenge with 20% bonus rate."""
        window = {"stake_amount_wei": "10000", "resolution": "upheld"}
        bonus = compute_staking_bonus(window, staking_config)
        assert bonus == 2000  # 10000 * 0.20

    def test_staking_disabled_returns_zero(self) -> None:
        config = StakingConfig(enabled=False)
        window = {"stake_amount_wei": "10000", "resolution": None}
        bonus = compute_staking_bonus(window, config)
        assert bonus == 0

    def test_zero_stake_returns_zero(self, staking_config) -> None:
        window = {"stake_amount_wei": "0", "resolution": None}
        bonus = compute_staking_bonus(window, staking_config)
        assert bonus == 0


# ═══════════════════════════════════════════════════════════════════════════════
# E. State transitions
# ═══════════════════════════════════════════════════════════════════════════════


class TestStateTransitions:
    """Test the state machine transition rules."""

    def test_valid_transitions(self) -> None:
        assert is_valid_transition("open", "executing") is True
        assert is_valid_transition("open", "challenged") is True
        assert is_valid_transition("executing", "executed") is True
        assert is_valid_transition("executing", "open") is True
        assert is_valid_transition("challenged", "resolved") is True
        assert is_valid_transition("challenged", "resolving") is True
        assert is_valid_transition("resolving", "resolved") is True
        assert is_valid_transition("resolving", "challenged") is True

    def test_invalid_transitions(self) -> None:
        assert is_valid_transition("open", "executed") is False
        assert is_valid_transition("open", "resolved") is False
        assert is_valid_transition("executing", "challenged") is False
        assert is_valid_transition("executed", "open") is False
        assert is_valid_transition("resolved", "open") is False
        assert is_valid_transition("resolving", "open") is False
        assert is_valid_transition("resolving", "executing") is False

    def test_terminal_states_have_no_transitions(self) -> None:
        assert is_valid_transition("executed", "open") is False
        assert is_valid_transition("executed", "executing") is False
        assert is_valid_transition("resolved", "challenged") is False

    async def test_db_transition_succeeds(self, intel_db) -> None:
        """CAS transition succeeds when expected status matches."""
        await _store_window(intel_db)
        ok = await intel_db.transition_window_status("win-1", "open", "executing")
        assert ok is True
        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executing"

    async def test_db_transition_fails_on_wrong_status(self, intel_db) -> None:
        """CAS transition fails when current status doesn't match expected."""
        await _store_window(intel_db)
        ok = await intel_db.transition_window_status("win-1", "executing", "executed")
        assert ok is False
        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "open"  # unchanged


# ═══════════════════════════════════════════════════════════════════════════════
# F. File challenge
# ═══════════════════════════════════════════════════════════════════════════════


class TestFileChallenge:
    """Test file_challenge() on the scheduler."""

    async def test_valid_challenge(self, intel_db, scheduler) -> None:
        await _store_window(intel_db, bounty_amount_wei="1000")
        ok, challenge_id = await scheduler.file_challenge(
            "win-1",
            challenger_address="0xchallenger",
            stake_wei=1000,
            rationale="I disagree",
        )
        assert ok is True
        assert len(challenge_id) == 32  # uuid4 hex
        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "challenged"
        assert window["challenger_address"] == "0xchallenger"

    async def test_challenge_wrong_status(self, intel_db, scheduler) -> None:
        await _store_window(intel_db)
        await intel_db.transition_window_status("win-1", "open", "executing")
        ok, msg = await scheduler.file_challenge(
            "win-1",
            challenger_address="0xchallenger",
            stake_wei=1000,
            rationale="I disagree",
        )
        assert ok is False
        assert "executing" in msg

    async def test_challenge_expired_window(self, intel_db, scheduler) -> None:
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)
        ok, msg = await scheduler.file_challenge(
            "win-1",
            challenger_address="0xchallenger",
            stake_wei=1000,
            rationale="I disagree",
        )
        assert ok is False
        assert "expired" in msg.lower()

    async def test_challenge_insufficient_stake(self, intel_db, scheduler) -> None:
        await _store_window(intel_db, bounty_amount_wei="1000")
        ok, msg = await scheduler.file_challenge(
            "win-1",
            challenger_address="0xchallenger",
            stake_wei=100,
            rationale="I disagree",
        )
        assert ok is False
        assert "below minimum" in msg

    async def test_challenge_not_found(self, scheduler) -> None:
        ok, msg = await scheduler.file_challenge(
            "nonexistent",
            challenger_address="0xchallenger",
            stake_wei=1000,
            rationale="I disagree",
        )
        assert ok is False
        assert "not found" in msg.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# G. Concurrent challenges
# ═══════════════════════════════════════════════════════════════════════════════


class TestConcurrentChallenge:
    """Only one of two simultaneous challenges should succeed."""

    async def test_only_one_wins(self, intel_db, scheduler) -> None:
        await _store_window(intel_db, bounty_amount_wei="1000")

        results = await asyncio.gather(
            scheduler.file_challenge(
                "win-1",
                challenger_address="0xchallenger1",
                stake_wei=1000,
                rationale="I disagree first",
            ),
            scheduler.file_challenge(
                "win-1",
                challenger_address="0xchallenger2",
                stake_wei=1000,
                rationale="I disagree second",
            ),
        )

        successes = [ok for ok, _ in results]
        assert successes.count(True) == 1
        assert successes.count(False) == 1

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "challenged"


# ═══════════════════════════════════════════════════════════════════════════════
# H. Scheduler tick
# ═══════════════════════════════════════════════════════════════════════════════


class TestSchedulerTick:
    """Test the scheduler's _tick() method."""

    async def test_processes_expired_window(
        self, intel_db, scheduler, mock_github_client,
    ) -> None:
        """An expired open window should be merged on tick."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)

        await scheduler._tick()

        mock_github_client.merge_pr.assert_awaited_once()
        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"

    async def test_no_action_when_no_expired(
        self, intel_db, scheduler, mock_github_client,
    ) -> None:
        """No expired windows → no merge calls."""
        future = (datetime.now(UTC) + timedelta(hours=24)).isoformat()
        await _store_window(intel_db, closes_at=future)

        await scheduler._tick()

        mock_github_client.merge_pr.assert_not_awaited()

    async def test_empty_db_no_error(self, scheduler) -> None:
        """Tick on empty DB should not raise."""
        await scheduler._tick()


# ═══════════════════════════════════════════════════════════════════════════════
# I. Execute window failures
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecuteWindowFailures:
    """Test _execute_window failure paths."""

    async def test_merge_fail_reverts_to_open(
        self, intel_db, scheduler, mock_github_client,
    ) -> None:
        """If merge fails, window reverts to 'open' for retry next tick."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)
        mock_github_client.merge_pr.side_effect = RuntimeError("GitHub down")

        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "open"

    async def test_merge_ok_payout_fails_stays_executed(
        self, intel_db, scheduler, mock_github_client, mock_treasury_mgr,
    ) -> None:
        """If merge succeeds but payout fails, window stays 'executed'."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past)
        mock_treasury_mgr.send_payout.side_effect = RuntimeError("Payout failed")

        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"
        assert window["resolution"] == "executed"

    async def test_no_payout_when_no_contributor(
        self, intel_db, scheduler, mock_github_client, mock_treasury_mgr,
    ) -> None:
        """No payout attempted when contributor_address is None."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(intel_db, closes_at=past, contributor_address=None)

        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"
        mock_treasury_mgr.send_payout.assert_not_awaited()

    async def test_no_payout_when_zero_bounty(
        self, intel_db, scheduler, mock_github_client, mock_treasury_mgr,
    ) -> None:
        """No payout attempted when bounty is 0."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        await _store_window(
            intel_db, closes_at=past, bounty_amount_wei="0",
        )

        await scheduler._tick()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "executed"
        mock_treasury_mgr.send_payout.assert_not_awaited()


# ═══════════════════════════════════════════════════════════════════════════════
# J. Crash recovery
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrashRecovery:
    """Test boot recovery of stale windows."""

    async def test_stale_executing_resets_to_open(
        self, intel_db, scheduler,
    ) -> None:
        """Windows stuck in 'executing' (crash) should be reset to 'open'."""
        await _store_window(intel_db, window_id="stale-1")
        await intel_db.transition_window_status("stale-1", "open", "executing")

        await scheduler.recover_pending_windows()

        window = await intel_db.get_verification_window("stale-1")
        assert window["status"] == "open"

    async def test_open_windows_remain_open(
        self, intel_db, scheduler,
    ) -> None:
        """Open windows should remain open after recovery."""
        await _store_window(intel_db)

        await scheduler.recover_pending_windows()

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "open"

    async def test_recovery_with_both_open_and_stale(
        self, intel_db, scheduler,
    ) -> None:
        """Recovery should handle a mix of open and stale executing windows."""
        await _store_window(intel_db, window_id="open-1")
        await _store_window(intel_db, window_id="stale-1")
        await intel_db.transition_window_status("stale-1", "open", "executing")
        await _store_window(intel_db, window_id="stale-2")
        await intel_db.transition_window_status("stale-2", "open", "executing")

        await scheduler.recover_pending_windows()

        w1 = await intel_db.get_verification_window("open-1")
        w2 = await intel_db.get_verification_window("stale-1")
        w3 = await intel_db.get_verification_window("stale-2")
        assert w1["status"] == "open"
        assert w2["status"] == "open"
        assert w3["status"] == "open"


# ═══════════════════════════════════════════════════════════════════════════════
# K. Resolve challenge
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveChallenge:
    """Test resolve_challenge()."""

    async def test_upheld_merges_and_pays(
        self, intel_db, scheduler, mock_github_client, mock_treasury_mgr,
    ) -> None:
        """Upheld challenge should merge and send payout."""
        await _store_window(intel_db, bounty_amount_wei="1000")
        await intel_db.transition_window_status(
            "win-1", "open", "challenged",
            challenge_id="ch-1",
            challenger_address="0xchallenger",
            challenger_stake_wei="1000",
            challenge_rationale="Suspicious",
        )

        ok, msg = await scheduler.resolve_challenge("win-1", upheld=True)
        assert ok is True

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "resolved"
        assert window["resolution"] == "upheld"
        mock_github_client.merge_pr.assert_awaited_once()

    async def test_overturned_no_merge(
        self, intel_db, scheduler, mock_github_client,
    ) -> None:
        """Overturned challenge should NOT merge."""
        await _store_window(intel_db)
        await intel_db.transition_window_status(
            "win-1", "open", "challenged",
            challenge_id="ch-1",
            challenger_address="0xchallenger",
            challenger_stake_wei="1000",
            challenge_rationale="Suspicious",
        )

        ok, msg = await scheduler.resolve_challenge("win-1", upheld=False)
        assert ok is True

        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "resolved"
        assert window["resolution"] == "overturned"
        mock_github_client.merge_pr.assert_not_awaited()

    async def test_resolve_wrong_status(self, intel_db, scheduler) -> None:
        """Resolving an 'open' window should fail."""
        await _store_window(intel_db)
        ok, msg = await scheduler.resolve_challenge("win-1", upheld=True)
        assert ok is False
        assert "open" in msg

    async def test_resolve_not_found(self, scheduler) -> None:
        ok, msg = await scheduler.resolve_challenge("nonexistent", upheld=True)
        assert ok is False
        assert "not found" in msg.lower()

    async def test_upheld_merge_fails_reverts_to_challenged(
        self, intel_db, scheduler, mock_github_client,
    ) -> None:
        """If merge fails after upheld, window reverts to challenged for retry."""
        await _store_window(intel_db)
        await intel_db.transition_window_status(
            "win-1", "open", "challenged",
            challenge_id="ch-1",
            challenger_address="0xchallenger",
            challenger_stake_wei="1000",
            challenge_rationale="Suspicious",
        )
        mock_github_client.merge_pr.side_effect = RuntimeError("GitHub down")

        ok, msg = await scheduler.resolve_challenge("win-1", upheld=True)
        assert ok is False
        assert "merge failed" in msg.lower()

        # Window reverts to challenged (resolving is transient)
        window = await intel_db.get_verification_window("win-1")
        assert window["status"] == "challenged"


# ═══════════════════════════════════════════════════════════════════════════════
# L. Scheduler run loop
# ═══════════════════════════════════════════════════════════════════════════════


class TestSchedulerRunLoop:
    """Test the run/stop lifecycle."""

    async def test_stop_exits_loop(self, scheduler) -> None:
        """Calling stop() should cause run() to exit."""
        async def stop_after_delay():
            await asyncio.sleep(0.05)
            await scheduler.stop()

        task = asyncio.create_task(scheduler.run())
        await stop_after_delay()
        await asyncio.wait_for(task, timeout=2.0)
        assert scheduler.running is False

    async def test_close_is_alias_for_stop(self, scheduler) -> None:
        async def close_after_delay():
            await asyncio.sleep(0.05)
            await scheduler.close()

        task = asyncio.create_task(scheduler.run())
        await close_after_delay()
        await asyncio.wait_for(task, timeout=2.0)
        assert scheduler.running is False


# ═══════════════════════════════════════════════════════════════════════════════
# M. Stake defaults (Gap 3)
# ═══════════════════════════════════════════════════════════════════════════════


class TestStakeDefaults:
    """Test that stake_amount_wei defaults to bounty when not specified."""

    async def test_stake_defaults_to_bounty(
        self, intel_db, verification_config,
    ) -> None:
        """When no explicit stake, stake_amount_wei equals bounty_amount_wei."""
        window_id = await create_window(
            intel_db=intel_db,
            config=verification_config,
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict={"decision": "APPROVE"},
            attestation={},
            contributor_address="0xabc",
            bounty_amount_wei=5000,
            is_self_modification=False,
        )
        window = await intel_db.get_verification_window(window_id)
        assert window["stake_amount_wei"] == "5000"

    async def test_explicit_stake_overrides_default(
        self, intel_db, verification_config,
    ) -> None:
        """An explicit stake_amount_wei overrides the bounty-based default."""
        window_id = await create_window(
            intel_db=intel_db,
            config=verification_config,
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict={"decision": "APPROVE"},
            attestation={},
            contributor_address="0xabc",
            bounty_amount_wei=5000,
            stake_amount_wei=9999,
            is_self_modification=False,
        )
        window = await intel_db.get_verification_window(window_id)
        assert window["stake_amount_wei"] == "9999"

    async def test_none_bounty_zero_stake(
        self, intel_db, verification_config,
    ) -> None:
        """None bounty → zero stake (not crash)."""
        window_id = await create_window(
            intel_db=intel_db,
            config=verification_config,
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict={"decision": "APPROVE"},
            attestation={},
            contributor_address=None,
            bounty_amount_wei=None,
            is_self_modification=False,
        )
        window = await intel_db.get_verification_window(window_id)
        assert window["stake_amount_wei"] == "0"


# ═══════════════════════════════════════════════════════════════════════════════
# N. Crash recovery — resolving state (Gap 6)
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrashRecoveryResolving:
    """Test recovery of stale resolving windows."""

    async def test_stale_resolving_resets_to_challenged(
        self, intel_db, scheduler,
    ) -> None:
        """Windows stuck in 'resolving' should be reset to 'challenged'."""
        await _store_window(intel_db, window_id="res-1")
        await intel_db.transition_window_status("res-1", "open", "challenged")
        await intel_db.transition_window_status("res-1", "challenged", "resolving")

        await scheduler.recover_pending_windows()

        window = await intel_db.get_verification_window("res-1")
        assert window["status"] == "challenged"

    async def test_recovery_with_mixed_transient_states(
        self, intel_db, scheduler,
    ) -> None:
        """Recovery handles both executing and resolving transient states."""
        # One executing window
        await _store_window(intel_db, window_id="exec-1")
        await intel_db.transition_window_status("exec-1", "open", "executing")

        # One resolving window
        await _store_window(intel_db, window_id="res-1")
        await intel_db.transition_window_status("res-1", "open", "challenged")
        await intel_db.transition_window_status("res-1", "challenged", "resolving")

        # One open window (should stay open)
        await _store_window(intel_db, window_id="open-1")

        await scheduler.recover_pending_windows()

        w_exec = await intel_db.get_verification_window("exec-1")
        w_res = await intel_db.get_verification_window("res-1")
        w_open = await intel_db.get_verification_window("open-1")
        assert w_exec["status"] == "open"
        assert w_res["status"] == "challenged"
        assert w_open["status"] == "open"


# ═══════════════════════════════════════════════════════════════════════════════
# O. Challenge deadline enforcement (Gap 5)
# ═══════════════════════════════════════════════════════════════════════════════


class TestChallengeDeadline:
    """Test auto-overturn of stale challenged windows."""

    async def test_stale_challenge_auto_overturned(
        self, intel_db, scheduler,
    ) -> None:
        """A challenged window past the deadline is auto-overturned."""
        # Create window and challenge it
        await _store_window(intel_db, window_id="stale-ch")
        await intel_db.transition_window_status(
            "stale-ch", "open", "challenged",
            challenge_id="ch-1",
            challenger_address="0xchallenger",
            challenger_stake_wei="1000",
            challenge_rationale="Suspicious",
        )
        # Backdate updated_at to 8 days ago (deadline is 7 days)
        db = intel_db._require_db()
        old_time = (datetime.now(UTC) - timedelta(days=8)).isoformat()
        async with intel_db._write_lock:
            await db.execute(
                "UPDATE verification_windows SET updated_at = ? WHERE id = ?",
                (old_time, "stale-ch"),
            )
            await db.commit()

        await scheduler._tick()

        window = await intel_db.get_verification_window("stale-ch")
        assert window["status"] == "resolved"
        assert window["resolution"] == "overturned"

    async def test_recent_challenge_not_auto_resolved(
        self, intel_db, scheduler,
    ) -> None:
        """A recently challenged window is NOT auto-overturned."""
        await _store_window(intel_db, window_id="recent-ch")
        await intel_db.transition_window_status(
            "recent-ch", "open", "challenged",
            challenge_id="ch-2",
            challenger_address="0xchallenger",
            challenger_stake_wei="1000",
            challenge_rationale="Suspicious",
        )

        await scheduler._tick()

        window = await intel_db.get_verification_window("recent-ch")
        assert window["status"] == "challenged"  # unchanged
