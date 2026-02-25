"""Tests for DisputeRouter: classification, routing, and staking consequences."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from src.config import DisputeConfig
from src.disputes.eigen_verify import SubmissionResult
from src.disputes.router import DisputeRouter
from src.models.enums import ClaimType, DisputeType

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def dispute_config() -> DisputeConfig:
    return DisputeConfig()


@pytest.fixture()
def mock_intel_db() -> AsyncMock:
    db = AsyncMock()
    return db


@pytest.fixture()
def mock_eigen() -> AsyncMock:
    client = AsyncMock()
    client.submit_dispute = AsyncMock(
        return_value=SubmissionResult(provider_case_id="eigen-123", accepted=True),
    )
    return client


@pytest.fixture()
def mock_molt() -> AsyncMock:
    client = AsyncMock()
    client.submit_dispute = AsyncMock(
        return_value=SubmissionResult(provider_case_id="molt-456", accepted=True),
    )
    return client


@pytest.fixture()
def mock_resolver() -> AsyncMock:
    return AsyncMock()


@pytest.fixture()
def mock_contract() -> AsyncMock:
    return AsyncMock()


@pytest.fixture()
def router(
    dispute_config: DisputeConfig,
    mock_intel_db: AsyncMock,
    mock_eigen: AsyncMock,
    mock_molt: AsyncMock,
    mock_resolver: AsyncMock,
    mock_contract: AsyncMock,
) -> DisputeRouter:
    return DisputeRouter(
        dispute_config, mock_intel_db, mock_eigen, mock_molt,
        mock_resolver, mock_contract,
    )


# ── Classification tests ───────────────────────────────────────────────────


class TestClassifyDispute:
    """Test the pure classify_dispute() static method."""

    def test_classify_ai_seed_and_hash_present(self) -> None:
        """COMPUTATION when ai_seed + ai_output_hash present and claim is AI_OUTPUT_INCORRECT."""
        att = json.dumps({"ai_seed": "abc123", "ai_output_hash": "def456"})
        result = DisputeRouter.classify_dispute(att, ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.COMPUTATION

    def test_classify_missing_ai_seed(self) -> None:
        """SUBJECTIVE when ai_seed is missing."""
        att = json.dumps({"ai_output_hash": "def456"})
        result = DisputeRouter.classify_dispute(att, ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.SUBJECTIVE

    def test_classify_missing_ai_hash(self) -> None:
        """SUBJECTIVE when ai_output_hash is missing."""
        att = json.dumps({"ai_seed": "abc123"})
        result = DisputeRouter.classify_dispute(att, ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.SUBJECTIVE

    def test_classify_wrong_claim_type(self) -> None:
        """SUBJECTIVE even with all fields if claim type is not AI_OUTPUT_INCORRECT."""
        att = json.dumps({"ai_seed": "abc123", "ai_output_hash": "def456"})
        result = DisputeRouter.classify_dispute(att, ClaimType.SCORING_UNFAIR)
        assert result == DisputeType.SUBJECTIVE

    def test_classify_malformed_json(self) -> None:
        """SUBJECTIVE on invalid JSON (safe default)."""
        result = DisputeRouter.classify_dispute("{bad json", ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.SUBJECTIVE

    def test_classify_empty_attestation(self) -> None:
        """SUBJECTIVE when attestation is empty string."""
        result = DisputeRouter.classify_dispute("", ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.SUBJECTIVE

    def test_classify_none_attestation(self) -> None:
        """SUBJECTIVE when attestation is None."""
        result = DisputeRouter.classify_dispute(None, ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.SUBJECTIVE

    def test_classify_null_ai_seed(self) -> None:
        """SUBJECTIVE when ai_seed is explicitly null."""
        att = json.dumps({"ai_seed": None, "ai_output_hash": "def456"})
        result = DisputeRouter.classify_dispute(att, ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.SUBJECTIVE

    def test_classify_attestation_is_array(self) -> None:
        """SUBJECTIVE when attestation JSON is an array, not dict."""
        result = DisputeRouter.classify_dispute("[1,2,3]", ClaimType.AI_OUTPUT_INCORRECT)
        assert result == DisputeType.SUBJECTIVE


# ── open_dispute tests ─────────────────────────────────────────────────────


class TestOpenDispute:
    """Test open_dispute routing and persistence logic."""

    async def test_open_dispute_window_not_found(
        self, router: DisputeRouter, mock_intel_db: AsyncMock,
    ) -> None:
        mock_intel_db.get_verification_window.return_value = None
        ok, msg = await router.open_dispute("w1", "c1", ClaimType.AI_OUTPUT_INCORRECT)
        assert not ok
        assert "not found" in msg.lower()

    async def test_open_dispute_wrong_status(
        self, router: DisputeRouter, mock_intel_db: AsyncMock,
    ) -> None:
        mock_intel_db.get_verification_window.return_value = {"status": "open"}
        ok, msg = await router.open_dispute("w1", "c1", ClaimType.AI_OUTPUT_INCORRECT)
        assert not ok
        assert "challenged" in msg.lower()

    async def test_open_dispute_existing_active(
        self, router: DisputeRouter, mock_intel_db: AsyncMock,
    ) -> None:
        """Reject if an active dispute already exists for the window."""
        mock_intel_db.get_verification_window.return_value = {"status": "challenged"}
        # check_and_insert_dispute returns False when a duplicate exists
        mock_intel_db.check_and_insert_dispute.return_value = False
        ok, msg = await router.open_dispute("w1", "c1", ClaimType.AI_OUTPUT_INCORRECT)
        assert not ok
        assert "active dispute" in msg.lower()

    async def test_open_dispute_persists_before_submission(
        self, router: DisputeRouter, mock_intel_db: AsyncMock, mock_eigen: AsyncMock,
    ) -> None:
        """Verify DB record is created even if submit fails."""
        mock_intel_db.get_verification_window.return_value = {
            "status": "challenged",
            "attestation_json": json.dumps({"ai_seed": "x", "ai_output_hash": "y"}),
            "challenger_address": "0xabc",
            "challenger_stake_wei": "1000",
            "challenge_rationale": "test",
        }
        mock_intel_db.check_and_insert_dispute.return_value = True
        mock_eigen.submit_dispute.side_effect = RuntimeError("network error")

        ok, dispute_id = await router.open_dispute(
            "w1", "c1", ClaimType.AI_OUTPUT_INCORRECT,
        )
        # Should succeed (record persisted) even though submission failed
        assert ok
        # check_and_insert_dispute must have been called (atomic persist)
        mock_intel_db.check_and_insert_dispute.assert_called_once()

    async def test_open_dispute_routes_to_eigen_verify(
        self, router: DisputeRouter, mock_intel_db: AsyncMock, mock_eigen: AsyncMock,
    ) -> None:
        """COMPUTATION dispute routes to EigenVerifyClient."""
        mock_intel_db.get_verification_window.return_value = {
            "status": "challenged",
            "attestation_json": json.dumps({"ai_seed": "x", "ai_output_hash": "y"}),
            "challenger_address": "0xabc",
            "challenger_stake_wei": "1000",
            "challenge_rationale": "test",
        }
        mock_intel_db.check_and_insert_dispute.return_value = True

        ok, dispute_id = await router.open_dispute(
            "w1", "c1", ClaimType.AI_OUTPUT_INCORRECT,
        )
        assert ok
        mock_eigen.submit_dispute.assert_called_once()

    async def test_open_dispute_routes_to_molt_court(
        self, router: DisputeRouter, mock_intel_db: AsyncMock, mock_molt: AsyncMock,
    ) -> None:
        """SUBJECTIVE dispute routes to MoltCourtClient."""
        mock_intel_db.get_verification_window.return_value = {
            "status": "challenged",
            "attestation_json": "{}",
            "challenger_address": "0xabc",
            "challenger_stake_wei": "1000",
            "challenge_rationale": "test",
        }
        mock_intel_db.check_and_insert_dispute.return_value = True

        ok, dispute_id = await router.open_dispute(
            "w1", "c1", ClaimType.SCORING_UNFAIR,
        )
        assert ok
        mock_molt.submit_dispute.assert_called_once()


# ── Staking consequence tests ──────────────────────────────────────────────


class TestStakingConsequences:
    """Test apply_staking_consequences for both outcomes."""

    async def test_staking_challenger_wins(
        self,
        router: DisputeRouter,
        mock_intel_db: AsyncMock,
        mock_resolver: AsyncMock,
        mock_contract: AsyncMock,
    ) -> None:
        """Challenger wins: contributor slashed 50%, challenger returned."""
        mock_intel_db.get_dispute_record.return_value = {
            "dispute_id": "d1",
            "contributor_stake_id": "aa" * 32,
            "challenger_stake_id": "bb" * 32,
        }
        await router.apply_staking_consequences("d1", challenger_won=True)
        mock_resolver.resolve_challenged_overturned.assert_called_once()
        mock_resolver.resolve_no_challenge.assert_called_once()
        mock_contract.slash_stake.assert_not_called()

    async def test_staking_challenger_loses(
        self,
        router: DisputeRouter,
        mock_intel_db: AsyncMock,
        mock_resolver: AsyncMock,
        mock_contract: AsyncMock,
    ) -> None:
        """Challenger loses: contributor returned + bonus, challenger slashed 100%."""
        mock_intel_db.get_dispute_record.return_value = {
            "dispute_id": "d1",
            "contributor_stake_id": "aa" * 32,
            "challenger_stake_id": "bb" * 32,
        }
        await router.apply_staking_consequences("d1", challenger_won=False)
        mock_resolver.resolve_challenged_upheld.assert_called_once()
        mock_contract.slash_stake.assert_called_once_with(
            bytes.fromhex("bb" * 32), 100,
        )

    async def test_staking_missing_stake_ids(
        self,
        router: DisputeRouter,
        mock_intel_db: AsyncMock,
        mock_resolver: AsyncMock,
        mock_contract: AsyncMock,
    ) -> None:
        """No crash when stake IDs are None."""
        mock_intel_db.get_dispute_record.return_value = {
            "dispute_id": "d1",
            "contributor_stake_id": None,
            "challenger_stake_id": None,
        }
        await router.apply_staking_consequences("d1", challenger_won=True)
        mock_resolver.resolve_challenged_overturned.assert_not_called()
        mock_resolver.resolve_no_challenge.assert_not_called()

    async def test_staking_partial_failure_logs(
        self,
        router: DisputeRouter,
        mock_intel_db: AsyncMock,
        mock_resolver: AsyncMock,
        mock_contract: AsyncMock,
    ) -> None:
        """Partial staking failure doesn't prevent the other operation."""
        mock_intel_db.get_dispute_record.return_value = {
            "dispute_id": "d1",
            "contributor_stake_id": "aa" * 32,
            "challenger_stake_id": "bb" * 32,
        }
        mock_resolver.resolve_challenged_upheld.side_effect = RuntimeError("chain error")
        # Should not raise — second operation still runs
        await router.apply_staking_consequences("d1", challenger_won=False)
        mock_contract.slash_stake.assert_called_once()
