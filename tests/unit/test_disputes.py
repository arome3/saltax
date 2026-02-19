"""Tests for EigenVerify, MoltCourt, DisputeScheduler, and DB integration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from src.config import DisputeConfig
from src.disputes.eigen_verify import EigenVerifyClient
from src.disputes.eigen_verify import CircuitBreaker, CircuitBreakerOpenError
from src.disputes.molt_court import MoltCourtClient
from src.disputes.scheduler import DisputeScheduler

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def dispute_config() -> DisputeConfig:
    return DisputeConfig(
        eigenverify_base_url="https://eigen.test/v1",
        moltcourt_base_url="https://molt.test/v1",
        eigenverify_timeout_seconds=5,
        moltcourt_timeout_seconds=5,
        eigenverify_deadline_hours=24,
        moltcourt_deadline_hours=72,
        poll_interval_seconds=1,
        max_submission_retries=3,
        circuit_breaker_failure_threshold=3,
        circuit_breaker_reset_seconds=60,
    )


# ── EigenVerifyClient tests ────────────────────────────────────────────────


class TestEigenVerifyClient:

    @respx.mock
    async def test_submit_dispute_success(self, dispute_config: DisputeConfig) -> None:
        """Successful submission returns provider case_id."""
        respx.post("https://eigen.test/v1/disputes").mock(
            return_value=httpx.Response(200, json={"case_id": "eigen-abc"}),
        )
        client = EigenVerifyClient(dispute_config)
        try:
            result = await client.submit_dispute("d1", {"proof": "data"})
            assert result.accepted is True
            assert result.provider_case_id == "eigen-abc"
        finally:
            await client.close()

    @respx.mock
    async def test_check_resolution_completed(self, dispute_config: DisputeConfig) -> None:
        """Completed dispute returns resolved=True with verdict."""
        respx.get("https://eigen.test/v1/disputes/case-1").mock(
            return_value=httpx.Response(200, json={
                "status": "completed",
                "verdict": "upheld",
                "details": "AI output verified incorrect",
            }),
        )
        client = EigenVerifyClient(dispute_config)
        try:
            result = await client.check_resolution("case-1")
            assert result.resolved is True
            assert result.verdict == "upheld"
        finally:
            await client.close()

    @respx.mock
    async def test_check_resolution_pending(self, dispute_config: DisputeConfig) -> None:
        """Pending dispute returns resolved=False."""
        respx.get("https://eigen.test/v1/disputes/case-1").mock(
            return_value=httpx.Response(200, json={"status": "pending"}),
        )
        client = EigenVerifyClient(dispute_config)
        try:
            result = await client.check_resolution("case-1")
            assert result.resolved is False
        finally:
            await client.close()

    @respx.mock
    async def test_check_resolution_404(self, dispute_config: DisputeConfig) -> None:
        """404 on poll returns resolved=False (delayed indexing)."""
        respx.get("https://eigen.test/v1/disputes/case-1").mock(
            return_value=httpx.Response(404),
        )
        client = EigenVerifyClient(dispute_config)
        try:
            result = await client.check_resolution("case-1")
            assert result.resolved is False
        finally:
            await client.close()


# ── MoltCourtClient tests ──────────────────────────────────────────────────


class TestMoltCourtClient:

    @respx.mock
    async def test_submit_dispute_success(self, dispute_config: DisputeConfig) -> None:
        """Successful submission returns provider case_id."""
        respx.post("https://molt.test/v1/disputes").mock(
            return_value=httpx.Response(200, json={"case_id": "molt-xyz"}),
        )
        client = MoltCourtClient(dispute_config)
        try:
            result = await client.submit_dispute("d1", {"claim": "unfair"})
            assert result.accepted is True
            assert result.provider_case_id == "molt-xyz"
            assert client.circuit_breaker_state == "closed"
        finally:
            await client.close()

    @respx.mock
    async def test_submit_dispute_404_records_failure(
        self, dispute_config: DisputeConfig,
    ) -> None:
        """404 on submit records circuit breaker failure."""
        respx.post("https://molt.test/v1/disputes").mock(
            return_value=httpx.Response(404),
        )
        client = MoltCourtClient(dispute_config)
        try:
            with pytest.raises(httpx.HTTPStatusError):
                await client.submit_dispute("d1", {"claim": "unfair"})
        finally:
            await client.close()

    @respx.mock
    async def test_check_resolution_404_manual_review(
        self, dispute_config: DisputeConfig,
    ) -> None:
        """404 on poll returns manual_review verdict."""
        respx.get("https://molt.test/v1/disputes/case-1").mock(
            return_value=httpx.Response(404),
        )
        client = MoltCourtClient(dispute_config)
        try:
            result = await client.check_resolution("case-1")
            assert result.resolved is False
            assert result.verdict == "manual_review"
        finally:
            await client.close()


# ── Circuit breaker tests ──────────────────────────────────────────────────


class TestCircuitBreaker:

    def test_starts_closed(self) -> None:
        breaker = CircuitBreaker(failure_threshold=3, reset_seconds=60)
        assert breaker.state == "closed"
        breaker.check()  # Should not raise

    def test_opens_on_threshold(self) -> None:
        breaker = CircuitBreaker(failure_threshold=3, reset_seconds=60)
        for _ in range(3):
            breaker.record_failure()
        assert breaker.state == "open"
        with pytest.raises(CircuitBreakerOpenError):
            breaker.check()

    def test_resets_on_success(self) -> None:
        breaker = CircuitBreaker(failure_threshold=3, reset_seconds=60)
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_success()
        assert breaker.state == "closed"
        assert breaker._failure_count == 0

    def test_half_open_after_reset_period(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, reset_seconds=0)
        breaker.record_failure()
        assert breaker.state == "open"
        # With reset_seconds=0, should immediately transition to half_open
        breaker.check()
        assert breaker.state == "half_open"

    def test_half_open_failure_reopens(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, reset_seconds=0)
        breaker.record_failure()
        breaker.check()  # → half_open
        assert breaker.state == "half_open"
        breaker.record_failure()
        assert breaker.state == "open"

    def test_half_open_success_closes(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, reset_seconds=0)
        breaker.record_failure()
        breaker.check()  # → half_open
        breaker.record_success()
        assert breaker.state == "closed"


# ── DisputeScheduler tests ─────────────────────────────────────────────────


class TestDisputeScheduler:

    @pytest.fixture()
    def mock_db(self) -> AsyncMock:
        db = AsyncMock()
        db.get_disputes_by_status = AsyncMock(return_value=[])
        return db

    @pytest.fixture()
    def mock_router(self) -> AsyncMock:
        router = AsyncMock()
        router._eigen = AsyncMock()
        router._molt = AsyncMock()
        return router

    @pytest.fixture()
    def mock_verification(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture()
    def scheduler(
        self,
        dispute_config: DisputeConfig,
        mock_db: AsyncMock,
        mock_router: AsyncMock,
        mock_verification: AsyncMock,
    ) -> DisputeScheduler:
        return DisputeScheduler(
            dispute_config, mock_db, mock_router, mock_verification,
        )

    async def test_retry_pending_submits(
        self,
        scheduler: DisputeScheduler,
        mock_db: AsyncMock,
        mock_router: AsyncMock,
    ) -> None:
        """Pending disputes are retried via the appropriate provider."""
        from src.disputes.eigen_verify import SubmissionResult  # noqa: PLC0415

        mock_db.get_disputes_by_status.side_effect = lambda status: (
            [{
                "dispute_id": "d1",
                "dispute_type": "computation",
                "claim_type": "ai_output_incorrect",
                "window_id": "w1",
                "challenge_id": "c1",
                "attestation_json": "{}",
                "submission_attempts": 0,
                "created_at": datetime.now(UTC).isoformat(),
            }]
            if status == "pending"
            else []
        )
        mock_router._eigen.submit_dispute.return_value = SubmissionResult(
            provider_case_id="eigen-retry", accepted=True,
        )

        await scheduler._tick()
        mock_router._eigen.submit_dispute.assert_called_once()
        mock_db.update_dispute_record.assert_any_call(
            "d1",
            status="submitted",
            provider_case_id="eigen-retry",
            submission_attempts=1,
        )

    async def test_retry_max_retries_marks_failed(
        self,
        scheduler: DisputeScheduler,
        mock_db: AsyncMock,
    ) -> None:
        """Disputes exceeding max retries are marked FAILED."""
        mock_db.get_disputes_by_status.side_effect = lambda status: (
            [{
                "dispute_id": "d1",
                "dispute_type": "computation",
                "claim_type": "ai_output_incorrect",
                "window_id": "w1",
                "challenge_id": "c1",
                "attestation_json": "{}",
                "submission_attempts": 3,  # == max_submission_retries
                "created_at": datetime.now(UTC).isoformat(),
            }]
            if status == "pending"
            else []
        )

        await scheduler._tick()
        mock_db.update_dispute_record.assert_any_call("d1", status="failed")

    async def test_poll_submitted_resolves(
        self,
        scheduler: DisputeScheduler,
        mock_db: AsyncMock,
        mock_router: AsyncMock,
        mock_verification: AsyncMock,
    ) -> None:
        """Submitted disputes that are resolved trigger handle_resolution."""
        now = datetime.now(UTC).isoformat()
        record = {
            "dispute_id": "d2",
            "window_id": "w2",
            "dispute_type": "subjective",
            "claim_type": "scoring_unfair",
            "status": "submitted",
            "provider_case_id": "molt-case",
            "created_at": now,
            "submission_attempts": 1,
        }
        mock_db.get_disputes_by_status.side_effect = lambda status: (
            [record] if status == "submitted" else []
        )
        mock_router.check_dispute_resolution.return_value = (True, "upheld")
        mock_verification.resolve_challenge.return_value = (True, "ok")

        await scheduler._tick()
        mock_router.check_dispute_resolution.assert_called_once_with("d2")
        # handle_resolution should call resolve_challenge on the verification scheduler
        mock_verification.resolve_challenge.assert_called_once()

    async def test_timeout_auto_resolves_as_rejected(
        self,
        scheduler: DisputeScheduler,
        mock_db: AsyncMock,
        mock_router: AsyncMock,
        mock_verification: AsyncMock,
    ) -> None:
        """Timed-out disputes are auto-resolved as challenge REJECTED."""
        # Create a dispute older than the deadline
        old_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        record = {
            "dispute_id": "d3",
            "window_id": "w3",
            "dispute_type": "computation",
            "claim_type": "ai_output_incorrect",
            "status": "pending",
            "created_at": old_time,
            "submission_attempts": 1,
            "challenge_id": "c3",
            "attestation_json": "{}",
        }
        mock_db.get_disputes_by_status.side_effect = lambda status: (
            [record] if status == "pending" else []
        )
        mock_verification.resolve_challenge.return_value = (True, "ok")

        await scheduler._check_timeouts(set())
        # Should mark as timed_out
        timed_out_calls = [
            c for c in mock_db.update_dispute_record.call_args_list
            if c.args[0] == "d3" and c.kwargs.get("status") == "timed_out"
        ]
        assert len(timed_out_calls) == 1, "Expected exactly one timed_out update for d3"
        assert "resolved_at" in timed_out_calls[0].kwargs
        # Should resolve as challenger_lost (upheld=True in existing code)
        mock_verification.resolve_challenge.assert_called_once_with(
            "w3", upheld=True,
        )

    async def test_subjective_timeout_uses_correct_deadline(
        self,
        scheduler: DisputeScheduler,
        mock_db: AsyncMock,
        mock_router: AsyncMock,
        mock_verification: AsyncMock,
    ) -> None:
        """Subjective disputes use the 72h deadline, not 24h."""
        # 48 hours old — past eigenverify deadline but NOT past moltcourt deadline
        old_time = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
        record = {
            "dispute_id": "d4",
            "window_id": "w4",
            "dispute_type": "subjective",
            "claim_type": "scoring_unfair",
            "status": "submitted",
            "created_at": old_time,
            "submission_attempts": 1,
        }
        mock_db.get_disputes_by_status.side_effect = lambda status: (
            [record] if status == "submitted" else []
        )

        await scheduler._check_timeouts(set())
        # Should NOT be timed out (72h deadline, only 48h elapsed)
        for call_args in mock_db.update_dispute_record.call_args_list:
            if len(call_args.args) > 0 and call_args.args[0] == "d4":
                kwargs = call_args.kwargs if call_args.kwargs else {}
                if kwargs.get("status") == "timed_out":
                    pytest.fail("Subjective dispute was timed out before 72h deadline")

    async def test_circuit_breaker_open_skips_retry(
        self,
        scheduler: DisputeScheduler,
        mock_db: AsyncMock,
        mock_router: AsyncMock,
    ) -> None:
        """Circuit breaker open skips retry without crashing."""
        mock_db.get_disputes_by_status.side_effect = lambda status: (
            [{
                "dispute_id": "d5",
                "dispute_type": "subjective",
                "claim_type": "scoring_unfair",
                "window_id": "w5",
                "challenge_id": "c5",
                "attestation_json": "{}",
                "submission_attempts": 0,
                "created_at": datetime.now(UTC).isoformat(),
            }]
            if status == "pending"
            else []
        )
        mock_router._molt.submit_dispute.side_effect = CircuitBreakerOpenError("open")

        # Should not raise
        await scheduler._retry_pending(set())


# ── DB integration tests ───────────────────────────────────────────────────


class TestDisputeDB:
    """Integration tests for dispute CRUD on a real aiosqlite DB."""

    @pytest.fixture()
    async def intel_db(self, tmp_path):
        """Create a real IntelligenceDB with schema v5."""
        from src.intelligence.database import IntelligenceDB  # noqa: PLC0415

        mock_kms = AsyncMock()
        mock_kms.unseal.side_effect = Exception("no sealed DB")
        # Patch DB_PATH to use tmp_path
        import src.intelligence.database as db_mod  # noqa: PLC0415

        original_path = db_mod.DB_PATH
        db_mod.DB_PATH = tmp_path / "test_intel.db"
        try:
            db = IntelligenceDB(kms=mock_kms)
            await db.initialize()
            yield db
            await db.close()
        finally:
            db_mod.DB_PATH = original_path

    async def test_store_and_get_dispute(self, intel_db) -> None:
        await intel_db.store_dispute_record(
            dispute_id="test-d1",
            challenge_id="test-c1",
            window_id="test-w1",
            dispute_type="computation",
            claim_type="ai_output_incorrect",
            challenger_address="0xabc",
            challenger_stake_wei="1000",
        )
        record = await intel_db.get_dispute_record("test-d1")
        assert record is not None
        assert record["dispute_id"] == "test-d1"
        assert record["status"] == "pending"
        assert record["challenger_address"] == "0xabc"

    async def test_update_dispute(self, intel_db) -> None:
        await intel_db.store_dispute_record(
            dispute_id="test-d2",
            challenge_id="test-c2",
            window_id="test-w2",
            dispute_type="subjective",
            claim_type="scoring_unfair",
            challenger_address="0xdef",
        )
        await intel_db.update_dispute_record(
            "test-d2",
            status="submitted",
            provider_case_id="provider-xyz",
        )
        record = await intel_db.get_dispute_record("test-d2")
        assert record is not None
        assert record["status"] == "submitted"
        assert record["provider_case_id"] == "provider-xyz"

    async def test_get_disputes_by_status(self, intel_db) -> None:
        await intel_db.store_dispute_record(
            dispute_id="s1",
            challenge_id="c1",
            window_id="w1",
            dispute_type="computation",
            claim_type="ai_output_incorrect",
            challenger_address="0x1",
        )
        await intel_db.store_dispute_record(
            dispute_id="s2",
            challenge_id="c2",
            window_id="w2",
            dispute_type="subjective",
            claim_type="scoring_unfair",
            challenger_address="0x2",
        )
        await intel_db.update_dispute_record("s1", status="submitted")
        pending = await intel_db.get_disputes_by_status("pending")
        submitted = await intel_db.get_disputes_by_status("submitted")
        assert len(pending) == 1
        assert pending[0]["dispute_id"] == "s2"
        assert len(submitted) == 1
        assert submitted[0]["dispute_id"] == "s1"

    async def test_get_disputes_for_window(self, intel_db) -> None:
        await intel_db.store_dispute_record(
            dispute_id="fw1",
            challenge_id="c1",
            window_id="target-window",
            dispute_type="computation",
            claim_type="ai_output_incorrect",
            challenger_address="0x1",
        )
        await intel_db.store_dispute_record(
            dispute_id="fw2",
            challenge_id="c2",
            window_id="other-window",
            dispute_type="subjective",
            claim_type="scoring_unfair",
            challenger_address="0x2",
        )
        results = await intel_db.get_disputes_for_window("target-window")
        assert len(results) == 1
        assert results[0]["dispute_id"] == "fw1"

    async def test_update_disallowed_column_raises(self, intel_db) -> None:
        await intel_db.store_dispute_record(
            dispute_id="bad-update",
            challenge_id="c1",
            window_id="w1",
            dispute_type="computation",
            claim_type="ai_output_incorrect",
            challenger_address="0x1",
        )
        with pytest.raises(ValueError, match="Cannot update column"):
            await intel_db.update_dispute_record(
                "bad-update", challenger_address="hacked",
            )
