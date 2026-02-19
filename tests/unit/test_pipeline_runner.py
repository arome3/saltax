"""Tests for the pipeline runner orchestration layer."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

from src.config import SaltaXConfig
from src.pipeline.runner import (
    _PIPELINE_STATE_FIELDS,
    Pipeline,
    _execute_stage,
    _should_short_circuit,
    _stage_timeout,
    build_pipeline,
    run_pipeline,
)
from src.pipeline.state import PipelineState

if TYPE_CHECKING:
    import pytest

# ── Helpers ──────────────────────────────────────────────────────────────────

_MODULE = "src.pipeline.runner"


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


def _make_env() -> AsyncMock:
    """Return a mock EnvConfig (only used as passthrough to AI analyzer)."""
    return AsyncMock()


def _make_intel_db() -> AsyncMock:
    db = AsyncMock()
    db.ingest_pipeline_results = AsyncMock()
    return db


def _make_attestation_engine() -> AsyncMock:
    return AsyncMock()


def _finding(severity: str) -> dict[str, object]:
    return {"severity": severity, "rule_id": "test-rule", "message": "x"}


# ── TestShouldShortCircuit ────────────────────────────────────────────────────


class TestShouldShortCircuit:
    def test_no_findings_returns_false(self) -> None:
        state = _make_state()
        assert _should_short_circuit(state) is False

    def test_critical_finding_returns_true(self) -> None:
        state = _make_state(static_findings=[_finding("CRITICAL")])
        assert _should_short_circuit(state) is True

    def test_five_high_returns_false(self) -> None:
        state = _make_state(static_findings=[_finding("HIGH")] * 5)
        assert _should_short_circuit(state) is False

    def test_six_high_returns_true(self) -> None:
        state = _make_state(static_findings=[_finding("HIGH")] * 6)
        assert _should_short_circuit(state) is True

    def test_mixed_severities_no_trigger(self) -> None:
        findings = [_finding("MEDIUM")] * 3 + [_finding("LOW")] * 10
        state = _make_state(static_findings=findings)
        assert _should_short_circuit(state) is False

    def test_case_insensitive_severity(self) -> None:
        """Severity comparison should be case-insensitive."""
        state = _make_state(static_findings=[_finding("critical")])
        assert _should_short_circuit(state) is True

        state2 = _make_state(static_findings=[_finding("Critical")])
        assert _should_short_circuit(state2) is True


# ── TestRunPipeline ───────────────────────────────────────────────────────────


class TestRunPipeline:
    """Tests for the async run_pipeline orchestration function."""

    async def test_happy_path_all_stages_called(self) -> None:
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        call_order: list[str] = []

        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock) as m_scan,
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock) as m_ai,
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock) as m_test,
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock) as m_dec,
        ):
            m_scan.side_effect = lambda *a, **kw: call_order.append("static_scanner")
            m_ai.side_effect = lambda *a, **kw: call_order.append("ai_analyzer")
            m_test.side_effect = lambda *a, **kw: call_order.append("test_executor")
            m_dec.side_effect = lambda *a, **kw: call_order.append("decision_engine")

            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        assert call_order == ["static_scanner", "ai_analyzer", "test_executor", "decision_engine"]
        assert result.current_stage == "completed"
        assert result.pipeline_start_time != ""
        assert result.error is None
        assert len(result.trace_id) == 32

        # Verify correct args passed to each stage
        m_scan.assert_awaited_once_with(state, config, intel_db)
        m_ai.assert_awaited_once_with(state, config, env, intel_db)
        m_test.assert_awaited_once_with(state, config)
        m_dec.assert_awaited_once_with(state, config, intel_db, attest_engine)

    async def test_short_circuit_skips_ai_and_tests(self) -> None:
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        def _inject_critical(st: PipelineState, *_a: object, **_kw: object) -> None:
            st.static_findings = [_finding("CRITICAL")]

        scan = patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock)
        with (
            scan as m_scan,
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock) as m_ai,
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock) as m_test,
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock) as m_dec,
        ):
            m_scan.side_effect = _inject_critical
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        m_ai.assert_not_awaited()
        m_test.assert_not_awaited()
        m_dec.assert_awaited_once()
        assert result.short_circuit is True
        assert result.ai_analysis is None
        assert result.test_results is None

    async def test_stage_error_skips_to_decision(self) -> None:
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        scan = patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock)
        with (
            scan as m_scan,
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock) as m_ai,
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock) as m_test,
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock) as m_dec,
        ):
            m_scan.side_effect = RuntimeError("boom")
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        m_ai.assert_not_awaited()
        m_test.assert_not_awaited()
        m_dec.assert_awaited_once()
        assert result.error is not None
        assert "static_scanner" in result.error

    async def test_ai_error_skips_tests_runs_decision(self) -> None:
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        ai = patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock)
        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock),
            ai as m_ai,
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock) as m_test,
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock) as m_dec,
        ):
            m_ai.side_effect = ValueError("ai fail")
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        m_test.assert_not_awaited()
        m_dec.assert_awaited_once()
        assert result.error is not None
        assert "ai_analyzer" in result.error

    async def test_current_stage_updated_before_each_call(self) -> None:
        """Verify current_stage is set *before* the stage function executes."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        observed_stages: list[str] = []

        def _capture_stage(*_a: object, **_kw: object) -> None:
            observed_stages.append(state.current_stage)

        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock, side_effect=_capture_stage),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock, side_effect=_capture_stage),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock, side_effect=_capture_stage),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock, side_effect=_capture_stage),
        ):
            await run_pipeline(state, config, env, intel_db, attest_engine)

        assert observed_stages == [
            "static_scanner",
            "ai_analyzer",
            "test_executor",
            "decision_engine",
        ]

    async def test_budget_warning_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """Verify WARNING when a stage exceeds its time budget."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        # Patch _log_stage_timing to verify it's called, then call the real
        # implementation with an artificially high elapsed value.
        from src.pipeline.runner import _log_stage_timing as real_log

        logged_calls: list[tuple[str, float, float]] = []

        def _spy(stage: str, elapsed: float, budget: object) -> None:
            logged_calls.append((stage, elapsed, float(budget)))  # type: ignore[arg-type]
            # Force the "exceeded" path for the first stage
            if stage == "static_scanner":
                real_log(stage, 9999.0, budget)  # type: ignore[arg-type]
            else:
                real_log(stage, elapsed, budget)  # type: ignore[arg-type]

        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock),
            patch(f"{_MODULE}._log_stage_timing", side_effect=_spy),
            caplog.at_level(logging.WARNING, logger="src.pipeline.runner"),
        ):
            await run_pipeline(state, config, env, intel_db, attest_engine)

        assert any("exceeded budget" in r.message for r in caplog.records)
        assert len(logged_calls) == 4

    async def test_total_timeout_enforced(self) -> None:
        """Verify timeout is caught AND the decision engine still runs."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        async def _stall(*_a: object, **_kw: object) -> None:
            await asyncio.sleep(700)

        with (
            patch(f"{_MODULE}._PIPELINE_TIMEOUT", 0.01),
            # Per-stage timeout must be larger than global so the global fires first
            patch(f"{_MODULE}._stage_timeout", return_value=9999),
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock, side_effect=_stall),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock) as m_dec,
        ):
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        assert result.current_stage == "timed_out"
        assert result.error is not None
        assert "timed out" in result.error.lower()
        # Decision engine must ALWAYS run, even after timeout
        m_dec.assert_awaited_once()

    async def test_error_preserved_when_decision_also_fails(self) -> None:
        """Both errors are kept when scanner and decision engine both fail."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        scan = patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock)
        dec = patch(f"{_MODULE}.run_decision", new_callable=AsyncMock)
        with (
            scan as m_scan,
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            dec as m_dec,
        ):
            m_scan.side_effect = RuntimeError("scan boom")
            m_dec.side_effect = RuntimeError("decision boom")
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        # Original error is preserved (not overwritten)
        assert "static_scanner" in result.error
        assert "decision_engine" in result.error

    async def test_pipeline_start_time_recorded(self) -> None:
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock),
        ):
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        assert result.pipeline_start_time != ""
        # Should be a valid ISO-8601 timestamp
        assert "T" in result.pipeline_start_time

    async def test_trace_id_generated(self) -> None:
        """Verify trace_id is a 32-char hex string assigned by run_pipeline."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock),
        ):
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        assert len(result.trace_id) == 32
        # Must be valid hex
        int(result.trace_id, 16)

    async def test_per_stage_timeout_fires(self) -> None:
        """A per-stage timeout is distinct from the global pipeline timeout."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        async def _stall(*_a: object, **_kw: object) -> None:
            await asyncio.sleep(700)

        with (
            # Keep global timeout large so it doesn't interfere
            patch(f"{_MODULE}._stage_timeout", return_value=0.01),
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock, side_effect=_stall),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock) as m_dec,
        ):
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        # Per-stage timeout message (not global "Pipeline timed out")
        assert result.error is not None
        assert "Stage timed out" in result.error
        # Decision engine still runs
        m_dec.assert_awaited_once()

    async def test_metrics_emitted_for_each_stage(self) -> None:
        """Verify _emit_metric called for all 4 stages + 3 end-of-pipeline metrics."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock),
            patch(f"{_MODULE}._emit_metric") as m_metric,
        ):
            await run_pipeline(state, config, env, intel_db, attest_engine)

        metric_names = [call.args[0] for call in m_metric.call_args_list]
        # 4 stage durations
        assert metric_names.count("pipeline.stage.duration_seconds") == 4
        # End-of-pipeline metrics
        assert "pipeline.duration_seconds" in metric_names
        assert "pipeline.short_circuit" in metric_names
        assert "pipeline.error" in metric_names

    async def test_trace_id_in_metrics(self) -> None:
        """Every _emit_metric call must include the trace_id kwarg."""
        state = _make_state()
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        with (
            patch(f"{_MODULE}.run_static_scan", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_ai_analysis", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_tests", new_callable=AsyncMock),
            patch(f"{_MODULE}.run_decision", new_callable=AsyncMock),
            patch(f"{_MODULE}._emit_metric") as m_metric,
        ):
            result = await run_pipeline(state, config, env, intel_db, attest_engine)

        for call in m_metric.call_args_list:
            assert "trace_id" in call.kwargs, f"Missing trace_id in {call}"
            assert call.kwargs["trace_id"] == result.trace_id

    async def test_execute_stage_emits_timing_on_error(self) -> None:
        """_log_stage_timing and _emit_metric are called even when a stage raises."""
        state = _make_state(trace_id="abc123")

        async def _boom(*_a: object) -> None:
            msg = "stage failure"
            raise RuntimeError(msg)

        with (
            patch(f"{_MODULE}._log_stage_timing") as m_log,
            patch(f"{_MODULE}._emit_metric") as m_metric,
        ):
            await _execute_stage("test_stage", _boom, (), state, 60, 120)

        m_log.assert_called_once()
        assert m_log.call_args[0][0] == "test_stage"
        m_metric.assert_called_once_with(
            "pipeline.stage.duration_seconds",
            m_metric.call_args[0][1],  # elapsed (any float)
            stage="test_stage",
            trace_id="abc123",
            pr_id=state.pr_id,
        )


# ── TestStageTimeout ──────────────────────────────────────────────────────────


class TestStageTimeout:
    """Tests for the _stage_timeout formula."""

    def test_proportional_scaling(self) -> None:
        """60s config → 150s wall-clock (60 * 2.5)."""
        assert _stage_timeout(60) == 150.0

    def test_floor_applied(self) -> None:
        """10s config → 120s (floor), not 25s."""
        assert _stage_timeout(10) == 120.0

    def test_cap_applied(self) -> None:
        """300s config → 600s (cap), not 750s."""
        assert _stage_timeout(300) == 600.0

    def test_zero_gets_floor(self) -> None:
        """0s config → 120s floor."""
        assert _stage_timeout(0) == 120.0


# ── TestPipelineClass ─────────────────────────────────────────────────────────


class TestPipelineClass:
    async def test_run_constructs_state_and_delegates(self) -> None:
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        pipeline = Pipeline(config, env, intel_db, attest_engine)

        pr_data: dict[str, Any] = {
            "pr_id": "owner/repo#1",
            "repo": "owner/repo",
            "repo_url": "https://github.com/owner/repo.git",
            "commit_sha": "deadbeef12345678",
            "diff": "+added",
            "base_branch": "main",
            "head_branch": "feat/x",
            "pr_author": "alice",
        }

        with patch(f"{_MODULE}.run_pipeline", new_callable=AsyncMock) as m_run:
            m_run.return_value = _make_state()
            await pipeline.run(pr_data)

        m_run.assert_awaited_once()
        call_state = m_run.call_args[0][0]
        assert isinstance(call_state, PipelineState)
        assert call_state.pr_id == "owner/repo#1"

    async def test_run_filters_unknown_keys(self) -> None:
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        pipeline = Pipeline(config, env, intel_db, attest_engine)

        pr_data: dict[str, Any] = {
            "pr_id": "owner/repo#1",
            "repo": "owner/repo",
            "repo_url": "https://github.com/owner/repo.git",
            "commit_sha": "deadbeef12345678",
            "diff": "+added",
            "base_branch": "main",
            "head_branch": "feat/x",
            "pr_author": "alice",
            "installation_id": 12345,
            "pr_number": 99,
            # Extra keys that aren't PipelineState fields
            "action": "opened",
            "webhook_delivery_id": "abc-123",
        }

        with patch(f"{_MODULE}.run_pipeline", new_callable=AsyncMock) as m_run:
            m_run.return_value = _make_state()
            # Should not raise
            await pipeline.run(pr_data)

        call_state = m_run.call_args[0][0]
        assert isinstance(call_state, PipelineState)
        assert not hasattr(call_state, "webhook_delivery_id")

    async def test_build_pipeline_returns_pipeline(self) -> None:
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        pipeline = build_pipeline(config, env, intel_db, attest_engine)
        assert isinstance(pipeline, Pipeline)

    async def test_run_raises_on_missing_required_fields(self) -> None:
        config = _make_config()
        env = _make_env()
        intel_db = _make_intel_db()
        attest_engine = _make_attestation_engine()

        pipeline = Pipeline(config, env, intel_db, attest_engine)

        # Missing required fields like commit_sha, diff, etc.
        incomplete: dict[str, Any] = {"pr_id": "owner/repo#1"}

        with __import__("pytest").raises(TypeError):
            await pipeline.run(incomplete)


# ── TestPipelineStateFields ──────────────────────────────────────────────────


class TestPipelineStateFields:
    def test_fields_set_is_populated(self) -> None:
        assert "pr_id" in _PIPELINE_STATE_FIELDS
        assert "repo" in _PIPELINE_STATE_FIELDS
        assert "commit_sha" in _PIPELINE_STATE_FIELDS
        assert "installation_id" in _PIPELINE_STATE_FIELDS
        assert "pr_number" in _PIPELINE_STATE_FIELDS
        assert "action" not in _PIPELINE_STATE_FIELDS
