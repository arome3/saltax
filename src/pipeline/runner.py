"""Pipeline runner — sequences stages with timing, error handling, and short-circuiting."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from src.pipeline.stages import run_ai_analysis, run_decision, run_static_scan, run_tests
from src.pipeline.state import PipelineState

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from src.attestation.engine import AttestationEngine
    from src.config import EnvConfig, SaltaXConfig
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

# Field names accepted when constructing PipelineState from a raw dict.
_PIPELINE_STATE_FIELDS: frozenset[str] = frozenset(
    f.name for f in dataclasses.fields(PipelineState)
)

# Hard ceiling for the entire pipeline (seconds).
_PIPELINE_TIMEOUT = 600


def _emit_metric(name: str, value: object, **tags: object) -> None:
    """Emit a structured metric as a log record for downstream aggregation."""
    logger.info("metric", extra={"metric_name": name, "metric_value": value, **tags})


def _stage_timeout(config_timeout: int | float) -> float:
    """Compute a per-stage wall-clock limit from the stage's config timeout.

    * ``× 2.5`` — headroom for internal retries and I/O overhead
    * ``max(…, 120)`` — 2-minute floor so short-timeout stages aren't killed prematurely
    * ``min(…, _PIPELINE_TIMEOUT)`` — cap at the global pipeline ceiling
    """
    return min(max(config_timeout * 2.5, 120), _PIPELINE_TIMEOUT)


# ── Core orchestration ────────────────────────────────────────────────────────


async def _execute_stage(
    name: str,
    coro: Callable[..., Awaitable[None]],
    args: tuple[Any, ...],
    state: PipelineState,
    budget: int | float,
    timeout_secs: float,
) -> None:
    """Run a single stage with per-stage timeout, error capture, and metrics.

    The ``finally`` block ensures timing and metrics are emitted even when the
    outer global ``asyncio.timeout`` cancels the stage mid-flight.
    """
    state.current_stage = name
    t0 = time.monotonic()
    try:
        async with asyncio.timeout(timeout_secs):
            await coro(*args)
    except TimeoutError:
        _set_error(state, name, f"Stage timed out after {timeout_secs:.0f}s")
        logger.error("Stage %s timed out after %.0fs", name, timeout_secs)
    except Exception:
        _set_error(state, name)
        logger.exception("Stage %s raised an unexpected error", name)
    finally:
        elapsed = time.monotonic() - t0
        _log_stage_timing(name, elapsed, budget)
        _emit_metric(
            "pipeline.stage.duration_seconds",
            elapsed,
            stage=name,
            trace_id=state.trace_id,
            pr_id=state.pr_id,
        )


async def run_pipeline(
    state: PipelineState,
    config: SaltaXConfig,
    env: EnvConfig,
    intel_db: IntelligenceDB,
    attestation_engine: AttestationEngine,
) -> PipelineState:
    """Execute all pipeline stages in sequence and return the mutated *state*.

    Flow: static_scan → (short-circuit?) → ai_analysis → test_execution → decision.
    The decision engine **always** runs so that every execution produces a verdict.
    """
    state.trace_id = uuid4().hex
    state.pipeline_start_time = datetime.now(UTC).isoformat()
    start_mono = time.monotonic()
    logger.info(
        "Pipeline started for %s (%s @ %s) trace_id=%s",
        state.pr_id,
        state.repo,
        state.commit_sha[:8],
        state.trace_id,
    )

    try:
        async with asyncio.timeout(_PIPELINE_TIMEOUT):
            # ── Stage 1: Static Scanner ──────────────────────────────────
            await _execute_stage(
                "static_scanner",
                run_static_scan,
                (state, config, intel_db),
                state,
                config.pipeline.static_scanner_timeout,
                _stage_timeout(config.pipeline.static_scanner_timeout),
            )

            # ── Short-circuit check ──────────────────────────────────────
            skip_middle = False
            if state.error:
                skip_middle = True
            elif _should_short_circuit(state):
                state.short_circuit = True
                skip_middle = True
                logger.warning("Short-circuit triggered — skipping AI analysis and tests")

            # ── Stage 2: AI Analyzer ─────────────────────────────────────
            if not skip_middle:
                await _execute_stage(
                    "ai_analyzer",
                    run_ai_analysis,
                    (state, config, env, intel_db),
                    state,
                    config.pipeline.ai_analyzer_timeout,
                    _stage_timeout(config.pipeline.ai_analyzer_timeout),
                )

            # ── Stage 3: Test Executor ───────────────────────────────────
            if not skip_middle and state.error is None:
                await _execute_stage(
                    "test_executor",
                    run_tests,
                    (state, config),
                    state,
                    config.pipeline.test_executor_timeout,
                    _stage_timeout(config.pipeline.test_executor_timeout),
                )

    except TimeoutError:
        _set_error(state, "timeout", f"Pipeline timed out after {_PIPELINE_TIMEOUT}s")
        logger.error("Pipeline timed out after %ds for %s", _PIPELINE_TIMEOUT, state.pr_id)

    # ── Stage 4: Decision Engine (ALWAYS runs, outside timeout) ───────
    await _execute_stage(
        "decision_engine",
        run_decision,
        (state, config, intel_db, attestation_engine),
        state,
        5,
        30,
    )

    if state.error and "timed out" in state.error.lower():
        state.current_stage = "timed_out"
    else:
        state.current_stage = "completed"

    total = time.monotonic() - start_mono
    _emit_metric(
        "pipeline.duration_seconds",
        total,
        trace_id=state.trace_id,
        pr_id=state.pr_id,
    )
    _emit_metric(
        "pipeline.short_circuit",
        1 if state.short_circuit else 0,
        trace_id=state.trace_id,
        pr_id=state.pr_id,
    )
    _emit_metric(
        "pipeline.error",
        1 if state.error else 0,
        trace_id=state.trace_id,
        pr_id=state.pr_id,
    )
    logger.info("Pipeline completed for %s in %.1fs", state.pr_id, total)

    return state


# ── Helpers ───────────────────────────────────────────────────────────────────


def _should_short_circuit(state: PipelineState) -> bool:
    """Return ``True`` when static findings warrant skipping AI/test stages."""
    findings = state.static_findings
    critical = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")
    return critical > 0 or high > 5


def _set_error(state: PipelineState, stage: str, msg: str | None = None) -> None:
    """Append an error to ``state.error``, preserving earlier errors."""
    detail = msg or _exc_summary()
    entry = f"{stage}: {detail}"
    if state.error:
        state.error = f"{state.error}; {entry}"
    else:
        state.error = entry


def _log_stage_timing(stage: str, elapsed: float, budget: int | float) -> None:
    """Log stage duration; emit a warning when it exceeds the budget."""
    logger.info("Stage %s completed in %.1fs", stage, elapsed)
    if elapsed > budget:
        logger.warning(
            "Stage %s exceeded budget (%.1fs > %ds)",
            stage,
            elapsed,
            int(budget),
        )


def _exc_summary() -> str:
    """Return a one-line summary of the current exception (call inside ``except``)."""
    import sys  # noqa: PLC0415

    exc = sys.exc_info()[1]
    return f"{type(exc).__name__}: {exc}" if exc else "unknown error"


# ── Backward-compatible wrapper ───────────────────────────────────────────────


class Pipeline:
    """Executes the multi-stage analysis pipeline on incoming PRs.

    Stores config/env/intel_db/attestation_engine and delegates to
    :func:`run_pipeline`.
    """

    def __init__(
        self,
        config: SaltaXConfig,
        env: EnvConfig,
        intel_db: IntelligenceDB,
        attestation_engine: AttestationEngine,
    ) -> None:
        self._config = config
        self._env = env
        self._intel_db = intel_db
        self._attestation_engine = attestation_engine

    async def run(self, pr_data: dict[str, Any]) -> PipelineState:
        """Build a :class:`PipelineState` from *pr_data* and execute the pipeline."""
        filtered = {k: v for k, v in pr_data.items() if k in _PIPELINE_STATE_FIELDS}
        state = PipelineState(**filtered)
        return await run_pipeline(
            state, self._config, self._env, self._intel_db,
            self._attestation_engine,
        )


def build_pipeline(
    config: SaltaXConfig,
    env: EnvConfig,
    intel_db: IntelligenceDB,
    attestation_engine: AttestationEngine,
) -> Pipeline:
    """Construct a fully-wired pipeline from configuration."""
    return Pipeline(config, env, intel_db, attestation_engine)
