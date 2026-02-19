"""Post-merge health validation for self-modification safety.

:func:`run_health_check` never raises — it always returns a
:class:`HealthResult` so the caller can decide whether to roll back.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import py_compile
import sys
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Modules whose source files are syntax-checked and importability is verified.
_CRITICAL_MODULES: tuple[str, ...] = (
    "src.config",
    "src.pipeline.runner",
    "src.pipeline.state",
    "src.api.handlers",
    "src.intelligence.database",
)


@dataclass
class HealthResult:
    """Outcome of a post-merge health check."""

    healthy: bool = False
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    error: str | None = None


def _syntax_check_module(mod_name: str) -> str | None:
    """Syntax-check a module's on-disk source file via :mod:`py_compile`.

    Returns ``None`` on success or an error message on failure.
    Unlike :func:`importlib.import_module`, this validates the *current*
    file on disk rather than the cached version in ``sys.modules``.
    """
    spec = importlib.util.find_spec(mod_name)
    if spec is None or spec.origin is None:
        return f"Cannot find source for {mod_name}"
    source_path = Path(spec.origin)
    if not source_path.is_file():
        return f"Source file missing: {source_path}"
    try:
        py_compile.compile(str(source_path), doraise=True)
    except py_compile.PyCompileError as exc:
        return f"Syntax error in {mod_name}: {exc}"
    return None


async def run_health_check(config_path: str | Path) -> HealthResult:
    """Run lightweight health probes after a self-merge.

    Catches :class:`BaseException` (not just :class:`Exception`) so that
    ``CancelledError`` does not escape.  Never raises.
    """
    result = HealthResult()

    try:
        # 1. Config parse + validate
        try:
            from src.config import SaltaXConfig  # noqa: PLC0415

            cfg = SaltaXConfig.load(Path(config_path))
            # validate_config is called internally by load(), but call
            # explicitly to surface any deferred validation errors.
            from src.config import validate_config  # noqa: PLC0415

            validate_config(cfg)
            result.checks_passed.append("config_parse")
        except BaseException as exc:
            result.checks_failed.append("config_parse")
            result.error = f"Config validation failed: {exc}"
            result.healthy = False
            return result

        # 2. Critical module syntax check + import
        for mod_name in _CRITICAL_MODULES:
            try:
                # Syntax-check the on-disk source (catches post-merge breakage
                # even when the module is already cached in sys.modules).
                syntax_err = _syntax_check_module(mod_name)
                if syntax_err is not None:
                    result.checks_failed.append(f"syntax:{mod_name}")
                    result.error = syntax_err
                    result.healthy = False
                    return result
                result.checks_passed.append(f"syntax:{mod_name}")

                # Verify importability (first-time or cached).
                if mod_name not in sys.modules:
                    importlib.import_module(mod_name)
                result.checks_passed.append(f"import:{mod_name}")
            except BaseException as exc:
                result.checks_failed.append(f"import:{mod_name}")
                result.error = f"Failed to import {mod_name}: {exc}"
                result.healthy = False
                return result

        # 3. PipelineState construction smoke test
        try:
            from src.pipeline.state import PipelineState  # noqa: PLC0415

            PipelineState(
                pr_id="healthcheck",
                repo="healthcheck/test",
                repo_url="https://example.com",
                commit_sha="abc123",
                diff="",
                base_branch="main",
                head_branch="test",
                pr_author="healthcheck",
            )
            result.checks_passed.append("pipeline_state_construction")
        except BaseException as exc:
            result.checks_failed.append("pipeline_state_construction")
            result.error = f"PipelineState construction failed: {exc}"
            result.healthy = False
            return result

        result.healthy = True

    except BaseException as exc:
        result.error = f"Unexpected health check failure: {exc}"
        result.healthy = False

    return result
