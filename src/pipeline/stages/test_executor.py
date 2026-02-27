"""Test executor stage — clones the PR head, detects language, runs tests."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from src.models.pipeline import TestResult
from src.security import scrub_tokens, validate_branch_name, validate_clone_url

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.config import SaltaXConfig
    from src.pipeline.state import PipelineState

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_CLONE_TIMEOUT = 60  # seconds
_INSTALL_TIMEOUT = 180  # seconds (pip with native extensions can be slow)
_INSTALL_MEMORY_MULTIPLIER = 4  # install phase gets N× the test memory budget
_STDERR_TAIL_LEN = 10_000
_STDOUT_TAIL_LEN = 10_000
_GRACEFUL_KILL_WAIT = 5  # seconds


# ── Language config ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _LangConfig:
    """Immutable description of how to install & test a given language."""

    name: str  # "nodejs" | "python" | "rust"
    detect_files: tuple[str, ...]  # checked in repo root
    install_cmd: list[str]
    install_fallback: list[str] | None
    test_cmd: list[str]


_LANGUAGES: tuple[_LangConfig, ...] = (
    _LangConfig(
        name="python",
        detect_files=("pyproject.toml", "setup.py", "setup.cfg"),
        install_cmd=["pip", "install", "-e", ".[test]", "pytest-timeout", "--quiet"],
        install_fallback=["pip", "install", "-e", ".", "pytest-timeout", "--quiet"],
        test_cmd=[
            "python", "-m", "pytest", "--tb=short", "-q",
            "--ignore=tests/integration", "--ignore=tests/e2e",
            "--timeout=30",
        ],
    ),
    _LangConfig(
        name="nodejs",
        detect_files=("package.json",),
        install_cmd=["npm", "ci", "--ignore-scripts"],
        install_fallback=None,
        test_cmd=["npm", "test", "--", "--ci", "--forceExit"],
    ),
    _LangConfig(
        name="rust",
        detect_files=("Cargo.toml",),
        install_cmd=["cargo", "fetch"],
        install_fallback=None,
        test_cmd=["cargo", "test"],
    ),
)


# ── Public entry point ───────────────────────────────────────────────────────


async def run_tests(state: PipelineState, config: SaltaXConfig) -> None:
    """Run the project's test suite and populate ``state.test_results``.

    Mutates *state* in place.  Never raises — all errors are caught, logged,
    and result in a failing ``TestResult``.
    """
    state.current_stage = "test_executor"
    t0 = time.monotonic()
    logger.info("Test executor started for %s", state.pr_id)

    tmp_dir: str | None = None
    try:
        validate_clone_url(state.repo_url)
        validate_branch_name(state.head_branch)

        tmp_dir = tempfile.mkdtemp(prefix="saltax-test-")
        repo_dir = Path(tmp_dir) / "repo"

        await asyncio.wait_for(
            _clone_repo(state.repo_url, state.head_branch, repo_dir),
            timeout=_CLONE_TIMEOUT,
        )
        logger.info("Clone completed in %.1fs", time.monotonic() - t0)

        lang = _detect_language(repo_dir)
        if lang is None:
            logger.warning("No recognised test runner — skipping tests")
            elapsed = time.monotonic() - t0
            state.test_results = _failed_test_result(
                "No recognised test runner found", elapsed, timed_out=False,
            ).model_dump()
            return

        mem_mb = config.pipeline.test_executor_memory_mb
        t_install = time.monotonic()
        await _install_deps(lang, repo_dir, tmp_dir, memory_mb=mem_mb)
        logger.info("Install completed in %.1fs", time.monotonic() - t_install)

        t_test = time.monotonic()
        result = await _run_test_suite(lang, repo_dir, tmp_dir, config)
        logger.info("Test suite completed in %.1fs", time.monotonic() - t_test)
        state.test_results = result.model_dump()

        elapsed = time.monotonic() - t0
        logger.info(
            "Test executor completed: passed=%s total=%d in %.1fs",
            result.passed,
            result.total_tests,
            elapsed,
        )

    except TimeoutError:
        elapsed = time.monotonic() - t0
        logger.error("Test executor timed out after %.1fs", elapsed)
        state.test_results = _failed_test_result(
            "Timed out", elapsed, timed_out=True,
        ).model_dump()
    except FileNotFoundError as exc:
        # Tool not found (e.g. pnpm, yarn) means tests *couldn't run*,
        # not that they *failed*.  Leave test_results as None so the
        # decision engine treats this as degraded-neutral (0.5) rather
        # than a hard failure (0.0).
        logger.warning(
            "Test runner tool not found — treating as unavailable: %s", exc,
        )
    except Exception:
        elapsed = time.monotonic() - t0
        logger.exception("Test executor failed unexpectedly")
        state.test_results = _failed_test_result(
            "Internal error", elapsed, timed_out=False,
        ).model_dump()
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Private helpers ──────────────────────────────────────────────────────────


async def _clone_repo(repo_url: str, branch: str, target_dir: Path) -> None:
    """Shallow-clone *branch* from *repo_url* into *target_dir*."""
    proc = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth=1",
        "--single-branch",
        f"--branch={branch}",
        repo_url,
        str(target_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _, stderr_bytes = await proc.communicate()
    except BaseException:
        await _graceful_kill(proc)
        raise
    if proc.returncode != 0:
        stderr_text = ""
        if stderr_bytes:
            stderr_text = scrub_tokens(
                stderr_bytes.decode(errors="replace").strip()[:300]
            )
        raise RuntimeError(
            f"git clone exited with code {proc.returncode}: {stderr_text}"
        )


def _detect_language(repo_dir: Path) -> _LangConfig | None:
    """Check for language marker files in deterministic order."""
    for lang in _LANGUAGES:
        if any((repo_dir / f).exists() for f in lang.detect_files):
            logger.info("Detected language: %s", lang.name)
            return lang
    return None


def _detect_js_install_cmd(repo_dir: Path) -> list[str]:
    """Pick the right Node.js install command based on lockfile presence."""
    if (repo_dir / "bun.lockb").exists():
        return ["bun", "install", "--frozen-lockfile"]
    if (repo_dir / "pnpm-lock.yaml").exists():
        return ["pnpm", "install", "--frozen-lockfile"]
    if (repo_dir / "yarn.lock").exists():
        return ["yarn", "install", "--frozen-lockfile"]
    return ["npm", "ci", "--ignore-scripts"]


async def _install_deps(
    lang: _LangConfig, repo_dir: Path, tmp_dir: str, *, memory_mb: int = 512,
) -> None:
    """Install dependencies; try fallback command on failure.

    The install phase uses a higher memory limit than the test phase because
    ``pip`` dependency resolution and native wheel compilation can temporarily
    require significantly more memory than test execution.
    """
    env = _subprocess_env(tmp_dir)
    install_mem = memory_mb * _INSTALL_MEMORY_MULTIPLIER
    install_cmd = lang.install_cmd
    if lang.name == "nodejs":
        install_cmd = _detect_js_install_cmd(repo_dir)
    rc, stderr = await asyncio.wait_for(
        _run_cmd(install_cmd, repo_dir, env, memory_mb=install_mem),
        timeout=_INSTALL_TIMEOUT,
    )
    if rc != 0 and lang.install_fallback is not None:
        logger.warning(
            "%s install failed (rc=%d): %s — trying fallback",
            lang.name, rc, stderr[-500:] if stderr else "(no stderr)",
        )
        rc, stderr = await asyncio.wait_for(
            _run_cmd(lang.install_fallback, repo_dir, env, memory_mb=install_mem),
            timeout=_INSTALL_TIMEOUT,
        )
        if rc != 0:
            logger.error(
                "%s install fallback also failed (rc=%d): %s",
                lang.name, rc, stderr[-500:] if stderr else "(no stderr)",
            )
            raise RuntimeError(
                f"{lang.name} install fallback failed with exit code {rc}"
            )
    elif rc != 0:
        logger.error(
            "%s install failed (rc=%d): %s",
            lang.name, rc, stderr[-500:] if stderr else "(no stderr)",
        )
        raise RuntimeError(
            f"{lang.name} install failed with exit code {rc}"
        )


async def _run_cmd(
    cmd: list[str], cwd: Path, env: dict[str, str], *, memory_mb: int = 512,
) -> tuple[int, str]:
    """Execute *cmd* and return ``(exit_code, stderr_tail)``.

    Stdout is discarded.  Stderr is captured via ``communicate()`` and
    tail-truncated for diagnostic logging when the command fails.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        preexec_fn=_set_resource_limits(memory_mb),
    )
    try:
        _, stderr_bytes = await proc.communicate()
    except BaseException:
        await _graceful_kill(proc)
        raise
    stderr_text = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
    return proc.returncode or 0, _smart_truncate(stderr_text, _STDERR_TAIL_LEN)


async def _run_test_suite(
    lang: _LangConfig,
    repo_dir: Path,
    tmp_dir: str,
    config: SaltaXConfig,
) -> TestResult:
    """Execute the test command and parse its output into a ``TestResult``."""
    env = _subprocess_env(tmp_dir)
    t0 = time.monotonic()

    proc = await asyncio.create_subprocess_exec(
        *lang.test_cmd,
        cwd=str(repo_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # No RLIMIT_AS here — shared libraries (NumPy/OpenBLAS) can require
        # >1 GB of virtual address space for memory-mapped .so files.  The
        # asyncio.wait_for timeout already guards against runaway processes.
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=config.pipeline.test_executor_timeout,
        )
    except TimeoutError:
        await _graceful_kill(proc)
        elapsed = time.monotonic() - t0
        return _failed_test_result("Timed out", elapsed, timed_out=True)
    except BaseException:
        await _graceful_kill(proc)
        raise

    elapsed = time.monotonic() - t0
    stdout_text = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
    stderr_text = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
    combined = stdout_text + "\n" + stderr_text

    passed_count, failed_count, skipped_count = _parse_test_counts(
        lang.name, combined,
    )
    coverage = _parse_coverage(lang.name, combined)
    total = passed_count + failed_count + skipped_count
    rc = proc.returncode or 0

    # Log output tail when tests fail or zero tests collected for debugging
    if rc != 0 or total == 0:
        logger.info("Test exit_code=%d, stdout_tail: %s", rc, stdout_text[-500:])
        logger.info("Test stderr_tail: %s", stderr_text[-500:])

    return TestResult(
        passed=rc == 0 and failed_count == 0 and total > 0,
        total_tests=total,
        passed_tests=passed_count,
        failed_tests=failed_count,
        skipped_tests=skipped_count,
        coverage_percent=coverage,
        execution_time_seconds=round(elapsed, 2),
        exit_code=rc,
        stdout_tail=_smart_truncate(stdout_text, _STDOUT_TAIL_LEN),
        stderr_tail=_smart_truncate(stderr_text, _STDERR_TAIL_LEN),
        timed_out=False,
    )


def _set_resource_limits(memory_mb: int) -> Callable[[], None] | None:
    """Return a ``preexec_fn`` that sets ``RLIMIT_AS`` (best-effort)."""
    try:
        import resource  # noqa: PLC0415
    except ImportError:
        return None

    def _apply() -> None:
        try:
            limit_bytes = memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
        except (ValueError, OSError):
            pass  # unsupported platform — silently skip

    return _apply


async def _graceful_kill(proc: asyncio.subprocess.Process) -> None:
    """SIGTERM → wait 5s → SIGKILL.  Suppresses ``ProcessLookupError``."""
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=_GRACEFUL_KILL_WAIT)
    except (TimeoutError, ProcessLookupError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(BaseException):
            await proc.wait()


def _smart_truncate(text: str, max_len: int) -> str:
    """Keep head + tail when *text* exceeds *max_len*, inserting a marker."""
    if len(text) <= max_len:
        return text
    marker = "...[truncated]..."
    half = (max_len - len(marker)) // 2
    return text[:half] + marker + text[-half:]


def _subprocess_env(tmp_dir: str) -> dict[str, str]:
    """Build a minimal, isolated environment for subprocess execution.

    ``PGCONNECT_TIMEOUT`` makes libpq fail fast when no PostgreSQL server is
    reachable, preventing test suites from hanging on ``AsyncConnectionPool``
    open attempts in the sandbox.
    """
    return {
        "HOME": tmp_dir,
        "CI": "true",
        "NODE_ENV": "test",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PGCONNECT_TIMEOUT": "3",
    }


# ── Output parsers ───────────────────────────────────────────────────────────

# Jest / Vitest: flexible pair-matching for any status order
_JEST_SUMMARY_LINE_RE = re.compile(r"Tests:?\s+(.+)")
_JEST_PAIR_RE = re.compile(r"(\d+)\s+(failed|passed|skipped|pending|todo|total)")
# Pytest: "18 passed, 2 failed, 1 skipped, 3 errors"
_PYTEST_PASSED_RE = re.compile(r"(\d+)\s+passed")
_PYTEST_FAILED_RE = re.compile(r"(\d+)\s+failed")
_PYTEST_SKIPPED_RE = re.compile(r"(\d+)\s+skipped")
_PYTEST_ERRORS_RE = re.compile(r"(\d+)\s+errors?")
# Cargo: "test result: ok. 18 passed; 0 failed; 1 ignored"
_CARGO_RESULT_RE = re.compile(
    r"test result:\s+\w+\.\s+(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+ignored",
)

# Coverage patterns
_JEST_COVERAGE_RE = re.compile(r"All files\s*\|\s*([\d.]+)")
_PYTEST_COVERAGE_RE = re.compile(r"TOTAL\s+.*?(\d+)%")
_CARGO_COVERAGE_RE = re.compile(r"[Cc]overage\s+([\d.]+)%")


def _parse_test_counts(
    lang: str, output: str,
) -> tuple[int, int, int]:
    """Extract (passed, failed, skipped) from test runner output."""
    if lang == "nodejs":
        return _parse_jest_counts(output)
    if lang == "python":
        return _parse_pytest_counts(output)
    if lang == "rust":
        return _parse_cargo_counts(output)
    return (0, 0, 0)


def _parse_jest_counts(output: str) -> tuple[int, int, int]:
    """Parse Jest/Vitest summary line using flexible pair-matching."""
    line_match = _JEST_SUMMARY_LINE_RE.search(output)
    if not line_match:
        return (0, 0, 0)
    summary = line_match.group(1)
    counts: dict[str, int] = {}
    for pair in _JEST_PAIR_RE.finditer(summary):
        counts[pair.group(2)] = int(pair.group(1))
    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0)
    skipped = counts.get("skipped", 0) + counts.get("pending", 0) + counts.get("todo", 0)
    return (passed, failed, skipped)


def _parse_pytest_counts(output: str) -> tuple[int, int, int]:
    """Parse pytest summary line.

    Pytest "errors" (fixture/collection failures) are counted as failed
    tests because they represent tests that could not execute.
    """
    passed = _first_int(_PYTEST_PASSED_RE, output)
    failed = _first_int(_PYTEST_FAILED_RE, output) + _first_int(_PYTEST_ERRORS_RE, output)
    skipped = _first_int(_PYTEST_SKIPPED_RE, output)
    return (passed, failed, skipped)


def _parse_cargo_counts(output: str) -> tuple[int, int, int]:
    """Parse ``cargo test`` result line."""
    m = _CARGO_RESULT_RE.search(output)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _first_int(pattern: re.Pattern[str], text: str) -> int:
    """Return the first integer captured by *pattern*, or 0."""
    m = pattern.search(text)
    return int(m.group(1)) if m else 0


def _parse_coverage(lang: str, output: str) -> float | None:
    """Extract coverage percentage from test output."""
    if lang == "nodejs":
        m = _JEST_COVERAGE_RE.search(output)
        return float(m.group(1)) if m else None
    if lang == "python":
        m = _PYTEST_COVERAGE_RE.search(output)
        return float(m.group(1)) if m else None
    if lang == "rust":
        m = _CARGO_COVERAGE_RE.search(output)
        return float(m.group(1)) if m else None
    return None


def _failed_test_result(
    stderr_tail: str, elapsed: float, *, timed_out: bool,
) -> TestResult:
    """Canonical factory for a failing ``TestResult``."""
    return TestResult(
        passed=False,
        total_tests=0,
        passed_tests=0,
        failed_tests=0,
        skipped_tests=0,
        coverage_percent=None,
        execution_time_seconds=round(elapsed, 2),
        exit_code=-1,
        stderr_tail=_smart_truncate(stderr_tail, _STDERR_TAIL_LEN),
        timed_out=timed_out,
    )
