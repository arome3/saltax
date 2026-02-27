"""Tests for the test executor pipeline stage."""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import SaltaXConfig
from src.pipeline.stages.test_executor import (
    _detect_js_install_cmd,
    _detect_language,
    _failed_test_result,
    _graceful_kill,
    _parse_cargo_counts,
    _parse_coverage,
    _parse_jest_counts,
    _parse_pytest_counts,
    _smart_truncate,
    _subprocess_env,
    run_tests,
)
from tests.unit.conftest import make_pipeline_state as _make_state

# ── Helpers ──────────────────────────────────────────────────────────────────

_MODULE = "src.pipeline.stages.test_executor"


def _make_config() -> SaltaXConfig:
    return SaltaXConfig()


def _mock_process(
    rc: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> AsyncMock:
    """Create a mock async subprocess process."""
    proc = AsyncMock()
    proc.returncode = rc
    proc.wait = AsyncMock(return_value=rc)
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = MagicMock()
    proc.terminate = MagicMock()
    proc.pid = 12345
    return proc


def _command_dispatch(
    *,
    clone_proc: AsyncMock,
    install_proc: AsyncMock,
    test_proc: AsyncMock,
) -> Any:
    """Return a side_effect that dispatches by command, not call order."""

    async def _dispatch(*args: object, **kwargs: object) -> AsyncMock:
        str_args = [str(a) for a in args]
        if str_args and str_args[0] == "git" and len(str_args) >= 2 and str_args[1] == "clone":
            return clone_proc
        # install commands: npm ci, pip install, cargo fetch, bun/pnpm/yarn install
        if str_args and str_args[0] in ("npm", "pip", "cargo", "bun", "pnpm", "yarn"):
            # Distinguish install from test: npm ci vs npm test, cargo fetch vs cargo test
            if len(str_args) >= 2 and str_args[1] in ("ci", "install", "fetch"):
                return install_proc
            return test_proc
        # python -m pytest
        if str_args and str_args[0] == "python":
            return test_proc
        return test_proc

    return _dispatch


# ═══════════════════════════════════════════════════════════════════════════════
# A. _parse_jest_counts
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseJestCounts:
    """Unit tests for _parse_jest_counts."""

    def test_standard_output(self) -> None:
        output = "Tests: 2 failed, 18 passed, 20 total"
        assert _parse_jest_counts(output) == (18, 2, 0)

    def test_all_passing(self) -> None:
        output = "Tests: 20 passed, 20 total"
        assert _parse_jest_counts(output) == (20, 0, 0)

    def test_with_skipped(self) -> None:
        output = "Tests: 1 failed, 2 skipped, 17 passed, 20 total"
        assert _parse_jest_counts(output) == (17, 1, 2)

    def test_no_summary_line(self) -> None:
        output = "Running tests...\nDone."
        assert _parse_jest_counts(output) == (0, 0, 0)

    def test_empty_output(self) -> None:
        assert _parse_jest_counts("") == (0, 0, 0)

    def test_with_todo(self) -> None:
        """Jest todo tests are counted as skipped."""
        output = "Tests: 3 todo, 17 passed, 20 total"
        assert _parse_jest_counts(output) == (17, 0, 3)

    def test_with_pending(self) -> None:
        """Pending tests are counted as skipped."""
        output = "Tests: 2 pending, 18 passed, 20 total"
        assert _parse_jest_counts(output) == (18, 0, 2)

    def test_reordered_statuses(self) -> None:
        """Statuses in non-standard order still parse correctly."""
        output = "Tests: 18 passed, 2 failed, 20 total"
        assert _parse_jest_counts(output) == (18, 2, 0)

    def test_vitest_format(self) -> None:
        """Vitest format: 'Tests  10 passed | 3 skipped (65)'."""
        output = "Tests  10 passed | 3 skipped (65)"
        assert _parse_jest_counts(output) == (10, 0, 3)

    def test_vitest_with_failures(self) -> None:
        """Vitest format with failures."""
        output = "Tests  2 failed | 8 passed | 1 skipped (11)"
        assert _parse_jest_counts(output) == (8, 2, 1)


# ═══════════════════════════════════════════════════════════════════════════════
# B. _parse_pytest_counts
# ═══════════════════════════════════════════════════════════════════════════════


class TestParsePytestCounts:
    """Unit tests for _parse_pytest_counts."""

    def test_standard_output(self) -> None:
        output = "18 passed, 2 failed, 1 skipped in 4.32s"
        assert _parse_pytest_counts(output) == (18, 2, 1)

    def test_passed_only(self) -> None:
        output = "20 passed in 2.10s"
        assert _parse_pytest_counts(output) == (20, 0, 0)

    def test_failed_only(self) -> None:
        output = "5 failed in 1.50s"
        assert _parse_pytest_counts(output) == (0, 5, 0)

    def test_with_deselected(self) -> None:
        """Deselected tests are not counted in passed/failed/skipped."""
        output = "10 passed, 3 deselected in 3.00s"
        assert _parse_pytest_counts(output) == (10, 0, 0)

    def test_errors_counted_as_failures(self) -> None:
        """Pytest 'errors' (fixture/collection failures) are added to failed count."""
        output = "5 passed, 2 failed, 3 errors in 2.50s"
        assert _parse_pytest_counts(output) == (5, 5, 0)

    def test_errors_only(self) -> None:
        """All tests erroring still produces a non-zero total."""
        output = "10 errors in 1.00s"
        assert _parse_pytest_counts(output) == (0, 10, 0)

    def test_single_error(self) -> None:
        """Singular 'error' also matches."""
        output = "1 error in 0.50s"
        assert _parse_pytest_counts(output) == (0, 1, 0)


# ═══════════════════════════════════════════════════════════════════════════════
# C. _parse_cargo_counts
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseCargoCounts:
    """Unit tests for _parse_cargo_counts."""

    def test_standard_ok(self) -> None:
        output = "test result: ok. 18 passed; 0 failed; 1 ignored"
        assert _parse_cargo_counts(output) == (18, 0, 1)

    def test_failed_result(self) -> None:
        output = "test result: FAILED. 15 passed; 3 failed; 0 ignored"
        assert _parse_cargo_counts(output) == (15, 3, 0)

    def test_no_result_line(self) -> None:
        output = "Compiling test_crate v0.1.0\nRunning tests..."
        assert _parse_cargo_counts(output) == (0, 0, 0)


# ═══════════════════════════════════════════════════════════════════════════════
# D. _parse_coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseCoverage:
    """Unit tests for _parse_coverage."""

    def test_jest_table(self) -> None:
        output = "All files | 82.5 | 70.0 | 90.0 | 82.5"
        assert _parse_coverage("nodejs", output) == 82.5

    def test_pytest_cov(self) -> None:
        output = "TOTAL                          500    90    82%"
        assert _parse_coverage("python", output) == 82.0

    def test_cargo_tarpaulin(self) -> None:
        output = "Coverage 75.42%"
        assert _parse_coverage("rust", output) == 75.42

    def test_none_when_missing(self) -> None:
        assert _parse_coverage("nodejs", "Tests: 20 passed, 20 total") is None

    def test_unknown_lang_returns_none(self) -> None:
        assert _parse_coverage("haskell", "Coverage 99%") is None


# ═══════════════════════════════════════════════════════════════════════════════
# E. _detect_language
# ═══════════════════════════════════════════════════════════════════════════════


class TestDetectLanguage:
    """Unit tests for _detect_language."""

    def test_nodejs(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "nodejs"

    def test_python_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "python"

    def test_python_setup_py(self, tmp_path: Path) -> None:
        """setup.py is detected as Python."""
        (tmp_path / "setup.py").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "python"

    def test_python_setup_cfg(self, tmp_path: Path) -> None:
        """setup.cfg is detected as Python."""
        (tmp_path / "setup.cfg").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "python"

    def test_rust(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.toml").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "rust"

    def test_empty_dir(self, tmp_path: Path) -> None:
        assert _detect_language(tmp_path) is None

    def test_priority_python_over_nodejs(self, tmp_path: Path) -> None:
        """When both pyproject.toml and package.json exist, python wins."""
        (tmp_path / "package.json").touch()
        (tmp_path / "pyproject.toml").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "python"

    def test_priority_python_over_rust(self, tmp_path: Path) -> None:
        """When both pyproject.toml and Cargo.toml exist, python wins."""
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "Cargo.toml").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "python"

    def test_priority_nodejs_over_rust(self, tmp_path: Path) -> None:
        """When both package.json and Cargo.toml exist, nodejs wins."""
        (tmp_path / "package.json").touch()
        (tmp_path / "Cargo.toml").touch()
        lang = _detect_language(tmp_path)
        assert lang is not None
        assert lang.name == "nodejs"


# ═══════════════════════════════════════════════════════════════════════════════
# E2. _detect_js_install_cmd
# ═══════════════════════════════════════════════════════════════════════════════


class TestDetectJsInstallCmd:
    """Unit tests for _detect_js_install_cmd."""

    def test_npm_default(self, tmp_path: Path) -> None:
        """No lockfile → npm ci."""
        cmd = _detect_js_install_cmd(tmp_path)
        assert cmd[0] == "npm"

    def test_yarn(self, tmp_path: Path) -> None:
        (tmp_path / "yarn.lock").touch()
        cmd = _detect_js_install_cmd(tmp_path)
        assert cmd[0] == "yarn"

    def test_pnpm(self, tmp_path: Path) -> None:
        (tmp_path / "pnpm-lock.yaml").touch()
        cmd = _detect_js_install_cmd(tmp_path)
        assert cmd[0] == "pnpm"

    def test_bun(self, tmp_path: Path) -> None:
        (tmp_path / "bun.lockb").touch()
        cmd = _detect_js_install_cmd(tmp_path)
        assert cmd[0] == "bun"

    def test_bun_over_yarn(self, tmp_path: Path) -> None:
        """When both bun.lockb and yarn.lock exist, bun wins."""
        (tmp_path / "bun.lockb").touch()
        (tmp_path / "yarn.lock").touch()
        cmd = _detect_js_install_cmd(tmp_path)
        assert cmd[0] == "bun"


# ═══════════════════════════════════════════════════════════════════════════════
# E3. _smart_truncate
# ═══════════════════════════════════════════════════════════════════════════════


class TestSmartTruncate:
    """Unit tests for _smart_truncate."""

    def test_short_unchanged(self) -> None:
        """Text shorter than max_len is returned unchanged."""
        assert _smart_truncate("hello", 100) == "hello"

    def test_exact_limit(self) -> None:
        """Text exactly at max_len is returned unchanged."""
        text = "x" * 50
        assert _smart_truncate(text, 50) == text

    def test_long_truncated(self) -> None:
        """Long text is truncated with marker."""
        text = "A" * 100 + "B" * 100
        result = _smart_truncate(text, 50)
        assert len(result) <= 50
        assert "...[truncated]..." in result

    def test_preserves_head_and_tail(self) -> None:
        """Both head and tail content are preserved."""
        head = "HEAD_CONTENT_"
        tail = "_TAIL_CONTENT"
        text = head + ("x" * 10_000) + tail
        result = _smart_truncate(text, 200)
        assert result.startswith("HEAD_")
        assert result.endswith("ONTENT")
        assert "...[truncated]..." in result


# ═══════════════════════════════════════════════════════════════════════════════
# E4. _subprocess_env
# ═══════════════════════════════════════════════════════════════════════════════


class TestSubprocessEnv:
    """Unit tests for _subprocess_env."""

    def test_home_set(self) -> None:
        env = _subprocess_env("/tmp/saltax-test-123")
        assert env["HOME"] == "/tmp/saltax-test-123"

    def test_ci_set(self) -> None:
        env = _subprocess_env("/tmp/test")
        assert env["CI"] == "true"

    def test_node_env_set(self) -> None:
        env = _subprocess_env("/tmp/test")
        assert env["NODE_ENV"] == "test"

    def test_path_present(self) -> None:
        env = _subprocess_env("/tmp/test")
        assert "PATH" in env
        assert len(env["PATH"]) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# F. run_tests — happy path
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunTestsHappyPath:
    """End-to-end tests with mocked subprocess — all languages."""

    async def test_nodejs_all_passing(self) -> None:
        state = _make_state()
        config = _make_config()

        test_stdout = b"Tests: 18 passed, 18 total\nAll files | 85.0 | 70 | 90 | 85"
        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=0),
            test_proc=_mock_process(rc=0, stdout=test_stdout),
        )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[1]  # nodejs
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is True
        assert state.test_results["passed_tests"] == 18
        assert state.test_results["failed_tests"] == 0
        assert state.test_results["coverage_percent"] == 85.0

    async def test_python_with_failures(self) -> None:
        state = _make_state()
        config = _make_config()

        test_stdout = b"8 passed, 2 failed in 3.00s\nTOTAL  200  40  80%"
        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=0),
            test_proc=_mock_process(rc=1, stdout=test_stdout),
        )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[0]  # python
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is False
        assert state.test_results["passed_tests"] == 8
        assert state.test_results["failed_tests"] == 2
        assert state.test_results["coverage_percent"] == 80.0

    async def test_rust_all_passing(self) -> None:
        state = _make_state()
        config = _make_config()

        test_stdout = b"test result: ok. 25 passed; 0 failed; 2 ignored\nCoverage 72.50%"
        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=0),
            test_proc=_mock_process(rc=0, stdout=test_stdout),
        )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[2]  # rust
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is True
        assert state.test_results["passed_tests"] == 25
        assert state.test_results["skipped_tests"] == 2
        assert state.test_results["coverage_percent"] == 72.5


# ═══════════════════════════════════════════════════════════════════════════════
# G. run_tests — failure cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunTestsFailureCases:
    """Tests for various failure modes."""

    async def test_clone_failure(self) -> None:
        """Clone failure → test_results populated with failure."""
        state = _make_state()
        config = _make_config()

        with patch(
            f"{_MODULE}.asyncio.create_subprocess_exec",
            side_effect=RuntimeError("clone failed"),
        ):
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is False

    async def test_no_runner_detected(self) -> None:
        """When no language file is found, result is failure."""
        state = _make_state()
        config = _make_config()

        clone_proc = _mock_process(rc=0)

        async def _dispatch(*args: object, **kwargs: object) -> AsyncMock:
            return clone_proc

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=_dispatch),
            patch(f"{_MODULE}._detect_language", return_value=None),
        ):
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is False
        assert "No recognised" in state.test_results["stderr_tail"]

    async def test_install_failure(self) -> None:
        """Install failure → exception caught, test_results populated."""
        state = _make_state()
        config = _make_config()

        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=1),
            test_proc=_mock_process(rc=0),
        )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[1]  # nodejs (no fallback)
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is False

    async def test_python_fallback_on_install(self) -> None:
        """Python install tries fallback when primary fails."""
        state = _make_state()
        config = _make_config()

        call_count = 0

        async def _dispatch(*args: object, **kwargs: object) -> AsyncMock:
            nonlocal call_count
            str_args = [str(a) for a in args]
            if str_args[0] == "git":
                return _mock_process(rc=0)
            if str_args[0] == "pip":
                call_count += 1
                # First pip call fails, second (fallback) succeeds
                if call_count == 1:
                    return _mock_process(rc=1)
                return _mock_process(rc=0)
            # test command
            return _mock_process(
                rc=0,
                stdout=b"10 passed in 2.00s\nTOTAL  100  10  90%",
            )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=_dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[0]  # python
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is True
        assert call_count == 2  # both pip calls were made

    async def test_test_timeout(self) -> None:
        """Test suite timeout → timed_out=True in result."""
        state = _make_state()
        config = _make_config()

        async def _slow_communicate() -> tuple[bytes, bytes]:
            await asyncio.sleep(999)
            return (b"", b"")

        test_proc = _mock_process(rc=0)
        test_proc.communicate = _slow_communicate

        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=0),
            test_proc=test_proc,
        )

        original_wait_for = asyncio.wait_for
        call_count = 0

        async def selective_timeout(coro: Any, *, timeout: float) -> Any:
            nonlocal call_count
            call_count += 1
            # Clone (1), install (2) succeed; test communicate (3) times out
            if call_count >= 3:
                with contextlib.suppress(AttributeError):
                    coro.close()
                raise TimeoutError
            return await original_wait_for(coro, timeout=timeout)

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
            patch(f"{_MODULE}.asyncio.wait_for", side_effect=selective_timeout),
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[1]  # nodejs
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["timed_out"] is True
        assert state.test_results["passed"] is False

    async def test_unsafe_url_rejected(self) -> None:
        """SSRF: file:// URL must not reach git clone."""
        state = _make_state(repo_url="file:///etc/passwd")
        config = _make_config()

        await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is False

    async def test_unsafe_branch_rejected(self) -> None:
        """Branch with '..' must not reach git clone."""
        state = _make_state(head_branch="main/../etc/passwd")
        config = _make_config()

        await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is False

    async def test_zero_tests_not_passing(self) -> None:
        """Exit code 0 but zero parsed tests → passed=False."""
        state = _make_state()
        config = _make_config()

        # Test runner exits 0 but produces no parseable output
        test_stdout = b"No tests found."
        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=0),
            test_proc=_mock_process(rc=0, stdout=test_stdout),
        )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[1]  # nodejs
            await run_tests(state, config)

        assert state.test_results is not None
        assert state.test_results["passed"] is False
        assert state.test_results["total_tests"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# G2. run_tests — memory_mb plumbing
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunCmdMemory:
    """Verify memory_mb is passed through to _set_resource_limits."""

    async def test_install_uses_config_memory(self) -> None:
        """_install_deps passes config memory_mb × 4 to _set_resource_limits."""
        state = _make_state()
        config = _make_config()

        captured_memory: list[int] = []
        original_set_limits = None

        # Import the real function to wrap it
        from src.pipeline.stages import test_executor as te_mod

        original_set_limits = te_mod._set_resource_limits

        def tracking_set_limits(memory_mb: int) -> Any:
            captured_memory.append(memory_mb)
            return original_set_limits(memory_mb)

        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=0),
            test_proc=_mock_process(rc=0, stdout=b"Tests: 5 passed, 5 total"),
        )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
            patch(f"{_MODULE}._set_resource_limits", side_effect=tracking_set_limits),
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[1]  # nodejs
            await run_tests(state, config)

        # Install uses 4× config memory; test suite has no RLIMIT_AS
        expected_install = config.pipeline.test_executor_memory_mb * 4
        assert expected_install in captured_memory


# ═══════════════════════════════════════════════════════════════════════════════
# H. _graceful_kill
# ═══════════════════════════════════════════════════════════════════════════════


class TestGracefulKill:
    """Tests for the graceful kill sequence."""

    async def test_sigterm_then_clean_exit(self) -> None:
        """If the process exits within 5s, no SIGKILL needed."""
        proc = _mock_process(rc=0)
        proc.wait = AsyncMock(return_value=0)

        await _graceful_kill(proc)

        proc.terminate.assert_called_once()
        proc.kill.assert_not_called()

    async def test_sigkill_after_timeout(self) -> None:
        """If the process doesn't exit in time, SIGKILL is sent."""
        proc = _mock_process(rc=0)
        killed = False

        async def _hang() -> int:
            if not killed:
                await asyncio.sleep(999)
            return 0

        def _do_kill() -> None:
            nonlocal killed
            killed = True

        proc.wait = _hang
        proc.kill = MagicMock(side_effect=_do_kill)

        with patch(f"{_MODULE}._GRACEFUL_KILL_WAIT", 0.01):
            await _graceful_kill(proc)

        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    async def test_process_lookup_error_suppressed(self) -> None:
        """ProcessLookupError on terminate is suppressed (already dead)."""
        proc = _mock_process(rc=0)
        proc.terminate = MagicMock(side_effect=ProcessLookupError)
        proc.wait = AsyncMock(return_value=0)

        # Should not raise
        await _graceful_kill(proc)

    async def test_cancelled_error_on_clone(self) -> None:
        """CancelledError during clone triggers graceful kill."""
        proc = _mock_process(rc=0)
        proc.communicate = AsyncMock(side_effect=asyncio.CancelledError())

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", return_value=proc),
            pytest.raises(asyncio.CancelledError),
        ):
            from src.pipeline.stages.test_executor import _clone_repo

            await _clone_repo(
                "https://github.com/owner/repo.git",
                "main",
                Path("/tmp/test-repo"),
            )

        proc.terminate.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# I. Temp dir cleanup
# ═══════════════════════════════════════════════════════════════════════════════


class TestTempDirCleanup:
    """Verify temp directory is always cleaned up."""

    async def test_cleanup_on_success(self) -> None:
        state = _make_state()
        config = _make_config()

        dispatch = _command_dispatch(
            clone_proc=_mock_process(rc=0),
            install_proc=_mock_process(rc=0),
            test_proc=_mock_process(rc=0, stdout=b"Tests: 5 passed, 5 total"),
        )

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}._detect_language") as mock_detect,
            patch(f"{_MODULE}.shutil.rmtree") as mock_rmtree,
        ):
            from src.pipeline.stages.test_executor import _LANGUAGES

            mock_detect.return_value = _LANGUAGES[1]  # nodejs
            await run_tests(state, config)

        mock_rmtree.assert_called_once()
        assert mock_rmtree.call_args[1].get("ignore_errors") is True

    async def test_cleanup_on_clone_failure(self) -> None:
        state = _make_state()
        config = _make_config()

        with (
            patch(
                f"{_MODULE}.asyncio.create_subprocess_exec",
                side_effect=RuntimeError("clone failed"),
            ),
            patch(f"{_MODULE}.shutil.rmtree") as mock_rmtree,
        ):
            await run_tests(state, config)

        mock_rmtree.assert_called_once()
        assert mock_rmtree.call_args[1].get("ignore_errors") is True

    async def test_cleanup_on_timeout(self) -> None:
        state = _make_state()
        config = _make_config()

        async def always_timeout(coro: Any, *, timeout: float) -> Any:
            coro.close()
            raise TimeoutError

        with (
            patch(f"{_MODULE}.asyncio.wait_for", side_effect=always_timeout),
            patch(f"{_MODULE}.shutil.rmtree") as mock_rmtree,
        ):
            await run_tests(state, config)

        mock_rmtree.assert_called_once()
        assert mock_rmtree.call_args[1].get("ignore_errors") is True


# ═══════════════════════════════════════════════════════════════════════════════
# J. _failed_test_result + state.current_stage
# ═══════════════════════════════════════════════════════════════════════════════


class TestFailedTestResult:
    """Tests for the canonical failure factory."""

    def test_defaults(self) -> None:
        result = _failed_test_result("error msg", 1.5, timed_out=False)
        assert result.passed is False
        assert result.total_tests == 0
        assert result.exit_code == -1
        assert result.stderr_tail == "error msg"
        assert result.timed_out is False

    def test_timed_out_flag(self) -> None:
        result = _failed_test_result("timeout", 5.0, timed_out=True)
        assert result.timed_out is True

    def test_stderr_truncation(self) -> None:
        long_msg = "x" * 20_000
        result = _failed_test_result(long_msg, 0.1, timed_out=False)
        assert len(result.stderr_tail) <= 10_000
        assert "...[truncated]..." in result.stderr_tail


class TestStateCurrentStage:
    """Verify that current_stage is set early."""

    async def test_current_stage_set(self) -> None:
        state = _make_state()
        config = _make_config()

        # Fail fast on clone to keep test quick
        with patch(
            f"{_MODULE}.asyncio.create_subprocess_exec",
            side_effect=RuntimeError("fail"),
        ):
            await run_tests(state, config)

        assert state.current_stage == "test_executor"
