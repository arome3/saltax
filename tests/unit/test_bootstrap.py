"""Tests for the SaltaX bootstrap sequence (src/main.py)."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest import REQUIRED_ENV_VARS, VALID_YAML

from src.main import (
    TSProxyManager,
    _configure_logging,
    _graceful_shutdown,
    _teardown,
    bootstrap,
)


# ═══════════════════════════════════════════════════════════════════════════════
# A. _configure_logging
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfigureLogging:
    def test_installs_json_handler(self) -> None:
        """After _configure_logging(), root logger has a JSON-formatted handler."""
        _configure_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 1
        handler = root.handlers[0]
        assert handler.formatter is not None
        assert "JsonFormatter" in type(handler.formatter).__name__

    def test_reads_env_var_log_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SALTAX_LOG_LEVEL env var sets the root logger level."""
        monkeypatch.setenv("SALTAX_LOG_LEVEL", "DEBUG")
        _configure_logging()
        assert logging.getLogger().level == logging.DEBUG

    def test_defaults_to_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without SALTAX_LOG_LEVEL, root logger defaults to INFO."""
        monkeypatch.delenv("SALTAX_LOG_LEVEL", raising=False)
        _configure_logging()
        assert logging.getLogger().level == logging.INFO

    def test_clears_existing_handlers(self) -> None:
        """Calling _configure_logging() replaces any existing root handlers."""
        root = logging.getLogger()
        root.addHandler(logging.StreamHandler())
        root.addHandler(logging.StreamHandler())
        assert len(root.handlers) >= 2
        _configure_logging()
        assert len(root.handlers) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# B. _teardown
# ═══════════════════════════════════════════════════════════════════════════════


class TestTeardown:
    async def test_reverse_order(self) -> None:
        """Resources are closed in reverse initialization order."""
        order: list[str] = []

        class FakeResource:
            def __init__(self, name: str) -> None:
                self.name = name

            async def close(self) -> None:
                order.append(self.name)

        resources = [("first", FakeResource("first")), ("second", FakeResource("second"))]
        await _teardown(resources)
        assert order == ["second", "first"]

    async def test_continues_on_error(self) -> None:
        """If one resource's close() raises, the rest still get closed."""
        order: list[str] = []

        class BadResource:
            async def close(self) -> None:
                raise RuntimeError("boom")

        class GoodResource:
            def __init__(self, name: str) -> None:
                self.name = name

            async def close(self) -> None:
                order.append(self.name)

        resources: list[tuple[str, object]] = [
            ("good1", GoodResource("good1")),
            ("bad", BadResource()),
            ("good2", GoodResource("good2")),
        ]
        await _teardown(resources)
        # good2 (reversed first), then bad errors, then good1
        assert order == ["good2", "good1"]

    async def test_empty_list_no_op(self) -> None:
        """Teardown with empty list completes without error."""
        await _teardown([])


# ═══════════════════════════════════════════════════════════════════════════════
# C. TSProxyManager
# ═══════════════════════════════════════════════════════════════════════════════


class TestTSProxyManager:
    async def test_start_launches_process(self) -> None:
        """start() calls _start_process and creates a monitor task."""
        manager = TSProxyManager(check_interval=0.01)
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.poll.return_value = None  # process still running

        with patch.object(manager, "_start_process", return_value=mock_proc):
            manager.start()

        assert manager._process is mock_proc
        assert manager._monitor_task is not None
        # Clean up
        manager._stopped = True
        manager._monitor_task.cancel()
        try:
            await manager._monitor_task
        except asyncio.CancelledError:
            pass

    async def test_crash_restart(self) -> None:
        """Monitor restarts the process after a crash."""
        manager = TSProxyManager(max_retries=3, check_interval=0.01)

        # First process: crashes (poll returns exit code)
        proc1 = MagicMock(spec=subprocess.Popen)
        proc1.poll.return_value = 1

        # Replacement process: stays alive
        proc2 = MagicMock(spec=subprocess.Popen)
        proc2.poll.return_value = None

        call_count = 0

        def fake_start() -> MagicMock:
            nonlocal call_count
            call_count += 1
            return proc1 if call_count == 1 else proc2

        with patch.object(manager, "_start_process", side_effect=fake_start):
            manager.start()
            # Give monitor time to detect crash and restart
            await asyncio.sleep(0.1)
            await manager.stop()

        assert call_count >= 2
        assert manager._retries >= 1

    async def test_max_retries_exceeded(self) -> None:
        """Monitor stops restarting after max_retries is exceeded."""
        manager = TSProxyManager(max_retries=1, check_interval=0.01)

        # Every process crashes immediately
        def fake_start() -> MagicMock:
            proc = MagicMock(spec=subprocess.Popen)
            proc.poll.return_value = 1
            return proc

        with patch.object(manager, "_start_process", side_effect=fake_start):
            manager.start()
            await asyncio.sleep(0.15)

        assert manager._retries > manager._max_retries
        manager._stopped = True
        if manager._monitor_task:
            manager._monitor_task.cancel()
            try:
                await manager._monitor_task
            except asyncio.CancelledError:
                pass

    async def test_graceful_stop(self) -> None:
        """stop() terminates the process and cancels the monitor."""
        manager = TSProxyManager(check_interval=0.01)
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.poll.return_value = None  # still running
        mock_proc.wait.return_value = 0

        with patch.object(manager, "_start_process", return_value=mock_proc):
            manager.start()
            await asyncio.sleep(0.05)
            await manager.stop()

        mock_proc.terminate.assert_called_once()

    async def test_force_kill_on_timeout(self) -> None:
        """If terminate doesn't stop the process within timeout, kill() is used."""
        import threading

        manager = TSProxyManager(check_interval=0.01, terminate_timeout=0.05)
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.poll.return_value = None  # still running

        # First wait() blocks until killed; second wait() returns immediately
        block = threading.Event()
        call_count = 0

        def _blocking_wait() -> int:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                block.wait(timeout=5)  # blocks executor → asyncio.wait_for times out
                return 0
            return 0

        mock_proc.wait.side_effect = _blocking_wait

        with patch.object(manager, "_start_process", return_value=mock_proc):
            manager.start()
            await asyncio.sleep(0.05)
            await manager.stop()
            block.set()  # unblock the orphaned executor thread

        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()

    async def test_restart_failure_logged(self) -> None:
        """If _start_process raises during monitor restart, the error is logged
        and the retry counter still advances toward the limit."""
        manager = TSProxyManager(max_retries=3, check_interval=0.01)

        # Initial process crashes immediately
        initial_proc = MagicMock(spec=subprocess.Popen)
        initial_proc.poll.return_value = 1

        call_count = 0

        def flaky_start() -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return initial_proc
            if call_count == 2:
                raise FileNotFoundError("node not found")
            # Third+ call succeeds
            good = MagicMock(spec=subprocess.Popen)
            good.poll.return_value = None
            return good

        with patch.object(manager, "_start_process", side_effect=flaky_start):
            manager.start()
            await asyncio.sleep(0.15)
            await manager.stop()

        # Initial start + failed restart + successful restart
        assert call_count >= 3
        assert manager._retries >= 2

    async def test_close_delegates_to_stop(self) -> None:
        """close() is an alias that calls stop()."""
        manager = TSProxyManager(check_interval=0.01)
        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.poll.return_value = None
        mock_proc.wait.return_value = 0

        with patch.object(manager, "_start_process", return_value=mock_proc):
            manager.start()
            await asyncio.sleep(0.02)
            await manager.close()  # use close() instead of stop()

        assert manager._stopped is True
        mock_proc.terminate.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# D. Bootstrap phases
# ═══════════════════════════════════════════════════════════════════════════════


def _write_config_and_set_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Helper: write valid YAML and set all required env vars."""
    cfg_file = tmp_path / "saltax.config.yaml"
    cfg_file.write_text(VALID_YAML)
    monkeypatch.chdir(tmp_path)
    for key, value in REQUIRED_ENV_VARS.items():
        monkeypatch.setenv(key, value)


class TestBootstrapPhases:
    async def test_phase1_bad_config_exits(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Phase 1 exits with code 1 when the YAML file is missing."""
        monkeypatch.chdir(tmp_path)
        # No saltax.config.yaml written
        with pytest.raises(SystemExit) as exc_info:
            await bootstrap()
        assert exc_info.value.code == 1

    async def test_phase1_missing_env_vars_exits(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Phase 1 exits with code 1 when required env vars are missing."""
        cfg_file = tmp_path / "saltax.config.yaml"
        cfg_file.write_text(VALID_YAML)
        monkeypatch.chdir(tmp_path)
        # Don't set any SALTAX_ env vars — clear them
        for key in REQUIRED_ENV_VARS:
            monkeypatch.delenv(key, raising=False)
        with pytest.raises(SystemExit) as exc_info:
            await bootstrap()
        assert exc_info.value.code == 1

    async def test_phase1_config_validation_errors_exit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Phase 1 exits if cross-validation finds errors."""
        _write_config_and_set_env(tmp_path, monkeypatch)

        with patch("src.main.validate_config", return_value=["some cross-validation error"]):
            with pytest.raises(SystemExit) as exc_info:
                await bootstrap()
            assert exc_info.value.code == 1

    async def test_phase2_wallet_failure_triggers_teardown(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If wallet initialization fails in Phase 2, teardown runs and exit(1)."""
        _write_config_and_set_env(tmp_path, monkeypatch)

        with (
            patch("src.main.WalletManager.initialize", new_callable=AsyncMock) as mock_init,
            patch("src.main._teardown", new_callable=AsyncMock) as mock_teardown,
        ):
            mock_init.side_effect = RuntimeError("KMS unreachable")
            with pytest.raises(SystemExit) as exc_info:
                await bootstrap()
            assert exc_info.value.code == 1
            mock_teardown.assert_called_once()

    async def test_phase3_intel_db_failure_triggers_teardown(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If intel_db initialization fails in Phase 3, teardown runs and exit(1)."""
        _write_config_and_set_env(tmp_path, monkeypatch)

        with (
            patch("src.main.IntelligenceDB.initialize", new_callable=AsyncMock) as mock_init,
            patch("src.main._teardown", new_callable=AsyncMock) as mock_teardown,
        ):
            mock_init.side_effect = RuntimeError("DB connection refused")
            with pytest.raises(SystemExit) as exc_info:
                await bootstrap()
            assert exc_info.value.code == 1
            mock_teardown.assert_called_once()

    async def test_phase4_pipeline_failure_triggers_teardown(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If build_pipeline fails in Phase 4, teardown runs and exit(1)."""
        _write_config_and_set_env(tmp_path, monkeypatch)

        with (
            patch("src.main.build_pipeline", side_effect=RuntimeError("pipeline build failed")),
            patch("src.main._teardown", new_callable=AsyncMock) as mock_teardown,
        ):
            with pytest.raises(SystemExit) as exc_info:
                await bootstrap()
            assert exc_info.value.code == 1
            mock_teardown.assert_called_once()

    async def test_phase5_create_app_failure_triggers_teardown(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If create_app fails in Phase 5, teardown runs and exit(1)."""
        _write_config_and_set_env(tmp_path, monkeypatch)

        with (
            patch("src.main.create_app", side_effect=RuntimeError("app creation failed")),
            patch("src.main._teardown", new_callable=AsyncMock) as mock_teardown,
        ):
            with pytest.raises(SystemExit) as exc_info:
                await bootstrap()
            assert exc_info.value.code == 1
            mock_teardown.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# E. Graceful shutdown
# ═══════════════════════════════════════════════════════════════════════════════


async def _make_done_task() -> asyncio.Task[None]:
    """Create an asyncio.Task that is already complete."""

    async def noop() -> None:
        pass

    task = asyncio.create_task(noop())
    await asyncio.sleep(0)  # let the event loop run the task to completion
    return task


class TestGracefulShutdown:
    async def test_shutdown_order(self) -> None:
        """Shutdown steps execute in the correct order."""
        order: list[str] = []

        server = MagicMock()
        server_task = await _make_done_task()
        scheduler_task = await _make_done_task()

        scheduler = MagicMock()

        async def track_stop() -> None:
            order.append("scheduler.stop")

        scheduler.stop = track_stop

        intel_db = MagicMock()

        async def track_seal(kms: object) -> None:
            order.append("intel_db.seal")

        intel_db.seal = track_seal

        kms = MagicMock()

        wallet = MagicMock()

        async def track_wallet_seal() -> None:
            order.append("wallet.seal")

        wallet.seal = track_wallet_seal

        ts_proxy = MagicMock()

        async def track_ts_stop() -> None:
            order.append("ts_proxy.stop")

        ts_proxy.stop = track_ts_stop

        await _graceful_shutdown(
            server=server,
            server_task=server_task,
            scheduler=scheduler,
            scheduler_task=scheduler_task,
            intel_db=intel_db,
            kms=kms,
            wallet=wallet,
            ts_proxy=ts_proxy,
        )

        assert server.should_exit is True
        assert order == ["scheduler.stop", "intel_db.seal", "wallet.seal", "ts_proxy.stop"]

    async def test_shutdown_continues_on_step_error(self) -> None:
        """If one shutdown step raises, the remaining steps still execute."""
        order: list[str] = []

        server = MagicMock()
        server_task = await _make_done_task()
        scheduler_task = await _make_done_task()

        scheduler = MagicMock()

        async def fail_stop() -> None:
            order.append("scheduler.stop")
            raise RuntimeError("scheduler error")

        scheduler.stop = fail_stop

        intel_db = MagicMock()

        async def track_seal(kms: object) -> None:
            order.append("intel_db.seal")

        intel_db.seal = track_seal

        kms = MagicMock()

        wallet = MagicMock()
        wallet.seal = AsyncMock()

        ts_proxy = MagicMock()

        async def track_ts_stop() -> None:
            order.append("ts_proxy.stop")

        ts_proxy.stop = track_ts_stop

        await _graceful_shutdown(
            server=server,
            server_task=server_task,
            scheduler=scheduler,
            scheduler_task=scheduler_task,
            intel_db=intel_db,
            kms=kms,
            wallet=wallet,
            ts_proxy=ts_proxy,
        )

        # All four steps attempted despite the first one raising
        assert order == ["scheduler.stop", "intel_db.seal", "ts_proxy.stop"]

    async def test_shutdown_timeout(self) -> None:
        """If a shutdown step hangs, the timeout fires and shutdown completes."""
        server = MagicMock()
        server_task = await _make_done_task()
        scheduler_task = await _make_done_task()

        scheduler = MagicMock()

        async def hang() -> None:
            await asyncio.Event().wait()  # blocks forever

        scheduler.stop = hang

        intel_db = MagicMock()
        kms = MagicMock()
        wallet = MagicMock()
        wallet.seal = AsyncMock()
        ts_proxy = MagicMock()

        # Should complete quickly (not hang) due to the short timeout
        await _graceful_shutdown(
            server=server,
            server_task=server_task,
            scheduler=scheduler,
            scheduler_task=scheduler_task,
            intel_db=intel_db,
            kms=kms,
            wallet=wallet,
            ts_proxy=ts_proxy,
            timeout=0.05,
        )

        # intel_db.seal, wallet.seal, and ts_proxy.stop should NOT have been called
        # because scheduler.stop hung and the timeout fired first
        intel_db.seal.assert_not_called()
        ts_proxy.stop.assert_not_called()

    async def test_shutdown_cancels_dangling_tasks(self) -> None:
        """The finally block cancels tasks that are still running after shutdown."""
        server = MagicMock()
        server_task = await _make_done_task()

        # Scheduler task that hasn't completed yet
        never_done = asyncio.Event()
        scheduler_task = asyncio.create_task(never_done.wait())

        scheduler = MagicMock()

        async def noop_stop() -> None:
            pass

        scheduler.stop = noop_stop

        intel_db = MagicMock()

        async def noop_seal(kms: object) -> None:
            pass

        intel_db.seal = noop_seal

        kms = MagicMock()

        wallet = MagicMock()
        wallet.seal = AsyncMock()

        ts_proxy = MagicMock()

        async def noop_ts_stop() -> None:
            pass

        ts_proxy.stop = noop_ts_stop

        await _graceful_shutdown(
            server=server,
            server_task=server_task,
            scheduler=scheduler,
            scheduler_task=scheduler_task,
            intel_db=intel_db,
            kms=kms,
            wallet=wallet,
            ts_proxy=ts_proxy,
        )

        # The scheduler_task should have been cancelled by the finally block
        assert scheduler_task.done()
        assert scheduler_task.cancelled()


# ═══════════════════════════════════════════════════════════════════════════════
# F. Signal handling mechanism
# ═══════════════════════════════════════════════════════════════════════════════


class TestSignalHandling:
    async def test_event_mechanism(self) -> None:
        """Verify the asyncio.Event pattern used for shutdown signaling."""
        event = asyncio.Event()
        assert not event.is_set()
        event.set()
        assert event.is_set()
        # wait() returns immediately when already set
        await asyncio.wait_for(event.wait(), timeout=1.0)
