"""Unit tests for the observability subsystem: logging, health checks, metrics."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from io import StringIO
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, PropertyMock

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

if TYPE_CHECKING:
    import pytest

from src.observability.health import (
    ComponentHealth,
    ComponentHealthChecker,
    ComponentStatus,
    SystemHealth,
)
from src.observability.logging import (
    _REDACTED,
    SensitiveFieldFilter,
    configure_logging,
)
from src.observability.metrics import (
    BudgetTracker,
)

# ── TestSensitiveFieldFilter ─────────────────────────────────────────────────


class TestSensitiveFieldFilter:
    """Verify sensitive field redaction on log records."""

    def _make_record(self, **extra: object) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_exact_match_redacted(self) -> None:
        """Fields exactly in _SENSITIVE_FIELDS are redacted."""
        record = self._make_record(
            private_key="my-secret-key",
            api_key="key-123",
            password="hunter2",
        )
        filt = SensitiveFieldFilter()
        result = filt.filter(record)

        assert result is True
        assert record.private_key == _REDACTED  # type: ignore[attr-defined]
        assert record.api_key == _REDACTED  # type: ignore[attr-defined]
        assert record.password == _REDACTED  # type: ignore[attr-defined]

    def test_substring_match_redacted(self) -> None:
        """Fields containing _SENSITIVE_SUBSTRINGS are redacted."""
        record = self._make_record(
            github_app_private_key="pem-contents",
            webhook_secret_value="whsec_xxx",
            jwt_token_data="eyJ...",
        )
        filt = SensitiveFieldFilter()
        filt.filter(record)

        assert record.github_app_private_key == _REDACTED  # type: ignore[attr-defined]
        assert record.webhook_secret_value == _REDACTED  # type: ignore[attr-defined]
        assert record.jwt_token_data == _REDACTED  # type: ignore[attr-defined]

    def test_non_sensitive_preserved(self) -> None:
        """Non-sensitive fields pass through unmodified."""
        record = self._make_record(
            repo_name="owner/repo",
            pr_number="42",
        )
        filt = SensitiveFieldFilter()
        filt.filter(record)

        assert record.repo_name == "owner/repo"  # type: ignore[attr-defined]
        assert record.pr_number == "42"  # type: ignore[attr-defined]

    def test_bytes_value_redacted(self) -> None:
        """Sensitive fields with bytes values are redacted."""
        record = self._make_record(private_key=b"secret-pem-bytes")
        filt = SensitiveFieldFilter()
        filt.filter(record)

        assert record.private_key == _REDACTED  # type: ignore[attr-defined]

    def test_dict_value_redacted(self) -> None:
        """Sensitive fields with dict values are redacted."""
        record = self._make_record(credential={"nested": "secret"})
        filt = SensitiveFieldFilter()
        filt.filter(record)

        assert record.credential == _REDACTED  # type: ignore[attr-defined]

    def test_list_value_redacted(self) -> None:
        """Sensitive fields with list values are redacted."""
        record = self._make_record(token=["tok1", "tok2"])
        filt = SensitiveFieldFilter()
        filt.filter(record)

        assert record.token == _REDACTED  # type: ignore[attr-defined]

    def test_int_value_not_redacted(self) -> None:
        """Sensitive field with int value passes through (not a covered type)."""
        record = self._make_record(token=12345)
        filt = SensitiveFieldFilter()
        filt.filter(record)

        assert record.token == 12345  # type: ignore[attr-defined]


# ── TestConfigureLogging ─────────────────────────────────────────────────────


class TestConfigureLogging:
    """Verify configure_logging installs filter, reads env, is idempotent."""

    def test_filter_installed(self) -> None:
        """The root logger's handlers have a SensitiveFieldFilter."""
        configure_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 2
        handler = root.handlers[0]
        filter_types = [type(f) for f in handler.filters]
        assert SensitiveFieldFilter in filter_types

    def test_env_level_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SALTAX_LOG_LEVEL env var sets the root logger level."""
        monkeypatch.setenv("SALTAX_LOG_LEVEL", "DEBUG")
        configure_logging()
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_idempotent_call(self) -> None:
        """Double call leaves exactly two handlers (clears first)."""
        configure_logging()
        configure_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 2


# ── TestJsonOutput ───────────────────────────────────────────────────────────


class TestJsonOutput:
    """Verify JSON-formatted log output."""

    def test_json_parseable(self) -> None:
        """Log output is valid JSON with required fields."""
        configure_logging()
        root = logging.getLogger()
        handler = root.handlers[0]

        # Capture output
        stream = StringIO()
        handler.stream = stream  # type: ignore[attr-defined]

        test_logger = logging.getLogger("test.json")
        test_logger.info("hello world")

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert "message" in parsed
        assert parsed["message"] == "hello world"

    def test_extra_fields_appear(self) -> None:
        """Extra keyword arguments appear in JSON output."""
        configure_logging()
        root = logging.getLogger()
        handler = root.handlers[0]

        stream = StringIO()
        handler.stream = stream  # type: ignore[attr-defined]

        test_logger = logging.getLogger("test.extra")
        test_logger.info("event", extra={"repo": "owner/repo", "pr": 42})

        output = stream.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["repo"] == "owner/repo"
        assert parsed["pr"] == 42


# ── TestComponentHealthChecker ───────────────────────────────────────────────


def _make_checker(
    *,
    db_ok: bool = True,
    github_connected: bool = True,
    wallet_addr: str | None = "0x" + "a" * 40,
    seal_failed: bool = False,
    scheduler_running: bool = True,
    kms_available: bool = True,
) -> ComponentHealthChecker:
    """Build a ComponentHealthChecker with mocked dependencies.

    Uses the public health interfaces (``ping()``, ``is_connected``,
    ``is_available``) rather than reaching into private attributes.
    """
    intel_db = MagicMock()
    if db_ok:
        intel_db.ping = AsyncMock()
    else:
        intel_db.ping = AsyncMock(side_effect=RuntimeError("not initialized"))

    github_client = MagicMock()
    type(github_client).is_connected = PropertyMock(return_value=github_connected)

    wallet = MagicMock()
    type(wallet).address = PropertyMock(return_value=wallet_addr)
    type(wallet).seal_failed = PropertyMock(return_value=seal_failed)

    scheduler = MagicMock()
    type(scheduler).running = PropertyMock(return_value=scheduler_running)

    kms = MagicMock()
    type(kms).is_available = PropertyMock(return_value=kms_available)

    return ComponentHealthChecker(intel_db, github_client, wallet, scheduler, kms)


class TestComponentHealthChecker:
    """Verify health probes for each component."""

    async def test_all_healthy(self) -> None:
        """All components healthy → overall HEALTHY."""
        checker = _make_checker()
        result = await checker.check()

        assert result.status == ComponentStatus.HEALTHY
        assert result.cached is False
        assert len(result.components) == 5
        for comp in result.components.values():
            assert comp.status == ComponentStatus.HEALTHY

    async def test_db_unhealthy(self) -> None:
        """Database probe failure → overall UNHEALTHY."""
        checker = _make_checker(db_ok=False)
        result = await checker.check()

        assert result.status == ComponentStatus.UNHEALTHY
        assert result.components["database"].status == ComponentStatus.UNHEALTHY

    async def test_wallet_degraded(self) -> None:
        """Wallet with seal_failed → DEGRADED component, overall DEGRADED."""
        checker = _make_checker(seal_failed=True)
        result = await checker.check()

        assert result.components["blockchain"].status == ComponentStatus.DEGRADED
        assert result.status == ComponentStatus.DEGRADED

    async def test_probe_timeout(self) -> None:
        """A slow probe times out → component UNHEALTHY."""
        checker = _make_checker()

        async def slow_probe() -> tuple[ComponentStatus, str]:
            await asyncio.sleep(10)
            return ComponentStatus.HEALTHY, "unreachable"

        checker._check_database = slow_probe  # type: ignore[assignment]
        result = await checker.check()

        assert result.components["database"].status == ComponentStatus.UNHEALTHY
        assert "timed out" in result.components["database"].detail

    async def test_cache_works(self) -> None:
        """Second call within TTL returns cached result."""
        checker = _make_checker()
        first = await checker.check()
        assert first.cached is False

        second = await checker.check()
        assert second.cached is True
        assert second.status == first.status


# ── TestHealthEndpoint ───────────────────────────────────────────────────────


class TestHealthEndpoint:
    """Verify the /api/v1/health HTTP endpoint."""

    def _make_app(
        self,
        *,
        status: ComponentStatus = ComponentStatus.HEALTHY,
    ) -> FastAPI:
        from src.api.routes.health import router as health_router

        app = FastAPI()
        app.include_router(health_router, prefix="/api/v1")

        mock_checker = AsyncMock()
        mock_checker.check.return_value = SystemHealth(
            status=status,
            components={
                "database": ComponentHealth(
                    name="database",
                    status=ComponentStatus.HEALTHY,
                    latency_ms=1.5,
                    detail="query ok",
                ),
            },
            cached=False,
        )
        app.state.health_checker = mock_checker
        return app

    async def test_healthy_returns_200(self) -> None:
        """Healthy system → 200 with status=healthy."""
        app = self._make_app(status=ComponentStatus.HEALTHY)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "database" in body["components"]

    async def test_unhealthy_returns_503(self) -> None:
        """Unhealthy system → 503 with status=unhealthy."""
        app = self._make_app(status=ComponentStatus.UNHEALTHY)
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/health")

        assert resp.status_code == 503
        assert resp.json()["status"] == "unhealthy"

    async def test_no_checker_returns_503(self) -> None:
        """Missing health_checker on app.state → 503."""
        from src.api.routes.health import router as health_router

        app = FastAPI()
        app.include_router(health_router, prefix="/api/v1")
        # Deliberately do NOT set app.state.health_checker

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/health")

        assert resp.status_code == 503
        assert "not configured" in resp.json()["detail"]


# ── TestBudgetTracker ────────────────────────────────────────────────────────


class TestBudgetTracker:
    """Verify budget tracking, warnings, and errors."""

    async def test_within_budget_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Operation within budget emits no warning or error."""
        tracker = BudgetTracker()
        with caplog.at_level(logging.WARNING, logger="src.observability.metrics"):
            async with tracker.track("intelligence_query"):
                pass  # instant — well within 0.5s budget

        assert not caplog.records

    async def test_warning_at_85_pct(self, caplog: pytest.LogCaptureFixture) -> None:
        """Operation at ~85% of budget emits WARNING."""
        tracker = BudgetTracker()
        # webhook_acceptance budget is 0.2s; sleeping 0.17s ≈ 85%
        with caplog.at_level(logging.WARNING, logger="src.observability.metrics"):
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.17)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) >= 1
        assert "Budget warning" in warnings[0].message

    async def test_error_at_over_100_pct(self, caplog: pytest.LogCaptureFixture) -> None:
        """Operation exceeding budget emits ERROR."""
        tracker = BudgetTracker()
        # webhook_acceptance budget is 0.2s; sleeping 0.25s ≈ 125%
        with caplog.at_level(logging.ERROR, logger="src.observability.metrics"):
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.25)

        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) >= 1
        assert "Budget exceeded" in errors[0].message

    async def test_unknown_operation_no_tracking(self) -> None:
        """Unknown operation yields immediately without tracking."""
        tracker = BudgetTracker()
        async with tracker.track("unknown_op"):
            pass
        assert tracker.get_summary() == {}

    async def test_get_summary(self) -> None:
        """get_summary returns utilisation for tracked operations."""
        tracker = BudgetTracker()
        async with tracker.track("intelligence_query"):
            pass
        summary = tracker.get_summary()
        assert "intelligence_query" in summary
        assert "last_duration_s" in summary["intelligence_query"]
        assert "budget_s" in summary["intelligence_query"]
        assert "utilisation_pct" in summary["intelligence_query"]


# ── TestBudgetThrottling ─────────────────────────────────────────────────────


class TestBudgetThrottling:
    """Verify that repeated budget errors are throttled."""

    async def test_repeated_errors_throttled(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Second immediate budget error is suppressed by throttle."""
        tracker = BudgetTracker()
        with caplog.at_level(logging.ERROR, logger="src.observability.metrics"):
            # First: exceeds budget → ERROR emitted
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.25)

            caplog.clear()

            # Second: also exceeds → throttled, no ERROR
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.25)

        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 0

    async def test_error_emitted_after_cooldown(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After cooldown expires, the next budget error is emitted."""
        tracker = BudgetTracker()

        # First call — record the error
        async with tracker.track("webhook_acceptance"):
            await asyncio.sleep(0.25)

        # Fake the timestamp to simulate cooldown having passed
        tracker._last_error_at["webhook_acceptance"] = time.monotonic() - 400

        records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r)  # type: ignore[assignment]
        metrics_logger = logging.getLogger("src.observability.metrics")
        metrics_logger.addHandler(handler)
        try:
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.25)

            errors = [r for r in records if r.levelno == logging.ERROR]
            assert len(errors) >= 1
        finally:
            metrics_logger.removeHandler(handler)


# ── TestWarningThrottling ─────────────────────────────────────────────────


class TestWarningThrottling:
    """Verify that repeated budget warnings are throttled."""

    async def test_repeated_warnings_throttled(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Second immediate budget warning is suppressed by throttle."""
        tracker = BudgetTracker()
        with caplog.at_level(logging.WARNING, logger="src.observability.metrics"):
            # First: ~85% of budget → WARNING emitted
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.17)

            caplog.clear()

            # Second: also ~85% → throttled, no WARNING
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.17)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 0

    async def test_warning_emitted_after_cooldown(self) -> None:
        """After cooldown expires, the next budget warning is emitted."""
        tracker = BudgetTracker()

        # First call — record the warning
        async with tracker.track("webhook_acceptance"):
            await asyncio.sleep(0.17)

        # Fake the timestamp to simulate cooldown having passed
        tracker._last_warning_at["webhook_acceptance"] = time.monotonic() - 400

        records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r)  # type: ignore[assignment]
        metrics_logger = logging.getLogger("src.observability.metrics")
        metrics_logger.addHandler(handler)
        try:
            async with tracker.track("webhook_acceptance"):
                await asyncio.sleep(0.17)

            warnings = [r for r in records if r.levelno == logging.WARNING]
            assert len(warnings) >= 1
        finally:
            metrics_logger.removeHandler(handler)


# ── TestHealthEndpointBudget ──────────────────────────────────────────────


class TestHealthEndpointBudget:
    """Verify budget_utilisation in health endpoint response."""

    async def test_budget_utilisation_included(self) -> None:
        """Health response includes budget_utilisation when tracker is present."""
        from src.api.routes.health import router as health_router

        app = FastAPI()
        app.include_router(health_router, prefix="/api/v1")

        mock_checker = AsyncMock()
        mock_checker.check.return_value = SystemHealth(
            status=ComponentStatus.HEALTHY,
            components={
                "database": ComponentHealth(
                    name="database",
                    status=ComponentStatus.HEALTHY,
                    latency_ms=1.5,
                    detail="query ok",
                ),
            },
            cached=False,
        )
        app.state.health_checker = mock_checker

        tracker = BudgetTracker()
        async with tracker.track("intelligence_query"):
            pass
        app.state.budget_tracker = tracker

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/health")

        body = resp.json()
        assert "budget_utilisation" in body
        assert "intelligence_query" in body["budget_utilisation"]

    async def test_no_budget_tracker_omits_field(self) -> None:
        """Health response omits budget_utilisation when no tracker is set."""
        from src.api.routes.health import router as health_router

        app = FastAPI()
        app.include_router(health_router, prefix="/api/v1")

        mock_checker = AsyncMock()
        mock_checker.check.return_value = SystemHealth(
            status=ComponentStatus.HEALTHY,
            components={},
            cached=False,
        )
        app.state.health_checker = mock_checker

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/health")

        body = resp.json()
        assert "budget_utilisation" not in body
