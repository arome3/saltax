"""Performance budget tracking with throttled log warnings.

Provides a timing context manager that measures operation duration against
predefined budgets.  Warnings are emitted at >=80% of budget, errors at
>=100%.  Repeated errors for the same operation are throttled to at most
one per 5 minutes to prevent log flooding.

Consistent with the doc's "derive metrics from logs" philosophy — no
external metrics backend required.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

# ── Budget definitions (seconds) ─────────────────────────────────────────────

PERFORMANCE_BUDGETS: dict[str, float] = {
    "webhook_acceptance": 0.2,
    "static_scanner": 120.0,
    "ai_analyzer": 60.0,
    "test_executor": 300.0,
    "full_pipeline": 600.0,
    "paid_audit": 300.0,
    "verification_tick": 5.0,
    "intelligence_query": 0.5,
    "kms_operation": 10.0,
    "treasury_payout": 30.0,
}

_WARNING_THRESHOLD = 0.80  # 80% of budget
_ERROR_COOLDOWN = 300.0  # 5 minutes between repeated errors per operation
_WARNING_COOLDOWN = 300.0  # 5 minutes between repeated warnings per operation


class BudgetTracker:
    """Track operation durations against performance budgets.

    Concurrency model: ``_last_error_at`` is a plain dict written from a
    single event loop.  Dict key writes are atomic under the GIL.  Worst
    case under concurrent access: two coroutines both see a stale timestamp
    and both emit an error — harmless and self-correcting on the next call.
    """

    def __init__(self) -> None:
        self._last_error_at: dict[str, float] = {}
        self._last_warning_at: dict[str, float] = {}
        self._last_durations: dict[str, float] = {}

    @asynccontextmanager
    async def track(self, operation: str) -> AsyncIterator[None]:
        """Time *operation* and check it against its performance budget.

        If *operation* is not in :data:`PERFORMANCE_BUDGETS`, yields
        immediately with no tracking.  If the wrapped code raises, the
        timing is still recorded in ``finally`` and the exception propagates.
        """
        budget = PERFORMANCE_BUDGETS.get(operation)
        if budget is None:
            yield
            return

        start = time.monotonic()
        try:
            yield
        finally:
            elapsed = time.monotonic() - start
            self._last_durations[operation] = elapsed
            self._check_budget(operation, elapsed, budget)

    def _check_budget(
        self,
        operation: str,
        elapsed: float,
        budget: float,
    ) -> None:
        """Emit log warnings/errors based on budget utilisation."""
        ratio = elapsed / budget

        if ratio >= 1.0:
            now = time.monotonic()
            last = self._last_error_at.get(operation, 0.0)
            if now - last >= _ERROR_COOLDOWN:
                self._last_error_at[operation] = now
                logger.error(
                    "Budget exceeded: %s took %.2fs (budget %.2fs, %.0f%%)",
                    operation,
                    elapsed,
                    budget,
                    ratio * 100,
                )
        elif ratio >= _WARNING_THRESHOLD:
            now = time.monotonic()
            last = self._last_warning_at.get(operation, 0.0)
            if now - last >= _WARNING_COOLDOWN:
                self._last_warning_at[operation] = now
                logger.warning(
                    "Budget warning: %s took %.2fs (budget %.2fs, %.0f%%)",
                    operation,
                    elapsed,
                    budget,
                    ratio * 100,
                )

    def get_summary(self) -> dict[str, dict[str, float]]:
        """Return budget utilisation for each tracked operation.

        Suitable for inclusion in health endpoint responses.
        """
        summary: dict[str, dict[str, float]] = {}
        for operation, budget in PERFORMANCE_BUDGETS.items():
            elapsed = self._last_durations.get(operation)
            if elapsed is not None:
                summary[operation] = {
                    "last_duration_s": round(elapsed, 3),
                    "budget_s": budget,
                    "utilisation_pct": round((elapsed / budget) * 100, 1),
                }
        return summary
