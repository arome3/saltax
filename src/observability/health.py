"""Component-level health checking with concurrent probes and caching.

Probes run concurrently via ``asyncio.gather()`` and results are cached
for :data:`_CACHE_TTL` seconds behind an ``asyncio.Lock`` that guards
only the fast cache read/write — not the probes themselves.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.intelligence.sealing import KMSSealManager
    from src.treasury.wallet import WalletManager
    from src.verification.scheduler import VerificationScheduler

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT = 2.0  # seconds per component probe
_CACHE_TTL = 5.0  # seconds


class ComponentStatus(StrEnum):
    """Health status values for individual components."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class ComponentHealth:
    """Health result for a single component."""

    name: str
    status: ComponentStatus
    latency_ms: float
    detail: str = ""


@dataclass(frozen=True)
class SystemHealth:
    """Aggregate health result across all components."""

    status: ComponentStatus
    components: dict[str, ComponentHealth] = field(default_factory=dict)
    cached: bool = False


class ComponentHealthChecker:
    """Runs concurrent health probes against core SaltaX subsystems.

    Concurrency model: the ``asyncio.Lock`` only guards cache read/write
    (fast dict operations).  Probes run outside the lock via
    ``asyncio.gather()``.  Two concurrent cache-miss requests may both
    run probes — acceptable since probes are read-only.
    """

    def __init__(
        self,
        intel_db: IntelligenceDB,
        github_client: GitHubClient,
        wallet: WalletManager,
        scheduler: VerificationScheduler,
        kms: KMSSealManager,
    ) -> None:
        self._intel_db = intel_db
        self._github_client = github_client
        self._wallet = wallet
        self._scheduler = scheduler
        self._kms = kms
        self._cache: SystemHealth | None = None
        self._cache_time: float = 0.0
        self._lock = asyncio.Lock()

    async def check(self) -> SystemHealth:
        """Return system health, serving from cache if fresh."""
        async with self._lock:
            now = time.monotonic()
            if self._cache is not None and (now - self._cache_time) < _CACHE_TTL:
                return SystemHealth(
                    status=self._cache.status,
                    components=self._cache.components,
                    cached=True,
                )

        # Run probes concurrently outside the lock
        results = await asyncio.gather(
            self._run_probe("database", self._check_database),
            self._run_probe("github", self._check_github),
            self._run_probe("blockchain", self._check_blockchain),
            self._run_probe("scheduler", self._check_scheduler),
            self._run_probe("tee", self._check_tee),
        )

        components = {r.name: r for r in results}
        overall = self._derive_overall(components)
        health = SystemHealth(status=overall, components=components, cached=False)

        async with self._lock:
            self._cache = health
            self._cache_time = time.monotonic()

        return health

    @staticmethod
    async def _run_probe(
        name: str,
        probe_fn: object,
    ) -> ComponentHealth:
        """Execute a single probe with a timeout guard."""
        start = time.monotonic()
        try:
            async with asyncio.timeout(_PROBE_TIMEOUT):
                # probe_fn is an async callable returning (status, detail)
                status, detail = await probe_fn()  # type: ignore[misc]
        except TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            return ComponentHealth(
                name=name,
                status=ComponentStatus.UNHEALTHY,
                latency_ms=round(elapsed_ms, 2),
                detail="probe timed out",
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return ComponentHealth(
                name=name,
                status=ComponentStatus.UNHEALTHY,
                latency_ms=round(elapsed_ms, 2),
                detail=str(exc),
            )

        elapsed_ms = (time.monotonic() - start) * 1000
        return ComponentHealth(
            name=name,
            status=status,
            latency_ms=round(elapsed_ms, 2),
            detail=detail,
        )

    @staticmethod
    def _derive_overall(
        components: dict[str, ComponentHealth],
    ) -> ComponentStatus:
        """Compute aggregate status from individual component statuses."""
        statuses = {c.status for c in components.values()}
        if ComponentStatus.UNHEALTHY in statuses:
            return ComponentStatus.UNHEALTHY
        if ComponentStatus.DEGRADED in statuses:
            return ComponentStatus.DEGRADED
        return ComponentStatus.HEALTHY

    # ── Individual probes ────────────────────────────────────────────────

    async def _check_database(self) -> tuple[ComponentStatus, str]:
        await self._intel_db.ping()
        return ComponentStatus.HEALTHY, "query ok"

    async def _check_github(self) -> tuple[ComponentStatus, str]:
        if not self._github_client.is_connected:
            return ComponentStatus.UNHEALTHY, "http client closed"
        return ComponentStatus.HEALTHY, "client open"

    async def _check_blockchain(self) -> tuple[ComponentStatus, str]:
        addr = self._wallet.address
        if addr is None:
            return ComponentStatus.UNHEALTHY, "no wallet address"
        if self._wallet.seal_failed:
            return ComponentStatus.DEGRADED, "wallet key seal failed"
        return ComponentStatus.HEALTHY, f"wallet {addr[:10]}..."

    async def _check_scheduler(self) -> tuple[ComponentStatus, str]:
        if self._scheduler.running:
            return ComponentStatus.HEALTHY, "running"
        return ComponentStatus.UNHEALTHY, "stopped"

    async def _check_tee(self) -> tuple[ComponentStatus, str]:
        if not self._kms.is_available:
            return ComponentStatus.UNHEALTHY, "kms client closed"
        return ComponentStatus.HEALTHY, "client open"
