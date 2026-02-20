"""Graceful degradation matrix for SaltaX dependencies.

Tracks which external dependencies are healthy and computes the
current operational mode.  The pipeline runner can query
:attr:`DependencyHealth.mode` to decide whether to skip stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

DependencyName = Literal["kms", "github", "eigenai", "database"]


class OperationalMode(StrEnum):
    """System operational modes, ordered by severity."""

    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    BLOCKED = "blocked"
    CRITICAL = "critical"


# Priority: higher index = more severe.
_MODE_SEVERITY: dict[OperationalMode, int] = {
    OperationalMode.OPERATIONAL: 0,
    OperationalMode.DEGRADED: 1,
    OperationalMode.BLOCKED: 2,
    OperationalMode.CRITICAL: 3,
}

# Which mode each dependency's failure triggers.
_FAILURE_MODE: dict[DependencyName, OperationalMode] = {
    "kms": OperationalMode.CRITICAL,
    "database": OperationalMode.CRITICAL,
    "github": OperationalMode.BLOCKED,
    "eigenai": OperationalMode.DEGRADED,
}


@dataclass
class DependencyHealth:
    """Tracks dependency health and derives system operational mode.

    Thread-safe for single-writer scenarios (the health checker).
    For concurrent writes, the caller must serialize.
    """

    _unhealthy: set[DependencyName] = field(default_factory=set)

    def mark_unhealthy(self, name: DependencyName) -> None:
        """Record a dependency as unavailable."""
        self._unhealthy.add(name)

    def mark_healthy(self, name: DependencyName) -> None:
        """Record a dependency as available."""
        self._unhealthy.discard(name)

    @property
    def mode(self) -> OperationalMode:
        """Current system operational mode based on dependency health.

        - ``kms`` or ``database`` down -> critical
        - ``github`` down -> blocked
        - ``eigenai`` down -> degraded
        - all up -> operational
        """
        if not self._unhealthy:
            return OperationalMode.OPERATIONAL

        worst = OperationalMode.OPERATIONAL
        for dep in self._unhealthy:
            dep_mode = _FAILURE_MODE.get(dep, OperationalMode.DEGRADED)
            if _MODE_SEVERITY[dep_mode] > _MODE_SEVERITY[worst]:
                worst = dep_mode
        return worst

    @property
    def is_ai_available(self) -> bool:
        """Whether the AI/embedding service is reachable."""
        return "eigenai" not in self._unhealthy
