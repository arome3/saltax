"""Pipeline runner for the multi-stage code review pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.config import EnvConfig, SaltaXConfig
    from src.intelligence.database import IntelligenceDB


class Pipeline:
    """Executes the multi-stage analysis pipeline on incoming PRs."""

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("Pipeline stages not yet implemented")


def build_pipeline(
    config: SaltaXConfig,
    env: EnvConfig,
    intel_db: IntelligenceDB,
) -> Pipeline:
    """Construct a fully-wired pipeline from configuration."""
    return Pipeline()
