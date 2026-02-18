"""Anonymized intelligence statistics endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends

from src.api.deps import get_intel_db

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

router = APIRouter()


@router.get("/intelligence/stats")
async def intelligence_stats(
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return anonymized aggregate intelligence statistics.

    CRITICAL: never expose raw patterns or vulnerability details.
    Only aggregate counts and distributions are returned.
    """
    pattern_count = await intel_db.count_patterns()

    return {
        "total_patterns": pattern_count,
        "category_distribution": {},
        "severity_distribution": {},
        "avg_false_positive_rate": 0.0,
        "patterns_last_7_days": 0,
        "top_contributing_repos": [],
    }
