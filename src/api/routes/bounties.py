"""Active bounties listing endpoint."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends

from src.api.deps import get_intel_db

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/bounties")
async def list_bounties(
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """List active bounties from the intelligence database."""
    try:
        bounties = await intel_db.get_active_bounties()
    except Exception:
        logger.exception("Failed to fetch active bounties")
        bounties = []
    return {"bounties": bounties, "count": len(bounties)}
