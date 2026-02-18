"""Active bounties listing endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.get("/bounties")
async def list_bounties() -> dict[str, Any]:
    """List active bounties.

    Currently returns an empty list — ``IntelligenceDB`` has no
    ``get_active_bounties()`` method yet.  When implemented, this will
    return ``BountyInfo.model_dump()`` objects.
    """
    return {"bounties": [], "count": 0}
