"""Treasury transaction history endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query

from src.api.deps import get_intel_db

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

router = APIRouter()


@router.get("/treasury/transactions")
async def list_transactions(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Results per page"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return paginated treasury transaction history."""
    offset = (page - 1) * limit
    items = await intel_db.list_transactions(limit=limit, offset=offset)
    count = await intel_db.count_transactions()
    return {"items": items, "count": count, "page": page, "limit": limit}
