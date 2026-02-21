"""Codebase knowledge endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query

from src.api.deps import get_intel_db

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

router = APIRouter()


@router.get("/intelligence/knowledge")
async def list_codebase_knowledge(
    repo: str = Query(..., description="Repository (owner/name)"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return codebase knowledge entries for a repository."""
    items = await intel_db.list_codebase_knowledge(repo)
    return {"items": items, "count": len(items)}
