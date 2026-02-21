"""Patrol dashboard endpoints — history, vulnerabilities, patches."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query

from src.api.deps import get_intel_db

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/patrol/history")
async def list_patrol_history(
    repo: str | None = Query(None, description="Filter by repository"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Results per page"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return paginated patrol scan history."""
    offset = (page - 1) * limit
    items = await intel_db.list_patrol_history(
        repo=repo, limit=limit, offset=offset,
    )
    return {"items": items, "page": page, "limit": limit}


@router.get("/patrol/vulnerabilities")
async def list_vulnerabilities(
    repo: str | None = Query(None, description="Filter by repository"),
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Results per page"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return paginated known vulnerabilities."""
    offset = (page - 1) * limit
    items = await intel_db.list_known_vulnerabilities(
        repo=repo, status=status, severity=severity,
        limit=limit, offset=offset,
    )
    return {"items": items, "page": page, "limit": limit}


@router.get("/patrol/patches")
async def list_patches(
    repo: str | None = Query(None, description="Filter by repository"),
    status: str | None = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Results per page"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return paginated patrol-generated patches."""
    offset = (page - 1) * limit
    items = await intel_db.list_patrol_patches(
        repo=repo, status=status, limit=limit, offset=offset,
    )
    return {"items": items, "page": page, "limit": limit}
