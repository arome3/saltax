"""Pipeline history endpoints — feed and detail views."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from src.api.deps import get_intel_db

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/pipeline")
async def list_pipeline(
    repo: str | None = Query(None, description="Filter by repository"),
    verdict: str | None = Query(None, description="Filter by verdict decision"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Results per page"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return paginated pipeline review history."""
    try:
        offset = (page - 1) * limit
        items = await intel_db.list_pipeline_history(
            repo=repo, verdict=verdict, limit=limit, offset=offset,
        )
        count = await intel_db.count_pipeline_history(repo=repo, verdict=verdict)
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"status_code": 503, "error": "Service Unavailable",
                     "detail": "Intelligence database is unavailable"},
        )
    return {"items": items, "count": count, "page": page, "limit": limit}


@router.get("/pipeline/{record_id}")
async def get_pipeline_record(
    record_id: str,
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> JSONResponse:
    """Return a single pipeline review record with score breakdown."""
    try:
        record = await intel_db.get_pipeline_record(record_id)
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"status_code": 503, "error": "Service Unavailable",
                     "detail": "Intelligence database is unavailable"},
        )
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"status_code": 404, "error": "Not Found",
                     "detail": f"Pipeline record '{record_id}' not found"},
        )
    return JSONResponse(status_code=200, content=record)
