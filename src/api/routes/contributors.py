"""Contributor profile endpoints."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import JSONResponse

from src.api.deps import get_intel_db

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

router = APIRouter()

_ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


@router.get("/contributors")
async def list_contributors(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Results per page"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return paginated contributor profiles."""
    try:
        offset = (page - 1) * limit
        items = await intel_db.list_contributors(limit=limit, offset=offset)
        count = await intel_db.count_contributors()
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"status_code": 503, "error": "Service Unavailable",
                     "detail": "Intelligence database is unavailable"},
        )
    return {"items": items, "count": count, "page": page, "limit": limit}


@router.get("/contributors/{contributor_id}")
async def get_contributor(
    contributor_id: str,
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> JSONResponse:
    """Return a single contributor profile."""
    try:
        record = await intel_db.get_contributor(contributor_id)
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
                     "detail": f"Contributor '{contributor_id}' not found"},
        )
    return JSONResponse(status_code=200, content=record)


@router.put("/contributors/{github_login}/wallet")
async def set_contributor_wallet(
    github_login: str,
    wallet_address: str = Body(..., embed=True),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> JSONResponse:
    """Register or update a contributor's payout wallet address."""
    if not _ETH_ADDRESS_RE.match(wallet_address):
        return JSONResponse(
            status_code=422,
            content={"status_code": 422, "error": "Unprocessable Entity",
                     "detail": "Invalid Ethereum address format"},
        )
    try:
        await intel_db.set_contributor_wallet(github_login, wallet_address)
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"status_code": 503, "error": "Service Unavailable",
                     "detail": "Intelligence database is unavailable"},
        )
    logger.info(
        "Contributor wallet registered",
        extra={"github_login": github_login, "wallet": wallet_address},
    )
    return JSONResponse(
        status_code=200,
        content={"github_login": github_login, "wallet_address": wallet_address},
    )
