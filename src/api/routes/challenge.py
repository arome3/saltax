"""Challenge and verification window API routes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from src.api.deps import get_intel_db, get_scheduler
from src.api.models import (
    ChallengeRequest,
    ChallengeResponse,
    ResolveRequest,
    ResolveResponse,
    VerificationWindowListResponse,
    VerificationWindowResponse,
)

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB
    from src.verification.scheduler import VerificationScheduler

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/challenges", response_model=ChallengeResponse)
async def file_challenge(
    body: ChallengeRequest,
    scheduler: VerificationScheduler = Depends(get_scheduler),  # noqa: B008
) -> ChallengeResponse | JSONResponse:
    """File a challenge against a verification window."""
    ok, msg = await scheduler.file_challenge(
        body.window_id,
        challenger_address=body.challenger_address,
        stake_wei=body.stake_wei,
        rationale=body.rationale,
    )
    if not ok:
        return JSONResponse(
            status_code=400,
            content=ChallengeResponse(success=False, message=msg).model_dump(),
        )
    return ChallengeResponse(success=True, message="Challenge filed", challenge_id=msg)


@router.post(
    "/challenges/{window_id}/resolve",
    response_model=ResolveResponse,
)
async def resolve_challenge(
    window_id: str,
    body: ResolveRequest,
    scheduler: VerificationScheduler = Depends(get_scheduler),  # noqa: B008
) -> ResolveResponse | JSONResponse:
    """Resolve an existing challenge on a verification window."""
    ok, msg = await scheduler.resolve_challenge(window_id, upheld=body.upheld)
    if not ok:
        return JSONResponse(
            status_code=400,
            content=ResolveResponse(success=False, message=msg).model_dump(),
        )
    resolution = "upheld" if body.upheld else "overturned"
    return ResolveResponse(success=True, message=f"Challenge {resolution}")


@router.get(
    "/verification/windows",
    response_model=VerificationWindowListResponse,
)
async def list_windows(
    status: str | None = None,
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> VerificationWindowListResponse:
    """List verification windows, optionally filtered by status."""
    if status:
        windows = await intel_db.get_windows_by_status(status)
    else:
        windows = await intel_db.get_all_verification_windows()

    items = [
        VerificationWindowResponse(
            id=str(w["id"]),
            pr_id=str(w["pr_id"]),
            repo=str(w["repo"]),
            pr_number=int(w["pr_number"]),  # type: ignore[arg-type]
            status=str(w["status"]),
            contributor_address=w.get("contributor_address"),  # type: ignore[arg-type]
            bounty_amount_wei=str(w.get("bounty_amount_wei", "0")),
            stake_amount_wei=str(w.get("stake_amount_wei", "0")),
            window_hours=int(w["window_hours"]),  # type: ignore[arg-type]
            opens_at=str(w["opens_at"]),
            closes_at=str(w["closes_at"]),
            challenge_id=w.get("challenge_id"),  # type: ignore[arg-type]
            challenger_address=w.get("challenger_address"),  # type: ignore[arg-type]
            resolution=w.get("resolution"),  # type: ignore[arg-type]
            created_at=str(w["created_at"]),
            updated_at=str(w["updated_at"]),
        )
        for w in windows
    ]
    return VerificationWindowListResponse(windows=items, count=len(items))


@router.get(
    "/verification/windows/{window_id}",
    response_model=VerificationWindowResponse,
)
async def get_window(
    window_id: str,
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> VerificationWindowResponse | JSONResponse:
    """Get a single verification window by ID."""
    w = await intel_db.get_verification_window(window_id)
    if w is None:
        return JSONResponse(
            status_code=404,
            content={"detail": "Window not found"},
        )
    return VerificationWindowResponse(
        id=str(w["id"]),
        pr_id=str(w["pr_id"]),
        repo=str(w["repo"]),
        pr_number=int(w["pr_number"]),  # type: ignore[arg-type]
        status=str(w["status"]),
        contributor_address=w.get("contributor_address"),  # type: ignore[arg-type]
        bounty_amount_wei=str(w.get("bounty_amount_wei", "0")),
        stake_amount_wei=str(w.get("stake_amount_wei", "0")),
        window_hours=int(w["window_hours"]),  # type: ignore[arg-type]
        opens_at=str(w["opens_at"]),
        closes_at=str(w["closes_at"]),
        challenge_id=w.get("challenge_id"),  # type: ignore[arg-type]
        challenger_address=w.get("challenger_address"),  # type: ignore[arg-type]
        resolution=w.get("resolution"),  # type: ignore[arg-type]
        created_at=str(w["created_at"]),
        updated_at=str(w["updated_at"]),
    )
