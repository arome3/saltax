"""Dispute resolution API routes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from src.api.deps import get_dispute_router, get_intel_db
from src.api.models import (
    DisputeListResponse,
    DisputeRecordResponse,
    DisputeRequest,
    DisputeResponse,
)

if TYPE_CHECKING:
    from src.disputes.router import DisputeRouter
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/disputes", response_model=DisputeResponse)
async def open_dispute(
    body: DisputeRequest,
    dispute_router: DisputeRouter = Depends(get_dispute_router),  # noqa: B008
) -> DisputeResponse | JSONResponse:
    """Open a dispute for a challenged verification window."""
    ok, msg = await dispute_router.open_dispute(
        body.window_id,
        body.challenge_id,
        body.claim_type,
    )
    if not ok:
        return JSONResponse(
            status_code=400,
            content=DisputeResponse(success=False, message=msg).model_dump(),
        )
    return DisputeResponse(success=True, message="Dispute opened", dispute_id=msg)


@router.get("/disputes/{dispute_id}", response_model=DisputeRecordResponse)
async def get_dispute(
    dispute_id: str,
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> DisputeRecordResponse | JSONResponse:
    """Get a dispute record by ID."""
    record = await intel_db.get_dispute_record(dispute_id)
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"detail": "Dispute not found"},
        )
    return DisputeRecordResponse(
        dispute_id=str(record["dispute_id"]),
        challenge_id=str(record["challenge_id"]),
        window_id=str(record["window_id"]),
        dispute_type=str(record["dispute_type"]),
        claim_type=str(record["claim_type"]),
        status=str(record["status"]),
        provider_case_id=record.get("provider_case_id"),  # type: ignore[arg-type]
        provider_verdict=record.get("provider_verdict"),  # type: ignore[arg-type]
        challenger_address=str(record["challenger_address"]),
        submission_attempts=int(record.get("submission_attempts", 0) or 0),
        created_at=str(record["created_at"]),
        updated_at=str(record["updated_at"]),
        resolved_at=record.get("resolved_at"),  # type: ignore[arg-type]
    )


@router.get(
    "/disputes/window/{window_id}",
    response_model=DisputeListResponse,
)
async def list_disputes_for_window(
    window_id: str,
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> DisputeListResponse:
    """List all disputes for a verification window."""
    records = await intel_db.get_disputes_for_window(window_id)
    items = [
        DisputeRecordResponse(
            dispute_id=str(r["dispute_id"]),
            challenge_id=str(r["challenge_id"]),
            window_id=str(r["window_id"]),
            dispute_type=str(r["dispute_type"]),
            claim_type=str(r["claim_type"]),
            status=str(r["status"]),
            provider_case_id=r.get("provider_case_id"),  # type: ignore[arg-type]
            provider_verdict=r.get("provider_verdict"),  # type: ignore[arg-type]
            challenger_address=str(r["challenger_address"]),
            submission_attempts=int(r.get("submission_attempts", 0) or 0),
            created_at=str(r["created_at"]),
            updated_at=str(r["updated_at"]),
            resolved_at=r.get("resolved_at"),  # type: ignore[arg-type]
        )
        for r in records
    ]
    return DisputeListResponse(disputes=items, count=len(items))
