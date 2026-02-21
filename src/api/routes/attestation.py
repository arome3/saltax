"""TEE attestation proof retrieval and search endpoints."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from src.api.deps import get_intel_db
from src.attestation.verifier import verify_signature
from src.models.attestation import AttestationProof

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

router = APIRouter()


def _reconstruct_proof(record: dict[str, object]) -> AttestationProof | None:
    """Reconstruct an ``AttestationProof`` from a DB record dict.

    Returns ``None`` if reconstruction fails (e.g. missing or malformed fields).
    """
    try:
        ts_raw = record.get("created_at", "")
        ts = datetime.fromisoformat(str(ts_raw)) if ts_raw else datetime.now(UTC)

        ai_seed_raw = record.get("ai_seed")
        ai_seed = int(ai_seed_raw) if ai_seed_raw is not None else None

        return AttestationProof(
            attestation_id=str(record["attestation_id"]),
            docker_image_digest=str(record.get("docker_image_digest", "")),
            tee_platform_id=str(record.get("tee_platform_id", "")),
            pipeline_input_hash=str(record["pipeline_input_hash"]),
            pipeline_output_hash=str(record["pipeline_output_hash"]),
            ai_seed=ai_seed,
            ai_output_hash=record.get("ai_output_hash"),
            ai_system_fingerprint=record.get("ai_system_fingerprint"),
            signature=str(record.get("signature", "")),
            signer_address=str(record.get("signer_address", "")),
            timestamp=ts,
            previous_attestation_id=record.get("previous_attestation_id"),
        )
    except Exception:
        logger.debug("Failed to reconstruct proof from record", exc_info=True)
        return None


def _determine_signature_status(record: dict[str, object]) -> str:
    """Verify the signature on a stored attestation and return its status.

    Returns one of: ``"valid"``, ``"invalid"``, ``"unsigned"``,
    ``"unverifiable"``.
    """
    sig = str(record.get("signature", ""))
    if not sig:
        return "unsigned"

    signer = str(record.get("signer_address", ""))
    if not signer:
        return "unverifiable"

    proof = _reconstruct_proof(record)
    if proof is None:
        return "invalid"

    if verify_signature(proof, signer):
        return "valid"
    return "invalid"


@router.get("/attestation", response_model=None)
async def search_attestations(
    q: str | None = Query(None, description="Search by attestation ID or PR ID"),
    action_type: str | None = Query(None, description="Filter by action type prefix"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Results per page"),
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Search attestation records."""
    try:
        offset = (page - 1) * limit
        items = await intel_db.search_attestations(
            query=q, action_type=action_type, limit=limit, offset=offset,
        )
        count = await intel_db.count_attestations(query=q, action_type=action_type)
    except RuntimeError:
        return JSONResponse(
            status_code=503,
            content={"status_code": 503, "error": "Service Unavailable",
                     "detail": "Intelligence database is unavailable"},
        )
    # Convert values to strings for JSON serialization safety
    serialized = []
    for item in items:
        serialized.append({k: str(v) if v is not None else None for k, v in item.items()})
    return {"items": serialized, "count": count, "page": page, "limit": limit}


@router.get("/attestation/{action_id}", response_model=None)
async def get_attestation(
    action_id: str,
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
) -> JSONResponse:
    """Retrieve an attestation proof by action ID."""
    try:
        record = await intel_db.get_attestation(action_id)
    except Exception:
        logger.exception("Failed to retrieve attestation %s", action_id)
        return JSONResponse(
            status_code=503,
            content={
                "status_code": 503,
                "error": "Service Unavailable",
                "detail": "Intelligence database is unavailable",
            },
        )

    if record is None:
        return JSONResponse(
            status_code=404,
            content={
                "status_code": 404,
                "error": "Not Found",
                "detail": f"Attestation '{action_id}' not found",
            },
        )

    signature_status = _determine_signature_status(record)
    content = {k: str(v) for k, v in record.items()}
    content["signature_status"] = signature_status
    return JSONResponse(status_code=200, content=content)
