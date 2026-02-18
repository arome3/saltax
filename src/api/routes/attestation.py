"""TEE attestation proof retrieval endpoint."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/attestation/{action_id}", response_model=None)
async def get_attestation(action_id: str) -> JSONResponse:
    """Retrieve an attestation proof by action ID.

    Currently returns 404 — ``IntelligenceDB`` has no ``get_attestation()``
    method yet.  When implemented, this will return an
    ``AttestationProof.model_dump()``.
    """
    return JSONResponse(
        status_code=404,
        content={
            "status_code": 404,
            "error": "Not Found",
            "detail": f"Attestation '{action_id}' not found",
        },
    )
