"""Vision document ingestion endpoint."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter()


class VisionRequestBody(BaseModel):
    """Incoming vision document payload."""

    repo: str
    document: str
    title: str


@router.post("/vision")
async def ingest_vision(body: VisionRequestBody) -> dict[str, Any]:
    """Accept a vision document for triage ingestion.

    Currently a stub — logs and acknowledges.  When implemented, this will
    call the triage vision ingestion layer.
    """
    logger.info(
        "Vision document received",
        extra={"repo": body.repo, "title": body.title, "doc_len": len(body.document)},
    )
    return {"status": "accepted"}
