"""Vision document list and ingestion endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.api.deps import get_config, get_env, get_intel_db
from src.triage.vision import ingest_vision_document

logger = logging.getLogger(__name__)

router = APIRouter()

_MAX_CONTENT_BYTES = 100_000  # 100 KB


_VALID_DOC_TYPES = frozenset({"vision", "architecture", "roadmap"})


class VisionRequestBody(BaseModel):
    """Incoming vision document payload."""

    repo: str
    content: str
    title: str | None = None
    doc_type: str = "vision"


@router.get("/vision")
async def list_vision_documents(
    intel_db: Any = Depends(get_intel_db),  # noqa: B008
) -> dict[str, Any]:
    """Return all vision documents (without content/embedding)."""
    items = await intel_db.list_all_vision_documents()
    return {"items": items, "count": len(items)}


@router.post("/vision")
async def ingest_vision(
    body: VisionRequestBody,
    config: Any = Depends(get_config),  # noqa: B008
    intel_db: Any = Depends(get_intel_db),  # noqa: B008
    env: Any = Depends(get_env),  # noqa: B008
) -> dict[str, Any]:
    """Accept a vision document for triage ingestion."""
    # Validate repo format
    if "/" not in body.repo:
        raise HTTPException(status_code=400, detail="repo must contain '/'")

    # Validate content
    if not body.content or not body.content.strip():
        raise HTTPException(status_code=400, detail="content must not be empty")

    if len(body.content.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise HTTPException(status_code=400, detail="content exceeds 100 KB limit")

    # Validate doc_type
    if body.doc_type not in _VALID_DOC_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"doc_type must be one of {sorted(_VALID_DOC_TYPES)}",
        )

    # Source guard — API ingestion only allowed when source == "api"
    if config.triage.vision.source != "api":
        raise HTTPException(
            status_code=400,
            detail="Vision source is not configured for API ingestion",
        )

    await ingest_vision_document(
        body.repo, body.content, intel_db=intel_db, doc_type=body.doc_type,
        env=env, config=config,
    )

    logger.info(
        "Vision document ingested",
        extra={
            "repo": body.repo,
            "title": body.title,
            "content_len": len(body.content),
        },
    )
    return {"status": "accepted"}
