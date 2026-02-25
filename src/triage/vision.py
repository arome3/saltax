"""Vision document loading and ingestion for triage alignment scoring.

Provides functions to load a project's vision/roadmap document (from DB cache
or GitHub repository) and to ingest documents uploaded via the API.  The loaded
text is injected into ``PipelineState.vision_document`` so the AI analyzer can
score PR alignment against it.

Supports multiple document types (``vision``, ``architecture``, ``roadmap``)
via ``config.triage.vision.document_types``.  Each type has its own set of
candidate paths in the repository.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_DOC_TYPE_PATHS: dict[str, tuple[str, ...]] = {
    "vision": ("VISION.md", "docs/VISION.md", ".github/VISION.md"),
    "architecture": ("ARCHITECTURE.md", "docs/ARCHITECTURE.md", ".github/ARCHITECTURE.md"),
    "roadmap": ("ROADMAP.md", "docs/ROADMAP.md", ".github/ROADMAP.md"),
}

# Backward-compat alias used by existing tests
_VISION_CANDIDATE_PATHS = _DOC_TYPE_PATHS["vision"]

_CACHE_MAX_AGE_HOURS = 24

_GENERIC_HEADERS = frozenset({
    "overview", "introduction", "about", "table of contents",
    "toc", "preface", "summary",
})

_MAX_GOALS = 10


# ── Public API ───────────────────────────────────────────────────────────────


def extract_vision_goals(content: str) -> list[str]:
    """Extract discrete goals from a vision document via markdown parsing.

    Extracts ``##`` headers and top-level bullets (``- items``).
    Filters generic headers (overview, introduction, about).
    Returns max 10 goals.
    """
    goals: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # ## Header extraction
        if stripped.startswith("## "):
            header_text = stripped[3:].strip()
            if header_text.lower() not in _GENERIC_HEADERS:
                goals.append(header_text)
        # Top-level bullet extraction (- Item)
        elif stripped.startswith("- ") and not line.startswith("  "):
            bullet_text = stripped[2:].strip()
            if bullet_text:
                goals.append(bullet_text)
        if len(goals) >= _MAX_GOALS:
            break
    return goals[:_MAX_GOALS]


async def load_vision_documents(
    repo: str,
    installation_id: int,
    *,
    config: SaltaXConfig,
    intel_db: IntelligenceDB,
    github_client: GitHubClient,
    env: EnvConfig | None = None,
) -> str | None:
    """Load all configured vision documents for *repo*, merged with headers.

    Iterates over ``config.triage.vision.document_types``, loads each via
    ``_load_single_document()``, and concatenates them with section headers.
    Returns ``None`` when no document exists for any configured type.
    """
    sections: list[str] = []

    for doc_type in config.triage.vision.document_types:
        content = await _load_single_document(
            repo, installation_id,
            doc_type=doc_type,
            config=config,
            intel_db=intel_db,
            github_client=github_client,
            env=env,
        )
        if content is not None:
            if len(config.triage.vision.document_types) > 1:
                sections.append(f"## Document: {doc_type}\n\n{content}")
            else:
                sections.append(content)

    if not sections:
        return None
    return "\n\n".join(sections)


async def load_vision_document(
    repo: str,
    installation_id: int,
    *,
    config: SaltaXConfig,
    intel_db: IntelligenceDB,
    github_client: GitHubClient,
    env: EnvConfig | None = None,
) -> str | None:
    """Backward-compat wrapper — delegates to :func:`load_vision_documents`."""
    return await load_vision_documents(
        repo, installation_id,
        config=config, intel_db=intel_db, github_client=github_client, env=env,
    )


async def ingest_vision_document(
    repo: str,
    content: str,
    *,
    intel_db: IntelligenceDB,
    doc_type: str = "vision",
    env: EnvConfig | None = None,
    config: SaltaXConfig | None = None,
) -> None:
    """Store a vision document in the intelligence DB.

    When *env* and *config* are provided, an embedding is computed and stored
    alongside the document for downstream similarity cross-checks.

    Validation (empty content, size limits) is enforced at the API route layer,
    not here — this function trusts its callers.
    """
    embedding_blob: bytes | None = None
    if env is not None and config is not None:
        try:
            from src.intelligence.similarity import ndarray_to_blob  # noqa: PLC0415
            from src.triage.dedup import embed_diff  # noqa: PLC0415

            vec, _model = await embed_diff(content, env=env, config=config)
            embedding_blob = ndarray_to_blob(vec)
        except Exception:
            logger.warning("Failed to embed vision document", exc_info=True)

    doc_id = f"vision:{repo}:{doc_type}"
    await intel_db.store_vision_document(
        doc_id=doc_id,
        repo=repo,
        content=content,
        doc_type=doc_type,
        embedding=embedding_blob,
    )


# ── Private helpers ──────────────────────────────────────────────────────────


async def _load_single_document(
    repo: str,
    installation_id: int,
    *,
    doc_type: str,
    config: SaltaXConfig,
    intel_db: IntelligenceDB,
    github_client: GitHubClient,
    env: EnvConfig | None = None,
) -> str | None:
    """Load a single document type, using DB cache when fresh.

    Cache policy mirrors the original ``load_vision_document`` behavior:
    - Fresh cache (<24h) → return immediately.
    - Stale/absent + ``source == "repo"`` → fetch from GitHub, cache, return.
    - ``source == "api"`` → return stale cache or None.
    """
    docs = await intel_db.get_vision_documents(repo, doc_type=doc_type)
    cached = docs[0] if docs else None

    cache_age: timedelta | None = None
    if cached is not None:
        cache_age = datetime.now(UTC) - datetime.fromisoformat(str(cached["updated_at"]))
        if cache_age < timedelta(hours=_CACHE_MAX_AGE_HOURS):
            age_hours = round(cache_age.total_seconds() / 3600, 1)
            logger.info(
                "Vision document cache hit (fresh)",
                extra={"repo": repo, "doc_type": doc_type, "age_hours": age_hours},
            )
            return str(cached["content"])

    source = config.triage.vision.source

    # API-sourced repos never fetch from GitHub — return stale cache or None.
    if source == "api":
        if cached is not None:
            age_hours = round(cache_age.total_seconds() / 3600, 1)  # type: ignore[union-attr]
            logger.info(
                "Returning stale vision document (source=api)",
                extra={"repo": repo, "doc_type": doc_type, "age_hours": age_hours},
            )
            return str(cached["content"])
        logger.debug("No vision document found", extra={"repo": repo, "doc_type": doc_type})
        return None

    # source == "repo": try fetching from the repository.
    content = await _fetch_from_repo(repo, installation_id, github_client, doc_type=doc_type)

    if content is not None:
        try:
            await ingest_vision_document(
                repo, content, intel_db=intel_db, doc_type=doc_type,
                env=env, config=config,
            )
        except Exception:
            logger.warning(
                "Failed to cache vision document",
                exc_info=True,
                extra={"repo": repo, "doc_type": doc_type},
            )
        return content

    # Fetch returned nothing — fall back to stale cache if available.
    if cached is not None:
        age_hours = round(cache_age.total_seconds() / 3600, 1)  # type: ignore[union-attr]
        logger.info(
            "Returning stale vision document (fetch returned nothing)",
            extra={"repo": repo, "doc_type": doc_type, "age_hours": age_hours},
        )
        return str(cached["content"])

    logger.debug("No vision document found", extra={"repo": repo, "doc_type": doc_type})
    return None


async def _fetch_from_repo(
    repo: str,
    installation_id: int,
    github_client: GitHubClient,
    *,
    doc_type: str = "vision",
) -> str | None:
    """Try each candidate path in order; return the first non-empty hit."""
    candidate_paths = _DOC_TYPE_PATHS.get(doc_type, ())
    for path in candidate_paths:
        content = await github_client.get_file_contents(
            repo, path, installation_id=installation_id,
        )
        if content is not None and content.strip():
            logger.info(
                "Fetched vision document from repo",
                extra={"repo": repo, "path": path, "doc_type": doc_type},
            )
            return content

    return None
