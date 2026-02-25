"""Triage dedup gate — detect duplicate/overlapping PRs via embedding similarity.

Advisory only: flags duplicates via a PR comment but never blocks the pipeline.
In bounty-driven repos multiple contributors often submit identical solutions;
without dedup detection each burns full pipeline resources.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from typing import TYPE_CHECKING, Any

import numpy as np

from src.intelligence.similarity import ndarray_to_blob
from src.intelligence.vector_index import find_similar

if TYPE_CHECKING:
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.intelligence.vector_index import VectorIndex

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_DIFF_CHARS = 12_000

# fastembed model — bge-small-en-v1.5 (int8 quantized ONNX, ~33 MB)
_FASTEMBED_MODEL = "BAAI/bge-small-en-v1.5"
_FASTEMBED_MODEL_TAG = "bge-small-en-v1.5"  # stored alongside embeddings
_FASTEMBED_CACHE_DIR = "/app/model_cache"


# ── Metrics helper ────────────────────────────────────────────────────────────


def _emit_metric(name: str, value: object, **tags: object) -> None:
    """Emit a structured metric via the JSON logger."""
    logger.info(
        "metric",
        extra={"metric_name": name, "metric_value": value, **tags},
    )


# ── Embedding: fastembed (primary) + feature-hash (fallback) ─────────────────

_HASH_EMBED_DIM = 256
_CODE_TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{1,}")
_HASH_EMBED_MODEL = "local-feature-hash-256"

# Module-level singleton — loaded once on first call, reused thereafter.
_fastembed_model: Any = None
_fastembed_available: bool | None = None  # None = not yet checked


def _get_fastembed() -> Any:
    """Return the fastembed TextEmbedding singleton, or None if unavailable."""
    global _fastembed_model, _fastembed_available  # noqa: PLW0603

    if _fastembed_available is False:
        return None
    if _fastembed_model is not None:
        return _fastembed_model

    try:
        from fastembed import TextEmbedding  # noqa: PLC0415

        _fastembed_model = TextEmbedding(
            model_name=_FASTEMBED_MODEL,
            cache_dir=_FASTEMBED_CACHE_DIR,
        )
        _fastembed_available = True
        logger.info("fastembed loaded: %s", _FASTEMBED_MODEL)
        return _fastembed_model
    except Exception:
        _fastembed_available = False
        logger.warning(
            "fastembed unavailable, using feature-hash fallback",
            exc_info=True,
        )
        return None


def _fastembed_embed(text: str) -> np.ndarray:
    """Embed via fastembed (bge-small-en-v1.5).  Raises if model unavailable."""
    model = _get_fastembed()
    if model is None:
        raise RuntimeError("fastembed not available")
    # embed() is a generator; take first result
    vec = next(model.embed([text]))
    return np.asarray(vec, dtype=np.float32)


def _hash_embed(text: str) -> np.ndarray:
    """Feature-hashing fallback — zero external dependencies.

    Uses the hashing trick (Weinberger et al. 2009): each token is hashed
    to a bucket in a fixed-size vector, with a sign hash to reduce collision
    bias.  The result is L2-normalised to unit length so cosine similarity
    works correctly.
    """
    vec = np.zeros(_HASH_EMBED_DIM, dtype=np.float64)
    tokens = _CODE_TOKEN_RE.findall(text.lower())
    bigrams = [f"{tokens[i]}_{tokens[i + 1]}" for i in range(len(tokens) - 1)]

    for feature in tokens + bigrams:
        h = hashlib.sha256(feature.encode()).digest()
        bucket = int.from_bytes(h[:4], "little") % _HASH_EMBED_DIM
        sign = 1.0 if h[4] & 1 else -1.0
        vec[bucket] += sign

    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec.astype(np.float32)


async def embed_diff(
    diff: str,
    *,
    env: EnvConfig,
    config: SaltaXConfig,
) -> tuple[np.ndarray, str]:
    """Obtain an embedding vector for a PR diff.

    Strategy (in priority order):
    1. **fastembed** (``BAAI/bge-small-en-v1.5``) — semantic embeddings,
       384-dim, runs locally via ONNX, no API calls.
    2. **feature-hash** — lexical-only fallback if fastembed is not installed.

    Returns ``(vector, model_name)`` so callers can store which method
    produced the embedding.  Embeddings from different methods are NOT
    comparable — ``find_similar`` must filter by model.
    """
    if not diff or not diff.strip():
        raise ValueError("Cannot embed an empty diff")

    truncated = diff[:_MAX_DIFF_CHARS]

    # Run fastembed in a thread to avoid blocking the event loop
    # (ONNX inference is CPU-bound, ~50ms per embed)
    loop = asyncio.get_running_loop()
    try:
        vec = await loop.run_in_executor(None, _fastembed_embed, truncated)
        return vec, _FASTEMBED_MODEL_TAG
    except Exception:
        logger.info("fastembed unavailable, using feature-hash fallback")

    vec = _hash_embed(truncated)
    return vec, _HASH_EMBED_MODEL


# ── Core dedup logic ──────────────────────────────────────────────────────────


async def run_dedup_check(
    state: dict[str, Any],
    config: SaltaXConfig,
    env: EnvConfig,
    intel_db: IntelligenceDB,
    vector_index: VectorIndex | None = None,
) -> list[dict[str, Any]]:
    """Run the full dedup check for a PR.

    Returns a list of duplicate candidates sorted by descending similarity,
    or ``[]`` on any failure or when dedup/triage is disabled.

    Flow:
    1. Check ``config.triage.enabled`` and ``config.triage.dedup.enabled``
    2. Check non-empty diff
    3. Embed the diff (with retry + timeout)
    4. Store the embedding (best-effort)
    5. Fetch recent embeddings for comparison (model-filtered)
    6. Compare and filter by threshold
    """
    t0 = time.monotonic()
    embed_failed = 0

    # 1. Gate: triage and dedup must both be enabled
    if not config.triage.enabled:
        return []
    if not config.triage.dedup.enabled:
        return []

    diff: str = state.get("diff", "")
    repo: str = state.get("repo", "")
    pr_number: int = state.get("pr_number", 0)
    pr_id: str = state.get("pr_id", "")
    commit_sha: str = state.get("commit_sha", "")
    issue_number: int | None = state.get("target_issue_number")

    # 2. Gate: non-empty diff
    if not diff or not diff.strip():
        return []

    # 3. Embed the diff
    try:
        query_vec, embed_model = await embed_diff(diff, env=env, config=config)
    except Exception:
        embed_failed = 1
        logger.exception(
            "Dedup embedding failed, skipping dedup",
            extra={"pr_id": pr_id},
        )
        _emit_metric("dedup.embed_api_failed", 1, pr_id=pr_id)
        return []

    # 4. Store embedding (best-effort — comparison can still proceed)
    embedding_blob = ndarray_to_blob(query_vec)
    try:
        await intel_db.store_embedding(
            pr_id=pr_id,
            repo=repo,
            pr_number=pr_number,
            commit_sha=commit_sha,
            embedding_blob=embedding_blob,
            embedding_model=embed_model,
            issue_number=issue_number,
        )
    except Exception:
        logger.warning(
            "Failed to store PR embedding, continuing dedup comparison",
            exc_info=True,
            extra={"pr_id": pr_id},
        )

    # Dual-write: keep HNSW index warm
    if vector_index is not None:
        try:
            vector_index.add(pr_id, query_vec)
        except (ValueError, MemoryError):
            logger.debug("Failed to add embedding to vector index", exc_info=True)

    # 5. Find similar embeddings (HNSW if available, brute-force fallback)
    # Filter by embedding_model so we only compare vectors from the same
    # method — API embeddings and local feature-hash vectors are incomparable.
    threshold = config.triage.dedup.similarity_threshold
    try:
        raw_matches = await find_similar(
            query_vec,
            entity_type="pr",
            repo=repo,
            exclude_id=pr_id,
            threshold=threshold,
            limit=20,
            intel_db=intel_db,
            vector_index=vector_index,
            exclude_number=pr_number,
            embedding_model=embed_model,
            max_scan=config.triage.dedup.max_scan_embeddings,
        )
    except Exception:
        logger.exception(
            "Failed to find similar embeddings",
            extra={"pr_id": pr_id},
        )
        return []

    # 6. Enrich matches with PR metadata
    candidates: list[dict[str, Any]] = []
    for match in raw_matches:
        row = await intel_db.get_pr_embedding_by_pr_id(match["id"])
        if row:
            candidates.append({
                "pr_id": match["id"],
                "pr_number": row["pr_number"],
                "commit_sha": row["commit_sha"],
                "similarity": match["similarity"],
            })

    # 7. Emit metrics
    elapsed = time.monotonic() - t0
    _emit_metric("dedup.duration_seconds", round(elapsed, 3), pr_id=pr_id)
    _emit_metric("dedup.candidates_found", len(candidates), pr_id=pr_id, repo=repo)
    _emit_metric("dedup.embed_api_failed", embed_failed, pr_id=pr_id)

    return candidates


# ── Comment formatting ────────────────────────────────────────────────────────


def format_dedup_comment(duplicates: list[dict[str, Any]]) -> str:
    """Build a markdown comment body listing duplicate candidates."""
    lines = [
        "## Duplicate PR Detection",
        "",
        "This PR has high similarity to existing submissions:",
        "",
        "| PR | Similarity | Commit |",
        "|---|---|---|",
    ]
    for dup in duplicates:
        sim_pct = f"{dup['similarity'] * 100:.1f}%"
        short_sha = str(dup["commit_sha"])[:7]
        lines.append(f"| {dup['pr_id']} | {sim_pct} | `{short_sha}` |")

    lines.append("")
    lines.append(
        "> This is an advisory notice. The pipeline will continue normally."
    )
    return "\n".join(lines)


async def post_dedup_comment(
    state: dict[str, Any],
    duplicates: list[dict[str, Any]],
    github_client: GitHubClient,
) -> None:
    """Post a dedup advisory comment on the PR.

    Validates required state keys before attempting the API call.
    Swallows all exceptions — dedup is advisory only and must never
    block the pipeline.
    """
    if not duplicates:
        return

    repo = state.get("repo")
    pr_number = state.get("pr_number")
    installation_id = state.get("installation_id")
    if not repo or pr_number is None or not installation_id:
        logger.warning(
            "post_dedup_comment: incomplete state, skipping",
            extra={"pr_id": state.get("pr_id")},
        )
        return

    try:
        body = format_dedup_comment(duplicates)
        await github_client.create_comment(
            repo=repo,
            pr_number=pr_number,
            installation_id=installation_id,
            body=body,
        )
    except Exception:
        logger.warning(
            "Failed to post dedup comment, continuing",
            exc_info=True,
            extra={"pr_id": state.get("pr_id")},
        )
