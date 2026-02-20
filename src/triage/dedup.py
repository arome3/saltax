"""Triage dedup gate — detect duplicate/overlapping PRs via embedding similarity.

Advisory only: flags duplicates via a PR comment but never blocks the pipeline.
In bounty-driven repos multiple contributors often submit identical solutions;
without dedup detection each burns full pipeline resources.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

import numpy as np
from openai import (
    APIConnectionError,
    APITimeoutError,
    AsyncOpenAI,
    InternalServerError,
    RateLimitError,
)

from src.intelligence.similarity import (
    blob_to_ndarray,
    cosine_similarity_vectors,
    ndarray_to_blob,
)

if TYPE_CHECKING:
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_DIFF_CHARS = 12_000
_MAX_EMBED_RETRIES = 2
_EMBED_BACKOFF_BASE = 1.0  # seconds; doubles each attempt (1s, 2s)

_RETRYABLE_EMBED_ERRORS = (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)


# ── Metrics helper ────────────────────────────────────────────────────────────


def _emit_metric(name: str, value: object, **tags: object) -> None:
    """Emit a structured metric via the JSON logger."""
    logger.info(
        "metric",
        extra={"metric_name": name, "metric_value": value, **tags},
    )


# ── Embedding API ─────────────────────────────────────────────────────────────


async def embed_diff(
    diff: str,
    *,
    env: EnvConfig,
    config: SaltaXConfig,
) -> np.ndarray:
    """Obtain an embedding vector for a PR diff via the EigenAI API.

    Truncates the diff to ``_MAX_DIFF_CHARS`` to stay within token limits.
    Retries up to ``_MAX_EMBED_RETRIES`` times on transient errors within
    the configured timeout budget.  Always closes the API client.
    """
    if not diff or not diff.strip():
        raise ValueError("Cannot embed an empty diff")

    truncated = diff[:_MAX_DIFF_CHARS]

    client = AsyncOpenAI(
        base_url=env.eigenai_api_url,
        api_key=env.eigenai_api_key,
        default_headers={"x-api-key": env.eigenai_api_key},
    )
    try:
        async with asyncio.timeout(config.triage.dedup.embedding_api_timeout_seconds):
            for attempt in range(_MAX_EMBED_RETRIES + 1):
                try:
                    response = await client.embeddings.create(
                        model=config.triage.dedup.embedding_model,
                        input=truncated,
                    )
                    vector = response.data[0].embedding
                    return np.array(vector, dtype=np.float32)
                except _RETRYABLE_EMBED_ERRORS as exc:
                    if attempt == _MAX_EMBED_RETRIES:
                        raise
                    delay = _EMBED_BACKOFF_BASE * (2 ** attempt)
                    logger.warning(
                        "Embedding API call failed (attempt %d/%d): %s "
                        "— retrying in %.1fs",
                        attempt + 1,
                        _MAX_EMBED_RETRIES + 1,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
        # Unreachable — loop either returns or raises on final attempt
        msg = "Embed retry loop exited unexpectedly"
        raise RuntimeError(msg)  # pragma: no cover
    finally:
        await client.close()


# ── Core dedup logic ──────────────────────────────────────────────────────────


async def run_dedup_check(
    state: dict[str, Any],
    config: SaltaXConfig,
    env: EnvConfig,
    intel_db: IntelligenceDB,
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
    mismatch_count = 0

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
        query_vec = await embed_diff(diff, env=env, config=config)
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
            embedding_model=config.triage.dedup.embedding_model,
            issue_number=issue_number,
        )
    except Exception:
        logger.warning(
            "Failed to store PR embedding, continuing dedup comparison",
            exc_info=True,
            extra={"pr_id": pr_id},
        )

    # 5. Fetch recent embeddings (excluding the current PR, model-filtered)
    try:
        recent = await intel_db.get_recent_embeddings(
            repo=repo,
            exclude_pr_number=pr_number,
            limit=config.triage.dedup.max_scan_embeddings,
            embedding_model=config.triage.dedup.embedding_model,
        )
    except Exception:
        logger.exception(
            "Failed to fetch recent embeddings",
            extra={"pr_id": pr_id},
        )
        return []

    # 6. Compare and filter
    threshold = config.triage.dedup.similarity_threshold
    candidates: list[dict[str, Any]] = []

    for row in recent:
        try:
            stored_vec = blob_to_ndarray(row["embedding"])
            sim = cosine_similarity_vectors(query_vec, stored_vec)
        except ValueError:
            mismatch_count += 1
            logger.debug(
                "Skipping embedding comparison due to dimension mismatch",
                extra={
                    "pr_id": pr_id,
                    "other_pr": row.get("pr_id"),
                },
            )
            continue

        if sim >= threshold:
            candidates.append({
                "pr_id": row["pr_id"],
                "pr_number": row["pr_number"],
                "commit_sha": row["commit_sha"],
                "similarity": round(sim, 4),
            })

    candidates.sort(key=lambda c: c["similarity"], reverse=True)

    # 7. Emit metrics
    elapsed = time.monotonic() - t0
    _emit_metric("dedup.duration_seconds", round(elapsed, 3), pr_id=pr_id)
    _emit_metric("dedup.candidates_found", len(candidates), pr_id=pr_id, repo=repo)
    _emit_metric("dedup.embeddings_compared", len(recent), pr_id=pr_id)
    _emit_metric("dedup.embed_api_failed", embed_failed, pr_id=pr_id)
    _emit_metric("dedup.dimension_mismatches", mismatch_count, pr_id=pr_id)

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
