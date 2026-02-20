"""Issue dedup gate — detect duplicate issues via embedding similarity.

Advisory only: flags probable duplicates via an issue comment but never
blocks issue processing.  In high-velocity repos the same bug or feature
request gets filed multiple times; without dedup detection redundant bounties
are allocated to identical work.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Any

import numpy as np
from openai import (
    APIConnectionError,
    APITimeoutError,
    AsyncOpenAI,
    InternalServerError,
    RateLimitError,
)

from src.github.comments import escape_cell
from src.intelligence.similarity import ndarray_to_blob
from src.intelligence.vector_index import find_similar

if TYPE_CHECKING:
    from src.config import EnvConfig, IssueDedupConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.intelligence.vector_index import VectorIndex

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_TEXT_CHARS = 12_000
_MIN_PREPROCESSED_LEN = 20
_MIN_TITLE_LEN = 10
_MAX_EMBED_RETRIES = 2
_EMBED_BACKOFF_BASE = 1.0  # seconds; doubles each attempt (1s, 2s)
_EMBED_TIMEOUT = 30  # seconds

_RETRYABLE_EMBED_ERRORS = (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)

_COMMENT_MARKER = "<!-- saltax-issue-dedup:"

# Regex patterns for template/boilerplate stripping
_TEMPLATE_HEADER_RE = re.compile(r"^###?\s+.+$", re.MULTILINE)
_CHECKBOX_RE = re.compile(r"^\s*-\s*\[[ xX]\]\s*", re.MULTILINE)
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]+\)")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


# ── Text preprocessing ───────────────────────────────────────────────────────


def preprocess_issue_text(title: str, body: str | None) -> str:
    """Combine and clean issue title + body for embedding.

    Strips template headers, checkboxes, markdown links (keeping link text),
    HTML tags, and collapses whitespace.  Returns a single cleaned string.
    """
    parts = [title.strip()]
    if body and body.strip():
        cleaned = body
        cleaned = _TEMPLATE_HEADER_RE.sub("", cleaned)
        cleaned = _CHECKBOX_RE.sub("", cleaned)
        cleaned = _MARKDOWN_LINK_RE.sub(r"\1", cleaned)
        cleaned = _HTML_TAG_RE.sub("", cleaned)
        cleaned = _WHITESPACE_RE.sub(" ", cleaned).strip()
        if cleaned:
            parts.append(cleaned)

    return " ".join(parts).strip()


# ── Embedding API ─────────────────────────────────────────────────────────────


async def embed_issue(
    title: str,
    body: str | None,
    env: EnvConfig,
    config: IssueDedupConfig,
) -> np.ndarray:
    """Obtain an embedding vector for an issue via the EigenAI API.

    Preprocesses title + body, applies the F1 short-text guard,
    truncates to ``_MAX_TEXT_CHARS``, and retries transient errors.
    Always closes the API client via try/finally.

    Raises
    ------
    ValueError
        If the text is too short for meaningful embedding after preprocessing.
    """
    text = preprocess_issue_text(title, body)

    # F1: short-text guard
    if len(text.strip()) < _MIN_PREPROCESSED_LEN:
        text = title.strip()
        if len(text) < _MIN_TITLE_LEN:
            raise ValueError("Issue text too short for embedding")

    truncated = text[:_MAX_TEXT_CHARS]

    client = AsyncOpenAI(
        base_url=env.eigenai_api_url,
        api_key=env.eigenai_api_key,
        default_headers={"x-api-key": env.eigenai_api_key},
    )
    try:
        for attempt in range(_MAX_EMBED_RETRIES + 1):
            try:
                async with asyncio.timeout(_EMBED_TIMEOUT):
                    response = await client.embeddings.create(
                        model=config.embedding_model,
                        input=truncated,
                    )
                vector = response.data[0].embedding
                return np.array(vector, dtype=np.float32)
            except (*_RETRYABLE_EMBED_ERRORS, TimeoutError) as exc:
                if attempt == _MAX_EMBED_RETRIES:
                    raise
                delay = _EMBED_BACKOFF_BASE * (2 ** attempt)
                logger.warning(
                    "Issue embedding API call failed (attempt %d/%d): %s "
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


async def run_issue_dedup_check(
    issue_data: dict[str, Any],
    config: SaltaXConfig,
    env: EnvConfig,
    intel_db: IntelligenceDB,
    vector_index: VectorIndex | None = None,
) -> list[dict[str, Any]]:
    """Run the full dedup check for an issue.

    Returns a list of duplicate candidates sorted by descending similarity,
    or ``[]`` on any failure or when dedup/triage is disabled.

    Flow:
    1. Gate: triage enabled, issue_dedup enabled, not already "duplicate" labeled
    2. Embed the issue text
    3. Store the embedding (best-effort)
    4. Fetch recent embeddings and compare
    5. Filter by threshold, sort descending
    """
    # 1. Gates
    if not config.triage.enabled:
        return []
    if not config.triage.issue_dedup.enabled:
        return []

    dedup_config = config.triage.issue_dedup
    labels = issue_data.get("labels", [])
    if "duplicate" in labels or dedup_config.label_name in labels:
        return []

    repo: str = issue_data.get("repo", issue_data.get("repo_full_name", ""))
    issue_number: int = issue_data.get("issue_number", 0)
    title: str = issue_data.get("title", "")
    body: str | None = issue_data.get("body")

    # 2. Embed
    try:
        query_vec = await embed_issue(title, body, env, dedup_config)
    except Exception:
        logger.warning(
            "Issue embedding failed, skipping dedup",
            exc_info=True,
            extra={"repo": repo, "issue_number": issue_number},
        )
        return []

    # 3. Store embedding (best-effort)
    embedding_blob = ndarray_to_blob(query_vec)
    issue_id = f"{repo}:{issue_number}"
    try:
        await intel_db.store_issue_embedding(
            issue_id=issue_id,
            repo=repo,
            issue_number=issue_number,
            title=title,
            embedding=embedding_blob,
            labels=labels if labels else None,
        )
    except Exception:
        logger.warning(
            "Failed to store issue embedding, continuing dedup comparison",
            exc_info=True,
            extra={"repo": repo, "issue_number": issue_number},
        )

    # Dual-write: keep HNSW index warm
    if vector_index is not None:
        try:
            vector_index.add(issue_id, query_vec)
        except (ValueError, MemoryError):
            logger.debug("Failed to add embedding to vector index", exc_info=True)

    # 4. Find similar embeddings (HNSW if available, brute-force fallback)
    threshold = dedup_config.similarity_threshold
    try:
        raw_matches = await find_similar(
            query_vec,
            entity_type="issue",
            repo=repo,
            exclude_id=issue_id,
            threshold=threshold,
            limit=dedup_config.max_candidates,
            intel_db=intel_db,
            vector_index=vector_index,
            exclude_number=issue_number,
            max_scan=dedup_config.max_candidates,
        )
    except Exception:
        logger.warning(
            "Failed to find similar issue embeddings",
            exc_info=True,
            extra={"repo": repo, "issue_number": issue_number},
        )
        return []

    # 5. Enrich matches with issue metadata and filter by status
    candidates: list[dict[str, Any]] = []
    for match in raw_matches:
        issue_num = int(match["id"].rsplit(":", 1)[1])
        row = await intel_db.get_issue_embedding(repo, issue_num)
        if row and row.get("status") == "open":
            candidates.append({
                "issue_number": issue_num,
                "title": row["title"],
                "similarity": match["similarity"],
                "status": row["status"],
            })
    return candidates


# ── Comment formatting ────────────────────────────────────────────────────────


def format_issue_dedup_comment(
    duplicates: list[dict[str, Any]],
    *,
    repo: str,
    issue_number: int,
) -> str:
    """Build a markdown comment body listing duplicate issue candidates.

    Includes an invisible HTML marker for comment deduplication.
    """
    lines = [
        f"{_COMMENT_MARKER}{repo}:{issue_number} -->",
        "## Duplicate Issue Detection",
        "",
        "This issue has high similarity to existing open issues:",
        "",
        "| Issue | Title | Similarity |",
        "|---|---|---|",
    ]
    for dup in duplicates:
        sim_pct = f"{dup['similarity'] * 100:.1f}%"
        lines.append(f"| #{dup['issue_number']} | {escape_cell(dup['title'])} | {sim_pct} |")

    lines.append("")
    lines.append(
        "> This is an advisory notice. "
        "Please check if this issue duplicates an existing one."
    )
    return "\n".join(lines)


def _extract_duplicate_issue_numbers(comment_body: str) -> set[int]:
    """Extract issue numbers from a dedup comment body."""
    numbers: set[int] = set()
    for match in re.finditer(r"\| #(\d+) \|", comment_body):
        numbers.add(int(match.group(1)))
    return numbers


# ── Comment posting ───────────────────────────────────────────────────────────


async def post_issue_dedup_comment(
    issue_data: dict[str, Any],
    duplicates: list[dict[str, Any]],
    github_client: GitHubClient,
    config: SaltaXConfig | None = None,
) -> None:
    """Post or update a dedup advisory comment on the issue.

    Validates required state keys before attempting the API call.
    Uses HTML marker to detect existing comments (F3 guard).
    Swallows all exceptions — dedup is advisory only.
    """
    if not duplicates:
        return

    repo = issue_data.get("repo", issue_data.get("repo_full_name"))
    issue_number = issue_data.get("issue_number")
    installation_id = issue_data.get("installation_id")
    if not repo or issue_number is None or not installation_id:
        logger.warning(
            "post_issue_dedup_comment: incomplete state, skipping",
            extra={"issue_number": issue_data.get("issue_number")},
        )
        return

    marker = f"{_COMMENT_MARKER}{repo}:{issue_number} -->"
    new_issue_numbers = {d["issue_number"] for d in duplicates}

    try:
        body = format_issue_dedup_comment(
            duplicates, repo=repo, issue_number=issue_number,
        )

        # F3: Check for existing marker comment
        comments = await github_client.list_issue_comments(
            repo=repo,
            issue_number=issue_number,
            installation_id=installation_id,
        )
        existing_comment_id = None
        existing_issue_numbers: set[int] = set()
        for comment in comments:
            comment_body = comment.get("body", "")
            if marker in comment_body:
                existing_comment_id = comment["id"]
                existing_issue_numbers = _extract_duplicate_issue_numbers(
                    comment_body,
                )
                break

        if existing_comment_id is not None:
            # Skip if duplicate sets are identical
            if existing_issue_numbers == new_issue_numbers:
                return
            # Update existing comment
            await github_client.update_comment(
                repo=repo,
                comment_id=existing_comment_id,
                installation_id=installation_id,
                body=body,
            )
        else:
            # Create new comment
            await github_client.create_comment(
                repo=repo,
                pr_number=issue_number,
                installation_id=installation_id,
                body=body,
            )

        # Optional labeling
        if config is not None and config.triage.issue_dedup.apply_label:
            label_name = config.triage.issue_dedup.label_name
            try:
                await github_client.ensure_label(
                    repo=repo,
                    installation_id=installation_id,
                    label=label_name,
                    color="d93f0b",
                    description="Potential duplicate issue detected by SaltaX",
                )
                await github_client.add_label(
                    repo=repo,
                    issue_number=issue_number,
                    installation_id=installation_id,
                    label=label_name,
                )
            except Exception:
                logger.warning(
                    "Failed to apply duplicate label, continuing",
                    exc_info=True,
                    extra={"issue_number": issue_number},
                )

    except Exception:
        logger.warning(
            "Failed to post issue dedup comment, continuing",
            exc_info=True,
            extra={"issue_number": issue_data.get("issue_number")},
        )


# ── Edit handler ──────────────────────────────────────────────────────────────


async def handle_issue_edited(
    issue_data: dict[str, Any],
    config: SaltaXConfig,
    env: EnvConfig,
    intel_db: IntelligenceDB,
    github_client: GitHubClient,
    vector_index: VectorIndex | None = None,
) -> None:
    """Handle ``issues.edited`` — re-embed if body changed, update comment.

    The ``body_changed`` flag must be True; otherwise the edit was title-only
    or label-only and re-embedding is unnecessary.
    """
    if not issue_data.get("body_changed", False):
        return

    duplicates = await run_issue_dedup_check(
        issue_data, config, env, intel_db, vector_index,
    )
    if duplicates:
        await post_issue_dedup_comment(
            issue_data, duplicates, github_client, config,
        )
