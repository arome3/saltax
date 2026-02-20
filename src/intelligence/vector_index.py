"""Ephemeral HNSW vector index for O(log n) similarity search.

Wraps ``usearch`` as an optional acceleration layer over the durable SQLite
embedding store.  When usearch is not installed or the index is not enabled,
all queries fall back to brute-force cosine similarity scanning.

The index is **ephemeral** — rebuilt from SQLite on every startup.  This
avoids persistence/corruption complexity while still accelerating hot-path
dedup queries.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import numpy as np  # noqa: TC002 — used at runtime for vector operations

from src.intelligence.similarity import blob_to_ndarray, cosine_similarity_vectors

if TYPE_CHECKING:
    from src.config import SaltaXConfig, VectorIndexConfig
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

# ── VectorIndex ─────────────────────────────────────────────────────────────


class VectorIndex:
    """In-memory HNSW index backed by usearch.

    External IDs are strings (e.g. ``"owner/repo#42"`` for PRs,
    ``"owner/repo:42"`` for issues).  Internally mapped to integer keys.
    """

    def __init__(
        self,
        *,
        dimension: int = 1536,
        m: int = 16,
        ef_construction: int = 200,
        ef_search: int = 50,
        max_elements: int = 100_000,
    ) -> None:
        self._dimension = dimension
        self._m = m
        self._ef_construction = ef_construction
        self._ef_search = ef_search
        self._max_elements = max_elements

        self._index: Any = None  # usearch.index.Index — typed as Any to avoid import
        self._id_map: dict[str, int] = {}  # external_id → internal_key
        self._reverse_map: dict[int, str] = {}  # internal_key → external_id
        self._next_key: int = 0
        self._initialized = False

    @property
    def count(self) -> int:
        """Number of vectors currently in the index."""
        return len(self._id_map)

    async def initialize(
        self,
        intel_db: IntelligenceDB,
        entity_type: str,
    ) -> None:
        """Build the HNSW index from the durable SQLite store.

        Parameters
        ----------
        intel_db:
            The intelligence database to read embeddings from.
        entity_type:
            ``"pr"`` or ``"issue"`` — determines which table to read.

        Raises
        ------
        ImportError
            If ``usearch`` is not installed.
        """
        from usearch.index import Index  # noqa: PLC0415

        table = "pr_embeddings" if entity_type == "pr" else "issue_embeddings"

        self._index = Index(
            ndim=self._dimension,
            metric="cos",
            dtype="f32",
            connectivity=self._m,
            expansion_add=self._ef_construction,
            expansion_search=self._ef_search,
        )
        self._index.reserve(self._max_elements)
        self._id_map.clear()
        self._reverse_map.clear()
        self._next_key = 0

        rows = await intel_db.get_all_embeddings(table=table)

        # For large datasets, batch-add in an executor to avoid blocking
        vectors_to_add: list[tuple[str, np.ndarray]] = []
        skipped = 0
        for row in rows:
            try:
                vec = blob_to_ndarray(row["embedding"])
            except Exception:
                skipped += 1
                continue
            if vec.shape[0] != self._dimension:
                skipped += 1
                continue
            vectors_to_add.append((str(row["id"]), vec))

        if len(vectors_to_add) > 10_000:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._batch_add, vectors_to_add)
        else:
            self._batch_add(vectors_to_add)

        mem_bytes = len(self._id_map) * (self._dimension * 4 + self._m * 2 * 4)
        self._initialized = True
        logger.info(
            "VectorIndex initialized: %d vectors loaded, %d skipped, "
            "~%.1f MB estimated memory",
            len(self._id_map),
            skipped,
            mem_bytes / (1024 * 1024),
        )

    def _batch_add(self, vectors: list[tuple[str, np.ndarray]]) -> None:
        """Add a batch of vectors to the index (CPU-bound, may run in executor)."""
        for external_id, vec in vectors:
            # Later entries overwrite earlier ones for the same external_id
            if external_id in self._id_map:
                old_key = self._id_map[external_id]
                self._index.remove(old_key)
                del self._reverse_map[old_key]

            key = self._next_key
            self._next_key += 1
            self._index.add(key, vec)
            self._id_map[external_id] = key
            self._reverse_map[key] = external_id

    def add(self, external_id: str, vector: np.ndarray) -> None:
        """Add or replace a vector in the index.

        Raises
        ------
        RuntimeError
            If the index is not initialized.
        ValueError
            If the vector dimension does not match.
        """
        if not self._initialized:
            raise RuntimeError("VectorIndex not initialized")
        if vector.shape[0] != self._dimension:
            raise ValueError(
                f"Dimension mismatch: expected {self._dimension}, got {vector.shape[0]}"
            )

        # Replace existing
        if external_id in self._id_map:
            old_key = self._id_map[external_id]
            self._index.remove(old_key)
            del self._reverse_map[old_key]

        # Auto-resize if needed
        if self._next_key >= self._max_elements:
            try:
                self._max_elements *= 2
                self._index.reserve(self._max_elements)
            except MemoryError:
                logger.error(
                    "MemoryError during index resize to %d, continuing with current capacity",
                    self._max_elements,
                )
                self._max_elements //= 2
                raise

        key = self._next_key
        self._next_key += 1
        self._index.add(key, vector)
        self._id_map[external_id] = key
        self._reverse_map[key] = external_id

    def query(
        self,
        vector: np.ndarray,
        k: int = 10,
        threshold: float = 0.85,
    ) -> list[dict[str, Any]]:
        """Find the k nearest neighbors above the similarity threshold.

        Returns ``[{"id": str, "similarity": float}]`` sorted descending
        by similarity.  Cosine distance from usearch is ``1 - similarity``.

        Returns an empty list if the index is empty or not initialized.
        """
        if not self._initialized or len(self._id_map) == 0:
            return []
        if vector.shape[0] != self._dimension:
            raise ValueError(
                f"Dimension mismatch: expected {self._dimension}, got {vector.shape[0]}"
            )

        actual_k = min(k, len(self._id_map))
        matches = self._index.search(vector, count=actual_k)

        results: list[dict[str, Any]] = []
        for i in range(len(matches.keys)):
            internal_key = int(matches.keys[i])
            distance = float(matches.distances[i])
            similarity = 1.0 - distance

            if similarity < threshold:
                continue
            external_id = self._reverse_map.get(internal_key)
            if external_id is None:
                continue

            results.append({"id": external_id, "similarity": round(similarity, 4)})

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results

    def remove(self, external_id: str) -> bool:
        """Remove a vector by external ID.

        Returns ``True`` if the vector was found and removed.
        """
        key = self._id_map.pop(external_id, None)
        if key is None:
            return False
        self._index.remove(key)
        del self._reverse_map[key]
        return True


# ── VectorIndexManager ──────────────────────────────────────────────────────


class VectorIndexManager:
    """Manages PR and issue HNSW indexes with graceful fallback.

    If usearch is not installed or initialization fails, indexes remain
    ``None`` and callers fall back to brute-force similarity scanning.
    """

    def __init__(self, config: SaltaXConfig) -> None:
        self._config: VectorIndexConfig = config.vector_index
        self.pr_index: VectorIndex | None = None
        self.issue_index: VectorIndex | None = None

    async def initialize(self, intel_db: IntelligenceDB) -> None:
        """Initialize both indexes from the durable store.

        Catches ``ImportError`` (usearch not installed) and general
        exceptions gracefully — indexes remain ``None`` on failure.
        """
        if not self._config.enabled:
            logger.info("Vector index disabled by configuration")
            return

        idx_kwargs = {
            "dimension": self._config.dimension,
            "m": self._config.m,
            "ef_construction": self._config.ef_construction,
            "ef_search": self._config.ef_search,
            "max_elements": self._config.max_elements,
        }

        try:
            pr_idx = VectorIndex(**idx_kwargs)
            await pr_idx.initialize(intel_db, "pr")
            self.pr_index = pr_idx

            issue_idx = VectorIndex(**idx_kwargs)
            await issue_idx.initialize(intel_db, "issue")
            self.issue_index = issue_idx

            logger.info(
                "VectorIndexManager ready: PR=%d, issues=%d",
                self.pr_index.count,
                self.issue_index.count,
            )
        except ImportError:
            logger.warning(
                "usearch not installed — vector index disabled, "
                "using brute-force similarity scanning"
            )
            self.pr_index = None
            self.issue_index = None
        except Exception:
            logger.exception("Vector index initialization failed, falling back to brute-force")
            self.pr_index = None
            self.issue_index = None

    async def close(self) -> None:
        """Release index references."""
        self.pr_index = None
        self.issue_index = None


# ── Strategy function ───────────────────────────────────────────────────────


async def find_similar(
    embedding: np.ndarray,
    *,
    entity_type: str,
    repo: str,
    exclude_id: str,
    threshold: float,
    limit: int,
    intel_db: IntelligenceDB,
    vector_index: VectorIndex | None = None,
    # Brute-force-specific params
    exclude_number: int | None = None,
    embedding_model: str = "",
    max_scan: int = 500,
) -> list[dict[str, Any]]:
    """Find similar embeddings using HNSW index with brute-force fallback.

    Parameters
    ----------
    embedding:
        The query vector (float32 numpy array).
    entity_type:
        ``"pr"`` or ``"issue"``.
    repo:
        Repository full name (e.g. ``"owner/repo"``).
    exclude_id:
        External ID to exclude from results (the query entity itself).
    threshold:
        Minimum cosine similarity to include.
    limit:
        Maximum number of results to return.
    intel_db:
        Intelligence database for brute-force fallback.
    vector_index:
        Optional HNSW index — if ``None``, uses brute-force.
    exclude_number:
        PR number or issue number to exclude (brute-force path).
    embedding_model:
        Embedding model filter (brute-force PR path only).
    max_scan:
        Maximum embeddings to scan in brute-force path.

    Returns
    -------
    list[dict]
        ``[{"id": str, "similarity": float}]`` sorted by descending similarity.
    """
    # ── HNSW path ────────────────────────────────────────────────────
    if vector_index is not None:
        try:
            # Over-fetch to compensate for cross-repo and excluded results
            raw = vector_index.query(embedding, k=limit * 3, threshold=threshold)

            # Filter by repo prefix and exclude self
            prefix = f"{repo}#" if entity_type == "pr" else f"{repo}:"
            filtered = [
                r for r in raw
                if r["id"] != exclude_id and r["id"].startswith(prefix)
            ]
            return filtered[:limit]
        except Exception:
            logger.warning(
                "HNSW query failed, falling back to brute-force",
                exc_info=True,
            )

    # ── Brute-force fallback ─────────────────────────────────────────
    if entity_type == "pr":
        return await _brute_force_pr(
            embedding,
            repo=repo,
            exclude_number=exclude_number,
            threshold=threshold,
            limit=limit,
            intel_db=intel_db,
            embedding_model=embedding_model,
            max_scan=max_scan,
        )
    return await _brute_force_issue(
        embedding,
        repo=repo,
        exclude_number=exclude_number,
        threshold=threshold,
        limit=limit,
        intel_db=intel_db,
        max_scan=max_scan,
    )


async def _brute_force_pr(
    embedding: np.ndarray,
    *,
    repo: str,
    exclude_number: int | None,
    threshold: float,
    limit: int,
    intel_db: IntelligenceDB,
    embedding_model: str,
    max_scan: int,
) -> list[dict[str, Any]]:
    """Brute-force cosine scan for PR embeddings."""
    recent = await intel_db.get_recent_embeddings(
        repo=repo,
        exclude_pr_number=exclude_number,
        limit=max_scan,
        embedding_model=embedding_model,
    )
    results: list[dict[str, Any]] = []
    for row in recent:
        try:
            stored_vec = blob_to_ndarray(row["embedding"])
            sim = cosine_similarity_vectors(embedding, stored_vec)
        except ValueError:
            continue
        if sim >= threshold:
            results.append({"id": row["pr_id"], "similarity": round(sim, 4)})
    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results[:limit]


async def _brute_force_issue(
    embedding: np.ndarray,
    *,
    repo: str,
    exclude_number: int | None,
    threshold: float,
    limit: int,
    intel_db: IntelligenceDB,
    max_scan: int,
) -> list[dict[str, Any]]:
    """Brute-force cosine scan for issue embeddings."""
    recent = await intel_db.get_recent_issue_embeddings(
        repo,
        exclude_issue=exclude_number or 0,
        status="open",
        limit=max_scan,
    )
    results: list[dict[str, Any]] = []
    for row in recent:
        try:
            stored_vec = blob_to_ndarray(row["embedding"])
            sim = cosine_similarity_vectors(embedding, stored_vec)
        except ValueError:
            continue
        if sim >= threshold:
            results.append({
                "id": f"{repo}:{row['issue_number']}",
                "similarity": round(sim, 4),
            })
    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results[:limit]


# ── Auto-enable heuristic ───────────────────────────────────────────────────


async def maybe_enable_vector_index(
    intel_db: IntelligenceDB,
    config: SaltaXConfig,
    manager: VectorIndexManager,
) -> None:
    """Automatically enable the vector index if embedding counts exceed threshold.

    Only acts when the index is not already initialized.  Counts both PR
    and issue embeddings; if the total exceeds
    ``config.vector_index.auto_enable_threshold``, initialises the manager.
    """
    if manager.pr_index is not None or manager.issue_index is not None:
        return
    if config.vector_index.enabled:
        return  # Already tried (and possibly failed) during normal init

    try:
        pr_count = await intel_db.count_embeddings("pr_embeddings")
        issue_count = await intel_db.count_embeddings("issue_embeddings")
        total = pr_count + issue_count
    except Exception:
        logger.debug("Failed to count embeddings for auto-enable check", exc_info=True)
        return

    if total < config.vector_index.auto_enable_threshold:
        return

    logger.info(
        "Auto-enabling vector index: %d total embeddings exceed threshold %d",
        total,
        config.vector_index.auto_enable_threshold,
    )
    # Temporarily enable for initialization
    config.vector_index.enabled = True
    await manager.initialize(intel_db)
