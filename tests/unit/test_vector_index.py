"""Tests for the vector similarity index (src/intelligence/vector_index.py).

Tests use mocked usearch to avoid requiring the optional dependency in CI.
Tests that exercise real HNSW behavior use ``pytest.importorskip("usearch")``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from src.intelligence.similarity import ndarray_to_blob
from src.intelligence.vector_index import (
    VectorIndex,
    VectorIndexManager,
    find_similar,
    maybe_enable_vector_index,
)

_ = pytest  # ensure pytest is used (fixture injection)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _random_vec(dim: int = 4, seed: int | None = None) -> np.ndarray:
    """Generate a random float32 vector, optionally seeded for reproducibility."""
    rng = np.random.default_rng(seed)
    v = rng.standard_normal(dim).astype(np.float32)
    return v / np.linalg.norm(v)  # unit normalize


def _make_mock_usearch_index(ndim: int = 4) -> MagicMock:
    """Create a mock usearch Index with basic add/search/remove/reserve."""
    index = MagicMock()
    index.reserve = MagicMock()
    index.add = MagicMock()
    index.remove = MagicMock()

    # search returns a result object with keys and distances arrays
    result = MagicMock()
    result.keys = np.array([], dtype=np.int64)
    result.distances = np.array([], dtype=np.float32)
    index.search = MagicMock(return_value=result)
    return index


def _make_intel_db() -> AsyncMock:
    """Build a minimal mock IntelligenceDB."""
    db = AsyncMock()
    db.get_all_embeddings = AsyncMock(return_value=[])
    db.count_embeddings = AsyncMock(return_value=0)
    db.get_recent_embeddings = AsyncMock(return_value=[])
    db.get_recent_issue_embeddings = AsyncMock(return_value=[])
    db.get_pr_embedding_by_pr_id = AsyncMock(return_value=None)
    db.get_issue_embedding = AsyncMock(return_value=None)
    return db


def _make_config(*, enabled: bool = False, auto_threshold: int = 2000):
    """Build a mock config with vector_index settings."""
    config = MagicMock()
    config.vector_index.enabled = enabled
    config.vector_index.dimension = 4
    config.vector_index.ef_construction = 16
    config.vector_index.m = 4
    config.vector_index.ef_search = 10
    config.vector_index.max_elements = 100
    config.vector_index.auto_enable_threshold = auto_threshold
    return config


# ── Test 1: Basic add + query (real usearch if available) ─────────────────


async def test_basic_add_and_query():
    """Add vectors and verify the nearest neighbor is returned."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=100)
    intel_db = _make_intel_db()
    intel_db.get_all_embeddings.return_value = []
    await idx.initialize(intel_db, "pr")

    # Add 5 vectors with distinct directions
    vecs = {}
    for i in range(5):
        v = _random_vec(4, seed=i)
        eid = f"owner/repo#{i}"
        idx.add(eid, v)
        vecs[eid] = v

    assert idx.count == 5

    # Query with a vector very close to seed=0
    query = vecs["owner/repo#0"] + _random_vec(4, seed=99) * 0.01
    query = query / np.linalg.norm(query)
    results = idx.query(query.astype(np.float32), k=3, threshold=0.5)

    assert len(results) > 0
    assert results[0]["id"] == "owner/repo#0"
    assert results[0]["similarity"] > 0.9


# ── Test 2: Threshold filtering ──────────────────────────────────────────


async def test_threshold_filtering():
    """Neighbor below threshold is excluded from results."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=100)
    intel_db = _make_intel_db()
    await idx.initialize(intel_db, "pr")

    # Add an orthogonal-ish vector
    v1 = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    v2 = np.array([0.0, 1.0, 0.0, 0.0], dtype=np.float32)
    idx.add("owner/repo#1", v1)
    idx.add("owner/repo#2", v2)

    # Query for v1 with high threshold — v2 should be excluded
    results = idx.query(v1, k=5, threshold=0.95)
    ids = {r["id"] for r in results}
    assert "owner/repo#1" in ids
    assert "owner/repo#2" not in ids


# ── Test 3: Dimension mismatch on add ────────────────────────────────────


async def test_dimension_mismatch_on_add():
    """Wrong dimension raises ValueError."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=100)
    intel_db = _make_intel_db()
    await idx.initialize(intel_db, "pr")

    wrong_dim = np.ones(8, dtype=np.float32)
    with pytest.raises(ValueError, match="Dimension mismatch"):
        idx.add("owner/repo#1", wrong_dim)


# ── Test 4: Replace existing ─────────────────────────────────────────────


async def test_replace_existing():
    """Adding same external_id replaces the old vector, count unchanged."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=100)
    intel_db = _make_intel_db()
    await idx.initialize(intel_db, "pr")

    v1 = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    v2 = np.array([0.0, 1.0, 0.0, 0.0], dtype=np.float32)
    idx.add("owner/repo#1", v1)
    assert idx.count == 1
    idx.add("owner/repo#1", v2)
    assert idx.count == 1

    # Query for v2 — should match the replaced vector
    results = idx.query(v2, k=1, threshold=0.9)
    assert len(results) == 1
    assert results[0]["id"] == "owner/repo#1"


# ── Test 5: Remove ───────────────────────────────────────────────────────


async def test_remove():
    """Add + remove → query returns empty, count decremented."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=100)
    intel_db = _make_intel_db()
    await idx.initialize(intel_db, "pr")

    v = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    idx.add("owner/repo#1", v)
    assert idx.count == 1

    removed = idx.remove("owner/repo#1")
    assert removed is True
    assert idx.count == 0

    # Remove non-existent
    assert idx.remove("nonexistent") is False


# ── Test 6: Empty index query ────────────────────────────────────────────


async def test_empty_index_query():
    """Query on empty index returns empty list, no crash."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=100)
    intel_db = _make_intel_db()
    await idx.initialize(intel_db, "pr")

    results = idx.query(_random_vec(4), k=10, threshold=0.5)
    assert results == []


# ── Test 7: Auto-resize ─────────────────────────────────────────────────


async def test_auto_resize():
    """Adding beyond max_elements triggers resize, all remain queryable."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    small_max = 5
    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=small_max)
    intel_db = _make_intel_db()
    await idx.initialize(intel_db, "pr")

    # Add more than max_elements
    for i in range(small_max + 3):
        v = _random_vec(4, seed=i)
        idx.add(f"owner/repo#{i}", v)

    assert idx.count == small_max + 3

    # All vectors should be queryable
    for i in range(small_max + 3):
        v = _random_vec(4, seed=i)
        results = idx.query(v, k=1, threshold=0.9)
        assert len(results) >= 1, f"Vector {i} not found"


# ── Test 8: find_similar strategy function ───────────────────────────────


async def test_find_similar_with_hnsw():
    """find_similar uses HNSW index when provided."""
    mock_index = MagicMock()
    mock_index.query.return_value = [
        {"id": "owner/repo#10", "similarity": 0.95},
        {"id": "owner/repo#20", "similarity": 0.88},
        {"id": "other/repo#30", "similarity": 0.92},  # different repo
    ]
    intel_db = _make_intel_db()

    results = await find_similar(
        _random_vec(4),
        entity_type="pr",
        repo="owner/repo",
        exclude_id="owner/repo#5",
        threshold=0.85,
        limit=10,
        intel_db=intel_db,
        vector_index=mock_index,
    )

    mock_index.query.assert_called_once()
    # Should filter out other/repo#30 (wrong repo)
    assert len(results) == 2
    assert results[0]["id"] == "owner/repo#10"
    assert results[1]["id"] == "owner/repo#20"


async def test_find_similar_brute_force_pr():
    """find_similar uses brute-force when no index provided."""
    intel_db = _make_intel_db()
    query = _random_vec(4, seed=0)
    similar = query + _random_vec(4, seed=99) * 0.01
    similar = (similar / np.linalg.norm(similar)).astype(np.float32)

    intel_db.get_recent_embeddings.return_value = [
        {
            "pr_id": "owner/repo#10",
            "pr_number": 10,
            "commit_sha": "abc123",
            "embedding": ndarray_to_blob(similar),
        },
    ]

    results = await find_similar(
        query,
        entity_type="pr",
        repo="owner/repo",
        exclude_id="owner/repo#5",
        threshold=0.5,
        limit=10,
        intel_db=intel_db,
        vector_index=None,
        exclude_number=5,
        embedding_model="text-embedding",
        max_scan=100,
    )

    intel_db.get_recent_embeddings.assert_called_once()
    assert len(results) == 1
    assert results[0]["id"] == "owner/repo#10"
    assert results[0]["similarity"] > 0.9


async def test_find_similar_brute_force_issue():
    """find_similar brute-force path for issues."""
    intel_db = _make_intel_db()
    query = _random_vec(4, seed=0)
    similar = query + _random_vec(4, seed=99) * 0.01
    similar = (similar / np.linalg.norm(similar)).astype(np.float32)

    intel_db.get_recent_issue_embeddings.return_value = [
        {
            "issue_number": 42,
            "title": "Test issue",
            "embedding": ndarray_to_blob(similar),
            "status": "open",
        },
    ]

    results = await find_similar(
        query,
        entity_type="issue",
        repo="owner/repo",
        exclude_id="owner/repo:99",
        threshold=0.5,
        limit=10,
        intel_db=intel_db,
        vector_index=None,
        exclude_number=99,
        max_scan=100,
    )

    intel_db.get_recent_issue_embeddings.assert_called_once()
    assert len(results) == 1
    assert results[0]["id"] == "owner/repo:42"


async def test_find_similar_hnsw_fallback_on_error():
    """HNSW query failure falls through to brute-force."""
    mock_index = MagicMock()
    mock_index.query.side_effect = RuntimeError("index corrupted")

    intel_db = _make_intel_db()
    intel_db.get_recent_embeddings.return_value = []

    results = await find_similar(
        _random_vec(4),
        entity_type="pr",
        repo="owner/repo",
        exclude_id="owner/repo#5",
        threshold=0.85,
        limit=10,
        intel_db=intel_db,
        vector_index=mock_index,
        exclude_number=5,
    )

    # Should have fallen through to brute-force
    intel_db.get_recent_embeddings.assert_called_once()
    assert results == []


# ── Test 9: usearch missing — VectorIndexManager graceful fallback ───────


async def test_manager_usearch_missing():
    """VectorIndexManager falls back gracefully when usearch is not installed."""
    config = _make_config(enabled=True)
    intel_db = _make_intel_db()

    manager = VectorIndexManager(config)
    with patch(
        "src.intelligence.vector_index.VectorIndex.initialize",
        side_effect=ImportError("No module named 'usearch'"),
    ):
        await manager.initialize(intel_db)

    assert manager.pr_index is None
    assert manager.issue_index is None


async def test_manager_disabled():
    """VectorIndexManager does nothing when disabled."""
    config = _make_config(enabled=False)
    intel_db = _make_intel_db()

    manager = VectorIndexManager(config)
    await manager.initialize(intel_db)

    assert manager.pr_index is None
    assert manager.issue_index is None


# ── Test 10: maybe_enable_vector_index ───────────────────────────────────


async def test_maybe_enable_below_threshold():
    """Count below threshold — no init called."""
    config = _make_config(enabled=False, auto_threshold=2000)
    intel_db = _make_intel_db()
    intel_db.count_embeddings.side_effect = [500, 300]  # PR=500, issue=300

    manager = VectorIndexManager(config)
    with patch.object(manager, "initialize", new_callable=AsyncMock) as mock_init:
        await maybe_enable_vector_index(intel_db, config, manager)
        mock_init.assert_not_called()


async def test_maybe_enable_above_threshold():
    """Count above threshold — init is called."""
    config = _make_config(enabled=False, auto_threshold=1000)
    intel_db = _make_intel_db()
    intel_db.count_embeddings.side_effect = [800, 500]  # PR=800, issue=500, total=1300

    manager = VectorIndexManager(config)
    with patch.object(manager, "initialize", new_callable=AsyncMock) as mock_init:
        await maybe_enable_vector_index(intel_db, config, manager)
        mock_init.assert_called_once_with(intel_db)


async def test_maybe_enable_skips_when_already_initialized():
    """If indexes are already initialized, maybe_enable does nothing."""
    config = _make_config(enabled=False)
    intel_db = _make_intel_db()

    manager = VectorIndexManager(config)
    manager.pr_index = MagicMock()  # Pretend already initialized

    with patch.object(manager, "initialize", new_callable=AsyncMock) as mock_init:
        await maybe_enable_vector_index(intel_db, config, manager)
        mock_init.assert_not_called()


# ── Test: VectorIndex not initialized guard ──────────────────────────────


async def test_add_before_initialize_raises():
    """add() on uninitialized index raises RuntimeError."""
    idx = VectorIndex(dimension=4)
    with pytest.raises(RuntimeError, match="not initialized"):
        idx.add("test", _random_vec(4))


# ── Test: Initialize from DB with dimension mismatches ───────────────────


async def test_initialize_skips_dimension_mismatch():
    """Vectors with wrong dimension are skipped during init."""
    usearch = pytest.importorskip("usearch")  # noqa: F841

    intel_db = _make_intel_db()
    good_vec = _random_vec(4, seed=0)
    bad_vec = _random_vec(8, seed=1)  # wrong dimension

    intel_db.get_all_embeddings.return_value = [
        {"id": "owner/repo#1", "embedding": ndarray_to_blob(good_vec)},
        {"id": "owner/repo#2", "embedding": ndarray_to_blob(bad_vec)},
    ]

    idx = VectorIndex(dimension=4, m=4, ef_construction=16, ef_search=10, max_elements=100)
    await idx.initialize(intel_db, "pr")

    assert idx.count == 1  # only the good vector loaded


# ── Test: Manager close sets indexes to None ─────────────────────────────


async def test_manager_close():
    """close() releases index references."""
    config = _make_config()
    manager = VectorIndexManager(config)
    manager.pr_index = MagicMock()
    manager.issue_index = MagicMock()

    await manager.close()

    assert manager.pr_index is None
    assert manager.issue_index is None
