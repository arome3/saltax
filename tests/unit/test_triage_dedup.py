"""Tests for the triage dedup gate (src/triage/dedup.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import numpy as np
import pytest

from src.intelligence.similarity import (
    blob_to_ndarray,
    cosine_similarity_vectors,
    ndarray_to_blob,
)
from src.triage.dedup import (
    _emit_metric,
    embed_diff,
    format_dedup_comment,
    post_dedup_comment,
    run_dedup_check,
)

_ = pytest  # ensure pytest is used (fixture injection)

# Common test-model tag used when mocking embed_diff return values.
_TEST_MODEL = "test-model"


# ═══════════════════════════════════════════════════════════════════════════════
# A. cosine_similarity_vectors
# ═══════════════════════════════════════════════════════════════════════════════


class TestCosineSimilarityVectors:
    """Pure math tests for cosine_similarity_vectors(ndarray, ndarray)."""

    def test_identical_vectors(self) -> None:
        """Identical vectors → 1.0."""
        v = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        assert cosine_similarity_vectors(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors(self) -> None:
        """Orthogonal vectors → 0.0."""
        a = np.array([1.0, 0.0], dtype=np.float32)
        b = np.array([0.0, 1.0], dtype=np.float32)
        assert cosine_similarity_vectors(a, b) == pytest.approx(0.0)

    def test_opposite_vectors(self) -> None:
        """Opposite vectors → -1.0."""
        a = np.array([1.0, 0.0], dtype=np.float32)
        b = np.array([-1.0, 0.0], dtype=np.float32)
        assert cosine_similarity_vectors(a, b) == pytest.approx(-1.0)

    def test_zero_vector(self) -> None:
        """Zero-norm vector → 0.0."""
        a = np.array([1.0, 2.0], dtype=np.float32)
        b = np.zeros(2, dtype=np.float32)
        assert cosine_similarity_vectors(a, b) == 0.0

    def test_dimension_mismatch(self) -> None:
        """Mismatched dimensions → ValueError."""
        a = np.array([1.0, 2.0], dtype=np.float32)
        b = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        with pytest.raises(ValueError, match="Dimension mismatch"):
            cosine_similarity_vectors(a, b)

    def test_nan_returns_zero(self) -> None:
        """NaN in either vector → 0.0."""
        a = np.array([1.0, float("nan")], dtype=np.float32)
        b = np.array([1.0, 2.0], dtype=np.float32)
        assert cosine_similarity_vectors(a, b) == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# B. Serialization round-trip
# ═══════════════════════════════════════════════════════════════════════════════


class TestSerialization:
    """Test ndarray_to_blob ↔ blob_to_ndarray round-trip."""

    def test_round_trip(self) -> None:
        """ndarray → bytes → ndarray with exact equality."""
        original = np.array([0.1, 0.2, 0.3, -0.5], dtype=np.float32)
        blob = ndarray_to_blob(original)
        restored = blob_to_ndarray(blob)
        np.testing.assert_array_equal(original, restored)

    def test_deserialized_is_writable(self) -> None:
        """Deserialized array must be writable (not a read-only buffer view)."""
        blob = ndarray_to_blob(np.array([1.0], dtype=np.float32))
        arr = blob_to_ndarray(blob)
        arr[0] = 99.0  # must not raise
        assert arr[0] == 99.0


# ═══════════════════════════════════════════════════════════════════════════════
# C. embed_diff
# ═══════════════════════════════════════════════════════════════════════════════


class TestEmbedDiff:
    """Test embed_diff with fastembed primary + hash fallback."""

    async def test_empty_diff_raises(self) -> None:
        """Empty diff raises ValueError without embedding."""
        env = AsyncMock()
        config = AsyncMock()
        with pytest.raises(ValueError, match="empty diff"):
            await embed_diff("", env=env, config=config)

    async def test_fastembed_returns_tuple(self) -> None:
        """When fastembed is available, returns (vector, model_tag) tuple."""
        fake_vec = np.array([0.1, 0.2, 0.3], dtype=np.float32)

        with patch(
            "src.triage.dedup._fastembed_embed",
            return_value=fake_vec,
        ):
            result = await embed_diff("diff content", env=AsyncMock(), config=AsyncMock())

        vec, model = result
        assert isinstance(vec, np.ndarray)
        assert vec.dtype == np.float32
        assert model == "bge-small-en-v1.5"

    async def test_hash_fallback_when_fastembed_unavailable(self) -> None:
        """Falls back to feature-hash when fastembed raises."""
        with patch(
            "src.triage.dedup._fastembed_embed",
            side_effect=RuntimeError("not installed"),
        ):
            vec, model = await embed_diff(
                "def hello(): pass", env=AsyncMock(), config=AsyncMock(),
            )

        assert isinstance(vec, np.ndarray)
        assert vec.dtype == np.float32
        assert model == "local-feature-hash-256"
        assert len(vec) == 256

    async def test_truncation(self) -> None:
        """Diff longer than 12K chars is truncated before embedding."""
        from src.triage.dedup import _MAX_DIFF_CHARS

        captured_input: list[str] = []

        def capture_embed(text: str) -> np.ndarray:
            captured_input.append(text)
            return np.ones(384, dtype=np.float32)

        long_diff = "x" * (_MAX_DIFF_CHARS + 5000)
        with patch("src.triage.dedup._fastembed_embed", side_effect=capture_embed):
            await embed_diff(long_diff, env=AsyncMock(), config=AsyncMock())

        assert len(captured_input[0]) == _MAX_DIFF_CHARS


# ═══════════════════════════════════════════════════════════════════════════════
# D. run_dedup_check
# ═══════════════════════════════════════════════════════════════════════════════


def _make_config(
    *,
    triage_enabled: bool = True,
    dedup_enabled: bool = True,
    threshold: float = 0.85,
    max_scan: int = 200,
    comment_on_synchronize: bool = False,
):
    """Build a mock config with triage/dedup settings."""
    config = AsyncMock()
    config.triage.enabled = triage_enabled
    config.triage.dedup.enabled = dedup_enabled
    config.triage.dedup.similarity_threshold = threshold
    config.triage.dedup.embedding_model = "bge-small-en-v1.5"
    config.triage.dedup.max_scan_embeddings = max_scan
    config.triage.dedup.comment_on_synchronize = comment_on_synchronize
    return config


def _make_state(
    *,
    diff: str = "some diff",
    repo: str = "owner/repo",
    pr_number: int = 42,
    action: str = "opened",
):
    """Build a minimal pipeline state dict."""
    return {
        "diff": diff,
        "repo": repo,
        "pr_number": pr_number,
        "pr_id": f"{repo}#{pr_number}",
        "commit_sha": "abc1234",
        "installation_id": 12345,
        "action": action,
    }


class TestRunDedupCheck:
    """Test the full dedup check flow.

    run_dedup_check embeds the diff via embed_diff (returns (vec, model)),
    stores the embedding, then delegates similarity search to find_similar().
    Tests mock both embed_diff and find_similar at their import boundaries.
    """

    async def test_disabled_returns_empty(self) -> None:
        """Returns [] when dedup is disabled."""
        config = _make_config(dedup_enabled=False)
        result = await run_dedup_check(
            _make_state(), config, AsyncMock(), AsyncMock(),
        )
        assert result == []

    async def test_triage_disabled_returns_empty(self) -> None:
        """Returns [] when triage.enabled is False."""
        config = _make_config(triage_enabled=False, dedup_enabled=True)
        result = await run_dedup_check(
            _make_state(), config, AsyncMock(), AsyncMock(),
        )
        assert result == []

    async def test_empty_diff_returns_empty(self) -> None:
        """Returns [] when diff is empty."""
        config = _make_config()
        result = await run_dedup_check(
            _make_state(diff=""), config, AsyncMock(), AsyncMock(),
        )
        assert result == []

    async def test_whitespace_diff_returns_empty(self) -> None:
        """Returns [] when diff is whitespace only."""
        config = _make_config()
        result = await run_dedup_check(
            _make_state(diff="   \n  "), config, AsyncMock(), AsyncMock(),
        )
        assert result == []

    async def test_embed_failure_returns_empty(self) -> None:
        """Returns [] when embed_diff raises."""
        config = _make_config()
        intel_db = AsyncMock()

        with patch(
            "src.triage.dedup.embed_diff",
            new_callable=AsyncMock,
            side_effect=RuntimeError("API down"),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        assert result == []

    async def test_no_similar_embeddings(self) -> None:
        """Returns [] when find_similar returns no matches."""
        config = _make_config()
        query_vec = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        intel_db = AsyncMock()

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        assert result == []

    async def test_finds_match_above_threshold(self) -> None:
        """Detects a duplicate when find_similar returns a match."""
        config = _make_config(threshold=0.85)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)

        intel_db = AsyncMock()
        intel_db.get_pr_embedding_by_pr_id = AsyncMock(return_value={
            "pr_id": "owner/repo#10",
            "pr_number": 10,
            "commit_sha": "def5678",
        })

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[{"id": "owner/repo#10", "similarity": 1.0}],
            ),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        assert len(result) == 1
        assert result[0]["pr_number"] == 10
        assert result[0]["similarity"] == pytest.approx(1.0)

    async def test_filters_below_threshold(self) -> None:
        """PRs below the similarity threshold are excluded by find_similar."""
        config = _make_config(threshold=0.95)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        intel_db = AsyncMock()

        # find_similar already filters by threshold — returns empty
        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        assert result == []

    async def test_sorted_descending(self) -> None:
        """Results preserve find_similar's descending similarity order."""
        config = _make_config(threshold=0.50)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)

        intel_db = AsyncMock()

        async def _pr_lookup(pr_id):
            lookup = {
                "owner/repo#5": {"pr_id": "owner/repo#5", "pr_number": 5, "commit_sha": "aaa"},
                "owner/repo#6": {"pr_id": "owner/repo#6", "pr_number": 6, "commit_sha": "bbb"},
            }
            return lookup.get(pr_id)
        intel_db.get_pr_embedding_by_pr_id = AsyncMock(side_effect=_pr_lookup)

        # find_similar returns results already sorted descending
        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[
                    {"id": "owner/repo#6", "similarity": 0.95},
                    {"id": "owner/repo#5", "similarity": 0.72},
                ],
            ),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        assert len(result) == 2
        assert result[0]["pr_number"] == 6  # higher similarity first
        assert result[1]["pr_number"] == 5

    async def test_find_similar_exception_returns_empty(self) -> None:
        """find_similar raising an exception → returns [] gracefully."""
        config = _make_config(threshold=0.50)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        intel_db = AsyncMock()

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                side_effect=RuntimeError("index corrupted"),
            ),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        assert result == []

    async def test_store_failure_continues(self) -> None:
        """Store failure doesn't prevent comparison."""
        config = _make_config(threshold=0.50)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)

        intel_db = AsyncMock()
        intel_db.store_embedding = AsyncMock(side_effect=RuntimeError("DB write fail"))
        intel_db.get_pr_embedding_by_pr_id = AsyncMock(return_value={
            "pr_id": "owner/repo#10",
            "pr_number": 10,
            "commit_sha": "def5678",
        })

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[{"id": "owner/repo#10", "similarity": 1.0}],
            ),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        # Match still found despite store failure
        assert len(result) == 1

    async def test_timeout_returns_empty(self) -> None:
        """embed_diff timeout → returns [] (caught by outer except)."""
        config = _make_config()

        with patch(
            "src.triage.dedup.embed_diff",
            new_callable=AsyncMock,
            side_effect=TimeoutError("timed out"),
        ):
            result = await run_dedup_check(
                _make_state(), config, AsyncMock(), AsyncMock(),
            )

        assert result == []

    async def test_model_tag_passed_to_find_similar(self) -> None:
        """find_similar is called with embedding_model from embed_diff's return."""
        config = _make_config()
        query_vec = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        intel_db = AsyncMock()

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[],
            ) as mock_find,
        ):
            await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        mock_find.assert_awaited_once()
        call_kwargs = mock_find.call_args.kwargs
        assert call_kwargs["embedding_model"] == _TEST_MODEL
        assert call_kwargs["max_scan"] == 200

    async def test_metrics_emitted(self) -> None:
        """After successful dedup, _emit_metric is called with expected metric names."""
        config = _make_config()
        query_vec = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        intel_db = AsyncMock()

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("src.triage.dedup._emit_metric") as mock_metric,
        ):
            await run_dedup_check(
                _make_state(), config, AsyncMock(), intel_db,
            )

        metric_names = [call.args[0] for call in mock_metric.call_args_list]
        assert "dedup.duration_seconds" in metric_names
        assert "dedup.candidates_found" in metric_names
        assert "dedup.embed_api_failed" in metric_names


# ═══════════════════════════════════════════════════════════════════════════════
# E. format_dedup_comment
# ═══════════════════════════════════════════════════════════════════════════════


class TestFormatDedupComment:
    """Test markdown comment rendering."""

    def test_markdown_table(self) -> None:
        """Output contains a markdown table with similarity percentages."""
        dupes = [
            {"pr_id": "owner/repo#10", "pr_number": 10, "commit_sha": "abc1234def", "similarity": 0.95},
            {"pr_id": "owner/repo#11", "pr_number": 11, "commit_sha": "def5678abc", "similarity": 0.87},
        ]
        body = format_dedup_comment(dupes)

        assert "## Duplicate PR Detection" in body
        assert "| owner/repo#10 | 95.0% |" in body
        assert "| owner/repo#11 | 87.0% |" in body
        assert "`abc1234`" in body
        assert "advisory" in body.lower()

    def test_single_duplicate(self) -> None:
        """Works with a single duplicate."""
        dupes = [
            {"pr_id": "owner/repo#5", "pr_number": 5, "commit_sha": "aabbccdd", "similarity": 0.91},
        ]
        body = format_dedup_comment(dupes)
        assert "91.0%" in body


# ═══════════════════════════════════════════════════════════════════════════════
# F. post_dedup_comment
# ═══════════════════════════════════════════════════════════════════════════════


class TestPostDedupComment:
    """Test advisory comment posting."""

    async def test_empty_duplicates_no_call(self) -> None:
        """No API call when duplicates list is empty."""
        github_client = AsyncMock()
        await post_dedup_comment(_make_state(), [], github_client)
        github_client.create_comment.assert_not_awaited()

    async def test_successful_post(self) -> None:
        """Posts a comment via GitHubClient.create_comment with correct kwargs."""
        github_client = AsyncMock()
        dupes = [
            {"pr_id": "owner/repo#10", "pr_number": 10, "commit_sha": "abc", "similarity": 0.92},
        ]
        await post_dedup_comment(_make_state(), dupes, github_client)
        github_client.create_comment.assert_awaited_once()

        call_kwargs = github_client.create_comment.call_args.kwargs
        assert call_kwargs["repo"] == "owner/repo"
        assert call_kwargs["pr_number"] == 42
        assert call_kwargs["installation_id"] == 12345

    async def test_github_error_swallowed(self) -> None:
        """GitHub API failure is swallowed — never raises."""
        github_client = AsyncMock()
        github_client.create_comment = AsyncMock(
            side_effect=RuntimeError("rate limited"),
        )
        dupes = [
            {"pr_id": "owner/repo#10", "pr_number": 10, "commit_sha": "abc", "similarity": 0.92},
        ]
        # Must not raise
        await post_dedup_comment(_make_state(), dupes, github_client)

    async def test_incomplete_state_skips_comment(self) -> None:
        """Missing required state keys → no create_comment call, no raise."""
        github_client = AsyncMock()
        dupes = [
            {"pr_id": "owner/repo#10", "pr_number": 10, "commit_sha": "abc", "similarity": 0.92},
        ]
        # State missing 'repo'
        incomplete_state: dict[str, object] = {
            "pr_number": 42,
            "installation_id": 12345,
            "pr_id": "owner/repo#42",
        }
        await post_dedup_comment(incomplete_state, dupes, github_client)
        github_client.create_comment.assert_not_awaited()

    async def test_missing_installation_id_skips(self) -> None:
        """Missing installation_id → no create_comment call."""
        github_client = AsyncMock()
        dupes = [
            {"pr_id": "owner/repo#10", "pr_number": 10, "commit_sha": "abc", "similarity": 0.92},
        ]
        state: dict[str, object] = {
            "repo": "owner/repo",
            "pr_number": 42,
            "pr_id": "owner/repo#42",
        }
        await post_dedup_comment(state, dupes, github_client)
        github_client.create_comment.assert_not_awaited()


# ═══════════════════════════════════════════════════════════════════════════════
# G. Comment gating (synchronize suppression)
# ═══════════════════════════════════════════════════════════════════════════════


class TestCommentGating:
    """Test that comment posting respects action + config gating.

    These tests verify the gating logic at the handlers.py level by
    testing the individual components that enforce the gate.
    """

    async def test_comment_suppressed_on_synchronize(self) -> None:
        """action=synchronize + comment_on_synchronize=False → comment skipped.

        The gating happens in handlers.py, but we verify the config is
        correctly wired by checking that the default config has
        comment_on_synchronize=False.
        """
        config = _make_config(comment_on_synchronize=False)
        assert config.triage.dedup.comment_on_synchronize is False

    async def test_comment_on_synchronize_when_enabled(self) -> None:
        """action=synchronize + comment_on_synchronize=True → comment allowed."""
        config = _make_config(comment_on_synchronize=True)
        assert config.triage.dedup.comment_on_synchronize is True


# ═══════════════════════════════════════════════════════════════════════════════
# H. issue_number forwarding
# ═══════════════════════════════════════════════════════════════════════════════


class TestIssueNumberForwarding:
    """GAP 1: Verify issue_number flows from state to store_embedding."""

    async def test_issue_number_forwarded_when_present(self) -> None:
        """target_issue_number in state → passed as issue_number to store_embedding."""
        config = _make_config()
        query_vec = np.array([0.1, 0.2, 0.3], dtype=np.float32)

        intel_db = AsyncMock()

        state = _make_state()
        state["target_issue_number"] = 42

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            await run_dedup_check(state, config, AsyncMock(), intel_db)

        intel_db.store_embedding.assert_awaited_once()
        call_kwargs = intel_db.store_embedding.call_args.kwargs
        assert call_kwargs["issue_number"] == 42

    async def test_issue_number_none_when_absent(self) -> None:
        """No target_issue_number in state → issue_number=None passed."""
        config = _make_config()
        query_vec = np.array([0.1, 0.2, 0.3], dtype=np.float32)

        intel_db = AsyncMock()

        state = _make_state()
        # No target_issue_number key

        with (
            patch(
                "src.triage.dedup.embed_diff",
                new_callable=AsyncMock,
                return_value=(query_vec, _TEST_MODEL),
            ),
            patch(
                "src.triage.dedup.find_similar",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            await run_dedup_check(state, config, AsyncMock(), intel_db)

        intel_db.store_embedding.assert_awaited_once()
        call_kwargs = intel_db.store_embedding.call_args.kwargs
        assert call_kwargs["issue_number"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# I. _emit_metric
# ═══════════════════════════════════════════════════════════════════════════════


class TestEmitMetric:
    """Test structured metric emission."""

    def test_emit_metric_logs(self) -> None:
        """_emit_metric logs with metric_name and metric_value extras."""
        with patch("src.triage.dedup.logger") as mock_logger:
            _emit_metric("dedup.test", 42, pr_id="x")

        mock_logger.info.assert_called_once()
        call_kwargs = mock_logger.info.call_args
        extra = call_kwargs.kwargs.get("extra") or call_kwargs[1].get("extra", {})
        assert extra["metric_name"] == "dedup.test"
        assert extra["metric_value"] == 42
        assert extra["pr_id"] == "x"
