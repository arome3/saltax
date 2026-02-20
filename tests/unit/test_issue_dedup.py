"""Tests for the issue dedup gate (src/triage/issue_dedup.py)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import numpy as np
import pytest

from src.intelligence.similarity import ndarray_to_blob
from src.triage.issue_dedup import (
    _extract_duplicate_issue_numbers,
    embed_issue,
    format_issue_dedup_comment,
    handle_issue_edited,
    post_issue_dedup_comment,
    preprocess_issue_text,
    run_issue_dedup_check,
)

_ = pytest  # ensure pytest is used (fixture injection)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _make_config(
    *,
    triage_enabled: bool = True,
    issue_dedup_enabled: bool = True,
    threshold: float = 0.90,
    max_candidates: int = 500,
    apply_label: bool = False,
    label_name: str = "duplicate-candidate",
):
    """Build a mock config with triage/issue_dedup settings."""
    config = AsyncMock()
    config.triage.enabled = triage_enabled
    config.triage.issue_dedup.enabled = issue_dedup_enabled
    config.triage.issue_dedup.similarity_threshold = threshold
    config.triage.issue_dedup.embedding_model = "text-embedding"
    config.triage.issue_dedup.max_candidates = max_candidates
    config.triage.issue_dedup.apply_label = apply_label
    config.triage.issue_dedup.label_name = label_name
    return config


def _make_issue_data(
    *,
    action: str = "opened",
    repo: str = "owner/repo",
    issue_number: int = 42,
    title: str = "Fix authentication bypass in login endpoint",
    body: str | None = "The login endpoint allows unauthenticated access to admin routes.",
    labels: list[str] | None = None,
    state: str = "open",
    body_changed: bool = False,
):
    """Build a minimal issue data dict."""
    return {
        "action": action,
        "repo": repo,
        "repo_full_name": repo,
        "issue_number": issue_number,
        "title": title,
        "body": body,
        "labels": labels or [],
        "state": state,
        "body_changed": body_changed,
        "installation_id": 12345,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# A. preprocess_issue_text
# ═══════════════════════════════════════════════════════════════════════════════


class TestPreprocessIssueText:
    """Test text preprocessing for embedding."""

    def test_title_and_body_combined(self) -> None:
        """Title and body are joined with a space."""
        result = preprocess_issue_text("Bug report", "The app crashes on startup")
        assert "Bug report" in result
        assert "The app crashes on startup" in result

    def test_template_headers_stripped(self) -> None:
        """Markdown ### headers from issue templates are removed."""
        body = "### Description\nThe app crashes\n### Steps\n1. Open app"
        result = preprocess_issue_text("Bug", body)
        assert "### Description" not in result
        assert "### Steps" not in result
        assert "crashes" in result

    def test_checkboxes_removed(self) -> None:
        """Issue template checkboxes are stripped."""
        body = "- [x] I have read the docs\n- [ ] I have searched issues"
        result = preprocess_issue_text("Bug", body)
        assert "[x]" not in result
        assert "[ ]" not in result
        assert "read the docs" in result

    def test_markdown_links_reduced(self) -> None:
        """Markdown links are replaced with their link text."""
        body = "See [the docs](https://example.com) for details"
        result = preprocess_issue_text("Help", body)
        assert "https://example.com" not in result
        assert "the docs" in result

    def test_html_tags_stripped(self) -> None:
        """HTML tags are removed."""
        body = "<details><summary>Info</summary>Content</details>"
        result = preprocess_issue_text("Bug", body)
        assert "<details>" not in result
        assert "<summary>" not in result
        assert "Content" in result

    def test_empty_body(self) -> None:
        """Empty body → title only."""
        result = preprocess_issue_text("Title only", "")
        assert result == "Title only"

    def test_none_body(self) -> None:
        """None body → title only."""
        result = preprocess_issue_text("Title only", None)
        assert result == "Title only"

    def test_body_entirely_template(self) -> None:
        """Body that is entirely template headers → title only."""
        body = "### Description\n### Steps to reproduce\n### Expected behavior"
        result = preprocess_issue_text("Bug", body)
        assert result == "Bug"

    def test_unicode_preserved(self) -> None:
        """Unicode characters are preserved."""
        result = preprocess_issue_text("Ошибка", "Приложение падает при запуске")
        assert "Ошибка" in result
        assert "Приложение" in result


# ═══════════════════════════════════════════════════════════════════════════════
# B. embed_issue
# ═══════════════════════════════════════════════════════════════════════════════


class TestEmbedIssue:
    """Test the embed_issue API wrapper."""

    async def test_successful_embedding(self) -> None:
        """Successful API call returns numpy array."""
        mock_response = AsyncMock()
        mock_response.data = [AsyncMock(embedding=[0.1, 0.2, 0.3])]

        mock_client = AsyncMock()
        mock_client.embeddings.create = AsyncMock(return_value=mock_response)
        mock_client.close = AsyncMock()

        env = AsyncMock()
        env.eigenai_api_url = "https://fake.api/v1"
        env.eigenai_api_key = "fake-key"

        config = AsyncMock()
        config.embedding_model = "text-embedding"

        with patch("src.triage.issue_dedup.AsyncOpenAI", return_value=mock_client):
            result = await embed_issue(
                "Fix login bug",
                "The login endpoint allows bypass",
                env,
                config,
            )

        assert isinstance(result, np.ndarray)
        assert result.dtype == np.float32
        assert len(result) == 3
        mock_client.close.assert_awaited_once()

    async def test_short_text_guard_f1(self) -> None:
        """F1: Very short title + no body raises ValueError."""
        env = AsyncMock()
        config = AsyncMock()
        config.embedding_model = "text-embedding"

        with pytest.raises(ValueError, match="too short"):
            await embed_issue("Bug", None, env, config)

    async def test_short_body_falls_back_to_title(self) -> None:
        """F1: Short body after preprocessing → falls back to title."""
        mock_response = AsyncMock()
        mock_response.data = [AsyncMock(embedding=[0.1, 0.2, 0.3])]

        mock_client = AsyncMock()
        mock_client.embeddings.create = AsyncMock(return_value=mock_response)
        mock_client.close = AsyncMock()

        env = AsyncMock()
        env.eigenai_api_url = "https://fake.api/v1"
        env.eigenai_api_key = "fake-key"

        config = AsyncMock()
        config.embedding_model = "text-embedding"

        # Body is very short after preprocessing
        with patch("src.triage.issue_dedup.AsyncOpenAI", return_value=mock_client):
            result = await embed_issue(
                "Authentication bypass in admin panel",
                "### Bug\n",
                env,
                config,
            )

        assert isinstance(result, np.ndarray)

    async def test_client_always_closed(self) -> None:
        """Client is closed even when the API call raises."""
        mock_client = AsyncMock()
        mock_client.embeddings.create = AsyncMock(
            side_effect=RuntimeError("API down"),
        )
        mock_client.close = AsyncMock()

        env = AsyncMock()
        env.eigenai_api_url = "https://fake.api/v1"
        env.eigenai_api_key = "fake-key"
        config = AsyncMock()
        config.embedding_model = "text-embedding"

        with (
            patch("src.triage.issue_dedup.AsyncOpenAI", return_value=mock_client),
            pytest.raises(RuntimeError, match="API down"),
        ):
            await embed_issue(
                "Fix the authentication bypass vulnerability",
                "Detailed description of the issue",
                env,
                config,
            )

        mock_client.close.assert_awaited_once()

    async def test_retry_on_transient_error(self) -> None:
        """Embedding API returns 500 then succeeds → retries and returns."""
        from openai import InternalServerError

        mock_response = AsyncMock()
        mock_response.data = [AsyncMock(embedding=[0.1, 0.2])]

        mock_client = AsyncMock()
        mock_client.embeddings.create = AsyncMock(
            side_effect=[
                InternalServerError(
                    "server error",
                    response=AsyncMock(status_code=500, headers={}),
                    body=None,
                ),
                mock_response,
            ],
        )
        mock_client.close = AsyncMock()

        env = AsyncMock()
        env.eigenai_api_url = "https://fake.api/v1"
        env.eigenai_api_key = "fake-key"
        config = AsyncMock()
        config.embedding_model = "text-embedding"

        with patch("src.triage.issue_dedup.AsyncOpenAI", return_value=mock_client):
            with patch("src.triage.issue_dedup.asyncio.sleep", new_callable=AsyncMock):
                result = await embed_issue(
                    "Fix the authentication bypass vulnerability",
                    "Detailed description of the issue",
                    env,
                    config,
                )

        assert isinstance(result, np.ndarray)
        assert mock_client.embeddings.create.await_count == 2

    async def test_timeout_raises(self) -> None:
        """asyncio.timeout fires TimeoutError when API call exceeds budget."""
        async def _slow_create(**_kwargs: object) -> None:
            await asyncio.sleep(10)  # will be cut short by timeout

        mock_client = AsyncMock()
        mock_client.embeddings.create = _slow_create
        mock_client.close = AsyncMock()

        env = AsyncMock()
        env.eigenai_api_url = "https://fake.api/v1"
        env.eigenai_api_key = "fake-key"
        config = AsyncMock()
        config.embedding_model = "text-embedding"

        with (
            patch("src.triage.issue_dedup.AsyncOpenAI", return_value=mock_client),
            patch("src.triage.issue_dedup._EMBED_TIMEOUT", 0.01),
            pytest.raises(TimeoutError),
        ):
            await embed_issue(
                "Fix the authentication bypass vulnerability",
                "Detailed description of the issue",
                env,
                config,
            )

        mock_client.close.assert_awaited_once()

    async def test_timeout_is_per_call_not_total(self) -> None:
        """Per-call timeout: first call times out, retry succeeds."""
        call_count = 0
        real_sleep = asyncio.sleep

        async def _slow_then_fast(**_kwargs: object) -> AsyncMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                await real_sleep(10)  # first call hangs → timeout
            # Second call succeeds immediately
            resp = AsyncMock()
            resp.data = [AsyncMock(embedding=[0.5, 0.5])]
            return resp

        mock_client = AsyncMock()
        mock_client.embeddings.create = _slow_then_fast
        mock_client.close = AsyncMock()

        env = AsyncMock()
        env.eigenai_api_url = "https://fake.api/v1"
        env.eigenai_api_key = "fake-key"
        config = AsyncMock()
        config.embedding_model = "text-embedding"

        with (
            patch("src.triage.issue_dedup.AsyncOpenAI", return_value=mock_client),
            patch("src.triage.issue_dedup._EMBED_TIMEOUT", 0.01),
            patch("src.triage.issue_dedup._EMBED_BACKOFF_BASE", 0.001),
        ):
            result = await embed_issue(
                "Fix the authentication bypass vulnerability",
                "Detailed description of the issue",
                env,
                config,
            )

        assert isinstance(result, np.ndarray)
        assert call_count == 2  # first timed out, second succeeded


# ═══════════════════════════════════════════════════════════════════════════════
# C. run_issue_dedup_check
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunIssueDedupCheck:
    """Test the full issue dedup check flow."""

    async def test_disabled_returns_empty(self) -> None:
        """Returns [] when issue_dedup is disabled."""
        config = _make_config(issue_dedup_enabled=False)
        result = await run_issue_dedup_check(
            _make_issue_data(), config, AsyncMock(), AsyncMock(),
        )
        assert result == []

    async def test_triage_disabled_returns_empty(self) -> None:
        """Returns [] when triage.enabled is False."""
        config = _make_config(triage_enabled=False)
        result = await run_issue_dedup_check(
            _make_issue_data(), config, AsyncMock(), AsyncMock(),
        )
        assert result == []

    async def test_duplicate_labeled_returns_empty(self) -> None:
        """Returns [] when issue has 'duplicate' label — no API calls made."""
        config = _make_config()
        intel_db = AsyncMock()
        result = await run_issue_dedup_check(
            _make_issue_data(labels=["duplicate"]),
            config,
            AsyncMock(),
            intel_db,
        )
        assert result == []
        intel_db.store_issue_embedding.assert_not_awaited()

    async def test_config_label_name_gates(self) -> None:
        """Returns [] when issue carries the config-driven label_name."""
        config = _make_config(label_name="dupe-detected")
        intel_db = AsyncMock()
        result = await run_issue_dedup_check(
            _make_issue_data(labels=["dupe-detected"]),
            config,
            AsyncMock(),
            intel_db,
        )
        assert result == []
        intel_db.store_issue_embedding.assert_not_awaited()

    async def test_default_label_name_gates(self) -> None:
        """Returns [] when issue carries the default 'duplicate-candidate' label."""
        config = _make_config()  # default label_name="duplicate-candidate"
        intel_db = AsyncMock()
        result = await run_issue_dedup_check(
            _make_issue_data(labels=["duplicate-candidate"]),
            config,
            AsyncMock(),
            intel_db,
        )
        assert result == []
        intel_db.store_issue_embedding.assert_not_awaited()

    async def test_embed_failure_returns_empty(self) -> None:
        """Returns [] when embed_issue raises."""
        config = _make_config()
        intel_db = AsyncMock()

        with patch(
            "src.triage.issue_dedup.embed_issue",
            new_callable=AsyncMock,
            side_effect=RuntimeError("API down"),
        ):
            result = await run_issue_dedup_check(
                _make_issue_data(), config, AsyncMock(), intel_db,
            )

        assert result == []

    async def test_matches_above_threshold(self) -> None:
        """Detects a duplicate when similarity exceeds threshold."""
        config = _make_config(threshold=0.85)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        stored_blob = ndarray_to_blob(query_vec)

        intel_db = AsyncMock()
        intel_db.get_recent_issue_embeddings = AsyncMock(return_value=[
            {
                "issue_number": 10,
                "title": "Similar bug",
                "embedding": stored_blob,
                "status": "open",
            },
        ])
        intel_db.get_issue_embedding = AsyncMock(return_value={
            "issue_number": 10,
            "title": "Similar bug",
            "status": "open",
        })

        with patch(
            "src.triage.issue_dedup.embed_issue",
            new_callable=AsyncMock,
            return_value=query_vec,
        ):
            result = await run_issue_dedup_check(
                _make_issue_data(), config, AsyncMock(), intel_db,
            )

        assert len(result) == 1
        assert result[0]["issue_number"] == 10
        assert result[0]["similarity"] == pytest.approx(1.0)

    async def test_filters_below_threshold(self) -> None:
        """Issues below the similarity threshold are excluded."""
        config = _make_config(threshold=0.95)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        other_vec = np.array([0.7, 0.7, 0.0], dtype=np.float32)

        intel_db = AsyncMock()
        intel_db.get_recent_issue_embeddings = AsyncMock(return_value=[
            {
                "issue_number": 10,
                "title": "Different issue",
                "embedding": ndarray_to_blob(other_vec),
                "status": "open",
            },
        ])

        with patch(
            "src.triage.issue_dedup.embed_issue",
            new_callable=AsyncMock,
            return_value=query_vec,
        ):
            result = await run_issue_dedup_check(
                _make_issue_data(), config, AsyncMock(), intel_db,
            )

        assert result == []

    async def test_sorted_descending(self) -> None:
        """Results are sorted by similarity descending."""
        config = _make_config(threshold=0.50)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)

        high_vec = np.array([0.95, 0.05, 0.0], dtype=np.float32)
        low_vec = np.array([0.7, 0.7, 0.0], dtype=np.float32)

        intel_db = AsyncMock()
        intel_db.get_recent_issue_embeddings = AsyncMock(return_value=[
            {
                "issue_number": 5,
                "title": "Low similarity",
                "embedding": ndarray_to_blob(low_vec),
                "status": "open",
            },
            {
                "issue_number": 6,
                "title": "High similarity",
                "embedding": ndarray_to_blob(high_vec),
                "status": "open",
            },
        ])
        # Enrichment lookup returns metadata keyed by issue_number
        async def _issue_lookup(repo, issue_num):
            lookup = {
                5: {"issue_number": 5, "title": "Low similarity", "status": "open"},
                6: {"issue_number": 6, "title": "High similarity", "status": "open"},
            }
            return lookup.get(issue_num)
        intel_db.get_issue_embedding = AsyncMock(side_effect=_issue_lookup)

        with patch(
            "src.triage.issue_dedup.embed_issue",
            new_callable=AsyncMock,
            return_value=query_vec,
        ):
            result = await run_issue_dedup_check(
                _make_issue_data(), config, AsyncMock(), intel_db,
            )

        assert len(result) == 2
        assert result[0]["issue_number"] == 6  # higher similarity first
        assert result[1]["issue_number"] == 5

    async def test_dimension_mismatch_skipped(self) -> None:
        """F2: Rows with mismatched dimensions are skipped, not fatal."""
        config = _make_config(threshold=0.50)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        mismatched = np.array([1.0, 0.0], dtype=np.float32)

        intel_db = AsyncMock()
        intel_db.get_recent_issue_embeddings = AsyncMock(return_value=[
            {
                "issue_number": 10,
                "title": "Mismatched",
                "embedding": ndarray_to_blob(mismatched),
                "status": "open",
            },
        ])

        with patch(
            "src.triage.issue_dedup.embed_issue",
            new_callable=AsyncMock,
            return_value=query_vec,
        ):
            result = await run_issue_dedup_check(
                _make_issue_data(), config, AsyncMock(), intel_db,
            )

        assert result == []

    async def test_store_failure_continues(self) -> None:
        """Store failure doesn't prevent comparison."""
        config = _make_config(threshold=0.50)
        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)

        intel_db = AsyncMock()
        intel_db.store_issue_embedding = AsyncMock(
            side_effect=RuntimeError("DB write fail"),
        )
        intel_db.get_recent_issue_embeddings = AsyncMock(return_value=[
            {
                "issue_number": 10,
                "title": "Match",
                "embedding": ndarray_to_blob(query_vec),
                "status": "open",
            },
        ])
        intel_db.get_issue_embedding = AsyncMock(return_value={
            "issue_number": 10,
            "title": "Match",
            "status": "open",
        })

        with patch(
            "src.triage.issue_dedup.embed_issue",
            new_callable=AsyncMock,
            return_value=query_vec,
        ):
            result = await run_issue_dedup_check(
                _make_issue_data(), config, AsyncMock(), intel_db,
            )

        assert len(result) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# D. format_issue_dedup_comment
# ═══════════════════════════════════════════════════════════════════════════════


class TestFormatIssueDedupComment:
    """Test markdown comment rendering."""

    def test_markdown_table_format(self) -> None:
        """Output contains a markdown table with similarity percentages."""
        dupes = [
            {"issue_number": 10, "title": "Login bug", "similarity": 0.95, "status": "open"},
            {"issue_number": 11, "title": "Auth issue", "similarity": 0.87, "status": "open"},
        ]
        body = format_issue_dedup_comment(
            dupes, repo="owner/repo", issue_number=42,
        )

        assert "## Duplicate Issue Detection" in body
        assert "| #10 | Login bug | 95.0% |" in body
        assert "| #11 | Auth issue | 87.0% |" in body
        assert "advisory" in body.lower()

    def test_html_marker_present(self) -> None:
        """Comment contains the HTML marker for deduplication."""
        dupes = [
            {"issue_number": 10, "title": "Bug", "similarity": 0.91, "status": "open"},
        ]
        body = format_issue_dedup_comment(
            dupes, repo="owner/repo", issue_number=42,
        )
        assert "<!-- saltax-issue-dedup:owner/repo:42 -->" in body

    def test_single_duplicate(self) -> None:
        """Works with a single duplicate."""
        dupes = [
            {"issue_number": 5, "title": "Bug", "similarity": 0.91, "status": "open"},
        ]
        body = format_issue_dedup_comment(
            dupes, repo="owner/repo", issue_number=42,
        )
        assert "91.0%" in body


# ═══════════════════════════════════════════════════════════════════════════════
# E. post_issue_dedup_comment
# ═══════════════════════════════════════════════════════════════════════════════


class TestPostIssueDedupComment:
    """Test advisory comment posting."""

    async def test_empty_duplicates_no_call(self) -> None:
        """No API call when duplicates list is empty."""
        github_client = AsyncMock()
        await post_issue_dedup_comment(_make_issue_data(), [], github_client)
        github_client.create_comment.assert_not_awaited()

    async def test_creates_new_comment(self) -> None:
        """Creates a comment when no existing marker comment found."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(return_value=[])
        dupes = [
            {"issue_number": 10, "title": "Bug", "similarity": 0.92, "status": "open"},
        ]
        await post_issue_dedup_comment(
            _make_issue_data(), dupes, github_client,
        )
        github_client.create_comment.assert_awaited_once()

    async def test_updates_existing_comment(self) -> None:
        """Updates comment when marker exists with different duplicates."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(return_value=[
            {
                "id": 999,
                "body": (
                    "<!-- saltax-issue-dedup:owner/repo:42 -->\n"
                    "## Duplicate Issue Detection\n"
                    "| #5 | Old bug | 90.0% |"
                ),
            },
        ])
        dupes = [
            {"issue_number": 10, "title": "New bug", "similarity": 0.95, "status": "open"},
        ]
        await post_issue_dedup_comment(
            _make_issue_data(), dupes, github_client,
        )
        github_client.update_comment.assert_awaited_once()
        github_client.create_comment.assert_not_awaited()

    async def test_skips_identical_duplicates(self) -> None:
        """F3: Skips if existing comment has same duplicate set."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(return_value=[
            {
                "id": 999,
                "body": (
                    "<!-- saltax-issue-dedup:owner/repo:42 -->\n"
                    "## Duplicate Issue Detection\n"
                    "| #10 | Bug | 92.0% |"
                ),
            },
        ])
        dupes = [
            {"issue_number": 10, "title": "Bug", "similarity": 0.95, "status": "open"},
        ]
        await post_issue_dedup_comment(
            _make_issue_data(), dupes, github_client,
        )
        github_client.update_comment.assert_not_awaited()
        github_client.create_comment.assert_not_awaited()

    async def test_github_error_swallowed(self) -> None:
        """F4: GitHub API failure is swallowed — never raises."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            side_effect=RuntimeError("rate limited"),
        )
        dupes = [
            {"issue_number": 10, "title": "Bug", "similarity": 0.92, "status": "open"},
        ]
        # Must not raise
        await post_issue_dedup_comment(
            _make_issue_data(), dupes, github_client,
        )

    async def test_incomplete_state_skips(self) -> None:
        """Missing required state keys → no API calls, no raise."""
        github_client = AsyncMock()
        dupes = [
            {"issue_number": 10, "title": "Bug", "similarity": 0.92, "status": "open"},
        ]
        incomplete: dict[str, object] = {
            "issue_number": 42,
            "installation_id": 12345,
        }
        await post_issue_dedup_comment(incomplete, dupes, github_client)
        github_client.create_comment.assert_not_awaited()
        github_client.list_issue_comments.assert_not_awaited()


# ═══════════════════════════════════════════════════════════════════════════════
# F. handle_issue_edited
# ═══════════════════════════════════════════════════════════════════════════════


class TestHandleIssueEdited:
    """Test the issues.edited handler."""

    async def test_body_changed_false_skipped(self) -> None:
        """body_changed=False → no embedding or comment calls."""
        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()

        with patch(
            "src.triage.issue_dedup.run_issue_dedup_check",
            new_callable=AsyncMock,
        ) as mock_check:
            await handle_issue_edited(
                _make_issue_data(body_changed=False),
                config,
                AsyncMock(),
                intel_db,
                github_client,
            )

        mock_check.assert_not_awaited()

    async def test_body_changed_true_triggers_dedup(self) -> None:
        """body_changed=True → re-embeds and checks for duplicates."""
        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(return_value=[])

        dupes = [
            {"issue_number": 10, "title": "Bug", "similarity": 0.95, "status": "open"},
        ]

        with (
            patch(
                "src.triage.issue_dedup.run_issue_dedup_check",
                new_callable=AsyncMock,
                return_value=dupes,
            ) as mock_check,
            patch(
                "src.triage.issue_dedup.post_issue_dedup_comment",
                new_callable=AsyncMock,
            ) as mock_post,
        ):
            await handle_issue_edited(
                _make_issue_data(body_changed=True),
                config,
                AsyncMock(),
                intel_db,
                github_client,
            )

        mock_check.assert_awaited_once()
        mock_post.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════════════════
# G. handle_issue_event (handlers.py)
# ═══════════════════════════════════════════════════════════════════════════════


class TestHandleIssueEvent:
    """Test the orchestration handler in handlers.py."""

    async def test_opened_triggers_dedup(self) -> None:
        """action=opened → runs dedup check and posts comment."""
        from src.api.handlers import handle_issue_event

        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(return_value=[])
        env = AsyncMock()

        dupes = [
            {"issue_number": 10, "title": "Bug", "similarity": 0.95, "status": "open"},
        ]

        with (
            patch(
                "src.triage.issue_dedup.run_issue_dedup_check",
                new_callable=AsyncMock,
                return_value=dupes,
            ),
            patch(
                "src.triage.issue_dedup.post_issue_dedup_comment",
                new_callable=AsyncMock,
            ) as mock_post,
        ):
            await handle_issue_event(
                _make_issue_data(action="opened"),
                github_client=github_client,
                intel_db=intel_db,
                config=config,
                env=env,
            )

        mock_post.assert_awaited_once()

    async def test_edited_with_body_change_triggers_dedup(self) -> None:
        """action=edited + body_changed → calls handle_issue_edited."""
        from src.api.handlers import handle_issue_event

        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()
        env = AsyncMock()

        with patch(
            "src.triage.issue_dedup.handle_issue_edited",
            new_callable=AsyncMock,
        ) as mock_edited:
            await handle_issue_event(
                _make_issue_data(action="edited", body_changed=True),
                github_client=github_client,
                intel_db=intel_db,
                config=config,
                env=env,
            )

        mock_edited.assert_awaited_once()

    async def test_edited_without_body_change_skips(self) -> None:
        """action=edited + body_changed=False → handle_issue_edited still called (it gates internally)."""
        from src.api.handlers import handle_issue_event

        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()
        env = AsyncMock()

        with patch(
            "src.triage.issue_dedup.handle_issue_edited",
            new_callable=AsyncMock,
        ) as mock_edited:
            await handle_issue_event(
                _make_issue_data(action="edited", body_changed=False),
                github_client=github_client,
                intel_db=intel_db,
                config=config,
                env=env,
            )

        mock_edited.assert_awaited_once()

    async def test_closed_updates_status(self) -> None:
        """action=closed → updates issue embedding status."""
        from src.api.handlers import handle_issue_event

        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()
        env = AsyncMock()

        await handle_issue_event(
            _make_issue_data(action="closed"),
            github_client=github_client,
            intel_db=intel_db,
            config=config,
            env=env,
        )

        intel_db.update_issue_status.assert_awaited_once_with(
            "owner/repo", 42, "closed",
        )

    async def test_disabled_skips(self) -> None:
        """Disabled triage → no dedup calls."""
        from src.api.handlers import handle_issue_event

        config = _make_config(triage_enabled=False)
        intel_db = AsyncMock()
        github_client = AsyncMock()
        env = AsyncMock()

        with patch(
            "src.triage.issue_dedup.run_issue_dedup_check",
            new_callable=AsyncMock,
        ) as mock_check:
            await handle_issue_event(
                _make_issue_data(action="opened"),
                github_client=github_client,
                intel_db=intel_db,
                config=config,
                env=env,
            )

        mock_check.assert_not_awaited()

    async def test_env_none_skips(self) -> None:
        """env=None → no dedup calls (except closed status update)."""
        from src.api.handlers import handle_issue_event

        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()

        with patch(
            "src.triage.issue_dedup.run_issue_dedup_check",
            new_callable=AsyncMock,
        ) as mock_check:
            await handle_issue_event(
                _make_issue_data(action="opened"),
                github_client=github_client,
                intel_db=intel_db,
                config=config,
                env=None,
            )

        mock_check.assert_not_awaited()

    async def test_swallows_exceptions(self) -> None:
        """Outer try/except catches and logs exceptions."""
        from src.api.handlers import handle_issue_event

        config = _make_config()
        intel_db = AsyncMock()
        github_client = AsyncMock()
        env = AsyncMock()

        with patch(
            "src.triage.issue_dedup.run_issue_dedup_check",
            new_callable=AsyncMock,
            side_effect=RuntimeError("unexpected"),
        ):
            # Must not raise
            await handle_issue_event(
                _make_issue_data(action="opened"),
                github_client=github_client,
                intel_db=intel_db,
                config=config,
                env=env,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# H. _extract_duplicate_issue_numbers
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractDuplicateIssueNumbers:
    """Test comment parsing for F3 guard."""

    def test_extracts_from_table(self) -> None:
        body = "| #10 | Bug | 95.0% |\n| #20 | Auth | 87.0% |"
        result = _extract_duplicate_issue_numbers(body)
        assert result == {10, 20}

    def test_empty_body(self) -> None:
        result = _extract_duplicate_issue_numbers("")
        assert result == set()
