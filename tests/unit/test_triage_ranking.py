"""Tests for triage issue linking, ranking formatting, and ranking orchestration."""

from __future__ import annotations

import os

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from src.config import RankingConfig
from src.github.comments import format_ranking_update
from src.intelligence.database import IntelligenceDB
from src.triage.issue_linker import extract_target_issue
from src.triage.ranking import post_ranking_update

_ = pytest  # ensure pytest is used (fixture injection)

_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
async def intel_db():
    """Provide a fresh IntelligenceDB backed by PostgreSQL."""
    db = IntelligenceDB(database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3)
    await db.initialize()
    try:
        yield db
    finally:
        try:
            pool = db.pool
            async with pool.connection() as conn:
                tables = await (
                    await conn.execute(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                    )
                ).fetchall()
                for t in tables:
                    await conn.execute(f'TRUNCATE TABLE "{t["tablename"]}" CASCADE')
        except Exception:
            pass
        await db.close()


def _ranking_config(**overrides) -> RankingConfig:
    defaults = {
        "enabled": True,
        "label_superseded": "superseded",
        "label_recommended": "saltax-recommended",
        "update_interval_seconds": 3600,
    }
    defaults.update(overrides)
    return RankingConfig(**defaults)


# ═══════════════════════════════════════════════════════════════════════════════
# A. extract_target_issue
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractTargetIssue:
    """Regex coverage for issue extraction."""

    def test_fixes_keyword(self) -> None:
        result = extract_target_issue(title="Fixes #42", body=None, head_branch="main")
        assert result == 42

    def test_fix_keyword(self) -> None:
        result = extract_target_issue(title="Fix #7", body=None, head_branch="main")
        assert result == 7

    def test_fixed_keyword(self) -> None:
        result = extract_target_issue(title="Fixed #100", body=None, head_branch="main")
        assert result == 100

    def test_closes_keyword(self) -> None:
        result = extract_target_issue(title="Closes #33", body=None, head_branch="main")
        assert result == 33

    def test_closed_keyword(self) -> None:
        result = extract_target_issue(title="Closed #5", body=None, head_branch="main")
        assert result == 5

    def test_close_keyword(self) -> None:
        result = extract_target_issue(title="Close #99", body=None, head_branch="main")
        assert result == 99

    def test_resolves_keyword(self) -> None:
        result = extract_target_issue(title="Resolves #12", body=None, head_branch="main")
        assert result == 12

    def test_resolved_keyword(self) -> None:
        result = extract_target_issue(title="Resolved #8", body=None, head_branch="main")
        assert result == 8

    def test_case_insensitive(self) -> None:
        result = extract_target_issue(title="FIXES #50", body=None, head_branch="main")
        assert result == 50

    def test_body_fallback(self) -> None:
        result = extract_target_issue(
            title="Improve performance",
            body="This fixes #77 by caching results",
            head_branch="main",
        )
        assert result == 77

    def test_branch_pattern_fix_dash(self) -> None:
        result = extract_target_issue(
            title="Update deps",
            body=None,
            head_branch="fix-123",
        )
        assert result == 123

    def test_branch_pattern_issue_slash(self) -> None:
        result = extract_target_issue(
            title="Update deps",
            body=None,
            head_branch="issue/456",
        )
        assert result == 456

    def test_branch_pattern_bug_dash(self) -> None:
        result = extract_target_issue(
            title="Update deps",
            body=None,
            head_branch="bug-789",
        )
        assert result == 789

    def test_branch_pattern_feat_slash(self) -> None:
        result = extract_target_issue(
            title="Update deps",
            body=None,
            head_branch="feat/42",
        )
        assert result == 42

    def test_no_match_returns_none(self) -> None:
        result = extract_target_issue(
            title="Refactor utils",
            body="Just cleaning up code",
            head_branch="refactor-utils",
        )
        assert result is None

    def test_none_body_handled(self) -> None:
        result = extract_target_issue(
            title="Update README",
            body=None,
            head_branch="main",
        )
        assert result is None

    def test_title_takes_priority_over_body(self) -> None:
        result = extract_target_issue(
            title="Fixes #10",
            body="Also closes #20",
            head_branch="fix-30",
        )
        assert result == 10

    def test_body_takes_priority_over_branch(self) -> None:
        result = extract_target_issue(
            title="Update deps",
            body="Closes #20",
            head_branch="fix-30",
        )
        assert result == 20


# ═══════════════════════════════════════════════════════════════════════════════
# B. format_ranking_update
# ═══════════════════════════════════════════════════════════════════════════════


class TestFormatRankingUpdate:
    """Table format, recommended marker, status column, HTML marker."""

    def test_contains_html_marker(self) -> None:
        """GAP 2: When repo/issue_number given, HTML marker is prepended."""
        rankings = [
            {
                "pr_number": 10,
                "pr_author": "alice",
                "composite_score": 0.95,
                "verdict": '{"decision": "APPROVE"}',
            },
        ]
        result = format_ranking_update(
            rankings, repo="owner/repo", issue_number=42,
        )
        assert "<!-- saltax-ranking:owner/repo:42 -->" in result

    def test_no_marker_without_params(self) -> None:
        """Without repo/issue_number, no marker is added."""
        rankings = [
            {
                "pr_number": 10,
                "pr_author": "alice",
                "composite_score": 0.95,
                "verdict": '{"decision": "APPROVE"}',
            },
        ]
        result = format_ranking_update(rankings)
        assert "<!-- saltax-ranking" not in result

    def test_basic_table_format(self) -> None:
        rankings = [
            {
                "pr_number": 10,
                "pr_author": "alice",
                "composite_score": 0.95,
                "verdict": '{"decision": "APPROVE"}',
            },
            {
                "pr_number": 20,
                "pr_author": "bob",
                "composite_score": 0.80,
                "verdict": '{"decision": "REVIEW"}',
            },
        ]
        result = format_ranking_update(rankings)
        assert "## SaltaX PR Rankings" in result
        assert "| Status |" in result

    def test_recommended_marker_on_first(self) -> None:
        rankings = [
            {
                "pr_number": 10,
                "pr_author": "alice",
                "composite_score": 0.95,
                "verdict": '{"decision": "APPROVE"}',
            },
            {
                "pr_number": 20,
                "pr_author": "bob",
                "composite_score": 0.80,
                "verdict": '{"decision": "REVIEW"}',
            },
        ]
        result = format_ranking_update(rankings)
        lines = result.split("\n")
        # Find the data rows
        data_rows = [line for line in lines if line.startswith("| 1 ") or line.startswith("| 2 ")]
        assert len(data_rows) == 2
        assert "(recommended)" in data_rows[0]
        assert "(recommended)" not in data_rows[1]

    def test_status_column_from_verdict(self) -> None:
        rankings = [
            {
                "pr_number": 10,
                "pr_author": "alice",
                "composite_score": 0.90,
                "verdict": '{"decision": "APPROVE"}',
            },
        ]
        result = format_ranking_update(rankings)
        assert "APPROVE" in result

    def test_invalid_verdict_json_shows_dash(self) -> None:
        rankings = [
            {
                "pr_number": 10,
                "pr_author": "alice",
                "composite_score": 0.90,
                "verdict": "not-json",
            },
        ]
        result = format_ranking_update(rankings)
        # Should not crash, and show dash for status
        assert "—" in result

    def test_pr_number_format(self) -> None:
        rankings = [
            {
                "pr_number": 42,
                "pr_author": "dev",
                "composite_score": 0.75,
                "verdict": "{}",
            },
        ]
        result = format_ranking_update(rankings)
        assert "#42" in result


# ═══════════════════════════════════════════════════════════════════════════════
# C. post_ranking_update orchestration
# ═══════════════════════════════════════════════════════════════════════════════


class TestPostRankingUpdate:
    """Test orchestration: rate limiting, guards, posting, labeling."""

    async def test_rate_limited_skips(self) -> None:
        """When recently posted, should skip without posting."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=True)
        mock_client = AsyncMock()

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        mock_db.get_ranked_prs.assert_not_awaited()
        mock_client.create_comment.assert_not_awaited()

    async def test_no_prs_skips(self) -> None:
        """When no PRs found, should skip without posting."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[])
        mock_client = AsyncMock()

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        mock_client.create_comment.assert_not_awaited()

    async def test_single_pr_skips(self) -> None:
        """When only one PR targets the issue, skip ranking."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "dev", "verdict": "{}"},
        ])
        mock_client = AsyncMock()

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        mock_client.create_comment.assert_not_awaited()

    async def test_posts_on_issue(self) -> None:
        """Comment should be posted on the issue, not the PR."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": '{"decision": "APPROVE"}'},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": '{"decision": "REVIEW"}'},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(return_value=[])

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        # Verify comment posted on issue 42, not PR 10
        mock_client.create_comment.assert_awaited_once()
        call_args = mock_client.create_comment.call_args
        assert call_args[0][0] == "owner/repo"
        assert call_args[0][1] == 42  # issue number, not PR number

    async def test_labels_top_pr(self) -> None:
        """Top PR should get recommended label, others superseded."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": '{"decision": "APPROVE"}'},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": '{"decision": "REVIEW"}'},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(return_value=[])

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        # Verify ensure_label called for both labels
        ensure_calls = mock_client.ensure_label.call_args_list
        assert len(ensure_calls) == 2

        # Verify add_label called for top PR with recommended
        add_calls = mock_client.add_label.call_args_list
        assert any(
            c[0] == ("owner/repo", 10, 1, "saltax-recommended")
            for c in add_calls
        )
        # Verify add_label called for second PR with superseded
        assert any(
            c[0] == ("owner/repo", 20, 1, "superseded")
            for c in add_calls
        )

    async def test_records_timestamp(self) -> None:
        """After posting, should record the update for rate limiting."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": '{"decision": "APPROVE"}'},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": '{"decision": "REVIEW"}'},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(return_value=[])

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        mock_db.record_ranking_update.assert_awaited_once()
        call_args = mock_db.record_ranking_update.call_args
        assert call_args[0][0] == "owner/repo"
        assert call_args[0][1] == 42

    async def test_github_error_swallowed(self) -> None:
        """GitHub API errors should be caught, not propagated."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": "{}"},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": "{}"},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(return_value=[])
        mock_client.create_comment = AsyncMock(side_effect=RuntimeError("GitHub down"))

        # Should not raise
        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

    async def test_updates_existing_comment(self) -> None:
        """GAP 2: When existing comment with marker found → update, not create."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": '{"decision": "APPROVE"}'},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": '{"decision": "REVIEW"}'},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(return_value=[
            {"id": 999, "body": "<!-- saltax-ranking:owner/repo:42 -->\n## old"},
        ])

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        mock_client.update_comment.assert_awaited_once()
        assert mock_client.update_comment.call_args[0][1] == 999
        mock_client.create_comment.assert_not_awaited()

    async def test_creates_new_when_no_existing(self) -> None:
        """GAP 2: When no matching marker → create new comment."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": '{"decision": "APPROVE"}'},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": '{"decision": "REVIEW"}'},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(return_value=[
            {"id": 111, "body": "Some unrelated comment"},
        ])

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        mock_client.create_comment.assert_awaited_once()
        mock_client.update_comment.assert_not_awaited()

    async def test_list_comments_failure_falls_back_to_create(self) -> None:
        """GAP 2: list_issue_comments failure → falls back to create_comment."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(return_value=False)
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": '{"decision": "APPROVE"}'},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": '{"decision": "REVIEW"}'},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(
            side_effect=RuntimeError("API error"),
        )

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        mock_client.create_comment.assert_awaited_once()
        mock_client.update_comment.assert_not_awaited()

    async def test_rate_check_failure_continues(self) -> None:
        """If rate limit check fails, should proceed with posting."""
        mock_db = AsyncMock()
        mock_db.was_ranking_recently_posted = AsyncMock(
            side_effect=RuntimeError("DB error"),
        )
        mock_db.get_ranked_prs = AsyncMock(return_value=[
            {"pr_number": 10, "composite_score": 0.9, "pr_author": "alice",
             "verdict": "{}"},
            {"pr_number": 20, "composite_score": 0.7, "pr_author": "bob",
             "verdict": "{}"},
        ])
        mock_client = AsyncMock()
        mock_client.list_issue_comments = AsyncMock(return_value=[])

        await post_ranking_update(
            repo="owner/repo",
            target_issue=42,
            installation_id=1,
            pr_number=10,
            ranking_config=_ranking_config(),
            github_client=mock_client,
            intel_db=mock_db,
        )

        # Should have proceeded to post
        mock_client.create_comment.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════════════════
# D. Ranking DB methods (real SQLite)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRankingDBMethods:
    """Test DB methods with real PostgreSQL — verifies SQL correctness."""

    async def test_ranking_updates_table_exists(
        self, intel_db: IntelligenceDB,
    ) -> None:
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT tablename FROM pg_catalog.pg_tables "
                "WHERE schemaname = 'public' AND tablename = 'ranking_updates'",
            )
            row = await cursor.fetchone()
        assert row is not None

    async def test_record_and_check_recently_posted(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Record an update and verify it's detected as recent."""
        await intel_db.record_ranking_update(
            "owner/repo", 42, "[]",
        )
        result = await intel_db.was_ranking_recently_posted(
            "owner/repo", 42, 3600,
        )
        assert result is True

    async def test_not_recently_posted_when_no_record(
        self, intel_db: IntelligenceDB,
    ) -> None:
        result = await intel_db.was_ranking_recently_posted(
            "owner/repo", 99, 3600,
        )
        assert result is False

    async def test_not_recently_posted_after_interval(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Manually insert an old record and verify it's not considered recent."""
        old_time = (datetime.now(UTC) - timedelta(seconds=7200)).isoformat()
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO ranking_updates "
                "(id, repo, issue_number, updated_at, ranking_json) "
                "VALUES ('old1', 'owner/repo', 42, %s, '[]')",
                (old_time,),
            )

        result = await intel_db.was_ranking_recently_posted(
            "owner/repo", 42, 3600,
        )
        assert result is False

    async def test_get_ranked_prs_ordering(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """PRs should be ranked by composite_score DESC, pr_number ASC."""
        now = datetime.now(UTC).isoformat()
        async with intel_db.pool.connection() as conn:
            # Insert embeddings linked to issue 42
            for pr_num, pr_id in [(10, "owner/repo#10"), (20, "owner/repo#20")]:
                await conn.execute(
                    "INSERT INTO pr_embeddings "
                    "(id, pr_id, repo, pr_number, commit_sha, embedding, "
                    "issue_number, created_at) "
                    "VALUES (%s, %s, 'owner/repo', %s, 'sha', %s, 42, %s)",
                    (f"emb-{pr_num}", pr_id, pr_num, b"\x01", now),
                )

            # Insert pipeline history — PR #20 has higher score
            await conn.execute(
                "INSERT INTO pipeline_history "
                "(id, pr_id, repo, pr_author, verdict, composite_score, "
                "findings_count, created_at) "
                "VALUES ('h1', 'owner/repo#10', 'owner/repo', 'alice', "
                "'{\"decision\": \"REVIEW\"}', 0.70, 0, %s)",
                (now,),
            )
            await conn.execute(
                "INSERT INTO pipeline_history "
                "(id, pr_id, repo, pr_author, verdict, composite_score, "
                "findings_count, created_at) "
                "VALUES ('h2', 'owner/repo#20', 'owner/repo', 'bob', "
                "'{\"decision\": \"APPROVE\"}', 0.90, 0, %s)",
                (now,),
            )

        ranking = await intel_db.get_ranked_prs("owner/repo", 42)
        assert len(ranking) == 2
        # PR #20 (score 0.90) should be ranked first
        assert ranking[0]["pr_number"] == 20
        assert ranking[0]["composite_score"] == 0.90
        assert ranking[1]["pr_number"] == 10

    async def test_latest_run_wins(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """When a PR has multiple pipeline runs, only the latest is used."""
        now = datetime.now(UTC).isoformat()
        later = (datetime.now(UTC) + timedelta(seconds=10)).isoformat()
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO pr_embeddings "
                "(id, pr_id, repo, pr_number, commit_sha, embedding, "
                "issue_number, created_at) "
                "VALUES ('emb-1', 'owner/repo#10', 'owner/repo', 10, 'sha', "
                "%s, 42, %s)",
                (b"\x01", now),
            )

            # First run: low score
            await conn.execute(
                "INSERT INTO pipeline_history "
                "(id, pr_id, repo, pr_author, verdict, composite_score, "
                "findings_count, created_at) "
                "VALUES ('h1', 'owner/repo#10', 'owner/repo', 'alice', "
                "'{\"decision\": \"REVIEW\"}', 0.50, 0, %s)",
                (now,),
            )
            # Second run: high score (later timestamp)
            await conn.execute(
                "INSERT INTO pipeline_history "
                "(id, pr_id, repo, pr_author, verdict, composite_score, "
                "findings_count, created_at) "
                "VALUES ('h2', 'owner/repo#10', 'owner/repo', 'alice', "
                "'{\"decision\": \"APPROVE\"}', 0.95, 0, %s)",
                (later,),
            )

        ranking = await intel_db.get_ranked_prs("owner/repo", 42)
        assert len(ranking) == 1
        # Should use the latest run's score (0.95)
        assert ranking[0]["composite_score"] == 0.95

    async def test_null_score_excluded(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """PRs with NULL composite_score should not appear in ranking."""
        now = datetime.now(UTC).isoformat()
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO pr_embeddings "
                "(id, pr_id, repo, pr_number, commit_sha, embedding, "
                "issue_number, created_at) "
                "VALUES ('emb-1', 'owner/repo#10', 'owner/repo', 10, 'sha', "
                "%s, 42, %s)",
                (b"\x01", now),
            )
            await conn.execute(
                "INSERT INTO pipeline_history "
                "(id, pr_id, repo, pr_author, verdict, composite_score, "
                "findings_count, created_at) "
                "VALUES ('h1', 'owner/repo#10', 'owner/repo', 'alice', "
                "'{}', NULL, 0, %s)",
                (now,),
            )

        ranking = await intel_db.get_ranked_prs("owner/repo", 42)
        assert len(ranking) == 0

    async def test_prunes_old_ranking_rows(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """GAP 3: After 7 inserts, only 5 most recent remain."""
        for i in range(7):
            await intel_db.record_ranking_update(
                "owner/repo", 42, f'[{{"run": {i}}}]',
            )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM ranking_updates "
                "WHERE repo = 'owner/repo' AND issue_number = 42",
            )
            row = await cursor.fetchone()
        assert row["count"] == 5

    async def test_prune_does_not_affect_other_issues(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """GAP 3: Pruning issue 42 doesn't touch issue 99."""
        for _ in range(7):
            await intel_db.record_ranking_update("owner/repo", 42, "[]")
        for _ in range(3):
            await intel_db.record_ranking_update("owner/repo", 99, "[]")

        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM ranking_updates "
                "WHERE repo = 'owner/repo' AND issue_number = 42",
            )
            row = await cursor.fetchone()
        assert row["count"] == 5

        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM ranking_updates "
                "WHERE repo = 'owner/repo' AND issue_number = 99",
            )
            row = await cursor.fetchone()
        assert row["count"] == 3  # untouched

    async def test_tiebreaker_by_pr_number(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """PRs with same score should be ordered by pr_number ASC."""
        now = datetime.now(UTC).isoformat()
        async with intel_db.pool.connection() as conn:
            for pr_num in [30, 10, 20]:
                pr_id = f"owner/repo#{pr_num}"
                await conn.execute(
                    "INSERT INTO pr_embeddings "
                    "(id, pr_id, repo, pr_number, commit_sha, embedding, "
                    "issue_number, created_at) "
                    "VALUES (%s, %s, 'owner/repo', %s, 'sha', %s, 42, %s)",
                    (f"emb-{pr_num}", pr_id, pr_num, b"\x01", now),
                )
                await conn.execute(
                    "INSERT INTO pipeline_history "
                    "(id, pr_id, repo, pr_author, verdict, composite_score, "
                    "findings_count, created_at) "
                    "VALUES (%s, %s, 'owner/repo', 'dev', '{}', 0.80, 0, %s)",
                    (f"h-{pr_num}", pr_id, now),
                )

        ranking = await intel_db.get_ranked_prs("owner/repo", 42)
        assert len(ranking) == 3
        # Same score → ordered by pr_number ASC: 10, 20, 30
        assert ranking[0]["pr_number"] == 10
        assert ranking[1]["pr_number"] == 20
        assert ranking[2]["pr_number"] == 30
