"""Tests for feedback reaction handler: pure helpers and collection logic."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.feedback.reaction_handler import (
    collect_reactions_for_pr,
    extract_rule_ids,
    is_saltax_comment,
)

_ = pytest  # ensure pytest is used (fixture injection)


# =============================================================================
# A. extract_rule_ids
# =============================================================================


class TestExtractRuleIds:
    def test_with_markers(self) -> None:
        body = "some text\n<!-- saltax-findings:rule-a,rule-b,rule-c -->\nmore"
        assert extract_rule_ids(body) == ["rule-a", "rule-b", "rule-c"]

    def test_single_rule(self) -> None:
        body = "<!-- saltax-findings:semgrep.xss -->"
        assert extract_rule_ids(body) == ["semgrep.xss"]

    def test_no_marker(self) -> None:
        body = "This is a regular comment without markers."
        assert extract_rule_ids(body) == []

    def test_empty_body(self) -> None:
        assert extract_rule_ids("") == []

    def test_empty_marker(self) -> None:
        body = "<!-- saltax-findings: -->"
        assert extract_rule_ids(body) == []

    def test_strips_whitespace(self) -> None:
        body = "<!-- saltax-findings: rule-a , rule-b -->"
        result = extract_rule_ids(body)
        assert result == ["rule-a", "rule-b"]


# =============================================================================
# B. is_saltax_comment
# =============================================================================


class TestIsSaltaxComment:
    def test_true(self) -> None:
        body = "<!-- saltax-advisory:owner/repo:42 -->\n## SaltaX Advisory"
        assert is_saltax_comment(body) is True

    def test_false(self) -> None:
        assert is_saltax_comment("Just a regular comment") is False

    def test_none(self) -> None:
        assert is_saltax_comment(None) is False

    def test_empty(self) -> None:
        assert is_saltax_comment("") is False


# =============================================================================
# C. collect_reactions_for_pr
# =============================================================================


def _make_comment(
    comment_id: int,
    *,
    is_advisory: bool = True,
    rule_ids: list[str] | None = None,
) -> dict:
    """Build a mock comment dict."""
    parts = []
    if is_advisory:
        parts.append("<!-- saltax-advisory:owner/repo:1 -->")
    parts.append("## SaltaX Advisory")
    if rule_ids:
        parts.append(f"<!-- saltax-findings:{','.join(rule_ids)} -->")
    return {"id": comment_id, "body": "\n".join(parts)}


def _make_reaction(login: str, content: str) -> dict:
    return {"user": {"login": login}, "content": content}


class TestCollectReactionsForPr:
    async def test_records_new_signals(self) -> None:
        """Happy path: thumbsup reaction → record_feedback_signal called."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=["rule-a"])],
        )
        github_client.get_comment_reactions = AsyncMock(
            return_value=[_make_reaction("alice", "+1")],
        )

        intel_db = AsyncMock()
        intel_db.record_feedback_signal = AsyncMock(return_value=True)

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 1
        intel_db.record_feedback_signal.assert_awaited_once_with(
            rule_id="rule-a",
            repo="owner/repo",
            pr_number=1,
            comment_id=100,
            reactor_login="alice",
            reaction="+1",
        )

    async def test_multiple_rules_multiple_reactions(self) -> None:
        """Two rules × two reactions = 4 signals."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=["rule-a", "rule-b"])],
        )
        github_client.get_comment_reactions = AsyncMock(
            return_value=[
                _make_reaction("alice", "+1"),
                _make_reaction("bob", "-1"),
            ],
        )

        intel_db = AsyncMock()
        intel_db.record_feedback_signal = AsyncMock(return_value=True)

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 4
        assert intel_db.record_feedback_signal.await_count == 4

    async def test_dedup_signals(self) -> None:
        """Duplicate signal (record returns False) → not counted."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=["rule-a"])],
        )
        github_client.get_comment_reactions = AsyncMock(
            return_value=[_make_reaction("alice", "+1")],
        )

        intel_db = AsyncMock()
        intel_db.record_feedback_signal = AsyncMock(return_value=False)

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 0

    async def test_skips_bots(self) -> None:
        """Reactor ending with [bot] is skipped."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=["rule-a"])],
        )
        github_client.get_comment_reactions = AsyncMock(
            return_value=[_make_reaction("dependabot[bot]", "+1")],
        )

        intel_db = AsyncMock()

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 0
        intel_db.record_feedback_signal.assert_not_awaited()

    async def test_skips_non_saltax_comments(self) -> None:
        """Comments without advisory marker are ignored."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[{"id": 100, "body": "Regular comment"}],
        )
        github_client.get_comment_reactions = AsyncMock()

        intel_db = AsyncMock()

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 0
        github_client.get_comment_reactions.assert_not_awaited()

    async def test_skips_no_finding_markers(self) -> None:
        """SaltaX comments without saltax-findings marker (old format)."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=None)],
        )
        github_client.get_comment_reactions = AsyncMock()

        intel_db = AsyncMock()

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 0
        github_client.get_comment_reactions.assert_not_awaited()

    async def test_handles_github_error(self) -> None:
        """list_issue_comments raises → returns 0, no crash."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            side_effect=RuntimeError("API down"),
        )

        intel_db = AsyncMock()

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 0

    async def test_disabled(self) -> None:
        """enabled=False → returns 0 immediately."""
        github_client = AsyncMock()
        intel_db = AsyncMock()

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
            enabled=False,
        )

        assert result == 0
        github_client.list_issue_comments.assert_not_awaited()

    async def test_positive_reaction_variants(self) -> None:
        """heart and rocket map to +1 signal."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=["rule-a"])],
        )
        github_client.get_comment_reactions = AsyncMock(
            return_value=[
                _make_reaction("alice", "heart"),
                _make_reaction("bob", "rocket"),
            ],
        )

        intel_db = AsyncMock()
        intel_db.record_feedback_signal = AsyncMock(return_value=True)

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 2
        calls = intel_db.record_feedback_signal.call_args_list
        assert all(c.kwargs["reaction"] == "+1" for c in calls)

    async def test_negative_reaction_variants(self) -> None:
        """confused maps to -1 signal."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=["rule-a"])],
        )
        github_client.get_comment_reactions = AsyncMock(
            return_value=[_make_reaction("alice", "confused")],
        )

        intel_db = AsyncMock()
        intel_db.record_feedback_signal = AsyncMock(return_value=True)

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 1
        intel_db.record_feedback_signal.assert_awaited_once()
        assert intel_db.record_feedback_signal.call_args.kwargs["reaction"] == "-1"

    async def test_ignores_irrelevant_reactions(self) -> None:
        """laugh, hooray, eyes are not TP or FP signals."""
        github_client = AsyncMock()
        github_client.list_issue_comments = AsyncMock(
            return_value=[_make_comment(100, rule_ids=["rule-a"])],
        )
        github_client.get_comment_reactions = AsyncMock(
            return_value=[
                _make_reaction("alice", "laugh"),
                _make_reaction("bob", "hooray"),
                _make_reaction("carol", "eyes"),
            ],
        )

        intel_db = AsyncMock()

        result = await collect_reactions_for_pr(
            repo="owner/repo",
            pr_number=1,
            installation_id=123,
            github_client=github_client,
            intel_db=intel_db,
        )

        assert result == 0
        intel_db.record_feedback_signal.assert_not_awaited()
