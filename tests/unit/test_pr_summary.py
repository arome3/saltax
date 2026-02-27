"""Unit tests for the PR summary builder (src/github/summary.py).

All builder functions are pure — no DB, no network, no monkeypatching needed.
The async ``post_or_update_summary`` tests use ``AsyncMock``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from src.github.summary import (
    _MAX_COMMENT_LENGTH,
    _MAX_FINDINGS_DISPLAYED,
    _build_file_risk_heatmap,
    _build_findings_detail,
    _build_module_diagram,
    _build_score_waterfall,
    _build_stage_results,
    _extract_changed_files,
    _truncate_path,
    build_pr_summary,
    post_or_update_summary,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────

SAMPLE_DIFF = """\
diff --git a/src/foo.py b/src/foo.py
index abc..def 100644
--- a/src/foo.py
+++ b/src/foo.py
@@ -1,3 +1,4 @@
+import os
 def foo():
     pass

diff --git a/src/bar.py b/src/bar.py
index 111..222 100644
--- a/src/bar.py
+++ b/src/bar.py
@@ -1 +1,2 @@
+# new comment
 x = 1

diff --git a/tests/test_baz.py b/tests/test_baz.py
index 333..444 100644
--- a/tests/test_baz.py
+++ b/tests/test_baz.py
@@ -0,0 +1,5 @@
+def test_baz():
+    assert True
"""

SAMPLE_FINDINGS = [
    {
        "file_path": "src/foo.py",
        "severity": "HIGH",
        "rule_id": "S101",
        "line_start": 10,
        "message": "Use of assert detected",
        "confidence": "HIGH",
    },
    {
        "file_path": "src/foo.py",
        "severity": "MEDIUM",
        "rule_id": "S102",
        "line_start": 20,
        "message": "Exec used",
        "confidence": "MEDIUM",
    },
    {
        "file_path": "src/bar.py",
        "severity": "CRITICAL",
        "rule_id": "S301",
        "line_start": 5,
        "message": "Pickle usage",
        "confidence": "HIGH",
    },
]

SAMPLE_VERDICT = {
    "decision": "APPROVE",
    "composite_score": 0.85,
    "threshold_used": 0.70,
    "score_breakdown": {
        "static_clear": 0.15,
        "ai_quality": 0.25,
        "ai_security": 0.20,
        "tests_pass": 0.25,
    },
}


# ── TestExtractChangedFiles ──────────────────────────────────────────────────


class TestExtractChangedFiles:
    def test_basic_diff(self) -> None:
        files = _extract_changed_files(SAMPLE_DIFF)
        assert files == ["src/foo.py", "src/bar.py", "tests/test_baz.py"]

    def test_empty_diff(self) -> None:
        assert _extract_changed_files("") == []

    def test_rename(self) -> None:
        """Uses b/ (new) path, not a/ (old) path."""
        diff = "diff --git a/old_name.py b/new_name.py\n"
        files = _extract_changed_files(diff)
        assert files == ["new_name.py"]

    def test_dedup(self) -> None:
        """Same file appearing twice yields a single entry."""
        diff = (
            "diff --git a/f.py b/f.py\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "diff --git a/f.py b/f.py\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
        )
        files = _extract_changed_files(diff)
        assert files == ["f.py"]


# ── TestTruncatePath ─────────────────────────────────────────────────────────


class TestTruncatePath:
    def test_long_path(self) -> None:
        assert _truncate_path("a/b/c/d.py", segments=3) == "b/c/d.py"

    def test_short_path(self) -> None:
        assert _truncate_path("d.py") == "d.py"

    def test_exact_segments(self) -> None:
        assert _truncate_path("a/b/c.py", segments=3) == "a/b/c.py"


# ── TestBuildScoreWaterfall ──────────────────────────────────────────────────


class TestBuildScoreWaterfall:
    def test_all_stages(self) -> None:
        breakdown = {
            "static_clear": 0.15,
            "ai_quality": 0.25,
            "ai_security": 0.20,
            "tests_pass": 0.25,
        }
        result = _build_score_waterfall(breakdown)
        assert "xychart-beta" in result
        assert '"Static"' in result
        assert '"AI Quality"' in result
        assert '"Tests"' in result
        assert "0.15" in result
        assert "0.25" in result

    def test_empty_breakdown(self) -> None:
        assert _build_score_waterfall({}) == ""

    def test_subset_stages(self) -> None:
        result = _build_score_waterfall({"static_clear": 0.3})
        assert "xychart-beta" in result
        assert '"Static"' in result
        # Only one label
        assert '"AI Quality"' not in result

    def test_y_axis_headroom(self) -> None:
        """Max value * 1.2 gives headroom."""
        result = _build_score_waterfall({"static_clear": 0.50})
        # 0.50 * 1.2 = 0.60
        assert "0.60" in result

    def test_y_axis_minimum(self) -> None:
        """Very small values still get y_max >= 0.30."""
        result = _build_score_waterfall({"static_clear": 0.01})
        # 0.01 * 1.2 = 0.012 < 0.30, so y_max should be 0.30
        assert "0.30" in result

    def test_unknown_keys_ignored(self) -> None:
        """Keys not in _STAGE_DISPLAY are skipped."""
        result = _build_score_waterfall({"unknown_stage": 0.5})
        assert result == ""


# ── TestBuildModuleDiagram ───────────────────────────────────────────────────


class TestBuildModuleDiagram:
    def test_with_json_knowledge(self) -> None:
        files = ["src/a.py", "src/b.py"]
        knowledge = [
            {
                "file_path": "src/a.py",
                "knowledge": '{"imports": ["src/b.py"]}',
            },
        ]
        result = _build_module_diagram(files, knowledge)
        assert result is not None
        assert "graph LR" in result
        assert "a.py" in result
        assert "b.py" in result
        assert "-->" in result

    def test_no_knowledge(self) -> None:
        assert _build_module_diagram(["a.py", "b.py"], []) is None

    def test_single_file_no_edges(self) -> None:
        """Single changed file → not enough nodes."""
        knowledge = [{"file_path": "a.py", "knowledge": "{}"}]
        assert _build_module_diagram(["a.py"], knowledge) is None

    def test_caps_nodes(self) -> None:
        """Maximum 10 nodes even with 15+ files."""
        files = [f"src/f{i}.py" for i in range(15)]
        knowledge = [
            {
                "file_path": files[0],
                "knowledge": f'{{"imports": ["{files[1]}"]}}',
            },
        ]
        result = _build_module_diagram(files, knowledge)
        assert result is not None
        # Should only have N0..N9
        assert "N10" not in result

    def test_non_json_knowledge(self) -> None:
        """Plain text knowledge is handled gracefully."""
        files = ["src/a.py", "src/b.py"]
        knowledge = [
            {"file_path": "src/a.py", "knowledge": "This is a utility module."},
        ]
        # No edges extracted → but we still have 2 files, so graph may render
        # with just nodes. Actually, 2 nodes + 0 edges → still renders.
        result = _build_module_diagram(files, knowledge)
        # 2 files, no edges from non-JSON knowledge → still builds the diagram
        assert result is not None
        assert "graph LR" in result

    def test_knowledge_already_dict(self) -> None:
        """When psycopg3 auto-deserializes JSONB, knowledge is already a dict."""
        files = ["src/a.py", "src/b.py"]
        knowledge = [
            {
                "file_path": "src/a.py",
                "knowledge": {"imports": ["src/b.py"]},
            },
        ]
        result = _build_module_diagram(files, knowledge)
        assert result is not None
        assert "-->" in result


# ── TestBuildFileRiskHeatmap ─────────────────────────────────────────────────


class TestBuildFileRiskHeatmap:
    def test_with_findings(self) -> None:
        files = ["src/foo.py", "src/bar.py"]
        result = _build_file_risk_heatmap(files, SAMPLE_FINDINGS)
        assert ":orange_circle:" in result  # HIGH for src/foo.py
        assert ":red_circle:" in result  # CRITICAL for src/bar.py
        assert "foo.py" in result
        assert "bar.py" in result

    def test_clean_files(self) -> None:
        files = ["src/clean.py"]
        result = _build_file_risk_heatmap(files, [])
        assert ":green_circle:" in result
        assert "clean.py" in result

    def test_severity_ordering(self) -> None:
        """File with mixed severities shows the highest as the icon."""
        files = ["src/foo.py"]
        # src/foo.py has HIGH and MEDIUM findings
        result = _build_file_risk_heatmap(files, SAMPLE_FINDINGS)
        # The icon should be :orange_circle: (HIGH), not :yellow_circle: (MEDIUM)
        lines = result.split("\n")
        foo_line = [ln for ln in lines if "foo.py" in ln][0]
        assert ":orange_circle:" in foo_line


# ── TestBuildStageResults ────────────────────────────────────────────────────


class TestBuildStageResults:
    def test_full_pipeline(self) -> None:
        ai = {
            "quality_score": 8.5,
            "risk_score": 3.2,
            "architectural_fit": 0.9,
            "security_concerns": ["XSS risk"],
        }
        tests = {
            "status": "PASSED",
            "passed_tests": 42,
            "total_tests": 45,
            "coverage_percent": 87,
        }
        result = _build_stage_results(SAMPLE_FINDINGS, ai, tests, 0.75)
        assert "8.5" in result
        assert "3.2" in result
        assert "42/45" in result
        assert "87%" in result
        assert "0.75" in result
        assert "Vision" in result

    def test_no_ai(self) -> None:
        result = _build_stage_results([], None, None, None)
        assert result.count("N/A") >= 3  # AI Quality, AI Security, Tests

    def test_no_tests(self) -> None:
        ai = {"quality_score": 7.0, "risk_score": 2.0}
        result = _build_stage_results([], ai, None, None)
        assert "7.0" in result
        # Tests row should show N/A
        lines = result.split("\n")
        tests_line = [ln for ln in lines if "Tests" in ln][0]
        assert "N/A" in tests_line

    def test_no_vision(self) -> None:
        """Vision row omitted when score is None."""
        result = _build_stage_results([], None, None, None)
        assert "Vision" not in result


# ── TestBuildFindingsDetail ──────────────────────────────────────────────────


class TestBuildFindingsDetail:
    def test_renders_table(self) -> None:
        result = _build_findings_detail(SAMPLE_FINDINGS)
        assert "<details>" in result
        assert "</details>" in result
        assert "S101" in result
        assert "S301" in result

    def test_sorted_by_severity(self) -> None:
        """CRITICAL first, then HIGH, then MEDIUM."""
        result = _build_findings_detail(SAMPLE_FINDINGS)
        lines = result.split("\n")
        data_lines = [ln for ln in lines if ln.startswith("| ") and not ln.startswith("| #")]
        # First data line should be CRITICAL (S301)
        assert "CRITICAL" in data_lines[0]

    def test_caps_at_max(self) -> None:
        """Truncation at _MAX_FINDINGS_DISPLAYED."""
        many_findings = [
            {
                "file_path": f"f{i}.py",
                "severity": "LOW",
                "rule_id": f"R{i}",
                "line_start": i,
                "message": f"Finding {i}",
                "confidence": "LOW",
            }
            for i in range(_MAX_FINDINGS_DISPLAYED + 10)
        ]
        result = _build_findings_detail(many_findings)
        assert "and 10 more" in result

    def test_empty_findings(self) -> None:
        assert _build_findings_detail([]) == ""


# ── TestBuildPrSummary ───────────────────────────────────────────────────────


class TestBuildPrSummary:
    def test_full_summary(self) -> None:
        body = build_pr_summary(
            repo="owner/repo",
            pr_number=42,
            diff=SAMPLE_DIFF,
            static_findings=SAMPLE_FINDINGS,
            ai_analysis={
                "quality_score": 8.0,
                "risk_score": 2.5,
                "security_concerns": [],
            },
            test_results={
                "status": "PASSED",
                "passed_tests": 10,
                "total_tests": 10,
                "coverage_percent": 95,
            },
            verdict=SAMPLE_VERDICT,
            attestation_id="attest-123",
            score_breakdown=SAMPLE_VERDICT["score_breakdown"],
        )
        assert "<!-- saltax-summary:owner/repo:42 -->" in body
        assert "SaltaX Analysis Summary" in body
        assert "APPROVE" in body
        assert "xychart-beta" in body
        assert "File Risk Heatmap" in body
        assert "Stage Results" in body
        assert "<details>" in body
        assert "attest-123" in body

    def test_no_findings(self) -> None:
        body = build_pr_summary(
            repo="owner/repo",
            pr_number=1,
            diff=SAMPLE_DIFF,
            static_findings=[],
            ai_analysis=None,
            test_results=None,
            verdict={"decision": "APPROVE", "composite_score": 0.9, "threshold_used": 0.7},
            attestation_id="attest-456",
        )
        assert "<details>" not in body
        assert ":green_circle:" in body

    def test_no_ai_no_tests(self) -> None:
        body = build_pr_summary(
            repo="owner/repo",
            pr_number=2,
            diff=SAMPLE_DIFF,
            static_findings=[],
            ai_analysis=None,
            test_results=None,
            verdict={"decision": "REJECT", "composite_score": 0.3, "threshold_used": 0.7},
            attestation_id="",
        )
        assert "N/A" in body
        assert "REJECT" in body

    def test_truncation(self) -> None:
        """Body exceeding _MAX_COMMENT_LENGTH is truncated with a note."""
        huge_findings = [
            {
                "file_path": f"src/{'x' * 200}/f{i}.py",
                "severity": "LOW",
                "rule_id": f"R{i}",
                "line_start": i,
                "message": "A" * 2000,
                "confidence": "LOW",
            }
            for i in range(200)
        ]
        body = build_pr_summary(
            repo="owner/repo",
            pr_number=99,
            diff=SAMPLE_DIFF,
            static_findings=huge_findings,
            ai_analysis=None,
            test_results=None,
            verdict=SAMPLE_VERDICT,
            attestation_id="attest-big",
            score_breakdown=SAMPLE_VERDICT["score_breakdown"],
        )
        assert len(body) <= _MAX_COMMENT_LENGTH
        assert "truncated" in body

    def test_module_diagram_included(self) -> None:
        """Module diagram shows when knowledge + multiple files."""
        body = build_pr_summary(
            repo="owner/repo",
            pr_number=5,
            diff=SAMPLE_DIFF,
            static_findings=[],
            ai_analysis=None,
            test_results=None,
            verdict=SAMPLE_VERDICT,
            attestation_id="attest-mod",
            codebase_knowledge=[
                {
                    "file_path": "src/foo.py",
                    "knowledge": '{"imports": ["src/bar.py"]}',
                },
            ],
        )
        assert "Module Dependencies" in body
        assert "graph LR" in body

    def test_no_module_diagram_without_knowledge(self) -> None:
        body = build_pr_summary(
            repo="owner/repo",
            pr_number=6,
            diff=SAMPLE_DIFF,
            static_findings=[],
            ai_analysis=None,
            test_results=None,
            verdict=SAMPLE_VERDICT,
            attestation_id="",
        )
        assert "Module Dependencies" not in body


# ── TestPostOrUpdateSummary ──────────────────────────────────────────────────


class TestPostOrUpdateSummary:
    async def test_creates_new(self) -> None:
        client = MagicMock()
        client.list_issue_comments = AsyncMock(return_value=[])
        client.create_comment = AsyncMock(return_value={"id": 1})

        await post_or_update_summary(
            repo="owner/repo",
            pr_number=10,
            installation_id=999,
            summary_body="test body",
            github_client=client,
        )

        client.list_issue_comments.assert_awaited_once_with(
            "owner/repo", 10, 999,
        )
        client.create_comment.assert_awaited_once_with(
            "owner/repo", 10, 999, "test body",
        )

    async def test_updates_existing(self) -> None:
        marker = "<!-- saltax-summary:owner/repo:10 -->"
        client = MagicMock()
        client.list_issue_comments = AsyncMock(
            return_value=[{"id": 42, "body": f"old content\n{marker}\nold"}],
        )
        client.update_comment = AsyncMock(return_value={"id": 42})

        await post_or_update_summary(
            repo="owner/repo",
            pr_number=10,
            installation_id=999,
            summary_body="new body",
            github_client=client,
        )

        client.update_comment.assert_awaited_once_with(
            "owner/repo", 42, 999, "new body",
        )

    async def test_handles_422_error(self) -> None:
        """422 (PR closed/merged) is logged as warning, not raised."""
        exc = Exception("Unprocessable")
        exc.status_code = 422  # type: ignore[attr-defined]
        client = MagicMock()
        client.list_issue_comments = AsyncMock(side_effect=exc)

        # Should not raise
        await post_or_update_summary(
            repo="owner/repo",
            pr_number=10,
            installation_id=999,
            summary_body="body",
            github_client=client,
        )

    async def test_handles_other_error(self) -> None:
        """Non-422 errors are logged, not raised."""
        client = MagicMock()
        client.list_issue_comments = AsyncMock(side_effect=RuntimeError("Network"))

        # Should not raise
        await post_or_update_summary(
            repo="owner/repo",
            pr_number=10,
            installation_id=999,
            summary_body="body",
            github_client=client,
        )
