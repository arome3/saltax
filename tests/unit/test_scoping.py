"""Tests for the path-scoping engine (Feature 39).

Covers: matches_scope(), filter_rules_for_files(), filter_findings_by_changed_files(),
scan configuration parsing, RuleSet scan fields, and prompt per-file applicability.
"""

from __future__ import annotations

import textwrap

from src.rules.loader import parse_rules_file
from src.rules.models import ReviewRule, RuleSet
from src.rules.prompt import format_rules_for_prompt
from src.rules.scoping import (
    filter_findings_by_changed_files,
    filter_rules_for_files,
    matches_scope,
)

# ── TestMatchesScope ────────────────────────────────────────────────────────


class TestMatchesScope:
    def test_empty_scope_matches_all(self):
        assert matches_scope("anything/at/all.py", ()) is True

    def test_include_match(self):
        assert matches_scope("src/api/foo.py", ("src/**/*.py",)) is True

    def test_include_no_match(self):
        assert matches_scope("tests/test_foo.py", ("src/**/*.py",)) is False

    def test_star_single_component(self):
        """``*`` matches a single path component — NOT across ``/`` boundaries."""
        assert matches_scope("src/foo.py", ("src/*.py",)) is True
        assert matches_scope("src/api/foo.py", ("src/*.py",)) is False

    def test_exclude_rejects(self):
        assert matches_scope("tests/test_foo.py", ("!tests/**",)) is False

    def test_exclude_only_allows_others(self):
        """With only excludes, files not matching any exclude are allowed."""
        assert matches_scope("src/foo.py", ("!tests/**",)) is True

    def test_mixed_include_exclude(self):
        patterns = ("src/**/*.py", "!src/generated/**")
        assert matches_scope("src/api/handler.py", patterns) is True
        assert matches_scope("src/generated/proto.py", patterns) is False

    def test_exclude_takes_priority(self):
        """An exclude pattern rejects even if an include would match."""
        patterns = ("**/*.py", "!vendor/**/*.py")
        assert matches_scope("src/main.py", patterns) is True
        assert matches_scope("vendor/lib/util.py", patterns) is False

    def test_backslash_normalization(self):
        assert matches_scope("src\\api\\foo.py", ("src/**/*.py",)) is True

    def test_double_star_recursive(self):
        assert matches_scope("a/b/c/d.sql", ("**/*.sql",)) is True
        assert matches_scope("schema.sql", ("**/*.sql",)) is True

    def test_multiple_include_patterns(self):
        patterns = ("src/**/*.py", "lib/**/*.py")
        assert matches_scope("src/main.py", patterns) is True
        assert matches_scope("lib/utils.py", patterns) is True
        assert matches_scope("tests/test.py", patterns) is False

    def test_multiple_exclude_patterns(self):
        patterns = ("**/*.py", "!tests/**", "!vendor/**")
        assert matches_scope("src/main.py", patterns) is True
        assert matches_scope("tests/test_main.py", patterns) is False
        assert matches_scope("vendor/lib.py", patterns) is False


# ── TestFilterRulesForFiles ─────────────────────────────────────────────────


class TestFilterRulesForFiles:
    def test_global_rule_matches_all_files(self):
        rule = ReviewRule(name="Global", severity="LOW")
        result = filter_rules_for_files([rule], ["a.py", "b.js", "c.rs"])
        assert len(result) == 1
        assert result[0][0] is rule
        assert result[0][1] == ["a.py", "b.js", "c.rs"]

    def test_scoped_rule_matches_subset(self):
        rule = ReviewRule(
            name="Python only",
            severity="HIGH",
            scope_patterns=("src/**/*.py",),
        )
        files = ["src/api/handler.py", "src/api/routes.js", "README.md"]
        result = filter_rules_for_files([rule], files)
        assert len(result) == 1
        assert result[0][1] == ["src/api/handler.py"]

    def test_no_match_excluded(self):
        rule = ReviewRule(
            name="JS only",
            severity="MEDIUM",
            scope_patterns=("**/*.js",),
        )
        result = filter_rules_for_files([rule], ["main.py", "lib.rs"])
        assert result == []

    def test_exclude_pattern_filters(self):
        rule = ReviewRule(
            name="No tests",
            severity="HIGH",
            scope_patterns=("**/*.py", "!tests/**"),
        )
        files = ["src/main.py", "tests/test_main.py", "src/util.py"]
        result = filter_rules_for_files([rule], files)
        assert len(result) == 1
        assert result[0][1] == ["src/main.py", "src/util.py"]

    def test_multiple_rules(self):
        r1 = ReviewRule(name="All", severity="LOW")
        r2 = ReviewRule(name="Py", severity="HIGH", scope_patterns=("**/*.py",))
        r3 = ReviewRule(name="Go", severity="HIGH", scope_patterns=("**/*.go",))
        result = filter_rules_for_files([r1, r2, r3], ["main.py"])
        assert len(result) == 2
        assert result[0][0] is r1
        assert result[1][0] is r2


# ── TestFilterFindingsByChangedFiles ────────────────────────────────────────


class TestFilterFindingsByChangedFiles:
    def test_keeps_matching_findings(self):
        findings = [
            {"file_path": "src/foo.py", "rule_id": "R1"},
            {"file_path": "src/bar.py", "rule_id": "R2"},
        ]
        changed = {"src/foo.py", "src/bar.py"}
        result = filter_findings_by_changed_files(findings, changed)
        assert len(result) == 2

    def test_removes_non_matching(self):
        findings = [
            {"file_path": "src/foo.py", "rule_id": "R1"},
            {"file_path": "lib/old.py", "rule_id": "R2"},
        ]
        changed = {"src/foo.py"}
        result = filter_findings_by_changed_files(findings, changed)
        assert len(result) == 1
        assert result[0]["file_path"] == "src/foo.py"

    def test_strips_leading_dot_slash(self):
        findings = [{"file_path": "./src/foo.py", "rule_id": "R1"}]
        changed = {"src/foo.py"}
        result = filter_findings_by_changed_files(findings, changed)
        assert len(result) == 1

    def test_empty_changed_files(self):
        findings = [{"file_path": "src/foo.py", "rule_id": "R1"}]
        result = filter_findings_by_changed_files(findings, set())
        assert result == []

    def test_empty_findings(self):
        result = filter_findings_by_changed_files([], {"src/foo.py"})
        assert result == []


# ── TestScanConfigParsing ───────────────────────────────────────────────────


class TestScanConfigParsing:
    def test_scan_config_section(self):
        content = textwrap.dedent("""\
            # Rules

            ## Scan Configuration
            **Scan_include:** src/**/*.py, lib/**/*.py
            **Scan_exclude:** vendor/**, node_modules/**
        """)
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.scan_include == ("src/**/*.py", "lib/**/*.py")
        assert ruleset.scan_exclude == ("vendor/**", "node_modules/**")
        assert ruleset.rules == []  # scan config is not a rule

    def test_scan_config_with_rules(self):
        content = textwrap.dedent("""\
            # Custom Rules

            ## Scan Configuration
            **Scan_include:** src/**/*.py

            ## No eval
            **Severity:** HIGH
            **Description:** Never use eval().
        """)
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.scan_include == ("src/**/*.py",)
        assert ruleset.scan_exclude == ()
        assert len(ruleset.rules) == 1
        assert ruleset.rules[0].name == "No eval"

    def test_no_scan_config(self):
        content = textwrap.dedent("""\
            ## Just a rule
            **Severity:** LOW
        """)
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.scan_include == ()
        assert ruleset.scan_exclude == ()
        assert len(ruleset.rules) == 1

    def test_scan_config_include_only(self):
        content = textwrap.dedent("""\
            ## Scan Configuration
            **Scan_include:** contracts/**/*.sol
        """)
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.scan_include == ("contracts/**/*.sol",)
        assert ruleset.scan_exclude == ()

    def test_scan_config_exclude_only(self):
        content = textwrap.dedent("""\
            ## Scan Configuration
            **Scan_exclude:** tests/**, docs/**
        """)
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.scan_include == ()
        assert ruleset.scan_exclude == ("tests/**", "docs/**")


# ── TestRuleSetScanFields ───────────────────────────────────────────────────


class TestRuleSetScanFields:
    def test_scan_include_default(self):
        rs = RuleSet(repo="r")
        assert rs.scan_include == ()

    def test_scan_exclude_default(self):
        rs = RuleSet(repo="r")
        assert rs.scan_exclude == ()

    def test_scan_fields_set(self):
        rs = RuleSet(
            repo="r",
            scan_include=("src/**",),
            scan_exclude=("vendor/**",),
        )
        assert rs.scan_include == ("src/**",)
        assert rs.scan_exclude == ("vendor/**",)

    def test_rules_for_file_uses_matches_scope(self):
        r1 = ReviewRule(name="Py", severity="HIGH", scope_patterns=("src/**/*.py",))
        r2 = ReviewRule(name="All", severity="LOW")
        rs = RuleSet(repo="r", rules=[r1, r2])

        assert rs.rules_for_file("src/api/handler.py") == [r1, r2]
        assert rs.rules_for_file("README.md") == [r2]

    def test_rules_for_files_with_excludes(self):
        rule = ReviewRule(
            name="No vendor",
            severity="HIGH",
            scope_patterns=("**/*.py", "!vendor/**"),
        )
        rs = RuleSet(repo="r", rules=[rule])
        assert rs.rules_for_files(["src/main.py"]) == [rule]
        assert rs.rules_for_files(["vendor/lib.py"]) == []

    def test_rules_for_files_exclude_only(self):
        rule = ReviewRule(
            name="Skip tests",
            severity="MEDIUM",
            scope_patterns=("!tests/**",),
        )
        rs = RuleSet(repo="r", rules=[rule])
        assert rs.rules_for_files(["src/main.py"]) == [rule]
        assert rs.rules_for_files(["tests/test_main.py"]) == []


# ── TestPromptPerFileApplicability ──────────────────────────────────────────


class TestPromptPerFileApplicability:
    def test_format_shows_applicable_files(self):
        ruleset = RuleSet(
            repo="r",
            rules=[
                ReviewRule(
                    name="API check",
                    severity="HIGH",
                    scope_patterns=("src/api/**/*.py",),
                ),
            ],
        )
        result = format_rules_for_prompt(
            ruleset,
            ["src/api/handler.py", "src/api/routes.py", "README.md"],
        )
        assert "Applies to: `src/api/handler.py`, `src/api/routes.py`" in result
        assert "README.md" not in result

    def test_format_truncates_file_list(self):
        ruleset = RuleSet(
            repo="r",
            rules=[ReviewRule(name="All files", severity="LOW")],
        )
        files = [f"src/file{i}.py" for i in range(10)]
        result = format_rules_for_prompt(ruleset, files)
        assert "and 5 more files" in result
        # First 5 files are shown
        for i in range(5):
            assert f"`src/file{i}.py`" in result

    def test_global_rule_shows_all_files(self):
        ruleset = RuleSet(
            repo="r",
            rules=[ReviewRule(name="Global", severity="LOW")],
        )
        files = ["a.py", "b.js"]
        result = format_rules_for_prompt(ruleset, files)
        assert "Applies to: `a.py`, `b.js`" in result

    def test_scope_line_shown_for_scoped_rules(self):
        ruleset = RuleSet(
            repo="r",
            rules=[
                ReviewRule(
                    name="Scoped",
                    severity="HIGH",
                    scope_patterns=("src/**/*.py", "!tests/**"),
                ),
            ],
        )
        result = format_rules_for_prompt(ruleset, ["src/main.py"])
        assert "Scope: src/**/*.py, !tests/**" in result

    def test_no_scope_line_for_global_rules(self):
        ruleset = RuleSet(
            repo="r",
            rules=[ReviewRule(name="Global", severity="LOW")],
        )
        result = format_rules_for_prompt(ruleset, ["a.py"])
        assert "Scope:" not in result
