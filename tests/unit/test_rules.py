"""Tests for the custom review rules feature (Feature 36).

Covers: parser, models, cache, prompt formatting, loading, config defaults,
and prompt builder integration.
"""

from __future__ import annotations

import textwrap
import time
from unittest.mock import AsyncMock

import pytest

from src.config import SaltaXConfig
from src.rules.cache import cache_rules, clear_cache, get_cached_rules, invalidate_cache
from src.rules.loader import parse_rules_file
from src.rules.models import ReviewRule, RuleSet
from src.rules.prompt import _slugify, format_rules_for_prompt

# ── Fixtures ────────────────────────────────────────────────────────────────

SAMPLE_RULES_MD = textwrap.dedent("""\
    # Custom Review Rules

    ## No console.log in production
    **Severity:** HIGH
    **Scope:** src/**/*.ts, src/**/*.js
    **Description:** Remove all console.log statements before merging.

    ## Use parameterized queries
    **Severity:** MEDIUM
    **Scope:** src/db/**/*.py
    **Description:** Never use f-strings or string concatenation in SQL queries.

    ## Add docstrings to public functions
    **Severity:** LOW
    **Description:** All exported functions must have a docstring.
""")


@pytest.fixture(autouse=True)
def _clear_rules_cache():
    """Ensure a clean cache for every test."""
    clear_cache()
    yield
    clear_cache()


# ── TestParseRulesFile ──────────────────────────────────────────────────────


class TestParseRulesFile:
    def test_basic_rules(self):
        ruleset = parse_rules_file(SAMPLE_RULES_MD, "owner/repo")
        assert len(ruleset.rules) == 3
        assert ruleset.repo == "owner/repo"
        assert ruleset.source == ".saltax/rules.md"

        r0 = ruleset.rules[0]
        assert r0.name == "No console.log in production"
        assert r0.severity == "HIGH"
        assert r0.scope_patterns == ("src/**/*.ts", "src/**/*.js")
        assert "console.log" in r0.description

        r1 = ruleset.rules[1]
        assert r1.severity == "MEDIUM"
        assert r1.scope_patterns == ("src/db/**/*.py",)

        r2 = ruleset.rules[2]
        assert r2.severity == "LOW"
        assert r2.scope_patterns == ()  # unscoped

    def test_missing_fields(self):
        content = "## My Rule\nJust some text, no structured fields.\n"
        ruleset = parse_rules_file(content, "owner/repo")
        assert len(ruleset.rules) == 1
        r = ruleset.rules[0]
        assert r.name == "My Rule"
        assert r.severity == "MEDIUM"  # default
        assert r.scope_patterns == ()
        assert r.description == ""

    def test_invalid_severity(self):
        content = "## Bad Severity\n**Severity:** URGENT\n"
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.rules[0].severity == "MEDIUM"

    def test_max_rules_cap(self):
        sections = [f"## Rule {i}\n**Severity:** LOW\n" for i in range(60)]
        content = "\n".join(sections)
        ruleset = parse_rules_file(content, "owner/repo", max_rules=50)
        assert len(ruleset.rules) == 50

    def test_description_truncation(self):
        long_desc = "A" * 1000
        content = f"## Long Desc\n**Description:** {long_desc}\n"
        ruleset = parse_rules_file(content, "owner/repo", max_description_chars=100)
        assert len(ruleset.rules[0].description) == 100

    def test_empty_content(self):
        ruleset = parse_rules_file("", "owner/repo")
        assert ruleset.rules == []

    def test_no_headers(self):
        content = "Just some text without any ## headers."
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.rules == []

    def test_multiple_scopes(self):
        content = "## Multi Scope\n**Scope:** src/api/**/*.py, src/core/**/*.py\n"
        ruleset = parse_rules_file(content, "owner/repo")
        assert ruleset.rules[0].scope_patterns == (
            "src/api/**/*.py",
            "src/core/**/*.py",
        )


# ── TestRuleSet ─────────────────────────────────────────────────────────────


class TestRuleSet:
    def test_rules_for_files_unscoped(self):
        rule = ReviewRule(name="Unscoped", severity="LOW")
        rs = RuleSet(repo="r", rules=[rule])
        matched = rs.rules_for_files(["anything.py"])
        assert matched == [rule]

    def test_rules_for_files_scoped_match(self):
        rule = ReviewRule(
            name="API rule",
            severity="HIGH",
            scope_patterns=("src/api/**/*.py",),
        )
        rs = RuleSet(repo="r", rules=[rule])
        matched = rs.rules_for_files(["src/api/routes/users.py"])
        assert matched == [rule]

    def test_rules_for_files_scoped_no_match(self):
        rule = ReviewRule(
            name="API rule",
            severity="HIGH",
            scope_patterns=("src/api/**/*.py",),
        )
        rs = RuleSet(repo="r", rules=[rule])
        matched = rs.rules_for_files(["src/core/models.py"])
        assert matched == []

    def test_disabled_rules_excluded(self):
        r1 = ReviewRule(name="Active", severity="HIGH")
        r2 = ReviewRule(name="Disabled", severity="LOW", enabled=False)
        rs = RuleSet(repo="r", rules=[r1, r2])
        assert rs.active_rules == [r1]
        assert rs.rules_for_files(["any.py"]) == [r1]


# ── TestSlugify ─────────────────────────────────────────────────────────────


class TestSlugify:
    def test_basic(self):
        assert _slugify("No raw SQL") == "no-raw-sql"

    def test_special_chars(self):
        assert _slugify("Don't use eval()!") == "don-t-use-eval"

    def test_length_cap(self):
        long_name = "a" * 200
        slug = _slugify(long_name)
        assert len(slug) <= 80


# ── TestFormatRulesForPrompt ────────────────────────────────────────────────


class TestFormatRulesForPrompt:
    def test_basic_format(self):
        ruleset = parse_rules_file(SAMPLE_RULES_MD, "owner/repo")
        # All files match the unscoped rule; src/api/main.ts matches the TS rule
        result = format_rules_for_prompt(
            ruleset,
            ["src/api/main.ts", "src/db/queries.py"],
        )
        assert "### No console.log in production" in result
        assert "custom:no-console-log-in-production" in result
        assert "### Use parameterized queries" in result
        assert "### Add docstrings to public functions" in result

    def test_scope_filtering(self):
        ruleset = parse_rules_file(SAMPLE_RULES_MD, "owner/repo")
        # Only README.md — only the unscoped rule should match
        result = format_rules_for_prompt(ruleset, ["README.md"])
        assert "### Add docstrings to public functions" in result
        assert "### No console.log in production" not in result
        assert "### Use parameterized queries" not in result

    def test_max_chars_truncation(self):
        # Create many rules to exceed a small budget
        sections = [
            f"## Rule Number {i}\n**Severity:** HIGH\n**Description:** {'X' * 100}\n"
            for i in range(50)
        ]
        content = "\n".join(sections)
        ruleset = parse_rules_file(content, "owner/repo")
        result = format_rules_for_prompt(
            ruleset, ["any.py"], max_chars=500,
        )
        assert "truncated" in result.lower()
        assert len(result) <= 600  # some slack for the truncation message

    def test_empty_ruleset(self):
        rs = RuleSet(repo="r", rules=[])
        result = format_rules_for_prompt(rs, ["any.py"])
        assert result == ""


# ── TestCache ───────────────────────────────────────────────────────────────


class TestCache:
    def test_cache_hit(self):
        rs = RuleSet(repo="owner/repo", rules=[ReviewRule(name="R", severity="LOW")])
        cache_rules("owner/repo", rs)
        cached = get_cached_rules("owner/repo", ttl_seconds=3600)
        assert cached is rs

    def test_cache_expired(self, monkeypatch):
        rs = RuleSet(repo="owner/repo")
        cache_rules("owner/repo", rs)

        # Fast-forward time beyond TTL
        original_monotonic = time.monotonic
        monkeypatch.setattr(
            time, "monotonic", lambda: original_monotonic() + 4000,
        )
        cached = get_cached_rules("owner/repo", ttl_seconds=3600)
        assert cached is None

    def test_invalidate(self):
        rs = RuleSet(repo="owner/repo")
        cache_rules("owner/repo", rs)
        invalidate_cache("owner/repo")
        assert get_cached_rules("owner/repo", ttl_seconds=3600) is None


# ── TestBuildUserPrompt ─────────────────────────────────────────────────────


class TestBuildUserPrompt:
    def test_with_custom_rules(self):
        from src.pipeline.prompts import build_analyzer_user_prompt

        result = build_analyzer_user_prompt(
            diff="diff --git a/test.py",
            static_findings=[],
            intel_matches=[],
            custom_rules_text="### No eval\n- Severity: HIGH\n- Rule ID to use: custom:no-eval",
        )
        assert "Custom Review Rules" in result
        assert "custom:no-eval" in result

    def test_without_custom_rules(self):
        from src.pipeline.prompts import build_analyzer_user_prompt

        result = build_analyzer_user_prompt(
            diff="diff --git a/test.py",
            static_findings=[],
            intel_matches=[],
            custom_rules_text=None,
        )
        assert "Custom Review Rules" not in result

    def test_rules_truncation(self):
        from src.pipeline.prompts import build_analyzer_user_prompt

        long_rules = "X" * 10000
        result = build_analyzer_user_prompt(
            diff="diff --git a/test.py",
            static_findings=[],
            intel_matches=[],
            custom_rules_text=long_rules,
            max_custom_rules_chars=500,
        )
        assert "remaining rules truncated" in result

    def test_rules_between_static_and_intel(self):
        """Custom rules section appears between static findings and intel matches."""
        from src.pipeline.prompts import build_analyzer_user_prompt

        result = build_analyzer_user_prompt(
            diff="diff --git a/test.py",
            static_findings=[
                {"severity": "HIGH", "rule_id": "S001", "message": "test", "file_path": "a.py"},
            ],
            intel_matches=[{"pattern": "xss", "description": "cross-site scripting"}],
            custom_rules_text="### My Rule\n- custom:my-rule",
        )
        static_idx = result.index("Static Analysis Findings")
        rules_idx = result.index("Custom Review Rules")
        intel_idx = result.index("Known Pattern Matches")
        assert static_idx < rules_idx < intel_idx


# ── TestLoadRulesForRepo ────────────────────────────────────────────────────


class TestLoadRulesForRepo:
    async def test_success(self):
        from src.config import RulesConfig
        from src.rules.loader import load_rules_for_repo

        mock_client = AsyncMock()
        mock_client.get_file_contents.return_value = SAMPLE_RULES_MD

        ruleset = await load_rules_for_repo(
            repo="owner/repo",
            installation_id=12345,
            github_client=mock_client,
            rules_config=RulesConfig(),
        )
        assert ruleset is not None
        assert len(ruleset.rules) == 3
        mock_client.get_file_contents.assert_awaited_once_with(
            "owner/repo",
            ".saltax/rules.md",
            installation_id=12345,
        )

    async def test_file_not_found(self):
        from src.config import RulesConfig
        from src.rules.loader import load_rules_for_repo

        mock_client = AsyncMock()
        mock_client.get_file_contents.return_value = None

        ruleset = await load_rules_for_repo(
            repo="owner/repo",
            installation_id=12345,
            github_client=mock_client,
            rules_config=RulesConfig(),
        )
        assert ruleset is None

    async def test_disabled(self):
        from src.config import RulesConfig
        from src.rules.loader import load_rules_for_repo

        mock_client = AsyncMock()

        ruleset = await load_rules_for_repo(
            repo="owner/repo",
            installation_id=12345,
            github_client=mock_client,
            rules_config=RulesConfig(enabled=False),
        )
        assert ruleset is None
        mock_client.get_file_contents.assert_not_awaited()


# ── TestRulesConfig ─────────────────────────────────────────────────────────


class TestRulesConfig:
    def test_defaults(self):
        cfg = SaltaXConfig()
        assert cfg.rules.enabled is True
        assert cfg.rules.rules_file_path == ".saltax/rules.md"
        assert cfg.rules.max_rules_per_repo == 50
        assert cfg.rules.max_rule_description_chars == 500
        assert cfg.rules.cache_ttl_seconds == 3600
        assert cfg.rules.max_prompt_chars == 6000
