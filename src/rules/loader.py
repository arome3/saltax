"""Parse ``.saltax/rules.md`` and load rules from GitHub.

The markdown format uses ``## `` headers for rule boundaries and
``**field:**`` markers for structured metadata extraction.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.rules.models import _VALID_SEVERITIES, ReviewRule, RuleSet

if TYPE_CHECKING:
    from src.config import RulesConfig
    from src.github.client import GitHubClient

logger = logging.getLogger(__name__)

# ── Regex patterns for field extraction ──────────────────────────────────────

_RE_SEVERITY = re.compile(r"\*\*[Ss]everity:\*\*\s*(\w+)", re.IGNORECASE)
_RE_SCOPE = re.compile(r"\*\*[Ss]cope:\*\*\s*(.+)", re.IGNORECASE)
_RE_DESCRIPTION = re.compile(
    r"\*\*[Dd]escription:\*\*\s*(.+?)(?=\n\*\*|\Z)", re.DOTALL
)
_RE_SCAN_INCLUDE = re.compile(r"\*\*[Ss]can_include:\*\*\s*(.+)", re.IGNORECASE)
_RE_SCAN_EXCLUDE = re.compile(r"\*\*[Ss]can_exclude:\*\*\s*(.+)", re.IGNORECASE)


def parse_rules_file(
    content: str,
    repo: str,
    *,
    max_rules: int = 50,
    max_description_chars: int = 500,
) -> RuleSet:
    """Parse a ``.saltax/rules.md`` file into a ``RuleSet``.

    Each ``## `` header starts a new rule.  Within each section, the parser
    looks for ``**Severity:**``, ``**Scope:**``, and ``**Description:**``
    fields.  Missing fields receive safe defaults.
    """
    if not content or not content.strip():
        return RuleSet(repo=repo, source=".saltax/rules.md")

    # Split on ## headers, keeping the header text.
    # The first element is preamble (before the first ##) — skip it.
    sections = re.split(r"^## ", content, flags=re.MULTILINE)
    rules: list[ReviewRule] = []
    scan_include: list[str] = []
    scan_exclude: list[str] = []

    for section in sections[1:]:
        section = section.strip()
        if not section:
            continue

        # First line is the section name
        lines = section.split("\n", 1)
        name = lines[0].strip()
        if not name:
            continue

        body = lines[1] if len(lines) > 1 else ""

        # Detect scan configuration section — not a rule
        if name.lower() == "scan configuration":
            inc_match = _RE_SCAN_INCLUDE.search(body)
            if inc_match:
                scan_include = [p.strip() for p in inc_match.group(1).split(",") if p.strip()]
            exc_match = _RE_SCAN_EXCLUDE.search(body)
            if exc_match:
                scan_exclude = [p.strip() for p in exc_match.group(1).split(",") if p.strip()]
            continue

        # Extract severity
        severity_match = _RE_SEVERITY.search(body)
        severity = severity_match.group(1).upper() if severity_match else "MEDIUM"
        if severity not in _VALID_SEVERITIES:
            severity = "MEDIUM"

        # Extract scope patterns
        scope_patterns: tuple[str, ...] = ()
        scope_match = _RE_SCOPE.search(body)
        if scope_match:
            raw_scope = scope_match.group(1).strip()
            patterns = [p.strip() for p in raw_scope.split(",") if p.strip()]
            scope_patterns = tuple(patterns)

        # Extract description
        description = ""
        desc_match = _RE_DESCRIPTION.search(body)
        if desc_match:
            description = desc_match.group(1).strip()[:max_description_chars]

        rules.append(
            ReviewRule(
                name=name,
                severity=severity,
                description=description,
                scope_patterns=scope_patterns,
            )
        )

        if len(rules) >= max_rules:
            logger.info(
                "Rules cap reached (%d), ignoring remaining rules",
                max_rules,
                extra={"repo": repo},
            )
            break

    return RuleSet(
        repo=repo,
        rules=rules,
        source=".saltax/rules.md",
        loaded_at=datetime.now(tz=UTC).isoformat(),
        scan_include=tuple(scan_include),
        scan_exclude=tuple(scan_exclude),
    )


async def load_rules_for_repo(
    *,
    repo: str,
    installation_id: int,
    github_client: GitHubClient,
    rules_config: RulesConfig,
) -> RuleSet | None:
    """Fetch and parse custom rules from a repository.

    Returns ``None`` if rules are disabled or the file doesn't exist.
    Always fetches from the default branch (no ``ref`` param) to prevent
    PR authors from injecting rules via their feature branch.
    """
    if not rules_config.enabled:
        return None

    content = await github_client.get_file_contents(
        repo,
        rules_config.rules_file_path,
        installation_id=installation_id,
    )
    if not isinstance(content, str):
        return None

    return parse_rules_file(
        content,
        repo,
        max_rules=rules_config.max_rules_per_repo,
        max_description_chars=rules_config.max_rule_description_chars,
    )
