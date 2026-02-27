"""Format custom review rules for injection into the AI analyzer prompt.

Each rule is rendered as a markdown block with an explicit ``custom:slug``
rule_id that tells the AI exactly what identifier to emit in findings.
Per-file applicability shows the AI which specific changed files each rule
governs.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from src.rules.scoping import filter_rules_for_files

if TYPE_CHECKING:
    from src.rules.models import RuleSet

_RE_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_MAX_SLUG_LEN = 80


def _slugify(name: str) -> str:
    """Convert a rule name into a URL-safe slug.

    ``"No raw SQL in API routes"`` -> ``"no-raw-sql-in-api-routes"``
    """
    slug = _RE_NON_ALNUM.sub("-", name.lower()).strip("-")
    return slug[:_MAX_SLUG_LEN]


def format_rules_for_prompt(
    ruleset: RuleSet,
    changed_files: list[str],
    *,
    max_chars: int = 6000,
) -> str:
    """Format scope-filtered rules as a prompt section with per-file applicability.

    Only includes rules whose scope matches at least one changed file.
    Each rule block lists the specific changed files it applies to.
    Truncates at rule boundaries (never mid-rule) when approaching
    ``max_chars``.
    """
    rules_with_files = filter_rules_for_files(ruleset.active_rules, changed_files)
    if not rules_with_files:
        return ""

    blocks: list[str] = []
    current_len = 0

    for rule, files in rules_with_files:
        lines = [f"### {rule.name}"]
        lines.append(f"- Severity: {rule.severity}")
        lines.append(f"- Rule ID to use: custom:{_slugify(rule.name)}")
        if rule.scope_patterns:
            lines.append(f"- Scope: {', '.join(rule.scope_patterns)}")
        lines.append(f"- Applies to: {', '.join(f'`{f}`' for f in files[:5])}")
        if len(files) > 5:
            lines.append(f"  ... and {len(files) - 5} more files")
        if rule.description:
            lines.append(f"- {rule.description}")

        block = "\n".join(lines)

        # Check if adding this block would exceed the budget
        block_len = len(block) + 2  # +2 for the "\n\n" separator
        if current_len + block_len > max_chars and blocks:
            blocks.append(
                "... [remaining rules truncated due to prompt size limit]"
            )
            break

        blocks.append(block)
        current_len += block_len

    return "\n\n".join(blocks)
