"""Data models for custom review rules.

``ReviewRule`` is a frozen dataclass representing a single rule parsed from
``.saltax/rules.md``.  ``RuleSet`` holds the full collection for a repo and
provides scope-based filtering against changed files.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.rules.scoping import matches_scope

_VALID_SEVERITIES = frozenset({"HIGH", "MEDIUM", "LOW"})


@dataclass(frozen=True)
class ReviewRule:
    """A single custom review rule defined by a repository owner."""

    name: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    description: str = ""
    scope_patterns: tuple[str, ...] = ()  # Glob patterns; empty = all files
    enabled: bool = True


@dataclass
class RuleSet:
    """Collection of review rules for a repository."""

    repo: str
    rules: list[ReviewRule] = field(default_factory=list)
    source: str = ""
    loaded_at: str = ""
    scan_include: tuple[str, ...] = ()  # Semgrep --include paths
    scan_exclude: tuple[str, ...] = ()  # Semgrep --exclude paths

    @property
    def active_rules(self) -> list[ReviewRule]:
        """Return only enabled rules."""
        return [r for r in self.rules if r.enabled]

    def rules_for_files(self, file_paths: list[str]) -> list[ReviewRule]:
        """Return active rules whose scope matches at least one changed file.

        Unscoped rules (empty ``scope_patterns``) match any file list.
        Supports ``!`` exclude patterns via ``matches_scope()``.
        """
        matched: list[ReviewRule] = []
        for rule in self.active_rules:
            if any(matches_scope(fp, rule.scope_patterns) for fp in file_paths):
                matched.append(rule)
        return matched

    def rules_for_file(self, file_path: str) -> list[ReviewRule]:
        """Return active rules whose scope matches a single file."""
        return [r for r in self.active_rules if matches_scope(file_path, r.scope_patterns)]
