"""Path-scoping engine for custom review rules.

Provides include/exclude glob pattern matching, per-file rule applicability
mapping, and post-scan finding filtering to changed files.

Pattern semantics:
- Empty patterns → match ALL files (global scope)
- ``!`` prefix → exclude pattern, checked first and rejects immediately
- If only excludes are specified → match everything not excluded
- If include patterns exist → at least one must match
- Matching respects ``/`` boundaries for ``*`` and supports ``**``
  recursive globbing (compatible with Python 3.11+)
"""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.rules.models import ReviewRule


def _glob_match(path: str, pattern: str) -> bool:
    """Match a POSIX path against a glob pattern respecting ``/`` boundaries.

    ``*`` matches within a single component, ``**`` matches zero or more
    components.  Works on Python 3.11+ (does not require 3.13 ``full_match``).
    """
    path_parts = path.split("/")
    pat_parts = pattern.split("/")
    return _match_parts(path_parts, 0, pat_parts, 0)


def _match_parts(
    path_parts: list[str],
    pi: int,
    pat_parts: list[str],
    gi: int,
) -> bool:
    """Recursively match path components against pattern components."""
    while pi < len(path_parts) and gi < len(pat_parts):
        pat = pat_parts[gi]
        if pat == "**":
            # ``**`` can match zero or more path components
            # Try matching the rest of the pattern starting from every
            # remaining position in the path (including current).
            for skip in range(pi, len(path_parts) + 1):
                if _match_parts(path_parts, skip, pat_parts, gi + 1):
                    return True
            return False
        if not fnmatch.fnmatch(path_parts[pi], pat):
            return False
        pi += 1
        gi += 1

    # Consume trailing ``**`` patterns (they can match zero components)
    while gi < len(pat_parts) and pat_parts[gi] == "**":
        gi += 1

    return pi == len(path_parts) and gi == len(pat_parts)


def matches_scope(file_path: str, scope_patterns: tuple[str, ...]) -> bool:
    """Check if a file path matches scope patterns with include/exclude semantics.

    Returns ``True`` if:
    - *scope_patterns* is empty (global rule, matches all files)
    - The file is not excluded AND at least one include pattern matches
    - Only exclude patterns exist and the file is not excluded
    """
    if not scope_patterns:
        return True

    # Normalize backslashes for cross-platform safety
    normalized = file_path.replace("\\", "/")

    excludes: list[str] = []
    includes: list[str] = []
    for pattern in scope_patterns:
        if pattern.startswith("!"):
            excludes.append(pattern[1:])
        else:
            includes.append(pattern)

    # Excludes are checked first — reject immediately on match
    for exc in excludes:
        if _glob_match(normalized, exc):
            return False

    # If no include patterns exist, everything not excluded matches
    if not includes:
        return True

    # At least one include pattern must match
    return any(_glob_match(normalized, inc) for inc in includes)


def filter_rules_for_files(
    rules: list[ReviewRule],
    changed_files: list[str],
) -> list[tuple[ReviewRule, list[str]]]:
    """For each rule, determine which changed files it applies to.

    Returns a list of ``(rule, applicable_files)`` tuples, including only
    rules that match at least one changed file.
    """
    result: list[tuple[ReviewRule, list[str]]] = []
    for rule in rules:
        applicable = [f for f in changed_files if matches_scope(f, rule.scope_patterns)]
        if applicable:
            result.append((rule, applicable))
    return result


def filter_findings_by_changed_files(
    findings: list[dict[str, object]],
    changed_files: set[str],
) -> list[dict[str, object]]:
    """Keep only findings whose ``file_path`` is in the changed files set.

    Strips leading ``./`` from finding paths before comparison so that
    Semgrep's relative paths (e.g. ``./src/foo.py``) match the normalized
    set from ``extract_modified_files()`` (e.g. ``src/foo.py``).
    """
    kept: list[dict[str, object]] = []
    for finding in findings:
        raw_path = str(finding.get("file_path", ""))
        normalized = raw_path.lstrip("./") if raw_path.startswith("./") else raw_path
        if normalized in changed_files:
            kept.append(finding)
    return kept
