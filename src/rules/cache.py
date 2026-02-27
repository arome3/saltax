"""TTL-based in-memory cache for parsed rule sets.

Uses ``time.monotonic()`` to avoid clock-skew issues.  No locking needed —
the asyncio event loop is single-threaded.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.rules.models import RuleSet

_rules_cache: dict[str, tuple[RuleSet, float]] = {}


def get_cached_rules(repo: str, ttl_seconds: int) -> RuleSet | None:
    """Return cached ``RuleSet`` if present and not expired."""
    entry = _rules_cache.get(repo)
    if entry is None:
        return None
    ruleset, cached_at = entry
    if (time.monotonic() - cached_at) > ttl_seconds:
        del _rules_cache[repo]
        return None
    return ruleset


def cache_rules(repo: str, ruleset: RuleSet) -> None:
    """Store a ``RuleSet`` in the cache."""
    _rules_cache[repo] = (ruleset, time.monotonic())


def invalidate_cache(repo: str) -> None:
    """Remove a specific repo's cached rules."""
    _rules_cache.pop(repo, None)


def clear_cache() -> None:
    """Remove all cached rules.  For testing only."""
    _rules_cache.clear()
