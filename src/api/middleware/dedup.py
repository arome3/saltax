"""Webhook delivery deduplication to prevent replay processing.

GitHub guarantees at-least-once delivery — if the server returns 200 but
GitHub's network times out, the same webhook is re-sent.  This module
tracks ``X-GitHub-Delivery`` IDs with a TTL to reject duplicates.
"""

from __future__ import annotations

import time


class DeliveryDedup:
    """TTL-based deduplication for webhook delivery IDs.

    Parameters
    ----------
    ttl_seconds:
        How long to remember a delivery ID (default 3600 = 1 hour).
    max_entries:
        Maximum tracked IDs before forced eviction (default 50_000).
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = 3600.0,
        max_entries: int = 50_000,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._seen: dict[str, float] = {}

    def is_duplicate(self, delivery_id: str) -> bool:
        """Return True if this delivery ID was already processed.

        Also registers the ID for future checks and prunes expired entries.
        """
        if not delivery_id or delivery_id == "unknown":
            # Missing delivery ID — can't dedup, allow through
            return False

        now = time.monotonic()
        self._prune(now)

        if delivery_id in self._seen:
            return True

        self._seen[delivery_id] = now

        # Enforce cap *after* insertion so the new entry is included
        if len(self._seen) > self._max_entries:
            by_age = sorted(self._seen.items(), key=lambda kv: kv[1])
            to_drop = len(self._seen) - self._max_entries
            for did, _ in by_age[:to_drop]:
                del self._seen[did]

        return False

    def _prune(self, now: float) -> None:
        """Remove expired entries and enforce max_entries cap."""
        # Remove expired
        cutoff = now - self._ttl
        expired = [did for did, ts in self._seen.items() if ts < cutoff]
        for did in expired:
            del self._seen[did]

        # Cap enforcement (oldest first)
        if len(self._seen) > self._max_entries:
            by_age = sorted(self._seen.items(), key=lambda kv: kv[1])
            to_drop = len(self._seen) - self._max_entries
            for did, _ in by_age[:to_drop]:
                del self._seen[did]

    @property
    def size(self) -> int:
        """Number of currently tracked delivery IDs."""
        return len(self._seen)
