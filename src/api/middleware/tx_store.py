"""Durable transaction hash store for payment replay protection.

Backed by aiosqlite to survive process restarts — a tx_hash can never
be reused for a different audit, even after reboot.  This is the
security-critical half of replay protection; the in-memory audit-slot
dedup (``_AuditDedup``) handles the non-critical duplicate-pipeline
prevention.

All write operations are serialized via ``asyncio.Lock`` because
aiosqlite shares a single connection across coroutines.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS seen_tx_hashes (
    tx_hash     TEXT PRIMARY KEY,
    audit_id    TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class TxHashStore:
    """SQLite-backed tx_hash store for payment replay protection.

    Lifecycle::

        store = TxHashStore("data/tx_hashes.db")
        await store.initialize()   # opens DB, creates table
        ...
        await store.close()        # closes DB connection

    After ``close()``, the store cannot be reused (unlike ``PaymentVerifier``
    which supports lazy re-creation).  This matches the ``IntelligenceDB``
    lifecycle pattern.
    """

    def __init__(self, db_path: str | Path = "data/tx_hashes.db") -> None:
        self._db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Open the database and create schema if needed."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.execute(_SCHEMA)
        await self._db.commit()
        logger.info("TxHashStore initialized at %s", self._db_path)

    async def check_and_record(self, tx_hash: str, audit_id: str) -> bool:
        """Return ``True`` if *tx_hash* was already recorded.  If not, record it.

        Atomic check-and-insert under a single lock acquisition.
        Empty tx_hash is treated as "not seen" (no-op).
        """
        if not tx_hash:
            return False
        if self._db is None:
            raise RuntimeError("TxHashStore not initialized — call initialize() first")
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT 1 FROM seen_tx_hashes WHERE tx_hash = ? LIMIT 1",
                (tx_hash,),
            )
            if await cursor.fetchone():
                return True
            await self._db.execute(
                "INSERT INTO seen_tx_hashes (tx_hash, audit_id) VALUES (?, ?)",
                (tx_hash, audit_id),
            )
            await self._db.commit()
            return False

    async def close(self) -> None:
        """Close the database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None
