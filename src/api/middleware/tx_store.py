"""Durable transaction hash store for payment replay protection.

Backed by PostgreSQL (shared pool from IntelligenceDB) to survive TEE
restarts — a tx_hash can never be reused for a different audit, even
after reboot.  This is the security-critical half of replay protection;
the in-memory audit-slot dedup (``_AuditDedup``) handles the
non-critical duplicate-pipeline prevention.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)


class TxHashStore:
    """PostgreSQL-backed tx_hash store for payment replay protection.

    Lifecycle::

        store = TxHashStore(pool)
        # No separate initialize() needed — pool already open
        ...
        await store.close()        # no-op (pool lifecycle is external)

    The ``seen_tx_hashes`` table is created by the shared schema in
    ``src/intelligence/schema.sql``.
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

    async def check_and_record(self, tx_hash: str, audit_id: str) -> bool:
        """Return ``True`` if *tx_hash* was already recorded.  If not, record it.

        Atomic check-and-insert using PostgreSQL's native concurrency.
        Empty tx_hash is treated as "not seen" (no-op).
        """
        if not tx_hash:
            return False
        async with self._pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT 1 FROM seen_tx_hashes WHERE tx_hash = %s",
                    (tx_hash,),
                )
            ).fetchone()
            if row:
                return True
            await conn.execute(
                "INSERT INTO seen_tx_hashes (tx_hash, audit_id) VALUES (%s, %s)",
                (tx_hash, audit_id),
            )
            return False

    async def close(self) -> None:
        """No-op — pool lifecycle is managed by IntelligenceDB."""
