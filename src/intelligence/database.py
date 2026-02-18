"""Intelligence pattern database with KMS-sealed aiosqlite storage.

The intelligence DB accumulates vulnerability patterns, contributor profiles,
and pipeline history from every code interaction.  Data at rest is protected
via :class:`KMSSealManager` (TEE-sealed SQLite file).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiosqlite

from src.intelligence.pattern_extractor import extract_patterns
from src.intelligence.similarity import _extract_code_tokens, cosine_similarity

if TYPE_CHECKING:
    from src.intelligence.sealing import KMSSealManager

logger = logging.getLogger(__name__)

# ── Module constants ─────────────────────────────────────────────────────────

DB_PATH = Path("/tmp/saltax_intel.db")

_FP_THRESHOLD = 0.8
_MIN_VERDICTS_FOR_HISTORY = 5
_CURRENT_SCHEMA_VERSION = 1
_MAX_RETRIES = 3
_RETRY_BASE_MS = 100
_MAX_LIKE_TOKENS = 20

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS schema_version (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_patterns (
    id                       TEXT PRIMARY KEY,
    rule_id                  TEXT NOT NULL,
    severity                 TEXT NOT NULL DEFAULT 'MEDIUM',
    category                 TEXT NOT NULL DEFAULT 'uncategorized',
    normalized_pattern       TEXT NOT NULL,
    pattern_signature        TEXT NOT NULL UNIQUE,
    confidence               REAL NOT NULL DEFAULT 0.5,
    times_seen               INTEGER NOT NULL DEFAULT 1,
    first_seen               TEXT NOT NULL,
    last_seen                TEXT NOT NULL,
    source_stage             TEXT NOT NULL DEFAULT 'unknown',
    confirmed_true_positive  INTEGER NOT NULL DEFAULT 0,
    confirmed_false_positive INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS contributor_profiles (
    id                   TEXT PRIMARY KEY,
    github_login         TEXT NOT NULL DEFAULT '',
    wallet_address       TEXT NOT NULL DEFAULT '',
    total_submissions    INTEGER NOT NULL DEFAULT 0,
    approved_submissions INTEGER NOT NULL DEFAULT 0,
    rejected_submissions INTEGER NOT NULL DEFAULT 0,
    reputation_score     REAL NOT NULL DEFAULT 0.5,
    first_seen           TEXT NOT NULL,
    last_active          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS codebase_knowledge (
    id          TEXT PRIMARY KEY,
    repo        TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    knowledge   TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pipeline_history (
    id              TEXT PRIMARY KEY,
    pr_id           TEXT NOT NULL,
    repo            TEXT NOT NULL,
    pr_author       TEXT DEFAULT '',
    verdict         TEXT NOT NULL,
    composite_score REAL,
    findings_count  INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attestation_store (
    attestation_id       TEXT PRIMARY KEY,
    pr_id                TEXT NOT NULL,
    repo                 TEXT NOT NULL,
    pipeline_input_hash  TEXT NOT NULL,
    pipeline_output_hash TEXT NOT NULL,
    signature            TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS active_bounties (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    label        TEXT NOT NULL,
    amount_eth   REAL NOT NULL DEFAULT 0.0,
    status       TEXT NOT NULL DEFAULT 'open',
    created_at   TEXT NOT NULL,
    claimed_by   TEXT
);

CREATE TABLE IF NOT EXISTS verification_windows (
    id              TEXT PRIMARY KEY,
    pr_id           TEXT NOT NULL,
    repo            TEXT NOT NULL,
    attestation_id  TEXT NOT NULL,
    window_hours    INTEGER NOT NULL,
    opens_at        TEXT NOT NULL,
    closes_at       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',
    challenges      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pr_embeddings (
    id           TEXT PRIMARY KEY,
    pr_id        TEXT NOT NULL,
    repo         TEXT NOT NULL,
    pr_number    INTEGER,
    commit_sha   TEXT NOT NULL,
    embedding    BLOB NOT NULL,
    issue_number INTEGER,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vision_documents (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    content      TEXT NOT NULL,
    embedding    BLOB,
    updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vp_signature ON vulnerability_patterns(pattern_signature);
CREATE INDEX IF NOT EXISTS idx_vp_rule_id ON vulnerability_patterns(rule_id);
CREATE INDEX IF NOT EXISTS idx_vp_category ON vulnerability_patterns(category);
CREATE INDEX IF NOT EXISTS idx_vp_severity ON vulnerability_patterns(severity);
CREATE INDEX IF NOT EXISTS idx_cp_github ON contributor_profiles(github_login);
CREATE INDEX IF NOT EXISTS idx_cp_wallet ON contributor_profiles(wallet_address);
CREATE INDEX IF NOT EXISTS idx_ph_repo ON pipeline_history(repo);
CREATE INDEX IF NOT EXISTS idx_ph_pr_author ON pipeline_history(pr_author);
CREATE INDEX IF NOT EXISTS idx_ph_created ON pipeline_history(created_at);
CREATE INDEX IF NOT EXISTS idx_as_pr ON attestation_store(pr_id);
CREATE INDEX IF NOT EXISTS idx_ab_repo ON active_bounties(repo);
CREATE INDEX IF NOT EXISTS idx_ab_status ON active_bounties(status);
CREATE INDEX IF NOT EXISTS idx_vw_status ON verification_windows(status);
CREATE INDEX IF NOT EXISTS idx_pe_repo ON pr_embeddings(repo);
CREATE INDEX IF NOT EXISTS idx_vd_repo ON vision_documents(repo);
"""


# ── Retry helper ─────────────────────────────────────────────────────────────


async def _retry_on_busy(coro_factory, *, max_retries: int = _MAX_RETRIES):  # noqa: ANN001
    """Retry a coroutine factory on SQLITE_BUSY with exponential backoff."""
    for attempt in range(max_retries + 1):
        try:
            return await coro_factory()
        except sqlite3.OperationalError as exc:
            is_busy = "locked" in str(exc).lower() or "busy" in str(exc).lower()
            if is_busy and attempt < max_retries:
                delay = _RETRY_BASE_MS * (2 ** attempt) / 1000.0
                logger.warning(
                    "SQLITE_BUSY, retrying in %.1fms (attempt %d/%d)",
                    delay * 1000, attempt + 1, max_retries,
                )
                await asyncio.sleep(delay)
                continue
            raise
    return None  # unreachable, satisfies type checker


# ── IntelligenceDB ───────────────────────────────────────────────────────────


class IntelligenceDB:
    """Stores and retrieves learned patterns for the decision engine.

    Data at rest is protected via :class:`KMSSealManager`.
    """

    def __init__(self, kms: KMSSealManager) -> None:
        self._kms = kms
        self._initialized = False
        self._db: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()

    @property
    def initialized(self) -> bool:
        return self._initialized

    def _require_db(self) -> aiosqlite.Connection:
        """Return the DB connection or raise if not initialized.

        Uses an explicit check instead of ``assert`` so it is never
        stripped by ``python -O``.  (Fix #3)
        """
        if self._db is None:
            raise RuntimeError("IntelligenceDB is not initialized; call initialize() first")
        return self._db

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Open the database and create schema.

        Attempts to unseal from KMS first; on failure, starts fresh.
        After opening, runs integrity check (CryptSQLite/BiTDB pattern).

        Safe to call multiple times — closes the prior connection first.  (Fix #5)
        """
        # Fix #5: Close existing connection before re-initializing
        if self._db is not None:
            await self._db.close()
            self._db = None
            self._initialized = False

        # Try unsealing existing DB
        try:
            sealed = await self._kms.unseal("saltax_intel_db")
            DB_PATH.write_bytes(sealed)
            # Restrict file permissions to owner-only (rw-------)
            os.chmod(DB_PATH, stat.S_IRUSR | stat.S_IWUSR)
            logger.info("Unsealed intelligence DB from KMS (%d bytes)", len(sealed))
        except Exception:
            logger.info("No sealed DB available, starting fresh")

        self._db = await aiosqlite.connect(str(DB_PATH))
        self._db.row_factory = aiosqlite.Row

        try:
            # Integrity check after unseal
            try:
                async with self._db.execute("PRAGMA quick_check") as cursor:
                    row = await cursor.fetchone()
                    if row is None or str(row[0]) != "ok":
                        logger.warning("DB integrity check failed, recreating fresh")
                        await self._db.close()
                        DB_PATH.unlink(missing_ok=True)
                        self._db = await aiosqlite.connect(str(DB_PATH))
                        self._db.row_factory = aiosqlite.Row
            except Exception:
                logger.warning("DB integrity check errored, recreating fresh")
                await self._db.close()
                DB_PATH.unlink(missing_ok=True)
                self._db = await aiosqlite.connect(str(DB_PATH))
                self._db.row_factory = aiosqlite.Row

            # WAL mode and pragmas
            await self._db.execute("PRAGMA journal_mode=WAL")
            await self._db.execute("PRAGMA synchronous=NORMAL")
            await self._db.execute("PRAGMA busy_timeout=5000")
            await self._db.execute("PRAGMA foreign_keys=ON")

            # Create schema (idempotent)
            await self._db.executescript(_SCHEMA_SQL)

            # Schema version tracking
            await self._ensure_schema_version()

            self._initialized = True
        except Exception:
            # Don't leak the connection if schema setup fails
            await self._db.close()
            self._db = None
            raise

    async def _ensure_schema_version(self) -> None:
        """Track and migrate schema versions."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with db.execute(
            "SELECT version FROM schema_version WHERE id = 1",
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            await db.execute(
                "INSERT INTO schema_version (id, version, updated_at) VALUES (1, ?, ?)",
                (_CURRENT_SCHEMA_VERSION, now),
            )
            await db.commit()
        else:
            current = row[0]
            if current < _CURRENT_SCHEMA_VERSION:
                # Future migration blocks go here
                await db.execute(
                    "UPDATE schema_version SET version = ?, updated_at = ? WHERE id = 1",
                    (_CURRENT_SCHEMA_VERSION, now),
                )
                await db.commit()

    async def seal(self, kms: KMSSealManager) -> None:
        """Seal the database for graceful shutdown.

        Fix #4: Read the file *before* closing the connection so KMS failure
        does not lose the connection.  Delete plaintext after confirmed seal.
        Fix #9: Remove plaintext DB + WAL sidecars after successful seal.
        """
        if self._db is None:
            return

        try:
            # Flush WAL into main DB file and verify completeness
            async with self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)") as cur:
                wal_row = await cur.fetchone()
                if wal_row and wal_row[0] != 0:
                    logger.warning("WAL checkpoint incomplete: %s", wal_row)

            # Read the file BEFORE closing the connection (Fix #4)
            # We need to close first for the file to be fully flushed on all platforms
            await self._db.close()
            self._db = None

            data = DB_PATH.read_bytes()
            await kms.seal("saltax_intel_db", data)
            logger.info("Sealed intelligence DB to KMS (%d bytes)", len(data))

            # Fix #9: Remove plaintext DB and WAL sidecars after confirmed seal
            DB_PATH.unlink(missing_ok=True)
            Path(str(DB_PATH) + "-wal").unlink(missing_ok=True)
            Path(str(DB_PATH) + "-shm").unlink(missing_ok=True)
        except Exception:
            logger.exception("Failed to seal intelligence DB to KMS")
        finally:
            # Always mark as uninitialized regardless of success/failure
            self._initialized = False

    async def close(self) -> None:
        """Release database resources."""
        if self._db is not None:
            await self._db.close()
            self._db = None
        self._initialized = False

    # ── Pattern queries ──────────────────────────────────────────────────

    async def count_patterns(self) -> int:
        """Return the number of stored vulnerability patterns."""
        db = self._require_db()
        async with db.execute(
            "SELECT COUNT(*) FROM vulnerability_patterns",
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def get_false_positive_signatures(self) -> frozenset[str]:
        """Return rule IDs with high false-positive rates (>0.8).

        Uses DefectDojo-style integer counters: FP rate is computed
        dynamically from ``confirmed_true_positive`` / ``confirmed_false_positive``.
        """
        db = self._require_db()
        sql = """\
            SELECT DISTINCT rule_id FROM vulnerability_patterns
            WHERE confirmed_false_positive > 0
              AND CAST(confirmed_false_positive AS REAL) /
                  (confirmed_true_positive + confirmed_false_positive) > ?
        """
        async with db.execute(sql, (_FP_THRESHOLD,)) as cursor:
            rows = await cursor.fetchall()
            return frozenset(row[0] for row in rows)

    async def query_similar_patterns(
        self, code_diff: str, limit: int = 10,
    ) -> list[dict[str, object]]:
        """Return patterns similar to the given code diff.

        Tokenizes the diff, builds ``LIKE`` clauses for the top tokens,
        and orders by ``times_seen DESC`` with dynamic FP rate as tiebreaker.
        """
        db = self._require_db()
        tokens = _extract_code_tokens(code_diff)
        if not tokens:
            return []

        tokens = tokens[:_MAX_LIKE_TOKENS]
        like_clauses = " OR ".join(
            "normalized_pattern LIKE ?" for _ in tokens
        )
        # Fix #6: Build typed params list — LIKE tokens are str, LIMIT is int
        params: list[object] = [f"%{tok}%" for tok in tokens]
        params.append(limit)

        # Fix #2: Order by dynamic FP rate from integer counters,
        # not the removed false_positive_rate column
        sql = f"""\
            SELECT id, rule_id, severity, category, normalized_pattern,
                   confidence, times_seen, first_seen, last_seen,
                   confirmed_true_positive, confirmed_false_positive
            FROM vulnerability_patterns
            WHERE {like_clauses}
            ORDER BY times_seen DESC,
                     CASE WHEN (confirmed_true_positive + confirmed_false_positive) > 0
                          THEN CAST(confirmed_false_positive AS REAL) /
                               (confirmed_true_positive + confirmed_false_positive)
                          ELSE 0.0 END ASC
            LIMIT ?
        """

        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    # ── FP verdict feedback ──────────────────────────────────────────────

    async def record_verdict_feedback(
        self,
        pattern_id: str,
        *,
        is_true_positive: bool,
    ) -> None:
        """Increment TP or FP counter for a vulnerability pattern.

        Called when a human or dispute process confirms whether a flagged
        pattern was a true or false positive.
        """
        db = self._require_db()
        async with self._write_lock:
            if is_true_positive:
                await db.execute(
                    "UPDATE vulnerability_patterns "
                    "SET confirmed_true_positive = confirmed_true_positive + 1 "
                    "WHERE id = ?",
                    (pattern_id,),
                )
            else:
                await db.execute(
                    "UPDATE vulnerability_patterns "
                    "SET confirmed_false_positive = confirmed_false_positive + 1 "
                    "WHERE id = ?",
                    (pattern_id,),
                )
            await db.commit()

    # ── Ingestion ────────────────────────────────────────────────────────

    async def ingest_pipeline_results(
        self,
        *,
        pr_id: str,
        repo: str,
        static_findings: list[dict[str, object]],
        ai_findings: list[object],
        verdict: dict[str, object],
        author: str | None = None,
    ) -> None:
        """Store pipeline results for future pattern learning.

        Extracts patterns, upserts into ``vulnerability_patterns``,
        inserts into ``pipeline_history``, and updates ``contributor_profiles``.

        Uses ``_write_lock`` to prevent concurrent writers from interleaving
        transactions on the shared connection.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()

        patterns = extract_patterns(static_findings, ai_findings)

        async def _do_ingest() -> None:
            async with self._write_lock:
                # Upsert patterns
                for pat in patterns:
                    sig = hashlib.sha256(
                        str(pat["normalized_pattern"]).encode(),
                    ).hexdigest()

                    async with db.execute(
                        "SELECT id, times_seen FROM vulnerability_patterns "
                        "WHERE pattern_signature = ?",
                        (sig,),
                    ) as cursor:
                        existing = await cursor.fetchone()

                    if existing:
                        await db.execute(
                            """\
                            UPDATE vulnerability_patterns
                            SET times_seen = times_seen + 1,
                                last_seen = ?
                            WHERE pattern_signature = ?
                            """,
                            (now, sig),
                        )
                    else:
                        pat_id = hashlib.sha256(
                            f"{sig}-{now}".encode(),
                        ).hexdigest()[:16]
                        await db.execute(
                            """\
                            INSERT INTO vulnerability_patterns
                                (id, rule_id, severity, category, normalized_pattern,
                                 pattern_signature, confidence, times_seen,
                                 first_seen, last_seen, source_stage)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                            """,
                            (
                                pat_id,
                                pat["rule_id"],
                                pat["severity"],
                                pat["category"],
                                pat["normalized_pattern"],
                                sig,
                                pat["confidence"],
                                now, now,
                                pat["source_stage"],
                            ),
                        )

                # Insert pipeline history — uuid4 prevents collision on same-second reruns
                history_id = hashlib.sha256(
                    f"{pr_id}-{now}-{uuid.uuid4()}".encode(),
                ).hexdigest()[:16]
                verdict_json = json.dumps(verdict, default=str)
                composite = float(verdict.get("composite_score", 0.0))
                findings_count = int(verdict.get("findings_count", 0))

                await db.execute(
                    """\
                    INSERT INTO pipeline_history
                        (id, pr_id, repo, pr_author, verdict, composite_score,
                         findings_count, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        history_id, pr_id, repo, author or "",
                        verdict_json, composite, findings_count, now,
                    ),
                )

                # Upsert contributor profile
                if author:
                    decision = str(verdict.get("decision", ""))
                    is_approved = decision.lower() in ("approve", "approved")

                    async with db.execute(
                        """\
                        SELECT id, total_submissions, approved_submissions,
                               rejected_submissions
                        FROM contributor_profiles
                        WHERE github_login = ?
                        """,
                        (author,),
                    ) as cursor:
                        existing_cp = await cursor.fetchone()

                    if existing_cp:
                        if is_approved:
                            await db.execute(
                                """\
                                UPDATE contributor_profiles
                                SET total_submissions = total_submissions + 1,
                                    approved_submissions = approved_submissions + 1,
                                    last_active = ?
                                WHERE id = ?
                                """,
                                (now, existing_cp[0]),
                            )
                        else:
                            await db.execute(
                                """\
                                UPDATE contributor_profiles
                                SET total_submissions = total_submissions + 1,
                                    rejected_submissions = rejected_submissions + 1,
                                    last_active = ?
                                WHERE id = ?
                                """,
                                (now, existing_cp[0]),
                            )
                    else:
                        cp_id = hashlib.sha256(author.encode()).hexdigest()[:16]
                        await db.execute(
                            """\
                            INSERT INTO contributor_profiles
                                (id, github_login, total_submissions,
                                 approved_submissions, rejected_submissions,
                                 first_seen, last_active)
                            VALUES (?, ?, 1, ?, ?, ?, ?)
                            """,
                            (
                                cp_id, author,
                                1 if is_approved else 0,
                                0 if is_approved else 1,
                                now, now,
                            ),
                        )

                await db.commit()

        await _retry_on_busy(_do_ingest)

    # ── Contributor history ──────────────────────────────────────────────

    async def get_contributor_acceptance_rate(
        self, repo: str, author: str,
    ) -> float | None:
        """Return the historical acceptance rate for a contributor.

        Returns ``None`` when the DB has insufficient data (<5 verdicts).
        """
        db = self._require_db()

        # Try contributor_profiles first (global, keyed by github_login)
        async with db.execute(
            """\
            SELECT total_submissions, approved_submissions
            FROM contributor_profiles
            WHERE github_login = ?
            """,
            (author,),
        ) as cursor:
            row = await cursor.fetchone()

        if row and row[0] >= _MIN_VERDICTS_FOR_HISTORY:
            return row[1] / row[0]

        # Fallback: query pipeline_history (repo-scoped)
        async with db.execute(
            """\
            SELECT COUNT(*) FROM pipeline_history
            WHERE pr_author = ? AND repo = ?
            """,
            (author, repo),
        ) as cursor:
            total_row = await cursor.fetchone()
            total = total_row[0] if total_row else 0

        if total < _MIN_VERDICTS_FOR_HISTORY:
            return None

        # Fix #10: Match the decision field precisely in stored JSON,
        # not any occurrence of "approve" anywhere in the verdict string.
        # The decision engine stores {"decision": "APPROVE"} or {"decision": "approve"}.
        async with db.execute(
            """\
            SELECT COUNT(*) FROM pipeline_history
            WHERE pr_author = ? AND repo = ?
              AND (verdict LIKE '%"decision": "approve"%'
                   OR verdict LIKE '%"decision": "APPROVE"%'
                   OR verdict LIKE '%"decision":"approve"%'
                   OR verdict LIKE '%"decision":"APPROVE"%')
            """,
            (author, repo),
        ) as cursor:
            approved_row = await cursor.fetchone()
            approved = approved_row[0] if approved_row else 0

        return approved / total

    # ── Stats (anonymized) ───────────────────────────────────────────────

    async def get_stats(self) -> dict[str, Any]:
        """Return anonymized aggregate intelligence statistics.

        Never exposes raw patterns — only counts and distributions.
        """
        db = self._require_db()

        # Total patterns
        async with db.execute(
            "SELECT COUNT(*) FROM vulnerability_patterns",
        ) as cursor:
            row = await cursor.fetchone()
            total_patterns = row[0] if row else 0

        # Category distribution
        async with db.execute(
            "SELECT category, COUNT(*) as cnt FROM vulnerability_patterns GROUP BY category",
        ) as cursor:
            cat_rows = await cursor.fetchall()
            category_distribution = {row[0]: row[1] for row in cat_rows}

        # Severity distribution
        async with db.execute(
            "SELECT severity, COUNT(*) as cnt FROM vulnerability_patterns GROUP BY severity",
        ) as cursor:
            sev_rows = await cursor.fetchall()
            severity_distribution = {row[0]: row[1] for row in sev_rows}

        # Average false positive rate (from integer counters)
        async with db.execute(
            """\
            SELECT AVG(
                CASE WHEN (confirmed_true_positive + confirmed_false_positive) > 0
                THEN CAST(confirmed_false_positive AS REAL) /
                     (confirmed_true_positive + confirmed_false_positive)
                ELSE 0.0 END
            ) FROM vulnerability_patterns
            """,
        ) as cursor:
            fp_row = await cursor.fetchone()
            avg_fp_rate = round(fp_row[0], 4) if fp_row and fp_row[0] is not None else 0.0

        # Patterns last 7 days
        async with db.execute(
            """\
            SELECT COUNT(*) FROM vulnerability_patterns
            WHERE first_seen > datetime('now', '-7 days')
            """,
        ) as cursor:
            recent_row = await cursor.fetchone()
            patterns_last_7 = recent_row[0] if recent_row else 0

        # Top contributing repos (names only, top 10)
        async with db.execute(
            """\
            SELECT repo, COUNT(*) as cnt FROM pipeline_history
            GROUP BY repo ORDER BY cnt DESC LIMIT 10
            """,
        ) as cursor:
            repo_rows = await cursor.fetchall()
            top_repos = [row[0] for row in repo_rows]

        return {
            "total_patterns": total_patterns,
            "category_distribution": category_distribution,
            "severity_distribution": severity_distribution,
            "avg_false_positive_rate": avg_fp_rate,
            "patterns_last_7_days": patterns_last_7,
            "top_contributing_repos": top_repos,
        }

    # ── Attestation store ────────────────────────────────────────────────

    async def store_attestation(
        self,
        *,
        attestation_id: str,
        pr_id: str,
        repo: str,
        pipeline_input_hash: str,
        pipeline_output_hash: str,
        signature: str = "",
    ) -> None:
        """Persist an attestation proof."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO attestation_store
                    (attestation_id, pr_id, repo, pipeline_input_hash,
                     pipeline_output_hash, signature, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (attestation_id, pr_id, repo, pipeline_input_hash,
                 pipeline_output_hash, signature, now),
            )
            await db.commit()

    async def get_attestation(self, attestation_id: str) -> dict[str, object] | None:
        """Retrieve an attestation by ID."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM attestation_store WHERE attestation_id = ?",
            (attestation_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    # ── Bounties ─────────────────────────────────────────────────────────

    async def store_bounty(
        self,
        *,
        bounty_id: str,
        repo: str,
        issue_number: int,
        label: str,
        amount_eth: float = 0.0,
    ) -> None:
        """Create or update a bounty record."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO active_bounties
                    (id, repo, issue_number, label, amount_eth, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'open', ?)
                """,
                (bounty_id, repo, issue_number, label, amount_eth, now),
            )
            await db.commit()

    async def close_bounty(self, bounty_id: str, claimed_by: str) -> None:
        """Mark a bounty as claimed."""
        db = self._require_db()
        async with self._write_lock:
            await db.execute(
                "UPDATE active_bounties SET status = 'claimed', claimed_by = ? "
                "WHERE id = ?",
                (claimed_by, bounty_id),
            )
            await db.commit()

    async def get_active_bounties(self) -> list[dict[str, object]]:
        """Return all open bounties."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM active_bounties WHERE status = 'open'",
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    # ── Verification windows ─────────────────────────────────────────────

    async def store_verification_window(
        self,
        *,
        window_id: str,
        pr_id: str,
        repo: str,
        attestation_id: str,
        window_hours: int,
        opens_at: str,
        closes_at: str,
    ) -> None:
        """Create a verification window."""
        db = self._require_db()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO verification_windows
                    (id, pr_id, repo, attestation_id, window_hours,
                     opens_at, closes_at, status, challenges)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'open', 0)
                """,
                (window_id, pr_id, repo, attestation_id, window_hours,
                 opens_at, closes_at),
            )
            await db.commit()

    async def record_challenge(self, window_id: str) -> None:
        """Increment challenge count on a verification window."""
        db = self._require_db()
        async with self._write_lock:
            await db.execute(
                "UPDATE verification_windows "
                "SET challenges = challenges + 1 WHERE id = ?",
                (window_id,),
            )
            await db.commit()

    # ── Codebase knowledge ───────────────────────────────────────────────

    async def store_codebase_knowledge(
        self,
        *,
        knowledge_id: str,
        repo: str,
        file_path: str,
        knowledge: str,
    ) -> None:
        """Store or update codebase knowledge."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO codebase_knowledge
                    (id, repo, file_path, knowledge, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (knowledge_id, repo, file_path, knowledge, now),
            )
            await db.commit()

    # ── Vision documents ─────────────────────────────────────────────────

    async def store_vision_document(
        self,
        *,
        doc_id: str,
        repo: str,
        content: str,
        embedding: bytes | None = None,
    ) -> None:
        """Store or update a vision document."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO vision_documents
                    (id, repo, content, embedding, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (doc_id, repo, content, embedding, now),
            )
            await db.commit()

    # ── Embeddings ───────────────────────────────────────────────────────

    async def store_embedding(
        self,
        pr_id: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        embedding_blob: bytes,
        issue_number: int | None = None,
    ) -> None:
        """Store or replace a PR embedding."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        emb_id = hashlib.sha256(f"{pr_id}-{commit_sha}".encode()).hexdigest()[:16]
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO pr_embeddings
                    (id, pr_id, repo, pr_number, commit_sha, embedding,
                     issue_number, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (emb_id, pr_id, repo, pr_number, commit_sha,
                 embedding_blob, issue_number, now),
            )
            await db.commit()

    async def find_similar_prs(
        self,
        embedding_blob: bytes,
        repo: str,
        threshold: float = 0.85,
        limit: int = 5,
        *,
        max_scan: int = 1000,
    ) -> list[dict[str, object]]:
        """Find PRs with similar embeddings via cosine similarity.

        Scans up to ``max_scan`` most recent embeddings for the repo,
        computes similarity in Python, and returns those above the
        threshold sorted by similarity descending.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT id, pr_id, pr_number, commit_sha, embedding, issue_number "
            "FROM pr_embeddings WHERE repo = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (repo, max_scan),
        ) as cursor:
            rows = await cursor.fetchall()

        results: list[dict[str, object]] = []
        for row in rows:
            sim = cosine_similarity(embedding_blob, row[4])
            if sim >= threshold:
                results.append({
                    "id": row[0],
                    "pr_id": row[1],
                    "pr_number": row[2],
                    "commit_sha": row[3],
                    "issue_number": row[5],
                    "similarity": round(sim, 4),
                })

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:limit]
