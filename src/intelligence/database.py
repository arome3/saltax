"""Intelligence pattern database with KMS-sealed aiosqlite storage.

The intelligence DB accumulates vulnerability patterns, contributor profiles,
and pipeline history from every code interaction.  Data at rest is protected
via :class:`KMSSealManager` (TEE-sealed SQLite file).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import stat
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiosqlite

from src.intelligence.pattern_extractor import extract_patterns
from src.intelligence.similarity import _extract_code_tokens, cosine_similarity
from src.models.identity import AgentIdentity

if TYPE_CHECKING:
    from src.intelligence.sealing import KMSSealManager

logger = logging.getLogger(__name__)

# ── Module constants ─────────────────────────────────────────────────────────

DB_PATH = Path("/tmp/saltax_intel.db")

_FP_THRESHOLD = 0.8
_MIN_VERDICTS_FOR_HISTORY = 5
_CURRENT_SCHEMA_VERSION = 16
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
    attestation_id          TEXT PRIMARY KEY,
    pr_id                   TEXT NOT NULL,
    repo                    TEXT NOT NULL,
    pipeline_input_hash     TEXT NOT NULL,
    pipeline_output_hash    TEXT NOT NULL,
    signature               TEXT NOT NULL DEFAULT '',
    docker_image_digest     TEXT NOT NULL DEFAULT '',
    tee_platform_id         TEXT NOT NULL DEFAULT '',
    previous_attestation_id TEXT,
    ai_seed                 INTEGER,
    ai_output_hash          TEXT,
    ai_system_fingerprint   TEXT,
    signer_address          TEXT NOT NULL DEFAULT '',
    created_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS active_bounties (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    label        TEXT NOT NULL,
    amount_eth   REAL NOT NULL DEFAULT 0.0,
    status       TEXT NOT NULL DEFAULT 'open',
    created_at   TEXT NOT NULL,
    claimed_by   TEXT,
    source       TEXT DEFAULT 'pipeline'
);

CREATE TABLE IF NOT EXISTS verification_windows (
    id                   TEXT PRIMARY KEY,
    pr_id                TEXT NOT NULL,
    repo                 TEXT NOT NULL,
    pr_number            INTEGER NOT NULL,
    installation_id      INTEGER NOT NULL,
    attestation_id       TEXT NOT NULL,
    verdict_json         TEXT NOT NULL,
    attestation_json     TEXT NOT NULL,
    contributor_address  TEXT,
    bounty_amount_wei    TEXT DEFAULT '0',
    stake_amount_wei     TEXT DEFAULT '0',
    window_hours         INTEGER NOT NULL,
    opens_at             TEXT NOT NULL,
    closes_at            TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'open',
    challenge_id         TEXT,
    challenger_address   TEXT,
    challenger_stake_wei TEXT,
    challenge_rationale  TEXT,
    resolution           TEXT,
    contributor_stake_id TEXT,
    challenger_stake_id  TEXT,
    is_self_modification INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pr_embeddings (
    id              TEXT PRIMARY KEY,
    pr_id           TEXT NOT NULL,
    repo            TEXT NOT NULL,
    pr_number       INTEGER,
    commit_sha      TEXT NOT NULL,
    embedding       BLOB NOT NULL,
    embedding_model TEXT NOT NULL DEFAULT '',
    issue_number    INTEGER,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vision_documents (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    doc_type     TEXT NOT NULL DEFAULT 'vision',
    content      TEXT NOT NULL,
    embedding    BLOB,
    updated_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vd_repo_doctype
    ON vision_documents(repo, doc_type);

CREATE TABLE IF NOT EXISTS vision_score_history (
    id               TEXT PRIMARY KEY,
    repo             TEXT NOT NULL,
    pr_id            TEXT NOT NULL,
    pr_number        INTEGER NOT NULL DEFAULT 0,
    vision_score     INTEGER NOT NULL,
    ai_confidence    REAL NOT NULL,
    goal_scores_json TEXT,
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vsh_repo_created
    ON vision_score_history(repo, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_identity_cache (
    wallet_address  TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    chain_id        INTEGER NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    registered_at   TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dispute_records (
    dispute_id           TEXT PRIMARY KEY,
    challenge_id         TEXT NOT NULL,
    window_id            TEXT NOT NULL,
    dispute_type         TEXT NOT NULL,
    claim_type           TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending',
    provider_case_id     TEXT,
    provider_verdict     TEXT,
    attestation_json     TEXT,
    challenger_address   TEXT NOT NULL,
    challenger_stake_wei TEXT NOT NULL DEFAULT '0',
    contributor_stake_id TEXT,
    challenger_stake_id  TEXT,
    submission_attempts  INTEGER NOT NULL DEFAULT 0,
    staking_applied      INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    resolved_at          TEXT
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
CREATE INDEX IF NOT EXISTS idx_as_created ON attestation_store(created_at);
CREATE INDEX IF NOT EXISTS idx_ab_repo ON active_bounties(repo);
CREATE INDEX IF NOT EXISTS idx_ab_status ON active_bounties(status);
CREATE INDEX IF NOT EXISTS idx_vw_status ON verification_windows(status);
CREATE INDEX IF NOT EXISTS idx_vw_closes_at ON verification_windows(closes_at);
CREATE INDEX IF NOT EXISTS idx_pe_repo ON pr_embeddings(repo);
CREATE INDEX IF NOT EXISTS idx_pe_repo_created ON pr_embeddings(repo, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vd_repo ON vision_documents(repo);
CREATE INDEX IF NOT EXISTS idx_dr_status ON dispute_records(status);
CREATE INDEX IF NOT EXISTS idx_dr_window ON dispute_records(window_id);

CREATE TABLE IF NOT EXISTS ranking_updates (
    id           TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    updated_at   TEXT NOT NULL,
    ranking_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_ru_repo_issue ON ranking_updates(repo, issue_number);
CREATE INDEX IF NOT EXISTS idx_pe_repo_issue ON pr_embeddings(repo, issue_number);

CREATE TABLE IF NOT EXISTS issue_embeddings (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    embedding BLOB NOT NULL,
    labels TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo, issue_number)
);
CREATE INDEX IF NOT EXISTS idx_ie_repo ON issue_embeddings(repo);
CREATE INDEX IF NOT EXISTS idx_ie_status ON issue_embeddings(status);

CREATE TABLE IF NOT EXISTS backfill_progress (
    id         TEXT PRIMARY KEY,
    repo       TEXT NOT NULL,
    mode       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'running',
    last_page  INTEGER NOT NULL DEFAULT 0,
    processed  INTEGER NOT NULL DEFAULT 0,
    failed     INTEGER NOT NULL DEFAULT 0,
    skipped    INTEGER NOT NULL DEFAULT 0,
    error_msg  TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(repo, mode)
);
CREATE INDEX IF NOT EXISTS idx_bp_repo_mode ON backfill_progress(repo, mode);

CREATE TABLE IF NOT EXISTS patrol_history (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    dependency_findings_count INTEGER DEFAULT 0,
    code_findings_count INTEGER DEFAULT 0,
    patches_generated INTEGER DEFAULT 0,
    issues_created INTEGER DEFAULT 0,
    bounties_assigned_wei TEXT DEFAULT '0',
    attestation_id TEXT,
    duration_ms INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_patrol_history_repo ON patrol_history(repo);
CREATE INDEX IF NOT EXISTS idx_patrol_history_timestamp ON patrol_history(timestamp);

CREATE TABLE IF NOT EXISTS known_vulnerabilities (
    id TEXT PRIMARY KEY,
    cve_id TEXT,
    dedup_key TEXT NOT NULL,
    package_name TEXT NOT NULL,
    language TEXT NOT NULL,
    severity TEXT NOT NULL,
    affected_range TEXT NOT NULL,
    fixed_version TEXT,
    advisory_url TEXT,
    repo TEXT NOT NULL,
    first_detected TEXT NOT NULL DEFAULT (datetime('now')),
    last_checked TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'open',
    bounty_issue_number INTEGER,
    UNIQUE(repo, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_known_vuln_package ON known_vulnerabilities(package_name, language);
CREATE INDEX IF NOT EXISTS idx_known_vuln_cve ON known_vulnerabilities(cve_id);

CREATE TABLE IF NOT EXISTS patrol_finding_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    bounty_issue_number INTEGER,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(repo, rule_id, file_path, line_start)
);
CREATE INDEX IF NOT EXISTS idx_pfs_repo ON patrol_finding_signatures(repo);

CREATE TABLE IF NOT EXISTS patrol_patches (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    pr_number INTEGER,
    cve_id TEXT,
    package_name TEXT NOT NULL,
    old_version TEXT NOT NULL,
    new_version TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    merged_at TEXT,
    attestation_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_patrol_patches_repo ON patrol_patches(repo);
CREATE INDEX IF NOT EXISTS idx_patrol_patches_status ON patrol_patches(status);

CREATE TABLE IF NOT EXISTS treasury_transactions (
    id              TEXT PRIMARY KEY,
    tx_hash         TEXT,
    tx_type         TEXT NOT NULL,
    amount_wei      INTEGER NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'ETH',
    counterparty    TEXT NOT NULL DEFAULT '',
    pr_id           TEXT,
    audit_id        TEXT,
    bounty_id       TEXT,
    attestation_id  TEXT,
    timestamp       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tt_timestamp ON treasury_transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_tt_tx_type ON treasury_transactions(tx_type);
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

    async def ping(self) -> None:
        """Lightweight health probe — raises RuntimeError if not initialized."""
        db = self._require_db()
        await db.execute("SELECT 1")

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
                if current < 2:
                    await db.executescript(
                        "CREATE TABLE IF NOT EXISTS agent_identity_cache ("
                        "    wallet_address  TEXT PRIMARY KEY,"
                        "    agent_id        TEXT NOT NULL,"
                        "    chain_id        INTEGER NOT NULL,"
                        "    name            TEXT NOT NULL DEFAULT '',"
                        "    description     TEXT NOT NULL DEFAULT '',"
                        "    registered_at   TEXT NOT NULL,"
                        "    updated_at      TEXT NOT NULL"
                        ");"
                    )
                if current < 3:
                    # Add new columns for expanded verification_windows schema.
                    # Column names are hard-coded literals — no SQL injection risk.
                    new_cols = [
                        ("pr_number", "INTEGER NOT NULL DEFAULT 0"),
                        ("installation_id", "INTEGER NOT NULL DEFAULT 0"),
                        ("verdict_json", "TEXT NOT NULL DEFAULT '{}'"),
                        ("attestation_json", "TEXT NOT NULL DEFAULT '{}'"),
                        ("contributor_address", "TEXT"),
                        ("bounty_amount_wei", "TEXT DEFAULT '0'"),
                        ("stake_amount_wei", "TEXT DEFAULT '0'"),
                        ("challenge_id", "TEXT"),
                        ("challenger_address", "TEXT"),
                        ("challenger_stake_wei", "TEXT"),
                        ("challenge_rationale", "TEXT"),
                        ("resolution", "TEXT"),
                        ("created_at", "TEXT NOT NULL DEFAULT ''"),
                        ("updated_at", "TEXT NOT NULL DEFAULT ''"),
                    ]
                    for col_name, col_def in new_cols:
                        with contextlib.suppress(sqlite3.OperationalError):
                            await db.execute(
                                f"ALTER TABLE verification_windows "
                                f"ADD COLUMN {col_name} {col_def}",
                            )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_vw_closes_at "
                        "ON verification_windows(closes_at)",
                    )
                    await db.commit()
                if current < 4:
                    await db.executescript(
                        "CREATE TABLE IF NOT EXISTS dispute_records ("
                        "    dispute_id           TEXT PRIMARY KEY,"
                        "    challenge_id         TEXT NOT NULL,"
                        "    window_id            TEXT NOT NULL,"
                        "    dispute_type         TEXT NOT NULL,"
                        "    claim_type           TEXT NOT NULL,"
                        "    status               TEXT NOT NULL DEFAULT 'pending',"
                        "    provider_case_id     TEXT,"
                        "    provider_verdict     TEXT,"
                        "    attestation_json     TEXT,"
                        "    challenger_address   TEXT NOT NULL,"
                        "    challenger_stake_wei TEXT NOT NULL DEFAULT '0',"
                        "    contributor_stake_id TEXT,"
                        "    challenger_stake_id  TEXT,"
                        "    submission_attempts  INTEGER NOT NULL DEFAULT 0,"
                        "    created_at           TEXT NOT NULL,"
                        "    updated_at           TEXT NOT NULL,"
                        "    resolved_at          TEXT"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_dr_status "
                        "ON dispute_records(status);"
                        "CREATE INDEX IF NOT EXISTS idx_dr_window "
                        "ON dispute_records(window_id);"
                    )
                    await db.commit()
                if current < 5:
                    await db.execute(
                        "ALTER TABLE verification_windows "
                        "ADD COLUMN contributor_stake_id TEXT",
                    )
                    await db.execute(
                        "ALTER TABLE verification_windows "
                        "ADD COLUMN challenger_stake_id TEXT",
                    )
                    await db.execute(
                        "ALTER TABLE dispute_records "
                        "ADD COLUMN staking_applied INTEGER NOT NULL DEFAULT 0",
                    )
                    await db.commit()
                if current < 6:
                    with contextlib.suppress(sqlite3.OperationalError):
                        await db.execute(
                            "ALTER TABLE verification_windows "
                            "ADD COLUMN is_self_modification INTEGER NOT NULL DEFAULT 0",
                        )
                    await db.commit()
                if current < 7:
                    new_cols_v7 = [
                        ("docker_image_digest", "TEXT NOT NULL DEFAULT ''"),
                        ("tee_platform_id", "TEXT NOT NULL DEFAULT ''"),
                        ("previous_attestation_id", "TEXT"),
                    ]
                    for col_name, col_def in new_cols_v7:
                        with contextlib.suppress(sqlite3.OperationalError):
                            await db.execute(
                                f"ALTER TABLE attestation_store "
                                f"ADD COLUMN {col_name} {col_def}",
                            )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_as_created "
                        "ON attestation_store(created_at)",
                    )
                    await db.commit()
                if current < 8:
                    new_cols_v8 = [
                        ("ai_seed", "INTEGER"),
                        ("ai_output_hash", "TEXT"),
                        ("ai_system_fingerprint", "TEXT"),
                        ("signer_address", "TEXT NOT NULL DEFAULT ''"),
                    ]
                    for col_name, col_def in new_cols_v8:
                        with contextlib.suppress(sqlite3.OperationalError):
                            await db.execute(
                                f"ALTER TABLE attestation_store "
                                f"ADD COLUMN {col_name} {col_def}",
                            )
                    await db.commit()
                if current < 9:
                    with contextlib.suppress(sqlite3.OperationalError):
                        await db.execute(
                            "ALTER TABLE pr_embeddings "
                            "ADD COLUMN embedding_model TEXT NOT NULL DEFAULT ''",
                        )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_pe_repo_created "
                        "ON pr_embeddings(repo, created_at DESC)",
                    )
                    await db.commit()
                if current < 10:
                    await db.executescript(
                        "CREATE TABLE IF NOT EXISTS ranking_updates ("
                        "    id           TEXT PRIMARY KEY,"
                        "    repo         TEXT NOT NULL,"
                        "    issue_number INTEGER NOT NULL,"
                        "    updated_at   TEXT NOT NULL,"
                        "    ranking_json TEXT NOT NULL DEFAULT '[]'"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_ru_repo_issue "
                        "ON ranking_updates(repo, issue_number);"
                        "CREATE INDEX IF NOT EXISTS idx_pe_repo_issue "
                        "ON pr_embeddings(repo, issue_number);"
                    )
                    await db.commit()
                if current < 11:
                    with contextlib.suppress(sqlite3.OperationalError):
                        await db.execute(
                            "ALTER TABLE vision_documents "
                            "ADD COLUMN doc_type TEXT NOT NULL DEFAULT 'vision'",
                        )
                    await db.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vd_repo_doctype "
                        "ON vision_documents(repo, doc_type)",
                    )
                    await db.commit()
                if current < 12:
                    await db.executescript(
                        "CREATE TABLE IF NOT EXISTS vision_score_history ("
                        "    id               TEXT PRIMARY KEY,"
                        "    repo             TEXT NOT NULL,"
                        "    pr_id            TEXT NOT NULL,"
                        "    pr_number        INTEGER NOT NULL DEFAULT 0,"
                        "    vision_score     INTEGER NOT NULL,"
                        "    ai_confidence    REAL NOT NULL,"
                        "    goal_scores_json TEXT,"
                        "    created_at       TEXT NOT NULL"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_vsh_repo_created "
                        "ON vision_score_history(repo, created_at DESC);"
                    )
                    await db.commit()
                if current < 13:
                    await db.executescript(
                        "CREATE TABLE IF NOT EXISTS issue_embeddings ("
                        "    id TEXT PRIMARY KEY,"
                        "    repo TEXT NOT NULL,"
                        "    issue_number INTEGER NOT NULL,"
                        "    title TEXT NOT NULL,"
                        "    embedding BLOB NOT NULL,"
                        "    labels TEXT,"
                        "    status TEXT DEFAULT 'open',"
                        "    created_at TEXT NOT NULL,"
                        "    updated_at TEXT NOT NULL,"
                        "    UNIQUE(repo, issue_number)"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_ie_repo "
                        "ON issue_embeddings(repo);"
                        "CREATE INDEX IF NOT EXISTS idx_ie_status "
                        "ON issue_embeddings(status);"
                    )
                    await db.commit()
                if current < 14:
                    await db.executescript(
                        "CREATE TABLE IF NOT EXISTS backfill_progress ("
                        "    id         TEXT PRIMARY KEY,"
                        "    repo       TEXT NOT NULL,"
                        "    mode       TEXT NOT NULL,"
                        "    status     TEXT NOT NULL DEFAULT 'running',"
                        "    last_page  INTEGER NOT NULL DEFAULT 0,"
                        "    processed  INTEGER NOT NULL DEFAULT 0,"
                        "    failed     INTEGER NOT NULL DEFAULT 0,"
                        "    skipped    INTEGER NOT NULL DEFAULT 0,"
                        "    error_msg  TEXT,"
                        "    created_at TEXT NOT NULL,"
                        "    updated_at TEXT NOT NULL,"
                        "    UNIQUE(repo, mode)"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_bp_repo_mode "
                        "ON backfill_progress(repo, mode);"
                    )
                    await db.commit()
                if current < 15:
                    await db.executescript(
                        "CREATE TABLE IF NOT EXISTS patrol_history ("
                        "    id TEXT PRIMARY KEY,"
                        "    repo TEXT NOT NULL,"
                        "    timestamp TEXT NOT NULL,"
                        "    dependency_findings_count INTEGER DEFAULT 0,"
                        "    code_findings_count INTEGER DEFAULT 0,"
                        "    patches_generated INTEGER DEFAULT 0,"
                        "    issues_created INTEGER DEFAULT 0,"
                        "    bounties_assigned_wei TEXT DEFAULT '0',"
                        "    attestation_id TEXT,"
                        "    duration_ms INTEGER,"
                        "    created_at TEXT NOT NULL DEFAULT (datetime('now'))"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_patrol_history_repo "
                        "ON patrol_history(repo);"
                        "CREATE INDEX IF NOT EXISTS idx_patrol_history_timestamp "
                        "ON patrol_history(timestamp);"
                        "CREATE TABLE IF NOT EXISTS known_vulnerabilities ("
                        "    id TEXT PRIMARY KEY,"
                        "    cve_id TEXT,"
                        "    dedup_key TEXT NOT NULL,"
                        "    package_name TEXT NOT NULL,"
                        "    language TEXT NOT NULL,"
                        "    severity TEXT NOT NULL,"
                        "    affected_range TEXT NOT NULL,"
                        "    fixed_version TEXT,"
                        "    advisory_url TEXT,"
                        "    repo TEXT NOT NULL,"
                        "    first_detected TEXT NOT NULL DEFAULT (datetime('now')),"
                        "    last_checked TEXT NOT NULL DEFAULT (datetime('now')),"
                        "    status TEXT NOT NULL DEFAULT 'open',"
                        "    bounty_issue_number INTEGER,"
                        "    UNIQUE(repo, dedup_key)"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_known_vuln_package "
                        "ON known_vulnerabilities(package_name, language);"
                        "CREATE INDEX IF NOT EXISTS idx_known_vuln_cve "
                        "ON known_vulnerabilities(cve_id);"
                        "CREATE TABLE IF NOT EXISTS patrol_finding_signatures ("
                        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "    repo TEXT NOT NULL,"
                        "    rule_id TEXT NOT NULL,"
                        "    file_path TEXT NOT NULL,"
                        "    line_start INTEGER NOT NULL,"
                        "    bounty_issue_number INTEGER,"
                        "    first_seen TEXT NOT NULL DEFAULT (datetime('now')),"
                        "    last_seen TEXT NOT NULL DEFAULT (datetime('now')),"
                        "    UNIQUE(repo, rule_id, file_path, line_start)"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_pfs_repo "
                        "ON patrol_finding_signatures(repo);"
                        "CREATE TABLE IF NOT EXISTS patrol_patches ("
                        "    id TEXT PRIMARY KEY,"
                        "    repo TEXT NOT NULL,"
                        "    pr_number INTEGER,"
                        "    cve_id TEXT,"
                        "    package_name TEXT NOT NULL,"
                        "    old_version TEXT NOT NULL,"
                        "    new_version TEXT NOT NULL,"
                        "    status TEXT DEFAULT 'pending',"
                        "    created_at TEXT NOT NULL DEFAULT (datetime('now')),"
                        "    merged_at TEXT,"
                        "    attestation_id TEXT"
                        ");"
                        "CREATE INDEX IF NOT EXISTS idx_patrol_patches_repo "
                        "ON patrol_patches(repo);"
                        "CREATE INDEX IF NOT EXISTS idx_patrol_patches_status "
                        "ON patrol_patches(status);"
                    )
                    with contextlib.suppress(sqlite3.OperationalError):
                        await db.execute(
                            "ALTER TABLE active_bounties "
                            "ADD COLUMN source TEXT DEFAULT 'pipeline'",
                        )
                    await db.commit()
            if current < 16:
                await db.executescript(
                    "CREATE TABLE IF NOT EXISTS treasury_transactions ("
                    "    id              TEXT PRIMARY KEY,"
                    "    tx_hash         TEXT,"
                    "    tx_type         TEXT NOT NULL,"
                    "    amount_wei      INTEGER NOT NULL,"
                    "    currency        TEXT NOT NULL DEFAULT 'ETH',"
                    "    counterparty    TEXT NOT NULL DEFAULT '',"
                    "    pr_id           TEXT,"
                    "    audit_id        TEXT,"
                    "    bounty_id       TEXT,"
                    "    attestation_id  TEXT,"
                    "    timestamp       TEXT NOT NULL,"
                    "    created_at      TEXT NOT NULL DEFAULT (datetime('now'))"
                    ");"
                    "CREATE INDEX IF NOT EXISTS idx_tt_timestamp "
                    "ON treasury_transactions(timestamp);"
                    "CREATE INDEX IF NOT EXISTS idx_tt_tx_type "
                    "ON treasury_transactions(tx_type);"
                )
                await db.commit()
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

    async def get_contributor_wallet(self, github_login: str) -> str | None:
        """Look up wallet address by GitHub login.  Uses ``idx_cp_github`` index."""
        db = self._require_db()
        async with db.execute(
            "SELECT wallet_address FROM contributor_profiles WHERE github_login = ?",
            (github_login,),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None or not row[0]:
                return None
            return str(row[0])

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
        docker_image_digest: str = "",
        tee_platform_id: str = "",
        previous_attestation_id: str | None = None,
        ai_seed: int | None = None,
        ai_output_hash: str | None = None,
        ai_system_fingerprint: str | None = None,
        signer_address: str = "",
        created_at: str | None = None,
    ) -> bool:
        """Persist an attestation proof.

        Uses ``INSERT OR IGNORE`` — a duplicate ``attestation_id`` is
        silently skipped, preserving the original proof and chain integrity.
        Returns ``True`` if the proof was inserted, ``False`` if it already
        existed.
        """
        db = self._require_db()
        ts = created_at or datetime.now(UTC).isoformat()
        async with self._write_lock:
            # Check for duplicate before insert (inside write lock — no race)
            async with db.execute(
                "SELECT 1 FROM attestation_store WHERE attestation_id = ?",
                (attestation_id,),
            ) as cursor:
                if await cursor.fetchone() is not None:
                    return False
            await db.execute(
                """\
                INSERT INTO attestation_store
                    (attestation_id, pr_id, repo, pipeline_input_hash,
                     pipeline_output_hash, signature, docker_image_digest,
                     tee_platform_id, previous_attestation_id,
                     ai_seed, ai_output_hash, ai_system_fingerprint,
                     signer_address, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (attestation_id, pr_id, repo, pipeline_input_hash,
                 pipeline_output_hash, signature, docker_image_digest,
                 tee_platform_id, previous_attestation_id,
                 ai_seed, ai_output_hash, ai_system_fingerprint,
                 signer_address, ts),
            )
            await db.commit()
            return True

    async def get_attestation(self, attestation_id: str) -> dict[str, object] | None:
        """Retrieve an attestation by ID."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM attestation_store WHERE attestation_id = ?",
            (attestation_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_latest_attestation_id(self) -> str | None:
        """Return the attestation_id of the most recent attestation, or None."""
        db = self._require_db()
        async with db.execute(
            "SELECT attestation_id FROM attestation_store "
            "ORDER BY created_at DESC LIMIT 1",
        ) as cursor:
            row = await cursor.fetchone()
            return str(row[0]) if row else None

    async def get_attestation_chain(
        self, start_id: str, count: int = 10,
    ) -> list[dict[str, object]]:
        """Walk the attestation chain backwards from *start_id*.

        Follows ``previous_attestation_id`` links up to *count* entries.
        """
        db = self._require_db()
        chain: list[dict[str, object]] = []
        current_id: str | None = start_id
        for _ in range(count):
            if current_id is None:
                break
            async with db.execute(
                "SELECT * FROM attestation_store WHERE attestation_id = ?",
                (current_id,),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                break
            entry = dict(row)
            chain.append(entry)
            prev = entry.get("previous_attestation_id")
            current_id = str(prev) if prev else None
        return chain

    # ── Bounties ─────────────────────────────────────────────────────────

    async def store_bounty(
        self,
        *,
        bounty_id: str,
        repo: str,
        issue_number: int,
        label: str,
        amount_eth: float = 0.0,
        source: str = "pipeline",
    ) -> None:
        """Create or update a bounty record."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO active_bounties
                    (id, repo, issue_number, label, amount_eth, status, created_at, source)
                VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (bounty_id, repo, issue_number, label, amount_eth, now, source),
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
        pr_number: int,
        installation_id: int,
        attestation_id: str,
        verdict_json: str,
        attestation_json: str,
        contributor_address: str | None,
        bounty_amount_wei: str,
        stake_amount_wei: str,
        window_hours: int,
        opens_at: str,
        closes_at: str,
        is_self_modification: bool = False,
    ) -> None:
        """Create a verification window with all metadata."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO verification_windows
                    (id, pr_id, repo, pr_number, installation_id,
                     attestation_id, verdict_json, attestation_json,
                     contributor_address, bounty_amount_wei, stake_amount_wei,
                     window_hours, opens_at, closes_at, status,
                     is_self_modification, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
                """,
                (
                    window_id, pr_id, repo, pr_number, installation_id,
                    attestation_id, verdict_json, attestation_json,
                    contributor_address, bounty_amount_wei, stake_amount_wei,
                    window_hours, opens_at, closes_at,
                    int(is_self_modification), now, now,
                ),
            )
            await db.commit()

    async def get_verification_window(
        self, window_id: str,
    ) -> dict[str, object] | None:
        """Retrieve a verification window by ID."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM verification_windows WHERE id = ?",
            (window_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_expired_open_windows(
        self, now_iso: str,
    ) -> list[dict[str, object]]:
        """Return open windows whose challenge period has elapsed."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM verification_windows "
            "WHERE status = 'open' AND closes_at <= ?",
            (now_iso,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_open_windows(self) -> list[dict[str, object]]:
        """Return all open verification windows."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM verification_windows WHERE status = 'open'",
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_windows_by_status(
        self, status: str,
    ) -> list[dict[str, object]]:
        """Return all verification windows with the given status."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM verification_windows WHERE status = ?",
            (status,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def transition_window_status(
        self,
        window_id: str,
        expected_status: str,
        new_status: str,
        *,
        resolution: str | None = None,
        challenge_id: str | None = None,
        challenger_address: str | None = None,
        challenger_stake_wei: str | None = None,
        challenge_rationale: str | None = None,
        contributor_stake_id: str | None = None,
        challenger_stake_id: str | None = None,
    ) -> bool:
        """Atomically transition window state. Returns True if transition happened.

        Uses compare-and-swap: only updates if current status matches
        ``expected_status``. Combined with ``_write_lock`` to prevent
        concurrent coroutines from interleaving.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            set_parts = ["status = ?", "updated_at = ?"]
            params: list[object] = [new_status, now]
            # Column names below are hard-coded literals — no injection risk.
            for col, val in [
                ("resolution", resolution),
                ("challenge_id", challenge_id),
                ("challenger_address", challenger_address),
                ("challenger_stake_wei", challenger_stake_wei),
                ("challenge_rationale", challenge_rationale),
                ("contributor_stake_id", contributor_stake_id),
                ("challenger_stake_id", challenger_stake_id),
            ]:
                if val is not None:
                    set_parts.append(f"{col} = ?")
                    params.append(val)
            params.extend([window_id, expected_status])
            cursor = await db.execute(
                f"UPDATE verification_windows SET {', '.join(set_parts)} "
                f"WHERE id = ? AND status = ?",
                params,
            )
            affected = cursor.rowcount
            await db.commit()
            return affected > 0

    async def get_stale_challenged_windows(
        self, deadline_iso: str,
    ) -> list[dict[str, object]]:
        """Return challenged/resolving windows with ``updated_at`` older than deadline."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM verification_windows "
            "WHERE status IN ('challenged', 'resolving') AND updated_at <= ?",
            (deadline_iso,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_all_verification_windows(self) -> list[dict[str, object]]:
        """Return all verification windows ordered by creation time."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM verification_windows ORDER BY created_at DESC",
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    # ── Dispute records ────────────────────────────────────────────────────

    async def store_dispute_record(
        self,
        *,
        dispute_id: str,
        challenge_id: str,
        window_id: str,
        dispute_type: str,
        claim_type: str,
        challenger_address: str,
        challenger_stake_wei: str = "0",
        contributor_stake_id: str | None = None,
        challenger_stake_id: str | None = None,
        attestation_json: str | None = None,
    ) -> None:
        """Persist a new dispute record (status=pending)."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT INTO dispute_records
                    (dispute_id, challenge_id, window_id, dispute_type,
                     claim_type, status, challenger_address,
                     challenger_stake_wei, contributor_stake_id,
                     challenger_stake_id, attestation_json,
                     submission_attempts, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    dispute_id, challenge_id, window_id, dispute_type,
                    claim_type, challenger_address, challenger_stake_wei,
                    contributor_stake_id, challenger_stake_id,
                    attestation_json, now, now,
                ),
            )
            await db.commit()

    async def check_and_insert_dispute(
        self,
        *,
        dispute_id: str,
        challenge_id: str,
        window_id: str,
        dispute_type: str,
        claim_type: str,
        challenger_address: str,
        challenger_stake_wei: str = "0",
        contributor_stake_id: str | None = None,
        challenger_stake_id: str | None = None,
        attestation_json: str | None = None,
    ) -> bool:
        """Atomically check for active disputes and insert if none exist.

        Performs the duplicate check and insert under a single
        ``_write_lock`` acquisition to prevent race conditions from
        concurrent ``open_dispute`` calls.

        Returns ``True`` if a new record was inserted, ``False`` if an
        active dispute already exists for the window.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            # Check for existing active dispute
            async with db.execute(
                "SELECT dispute_id FROM dispute_records "
                "WHERE window_id = ? AND status IN ('pending', 'submitted')",
                (window_id,),
            ) as cursor:
                if await cursor.fetchone() is not None:
                    return False

            await db.execute(
                """\
                INSERT INTO dispute_records
                    (dispute_id, challenge_id, window_id, dispute_type,
                     claim_type, status, challenger_address,
                     challenger_stake_wei, contributor_stake_id,
                     challenger_stake_id, attestation_json,
                     submission_attempts, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    dispute_id, challenge_id, window_id, dispute_type,
                    claim_type, challenger_address, challenger_stake_wei,
                    contributor_stake_id, challenger_stake_id,
                    attestation_json, now, now,
                ),
            )
            await db.commit()
            return True

    # Pre-defined UPDATE statements per column — no f-string interpolation.
    _DISPUTE_UPDATE_SQL: dict[str, str] = {
        "status": (
            "UPDATE dispute_records SET status = ?, updated_at = ? "
            "WHERE dispute_id = ?"
        ),
        "provider_case_id": (
            "UPDATE dispute_records SET provider_case_id = ?, updated_at = ? "
            "WHERE dispute_id = ?"
        ),
        "provider_verdict": (
            "UPDATE dispute_records SET provider_verdict = ?, updated_at = ? "
            "WHERE dispute_id = ?"
        ),
        "submission_attempts": (
            "UPDATE dispute_records SET submission_attempts = ?, updated_at = ? "
            "WHERE dispute_id = ?"
        ),
        "resolved_at": (
            "UPDATE dispute_records SET resolved_at = ?, updated_at = ? "
            "WHERE dispute_id = ?"
        ),
        "staking_applied": (
            "UPDATE dispute_records SET staking_applied = ?, updated_at = ? "
            "WHERE dispute_id = ?"
        ),
    }

    async def update_dispute_record(
        self,
        dispute_id: str,
        **kwargs: object,
    ) -> None:
        """Update specific fields on a dispute record.

        Accepts keyword arguments matching column names.  Column names
        are validated against a dict of pre-defined SQL statements to
        prevent SQL injection — no column names are ever interpolated.
        ``updated_at`` is always set to the current timestamp.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            for col, val in kwargs.items():
                sql = self._DISPUTE_UPDATE_SQL.get(col)
                if sql is None:
                    raise ValueError(f"Cannot update column: {col}")
                await db.execute(sql, (val, now, dispute_id))
            await db.commit()

    async def get_dispute_record(
        self, dispute_id: str,
    ) -> dict[str, object] | None:
        """Retrieve a dispute record by ID."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM dispute_records WHERE dispute_id = ?",
            (dispute_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_disputes_by_status(
        self, status: str,
    ) -> list[dict[str, object]]:
        """Return all dispute records with the given status."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM dispute_records WHERE status = ?",
            (status,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_disputes_for_window(
        self, window_id: str,
    ) -> list[dict[str, object]]:
        """Return all dispute records for a verification window."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM dispute_records WHERE window_id = ?",
            (window_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

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
        doc_type: str = "vision",
        embedding: bytes | None = None,
    ) -> None:
        """Store or update a vision document.

        Uses ``_retry_on_busy`` to handle SQLITE_BUSY under write contention.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()

        async def _do_store() -> None:
            async with self._write_lock:
                await db.execute(
                    """\
                    INSERT OR REPLACE INTO vision_documents
                        (id, repo, doc_type, content, embedding, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (doc_id, repo, doc_type, content, embedding, now),
                )
                await db.commit()

        await _retry_on_busy(_do_store)

    async def get_vision_document(self, repo: str) -> dict[str, str] | None:
        """Return the cached vision document for *repo*, or ``None``.

        Backward-compat wrapper — returns the first ``vision``-type document.
        The ``embedding`` BLOB is intentionally excluded — it is only used
        by the similarity engine, not by prompt construction.
        """
        docs = await self.get_vision_documents(repo, doc_type="vision")
        return docs[0] if docs else None

    async def get_vision_documents(
        self, repo: str, doc_type: str | None = None,
    ) -> list[dict[str, object]]:
        """Return vision documents for *repo*, optionally filtered by type.

        Each dict includes ``id``, ``repo``, ``doc_type``, ``content``,
        ``embedding`` (bytes or None), and ``updated_at``.
        """
        db = self._require_db()
        if doc_type is not None:
            cursor = await db.execute(
                "SELECT id, repo, doc_type, content, embedding, updated_at "
                "FROM vision_documents WHERE repo = ? AND doc_type = ?",
                (repo, doc_type),
            )
        else:
            cursor = await db.execute(
                "SELECT id, repo, doc_type, content, embedding, updated_at "
                "FROM vision_documents WHERE repo = ?",
                (repo,),
            )
        rows = await cursor.fetchall()
        return [
            {
                "id": row[0],
                "repo": row[1],
                "doc_type": row[2],
                "content": row[3],
                "embedding": row[4],
                "updated_at": row[5],
            }
            for row in rows
        ]

    async def purge_stale_vision_documents(
        self, max_age_days: int = 90,
    ) -> int:
        """Delete vision documents older than *max_age_days*.

        Uses ``_write_lock`` + ``_retry_on_busy``.  Returns the number of
        deleted rows.
        """
        db = self._require_db()
        cutoff = (datetime.now(UTC) - timedelta(days=max_age_days)).isoformat()

        async def _do_purge() -> int:
            async with self._write_lock:
                cursor = await db.execute(
                    "DELETE FROM vision_documents WHERE updated_at < ?",
                    (cutoff,),
                )
                deleted = cursor.rowcount
                await db.commit()
                return deleted

        return await _retry_on_busy(_do_purge)

    # ── Vision score trending ────────────────────────────────────────────

    async def store_vision_score(
        self,
        *,
        repo: str,
        pr_id: str,
        pr_number: int,
        vision_score: int,
        ai_confidence: float,
        goal_scores_json: str | None = None,
    ) -> None:
        """Record a vision alignment score for trending.

        Uses ``uuid.uuid4()`` for retry-safe IDs.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        score_id = uuid.uuid4().hex[:16]

        async def _do_store() -> None:
            async with self._write_lock:
                await db.execute(
                    """\
                    INSERT INTO vision_score_history
                        (id, repo, pr_id, pr_number, vision_score,
                         ai_confidence, goal_scores_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        score_id, repo, pr_id, pr_number,
                        vision_score, ai_confidence,
                        goal_scores_json, now,
                    ),
                )
                await db.commit()

        await _retry_on_busy(_do_store)

    async def get_vision_score_trend(
        self, repo: str, limit: int = 20,
    ) -> list[dict[str, object]]:
        """Return recent vision scores for *repo*, newest first."""
        db = self._require_db()
        cursor = await db.execute(
            "SELECT id, repo, pr_id, pr_number, vision_score, "
            "ai_confidence, goal_scores_json, created_at "
            "FROM vision_score_history "
            "WHERE repo = ? ORDER BY created_at DESC LIMIT ?",
            (repo, limit),
        )
        rows = await cursor.fetchall()
        return [
            {
                "id": row[0],
                "repo": row[1],
                "pr_id": row[2],
                "pr_number": row[3],
                "vision_score": row[4],
                "ai_confidence": row[5],
                "goal_scores_json": row[6],
                "created_at": row[7],
            }
            for row in rows
        ]

    # ── Identity cache ────────────────────────────────────────────────────

    async def cache_identity(self, identity: AgentIdentity) -> None:
        """Cache an agent identity for cross-boot recovery.

        Uses ``INSERT OR REPLACE`` so repeated calls for the same wallet
        address update rather than conflict.  Requires ``_write_lock``.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT OR REPLACE INTO agent_identity_cache
                    (wallet_address, agent_id, chain_id, name,
                     description, registered_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identity.wallet_address,
                    identity.agent_id,
                    identity.chain_id,
                    identity.name,
                    identity.description,
                    identity.registered_at.isoformat(),
                    now,
                ),
            )
            await db.commit()

    async def get_cached_identity(
        self, wallet_address: str,
    ) -> AgentIdentity | None:
        """Retrieve a cached identity by wallet address.  Read-only."""
        db = self._require_db()
        async with db.execute(
            "SELECT wallet_address, agent_id, chain_id, name, "
            "description, registered_at FROM agent_identity_cache "
            "WHERE wallet_address = ?",
            (wallet_address,),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return AgentIdentity(
                agent_id=row[1],
                chain_id=row[2],
                wallet_address=row[0],
                name=row[3],
                description=row[4],
                registered_at=datetime.fromisoformat(row[5]),
            )

    # ── Ranking ──────────────────────────────────────────────────────────

    async def get_ranked_prs(
        self, repo: str, issue_number: int,
    ) -> list[dict[str, object]]:
        """Return PRs targeting an issue, ranked by latest composite score.

        Uses a window function to select the most recent pipeline run per PR,
        then joins with ``pr_embeddings`` for issue linkage.  Read-only — no
        ``_write_lock`` required.
        """
        db = self._require_db()
        sql = """\
            SELECT pe.pr_number, ph.pr_id, ph.composite_score,
                   ph.verdict, ph.pr_author
            FROM pr_embeddings pe
            INNER JOIN (
                SELECT pr_id, composite_score, verdict, pr_author,
                       ROW_NUMBER() OVER (
                           PARTITION BY pr_id ORDER BY created_at DESC
                       ) AS rn
                FROM pipeline_history WHERE repo = ?
            ) ph ON pe.pr_id = ph.pr_id AND ph.rn = 1
            WHERE pe.repo = ? AND pe.issue_number = ?
              AND ph.composite_score IS NOT NULL
            ORDER BY ph.composite_score DESC, pe.pr_number ASC
        """
        async with db.execute(sql, (repo, repo, issue_number)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def record_ranking_update(
        self,
        repo: str,
        issue_number: int,
        ranking_json: str,
    ) -> None:
        """Record a ranking update for rate-limiting purposes.

        Uses ``uuid.uuid4()`` for the primary key to avoid collisions on
        retries (per CLAUDE.md concurrency rules).

        Prunes old rows to keep at most 5 per ``(repo, issue_number)``
        for audit trail without unbounded growth.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        record_id = uuid.uuid4().hex[:16]
        async with self._write_lock:
            await db.execute(
                "INSERT INTO ranking_updates "
                "(id, repo, issue_number, updated_at, ranking_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (record_id, repo, issue_number, now, ranking_json),
            )
            # Prune: keep only 5 most recent per (repo, issue_number)
            await db.execute(
                "DELETE FROM ranking_updates "
                "WHERE repo = ? AND issue_number = ? "
                "AND id NOT IN ("
                "    SELECT id FROM ranking_updates "
                "    WHERE repo = ? AND issue_number = ? "
                "    ORDER BY updated_at DESC LIMIT 5"
                ")",
                (repo, issue_number, repo, issue_number),
            )
            await db.commit()

    async def was_ranking_recently_posted(
        self,
        repo: str,
        issue_number: int,
        interval_seconds: int,
    ) -> bool:
        """Check if a ranking update was posted within the given interval.

        Returns ``False`` if no record exists (first post is always allowed).
        Read-only — no ``_write_lock`` required.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT updated_at FROM ranking_updates "
            "WHERE repo = ? AND issue_number = ? "
            "ORDER BY updated_at DESC LIMIT 1",
            (repo, issue_number),
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            return False

        last_update = datetime.fromisoformat(row[0])
        elapsed = (datetime.now(UTC) - last_update).total_seconds()
        return elapsed < interval_seconds

    # ── Embeddings ───────────────────────────────────────────────────────

    async def store_embedding(
        self,
        pr_id: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        embedding_blob: bytes,
        issue_number: int | None = None,
        embedding_model: str = "",
    ) -> None:
        """Store a PR embedding, updating on conflict to preserve created_at."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        emb_id = hashlib.sha256(f"{pr_id}-{commit_sha}".encode()).hexdigest()[:16]
        async with self._write_lock:
            await db.execute(
                """\
                INSERT INTO pr_embeddings
                    (id, pr_id, repo, pr_number, commit_sha, embedding,
                     embedding_model, issue_number, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    embedding = excluded.embedding,
                    embedding_model = excluded.embedding_model,
                    issue_number = excluded.issue_number
                """,
                (emb_id, pr_id, repo, pr_number, commit_sha,
                 embedding_blob, embedding_model, issue_number, now),
            )
            await db.commit()

    async def backfill_embedding_issue_number(
        self,
        pr_id: str,
        repo: str,
        issue_number: int,
    ) -> int:
        """Backfill ``issue_number`` on existing embeddings that have NULL.

        Only updates rows where ``issue_number IS NULL`` — will not overwrite
        intentionally set values.  Idempotent: a second call returns 0.

        Returns the number of rows updated.
        """
        db = self._require_db()
        async with self._write_lock:
            cursor = await db.execute(
                "UPDATE pr_embeddings SET issue_number = ? "
                "WHERE pr_id = ? AND repo = ? AND issue_number IS NULL",
                (issue_number, pr_id, repo),
            )
            updated = cursor.rowcount
            await db.commit()
            return updated

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

    async def get_recent_embeddings(
        self,
        repo: str,
        exclude_pr_number: int | None = None,
        limit: int = 200,
        embedding_model: str = "",
    ) -> list[dict[str, object]]:
        """Fetch recent embeddings for a repo, optionally excluding one PR.

        When *embedding_model* is non-empty, only rows matching that model
        are returned — prevents comparing vectors from different models.

        Returns raw rows as dicts with ``pr_id``, ``pr_number``,
        ``commit_sha``, and ``embedding`` (bytes blob).  Read-only — no
        ``_write_lock`` required.
        """
        db = self._require_db()

        # Four SQL branches: with/without exclude, with/without model filter.
        # All use parameterized queries — no f-strings.
        if exclude_pr_number is not None and embedding_model:
            async with db.execute(
                "SELECT pr_id, pr_number, commit_sha, embedding "
                "FROM pr_embeddings "
                "WHERE repo = ? AND pr_number != ? AND embedding_model = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (repo, exclude_pr_number, embedding_model, limit),
            ) as cursor:
                rows = await cursor.fetchall()
        elif exclude_pr_number is not None:
            async with db.execute(
                "SELECT pr_id, pr_number, commit_sha, embedding "
                "FROM pr_embeddings WHERE repo = ? AND pr_number != ? "
                "ORDER BY created_at DESC LIMIT ?",
                (repo, exclude_pr_number, limit),
            ) as cursor:
                rows = await cursor.fetchall()
        elif embedding_model:
            async with db.execute(
                "SELECT pr_id, pr_number, commit_sha, embedding "
                "FROM pr_embeddings "
                "WHERE repo = ? AND embedding_model = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (repo, embedding_model, limit),
            ) as cursor:
                rows = await cursor.fetchall()
        else:
            async with db.execute(
                "SELECT pr_id, pr_number, commit_sha, embedding "
                "FROM pr_embeddings WHERE repo = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (repo, limit),
            ) as cursor:
                rows = await cursor.fetchall()

        return [
            {
                "pr_id": row[0],
                "pr_number": row[1],
                "commit_sha": row[2],
                "embedding": row[3],
            }
            for row in rows
        ]

    # ── Issue embeddings ────────────────────────────────────────────────

    async def store_issue_embedding(
        self,
        *,
        issue_id: str,
        repo: str,
        issue_number: int,
        title: str,
        embedding: bytes,
        labels: list[str] | None = None,
    ) -> None:
        """Store or upsert an issue embedding.

        Uses ``ON CONFLICT(repo, issue_number) DO UPDATE`` to transparently
        update when an issue is edited while preserving the original
        ``created_at`` timestamp for correct recency ordering.
        ``labels`` is serialized as a JSON array string.
        Uses ``_write_lock`` to prevent concurrent writers.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        labels_json = json.dumps(labels) if labels is not None else None

        async def _do_store() -> None:
            async with self._write_lock:
                await db.execute(
                    """\
                    INSERT INTO issue_embeddings
                        (id, repo, issue_number, title, embedding,
                         labels, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)
                    ON CONFLICT(repo, issue_number) DO UPDATE SET
                        id = excluded.id,
                        title = excluded.title,
                        embedding = excluded.embedding,
                        labels = excluded.labels,
                        status = 'open',
                        updated_at = excluded.updated_at
                    """,
                    (
                        issue_id, repo, issue_number, title,
                        embedding, labels_json, now, now,
                    ),
                )
                await db.commit()

        await _retry_on_busy(_do_store)

    async def get_recent_issue_embeddings(
        self,
        repo: str,
        *,
        exclude_issue: int,
        status: str = "open",
        limit: int = 500,
    ) -> list[dict[str, object]]:
        """Fetch recent issue embeddings for a repo, excluding one issue.

        Returns rows as dicts with ``issue_number``, ``title``,
        ``embedding`` (bytes blob), and ``status``.  Read-only — no
        ``_write_lock`` required.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT issue_number, title, embedding, status "
            "FROM issue_embeddings "
            "WHERE repo = ? AND issue_number != ? AND status = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (repo, exclude_issue, status, limit),
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            {
                "issue_number": row[0],
                "title": row[1],
                "embedding": row[2],
                "status": row[3],
            }
            for row in rows
        ]

    async def get_issue_embedding(
        self,
        repo: str,
        issue_number: int,
    ) -> dict[str, object] | None:
        """Retrieve a single issue embedding by repo+issue_number.

        Returns the full row as a dict, or ``None`` if not found.
        Read-only — no ``_write_lock`` required.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM issue_embeddings "
            "WHERE repo = ? AND issue_number = ?",
            (repo, issue_number),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def update_issue_status(
        self,
        repo: str,
        issue_number: int,
        status: str,
    ) -> int:
        """Update the status of an issue embedding.

        Returns the number of rows updated (0 or 1).
        Uses ``_write_lock`` for write safety.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            cursor = await db.execute(
                "UPDATE issue_embeddings SET status = ?, updated_at = ? "
                "WHERE repo = ? AND issue_number = ?",
                (status, now, repo, issue_number),
            )
            updated = cursor.rowcount
            await db.commit()
            return updated

    # ── PR embedding lookup ──────────────────────────────────────────────

    async def get_pr_embedding(
        self,
        repo: str,
        pr_number: int,
    ) -> dict[str, object] | None:
        """Retrieve a single PR embedding by repo+pr_number.

        Used by the backfill engine for idempotency checks — if an
        embedding already exists, the PR can be skipped.
        Read-only — no ``_write_lock`` required.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT id, pr_id, repo, pr_number, commit_sha, embedding_model, "
            "issue_number, created_at "
            "FROM pr_embeddings WHERE repo = ? AND pr_number = ?",
            (repo, pr_number),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    # ── Vector index support ──────────────────────────────────────────────

    _EMBEDDING_TABLES = frozenset({"pr_embeddings", "issue_embeddings"})

    async def get_all_embeddings(self, *, table: str) -> list[dict[str, object]]:
        """Bulk-read all embeddings for HNSW index initialization.

        For ``pr_embeddings``, returns ``pr_id`` as the external ID (not the
        hash ``id``), ordered by ``created_at ASC`` so that later entries for
        the same ``pr_id`` overwrite earlier ones in the index.

        For ``issue_embeddings``, returns ``id`` as the external ID.

        Raises ``ValueError`` for unrecognised table names (SQL injection guard).
        """
        if table not in self._EMBEDDING_TABLES:
            raise ValueError(f"Invalid embedding table: {table}")
        db = self._require_db()
        if table == "pr_embeddings":
            query = "SELECT pr_id, embedding FROM pr_embeddings ORDER BY created_at ASC"
        else:
            query = "SELECT id, embedding FROM issue_embeddings"
        async with db.execute(query) as cursor:
            rows = await cursor.fetchall()
        return [{"id": row[0], "embedding": row[1]} for row in rows]

    async def count_embeddings(self, table: str) -> int:
        """Count embeddings in a table for auto-enable heuristic.

        Raises ``ValueError`` for unrecognised table names.
        """
        if table not in self._EMBEDDING_TABLES:
            raise ValueError(f"Invalid embedding table: {table}")
        db = self._require_db()
        if table == "pr_embeddings":
            query = "SELECT COUNT(*) FROM pr_embeddings"
        else:
            query = "SELECT COUNT(*) FROM issue_embeddings"
        async with db.execute(query) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_pr_embedding_by_pr_id(self, pr_id: str) -> dict[str, object] | None:
        """Fetch most recent PR embedding metadata by ``pr_id``.

        Returns ``pr_id``, ``pr_number``, and ``commit_sha`` for the most
        recent embedding row matching the given ``pr_id``.  Used by
        ``find_similar`` to enrich HNSW results with PR metadata.

        Read-only — no ``_write_lock`` required.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT pr_id, pr_number, commit_sha FROM pr_embeddings "
            "WHERE pr_id = ? ORDER BY created_at DESC LIMIT 1",
            (pr_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if not row:
            return None
        return {"pr_id": row[0], "pr_number": row[1], "commit_sha": row[2]}

    # ── Backfill progress ────────────────────────────────────────────────

    async def get_backfill_progress(
        self,
        repo: str,
        mode: str,
    ) -> dict[str, object] | None:
        """Retrieve the backfill progress record for a repo+mode.

        Returns the row as a dict, or ``None`` if no prior run exists.
        Read-only — no ``_write_lock`` required.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM backfill_progress WHERE repo = ? AND mode = ?",
            (repo, mode),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def save_backfill_progress(
        self,
        *,
        repo: str,
        mode: str,
        status: str,
        last_page: int,
        processed: int,
        failed: int,
        skipped: int,
        error_msg: str | None = None,
    ) -> None:
        """Upsert backfill progress for a repo+mode.

        Uses ``ON CONFLICT(repo, mode) DO UPDATE`` so repeated saves
        are idempotent.  Uses ``_write_lock`` for write safety.
        """
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        progress_id = hashlib.sha256(f"backfill:{repo}:{mode}".encode()).hexdigest()[:16]

        async def _do_save() -> None:
            async with self._write_lock:
                await db.execute(
                    """\
                    INSERT INTO backfill_progress
                        (id, repo, mode, status, last_page, processed,
                         failed, skipped, error_msg, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repo, mode) DO UPDATE SET
                        status = excluded.status,
                        last_page = excluded.last_page,
                        processed = excluded.processed,
                        failed = excluded.failed,
                        skipped = excluded.skipped,
                        error_msg = excluded.error_msg,
                        updated_at = excluded.updated_at
                    """,
                    (
                        progress_id, repo, mode, status, last_page,
                        processed, failed, skipped, error_msg, now, now,
                    ),
                )
                await db.commit()

        await _retry_on_busy(_do_save)

    # ── Patrol ────────────────────────────────────────────────────────────

    async def record_patrol_run(
        self,
        *,
        run_id: str,
        repo: str,
        timestamp: str,
        dependency_findings_count: int = 0,
        code_findings_count: int = 0,
        patches_generated: int = 0,
        issues_created: int = 0,
        bounties_assigned_wei: str = "0",
        attestation_id: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        """Insert a patrol run record into ``patrol_history``."""
        db = self._require_db()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT INTO patrol_history
                    (id, repo, timestamp, dependency_findings_count,
                     code_findings_count, patches_generated, issues_created,
                     bounties_assigned_wei, attestation_id, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, repo, timestamp, dependency_findings_count,
                    code_findings_count, patches_generated, issues_created,
                    bounties_assigned_wei, attestation_id, duration_ms,
                ),
            )
            await db.commit()

    async def get_latest_patrol_run(self, repo: str) -> dict[str, object] | None:
        """Return the most recent patrol run for *repo*, or ``None``."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM patrol_history WHERE repo = ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (repo,),
        ) as cursor:
            row = await cursor.fetchone()
        if not row:
            return None
        return dict(row)

    async def record_patrol_patch(
        self,
        *,
        patch_id: str,
        repo: str,
        pr_number: int | None = None,
        cve_id: str | None = None,
        package_name: str,
        old_version: str,
        new_version: str,
        status: str = "pending",
        attestation_id: str | None = None,
    ) -> None:
        """Insert a patrol patch record into ``patrol_patches``."""
        db = self._require_db()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT INTO patrol_patches
                    (id, repo, pr_number, cve_id, package_name,
                     old_version, new_version, status, attestation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    patch_id, repo, pr_number, cve_id, package_name,
                    old_version, new_version, status, attestation_id,
                ),
            )
            await db.commit()

    async def count_open_patrol_bounties(self, repo: str) -> int:
        """Count open bounties created by patrol for *repo*."""
        db = self._require_db()
        async with db.execute(
            "SELECT COUNT(*) FROM active_bounties "
            "WHERE repo = ? AND status = 'open' AND source = 'patrol'",
            (repo,),
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_known_vulnerability(
        self, repo: str, dedup_key: str,
    ) -> dict[str, object] | None:
        """Look up a known vulnerability by repo + dedup_key."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM known_vulnerabilities WHERE repo = ? AND dedup_key = ?",
            (repo, dedup_key),
        ) as cursor:
            row = await cursor.fetchone()
        if not row:
            return None
        return dict(row)

    @staticmethod
    def compute_dedup_key(
        cve_id: str | None,
        package_name: str,
        language: str,
        affected_range: str,
    ) -> str:
        """Compute a deterministic dedup key for a vulnerability.

        Uses the CVE ID when available, otherwise falls back to a composite
        of package metadata so non-CVE findings still dedup correctly.
        """
        if cve_id:
            return cve_id
        return f"{package_name}:{language}:{affected_range}"

    async def upsert_known_vulnerability(
        self,
        *,
        vuln_id: str,
        cve_id: str | None,
        dedup_key: str,
        package_name: str,
        language: str,
        severity: str,
        affected_range: str,
        fixed_version: str | None = None,
        advisory_url: str | None = None,
        repo: str,
        status: str = "open",
        bounty_issue_number: int | None = None,
    ) -> None:
        """Insert or update a known vulnerability record."""
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                """\
                INSERT INTO known_vulnerabilities
                    (id, cve_id, dedup_key, package_name, language, severity,
                     affected_range, fixed_version, advisory_url, repo,
                     first_detected, last_checked, status, bounty_issue_number)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repo, dedup_key) DO UPDATE SET
                    severity = excluded.severity,
                    affected_range = excluded.affected_range,
                    fixed_version = excluded.fixed_version,
                    advisory_url = excluded.advisory_url,
                    last_checked = excluded.last_checked,
                    status = excluded.status,
                    bounty_issue_number = COALESCE(
                        excluded.bounty_issue_number,
                        known_vulnerabilities.bounty_issue_number
                    )
                """,
                (
                    vuln_id, cve_id, dedup_key, package_name, language, severity,
                    affected_range, fixed_version, advisory_url, repo,
                    now, now, status, bounty_issue_number,
                ),
            )
            await db.commit()

    # ── Patrol finding signatures ─────────────────────────────────────

    async def get_known_finding_signatures(
        self, repo: str,
    ) -> set[tuple[str, str, int]]:
        """Return known finding signatures as ``(rule_id, file_path, line_start)`` tuples."""
        db = self._require_db()
        async with db.execute(
            "SELECT rule_id, file_path, line_start FROM patrol_finding_signatures "
            "WHERE repo = ?",
            (repo,),
        ) as cursor:
            rows = await cursor.fetchall()
        return {(row[0], row[1], row[2]) for row in rows}

    async def upsert_finding_signatures(
        self,
        repo: str,
        signatures: list[tuple[str, str, int]],
    ) -> None:
        """Batch insert or update finding signatures, refreshing ``last_seen``."""
        if not signatures:
            return
        db = self._require_db()
        now = datetime.now(UTC).isoformat()
        async with self._write_lock:
            for rule_id, file_path, line_start in signatures:
                await db.execute(
                    """\
                    INSERT INTO patrol_finding_signatures
                        (repo, rule_id, file_path, line_start, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repo, rule_id, file_path, line_start) DO UPDATE SET
                        last_seen = excluded.last_seen
                    """,
                    (repo, rule_id, file_path, line_start, now, now),
                )
            await db.commit()

    async def get_code_finding_bounty(
        self, repo: str, rule_id: str, file_path: str, line_start: int,
    ) -> int | None:
        """Return bounty issue number for a code finding, or ``None`` if not found."""
        db = self._require_db()
        async with db.execute(
            "SELECT bounty_issue_number FROM patrol_finding_signatures "
            "WHERE repo = ? AND rule_id = ? AND file_path = ? AND line_start = ? "
            "AND bounty_issue_number IS NOT NULL",
            (repo, rule_id, file_path, line_start),
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else None

    async def set_finding_bounty(
        self, repo: str, rule_id: str, file_path: str, line_start: int,
        bounty_issue_number: int,
    ) -> None:
        """Record the bounty issue number for a code finding signature."""
        db = self._require_db()
        async with self._write_lock:
            await db.execute(
                "UPDATE patrol_finding_signatures SET bounty_issue_number = ? "
                "WHERE repo = ? AND rule_id = ? AND file_path = ? AND line_start = ?",
                (bounty_issue_number, repo, rule_id, file_path, line_start),
            )
            await db.commit()

    # ── Dashboard query methods ───────────────────────────────────────

    async def list_pipeline_history(
        self,
        repo: str | None = None,
        verdict: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return pipeline history records with parsed verdict JSON."""
        db = self._require_db()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = ?")
            params.append(repo)
        if verdict:
            conditions.append("verdict LIKE ?")
            params.append(f'%"decision": "{verdict}"%')
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM pipeline_history{where} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        results = []
        for row in rows:
            record = dict(zip(cols, row, strict=False))
            raw = record.get("verdict", "{}")
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else raw
            except (json.JSONDecodeError, TypeError):
                parsed = {}
            record["verdict_parsed"] = parsed
            record["verdict"] = parsed.get("decision", "UNKNOWN")
            record["score_breakdown"] = parsed.get("score_breakdown", {})
            record["is_self_modification"] = parsed.get("is_self_modification", False)
            record["threshold_used"] = parsed.get("threshold_used")
            results.append(record)
        return results

    async def get_pipeline_record(self, record_id: str) -> dict[str, Any] | None:
        """Return a single pipeline history record with parsed verdict JSON."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM pipeline_history WHERE id = ?", (record_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cursor.description]
        record = dict(zip(cols, row, strict=False))
        raw = record.get("verdict", "{}")
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        record["verdict_parsed"] = parsed
        record["verdict"] = parsed.get("decision", "UNKNOWN")
        record["score_breakdown"] = parsed.get("score_breakdown", {})
        record["is_self_modification"] = parsed.get("is_self_modification", False)
        record["threshold_used"] = parsed.get("threshold_used")
        record["attestation_id"] = parsed.get("attestation_id")
        return record

    async def count_pipeline_history(
        self,
        repo: str | None = None,
        verdict: str | None = None,
    ) -> int:
        """Count pipeline history records matching optional filters."""
        db = self._require_db()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = ?")
            params.append(repo)
        if verdict:
            conditions.append("verdict LIKE ?")
            params.append(f'%"decision": "{verdict}"%')
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT COUNT(*) FROM pipeline_history{where}"  # noqa: S608
        async with db.execute(sql, params) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def list_contributors(
        self,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return contributor profiles ordered by approved submissions."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM contributor_profiles "
            "ORDER BY approved_submissions DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def get_contributor(self, contributor_id: str) -> dict[str, Any] | None:
        """Return a single contributor profile by ID."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM contributor_profiles WHERE id = ?",
            (contributor_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cursor.description]
        return dict(zip(cols, row, strict=False))

    async def count_contributors(self) -> int:
        """Count total contributor profiles."""
        db = self._require_db()
        async with db.execute(
            "SELECT COUNT(*) FROM contributor_profiles",
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def list_patrol_history(
        self,
        repo: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return patrol history records ordered by timestamp descending."""
        db = self._require_db()
        params: list[Any] = []
        where = ""
        if repo:
            where = " WHERE repo = ?"
            params.append(repo)
        sql = (
            f"SELECT * FROM patrol_history{where} "  # noqa: S608
            "ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def list_known_vulnerabilities(
        self,
        repo: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return known vulnerabilities with optional filters."""
        db = self._require_db()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = ?")
            params.append(repo)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM known_vulnerabilities{where} "  # noqa: S608
            "ORDER BY first_detected DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def list_patrol_patches(
        self,
        repo: str | None = None,
        status: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return patrol patches with optional filters."""
        db = self._require_db()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = ?")
            params.append(repo)
        if status:
            conditions.append("status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM patrol_patches{where} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def list_codebase_knowledge(self, repo: str) -> list[dict[str, Any]]:
        """Return all codebase knowledge entries for a repository."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM codebase_knowledge WHERE repo = ? ORDER BY file_path",
            (repo,),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def search_attestations(
        self,
        query: str | None = None,
        action_type: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search attestation records by ID or PR ID prefix."""
        db = self._require_db()
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            conditions.append(
                "(attestation_id LIKE ? OR pr_id LIKE ?)",
            )
            like_param = f"%{query}%"
            params.extend([like_param, like_param])
        if action_type:
            conditions.append("attestation_id LIKE ?")
            params.append(f"{action_type}-%")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM attestation_store{where} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def count_attestations(
        self,
        query: str | None = None,
        action_type: str | None = None,
    ) -> int:
        """Count attestation records matching optional filters."""
        db = self._require_db()
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            conditions.append("(attestation_id LIKE ? OR pr_id LIKE ?)")
            like_param = f"%{query}%"
            params.extend([like_param, like_param])
        if action_type:
            conditions.append("attestation_id LIKE ?")
            params.append(f"{action_type}-%")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT COUNT(*) FROM attestation_store{where}"  # noqa: S608
        async with db.execute(sql, params) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def list_all_vision_documents(self) -> list[dict[str, Any]]:
        """Return all vision documents without content/embedding for listing."""
        db = self._require_db()
        async with db.execute(
            "SELECT id, repo, doc_type, updated_at FROM vision_documents "
            "ORDER BY updated_at DESC",
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def list_transactions(
        self,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return treasury transactions ordered by timestamp descending."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM treasury_transactions "
            "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row, strict=False)) for row in rows]

    async def count_transactions(self) -> int:
        """Count total treasury transactions."""
        db = self._require_db()
        async with db.execute(
            "SELECT COUNT(*) FROM treasury_transactions",
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def record_transaction(
        self,
        *,
        tx_id: str,
        tx_hash: str,
        tx_type: str,
        amount_wei: int,
        currency: str = "ETH",
        counterparty: str = "",
        pr_id: str | None = None,
        audit_id: str | None = None,
        bounty_id: str | None = None,
        attestation_id: str | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Persist a treasury transaction to the database."""
        db = self._require_db()
        ts = timestamp or datetime.now(UTC).isoformat()
        async with self._write_lock:
            await db.execute(
                "INSERT INTO treasury_transactions "
                "(id, tx_hash, tx_type, amount_wei, currency, counterparty, "
                "pr_id, audit_id, bounty_id, attestation_id, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tx_id, tx_hash, tx_type, amount_wei, currency, counterparty,
                    pr_id, audit_id, bounty_id, attestation_id, ts,
                ),
            )
            await db.commit()
