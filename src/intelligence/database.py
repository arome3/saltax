"""Intelligence pattern database backed by Supabase PostgreSQL.

The intelligence DB accumulates vulnerability patterns, contributor profiles,
and pipeline history from every code interaction.  Data is stored in a
persistent PostgreSQL database (Supabase) that survives TEE restarts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from src.intelligence.pattern_extractor import extract_patterns
from src.intelligence.similarity import _extract_code_tokens, cosine_similarity

if TYPE_CHECKING:
    from psycopg import AsyncConnection

    from src.models.identity import AgentIdentity

logger = logging.getLogger(__name__)

# ── Module constants ─────────────────────────────────────────────────────────

_FP_THRESHOLD = 0.8
_MIN_FEEDBACK_FOR_SUPPRESSION = 5
_MIN_VERDICTS_FOR_HISTORY = 5
_CURRENT_SCHEMA_VERSION = 17
_MAX_LIKE_TOKENS = 20

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


# ── IntelligenceDB ───────────────────────────────────────────────────────────


class IntelligenceDB:
    """Stores and retrieves learned patterns for the decision engine.

    Data is stored in Supabase PostgreSQL.  Connection pooling is managed
    by ``psycopg_pool.AsyncConnectionPool``.
    """

    def __init__(
        self,
        database_url: str,
        *,
        pool_min_size: int = 2,
        pool_max_size: int = 10,
    ) -> None:
        self._database_url = database_url
        self._pool: AsyncConnectionPool | None = None
        self._pool_min_size = pool_min_size
        self._pool_max_size = pool_max_size
        self._initialized = False

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def pool(self) -> AsyncConnectionPool:
        """Expose the connection pool for shared use (e.g. TxHashStore)."""
        return self._require_pool()

    def _require_pool(self) -> AsyncConnectionPool:
        """Return the pool or raise if not initialized.

        Uses an explicit check instead of ``assert`` so it is never
        stripped by ``python -O``.
        """
        if self._pool is None:
            raise RuntimeError("IntelligenceDB is not initialized; call initialize() first")
        return self._pool

    async def ping(self) -> None:
        """Lightweight health probe — raises RuntimeError if not initialized."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            await conn.execute("SELECT 1")

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Open the connection pool and apply the schema.

        Safe to call multiple times — closes the prior pool first.
        """
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            self._initialized = False

        self._pool = AsyncConnectionPool(
            conninfo=self._database_url,
            min_size=self._pool_min_size,
            max_size=self._pool_max_size,
            kwargs={"autocommit": True, "row_factory": dict_row},
            open=False,
        )
        try:
            await self._pool.open()

            # Apply schema (idempotent CREATE IF NOT EXISTS)
            async with self._pool.connection() as conn:
                schema_sql = _SCHEMA_PATH.read_text()
                await conn.execute(schema_sql)

            # Schema version tracking
            await self._ensure_schema_version()

            self._initialized = True
        except Exception:
            # Don't leak the pool if schema setup fails
            await self._pool.close()
            self._pool = None
            raise

    async def _ensure_schema_version(self) -> None:
        """Track schema version (insert or update)."""
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT version FROM schema_version WHERE id = 1",
                )
            ).fetchone()

            if row is None:
                await conn.execute(
                    "INSERT INTO schema_version (id, version, updated_at) VALUES (1, %s, %s)",
                    (_CURRENT_SCHEMA_VERSION, now),
                )
            else:
                await conn.execute(
                    "UPDATE schema_version SET version = %s, updated_at = %s WHERE id = 1",
                    (_CURRENT_SCHEMA_VERSION, now),
                )

    async def close(self) -> None:
        """Release database resources."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        self._initialized = False

    # ── Pattern queries ──────────────────────────────────────────────────

    async def count_patterns(self) -> int:
        """Return the number of stored vulnerability patterns."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute("SELECT COUNT(*) AS cnt FROM vulnerability_patterns")
            ).fetchone()
            return row["cnt"] if row else 0

    async def get_false_positive_signatures(self) -> frozenset[str]:
        """Return rule IDs with high false-positive rates (>0.8).

        Uses DefectDojo-style integer counters: FP rate is computed
        dynamically from ``confirmed_true_positive`` / ``confirmed_false_positive``.

        A minimum of ``_MIN_FEEDBACK_FOR_SUPPRESSION`` total signals is
        required before a rule can be suppressed.  This prevents premature
        suppression from a handful of noisy reactions.
        """
        pool = self._require_pool()
        sql = """\
            SELECT DISTINCT rule_id FROM vulnerability_patterns
            WHERE confirmed_false_positive > 0
              AND (confirmed_true_positive + confirmed_false_positive) >= %s
              AND CAST(confirmed_false_positive AS REAL) /
                  (confirmed_true_positive + confirmed_false_positive) > %s
        """
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(sql, (_MIN_FEEDBACK_FOR_SUPPRESSION, _FP_THRESHOLD))
            ).fetchall()
            return frozenset(row["rule_id"] for row in rows)

    async def query_similar_patterns(
        self, code_diff: str, limit: int = 10,
    ) -> list[dict[str, object]]:
        """Return patterns similar to the given code diff.

        Tokenizes the diff, builds ``LIKE`` clauses for the top tokens,
        and orders by ``times_seen DESC`` with dynamic FP rate as tiebreaker.
        """
        pool = self._require_pool()
        tokens = _extract_code_tokens(code_diff)
        if not tokens:
            return []

        tokens = tokens[:_MAX_LIKE_TOKENS]
        like_clauses = " OR ".join(
            "normalized_pattern LIKE %s" for _ in tokens
        )
        # Build typed params list — LIKE tokens are str, LIMIT is int
        params: list[object] = [f"%{tok}%" for tok in tokens]
        params.append(limit)

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
            LIMIT %s
        """

        async with pool.connection() as conn:
            rows = await (await conn.execute(sql, params)).fetchall()
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
        pool = self._require_pool()
        async with pool.connection() as conn:
            if is_true_positive:
                await conn.execute(
                    "UPDATE vulnerability_patterns "
                    "SET confirmed_true_positive = confirmed_true_positive + 1 "
                    "WHERE id = %s",
                    (pattern_id,),
                )
            else:
                await conn.execute(
                    "UPDATE vulnerability_patterns "
                    "SET confirmed_false_positive = confirmed_false_positive + 1 "
                    "WHERE id = %s",
                    (pattern_id,),
                )

    async def record_feedback_signal(
        self,
        rule_id: str,
        repo: str,
        pr_number: int,
        comment_id: int,
        reactor_login: str,
        reaction: str,
    ) -> bool:
        """Record a feedback signal from a GitHub reaction.

        Inserts a row into ``feedback_log`` and increments the appropriate
        counter (TP or FP) on all ``vulnerability_patterns`` matching
        *rule_id*.  Uses ``ON CONFLICT DO NOTHING`` for idempotency.

        Returns ``True`` if a new signal was recorded, ``False`` if the
        signal was a duplicate (already recorded for this rule/repo/PR/
        reactor/reaction combination).
        """
        pool = self._require_pool()
        signal_id = uuid.uuid4().hex

        async with pool.connection() as conn, conn.transaction():
            cur = await conn.execute(
                "INSERT INTO feedback_log "
                "(id, rule_id, repo, pr_number, comment_id, reactor_login, reaction) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT DO NOTHING",
                (signal_id, rule_id, repo, pr_number, comment_id, reactor_login, reaction),
            )
            if cur.rowcount == 0:
                return False

            counter_col = (
                "confirmed_true_positive"
                if reaction == "+1"
                else "confirmed_false_positive"
            )
            await conn.execute(
                f"UPDATE vulnerability_patterns "  # noqa: S608
                f"SET {counter_col} = {counter_col} + 1 "
                "WHERE rule_id = %s",
                (rule_id,),
            )
        return True

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
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()

        patterns = extract_patterns(static_findings, ai_findings)

        async with pool.connection() as conn:
            # Upsert patterns
            for pat in patterns:
                sig = hashlib.sha256(
                    str(pat["normalized_pattern"]).encode(),
                ).hexdigest()

                existing = await (
                    await conn.execute(
                        "SELECT id, times_seen FROM vulnerability_patterns "
                        "WHERE pattern_signature = %s",
                        (sig,),
                    )
                ).fetchone()

                if existing:
                    await conn.execute(
                        """\
                        UPDATE vulnerability_patterns
                        SET times_seen = times_seen + 1,
                            last_seen = %s
                        WHERE pattern_signature = %s
                        """,
                        (now, sig),
                    )
                else:
                    pat_id = hashlib.sha256(
                        f"{sig}-{now}".encode(),
                    ).hexdigest()[:16]
                    await conn.execute(
                        """\
                        INSERT INTO vulnerability_patterns
                            (id, rule_id, severity, category, normalized_pattern,
                             pattern_signature, confidence, times_seen,
                             first_seen, last_seen, source_stage)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s, %s, %s)
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

            await conn.execute(
                """\
                INSERT INTO pipeline_history
                    (id, pr_id, repo, pr_author, verdict, composite_score,
                     findings_count, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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

                existing_cp = await (
                    await conn.execute(
                        """\
                        SELECT id, total_submissions, approved_submissions,
                               rejected_submissions
                        FROM contributor_profiles
                        WHERE github_login = %s
                        """,
                        (author,),
                    )
                ).fetchone()

                if existing_cp:
                    if is_approved:
                        await conn.execute(
                            """\
                            UPDATE contributor_profiles
                            SET total_submissions = total_submissions + 1,
                                approved_submissions = approved_submissions + 1,
                                last_active = %s
                            WHERE id = %s
                            """,
                            (now, existing_cp["id"]),
                        )
                    else:
                        await conn.execute(
                            """\
                            UPDATE contributor_profiles
                            SET total_submissions = total_submissions + 1,
                                rejected_submissions = rejected_submissions + 1,
                                last_active = %s
                            WHERE id = %s
                            """,
                            (now, existing_cp["id"]),
                        )
                else:
                    cp_id = hashlib.sha256(author.encode()).hexdigest()[:16]
                    await conn.execute(
                        """\
                        INSERT INTO contributor_profiles
                            (id, github_login, total_submissions,
                             approved_submissions, rejected_submissions,
                             first_seen, last_active)
                        VALUES (%s, %s, 1, %s, %s, %s, %s)
                        """,
                        (
                            cp_id, author,
                            1 if is_approved else 0,
                            0 if is_approved else 1,
                            now, now,
                        ),
                    )

    # ── Contributor history ──────────────────────────────────────────────

    async def get_contributor_acceptance_rate(
        self, repo: str, author: str,
    ) -> float | None:
        """Return the historical acceptance rate for a contributor.

        Returns ``None`` when the DB has insufficient data (<5 verdicts).
        """
        pool = self._require_pool()

        async with pool.connection() as conn:
            # Try contributor_profiles first (global, keyed by github_login)
            row = await (
                await conn.execute(
                    """\
                    SELECT total_submissions, approved_submissions
                    FROM contributor_profiles
                    WHERE github_login = %s
                    """,
                    (author,),
                )
            ).fetchone()

            if row and row["total_submissions"] >= _MIN_VERDICTS_FOR_HISTORY:
                return row["approved_submissions"] / row["total_submissions"]

            # Fallback: query pipeline_history (repo-scoped)
            total_row = await (
                await conn.execute(
                    """\
                    SELECT COUNT(*) AS cnt FROM pipeline_history
                    WHERE pr_author = %s AND repo = %s
                    """,
                    (author, repo),
                )
            ).fetchone()
            total = total_row["cnt"] if total_row else 0

            if total < _MIN_VERDICTS_FOR_HISTORY:
                return None

            # Match the decision field precisely in stored JSON
            approved_row = await (
                await conn.execute(
                    """\
                    SELECT COUNT(*) AS cnt FROM pipeline_history
                    WHERE pr_author = %s AND repo = %s
                      AND (verdict LIKE '%%"decision": "approve"%%'
                           OR verdict LIKE '%%"decision": "APPROVE"%%'
                           OR verdict LIKE '%%"decision":"approve"%%'
                           OR verdict LIKE '%%"decision":"APPROVE"%%')
                    """,
                    (author, repo),
                )
            ).fetchone()
            approved = approved_row["cnt"] if approved_row else 0

            return approved / total

    async def get_contributor_wallet(self, github_login: str) -> str | None:
        """Look up wallet address by GitHub login.  Uses ``idx_cp_github`` index."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT wallet_address FROM contributor_profiles WHERE github_login = %s",
                    (github_login,),
                )
            ).fetchone()
            if row is None or not row["wallet_address"]:
                return None
            return str(row["wallet_address"])

    async def set_contributor_wallet(
        self, github_login: str, wallet_address: str,
    ) -> bool:
        """Register or update a contributor's wallet address.

        If the contributor already has a profile, updates the wallet.
        If not, creates a new profile with the wallet.

        Returns True if a row was created or updated.
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            existing = await (
                await conn.execute(
                    "SELECT id FROM contributor_profiles WHERE github_login = %s",
                    (github_login,),
                )
            ).fetchone()

            if existing:
                await conn.execute(
                    "UPDATE contributor_profiles SET wallet_address = %s WHERE id = %s",
                    (wallet_address, existing["id"]),
                )
            else:
                cp_id = hashlib.sha256(github_login.encode()).hexdigest()[:16]
                await conn.execute(
                    """\
                    INSERT INTO contributor_profiles
                        (id, github_login, wallet_address, first_seen, last_active)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (cp_id, github_login, wallet_address, now, now),
                )
        return True

    # ── Stats (anonymized) ───────────────────────────────────────────────

    async def get_stats(self) -> dict[str, Any]:
        """Return anonymized aggregate intelligence statistics.

        Never exposes raw patterns — only counts and distributions.
        """
        pool = self._require_pool()
        async with pool.connection() as conn:
            # Total patterns
            row = await (
                await conn.execute("SELECT COUNT(*) AS cnt FROM vulnerability_patterns")
            ).fetchone()
            total_patterns = row["cnt"] if row else 0

            # Category distribution
            cat_rows = await (
                await conn.execute(
                    "SELECT category, COUNT(*) AS cnt FROM vulnerability_patterns "
                    "GROUP BY category",
                )
            ).fetchall()
            category_distribution = {r["category"]: r["cnt"] for r in cat_rows}

            # Severity distribution
            sev_rows = await (
                await conn.execute(
                    "SELECT severity, COUNT(*) AS cnt FROM vulnerability_patterns "
                    "GROUP BY severity",
                )
            ).fetchall()
            severity_distribution = {r["severity"]: r["cnt"] for r in sev_rows}

            # Average false positive rate (from integer counters)
            fp_row = await (
                await conn.execute(
                    """\
                    SELECT AVG(
                        CASE WHEN (confirmed_true_positive + confirmed_false_positive) > 0
                        THEN CAST(confirmed_false_positive AS REAL) /
                             (confirmed_true_positive + confirmed_false_positive)
                        ELSE 0.0 END
                    ) AS avg_fp FROM vulnerability_patterns
                    """,
                )
            ).fetchone()
            avg_fp_rate = (
                round(fp_row["avg_fp"], 4)
                if fp_row and fp_row["avg_fp"] is not None
                else 0.0
            )

            # Patterns last 7 days
            recent_row = await (
                await conn.execute(
                    """\
                    SELECT COUNT(*) AS cnt FROM vulnerability_patterns
                    WHERE first_seen > %s
                    """,
                    ((datetime.now(UTC) - timedelta(days=7)).isoformat(),),
                )
            ).fetchone()
            patterns_last_7 = recent_row["cnt"] if recent_row else 0

            # Top contributing repos (names only, top 10)
            repo_rows = await (
                await conn.execute(
                    """\
                    SELECT repo, COUNT(*) AS cnt FROM pipeline_history
                    GROUP BY repo ORDER BY cnt DESC LIMIT 10
                    """,
                )
            ).fetchall()
            top_repos = [r["repo"] for r in repo_rows]

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

        Uses ``INSERT ... ON CONFLICT DO NOTHING`` — a duplicate
        ``attestation_id`` is silently skipped, preserving the original
        proof and chain integrity.
        Returns ``True`` if the proof was inserted, ``False`` if it already
        existed.
        """
        pool = self._require_pool()
        ts = created_at or datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            cursor = await conn.execute(
                """\
                INSERT INTO attestation_store
                    (attestation_id, pr_id, repo, pipeline_input_hash,
                     pipeline_output_hash, signature, docker_image_digest,
                     tee_platform_id, previous_attestation_id,
                     ai_seed, ai_output_hash, ai_system_fingerprint,
                     signer_address, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (attestation_id) DO NOTHING
                """,
                (attestation_id, pr_id, repo, pipeline_input_hash,
                 pipeline_output_hash, signature, docker_image_digest,
                 tee_platform_id, previous_attestation_id,
                 ai_seed, ai_output_hash, ai_system_fingerprint,
                 signer_address, ts),
            )
            return cursor.rowcount > 0

    async def get_attestation(self, attestation_id: str) -> dict[str, object] | None:
        """Retrieve an attestation by ID."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM attestation_store WHERE attestation_id = %s",
                    (attestation_id,),
                )
            ).fetchone()
            return dict(row) if row else None

    async def get_latest_attestation_id(self) -> str | None:
        """Return the attestation_id of the most recent attestation, or None."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT attestation_id FROM attestation_store "
                    "ORDER BY created_at DESC LIMIT 1",
                )
            ).fetchone()
            return str(row["attestation_id"]) if row else None

    async def get_attestation_chain(
        self, start_id: str, count: int = 10,
    ) -> list[dict[str, object]]:
        """Walk the attestation chain backwards from *start_id*.

        Follows ``previous_attestation_id`` links up to *count* entries.
        """
        pool = self._require_pool()
        chain: list[dict[str, object]] = []
        current_id: str | None = start_id
        async with pool.connection() as conn:
            for _ in range(count):
                if current_id is None:
                    break
                row = await (
                    await conn.execute(
                        "SELECT * FROM attestation_store WHERE attestation_id = %s",
                        (current_id,),
                    )
                ).fetchone()
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO active_bounties
                    (id, repo, issue_number, label, amount_eth, status, created_at, source)
                VALUES (%s, %s, %s, %s, %s, 'open', %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    repo = EXCLUDED.repo,
                    issue_number = EXCLUDED.issue_number,
                    label = EXCLUDED.label,
                    amount_eth = EXCLUDED.amount_eth,
                    status = 'open',
                    created_at = EXCLUDED.created_at,
                    source = EXCLUDED.source
                """,
                (bounty_id, repo, issue_number, label, amount_eth, now, source),
            )

    async def close_bounty(self, bounty_id: str, claimed_by: str) -> None:
        """Mark a bounty as claimed."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            await conn.execute(
                "UPDATE active_bounties SET status = 'claimed', claimed_by = %s "
                "WHERE id = %s",
                (claimed_by, bounty_id),
            )

    async def get_active_bounties(self) -> list[dict[str, object]]:
        """Return all open bounties."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM active_bounties WHERE status = 'open'",
                )
            ).fetchall()
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO verification_windows
                    (id, pr_id, repo, pr_number, installation_id,
                     attestation_id, verdict_json, attestation_json,
                     contributor_address, bounty_amount_wei, stake_amount_wei,
                     window_hours, opens_at, closes_at, status,
                     is_self_modification, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open', %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    pr_id = EXCLUDED.pr_id,
                    repo = EXCLUDED.repo,
                    pr_number = EXCLUDED.pr_number,
                    installation_id = EXCLUDED.installation_id,
                    attestation_id = EXCLUDED.attestation_id,
                    verdict_json = EXCLUDED.verdict_json,
                    attestation_json = EXCLUDED.attestation_json,
                    contributor_address = EXCLUDED.contributor_address,
                    bounty_amount_wei = EXCLUDED.bounty_amount_wei,
                    stake_amount_wei = EXCLUDED.stake_amount_wei,
                    window_hours = EXCLUDED.window_hours,
                    opens_at = EXCLUDED.opens_at,
                    closes_at = EXCLUDED.closes_at,
                    status = 'open',
                    is_self_modification = EXCLUDED.is_self_modification,
                    created_at = EXCLUDED.created_at,
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    window_id, pr_id, repo, pr_number, installation_id,
                    attestation_id, verdict_json, attestation_json,
                    contributor_address, bounty_amount_wei, stake_amount_wei,
                    window_hours, opens_at, closes_at,
                    is_self_modification, now, now,
                ),
            )

    async def get_verification_window(
        self, window_id: str,
    ) -> dict[str, object] | None:
        """Retrieve a verification window by ID."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM verification_windows WHERE id = %s",
                    (window_id,),
                )
            ).fetchone()
            return dict(row) if row else None

    async def get_expired_open_windows(
        self, now_iso: str,
    ) -> list[dict[str, object]]:
        """Return open windows whose challenge period has elapsed."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM verification_windows "
                    "WHERE status = 'open' AND closes_at <= %s",
                    (now_iso,),
                )
            ).fetchall()
            return [dict(row) for row in rows]

    async def get_open_windows(self) -> list[dict[str, object]]:
        """Return all open verification windows."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM verification_windows WHERE status = 'open'",
                )
            ).fetchall()
            return [dict(row) for row in rows]

    async def get_windows_by_status(
        self, status: str,
    ) -> list[dict[str, object]]:
        """Return all verification windows with the given status."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM verification_windows WHERE status = %s",
                    (status,),
                )
            ).fetchall()
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
        ``expected_status``.
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        set_parts = ["status = %s", "updated_at = %s"]
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
                set_parts.append(f"{col} = %s")
                params.append(val)
        params.extend([window_id, expected_status])
        async with pool.connection() as conn:
            cursor = await conn.execute(
                f"UPDATE verification_windows SET {', '.join(set_parts)} "
                f"WHERE id = %s AND status = %s",
                params,
            )
            return cursor.rowcount > 0

    async def get_stale_challenged_windows(
        self, deadline_iso: str,
    ) -> list[dict[str, object]]:
        """Return challenged/resolving windows with ``updated_at`` older than deadline."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM verification_windows "
                    "WHERE status IN ('challenged', 'resolving') AND updated_at <= %s",
                    (deadline_iso,),
                )
            ).fetchall()
            return [dict(row) for row in rows]

    async def get_all_verification_windows(self) -> list[dict[str, object]]:
        """Return all verification windows ordered by creation time."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM verification_windows ORDER BY created_at DESC",
                )
            ).fetchall()
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO dispute_records
                    (dispute_id, challenge_id, window_id, dispute_type,
                     claim_type, status, challenger_address,
                     challenger_stake_wei, contributor_stake_id,
                     challenger_stake_id, attestation_json,
                     submission_attempts, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s, 0, %s, %s)
                """,
                (
                    dispute_id, challenge_id, window_id, dispute_type,
                    claim_type, challenger_address, challenger_stake_wei,
                    contributor_stake_id, challenger_stake_id,
                    attestation_json, now, now,
                ),
            )

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

        Uses a single connection to check + insert. PostgreSQL MVCC
        prevents race conditions from concurrent calls.

        Returns ``True`` if a new record was inserted, ``False`` if an
        active dispute already exists for the window.
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            # Use a transaction for atomicity of the check-then-insert
            async with conn.transaction():
                existing = await (
                    await conn.execute(
                        "SELECT dispute_id FROM dispute_records "
                        "WHERE window_id = %s AND status IN ('pending', 'submitted')",
                        (window_id,),
                    )
                ).fetchone()
                if existing is not None:
                    return False

                await conn.execute(
                    """\
                    INSERT INTO dispute_records
                        (dispute_id, challenge_id, window_id, dispute_type,
                         claim_type, status, challenger_address,
                         challenger_stake_wei, contributor_stake_id,
                         challenger_stake_id, attestation_json,
                         submission_attempts, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s, 0, %s, %s)
                    """,
                    (
                        dispute_id, challenge_id, window_id, dispute_type,
                        claim_type, challenger_address, challenger_stake_wei,
                        contributor_stake_id, challenger_stake_id,
                        attestation_json, now, now,
                    ),
                )
                return True

    # Pre-defined UPDATE statements per column — no f-string interpolation.
    _DISPUTE_UPDATE_SQL: dict[str, str] = {
        "status": (
            "UPDATE dispute_records SET status = %s, updated_at = %s "
            "WHERE dispute_id = %s"
        ),
        "provider_case_id": (
            "UPDATE dispute_records SET provider_case_id = %s, updated_at = %s "
            "WHERE dispute_id = %s"
        ),
        "provider_verdict": (
            "UPDATE dispute_records SET provider_verdict = %s, updated_at = %s "
            "WHERE dispute_id = %s"
        ),
        "submission_attempts": (
            "UPDATE dispute_records SET submission_attempts = %s, updated_at = %s "
            "WHERE dispute_id = %s"
        ),
        "resolved_at": (
            "UPDATE dispute_records SET resolved_at = %s, updated_at = %s "
            "WHERE dispute_id = %s"
        ),
        "staking_applied": (
            "UPDATE dispute_records SET staking_applied = %s, updated_at = %s "
            "WHERE dispute_id = %s"
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            for col, val in kwargs.items():
                sql = self._DISPUTE_UPDATE_SQL.get(col)
                if sql is None:
                    raise ValueError(f"Cannot update column: {col}")
                await conn.execute(sql, (val, now, dispute_id))

    async def get_dispute_record(
        self, dispute_id: str,
    ) -> dict[str, object] | None:
        """Retrieve a dispute record by ID."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM dispute_records WHERE dispute_id = %s",
                    (dispute_id,),
                )
            ).fetchone()
            return dict(row) if row else None

    async def get_disputes_by_status(
        self, status: str,
    ) -> list[dict[str, object]]:
        """Return all dispute records with the given status."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM dispute_records WHERE status = %s",
                    (status,),
                )
            ).fetchall()
            return [dict(row) for row in rows]

    async def get_disputes_for_window(
        self, window_id: str,
    ) -> list[dict[str, object]]:
        """Return all dispute records for a verification window."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM dispute_records WHERE window_id = %s",
                    (window_id,),
                )
            ).fetchall()
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO codebase_knowledge
                    (id, repo, file_path, knowledge, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    repo = EXCLUDED.repo,
                    file_path = EXCLUDED.file_path,
                    knowledge = EXCLUDED.knowledge,
                    updated_at = EXCLUDED.updated_at
                """,
                (knowledge_id, repo, file_path, knowledge, now),
            )

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
        """Store or update a vision document."""
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO vision_documents
                    (id, repo, doc_type, content, embedding, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    repo = EXCLUDED.repo,
                    doc_type = EXCLUDED.doc_type,
                    content = EXCLUDED.content,
                    embedding = EXCLUDED.embedding,
                    updated_at = EXCLUDED.updated_at
                """,
                (doc_id, repo, doc_type, content, embedding, now),
            )

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
        pool = self._require_pool()
        async with pool.connection() as conn:
            if doc_type is not None:
                rows = await (
                    await conn.execute(
                        "SELECT id, repo, doc_type, content, embedding, updated_at "
                        "FROM vision_documents WHERE repo = %s AND doc_type = %s",
                        (repo, doc_type),
                    )
                ).fetchall()
            else:
                rows = await (
                    await conn.execute(
                        "SELECT id, repo, doc_type, content, embedding, updated_at "
                        "FROM vision_documents WHERE repo = %s",
                        (repo,),
                    )
                ).fetchall()
        return [dict(row) for row in rows]

    async def purge_stale_vision_documents(
        self, max_age_days: int = 90,
    ) -> int:
        """Delete vision documents older than *max_age_days*.

        Returns the number of deleted rows.
        """
        pool = self._require_pool()
        cutoff = (datetime.now(UTC) - timedelta(days=max_age_days)).isoformat()
        async with pool.connection() as conn:
            cursor = await conn.execute(
                "DELETE FROM vision_documents WHERE updated_at < %s",
                (cutoff,),
            )
            return cursor.rowcount

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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        score_id = uuid.uuid4().hex[:16]
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO vision_score_history
                    (id, repo, pr_id, pr_number, vision_score,
                     ai_confidence, goal_scores_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    score_id, repo, pr_id, pr_number,
                    vision_score, ai_confidence,
                    goal_scores_json, now,
                ),
            )

    async def get_vision_score_trend(
        self, repo: str, limit: int = 20,
    ) -> list[dict[str, object]]:
        """Return recent vision scores for *repo*, newest first."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT id, repo, pr_id, pr_number, vision_score, "
                    "ai_confidence, goal_scores_json, created_at "
                    "FROM vision_score_history "
                    "WHERE repo = %s ORDER BY created_at DESC LIMIT %s",
                    (repo, limit),
                )
            ).fetchall()
        return [dict(row) for row in rows]

    # ── Identity cache ────────────────────────────────────────────────────

    async def cache_identity(self, identity: AgentIdentity) -> None:
        """Cache an agent identity for cross-boot recovery.

        Uses ``INSERT ... ON CONFLICT ... DO UPDATE`` so repeated calls
        for the same wallet address update rather than conflict.
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO agent_identity_cache
                    (wallet_address, agent_id, chain_id, name,
                     description, registered_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (wallet_address) DO UPDATE SET
                    agent_id = EXCLUDED.agent_id,
                    chain_id = EXCLUDED.chain_id,
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    registered_at = EXCLUDED.registered_at,
                    updated_at = EXCLUDED.updated_at
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

    async def get_cached_identity(
        self, wallet_address: str,
    ) -> AgentIdentity | None:
        """Retrieve a cached identity by wallet address.  Read-only."""
        from src.models.identity import AgentIdentity  # noqa: PLC0415

        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT wallet_address, agent_id, chain_id, name, "
                    "description, registered_at FROM agent_identity_cache "
                    "WHERE wallet_address = %s",
                    (wallet_address,),
                )
            ).fetchone()
            if row is None:
                return None
            return AgentIdentity(
                agent_id=row["agent_id"],
                chain_id=row["chain_id"],
                wallet_address=row["wallet_address"],
                name=row["name"],
                description=row["description"],
                registered_at=datetime.fromisoformat(row["registered_at"]),
            )

    # ── Ranking ──────────────────────────────────────────────────────────

    async def get_ranked_prs(
        self, repo: str, issue_number: int,
    ) -> list[dict[str, object]]:
        """Return PRs targeting an issue, ranked by latest composite score.

        Uses a window function to select the most recent pipeline run per PR,
        then joins with ``pr_embeddings`` for issue linkage.
        """
        pool = self._require_pool()
        sql = """\
            SELECT pe.pr_number, ph.pr_id, ph.composite_score,
                   ph.verdict, ph.pr_author
            FROM pr_embeddings pe
            INNER JOIN (
                SELECT pr_id, composite_score, verdict, pr_author,
                       ROW_NUMBER() OVER (
                           PARTITION BY pr_id ORDER BY created_at DESC
                       ) AS rn
                FROM pipeline_history WHERE repo = %s
            ) ph ON pe.pr_id = ph.pr_id AND ph.rn = 1
            WHERE pe.repo = %s AND pe.issue_number = %s
              AND ph.composite_score IS NOT NULL
            ORDER BY ph.composite_score DESC, pe.pr_number ASC
        """
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(sql, (repo, repo, issue_number))
            ).fetchall()
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        record_id = uuid.uuid4().hex[:16]
        async with pool.connection() as conn:
            await conn.execute(
                "INSERT INTO ranking_updates "
                "(id, repo, issue_number, updated_at, ranking_json) "
                "VALUES (%s, %s, %s, %s, %s)",
                (record_id, repo, issue_number, now, ranking_json),
            )
            # Prune: keep only 5 most recent per (repo, issue_number)
            await conn.execute(
                "DELETE FROM ranking_updates "
                "WHERE repo = %s AND issue_number = %s "
                "AND id NOT IN ("
                "    SELECT id FROM ranking_updates "
                "    WHERE repo = %s AND issue_number = %s "
                "    ORDER BY updated_at DESC LIMIT 5"
                ")",
                (repo, issue_number, repo, issue_number),
            )

    async def was_ranking_recently_posted(
        self,
        repo: str,
        issue_number: int,
        interval_seconds: int,
    ) -> bool:
        """Check if a ranking update was posted within the given interval.

        Returns ``False`` if no record exists (first post is always allowed).
        """
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT updated_at FROM ranking_updates "
                    "WHERE repo = %s AND issue_number = %s "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (repo, issue_number),
                )
            ).fetchone()

        if row is None:
            return False

        last_update = datetime.fromisoformat(row["updated_at"])
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        emb_id = hashlib.sha256(f"{pr_id}-{commit_sha}".encode()).hexdigest()[:16]
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO pr_embeddings
                    (id, pr_id, repo, pr_number, commit_sha, embedding,
                     embedding_model, issue_number, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(id) DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    embedding_model = EXCLUDED.embedding_model,
                    issue_number = EXCLUDED.issue_number
                """,
                (emb_id, pr_id, repo, pr_number, commit_sha,
                 embedding_blob, embedding_model, issue_number, now),
            )

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
        pool = self._require_pool()
        async with pool.connection() as conn:
            cursor = await conn.execute(
                "UPDATE pr_embeddings SET issue_number = %s "
                "WHERE pr_id = %s AND repo = %s AND issue_number IS NULL",
                (issue_number, pr_id, repo),
            )
            return cursor.rowcount

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
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT id, pr_id, pr_number, commit_sha, embedding, issue_number "
                    "FROM pr_embeddings WHERE repo = %s "
                    "ORDER BY created_at DESC LIMIT %s",
                    (repo, max_scan),
                )
            ).fetchall()

        results: list[dict[str, object]] = []
        for row in rows:
            sim = cosine_similarity(embedding_blob, row["embedding"])
            if sim >= threshold:
                results.append({
                    "id": row["id"],
                    "pr_id": row["pr_id"],
                    "pr_number": row["pr_number"],
                    "commit_sha": row["commit_sha"],
                    "issue_number": row["issue_number"],
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
        ``commit_sha``, and ``embedding`` (bytes blob).
        """
        pool = self._require_pool()

        # Four SQL branches: with/without exclude, with/without model filter.
        # All use parameterized queries — no f-strings.
        async with pool.connection() as conn:
            if exclude_pr_number is not None and embedding_model:
                rows = await (
                    await conn.execute(
                        "SELECT pr_id, pr_number, commit_sha, embedding "
                        "FROM pr_embeddings "
                        "WHERE repo = %s AND pr_number != %s AND embedding_model = %s "
                        "ORDER BY created_at DESC LIMIT %s",
                        (repo, exclude_pr_number, embedding_model, limit),
                    )
                ).fetchall()
            elif exclude_pr_number is not None:
                rows = await (
                    await conn.execute(
                        "SELECT pr_id, pr_number, commit_sha, embedding "
                        "FROM pr_embeddings WHERE repo = %s AND pr_number != %s "
                        "ORDER BY created_at DESC LIMIT %s",
                        (repo, exclude_pr_number, limit),
                    )
                ).fetchall()
            elif embedding_model:
                rows = await (
                    await conn.execute(
                        "SELECT pr_id, pr_number, commit_sha, embedding "
                        "FROM pr_embeddings "
                        "WHERE repo = %s AND embedding_model = %s "
                        "ORDER BY created_at DESC LIMIT %s",
                        (repo, embedding_model, limit),
                    )
                ).fetchall()
            else:
                rows = await (
                    await conn.execute(
                        "SELECT pr_id, pr_number, commit_sha, embedding "
                        "FROM pr_embeddings WHERE repo = %s "
                        "ORDER BY created_at DESC LIMIT %s",
                        (repo, limit),
                    )
                ).fetchall()

        return [dict(row) for row in rows]

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
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        labels_json = json.dumps(labels) if labels is not None else None

        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO issue_embeddings
                    (id, repo, issue_number, title, embedding,
                     labels, status, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'open', %s, %s)
                ON CONFLICT(repo, issue_number) DO UPDATE SET
                    id = EXCLUDED.id,
                    title = EXCLUDED.title,
                    embedding = EXCLUDED.embedding,
                    labels = EXCLUDED.labels,
                    status = 'open',
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    issue_id, repo, issue_number, title,
                    embedding, labels_json, now, now,
                ),
            )

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
        ``embedding`` (bytes blob), and ``status``.
        """
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT issue_number, title, embedding, status "
                    "FROM issue_embeddings "
                    "WHERE repo = %s AND issue_number != %s AND status = %s "
                    "ORDER BY created_at DESC LIMIT %s",
                    (repo, exclude_issue, status, limit),
                )
            ).fetchall()
        return [dict(row) for row in rows]

    async def get_issue_embedding(
        self,
        repo: str,
        issue_number: int,
    ) -> dict[str, object] | None:
        """Retrieve a single issue embedding by repo+issue_number.

        Returns the full row as a dict, or ``None`` if not found.
        """
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM issue_embeddings "
                    "WHERE repo = %s AND issue_number = %s",
                    (repo, issue_number),
                )
            ).fetchone()
            return dict(row) if row else None

    async def update_issue_status(
        self,
        repo: str,
        issue_number: int,
        status: str,
    ) -> int:
        """Update the status of an issue embedding.

        Returns the number of rows updated (0 or 1).
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            cursor = await conn.execute(
                "UPDATE issue_embeddings SET status = %s, updated_at = %s "
                "WHERE repo = %s AND issue_number = %s",
                (status, now, repo, issue_number),
            )
            return cursor.rowcount

    # ── PR embedding lookup ──────────────────────────────────────────────

    async def get_pr_embedding(
        self,
        repo: str,
        pr_number: int,
    ) -> dict[str, object] | None:
        """Retrieve a single PR embedding by repo+pr_number.

        Used by the backfill engine for idempotency checks — if an
        embedding already exists, the PR can be skipped.
        """
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT id, pr_id, repo, pr_number, commit_sha, embedding_model, "
                    "issue_number, created_at "
                    "FROM pr_embeddings WHERE repo = %s AND pr_number = %s",
                    (repo, pr_number),
                )
            ).fetchone()
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
        pool = self._require_pool()
        async with pool.connection() as conn:
            if table == "pr_embeddings":
                query = "SELECT pr_id AS id, embedding FROM pr_embeddings ORDER BY created_at ASC"
            else:
                query = "SELECT id, embedding FROM issue_embeddings"
            rows = await (await conn.execute(query)).fetchall()
        return [dict(row) for row in rows]

    async def count_embeddings(self, table: str) -> int:
        """Count embeddings in a table for auto-enable heuristic.

        Raises ``ValueError`` for unrecognised table names.
        """
        if table not in self._EMBEDDING_TABLES:
            raise ValueError(f"Invalid embedding table: {table}")
        pool = self._require_pool()
        async with pool.connection() as conn:
            if table == "pr_embeddings":
                query = "SELECT COUNT(*) AS cnt FROM pr_embeddings"
            else:
                query = "SELECT COUNT(*) AS cnt FROM issue_embeddings"
            row = await (await conn.execute(query)).fetchone()
        return row["cnt"] if row else 0

    async def get_pr_embedding_by_pr_id(self, pr_id: str) -> dict[str, object] | None:
        """Fetch most recent PR embedding metadata by ``pr_id``.

        Returns ``pr_id``, ``pr_number``, and ``commit_sha`` for the most
        recent embedding row matching the given ``pr_id``.  Used by
        ``find_similar`` to enrich HNSW results with PR metadata.
        """
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT pr_id, pr_number, commit_sha FROM pr_embeddings "
                    "WHERE pr_id = %s ORDER BY created_at DESC LIMIT 1",
                    (pr_id,),
                )
            ).fetchone()
        if not row:
            return None
        return dict(row)

    # ── Backfill progress ────────────────────────────────────────────────

    async def get_backfill_progress(
        self,
        repo: str,
        mode: str,
    ) -> dict[str, object] | None:
        """Retrieve the backfill progress record for a repo+mode.

        Returns the row as a dict, or ``None`` if no prior run exists.
        """
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM backfill_progress WHERE repo = %s AND mode = %s",
                    (repo, mode),
                )
            ).fetchone()
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
        are idempotent.
        """
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        progress_id = hashlib.sha256(f"backfill:{repo}:{mode}".encode()).hexdigest()[:16]

        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO backfill_progress
                    (id, repo, mode, status, last_page, processed,
                     failed, skipped, error_msg, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(repo, mode) DO UPDATE SET
                    status = EXCLUDED.status,
                    last_page = EXCLUDED.last_page,
                    processed = EXCLUDED.processed,
                    failed = EXCLUDED.failed,
                    skipped = EXCLUDED.skipped,
                    error_msg = EXCLUDED.error_msg,
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    progress_id, repo, mode, status, last_page,
                    processed, failed, skipped, error_msg, now, now,
                ),
            )

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
        pool = self._require_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO patrol_history
                    (id, repo, timestamp, dependency_findings_count,
                     code_findings_count, patches_generated, issues_created,
                     bounties_assigned_wei, attestation_id, duration_ms)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    run_id, repo, timestamp, dependency_findings_count,
                    code_findings_count, patches_generated, issues_created,
                    bounties_assigned_wei, attestation_id, duration_ms,
                ),
            )

    async def get_latest_patrol_run(self, repo: str) -> dict[str, object] | None:
        """Return the most recent patrol run for *repo*, or ``None``."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM patrol_history WHERE repo = %s "
                    "ORDER BY timestamp DESC LIMIT 1",
                    (repo,),
                )
            ).fetchone()
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
        pool = self._require_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO patrol_patches
                    (id, repo, pr_number, cve_id, package_name,
                     old_version, new_version, status, attestation_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    patch_id, repo, pr_number, cve_id, package_name,
                    old_version, new_version, status, attestation_id,
                ),
            )

    async def count_open_patrol_bounties(self, repo: str) -> int:
        """Count open bounties created by patrol for *repo*."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT COUNT(*) AS cnt FROM active_bounties "
                    "WHERE repo = %s AND status = 'open' AND source = 'patrol'",
                    (repo,),
                )
            ).fetchone()
        return row["cnt"] if row else 0

    async def get_known_vulnerability(
        self, repo: str, dedup_key: str,
    ) -> dict[str, object] | None:
        """Look up a known vulnerability by repo + dedup_key."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM known_vulnerabilities WHERE repo = %s AND dedup_key = %s",
                    (repo, dedup_key),
                )
            ).fetchone()
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
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO known_vulnerabilities
                    (id, cve_id, dedup_key, package_name, language, severity,
                     affected_range, fixed_version, advisory_url, repo,
                     first_detected, last_checked, status, bounty_issue_number)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(repo, dedup_key) DO UPDATE SET
                    severity = EXCLUDED.severity,
                    affected_range = EXCLUDED.affected_range,
                    fixed_version = EXCLUDED.fixed_version,
                    advisory_url = EXCLUDED.advisory_url,
                    last_checked = EXCLUDED.last_checked,
                    status = EXCLUDED.status,
                    bounty_issue_number = COALESCE(
                        EXCLUDED.bounty_issue_number,
                        known_vulnerabilities.bounty_issue_number
                    )
                """,
                (
                    vuln_id, cve_id, dedup_key, package_name, language, severity,
                    affected_range, fixed_version, advisory_url, repo,
                    now, now, status, bounty_issue_number,
                ),
            )

    # ── Patrol finding signatures ─────────────────────────────────────

    async def get_known_finding_signatures(
        self, repo: str,
    ) -> set[tuple[str, str, int]]:
        """Return known finding signatures as ``(rule_id, file_path, line_start)`` tuples."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT rule_id, file_path, line_start FROM patrol_finding_signatures "
                    "WHERE repo = %s",
                    (repo,),
                )
            ).fetchall()
        return {(row["rule_id"], row["file_path"], row["line_start"]) for row in rows}

    async def upsert_finding_signatures(
        self,
        repo: str,
        signatures: list[tuple[str, str, int]],
    ) -> None:
        """Batch insert or update finding signatures, refreshing ``last_seen``."""
        if not signatures:
            return
        pool = self._require_pool()
        now = datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            for rule_id, file_path, line_start in signatures:
                await conn.execute(
                    """\
                    INSERT INTO patrol_finding_signatures
                        (repo, rule_id, file_path, line_start, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT(repo, rule_id, file_path, line_start) DO UPDATE SET
                        last_seen = EXCLUDED.last_seen
                    """,
                    (repo, rule_id, file_path, line_start, now, now),
                )

    async def get_code_finding_bounty(
        self, repo: str, rule_id: str, file_path: str, line_start: int,
    ) -> int | None:
        """Return bounty issue number for a code finding, or ``None`` if not found."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT bounty_issue_number FROM patrol_finding_signatures "
                    "WHERE repo = %s AND rule_id = %s AND file_path = %s AND line_start = %s "
                    "AND bounty_issue_number IS NOT NULL",
                    (repo, rule_id, file_path, line_start),
                )
            ).fetchone()
        return row["bounty_issue_number"] if row else None

    async def set_finding_bounty(
        self, repo: str, rule_id: str, file_path: str, line_start: int,
        bounty_issue_number: int,
    ) -> None:
        """Record the bounty issue number for a code finding signature."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            await conn.execute(
                "UPDATE patrol_finding_signatures SET bounty_issue_number = %s "
                "WHERE repo = %s AND rule_id = %s AND file_path = %s AND line_start = %s",
                (bounty_issue_number, repo, rule_id, file_path, line_start),
            )

    # ── Dashboard query methods ───────────────────────────────────────

    async def list_pipeline_history(
        self,
        repo: str | None = None,
        verdict: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return pipeline history records with parsed verdict JSON."""
        pool = self._require_pool()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = %s")
            params.append(repo)
        if verdict:
            conditions.append("verdict LIKE %s")
            params.append(f'%"decision": "{verdict}"%')
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM pipeline_history{where} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        async with pool.connection() as conn:
            cursor = await conn.execute(sql, params)
            rows = await cursor.fetchall()
        results = []
        for row in rows:
            record = dict(row)
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
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM pipeline_history WHERE id = %s", (record_id,),
                )
            ).fetchone()
            if row is None:
                return None
        record = dict(row)
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
        pool = self._require_pool()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = %s")
            params.append(repo)
        if verdict:
            conditions.append("verdict LIKE %s")
            params.append(f'%"decision": "{verdict}"%')
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT COUNT(*) AS cnt FROM pipeline_history{where}"  # noqa: S608
        async with pool.connection() as conn:
            row = await (await conn.execute(sql, params)).fetchone()
        return row["cnt"] if row else 0

    async def list_contributors(
        self,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return contributor profiles ordered by approved submissions."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM contributor_profiles "
                    "ORDER BY approved_submissions DESC LIMIT %s OFFSET %s",
                    (limit, offset),
                )
            ).fetchall()
        return [dict(row) for row in rows]

    async def get_contributor(self, contributor_id: str) -> dict[str, Any] | None:
        """Return a single contributor profile by ID."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT * FROM contributor_profiles WHERE id = %s",
                    (contributor_id,),
                )
            ).fetchone()
        return dict(row) if row else None

    async def count_contributors(self) -> int:
        """Count total contributor profiles."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute("SELECT COUNT(*) AS cnt FROM contributor_profiles")
            ).fetchone()
        return row["cnt"] if row else 0

    async def list_patrol_history(
        self,
        repo: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return patrol history records ordered by timestamp descending."""
        pool = self._require_pool()
        params: list[Any] = []
        where = ""
        if repo:
            where = " WHERE repo = %s"
            params.append(repo)
        sql = (
            f"SELECT * FROM patrol_history{where} "  # noqa: S608
            "ORDER BY timestamp DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        async with pool.connection() as conn:
            rows = await (await conn.execute(sql, params)).fetchall()
        return [dict(row) for row in rows]

    async def list_known_vulnerabilities(
        self,
        repo: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return known vulnerabilities with optional filters."""
        pool = self._require_pool()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = %s")
            params.append(repo)
        if status:
            conditions.append("status = %s")
            params.append(status)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM known_vulnerabilities{where} "  # noqa: S608
            "ORDER BY first_detected DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        async with pool.connection() as conn:
            rows = await (await conn.execute(sql, params)).fetchall()
        return [dict(row) for row in rows]

    async def list_patrol_patches(
        self,
        repo: str | None = None,
        status: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return patrol patches with optional filters."""
        pool = self._require_pool()
        conditions: list[str] = []
        params: list[Any] = []
        if repo:
            conditions.append("repo = %s")
            params.append(repo)
        if status:
            conditions.append("status = %s")
            params.append(status)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM patrol_patches{where} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        async with pool.connection() as conn:
            rows = await (await conn.execute(sql, params)).fetchall()
        return [dict(row) for row in rows]

    async def list_codebase_knowledge(self, repo: str) -> list[dict[str, Any]]:
        """Return all codebase knowledge entries for a repository."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM codebase_knowledge WHERE repo = %s ORDER BY file_path",
                    (repo,),
                )
            ).fetchall()
        return [dict(row) for row in rows]

    async def search_attestations(
        self,
        query: str | None = None,
        action_type: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search attestation records by ID or PR ID prefix."""
        pool = self._require_pool()
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            conditions.append(
                "(attestation_id LIKE %s OR pr_id LIKE %s)",
            )
            like_param = f"%{query}%"
            params.extend([like_param, like_param])
        if action_type:
            conditions.append("attestation_id LIKE %s")
            params.append(f"{action_type}-%")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM attestation_store{where} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        async with pool.connection() as conn:
            rows = await (await conn.execute(sql, params)).fetchall()
        return [dict(row) for row in rows]

    async def count_attestations(
        self,
        query: str | None = None,
        action_type: str | None = None,
    ) -> int:
        """Count attestation records matching optional filters."""
        pool = self._require_pool()
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            conditions.append("(attestation_id LIKE %s OR pr_id LIKE %s)")
            like_param = f"%{query}%"
            params.extend([like_param, like_param])
        if action_type:
            conditions.append("attestation_id LIKE %s")
            params.append(f"{action_type}-%")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT COUNT(*) AS cnt FROM attestation_store{where}"  # noqa: S608
        async with pool.connection() as conn:
            row = await (await conn.execute(sql, params)).fetchone()
        return row["cnt"] if row else 0

    async def list_all_vision_documents(self) -> list[dict[str, Any]]:
        """Return all vision documents without content/embedding for listing."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT id, repo, doc_type, updated_at FROM vision_documents "
                    "ORDER BY updated_at DESC",
                )
            ).fetchall()
        return [dict(row) for row in rows]

    async def list_transactions(
        self,
        limit: int = 25,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return treasury transactions ordered by timestamp descending."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT * FROM treasury_transactions "
                    "ORDER BY timestamp DESC LIMIT %s OFFSET %s",
                    (limit, offset),
                )
            ).fetchall()
        return [dict(row) for row in rows]

    async def count_transactions(self) -> int:
        """Count total treasury transactions."""
        pool = self._require_pool()
        async with pool.connection() as conn:
            row = await (
                await conn.execute("SELECT COUNT(*) AS cnt FROM treasury_transactions")
            ).fetchone()
        return row["cnt"] if row else 0

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
        pool = self._require_pool()
        ts = timestamp or datetime.now(UTC).isoformat()
        async with pool.connection() as conn:
            await conn.execute(
                "INSERT INTO treasury_transactions "
                "(id, tx_hash, tx_type, amount_wei, currency, counterparty, "
                "pr_id, audit_id, bounty_id, attestation_id, timestamp) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    tx_id, tx_hash, tx_type, amount_wei, currency, counterparty,
                    pr_id, audit_id, bounty_id, attestation_id, ts,
                ),
            )
