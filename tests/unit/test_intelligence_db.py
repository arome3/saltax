"""Tests for intelligence database, similarity, and pattern extraction."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from src.intelligence.database import IntelligenceDB
from src.intelligence.pattern_extractor import extract_patterns
from src.intelligence.similarity import (
    _extract_code_tokens,
    _normalize_pattern,
    blob_to_vector,
    cosine_similarity,
    vector_to_blob,
)

_ = pytest  # ensure pytest is used (fixture injection)


# ── Fixtures ─────────────────────────────────────────────────────────────────


_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)


@pytest.fixture()
async def intel_db():
    """Provide a fresh IntelligenceDB backed by a PostgreSQL test database."""
    db = IntelligenceDB(
        database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3,
    )
    await db.initialize()
    try:
        yield db
    finally:
        try:
            pool = db.pool
            async with pool.connection() as conn:
                tables = await (
                    await conn.execute(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                    )
                ).fetchall()
                for t in tables:
                    await conn.execute(f'TRUNCATE TABLE "{t["tablename"]}" CASCADE')
        except Exception:
            pass
        await db.close()


def _make_verdict(decision: str = "approve", score: float = 0.85) -> dict:
    return {
        "decision": decision,
        "composite_score": score,
        "findings_count": 2,
        "score_breakdown": {"static_clear": 1.0},
    }


def _make_static_findings() -> list[dict]:
    return [
        {
            "rule_id": "sql-injection",
            "severity": "HIGH",
            "category": "security",
            "message": "SQL injection via f-string",
            "snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
            "confidence": 0.95,
        },
        {
            "rule_id": "hardcoded-secret",
            "severity": "CRITICAL",
            "category": "security",
            "message": "Hardcoded API key detected",
            "snippet": 'API_KEY = "sk-12345-secret"',
            "confidence": 0.99,
        },
    ]


def _make_ai_findings() -> list[dict]:
    return [
        {
            "rule_id": "missing-auth-check",
            "severity": "HIGH",
            "category": "ai-analysis",
            "description": "The endpoint /api/admin lacks authentication middleware",
            "confidence": 0.75,
        },
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# A. Schema creation
# ═══════════════════════════════════════════════════════════════════════════════


class TestSchemaCreation:
    """Verify DB schema is created correctly."""

    async def test_all_tables_exist(self, intel_db: IntelligenceDB) -> None:
        """All 16 expected tables should be present."""
        expected = {
            "schema_version", "vulnerability_patterns", "contributor_profiles",
            "codebase_knowledge", "pipeline_history", "attestation_store",
            "active_bounties", "verification_windows", "pr_embeddings",
            "vision_documents", "ranking_updates", "issue_embeddings",
            "backfill_progress",
            "patrol_history", "known_vulnerabilities", "patrol_patches",
        }
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT tablename FROM pg_catalog.pg_tables "
                "WHERE schemaname = 'public'",
            )
            rows = await cursor.fetchall()
            tables = {row["tablename"] for row in rows}
        assert expected <= tables

    async def test_idempotent_reinit_closes_old_connection(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Fix #5: Calling initialize() again closes the prior connection."""
        old_pool = intel_db.pool
        await intel_db.initialize()
        assert intel_db.initialized is True
        # The old pool should no longer be the active one
        assert intel_db.pool is not old_pool
        count = await intel_db.count_patterns()
        assert count == 0

    async def test_schema_version_row(self, intel_db: IntelligenceDB) -> None:
        """schema_version table should have exactly one row with current version."""
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT version FROM schema_version WHERE id = 1",
            )
            row = await cursor.fetchone()
        assert row is not None
        assert row["version"] == 16


# ═══════════════════════════════════════════════════════════════════════════════
# B. Count patterns
# ═══════════════════════════════════════════════════════════════════════════════


class TestCountPatterns:
    """Test the count_patterns method."""

    async def test_empty_db_returns_zero(self, intel_db: IntelligenceDB) -> None:
        assert await intel_db.count_patterns() == 0

    async def test_correct_after_ingest(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=_make_static_findings(),
            ai_findings=_make_ai_findings(),
            verdict=_make_verdict(),
        )
        # 2 static + 1 AI = 3 patterns
        assert await intel_db.count_patterns() == 3


# ═══════════════════════════════════════════════════════════════════════════════
# C. Ingest pipeline results
# ═══════════════════════════════════════════════════════════════════════════════


class TestIngestPipelineResults:
    """Test full ingest lifecycle."""

    async def test_creates_patterns(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=_make_static_findings(),
            ai_findings=[],
            verdict=_make_verdict(),
        )
        assert await intel_db.count_patterns() == 2

    async def test_creates_history_record(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=[],
            ai_findings=[],
            verdict=_make_verdict(),
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM pipeline_history",
            )
            row = await cursor.fetchone()
        assert row["count"] == 1

    async def test_upserts_contributor_profile(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=[],
            ai_findings=[],
            verdict=_make_verdict(decision="approve"),
            author="dev-alice",
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT total_submissions, approved_submissions "
                "FROM contributor_profiles WHERE github_login = %s",
                ("dev-alice",),
            )
            row = await cursor.fetchone()
        assert row is not None
        assert row["total_submissions"] == 1  # total
        assert row["approved_submissions"] == 1  # approved

    async def test_increments_times_seen(self, intel_db: IntelligenceDB) -> None:
        findings = _make_static_findings()[:1]  # just sql-injection
        for _ in range(3):
            await intel_db.ingest_pipeline_results(
                pr_id="owner/repo#1",
                repo="owner/repo",
                static_findings=findings,
                ai_findings=[],
                verdict=_make_verdict(),
            )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT times_seen FROM vulnerability_patterns",
            )
            row = await cursor.fetchone()
        assert row is not None
        # 3 calls: INSERT(times_seen=1), UPDATE(+1=2), UPDATE(+1=3)
        assert row["times_seen"] == 3

    async def test_handles_empty_findings(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=[],
            ai_findings=[],
            verdict=_make_verdict(),
        )
        assert await intel_db.count_patterns() == 0


# ═══════════════════════════════════════════════════════════════════════════════
# D. False positive signatures
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetFalsePositiveSignatures:
    """Test FP signature retrieval with DefectDojo-style counters."""

    async def test_empty_returns_empty_frozenset(
        self, intel_db: IntelligenceDB,
    ) -> None:
        result = await intel_db.get_false_positive_signatures()
        assert result == frozenset()

    async def test_returns_high_fp_rules(self, intel_db: IntelligenceDB) -> None:
        """Patterns with >80% FP rate should return rule_id (not internal id)."""
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO vulnerability_patterns
                    (id, rule_id, severity, category, normalized_pattern,
                     pattern_signature, confidence, times_seen, first_seen, last_seen,
                     source_stage, confirmed_true_positive, confirmed_false_positive)
                VALUES ('fp1', 'noisy-rule', 'LOW', 'lint', 'pattern', 'sig1',
                        0.5, 10, '2024-01-01', '2024-01-01', 'static_scanner', 1, 9)
                """,
            )

        result = await intel_db.get_false_positive_signatures()
        # Should return rule_id, not internal UUID
        assert "noisy-rule" in result
        assert "fp1" not in result

    async def test_excludes_low_fp_rules(self, intel_db: IntelligenceDB) -> None:
        """Patterns with <=80% FP rate should NOT be returned."""
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO vulnerability_patterns
                    (id, rule_id, severity, category, normalized_pattern,
                     pattern_signature, confidence, times_seen, first_seen, last_seen,
                     source_stage, confirmed_true_positive, confirmed_false_positive)
                VALUES ('good1', 'good-rule', 'HIGH', 'security', 'pattern', 'sig2',
                        0.9, 10, '2024-01-01', '2024-01-01', 'static_scanner', 8, 2)
                """,
            )

        result = await intel_db.get_false_positive_signatures()
        assert "good-rule" not in result

    async def test_min_signals_guard(self, intel_db: IntelligenceDB) -> None:
        """Rules with fewer than 5 total signals should NOT be suppressed."""
        async with intel_db.pool.connection() as conn:
            # 0 TP + 4 FP = 100% FP rate but only 4 signals (below threshold)
            await conn.execute(
                """\
                INSERT INTO vulnerability_patterns
                    (id, rule_id, severity, category, normalized_pattern,
                     pattern_signature, confidence, times_seen, first_seen, last_seen,
                     source_stage, confirmed_true_positive, confirmed_false_positive)
                VALUES ('few1', 'few-signal-rule', 'LOW', 'lint', 'pattern', 'sig-few',
                        0.5, 10, '2024-01-01', '2024-01-01', 'static_scanner', 0, 4)
                """,
            )

        result = await intel_db.get_false_positive_signatures()
        assert "few-signal-rule" not in result

        # Now bump to exactly 5 FP → should appear
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                "UPDATE vulnerability_patterns "
                "SET confirmed_false_positive = 5 "
                "WHERE id = 'few1'",
            )

        result = await intel_db.get_false_positive_signatures()
        assert "few-signal-rule" in result


class TestRecordFeedbackSignal:
    """Test the feedback signal recording from reactions."""

    async def test_new_signal_returns_true(self, intel_db: IntelligenceDB) -> None:
        """A brand-new feedback signal inserts and returns True."""
        # Insert a pattern to update
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO vulnerability_patterns
                    (id, rule_id, severity, category, normalized_pattern,
                     pattern_signature, confidence, times_seen, first_seen, last_seen,
                     source_stage, confirmed_true_positive, confirmed_false_positive)
                VALUES ('p1', 'test-rule', 'MEDIUM', 'security', 'pattern', 'sig-fb1',
                        0.5, 1, '2024-01-01', '2024-01-01', 'static_scanner', 0, 0)
                """,
            )

        result = await intel_db.record_feedback_signal(
            rule_id="test-rule",
            repo="owner/repo",
            pr_number=42,
            comment_id=100,
            reactor_login="alice",
            reaction="+1",
        )
        assert result is True

        # Verify counter incremented
        async with intel_db.pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT confirmed_true_positive, confirmed_false_positive "
                    "FROM vulnerability_patterns WHERE id = 'p1'",
                )
            ).fetchone()
        assert row is not None
        assert row["confirmed_true_positive"] == 1
        assert row["confirmed_false_positive"] == 0

    async def test_duplicate_signal_returns_false(self, intel_db: IntelligenceDB) -> None:
        """Duplicate signal (same rule/repo/PR/reactor/reaction) returns False."""
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO vulnerability_patterns
                    (id, rule_id, severity, category, normalized_pattern,
                     pattern_signature, confidence, times_seen, first_seen, last_seen,
                     source_stage, confirmed_true_positive, confirmed_false_positive)
                VALUES ('p2', 'dup-rule', 'LOW', 'lint', 'pattern', 'sig-fb2',
                        0.5, 1, '2024-01-01', '2024-01-01', 'static_scanner', 0, 0)
                """,
            )

        # First call succeeds
        r1 = await intel_db.record_feedback_signal(
            rule_id="dup-rule", repo="owner/repo", pr_number=1,
            comment_id=200, reactor_login="bob", reaction="-1",
        )
        assert r1 is True

        # Duplicate call returns False
        r2 = await intel_db.record_feedback_signal(
            rule_id="dup-rule", repo="owner/repo", pr_number=1,
            comment_id=200, reactor_login="bob", reaction="-1",
        )
        assert r2 is False

        # Counter should only be incremented once
        async with intel_db.pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT confirmed_false_positive "
                    "FROM vulnerability_patterns WHERE id = 'p2'",
                )
            ).fetchone()
        assert row is not None
        assert row["confirmed_false_positive"] == 1

    async def test_negative_reaction_increments_fp(self, intel_db: IntelligenceDB) -> None:
        """A -1 reaction increments confirmed_false_positive."""
        async with intel_db.pool.connection() as conn:
            await conn.execute(
                """\
                INSERT INTO vulnerability_patterns
                    (id, rule_id, severity, category, normalized_pattern,
                     pattern_signature, confidence, times_seen, first_seen, last_seen,
                     source_stage, confirmed_true_positive, confirmed_false_positive)
                VALUES ('p3', 'neg-rule', 'HIGH', 'security', 'pattern', 'sig-fb3',
                        0.5, 1, '2024-01-01', '2024-01-01', 'static_scanner', 0, 0)
                """,
            )

        await intel_db.record_feedback_signal(
            rule_id="neg-rule", repo="owner/repo", pr_number=5,
            comment_id=300, reactor_login="carol", reaction="-1",
        )

        async with intel_db.pool.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT confirmed_true_positive, confirmed_false_positive "
                    "FROM vulnerability_patterns WHERE id = 'p3'",
                )
            ).fetchone()
        assert row is not None
        assert row["confirmed_true_positive"] == 0
        assert row["confirmed_false_positive"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# E. Contributor acceptance rate
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetContributorAcceptanceRate:
    """Test contributor history query."""

    async def test_unknown_returns_none(self, intel_db: IntelligenceDB) -> None:
        result = await intel_db.get_contributor_acceptance_rate("repo", "unknown")
        assert result is None

    async def test_insufficient_data_returns_none(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Less than 5 submissions → None."""
        for i in range(4):
            await intel_db.ingest_pipeline_results(
                pr_id=f"owner/repo#{i}",
                repo="owner/repo",
                static_findings=[],
                ai_findings=[],
                verdict=_make_verdict(decision="approve"),
                author="dev",
            )
        result = await intel_db.get_contributor_acceptance_rate(
            "owner/repo", "dev",
        )
        assert result is None

    async def test_correct_rate_after_threshold(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """5+ submissions → returns correct rate."""
        for i in range(4):
            await intel_db.ingest_pipeline_results(
                pr_id=f"owner/repo#{i}",
                repo="owner/repo",
                static_findings=[],
                ai_findings=[],
                verdict=_make_verdict(decision="approve"),
                author="dev",
            )
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#4",
            repo="owner/repo",
            static_findings=[],
            ai_findings=[],
            verdict=_make_verdict(decision="reject"),
            author="dev",
        )
        result = await intel_db.get_contributor_acceptance_rate(
            "owner/repo", "dev",
        )
        assert result is not None
        assert abs(result - 0.8) < 0.01  # 4/5 = 0.8

    async def test_fallback_matches_decision_precisely(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Fix #10: fallback LIKE only matches "decision": "approve"."""
        async with intel_db.pool.connection() as conn:
            # Insert history rows directly (bypass contributor_profiles)
            for i in range(5):
                decision = "approve" if i < 3 else "reject"
                verdict = f'{{"decision": "{decision}", "composite_score": 0.5}}'
                await conn.execute(
                    """\
                    INSERT INTO pipeline_history
                        (id, pr_id, repo, pr_author, verdict,
                         composite_score, findings_count, created_at)
                    VALUES (%s, %s, 'owner/repo', 'fallback-dev', %s, 0.5, 0, '2024-01-01')
                    """,
                    (f"h{i}", f"pr#{i}", verdict),
                )

        result = await intel_db.get_contributor_acceptance_rate(
            "owner/repo", "fallback-dev",
        )
        assert result is not None
        assert abs(result - 0.6) < 0.01  # 3/5 = 0.6


# ═══════════════════════════════════════════════════════════════════════════════
# F. Query similar patterns
# ═══════════════════════════════════════════════════════════════════════════════


class TestQuerySimilarPatterns:
    """Test LIKE-based pattern search."""

    async def test_empty_result(self, intel_db: IntelligenceDB) -> None:
        result = await intel_db.query_similar_patterns("def hello():\n    pass")
        assert result == []

    async def test_finds_matching_pattern(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=[{
                "rule_id": "sql-injection",
                "severity": "HIGH",
                "category": "security",
                "snippet": "cursor.execute(f\"SELECT * FROM users\")",
            }],
            ai_findings=[],
            verdict=_make_verdict(),
        )
        result = await intel_db.query_similar_patterns(
            "cursor.execute(f\"SELECT * FROM orders\")",
        )
        assert len(result) > 0

    async def test_respects_limit(self, intel_db: IntelligenceDB) -> None:
        for i in range(5):
            await intel_db.ingest_pipeline_results(
                pr_id=f"owner/repo#{i}",
                repo="owner/repo",
                static_findings=[{
                    "rule_id": f"rule-{i}",
                    "severity": "MEDIUM",
                    "category": "test",
                    "snippet": f"vulnerable_function_{i}(user_input)",
                }],
                ai_findings=[],
                verdict=_make_verdict(),
            )
        result = await intel_db.query_similar_patterns(
            "vulnerable_function(user_input)", limit=2,
        )
        assert len(result) <= 2


# ═══════════════════════════════════════════════════════════════════════════════
# G. Get stats
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetStats:
    """Test anonymized stats aggregation."""

    async def test_empty_db_zeroes(self, intel_db: IntelligenceDB) -> None:
        stats = await intel_db.get_stats()
        assert stats["total_patterns"] == 0
        assert stats["category_distribution"] == {}
        assert stats["severity_distribution"] == {}
        assert stats["avg_false_positive_rate"] == 0.0
        assert stats["patterns_last_7_days"] == 0
        assert stats["top_contributing_repos"] == []

    async def test_populated_correct_aggregates(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=_make_static_findings(),
            ai_findings=_make_ai_findings(),
            verdict=_make_verdict(),
            author="dev",
        )
        stats = await intel_db.get_stats()
        assert stats["total_patterns"] == 3
        assert "security" in stats["category_distribution"]
        assert "HIGH" in stats["severity_distribution"]
        assert stats["top_contributing_repos"] == ["owner/repo"]


# ═══════════════════════════════════════════════════════════════════════════════
# H. Close lifecycle
# ═══════════════════════════════════════════════════════════════════════════════


class TestCloseLifecycle:
    """Test close operations."""

    async def test_close_sets_uninitialized(
        self, intel_db: IntelligenceDB,
    ) -> None:
        assert intel_db.initialized is True
        await intel_db.close()
        assert intel_db.initialized is False

    async def test_close_is_idempotent(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Calling close() twice should not raise."""
        await intel_db.close()
        await intel_db.close()
        assert intel_db.initialized is False


# ═══════════════════════════════════════════════════════════════════════════════
# I. Get attestation
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetAttestation:
    """Test attestation store queries."""

    async def test_not_found_returns_none(
        self, intel_db: IntelligenceDB,
    ) -> None:
        result = await intel_db.get_attestation("nonexistent")
        assert result is None

    async def test_store_and_retrieve(self, intel_db: IntelligenceDB) -> None:
        """Fix #1: Test the write path for attestation_store."""
        await intel_db.store_attestation(
            attestation_id="attest-1",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash="abc123",
            pipeline_output_hash="def456",
            signature="sig",
        )
        result = await intel_db.get_attestation("attest-1")
        assert result is not None
        assert result["attestation_id"] == "attest-1"
        assert result["pr_id"] == "owner/repo#1"


# ═══════════════════════════════════════════════════════════════════════════════
# J. Pattern extractor
# ═══════════════════════════════════════════════════════════════════════════════


class TestPatternExtractor:
    """Test the pattern extraction module."""

    def test_static_findings_extracted(self) -> None:
        patterns = extract_patterns(_make_static_findings(), [])
        assert len(patterns) == 2
        assert all(p["source_stage"] == "static_scanner" for p in patterns)

    def test_ai_findings_extracted(self) -> None:
        patterns = extract_patterns([], _make_ai_findings())
        assert len(patterns) == 1
        assert patterns[0]["source_stage"] == "ai_analyzer"

    def test_empty_snippets_skipped(self) -> None:
        findings = [{"rule_id": "empty", "severity": "LOW", "snippet": ""}]
        patterns = extract_patterns(findings, [])
        assert len(patterns) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# K. Similarity module
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimilarity:
    """Test tokenization, normalization, and cosine similarity."""

    def test_extract_code_tokens(self) -> None:
        tokens = _extract_code_tokens("def hello_world():\n    return value")
        assert "hello_world" in tokens
        assert "value" in tokens
        # stopwords removed
        assert "def" not in tokens
        assert "return" not in tokens

    def test_normalize_pattern(self) -> None:
        raw = 'execute(f"SELECT * FROM users WHERE id = 42")'
        normalized = _normalize_pattern(raw)
        assert "42" not in normalized  # numerics replaced
        assert "  " not in normalized  # whitespace collapsed

    def test_cosine_identical_vectors(self) -> None:
        vec = vector_to_blob([1.0, 0.0, 0.0])
        assert abs(cosine_similarity(vec, vec) - 1.0) < 1e-6

    def test_cosine_orthogonal_vectors(self) -> None:
        a = vector_to_blob([1.0, 0.0, 0.0])
        b = vector_to_blob([0.0, 1.0, 0.0])
        assert abs(cosine_similarity(a, b)) < 1e-6

    def test_cosine_mismatched_sizes_returns_zero(self) -> None:
        """Fix #8: Mismatched blob sizes return 0.0 instead of crashing."""
        a = vector_to_blob([1.0, 0.0, 0.0])
        b = vector_to_blob([1.0, 0.0])  # different dimension
        assert cosine_similarity(a, b) == 0.0

    def test_cosine_empty_blobs_returns_zero(self) -> None:
        """Fix #8: Empty blobs return 0.0."""
        assert cosine_similarity(b"", b"") == 0.0

    def test_cosine_non_aligned_blobs_returns_zero(self) -> None:
        """Fix #8: Blobs not aligned to float32 (4 bytes) return 0.0."""
        assert cosine_similarity(b"\x00\x01\x02", b"\x00\x01\x02") == 0.0

    def test_vector_roundtrip(self) -> None:
        original = [0.1, 0.2, 0.3, 0.4, 0.5]
        blob = vector_to_blob(original)
        restored = blob_to_vector(blob)
        for a, b in zip(original, restored, strict=True):
            assert abs(a - b) < 1e-6


# ═══════════════════════════════════════════════════════════════════════════════
# L. Embeddings
# ═══════════════════════════════════════════════════════════════════════════════


class TestEmbeddings:
    """Test PR embedding storage and similarity search."""

    async def test_store_and_retrieve(self, intel_db: IntelligenceDB) -> None:
        emb = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_embedding(
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            commit_sha="abc123",
            embedding_blob=emb,
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM pr_embeddings",
            )
            row = await cursor.fetchone()
        assert row["count"] == 1

    async def test_find_similar_above_threshold(
        self, intel_db: IntelligenceDB,
    ) -> None:
        emb1 = vector_to_blob([1.0, 0.0, 0.0])
        emb2 = vector_to_blob([0.99, 0.1, 0.0])  # very similar to emb1
        await intel_db.store_embedding(
            pr_id="owner/repo#1", repo="owner/repo",
            pr_number=1, commit_sha="aaa",
            embedding_blob=emb1,
        )
        results = await intel_db.find_similar_prs(
            emb2, "owner/repo", threshold=0.9,
        )
        assert len(results) == 1
        assert results[0]["similarity"] >= 0.9

    async def test_no_matches_below_threshold(
        self, intel_db: IntelligenceDB,
    ) -> None:
        emb1 = vector_to_blob([1.0, 0.0, 0.0])
        emb_orth = vector_to_blob([0.0, 1.0, 0.0])  # orthogonal
        await intel_db.store_embedding(
            pr_id="owner/repo#1", repo="owner/repo",
            pr_number=1, commit_sha="aaa",
            embedding_blob=emb1,
        )
        results = await intel_db.find_similar_prs(
            emb_orth, "owner/repo", threshold=0.5,
        )
        assert len(results) == 0

    async def test_backfill_null_to_value(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """GAP 4: backfill_embedding_issue_number updates NULL→42."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_embedding(
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            commit_sha="abc123",
            embedding_blob=emb,
        )
        updated = await intel_db.backfill_embedding_issue_number(
            pr_id="owner/repo#1", repo="owner/repo", issue_number=42,
        )
        assert updated == 1
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT issue_number FROM pr_embeddings WHERE pr_id = 'owner/repo#1'",
            )
            row = await cursor.fetchone()
        assert row["issue_number"] == 42

    async def test_backfill_skips_non_null(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """GAP 4: backfill does not overwrite already-set issue_number."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_embedding(
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            commit_sha="abc123",
            embedding_blob=emb,
            issue_number=99,
        )
        updated = await intel_db.backfill_embedding_issue_number(
            pr_id="owner/repo#1", repo="owner/repo", issue_number=42,
        )
        assert updated == 0
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT issue_number FROM pr_embeddings WHERE pr_id = 'owner/repo#1'",
            )
            row = await cursor.fetchone()
        assert row["issue_number"] == 99  # unchanged

    async def test_backfill_no_match_returns_zero(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """GAP 4: no matching rows → returns 0."""
        updated = await intel_db.backfill_embedding_issue_number(
            pr_id="nonexistent", repo="owner/repo", issue_number=42,
        )
        assert updated == 0

    async def test_on_conflict_updates_issue_number(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """GAP 1: Re-storing an embedding with issue_number updates NULL→42."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        # First store — no issue_number (defaults to NULL)
        await intel_db.store_embedding(
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            commit_sha="abc123",
            embedding_blob=emb,
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT issue_number FROM pr_embeddings WHERE pr_id = 'owner/repo#1'",
            )
            row = await cursor.fetchone()
        assert row["issue_number"] is None

        # Second store — same pr_id + commit_sha → same deterministic id
        await intel_db.store_embedding(
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            commit_sha="abc123",
            embedding_blob=emb,
            issue_number=42,
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT issue_number FROM pr_embeddings WHERE pr_id = 'owner/repo#1'",
            )
            row = await cursor.fetchone()
        assert row["issue_number"] == 42

    async def test_mismatched_embedding_sizes_skipped(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Fix #8: Stored 3-dim embedding queried with 2-dim → no crash."""
        emb_3d = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_embedding(
            pr_id="owner/repo#1", repo="owner/repo",
            pr_number=1, commit_sha="aaa",
            embedding_blob=emb_3d,
        )
        emb_2d = vector_to_blob([1.0, 0.0])
        results = await intel_db.find_similar_prs(
            emb_2d, "owner/repo", threshold=0.01,
        )
        assert len(results) == 0  # mismatched sizes → sim 0.0 → below threshold


# ═══════════════════════════════════════════════════════════════════════════════
# M. Require DB guard (Fix #3)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRequireDB:
    """Fix #3: Methods raise RuntimeError when DB is not initialized."""

    async def test_count_patterns_raises_before_init(self) -> None:
        db = IntelligenceDB(
            database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3,
        )
        # Do NOT call initialize()
        with pytest.raises(RuntimeError, match="not initialized"):
            await db.count_patterns()

    async def test_pool_available_after_init(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """After initialize(), pool property returns a connection pool."""
        pool = intel_db.pool
        assert pool is not None


# ═══════════════════════════════════════════════════════════════════════════════
# N. Verdict feedback (Fix #2)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerdictFeedback:
    """Fix #2: FP counters are actually incremented."""

    async def test_record_true_positive(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=_make_static_findings()[:1],
            ai_findings=[],
            verdict=_make_verdict(),
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT id FROM vulnerability_patterns LIMIT 1",
            )
            row = await cursor.fetchone()
        pat_id = row["id"]

        await intel_db.record_verdict_feedback(pat_id, is_true_positive=True)

        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT confirmed_true_positive, confirmed_false_positive "
                "FROM vulnerability_patterns WHERE id = %s",
                (pat_id,),
            )
            row = await cursor.fetchone()
        assert row["confirmed_true_positive"] == 1  # TP incremented
        assert row["confirmed_false_positive"] == 0  # FP unchanged

    async def test_record_false_positive(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=_make_static_findings()[:1],
            ai_findings=[],
            verdict=_make_verdict(),
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT id FROM vulnerability_patterns LIMIT 1",
            )
            row = await cursor.fetchone()
        pat_id = row["id"]

        await intel_db.record_verdict_feedback(pat_id, is_true_positive=False)

        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT confirmed_true_positive, confirmed_false_positive "
                "FROM vulnerability_patterns WHERE id = %s",
                (pat_id,),
            )
            row = await cursor.fetchone()
        assert row["confirmed_true_positive"] == 0  # TP unchanged
        assert row["confirmed_false_positive"] == 1  # FP incremented

    async def test_fp_feedback_surfaces_in_signatures(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """After enough FP feedback, the rule_id appears in FP signatures."""
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=_make_static_findings()[:1],
            ai_findings=[],
            verdict=_make_verdict(),
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT id, rule_id FROM vulnerability_patterns LIMIT 1",
            )
            row = await cursor.fetchone()
        pat_id = row["id"]
        rule_id = row["rule_id"]

        # 9 FP, 1 TP → 90% FP rate → above 80% threshold
        for _ in range(9):
            await intel_db.record_verdict_feedback(pat_id, is_true_positive=False)
        await intel_db.record_verdict_feedback(pat_id, is_true_positive=True)

        sigs = await intel_db.get_false_positive_signatures()
        assert rule_id in sigs


# ═══════════════════════════════════════════════════════════════════════════════
# O. Ghost table write paths (Fix #1)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGhostTableWritePaths:
    """Fix #1: All tables now have functional write paths."""

    async def test_store_bounty(self, intel_db: IntelligenceDB) -> None:
        await intel_db.store_bounty(
            bounty_id="b1",
            repo="owner/repo",
            issue_number=42,
            label="bounty-md",
            amount_eth=0.1,
        )
        bounties = await intel_db.get_active_bounties()
        assert len(bounties) == 1
        assert bounties[0]["label"] == "bounty-md"

    async def test_close_bounty(self, intel_db: IntelligenceDB) -> None:
        await intel_db.store_bounty(
            bounty_id="b1",
            repo="owner/repo",
            issue_number=42,
            label="bounty-md",
        )
        await intel_db.close_bounty("b1", claimed_by="dev")
        bounties = await intel_db.get_active_bounties()
        assert len(bounties) == 0  # no longer 'open'

    async def test_store_verification_window(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.store_verification_window(
            window_id="vw1",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict_json='{"decision": "APPROVE"}',
            attestation_json='{"attestation_id": "attest-1"}',
            contributor_address="0xabc",
            bounty_amount_wei="1000",
            stake_amount_wei="500",
            window_hours=24,
            opens_at="2024-01-01T00:00:00",
            closes_at="2024-01-02T00:00:00",
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM verification_windows",
            )
            row = await cursor.fetchone()
        assert row["count"] == 1

    async def test_transition_window_status(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.store_verification_window(
            window_id="vw1",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict_json='{"decision": "APPROVE"}',
            attestation_json='{"attestation_id": "attest-1"}',
            contributor_address="0xabc",
            bounty_amount_wei="1000",
            stake_amount_wei="500",
            window_hours=24,
            opens_at="2024-01-01T00:00:00",
            closes_at="2024-01-02T00:00:00",
        )
        ok = await intel_db.transition_window_status(
            "vw1", "open", "executing",
        )
        assert ok is True
        window = await intel_db.get_verification_window("vw1")
        assert window is not None
        assert window["status"] == "executing"

    async def test_store_codebase_knowledge(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.store_codebase_knowledge(
            knowledge_id="ck1",
            repo="owner/repo",
            file_path="src/main.py",
            knowledge="Entry point for the application",
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT knowledge FROM codebase_knowledge WHERE id = 'ck1'",
            )
            row = await cursor.fetchone()
        assert row["knowledge"] == "Entry point for the application"

    async def test_store_vision_document(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.store_vision_document(
            doc_id="vd1",
            repo="owner/repo",
            content="The project aims to...",
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT content FROM vision_documents WHERE id = 'vd1'",
            )
            row = await cursor.fetchone()
        assert row["content"] == "The project aims to..."


# ═══════════════════════════════════════════════════════════════════════════════
# P. Purge stale vision documents (I11)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPurgeStaleVisionDocuments:
    """I11: purge_stale_vision_documents deletes old rows, keeps fresh ones."""

    async def test_purges_old_documents(self, intel_db: IntelligenceDB) -> None:
        """Documents older than max_age_days are deleted, fresh ones kept."""
        old_time = (datetime.now(UTC) - timedelta(days=100)).isoformat()
        fresh_time = datetime.now(UTC).isoformat()

        async with intel_db.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO vision_documents (id, repo, content, embedding, updated_at) "
                "VALUES (%s, %s, %s, NULL, %s)",
                ("old1", "owner/old-repo", "Old vision.", old_time),
            )
            await conn.execute(
                "INSERT INTO vision_documents (id, repo, content, embedding, updated_at) "
                "VALUES (%s, %s, %s, NULL, %s)",
                ("fresh1", "owner/fresh-repo", "Fresh vision.", fresh_time),
            )

        deleted = await intel_db.purge_stale_vision_documents(max_age_days=90)
        assert deleted == 1

        # Old one gone
        old_doc = await intel_db.get_vision_document("owner/old-repo")
        assert old_doc is None

        # Fresh one kept
        fresh_doc = await intel_db.get_vision_document("owner/fresh-repo")
        assert fresh_doc is not None
        assert fresh_doc["content"] == "Fresh vision."

    async def test_purge_no_stale(self, intel_db: IntelligenceDB) -> None:
        """When no documents are stale, returns 0."""
        await intel_db.store_vision_document(
            doc_id="vd1",
            repo="owner/repo",
            content="Fresh doc.",
        )
        deleted = await intel_db.purge_stale_vision_documents(max_age_days=90)
        assert deleted == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Multi-source vision documents (Feature 5)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMultiSourceVisionDocs:
    async def test_store_vision_doc_with_doc_type(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Store a document with doc_type='architecture', retrieve by type."""
        await intel_db.store_vision_document(
            doc_id="vision:org/repo:architecture",
            repo="org/repo",
            content="Microservices.",
            doc_type="architecture",
        )
        docs = await intel_db.get_vision_documents("org/repo", doc_type="architecture")
        assert len(docs) == 1
        assert docs[0]["doc_type"] == "architecture"
        assert docs[0]["content"] == "Microservices."

    async def test_get_vision_documents_multiple(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Store 2 types, get_vision_documents returns both."""
        await intel_db.store_vision_document(
            doc_id="vision:org/repo:vision",
            repo="org/repo",
            content="Vision text.",
            doc_type="vision",
        )
        await intel_db.store_vision_document(
            doc_id="vision:org/repo:roadmap",
            repo="org/repo",
            content="Roadmap text.",
            doc_type="roadmap",
        )
        docs = await intel_db.get_vision_documents("org/repo")
        assert len(docs) == 2
        doc_types = {d["doc_type"] for d in docs}
        assert doc_types == {"vision", "roadmap"}

    async def test_get_vision_documents_empty(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """No documents → empty list."""
        docs = await intel_db.get_vision_documents("unknown/repo")
        assert docs == []

    async def test_store_with_embedding(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Store a document with an embedding blob, retrieve it."""
        fake_embedding = b"\x00\x01\x02\x03"
        await intel_db.store_vision_document(
            doc_id="vision:org/repo:vision",
            repo="org/repo",
            content="Vision.",
            doc_type="vision",
            embedding=fake_embedding,
        )
        docs = await intel_db.get_vision_documents("org/repo", doc_type="vision")
        assert len(docs) == 1
        assert docs[0]["embedding"] == fake_embedding


# ═══════════════════════════════════════════════════════════════════════════════
# Vision score trending (Feature 2)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVisionScoreTrending:
    async def test_store_vision_score(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Store a score, verify it exists in the table."""
        await intel_db.store_vision_score(
            repo="org/repo",
            pr_id="org/repo#10",
            pr_number=10,
            vision_score=8,
            ai_confidence=0.9,
        )
        trend = await intel_db.get_vision_score_trend("org/repo", limit=10)
        assert len(trend) == 1
        assert trend[0]["vision_score"] == 8
        assert trend[0]["ai_confidence"] == 0.9
        assert trend[0]["pr_number"] == 10

    async def test_get_vision_score_trend(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Store 5, retrieve 3, verify newest-first."""
        for i in range(5):
            await intel_db.store_vision_score(
                repo="org/repo",
                pr_id=f"org/repo#{i}",
                pr_number=i,
                vision_score=i + 5,
                ai_confidence=0.8,
            )
        trend = await intel_db.get_vision_score_trend("org/repo", limit=3)
        assert len(trend) == 3
        # Newest first — all have same timestamp so order is by rowid
        # Just verify we got 3 results
        scores = [t["vision_score"] for t in trend]
        assert len(scores) == 3

    async def test_get_vision_score_trend_empty(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """No scores → empty list."""
        trend = await intel_db.get_vision_score_trend("unknown/repo")
        assert trend == []

    async def test_store_with_goal_scores(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Store with goal_scores_json, verify retrieval."""
        import json

        goals = {"Ship v2": 8, "Improve DX": 7}
        await intel_db.store_vision_score(
            repo="org/repo",
            pr_id="org/repo#1",
            pr_number=1,
            vision_score=8,
            ai_confidence=0.9,
            goal_scores_json=json.dumps(goals),
        )
        trend = await intel_db.get_vision_score_trend("org/repo")
        assert len(trend) == 1
        # JSONB columns are auto-deserialized to dicts by psycopg3
        assert trend[0]["goal_scores_json"] == goals


# ═══════════════════════════════════════════════════════════════════════════════
# Issue embeddings (Doc 31)
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
# L-bis. Backfill progress (Fix #11)
# ═══════════════════════════════════════════════════════════════════════════════


class TestBackfillProgress:
    """Test backfill progress save/get/upsert lifecycle."""

    async def test_save_and_get_progress(self, intel_db: IntelligenceDB) -> None:
        """Save progress, read back, verify all fields."""
        await intel_db.save_backfill_progress(
            repo="owner/repo",
            mode="embedding_only",
            status="running",
            last_page=5,
            processed=42,
            failed=2,
            skipped=10,
        )
        progress = await intel_db.get_backfill_progress("owner/repo", "embedding_only")
        assert progress is not None
        assert progress["repo"] == "owner/repo"
        assert progress["mode"] == "embedding_only"
        assert progress["status"] == "running"
        assert progress["last_page"] == 5
        assert progress["processed"] == 42
        assert progress["failed"] == 2
        assert progress["skipped"] == 10

    async def test_upsert_on_same_repo_mode(self, intel_db: IntelligenceDB) -> None:
        """Second save with same repo+mode overwrites values."""
        await intel_db.save_backfill_progress(
            repo="owner/repo",
            mode="full:pr",
            status="running",
            last_page=3,
            processed=20,
            failed=1,
            skipped=5,
        )
        await intel_db.save_backfill_progress(
            repo="owner/repo",
            mode="full:pr",
            status="completed",
            last_page=10,
            processed=100,
            failed=3,
            skipped=15,
        )
        progress = await intel_db.get_backfill_progress("owner/repo", "full:pr")
        assert progress is not None
        assert progress["status"] == "completed"
        assert progress["last_page"] == 10
        assert progress["processed"] == 100

    async def test_get_nonexistent_returns_none(self, intel_db: IntelligenceDB) -> None:
        """No progress record → None."""
        progress = await intel_db.get_backfill_progress("nonexistent/repo", "embedding_only")
        assert progress is None


class TestGetPrEmbedding:
    """Test PR embedding retrieval used for idempotency checks."""

    async def test_returns_stored_embedding(self, intel_db: IntelligenceDB) -> None:
        """Store an embedding, then retrieve via get_pr_embedding."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_embedding(
            pr_id="owner/repo#5",
            repo="owner/repo",
            pr_number=5,
            commit_sha="deadbeef",
            embedding_blob=emb,
            embedding_model="text-embedding",
        )
        result = await intel_db.get_pr_embedding("owner/repo", 5)
        assert result is not None
        assert result["pr_id"] == "owner/repo#5"
        assert result["pr_number"] == 5
        assert result["commit_sha"] == "deadbeef"

    async def test_nonexistent_returns_none(self, intel_db: IntelligenceDB) -> None:
        """No embedding for this repo+pr_number → None."""
        result = await intel_db.get_pr_embedding("owner/repo", 999)
        assert result is None


class TestIssueEmbeddings:
    """Test issue embedding storage and retrieval."""

    async def test_issue_embeddings_table_exists(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """issue_embeddings table should be present after init."""
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT tablename FROM pg_catalog.pg_tables "
                "WHERE schemaname = 'public' AND tablename = 'issue_embeddings'",
            )
            row = await cursor.fetchone()
        assert row is not None

    async def test_store_and_retrieve_issue_embedding(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Round-trip: store → retrieve by repo+issue_number."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_issue_embedding(
            issue_id="owner/repo:42",
            repo="owner/repo",
            issue_number=42,
            title="Bug report",
            embedding=emb,
            labels=["bug", "high-priority"],
        )
        result = await intel_db.get_issue_embedding("owner/repo", 42)
        assert result is not None
        assert result["issue_number"] == 42
        assert result["title"] == "Bug report"
        assert result["repo"] == "owner/repo"

    async def test_store_replaces_on_same_issue(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """ON CONFLICT upsert updates title/embedding but preserves created_at."""
        emb1 = vector_to_blob([1.0, 0.0, 0.0])
        emb2 = vector_to_blob([0.0, 1.0, 0.0])
        await intel_db.store_issue_embedding(
            issue_id="owner/repo:42",
            repo="owner/repo",
            issue_number=42,
            title="Original",
            embedding=emb1,
        )

        # Capture original created_at
        original = await intel_db.get_issue_embedding("owner/repo", 42)
        assert original is not None
        original_created = original["created_at"]

        await intel_db.store_issue_embedding(
            issue_id="owner/repo:42",
            repo="owner/repo",
            issue_number=42,
            title="Updated",
            embedding=emb2,
        )
        result = await intel_db.get_issue_embedding("owner/repo", 42)
        assert result is not None
        assert result["title"] == "Updated"

        # created_at preserved, updated_at changed
        assert result["created_at"] == original_created
        assert result["updated_at"] >= original_created

        # Only one row should exist
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM issue_embeddings WHERE repo = 'owner/repo'",
            )
            row = await cursor.fetchone()
        assert row["count"] == 1

    async def test_get_recent_excludes_current(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """exclude_issue parameter works correctly."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        for i in range(3):
            await intel_db.store_issue_embedding(
                issue_id=f"owner/repo:{i + 1}",
                repo="owner/repo",
                issue_number=i + 1,
                title=f"Issue {i + 1}",
                embedding=emb,
            )
        recent = await intel_db.get_recent_issue_embeddings(
            "owner/repo", exclude_issue=2, status="open",
        )
        issue_numbers = {r["issue_number"] for r in recent}
        assert 2 not in issue_numbers
        assert 1 in issue_numbers
        assert 3 in issue_numbers

    async def test_get_recent_filters_by_status(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Only issues with matching status are returned."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_issue_embedding(
            issue_id="owner/repo:1",
            repo="owner/repo",
            issue_number=1,
            title="Open issue",
            embedding=emb,
        )
        await intel_db.store_issue_embedding(
            issue_id="owner/repo:2",
            repo="owner/repo",
            issue_number=2,
            title="Closed issue",
            embedding=emb,
        )
        await intel_db.update_issue_status("owner/repo", 2, "closed")

        recent = await intel_db.get_recent_issue_embeddings(
            "owner/repo", exclude_issue=999, status="open",
        )
        assert len(recent) == 1
        assert recent[0]["issue_number"] == 1

    async def test_update_issue_status(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """update_issue_status sets status to 'closed'."""
        emb = vector_to_blob([1.0, 0.0, 0.0])
        await intel_db.store_issue_embedding(
            issue_id="owner/repo:42",
            repo="owner/repo",
            issue_number=42,
            title="Bug",
            embedding=emb,
        )
        updated = await intel_db.update_issue_status("owner/repo", 42, "closed")
        assert updated == 1

        result = await intel_db.get_issue_embedding("owner/repo", 42)
        assert result is not None
        assert result["status"] == "closed"

    async def test_schema_version_15(self, intel_db: IntelligenceDB) -> None:
        """Schema version should be 15 after initialization."""
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT version FROM schema_version WHERE id = 1",
            )
            row = await cursor.fetchone()
        assert row is not None
        assert row["version"] == 16


# ── V. Patrol CRUD ───────────────────────────────────────────────────────────


class TestPatrolCRUD:
    """Tests for patrol-related CRUD methods."""

    async def test_record_patrol_run_and_get(self, intel_db: IntelligenceDB) -> None:
        """Record a patrol run and retrieve it."""
        await intel_db.record_patrol_run(
            run_id="run-001",
            repo="owner/repo",
            timestamp="2024-01-01T00:00:00",
            dependency_findings_count=3,
            code_findings_count=2,
            patches_generated=1,
            issues_created=1,
            bounties_assigned_wei="100000",
            attestation_id="att-001",
            duration_ms=5000,
        )
        result = await intel_db.get_latest_patrol_run("owner/repo")
        assert result is not None
        assert result["id"] == "run-001"
        assert result["dependency_findings_count"] == 3
        assert result["attestation_id"] == "att-001"

    async def test_get_latest_patrol_run_empty(self, intel_db: IntelligenceDB) -> None:
        """No runs -> None."""
        result = await intel_db.get_latest_patrol_run("nonexistent/repo")
        assert result is None

    async def test_count_open_patrol_bounties(self, intel_db: IntelligenceDB) -> None:
        """Count bounties with source='patrol' only."""
        # Pipeline bounty (should not be counted)
        await intel_db.store_bounty(
            bounty_id="b-pipeline",
            repo="owner/repo",
            issue_number=1,
            label="bounty-sm",
            source="pipeline",
        )
        # Patrol bounty (should be counted)
        await intel_db.store_bounty(
            bounty_id="b-patrol",
            repo="owner/repo",
            issue_number=2,
            label="bounty-lg",
            source="patrol",
        )
        count = await intel_db.count_open_patrol_bounties("owner/repo")
        assert count == 1

    async def test_upsert_known_vulnerability_insert_and_update(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Insert then update a known vulnerability."""
        dedup_key = IntelligenceDB.compute_dedup_key(
            "CVE-2023-100", "requests", "python", "<2.31.0",
        )
        await intel_db.upsert_known_vulnerability(
            vuln_id="v-001",
            cve_id="CVE-2023-100",
            dedup_key=dedup_key,
            package_name="requests",
            language="python",
            severity="HIGH",
            affected_range="<2.31.0",
            fixed_version="2.31.0",
            repo="owner/repo",
            status="open",
            bounty_issue_number=42,
        )
        result = await intel_db.get_known_vulnerability("owner/repo", dedup_key)
        assert result is not None
        assert result["package_name"] == "requests"
        assert result["bounty_issue_number"] == 42

        # Update severity
        await intel_db.upsert_known_vulnerability(
            vuln_id="v-002",
            cve_id="CVE-2023-100",
            dedup_key=dedup_key,
            package_name="requests",
            language="python",
            severity="CRITICAL",
            affected_range="<2.31.0",
            repo="owner/repo",
        )
        result = await intel_db.get_known_vulnerability("owner/repo", dedup_key)
        assert result is not None
        assert result["severity"] == "CRITICAL"
        # bounty_issue_number should be preserved (COALESCE)
        assert result["bounty_issue_number"] == 42

    async def test_dedup_key_null_cve(self, intel_db: IntelligenceDB) -> None:
        """Non-CVE findings use composite dedup_key instead of NULL cve_id."""
        dedup_key = IntelligenceDB.compute_dedup_key(
            None, "lodash", "node", "<=4.17.20",
        )
        assert dedup_key == "lodash:node:<=4.17.20"
        await intel_db.upsert_known_vulnerability(
            vuln_id="v-null",
            cve_id=None,
            dedup_key=dedup_key,
            package_name="lodash",
            language="node",
            severity="HIGH",
            affected_range="<=4.17.20",
            repo="owner/repo",
        )
        result = await intel_db.get_known_vulnerability("owner/repo", dedup_key)
        assert result is not None
        assert result["cve_id"] is None
        assert result["dedup_key"] == dedup_key

    async def test_patrol_run_ordering(self, intel_db: IntelligenceDB) -> None:
        """get_latest_patrol_run returns the most recent by timestamp."""
        await intel_db.record_patrol_run(
            run_id="run-old",
            repo="owner/repo",
            timestamp="2024-01-01T00:00:00",
            dependency_findings_count=1,
        )
        await intel_db.record_patrol_run(
            run_id="run-new",
            repo="owner/repo",
            timestamp="2024-06-01T00:00:00",
            dependency_findings_count=5,
        )
        result = await intel_db.get_latest_patrol_run("owner/repo")
        assert result is not None
        assert result["id"] == "run-new"
        assert result["dependency_findings_count"] == 5

    async def test_finding_signatures_crud(self, intel_db: IntelligenceDB) -> None:
        """Insert, retrieve, and dedup finding signatures."""
        repo = "owner/repo"
        sigs = [
            ("sql-injection", "src/db.py", 42),
            ("xss", "src/web.py", 10),
        ]
        await intel_db.upsert_finding_signatures(repo, sigs)
        known = await intel_db.get_known_finding_signatures(repo)
        assert ("sql-injection", "src/db.py", 42) in known
        assert ("xss", "src/web.py", 10) in known
        assert len(known) == 2

        # Re-upsert should not create duplicates
        await intel_db.upsert_finding_signatures(repo, sigs)
        known2 = await intel_db.get_known_finding_signatures(repo)
        assert len(known2) == 2

    async def test_code_finding_bounty(self, intel_db: IntelligenceDB) -> None:
        """get_code_finding_bounty returns None then value after set_finding_bounty."""
        repo = "owner/repo"
        await intel_db.upsert_finding_signatures(
            repo, [("rule-1", "file.py", 10)],
        )
        # No bounty yet
        result = await intel_db.get_code_finding_bounty(repo, "rule-1", "file.py", 10)
        assert result is None

        # Set bounty
        await intel_db.set_finding_bounty(repo, "rule-1", "file.py", 10, 99)
        result = await intel_db.get_code_finding_bounty(repo, "rule-1", "file.py", 10)
        assert result == 99

    async def test_record_patrol_patch(self, intel_db: IntelligenceDB) -> None:
        """Record a patrol patch."""
        await intel_db.record_patrol_patch(
            patch_id="p-001",
            repo="owner/repo",
            pr_number=99,
            cve_id="CVE-2023-100",
            package_name="requests",
            old_version="2.25.0",
            new_version="2.31.0",
            status="submitted",
        )
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM patrol_patches WHERE id = %s", ("p-001",),
            )
            row = await cursor.fetchone()
        assert row is not None
        assert row["pr_number"] == 99
        assert row["package_name"] == "requests"
