"""Tests for intelligence database, sealing, similarity, and pattern extraction."""

from __future__ import annotations

from unittest.mock import AsyncMock

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


@pytest.fixture()
async def intel_db(tmp_path, monkeypatch):
    """Provide a fresh IntelligenceDB backed by a tmp_path SQLite file."""
    monkeypatch.setattr("src.intelligence.database.DB_PATH", tmp_path / "test.db")
    kms = AsyncMock()
    kms.unseal = AsyncMock(side_effect=Exception("no sealed data"))
    db = IntelligenceDB(kms=kms)
    await db.initialize()
    yield db
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
        """All 10 expected tables should be present."""
        expected = {
            "schema_version", "vulnerability_patterns", "contributor_profiles",
            "codebase_knowledge", "pipeline_history", "attestation_store",
            "active_bounties", "verification_windows", "pr_embeddings",
            "vision_documents",
        }
        db = intel_db._require_db()
        async with db.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        ) as cursor:
            rows = await cursor.fetchall()
            tables = {row[0] for row in rows}
        assert expected <= tables

    async def test_idempotent_reinit_closes_old_connection(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Fix #5: Calling initialize() again closes the prior connection."""
        old_db = intel_db._db
        await intel_db.initialize()
        assert intel_db.initialized is True
        # The old connection object should no longer be the active one
        assert intel_db._db is not old_db
        count = await intel_db.count_patterns()
        assert count == 0

    async def test_schema_version_row(self, intel_db: IntelligenceDB) -> None:
        """schema_version table should have exactly one row with version 1."""
        db = intel_db._require_db()
        async with db.execute(
            "SELECT version FROM schema_version WHERE id = 1",
        ) as cursor:
            row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 1


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
        db = intel_db._require_db()
        async with db.execute(
            "SELECT COUNT(*) FROM pipeline_history",
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == 1

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
        db = intel_db._require_db()
        async with db.execute(
            "SELECT total_submissions, approved_submissions "
            "FROM contributor_profiles WHERE github_login = ?",
            ("dev-alice",),
        ) as cursor:
            row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 1  # total
        assert row[1] == 1  # approved

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
        db = intel_db._require_db()
        async with db.execute(
            "SELECT times_seen FROM vulnerability_patterns",
        ) as cursor:
            row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 3

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
        db = intel_db._require_db()
        await db.execute(
            """\
            INSERT INTO vulnerability_patterns
                (id, rule_id, severity, category, normalized_pattern,
                 pattern_signature, confidence, times_seen, first_seen, last_seen,
                 source_stage, confirmed_true_positive, confirmed_false_positive)
            VALUES ('fp1', 'noisy-rule', 'LOW', 'lint', 'pattern', 'sig1',
                    0.5, 10, '2024-01-01', '2024-01-01', 'static_scanner', 1, 9)
            """,
        )
        await db.commit()

        result = await intel_db.get_false_positive_signatures()
        # Should return rule_id, not internal UUID
        assert "noisy-rule" in result
        assert "fp1" not in result

    async def test_excludes_low_fp_rules(self, intel_db: IntelligenceDB) -> None:
        """Patterns with <=80% FP rate should NOT be returned."""
        db = intel_db._require_db()
        await db.execute(
            """\
            INSERT INTO vulnerability_patterns
                (id, rule_id, severity, category, normalized_pattern,
                 pattern_signature, confidence, times_seen, first_seen, last_seen,
                 source_stage, confirmed_true_positive, confirmed_false_positive)
            VALUES ('good1', 'good-rule', 'HIGH', 'security', 'pattern', 'sig2',
                    0.9, 10, '2024-01-01', '2024-01-01', 'static_scanner', 8, 2)
            """,
        )
        await db.commit()

        result = await intel_db.get_false_positive_signatures()
        assert "good-rule" not in result


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
        db = intel_db._require_db()
        # Insert history rows directly (bypass contributor_profiles)
        for i in range(5):
            decision = "approve" if i < 3 else "reject"
            verdict = f'{{"decision": "{decision}", "composite_score": 0.5}}'
            await db.execute(
                """\
                INSERT INTO pipeline_history
                    (id, pr_id, repo, pr_author, verdict,
                     composite_score, findings_count, created_at)
                VALUES (?, ?, 'owner/repo', 'fallback-dev', ?, 0.5, 0, '2024-01-01')
                """,
                (f"h{i}", f"pr#{i}", verdict),
            )
        await db.commit()

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
# H. Seal lifecycle
# ═══════════════════════════════════════════════════════════════════════════════


class TestSealLifecycle:
    """Test seal/close operations."""

    async def test_seal_calls_kms_and_cleans_plaintext(
        self, intel_db: IntelligenceDB, tmp_path,
    ) -> None:
        """After seal, plaintext DB file is removed."""
        import src.intelligence.database as db_mod

        # Access the monkeypatched path via the module attribute (not import)
        test_db_path = db_mod.DB_PATH
        assert test_db_path.exists(), "DB file should exist before seal"

        kms = AsyncMock()
        kms.seal = AsyncMock()
        await intel_db.seal(kms)
        kms.seal.assert_awaited_once()
        assert intel_db.initialized is False
        assert not test_db_path.exists()

    async def test_seal_kms_failure_still_uninitializes(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Fix #4: Even if KMS seal fails, DB is marked uninitialized."""
        kms = AsyncMock()
        kms.seal = AsyncMock(side_effect=RuntimeError("KMS down"))
        await intel_db.seal(kms)
        assert intel_db.initialized is False

    async def test_close_sets_uninitialized(
        self, intel_db: IntelligenceDB,
    ) -> None:
        assert intel_db.initialized is True
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
        db = intel_db._require_db()
        async with db.execute(
            "SELECT COUNT(*) FROM pr_embeddings",
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == 1

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

    async def test_count_patterns_raises_before_init(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            "src.intelligence.database.DB_PATH", tmp_path / "test.db",
        )
        kms = AsyncMock()
        db = IntelligenceDB(kms=kms)
        # Do NOT call initialize()
        with pytest.raises(RuntimeError, match="not initialized"):
            await db.count_patterns()

    async def test_require_db_returns_connection(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """After initialize(), _require_db returns a live connection."""
        conn = intel_db._require_db()
        assert conn is not None


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
        db = intel_db._require_db()
        async with db.execute(
            "SELECT id FROM vulnerability_patterns LIMIT 1",
        ) as cursor:
            row = await cursor.fetchone()
        pat_id = row[0]

        await intel_db.record_verdict_feedback(pat_id, is_true_positive=True)

        async with db.execute(
            "SELECT confirmed_true_positive, confirmed_false_positive "
            "FROM vulnerability_patterns WHERE id = ?",
            (pat_id,),
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == 1  # TP incremented
        assert row[1] == 0  # FP unchanged

    async def test_record_false_positive(self, intel_db: IntelligenceDB) -> None:
        await intel_db.ingest_pipeline_results(
            pr_id="owner/repo#1",
            repo="owner/repo",
            static_findings=_make_static_findings()[:1],
            ai_findings=[],
            verdict=_make_verdict(),
        )
        db = intel_db._require_db()
        async with db.execute(
            "SELECT id FROM vulnerability_patterns LIMIT 1",
        ) as cursor:
            row = await cursor.fetchone()
        pat_id = row[0]

        await intel_db.record_verdict_feedback(pat_id, is_true_positive=False)

        async with db.execute(
            "SELECT confirmed_true_positive, confirmed_false_positive "
            "FROM vulnerability_patterns WHERE id = ?",
            (pat_id,),
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == 0  # TP unchanged
        assert row[1] == 1  # FP incremented

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
        db = intel_db._require_db()
        async with db.execute(
            "SELECT id, rule_id FROM vulnerability_patterns LIMIT 1",
        ) as cursor:
            row = await cursor.fetchone()
        pat_id = row[0]
        rule_id = row[1]

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
            attestation_id="attest-1",
            window_hours=24,
            opens_at="2024-01-01T00:00:00",
            closes_at="2024-01-02T00:00:00",
        )
        db = intel_db._require_db()
        async with db.execute(
            "SELECT COUNT(*) FROM verification_windows",
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == 1

    async def test_record_challenge(self, intel_db: IntelligenceDB) -> None:
        await intel_db.store_verification_window(
            window_id="vw1",
            pr_id="owner/repo#1",
            repo="owner/repo",
            attestation_id="attest-1",
            window_hours=24,
            opens_at="2024-01-01T00:00:00",
            closes_at="2024-01-02T00:00:00",
        )
        await intel_db.record_challenge("vw1")
        db = intel_db._require_db()
        async with db.execute(
            "SELECT challenges FROM verification_windows WHERE id = 'vw1'",
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == 1

    async def test_store_codebase_knowledge(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.store_codebase_knowledge(
            knowledge_id="ck1",
            repo="owner/repo",
            file_path="src/main.py",
            knowledge="Entry point for the application",
        )
        db = intel_db._require_db()
        async with db.execute(
            "SELECT knowledge FROM codebase_knowledge WHERE id = 'ck1'",
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == "Entry point for the application"

    async def test_store_vision_document(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.store_vision_document(
            doc_id="vd1",
            repo="owner/repo",
            content="The project aims to...",
        )
        db = intel_db._require_db()
        async with db.execute(
            "SELECT content FROM vision_documents WHERE id = 'vd1'",
        ) as cursor:
            row = await cursor.fetchone()
        assert row[0] == "The project aims to..."
