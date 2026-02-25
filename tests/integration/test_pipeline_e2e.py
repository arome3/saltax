"""Integration tests: pipeline execution with real IntelligenceDB (Doc 27).

Pipeline stages are monkeypatched to return deterministic results, but the
IntelligenceDB is a real SQLite database on ``tmp_path``.  This validates that
ingestion (patterns, history, contributor profiles) actually persists rows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from src.config import SaltaXConfig
from src.pipeline.runner import Pipeline

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB
    from src.pipeline.state import PipelineState

_ = pytest  # ensure pytest is used (fixture injection)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _state_dict(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "pr_id": "owner/repo#42",
        "repo": "owner/repo",
        "repo_url": "https://github.com/owner/repo.git",
        "commit_sha": "abc12345deadbeef",
        "diff": "diff --git a/f.py b/f.py\n+pass",
        "base_branch": "main",
        "head_branch": "fix/stuff",
        "pr_author": "dev",
        "pr_number": 42,
        "installation_id": 1,
    }
    defaults.update(overrides)
    return defaults


async def _stage_noop(state: PipelineState, *_args: object, **_kw: object) -> None:
    """No-op stage that leaves state untouched."""


async def _stage_static_findings(
    state: PipelineState, *_args: object, **_kw: object,
) -> None:
    """Inject synthetic static findings."""
    state.static_findings = [
        {
            "rule_id": "sql-injection",
            "severity": "HIGH",
            "category": "security",
            "message": "SQL injection via f-string",
            "snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            "confidence": 0.95,
        },
    ]


async def _stage_static_critical(
    state: PipelineState, *_args: object, **_kw: object,
) -> None:
    """Inject a CRITICAL finding that triggers short-circuit."""
    state.static_findings = [
        {
            "rule_id": "hardcoded-secret",
            "severity": "CRITICAL",
            "category": "security",
            "message": "Hardcoded API key detected",
            "snippet": 'API_KEY = "sk-12345-secret"',
            "confidence": 0.99,
        },
    ]


async def _stage_approve(
    state: PipelineState, *_args: object, **_kw: object,
) -> None:
    """Set an APPROVE verdict with a high score."""
    state.verdict = {
        "decision": "APPROVE",
        "composite_score": 0.92,
        "threshold_used": 0.75,
        "findings_count": 0,
        "score_breakdown": {
            "static_clear": 1.0,
            "ai_quality": 0.90,
            "ai_security": 0.85,
            "tests_pass": 0.95,
        },
    }


async def _stage_reject(
    state: PipelineState, *_args: object, **_kw: object,
) -> None:
    """Set a REJECT verdict."""
    state.verdict = {
        "decision": "REJECT",
        "composite_score": 0.30,
        "threshold_used": 0.75,
        "findings_count": 1,
        "score_breakdown": {
            "static_clear": 0.0,
            "ai_quality": 0.5,
            "ai_security": 0.3,
            "tests_pass": 0.4,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPipelineIntegration:
    """Pipeline integration tests with real SQLite DB."""

    async def test_full_pipeline_approve_stored(
        self, mock_intel_db: IntelligenceDB, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """All stages pass → APPROVE verdict persisted in pipeline_history."""
        monkeypatch.setattr("src.pipeline.runner.run_static_scan", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_ai_analysis", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_tests", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_decision", _stage_approve)

        config = SaltaXConfig()
        env = AsyncMock()
        attestation = AsyncMock()

        pipeline = Pipeline(config, env, mock_intel_db, attestation)
        state = await pipeline.run(_state_dict())

        if state.verdict is None:
            raise RuntimeError("Expected verdict but got None")
        assert state.verdict["decision"] == "APPROVE"

        # Ingest results into real DB
        await mock_intel_db.ingest_pipeline_results(
            pr_id=state.pr_id,
            repo=state.repo,
            static_findings=state.static_findings,
            ai_findings=[],
            verdict=state.verdict,
            author=state.pr_author,
        )

        # Verify pipeline_history row was written
        async with mock_intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT pr_id, repo, verdict FROM pipeline_history WHERE pr_id = %s",
                (state.pr_id,),
            )
            row = await cursor.fetchone()

        if row is None:
            raise RuntimeError("Expected pipeline_history row but found none")
        assert row["pr_id"] == "owner/repo#42"
        assert row["repo"] == "owner/repo"
        assert "APPROVE" in row["verdict"]

    async def test_pipeline_reject_static_critical(
        self, mock_intel_db: IntelligenceDB, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CRITICAL static finding → short-circuit → REJECT verdict."""
        monkeypatch.setattr("src.pipeline.runner.run_static_scan", _stage_static_critical)
        monkeypatch.setattr("src.pipeline.runner.run_ai_analysis", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_tests", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_decision", _stage_reject)

        config = SaltaXConfig()
        env = AsyncMock()
        attestation = AsyncMock()

        pipeline = Pipeline(config, env, mock_intel_db, attestation)
        state = await pipeline.run(_state_dict())

        if state.verdict is None:
            raise RuntimeError("Expected verdict but got None")
        assert state.verdict["decision"] == "REJECT"
        assert state.short_circuit is True

    async def test_pipeline_ingests_patterns(
        self, mock_intel_db: IntelligenceDB, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After pipeline run, vulnerability_patterns table has rows."""
        monkeypatch.setattr("src.pipeline.runner.run_static_scan", _stage_static_findings)
        monkeypatch.setattr("src.pipeline.runner.run_ai_analysis", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_tests", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_decision", _stage_approve)

        config = SaltaXConfig()
        env = AsyncMock()
        attestation = AsyncMock()

        pipeline = Pipeline(config, env, mock_intel_db, attestation)
        state = await pipeline.run(_state_dict())

        # Ingest with real findings
        await mock_intel_db.ingest_pipeline_results(
            pr_id=state.pr_id,
            repo=state.repo,
            static_findings=state.static_findings,
            ai_findings=[],
            verdict=state.verdict or {},
            author=state.pr_author,
        )

        async with mock_intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM vulnerability_patterns",
            )
            row = await cursor.fetchone()

        assert row["count"] >= 1

    async def test_pipeline_updates_contributor_profile(
        self, mock_intel_db: IntelligenceDB, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After pipeline run, contributor_profiles row is created."""
        monkeypatch.setattr("src.pipeline.runner.run_static_scan", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_ai_analysis", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_tests", _stage_noop)
        monkeypatch.setattr("src.pipeline.runner.run_decision", _stage_approve)

        config = SaltaXConfig()
        env = AsyncMock()
        attestation = AsyncMock()

        pipeline = Pipeline(config, env, mock_intel_db, attestation)
        state = await pipeline.run(_state_dict(pr_author="alice"))

        await mock_intel_db.ingest_pipeline_results(
            pr_id=state.pr_id,
            repo=state.repo,
            static_findings=state.static_findings,
            ai_findings=[],
            verdict=state.verdict or {},
            author=state.pr_author,
        )

        async with mock_intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT github_login, total_submissions FROM contributor_profiles "
                "WHERE github_login = %s",
                ("alice",),
            )
            row = await cursor.fetchone()

        if row is None:
            raise RuntimeError("Expected contributor_profiles row but found none")
        assert row["github_login"] == "alice"
        assert row["total_submissions"] == 1
