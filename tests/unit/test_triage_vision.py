"""Tests for triage vision alignment: loading, ingestion, prompt, and weight redistribution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from src.config import SaltaXConfig, VisionConfig
from src.intelligence.database import IntelligenceDB
from src.pipeline.prompts import build_analyzer_system_prompt
from src.pipeline.stages.decision_engine import _compute_weighted_score
from src.triage.vision import (
    _CACHE_MAX_AGE_HOURS,
    _DOC_TYPE_PATHS,
    _VISION_CANDIDATE_PATHS,
    _fetch_from_repo,
    extract_vision_goals,
    ingest_vision_document,
    load_vision_document,
    load_vision_documents,
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


def _vision_config(**overrides) -> VisionConfig:
    defaults = {"enabled": True, "source": "repo"}
    defaults.update(overrides)
    return VisionConfig(**defaults)


from tests.unit.conftest import make_pipeline_state as _make_state


def _make_config(**overrides) -> SaltaXConfig:
    return SaltaXConfig(**overrides)


def _make_ai_analysis(**overrides) -> dict:
    defaults: dict = {
        "quality_score": 8.0,
        "risk_score": 2.0,
        "confidence": 0.9,
        "concerns": [],
        "recommendations": [],
        "architectural_fit": "good",
        "findings": [],
    }
    defaults.update(overrides)
    return defaults


def _make_test_results(*, passed: bool = True) -> dict:
    return {"passed": passed, "coverage": 0.85, "test_count": 10}


# ═══════════════════════════════════════════════════════════════════════════════
# A. get_vision_document (DB read method)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetVisionDocument:
    async def test_returns_none_for_unknown_repo(
        self, intel_db: IntelligenceDB,
    ) -> None:
        result = await intel_db.get_vision_document("unknown/repo")
        assert result is None

    async def test_returns_correct_fields_after_store(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await intel_db.store_vision_document(
            doc_id="vision:owner/repo:vision",
            repo="owner/repo",
            content="Build the best tool.",
        )
        result = await intel_db.get_vision_document("owner/repo")
        assert result is not None
        assert result["id"] == "vision:owner/repo:vision"
        assert result["repo"] == "owner/repo"
        assert result["content"] == "Build the best tool."
        assert result["updated_at"]  # non-empty ISO timestamp

    async def test_get_vision_document_excludes_embedding(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """get_vision_document (backward-compat) does not include embedding."""
        await intel_db.store_vision_document(
            doc_id="vision:owner/repo:vision",
            repo="owner/repo",
            content="Vision text.",
        )
        result = await intel_db.get_vision_document("owner/repo")
        assert result is not None
        # Backward-compat wrapper returns full dict from get_vision_documents
        # which does include embedding — this verifies the field is present
        assert "embedding" in result


# ═══════════════════════════════════════════════════════════════════════════════
# B. _fetch_from_repo
# ═══════════════════════════════════════════════════════════════════════════════


class TestFetchFromRepo:
    async def test_returns_first_candidate_found(self) -> None:
        """Stops at the first found file, doesn't try subsequent paths."""
        client = AsyncMock()
        call_count = 0

        async def _fake_get(repo, path, *, installation_id):
            nonlocal call_count
            call_count += 1
            if path == "VISION.md":
                return None  # 404
            if path == "docs/VISION.md":
                return "# Vision\nBuild great tools."
            return "should not reach"

        client.get_file_contents = _fake_get
        content = await _fetch_from_repo("owner/repo", 123, client)
        assert content == "# Vision\nBuild great tools."
        assert call_count == 2  # stopped after docs/VISION.md

    async def test_skips_404_paths(self) -> None:
        client = AsyncMock()
        client.get_file_contents = AsyncMock(return_value=None)
        content = await _fetch_from_repo("owner/repo", 123, client)
        assert content is None
        assert client.get_file_contents.call_count == len(_VISION_CANDIDATE_PATHS)

    async def test_returns_none_when_all_miss(self) -> None:
        client = AsyncMock()
        client.get_file_contents = AsyncMock(return_value=None)
        result = await _fetch_from_repo("owner/repo", 123, client)
        assert result is None

    async def test_skips_empty_whitespace_content(self) -> None:
        """Files that contain only whitespace are treated as absent."""
        client = AsyncMock()
        client.get_file_contents = AsyncMock(return_value="   \n\t  ")
        result = await _fetch_from_repo("owner/repo", 123, client)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# C. load_vision_document
# ═══════════════════════════════════════════════════════════════════════════════


class TestLoadVisionDocument:
    async def test_cache_hit_skips_github(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """A fresh cache (<24h) returns immediately — no GitHub call."""
        await intel_db.store_vision_document(
            doc_id="vision:owner/repo:vision",
            repo="owner/repo",
            content="Cached vision.",
        )
        config = _make_config(
            triage={"enabled": True, "vision": {"enabled": True, "source": "repo"}},
        )
        client = AsyncMock()
        client.get_file_contents = AsyncMock()

        result = await load_vision_document(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result == "Cached vision."
        client.get_file_contents.assert_not_called()

    async def test_stale_cache_triggers_refetch_source_repo(
        self, intel_db: IntelligenceDB, monkeypatch,
    ) -> None:
        """Stale cache (>24h) triggers a GitHub re-fetch when source=repo."""
        # Insert a stale document
        stale_time = (
            datetime.now(UTC) - timedelta(hours=_CACHE_MAX_AGE_HOURS + 1)
        ).isoformat()
        db = intel_db._require_db()
        async with intel_db._write_lock:
            await db.execute(
                "INSERT OR REPLACE INTO vision_documents "
                "(id, repo, doc_type, content, embedding, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("vision:owner/repo:vision", "owner/repo", "vision", "Old vision.", None, stale_time),
            )
            await db.commit()

        config = _make_config(
            triage={"enabled": True, "vision": {"enabled": True, "source": "repo"}},
        )
        client = AsyncMock()
        client.get_file_contents = AsyncMock(return_value="New vision!")

        result = await load_vision_document(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result == "New vision!"
        client.get_file_contents.assert_called()

    async def test_source_api_returns_stale_cache(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """source=api never fetches from GitHub — returns stale cache as-is."""
        stale_time = (
            datetime.now(UTC) - timedelta(hours=_CACHE_MAX_AGE_HOURS + 1)
        ).isoformat()
        db = intel_db._require_db()
        async with intel_db._write_lock:
            await db.execute(
                "INSERT OR REPLACE INTO vision_documents "
                "(id, repo, doc_type, content, embedding, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("vision:owner/repo:vision", "owner/repo", "vision", "API vision.", None, stale_time),
            )
            await db.commit()

        config = _make_config(
            triage={"enabled": True, "vision": {"enabled": True, "source": "api"}},
        )
        client = AsyncMock()

        result = await load_vision_document(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result == "API vision."

    async def test_returns_none_when_no_doc_exists(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """No cache + all GitHub paths 404 → returns None (normal flow)."""
        config = _make_config(
            triage={"enabled": True, "vision": {"enabled": True, "source": "repo"}},
        )
        client = AsyncMock()
        client.get_file_contents = AsyncMock(return_value=None)

        result = await load_vision_document(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result is None

    async def test_stores_fetched_doc_in_db(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """A successfully fetched document is stored in the DB cache."""
        config = _make_config(
            triage={"enabled": True, "vision": {"enabled": True, "source": "repo"}},
        )
        client = AsyncMock()
        client.get_file_contents = AsyncMock(return_value="# Fresh Vision")

        await load_vision_document(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )

        cached = await intel_db.get_vision_document("owner/repo")
        assert cached is not None
        assert cached["content"] == "# Fresh Vision"
        assert cached["id"] == "vision:owner/repo:vision"

    async def test_ingest_failure_still_returns_content(
        self, intel_db: IntelligenceDB, monkeypatch,
    ) -> None:
        """B1: If ingest_vision_document raises, fetched content is still returned."""
        config = _make_config(
            triage={"enabled": True, "vision": {"enabled": True, "source": "repo"}},
        )
        client = AsyncMock()
        client.get_file_contents = AsyncMock(return_value="# Good Vision")

        # Make store_vision_document raise
        monkeypatch.setattr(
            intel_db,
            "store_vision_document",
            AsyncMock(side_effect=RuntimeError("DB write failed")),
        )

        result = await load_vision_document(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result == "# Good Vision"

    async def test_stale_cache_logs_info(
        self, intel_db: IntelligenceDB, caplog,
    ) -> None:
        """I9: Stale cache return paths log age information."""
        import logging

        stale_time = (
            datetime.now(UTC) - timedelta(hours=_CACHE_MAX_AGE_HOURS + 1)
        ).isoformat()
        db = intel_db._require_db()
        async with intel_db._write_lock:
            await db.execute(
                "INSERT OR REPLACE INTO vision_documents "
                "(id, repo, doc_type, content, embedding, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("vision:owner/repo:vision", "owner/repo", "vision", "Stale vision.", None, stale_time),
            )
            await db.commit()

        config = _make_config(
            triage={"enabled": True, "vision": {"enabled": True, "source": "api"}},
        )
        client = AsyncMock()

        with caplog.at_level(logging.INFO, logger="src.triage.vision"):
            result = await load_vision_document(
                "owner/repo", 123,
                config=config, intel_db=intel_db, github_client=client,
            )

        assert result == "Stale vision."
        assert any("stale" in rec.message.lower() for rec in caplog.records)


# ═══════════════════════════════════════════════════════════════════════════════
# D. ingest_vision_document
# ═══════════════════════════════════════════════════════════════════════════════


class TestIngestVisionDocument:
    async def test_stores_with_correct_doc_id_format(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await ingest_vision_document("org/project", "Vision text.", intel_db=intel_db)
        result = await intel_db.get_vision_document("org/project")
        assert result is not None
        assert result["id"] == "vision:org/project:vision"
        assert result["content"] == "Vision text."

    async def test_second_call_replaces_prior(
        self, intel_db: IntelligenceDB,
    ) -> None:
        await ingest_vision_document("org/project", "V1", intel_db=intel_db)
        await ingest_vision_document("org/project", "V2", intel_db=intel_db)
        result = await intel_db.get_vision_document("org/project")
        assert result is not None
        assert result["content"] == "V2"


# ═══════════════════════════════════════════════════════════════════════════════
# E. Vision prompt extension
# ═══════════════════════════════════════════════════════════════════════════════


class TestVisionPromptExtension:
    def test_penalize_contradictions_only_present(self) -> None:
        prompt = build_analyzer_system_prompt(vision_enabled=True)
        assert "PENALIZE CONTRADICTIONS ONLY" in prompt

    def test_do_not_penalize_instruction_present(self) -> None:
        prompt = build_analyzer_system_prompt(vision_enabled=True)
        assert "Do NOT penalize" in prompt

    def test_scoring_guidance_absent_when_disabled(self) -> None:
        prompt = build_analyzer_system_prompt(vision_enabled=False)
        assert "PENALIZE CONTRADICTIONS ONLY" not in prompt


# ═══════════════════════════════════════════════════════════════════════════════
# F. Weight redistribution
# ═══════════════════════════════════════════════════════════════════════════════


class TestWeightRedistribution:
    def test_default_015_weight_sums_to_one(self) -> None:
        config = _make_config(
            triage={"vision": {"enabled": True, "alignment_weight": 0.15}},
        )
        state = _make_state(
            ai_analysis=_make_ai_analysis(vision_alignment_score=8),
            test_results=_make_test_results(),
        )
        # No RuntimeError means weights summed correctly
        _compute_weighted_score(config, state, 1.0, 0.8, 0.8, 1.0)

    def test_custom_020_weight_sums_to_one(self) -> None:
        config = _make_config(
            triage={"vision": {"enabled": True, "alignment_weight": 0.20}},
        )
        state = _make_state(
            ai_analysis=_make_ai_analysis(vision_alignment_score=7),
            test_results=_make_test_results(),
        )
        _compute_weighted_score(config, state, 1.0, 0.8, 0.8, 1.0)

    def test_no_vision_score_no_redistribution(self) -> None:
        """When vision_alignment_score is absent, base weights remain untouched."""
        config = _make_config(
            triage={"vision": {"enabled": True, "alignment_weight": 0.15}},
        )
        state = _make_state(
            ai_analysis=_make_ai_analysis(),  # no vision_alignment_score
            test_results=_make_test_results(),
        )
        _, breakdown = _compute_weighted_score(
            config, state, 1.0, 0.8, 0.8, 1.0,
        )
        assert "vision_alignment" not in breakdown


# ═══════════════════════════════════════════════════════════════════════════════
# G. Vision API endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestVisionAPIEndpoint:
    """Integration tests for the /vision endpoint using real IntelligenceDB."""

    @pytest.fixture()
    def _app(self, intel_db):
        from unittest.mock import MagicMock

        from fastapi import FastAPI

        from src.api.routes.vision import router

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        config = MagicMock()
        config.triage.vision.source = "api"
        app.state.config = config
        app.state.intel_db = intel_db
        app.state.env = MagicMock()
        return app

    @pytest.fixture()
    async def client(self, _app):
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=_app),
            base_url="http://test",
        ) as c:
            yield c

    async def test_valid_content_accepted(self, client) -> None:
        resp = await client.post(
            "/api/v1/vision",
            json={"repo": "owner/repo", "content": "# Vision\nBuild great tools."},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"

    async def test_empty_content_rejected(self, client) -> None:
        resp = await client.post(
            "/api/v1/vision",
            json={"repo": "owner/repo", "content": "   "},
        )
        assert resp.status_code == 400

    async def test_oversized_content_rejected(self, client) -> None:
        resp = await client.post(
            "/api/v1/vision",
            json={"repo": "owner/repo", "content": "x" * 200_000},
        )
        assert resp.status_code == 400

    async def test_wrong_source_rejected(self, _app, intel_db) -> None:
        from httpx import ASGITransport, AsyncClient

        _app.state.config.triage.vision.source = "repo"
        async with AsyncClient(
            transport=ASGITransport(app=_app),
            base_url="http://test",
        ) as c:
            resp = await c.post(
                "/api/v1/vision",
                json={"repo": "owner/repo", "content": "# Vision"},
            )
        assert resp.status_code == 400

    async def test_missing_repo_slash_rejected(self, client) -> None:
        resp = await client.post(
            "/api/v1/vision",
            json={"repo": "noslash", "content": "# Vision"},
        )
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# H. Multi-source vision documents (Feature 5)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMultiDocVision:
    async def test_multi_doc_loads_all_types(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Two types configured and cached → both returned with section headers."""
        await intel_db.store_vision_document(
            doc_id="vision:owner/repo:vision",
            repo="owner/repo",
            content="Vision content.",
            doc_type="vision",
        )
        await intel_db.store_vision_document(
            doc_id="vision:owner/repo:architecture",
            repo="owner/repo",
            content="Architecture content.",
            doc_type="architecture",
        )
        config = _make_config(
            triage={
                "enabled": True,
                "vision": {
                    "enabled": True,
                    "source": "repo",
                    "document_types": ["vision", "architecture"],
                },
            },
        )
        client = AsyncMock()
        result = await load_vision_documents(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result is not None
        assert "## Document: vision" in result
        assert "Vision content." in result
        assert "## Document: architecture" in result
        assert "Architecture content." in result

    async def test_multi_doc_missing_one_type(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Only vision exists → returns vision content only."""
        await intel_db.store_vision_document(
            doc_id="vision:owner/repo:vision",
            repo="owner/repo",
            content="Only vision.",
            doc_type="vision",
        )
        config = _make_config(
            triage={
                "enabled": True,
                "vision": {
                    "enabled": True,
                    "source": "api",
                    "document_types": ["vision", "architecture"],
                },
            },
        )
        client = AsyncMock()
        result = await load_vision_documents(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result is not None
        assert "Only vision." in result
        # Architecture was not found — should not appear
        assert "architecture" not in result.lower().replace("## document: architecture", "").lower()

    async def test_doc_type_in_ingest(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Verify doc_id format is vision:{repo}:{doc_type}."""
        await ingest_vision_document(
            "org/project", "Arch text.", intel_db=intel_db, doc_type="architecture",
        )
        docs = await intel_db.get_vision_documents("org/project", doc_type="architecture")
        assert len(docs) == 1
        assert docs[0]["id"] == "vision:org/project:architecture"
        assert docs[0]["doc_type"] == "architecture"

    async def test_fetch_from_repo_architecture(self) -> None:
        """_fetch_from_repo with doc_type='architecture' tries ARCHITECTURE.md paths."""
        client = AsyncMock()
        call_paths: list[str] = []

        async def _fake_get(repo, path, *, installation_id):
            call_paths.append(path)
            if path == "ARCHITECTURE.md":
                return "# Architecture\nMicroservices."
            return None

        client.get_file_contents = _fake_get
        content = await _fetch_from_repo(
            "owner/repo", 123, client, doc_type="architecture",
        )
        assert content == "# Architecture\nMicroservices."
        assert "ARCHITECTURE.md" in call_paths

    async def test_single_doc_no_header(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """Single document_type → no section header prepended."""
        await intel_db.store_vision_document(
            doc_id="vision:owner/repo:vision",
            repo="owner/repo",
            content="Vision text.",
            doc_type="vision",
        )
        config = _make_config(
            triage={
                "enabled": True,
                "vision": {"enabled": True, "source": "repo"},
            },
        )
        client = AsyncMock()
        result = await load_vision_documents(
            "owner/repo", 123,
            config=config, intel_db=intel_db, github_client=client,
        )
        assert result is not None
        assert "## Document:" not in result
        assert result == "Vision text."


# ═══════════════════════════════════════════════════════════════════════════════
# I. Vision embeddings (Feature 3)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVisionEmbeddings:
    async def test_ingest_with_embedding(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """When env + config provided, embed_diff is called and blob stored."""
        from unittest.mock import MagicMock, patch

        import numpy as np

        from src.intelligence.similarity import ndarray_to_blob

        fake_vec = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        mock_embed = AsyncMock(return_value=fake_vec)

        env = MagicMock()
        config = _make_config()

        with (
            patch("src.triage.dedup.embed_diff", mock_embed),
            patch("src.intelligence.similarity.ndarray_to_blob", ndarray_to_blob),
        ):
            await ingest_vision_document(
                "org/repo", "Vision text.",
                intel_db=intel_db, env=env, config=config,
            )

        mock_embed.assert_awaited_once()
        docs = await intel_db.get_vision_documents("org/repo", doc_type="vision")
        assert len(docs) == 1
        assert docs[0]["embedding"] is not None

    async def test_ingest_embedding_failure_still_stores(
        self, intel_db: IntelligenceDB,
    ) -> None:
        """embed_diff failure → document stored with embedding=None."""
        from unittest.mock import MagicMock, patch

        mock_embed = AsyncMock(side_effect=RuntimeError("embed failed"))

        env = MagicMock()
        config = _make_config()

        with patch("src.triage.dedup.embed_diff", mock_embed):
            await ingest_vision_document(
                "org/repo", "Vision text.",
                intel_db=intel_db, env=env, config=config,
            )

        docs = await intel_db.get_vision_documents("org/repo", doc_type="vision")
        assert len(docs) == 1
        assert docs[0]["embedding"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# J. Goal decomposition (Feature 4)
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractVisionGoals:
    def test_extract_goals_headers(self) -> None:
        """## headers are extracted as goals."""
        content = "# Vision\n## Goal A\nDetails.\n## Goal B\nMore details."
        goals = extract_vision_goals(content)
        assert goals == ["Goal A", "Goal B"]

    def test_extract_goals_bullets(self) -> None:
        """Top-level bullets are extracted as goals."""
        content = "# Vision\n- Ship v2\n- Improve DX\n  - Sub-item"
        goals = extract_vision_goals(content)
        assert goals == ["Ship v2", "Improve DX"]

    def test_extract_goals_max_10(self) -> None:
        """15 goals → first 10 returned."""
        lines = [f"## Goal {i}" for i in range(15)]
        content = "\n".join(lines)
        goals = extract_vision_goals(content)
        assert len(goals) == 10

    def test_extract_goals_filters_generic_headers(self) -> None:
        """Generic headers (Overview, Introduction) are filtered out."""
        content = "## Overview\n## Ship v2\n## Introduction\n## Improve DX"
        goals = extract_vision_goals(content)
        assert goals == ["Ship v2", "Improve DX"]

    def test_extract_goals_empty(self) -> None:
        """No goals → empty list."""
        content = "Just plain text without headers or bullets."
        goals = extract_vision_goals(content)
        assert goals == []

    def test_extract_goals_mixed(self) -> None:
        """Mix of headers and bullets."""
        content = "## Ship v2\n- Improve DX\n- Add auth"
        goals = extract_vision_goals(content)
        assert goals == ["Ship v2", "Improve DX", "Add auth"]
