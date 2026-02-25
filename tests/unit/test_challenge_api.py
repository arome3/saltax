"""Tests for the challenge and verification window API routes."""

from __future__ import annotations

import os

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.api.routes.challenge import router
from src.intelligence.database import IntelligenceDB

_ = pytest  # ensure pytest is used (fixture injection)

_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)


# ── Helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture()
async def intel_db():
    """Provide a fresh IntelligenceDB backed by PostgreSQL."""
    db = IntelligenceDB(database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3)
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


def _make_app(*, scheduler: object, intel_db: object) -> FastAPI:
    """Create a minimal FastAPI app with the challenge router."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.state.scheduler = scheduler
    app.state.intel_db = intel_db
    return app


async def _store_window(
    intel_db: IntelligenceDB,
    *,
    window_id: str = "win-1",
    status: str = "open",
    bounty_amount_wei: str = "1000",
) -> None:
    now = datetime.now(UTC)
    await intel_db.store_verification_window(
        window_id=window_id,
        pr_id="owner/repo#1",
        repo="owner/repo",
        pr_number=1,
        installation_id=12345,
        attestation_id="attest-1",
        verdict_json='{"decision": "APPROVE"}',
        attestation_json="{}",
        contributor_address="0xcontrib",
        bounty_amount_wei=bounty_amount_wei,
        stake_amount_wei=bounty_amount_wei,
        window_hours=24,
        opens_at=now.isoformat(),
        closes_at=(now + timedelta(hours=24)).isoformat(),
    )
    if status != "open":
        await intel_db.transition_window_status(window_id, "open", status)


# ═══════════════════════════════════════════════════════════════════════════════
# A. File challenge endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestFileChallengeEndpoint:
    """POST /api/v1/challenges"""

    async def test_success(self) -> None:
        scheduler = AsyncMock()
        scheduler.file_challenge = AsyncMock(return_value=(True, "abc123def456"))
        app = _make_app(scheduler=scheduler, intel_db=AsyncMock())
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/challenges", json={
                "window_id": "win-1",
                "challenger_address": "0xchallenger",
                "stake_wei": 1000,
                "rationale": "I disagree",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["challenge_id"] == "abc123def456"

    async def test_invalid_window(self) -> None:
        scheduler = AsyncMock()
        scheduler.file_challenge = AsyncMock(
            return_value=(False, "Window not found"),
        )
        app = _make_app(scheduler=scheduler, intel_db=AsyncMock())
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/challenges", json={
                "window_id": "nonexistent",
                "challenger_address": "0xchallenger",
                "stake_wei": 1000,
                "rationale": "I disagree",
            })
        assert resp.status_code == 400
        assert resp.json()["success"] is False

    async def test_validation_error(self) -> None:
        scheduler = AsyncMock()
        app = _make_app(scheduler=scheduler, intel_db=AsyncMock())
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/challenges", json={
                "window_id": "win-1",
                # missing required fields
            })
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# B. Resolve challenge endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveChallengeEndpoint:
    """POST /api/v1/challenges/{window_id}/resolve"""

    async def test_upheld(self) -> None:
        scheduler = AsyncMock()
        scheduler.resolve_challenge = AsyncMock(return_value=(True, "ok"))
        app = _make_app(scheduler=scheduler, intel_db=AsyncMock())
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/challenges/win-1/resolve",
                json={"upheld": True},
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert "upheld" in resp.json()["message"]

    async def test_overturned(self) -> None:
        scheduler = AsyncMock()
        scheduler.resolve_challenge = AsyncMock(return_value=(True, "ok"))
        app = _make_app(scheduler=scheduler, intel_db=AsyncMock())
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/challenges/win-1/resolve",
                json={"upheld": False},
            )
        assert resp.status_code == 200
        assert "overturned" in resp.json()["message"]

    async def test_wrong_status(self) -> None:
        scheduler = AsyncMock()
        scheduler.resolve_challenge = AsyncMock(
            return_value=(False, "Window status is 'open', expected 'challenged'"),
        )
        app = _make_app(scheduler=scheduler, intel_db=AsyncMock())
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/challenges/win-1/resolve",
                json={"upheld": True},
            )
        assert resp.status_code == 400
        assert resp.json()["success"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# C. List windows endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestListWindowsEndpoint:
    """GET /api/v1/verification/windows"""

    async def test_list_all(self, intel_db) -> None:
        await _store_window(intel_db, window_id="win-1")
        await _store_window(intel_db, window_id="win-2")
        app = _make_app(scheduler=AsyncMock(), intel_db=intel_db)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/verification/windows")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        assert len(data["windows"]) == 2

    async def test_filter_by_status(self, intel_db) -> None:
        await _store_window(intel_db, window_id="win-open")
        await _store_window(intel_db, window_id="win-challenged", status="challenged")
        app = _make_app(scheduler=AsyncMock(), intel_db=intel_db)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/verification/windows?status=challenged")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["windows"][0]["status"] == "challenged"


# ═══════════════════════════════════════════════════════════════════════════════
# D. Get single window endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetWindowEndpoint:
    """GET /api/v1/verification/windows/{window_id}"""

    async def test_found(self, intel_db) -> None:
        await _store_window(intel_db, window_id="win-1")
        app = _make_app(scheduler=AsyncMock(), intel_db=intel_db)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/verification/windows/win-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "win-1"
        assert data["status"] == "open"

    async def test_not_found(self, intel_db) -> None:
        app = _make_app(scheduler=AsyncMock(), intel_db=intel_db)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/verification/windows/nonexistent")
        assert resp.status_code == 404
