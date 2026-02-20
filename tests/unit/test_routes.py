"""Unit tests for all new API route modules."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.api.routes.attestation import router as attestation_router
from src.api.routes.audit import router as audit_router
from src.api.routes.bounties import router as bounties_router
from src.api.routes.intelligence import router as intelligence_router
from src.api.routes.status import router as status_router
from src.api.routes.vision import router as vision_router


@pytest.fixture(autouse=True)
def _reset_audit_dedup(monkeypatch):
    """Give each test a fresh _AuditDedup (clean caches, fresh asyncio.Lock)."""
    from src.api.routes import audit

    monkeypatch.setattr(audit, "_audit_dedup", audit._AuditDedup())


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_app() -> FastAPI:
    """Create a minimal FastAPI app with all new routers and mocked state."""
    app = FastAPI()
    app.include_router(status_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(attestation_router, prefix="/api/v1")
    app.include_router(bounties_router, prefix="/api/v1")
    app.include_router(intelligence_router, prefix="/api/v1")
    app.include_router(vision_router, prefix="/api/v1")

    # Wire up mocked state
    config = MagicMock()
    config.agent.name = "SaltaX"
    config.version = "1.0"
    config.audit_pricing.security_only_usdc = 5.0
    config.audit_pricing.quality_only_usdc = 3.0
    config.audit_pricing.full_audit_usdc = 10.0
    config.triage.vision.source = "api"

    wallet = MagicMock()
    wallet.address = "0x" + "0" * 40

    identity = MagicMock()
    identity.agent_id = "saltax-agent-11155111"

    intel_db = AsyncMock()
    intel_db.count_patterns.return_value = 42
    intel_db.get_attestation.return_value = None
    intel_db.get_stats.return_value = {
        "total_patterns": 42,
        "category_distribution": {},
        "severity_distribution": {},
        "avg_false_positive_rate": 0.0,
        "patterns_last_7_days": 0,
        "top_contributing_repos": [],
    }
    intel_db.initialized = True

    pipeline = AsyncMock()
    pipeline.run.return_value = {}

    scheduler = MagicMock()
    scheduler.running = True

    app.state.config = config
    app.state.env = MagicMock()
    app.state.wallet = wallet
    app.state.intel_db = intel_db
    app.state.identity = identity
    app.state.scheduler = scheduler
    app.state.pipeline = pipeline
    app.state.github_client = AsyncMock()

    treasury_mgr = MagicMock()
    treasury_mgr.check_balance = AsyncMock(
        return_value=MagicMock(
            balance_wei=0,
            reserve_wei=0,
            bounty_wei=0,
        )
    )
    app.state.treasury_mgr = treasury_mgr

    # x402 payment verifier — returns valid by default for backward compat
    from src.api.middleware.x402 import PaymentRequirements, PaymentVerification

    payment_verifier = MagicMock()
    payment_verifier.build_requirements.return_value = PaymentRequirements(
        amount_atomic=10_000_000,
        resource="/api/v1/audit",
        description="SaltaX full audit",
        pay_to="0x" + "0" * 40,
    )
    payment_verifier.verify = AsyncMock(
        return_value=PaymentVerification(
            valid=True,
            amount_atomic=10_000_000,
            payer_address="0x" + "a" * 40,
            tx_hash="0x" + "b" * 64,
            payment_id="pay-mock-001",
            error="",
        )
    )
    app.state.payment_verifier = payment_verifier

    # Durable tx_hash replay protection — default: no duplicates seen
    tx_store = AsyncMock()
    tx_store.check_and_record = AsyncMock(return_value=False)
    app.state.tx_store = tx_store

    # Reputation manager — returns empty metrics by default
    from src.models.identity import ReputationMetrics

    reputation_mgr = AsyncMock()
    reputation_mgr.get_metrics = AsyncMock(return_value=ReputationMetrics())
    reputation_mgr.get_on_chain_reputation = AsyncMock(return_value=None)
    app.state.reputation_mgr = reputation_mgr

    return app


@pytest.fixture()
async def client() -> AsyncClient:
    app = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════════════
# Status Route
# ═══════════════════════════════════════════════════════════════════════════════


class TestStatusRoute:
    async def test_returns_200_with_agent_info(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert data["agent"]["name"] == "SaltaX"
        assert data["agent"]["version"] == "1.0"
        assert data["agent"]["wallet_address"] == "0x" + "0" * 40

    async def test_returns_treasury_section(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/status")
        data = response.json()
        assert "treasury" in data
        assert data["treasury"]["balance_wei"] == 0
        assert data["treasury"]["available"] is True

    async def test_returns_reputation_section(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/status")
        data = response.json()
        assert "reputation" in data
        assert data["reputation"]["total_prs_reviewed"] == 0

    async def test_returns_intelligence_section(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/status")
        data = response.json()
        assert data["intelligence"]["total_patterns"] == 42
        assert data["intelligence"]["db_initialized"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# Audit Route
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuditRoute:
    async def test_returns_402_without_payment(self) -> None:
        from src.api.middleware.x402 import PaymentRequirements, PaymentVerification

        app = _make_app()
        # Override verifier to return invalid
        verifier = MagicMock()
        verifier.build_requirements.return_value = PaymentRequirements(
            amount_atomic=10_000_000,
            resource="/api/v1/audit",
            description="SaltaX full audit",
            pay_to="0x" + "0" * 40,
        )
        verifier.verify = AsyncMock(
            return_value=PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="missing_payment_header",
            )
        )
        app.state.payment_verifier = verifier

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            response = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/repo",
                    "commit_sha": "abc123",
                    "scope": "full",
                },
            )
        assert response.status_code == 402
        data = response.json()
        assert data["error"] == "Payment Required"
        assert "PAYMENT-REQUIRED" in response.headers

    async def test_returns_202_with_valid_payment(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/audit",
            json={
                "repository_url": "https://github.com/owner/repo-202",
                "commit_sha": "abc123-202",
                "scope": "security-only",
            },
            headers={"X-PAYMENT": "dGVzdA=="},
        )
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert data["audit_id"].startswith("audit-")
        assert data["scope"] == "security-only"
        assert "payment_tx_hash" in data

    async def test_invalid_scope_returns_422(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/audit",
            json={
                "repository_url": "https://github.com/owner/repo",
                "commit_sha": "abc123",
                "scope": "invalid-scope",
            },
        )
        assert response.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# Attestation Route
# ═══════════════════════════════════════════════════════════════════════════════


class TestAttestationRoute:
    async def test_returns_404_for_any_id(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/attestation/some-action-id")
        assert response.status_code == 404
        data = response.json()
        assert "some-action-id" in data["detail"]


# ═══════════════════════════════════════════════════════════════════════════════
# Bounties Route
# ═══════════════════════════════════════════════════════════════════════════════


class TestBountiesRoute:
    async def test_returns_empty_list(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/bounties")
        assert response.status_code == 200
        data = response.json()
        assert data["bounties"] == []
        assert data["count"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Intelligence Route
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntelligenceRoute:
    async def test_returns_pattern_count(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/intelligence/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_patterns"] == 42

    async def test_returns_stubbed_distributions(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/intelligence/stats")
        data = response.json()
        assert data["category_distribution"] == {}
        assert data["severity_distribution"] == {}
        assert data["avg_false_positive_rate"] == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Vision Route
# ═══════════════════════════════════════════════════════════════════════════════


class TestVisionRoute:
    async def test_accepts_document(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/vision",
            json={
                "repo": "owner/repo",
                "content": "# Project Vision\n\nBuild something great.",
                "title": "Project Vision",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"

    async def test_missing_fields_returns_422(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/vision",
            json={"repo": "owner/repo"},
        )
        assert response.status_code == 422

    async def test_empty_content_returns_400(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/vision",
            json={"repo": "owner/repo", "content": "   "},
        )
        assert response.status_code == 400

    async def test_oversized_content_returns_400(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/vision",
            json={"repo": "owner/repo", "content": "x" * 200_000},
        )
        assert response.status_code == 400

    async def test_wrong_source_returns_400(self, client: AsyncClient) -> None:
        """When source != 'api', the endpoint rejects ingestion."""
        app = _make_app()
        app.state.config.triage.vision.source = "repo"
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            response = await c.post(
                "/api/v1/vision",
                json={"repo": "owner/repo", "content": "# Vision"},
            )
        assert response.status_code == 400

    async def test_missing_repo_slash_returns_400(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/vision",
            json={"repo": "noslash", "content": "# Vision"},
        )
        assert response.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limiter
# ═══════════════════════════════════════════════════════════════════════════════


class TestRateLimiter:
    async def test_returns_429_after_exceeding_limit(self) -> None:
        from src.api.middleware.rate_limiter import RateLimiterMiddleware

        app = _make_app()
        app.add_middleware(RateLimiterMiddleware, global_rpm=3, audit_rpm=2)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # First 3 requests should succeed
            for _ in range(3):
                r = await c.get("/api/v1/bounties")
                assert r.status_code == 200

            # 4th request should be rate-limited
            r = await c.get("/api/v1/bounties")
            assert r.status_code == 429
            data = r.json()
            assert data["error"] == "Too Many Requests"

    async def test_audit_has_stricter_limit(self) -> None:
        from src.api.middleware.rate_limiter import RateLimiterMiddleware

        app = _make_app()
        app.add_middleware(RateLimiterMiddleware, global_rpm=100, audit_rpm=2)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            payment = base64.b64encode(b"payment").decode()
            for _ in range(2):
                r = await c.post(
                    "/api/v1/audit",
                    json={
                        "repository_url": "https://github.com/o/r",
                        "commit_sha": "abc",
                        "scope": "full",
                    },
                    headers={"X-PAYMENT": payment},
                )
                # Either 202 or 402 — not 429 yet
                assert r.status_code in (202, 402)

            # 3rd audit request should be rate-limited
            r = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/o/r",
                    "commit_sha": "abc",
                    "scope": "full",
                },
                headers={"X-PAYMENT": payment},
            )
            assert r.status_code == 429

    async def test_lru_eviction_caps_memory(self) -> None:
        """Rate limiter should evict stale IPs when max_ips is exceeded."""
        from src.api.middleware.rate_limiter import RateLimiterMiddleware

        app = _make_app()
        mw = RateLimiterMiddleware(app, global_rpm=100, audit_rpm=10, max_ips=5)

        # Manually inject entries to simulate many IPs
        import time

        now = time.monotonic()
        for i in range(10):
            mw._buckets[f"10.0.0.{i}"] = [now]

        assert len(mw._buckets) == 10

        # Trigger eviction
        mw._evict_stale(now, 60.0)

        assert len(mw._buckets) <= 5


# ═══════════════════════════════════════════════════════════════════════════════
# Delivery Dedup
# ═══════════════════════════════════════════════════════════════════════════════


class TestDeliveryDedup:
    def test_first_delivery_is_not_duplicate(self) -> None:
        from src.api.middleware.dedup import DeliveryDedup

        dedup = DeliveryDedup()
        assert dedup.is_duplicate("delivery-1") is False

    def test_second_delivery_is_duplicate(self) -> None:
        from src.api.middleware.dedup import DeliveryDedup

        dedup = DeliveryDedup()
        dedup.is_duplicate("delivery-2")
        assert dedup.is_duplicate("delivery-2") is True

    def test_unknown_delivery_id_allowed_through(self) -> None:
        from src.api.middleware.dedup import DeliveryDedup

        dedup = DeliveryDedup()
        # Missing/unknown delivery IDs can't be deduplicated
        assert dedup.is_duplicate("unknown") is False
        assert dedup.is_duplicate("") is False

    def test_expired_entries_pruned(self) -> None:
        import time

        from src.api.middleware.dedup import DeliveryDedup

        dedup = DeliveryDedup(ttl_seconds=0.0)  # Instant expiry
        dedup.is_duplicate("old-delivery")
        # Force time advancement by waiting a tiny bit
        time.sleep(0.01)
        # After TTL, should not be considered duplicate
        assert dedup.is_duplicate("old-delivery") is False

    def test_max_entries_enforced(self) -> None:
        from src.api.middleware.dedup import DeliveryDedup

        dedup = DeliveryDedup(max_entries=3)
        for i in range(10):
            dedup.is_duplicate(f"d-{i}")
        assert dedup.size <= 3


# ═══════════════════════════════════════════════════════════════════════════════
# Healthz Endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class TestHealthz:
    async def test_healthy_returns_200(self) -> None:
        from src.api.app import create_app

        config = MagicMock()
        config.version = "1.0"
        intel_db = AsyncMock()
        intel_db.initialized = True
        intel_db.count_patterns.return_value = 0
        scheduler = MagicMock()
        scheduler.running = True
        wallet = MagicMock()
        wallet.address = "0x" + "0" * 40

        app = create_app(
            config=config,
            env=MagicMock(),
            pipeline=AsyncMock(),
            wallet=wallet,
            intel_db=intel_db,
            identity=MagicMock(),
            scheduler=scheduler,
            github_client=AsyncMock(),
            treasury_mgr=AsyncMock(),
            payment_verifier=MagicMock(),
            tx_store=MagicMock(),
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/healthz")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["checks"]["intel_db"] is True
        assert data["checks"]["scheduler"] is True
        assert data["checks"]["wallet"] is True

    async def test_degraded_returns_503(self) -> None:
        from src.api.app import create_app

        config = MagicMock()
        config.version = "1.0"
        intel_db = AsyncMock()
        intel_db.initialized = False  # DB not ready
        intel_db.count_patterns.return_value = 0
        scheduler = MagicMock()
        scheduler.running = True
        wallet = MagicMock()
        wallet.address = "0x" + "0" * 40

        app = create_app(
            config=config,
            env=MagicMock(),
            pipeline=AsyncMock(),
            wallet=wallet,
            intel_db=intel_db,
            identity=MagicMock(),
            scheduler=scheduler,
            github_client=AsyncMock(),
            treasury_mgr=AsyncMock(),
            payment_verifier=MagicMock(),
            tx_store=MagicMock(),
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/healthz")
        assert r.status_code == 503
        data = r.json()
        assert data["status"] == "degraded"
        assert data["checks"]["intel_db"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# Global Exception Handler
# ═══════════════════════════════════════════════════════════════════════════════


class TestGlobalExceptionHandler:
    async def test_unhandled_error_returns_sanitized_500(self) -> None:
        """Unhandled exceptions should return ErrorResponse JSON, not a traceback."""
        from src.api.app import create_app

        config = MagicMock()
        config.version = "1.0"

        app = create_app(
            config=config,
            env=MagicMock(),
            pipeline=AsyncMock(),
            wallet=MagicMock(),
            intel_db=AsyncMock(),
            identity=MagicMock(),
            scheduler=MagicMock(),
            github_client=AsyncMock(),
            treasury_mgr=AsyncMock(),
            payment_verifier=MagicMock(),
            tx_store=MagicMock(),
        )

        # Add a route that raises an unhandled error
        @app.get("/api/v1/explode")
        async def explode() -> None:
            msg = "something broke"
            raise RuntimeError(msg)

        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/api/v1/explode")

        assert r.status_code == 500
        data = r.json()
        assert data["status_code"] == 500
        assert data["error"] == "Internal Server Error"
        # Should NOT contain the actual error message or traceback
        assert "something broke" not in data["detail"]
        assert "RuntimeError" not in data["detail"]

    async def test_404_returns_error_response_shape(self) -> None:
        from src.api.app import create_app

        config = MagicMock()
        config.version = "1.0"

        app = create_app(
            config=config,
            env=MagicMock(),
            pipeline=AsyncMock(),
            wallet=MagicMock(),
            intel_db=AsyncMock(),
            identity=MagicMock(),
            scheduler=MagicMock(),
            github_client=AsyncMock(),
            treasury_mgr=AsyncMock(),
            payment_verifier=MagicMock(),
            tx_store=MagicMock(),
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/api/v1/nonexistent-route")

        assert r.status_code == 404
        data = r.json()
        assert data["status_code"] == 404
        assert data["error"] == "Not Found"
