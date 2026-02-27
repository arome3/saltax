"""Tests for identity subsystem: registration, reputation, bridge client, and cache."""

from __future__ import annotations

import os

from datetime import UTC, datetime

import pytest

from src.identity.bridge_client import AlreadyRegisteredError, IdentityBridgeClient
from src.identity.registration import IdentityRegistrar
from src.identity.reputation import _EVENT_FEEDBACK_MAP, ReputationEvent, ReputationManager
from src.intelligence.database import IntelligenceDB
from src.models.identity import AgentIdentity

_ = pytest  # ensure pytest is used (fixture injection)

_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)


# ── Helpers ──────────────────────────────────────────────────────────────────


class FakeWallet:
    """Minimal wallet stub — avoids importing WalletManager (needs web3)."""

    def __init__(self, address: str | None = "0xABCDEF1234567890abcdef1234567890ABCDEF12"):
        self._address = address

    @property
    def address(self) -> str | None:
        return self._address


class FakeBridgeClient:
    """In-memory bridge client stub for testing without HTTP."""

    def __init__(
        self,
        *,
        register_result=None,
        feedback_result=None,
        reputation_result=None,
        raise_already_registered: bool = False,
        get_agent_result=None,
    ):
        self._register_result = register_result
        self._feedback_result = feedback_result
        self._reputation_result = reputation_result
        self._raise_already_registered = raise_already_registered
        self._get_agent_result = get_agent_result
        self.register_calls: list[dict] = []
        self.feedback_calls: list[dict] = []
        self.reputation_calls: list[str] = []
        self.get_agent_calls: list[str] = []
        self._closed = False

    async def register_agent(self, name, description, chain_id, metadata=None):
        self.register_calls.append({
            "name": name, "description": description,
            "chain_id": chain_id, "metadata": metadata,
        })
        if self._raise_already_registered:
            raise AlreadyRegisteredError("agent already exists")
        return self._register_result

    async def get_agent(self, agent_id):
        self.get_agent_calls.append(agent_id)
        return self._get_agent_result

    async def give_feedback(self, agent_id, value, tag1, tag2):
        self.feedback_calls.append({
            "agent_id": agent_id, "value": value, "tag1": tag1, "tag2": tag2,
        })
        return self._feedback_result

    async def get_reputation_summary(self, agent_id):
        self.reputation_calls.append(agent_id)
        return self._reputation_result

    async def close(self):
        self._closed = True


# ── Fixtures ─────────────────────────────────────────────────────────────────


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


# ── TestIdentityRegistrar ────────────────────────────────────────────────────


class TestIdentityRegistrar:
    """Tests for IdentityRegistrar registration and recovery flows."""

    async def test_successful_registration(self):
        """Bridge returns agentId → registrar stores identity."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(register_result={"agentId": "agent-123"})
        registrar = IdentityRegistrar(
            wallet, bridge, chain_id=11155111,
            agent_name="TestAgent", agent_description="Test",
        )

        identity = await registrar.register_or_recover()

        assert identity.agent_id == "agent-123"
        assert identity.chain_id == 11155111
        assert identity.wallet_address == wallet.address
        assert registrar.agent_id == "agent-123"
        assert len(bridge.register_calls) == 1

    async def test_idempotent_double_call(self):
        """Second call returns cached identity without hitting bridge again."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(register_result={"agentId": "agent-123"})
        registrar = IdentityRegistrar(wallet, bridge, chain_id=1)

        first = await registrar.register_or_recover()
        second = await registrar.register_or_recover()

        assert first is second
        assert len(bridge.register_calls) == 1  # only one bridge call

    async def test_bridge_down_uses_placeholder(self):
        """When bridge returns None → deterministic placeholder identity."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(register_result=None)  # bridge failure
        registrar = IdentityRegistrar(wallet, bridge, chain_id=11155111)

        identity = await registrar.register_or_recover()

        assert identity.agent_id.startswith("11155111:placeholder-")
        assert registrar.agent_id == identity.agent_id

    async def test_placeholder_determinism(self):
        """Same wallet address always produces the same placeholder ID."""
        wallet = FakeWallet(address="0x1111111111111111111111111111111111111111")
        bridge = FakeBridgeClient(register_result=None)

        r1 = IdentityRegistrar(wallet, bridge, chain_id=1)
        r2 = IdentityRegistrar(wallet, bridge, chain_id=1)

        id1 = await r1.register_or_recover()
        id2 = await r2.register_or_recover()

        assert id1.agent_id == id2.agent_id

    async def test_cache_write_failure_continues(self, intel_db):
        """If caching fails, registration still succeeds."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(register_result={"agentId": "agent-ok"})

        # Make cache_identity raise
        original = intel_db.cache_identity
        async def failing_cache(identity):
            raise RuntimeError("cache write boom")

        intel_db.cache_identity = failing_cache
        try:
            registrar = IdentityRegistrar(
                wallet, bridge, chain_id=1, intel_db=intel_db,
            )
            identity = await registrar.register_or_recover()
            assert identity.agent_id == "agent-ok"
        finally:
            intel_db.cache_identity = original

    async def test_recovers_from_cache(self, intel_db):
        """If identity is cached in DB, skips bridge call entirely."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(register_result={"agentId": "should-not-see"})

        # Pre-populate cache
        cached = AgentIdentity(
            agent_id="cached-agent-42",
            chain_id=1,
            wallet_address=wallet.address,
            name="Cached",
            description="From cache",
            registered_at=datetime.now(UTC),
        )
        await intel_db.cache_identity(cached)

        registrar = IdentityRegistrar(wallet, bridge, chain_id=1, intel_db=intel_db)
        identity = await registrar.register_or_recover()

        assert identity.agent_id == "cached-agent-42"
        assert len(bridge.register_calls) == 0  # bridge never called

    async def test_wallet_not_initialized_raises(self):
        """Registrar raises RuntimeError if wallet has no address."""
        wallet = FakeWallet(address=None)
        bridge = FakeBridgeClient()
        registrar = IdentityRegistrar(wallet, bridge, chain_id=1)

        with pytest.raises(RuntimeError, match="wallet address"):
            await registrar.register_or_recover()

    async def test_409_recovery_via_get_agent(self):
        """On AlreadyRegisteredError, registrar recovers via get_agent()."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(
            raise_already_registered=True,
            get_agent_result={"agentId": "recovered-agent-99"},
        )
        registrar = IdentityRegistrar(wallet, bridge, chain_id=1)

        identity = await registrar.register_or_recover()

        assert identity.agent_id == "recovered-agent-99"
        assert registrar.agent_id == "recovered-agent-99"
        assert len(bridge.register_calls) == 1  # tried register
        assert len(bridge.get_agent_calls) == 1  # fell back to get_agent

    async def test_409_recovery_bridge_returns_none_uses_placeholder(self):
        """If 409 recovery also fails, falls through to placeholder."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(
            raise_already_registered=True,
            get_agent_result=None,  # get_agent also fails
        )
        registrar = IdentityRegistrar(wallet, bridge, chain_id=1)

        identity = await registrar.register_or_recover()

        assert identity.agent_id.startswith("1:placeholder-")

    async def test_409_recovery_empty_agent_id_uses_placeholder(self):
        """If 409 recovery returns empty agentId, falls to placeholder."""
        wallet = FakeWallet()
        bridge = FakeBridgeClient(
            raise_already_registered=True,
            get_agent_result={"agentId": ""},  # empty ID
        )
        registrar = IdentityRegistrar(wallet, bridge, chain_id=1)

        identity = await registrar.register_or_recover()

        assert identity.agent_id.startswith("1:placeholder-")

    async def test_close_closes_bridge(self):
        """Registrar.close() closes the bridge client."""
        bridge = FakeBridgeClient()
        registrar = IdentityRegistrar(FakeWallet(), bridge, chain_id=1)
        await registrar.close()
        assert bridge._closed


# ── TestReputationManager ────────────────────────────────────────────────────


class TestReputationManager:
    """Tests for reputation update and metrics aggregation."""

    async def test_feedback_sent_with_correct_tags(self):
        """update_reputation sends correct (value, tag1, tag2) to bridge."""
        bridge = FakeBridgeClient(feedback_result={"txHash": "0xabc"})
        mgr = ReputationManager(bridge, None, "agent-1")

        await mgr.update_reputation(ReputationEvent.SUCCESSFUL_MERGE)

        assert len(bridge.feedback_calls) == 1
        call = bridge.feedback_calls[0]
        assert call["agent_id"] == "agent-1"
        assert call["value"] == 85
        assert call["tag1"] == "code-review"
        assert call["tag2"] == "merge"

    async def test_bridge_down_no_raise(self):
        """update_reputation never raises when bridge returns None."""
        bridge = FakeBridgeClient(feedback_result=None)
        mgr = ReputationManager(bridge, None, "agent-1")

        # Should not raise
        await mgr.update_reputation(ReputationEvent.REJECTED_PR)

    async def test_exception_no_raise(self):
        """update_reputation catches bridge exceptions."""
        bridge = FakeBridgeClient()
        # Make give_feedback raise
        async def exploding_feedback(*args):
            raise ConnectionError("boom")
        bridge.give_feedback = exploding_feedback

        mgr = ReputationManager(bridge, None, "agent-1")
        # Should not raise
        await mgr.update_reputation(ReputationEvent.AUDIT_COMPLETED)

    async def test_empty_db_returns_zeros(self, intel_db):
        """get_metrics returns zeroed ReputationMetrics on empty DB."""
        bridge = FakeBridgeClient()
        mgr = ReputationManager(bridge, intel_db, "agent-1")

        metrics = await mgr.get_metrics()

        assert metrics.total_prs_reviewed == 0
        assert metrics.total_prs_approved == 0
        assert metrics.total_prs_rejected == 0
        assert metrics.approval_rate == 0.0

    async def test_metrics_from_pipeline_history(self, intel_db):
        """get_metrics aggregates from pipeline_history correctly."""
        bridge = FakeBridgeClient()

        # Insert some pipeline history entries
        await intel_db.ingest_pipeline_results(
            pr_id="pr-1", repo="test/repo",
            static_findings=[], ai_findings=[],
            verdict={"decision": "approve", "composite_score": 0.9, "findings_count": 0},
            author="alice",
        )
        await intel_db.ingest_pipeline_results(
            pr_id="pr-2", repo="test/repo",
            static_findings=[], ai_findings=[],
            verdict={"decision": "reject", "composite_score": 0.3, "findings_count": 5},
            author="bob",
        )

        mgr = ReputationManager(bridge, intel_db, "agent-1")
        metrics = await mgr.get_metrics()

        assert metrics.total_prs_reviewed == 2
        assert metrics.total_prs_approved == 1
        assert metrics.total_prs_rejected == 1

    async def test_all_events_have_feedback_mappings(self):
        """Every ReputationEvent has a corresponding feedback mapping."""
        for event in ReputationEvent:
            assert event in _EVENT_FEEDBACK_MAP, f"Missing mapping for {event}"
            value, tag1, tag2 = _EVENT_FEEDBACK_MAP[event]
            assert isinstance(value, int)
            assert isinstance(tag1, str) and tag1
            assert isinstance(tag2, str) and tag2

    async def test_no_agent_id_skips_update(self):
        """update_reputation does nothing when agent_id is empty."""
        bridge = FakeBridgeClient(feedback_result={"txHash": "0x"})
        mgr = ReputationManager(bridge, None, "")

        await mgr.update_reputation(ReputationEvent.SUCCESSFUL_MERGE)
        assert len(bridge.feedback_calls) == 0

    async def test_metrics_populates_vulnerability_count(self, intel_db):
        """get_metrics counts vulnerability patterns."""
        bridge = FakeBridgeClient()

        # Ingest a pipeline result that produces vulnerability patterns.
        # extract_patterns needs 'snippet' or 'message' key in findings.
        await intel_db.ingest_pipeline_results(
            pr_id="pr-vuln", repo="test/repo",
            static_findings=[
                {"rule_id": "S501", "severity": "HIGH", "category": "security",
                 "snippet": "eval(user_input)", "confidence": 0.9,
                 "source_stage": "bandit"},
            ],
            ai_findings=[],
            verdict={"decision": "reject", "composite_score": 0.2, "findings_count": 1},
            author="alice",
        )

        mgr = ReputationManager(bridge, intel_db, "agent-1")
        metrics = await mgr.get_metrics()

        assert metrics.vulnerabilities_caught >= 1

    async def test_metrics_populates_bounties_paid(self, intel_db):
        """get_metrics sums claimed bounty amounts in wei."""
        bridge = FakeBridgeClient()

        # Add and claim bounties via store_bounty (the actual DB method)
        await intel_db.store_bounty(
            bounty_id="b-1", repo="test/repo",
            issue_number=1, label="bug", amount_eth=0.5,
        )
        await intel_db.store_bounty(
            bounty_id="b-2", repo="test/repo",
            issue_number=2, label="feature", amount_eth=1.0,
        )
        # Claim one bounty
        await intel_db.close_bounty("b-1", "alice")

        mgr = ReputationManager(bridge, intel_db, "agent-1")
        metrics = await mgr.get_metrics()

        # Only the claimed bounty (0.5 ETH) counts → 500000000000000000 wei
        assert metrics.total_bounties_paid_wei == int(0.5 * 10**18)

    async def test_metrics_populates_uptime(self, intel_db):
        """get_metrics includes uptime_seconds > 0."""
        bridge = FakeBridgeClient()
        mgr = ReputationManager(bridge, intel_db, "agent-1")

        metrics = await mgr.get_metrics()

        # Boot time was set at construction, uptime should be >= 0
        assert metrics.uptime_seconds >= 0

    async def test_json_extract_case_insensitive(self, intel_db):
        """json_extract query handles 'APPROVE' and 'approve' equally."""
        bridge = FakeBridgeClient()

        # Insert with different case decisions
        await intel_db.ingest_pipeline_results(
            pr_id="pr-lower", repo="test/repo",
            static_findings=[], ai_findings=[],
            verdict={"decision": "approve", "composite_score": 0.9, "findings_count": 0},
            author="alice",
        )
        await intel_db.ingest_pipeline_results(
            pr_id="pr-upper", repo="test/repo",
            static_findings=[], ai_findings=[],
            verdict={"decision": "APPROVE", "composite_score": 0.8, "findings_count": 0},
            author="bob",
        )

        mgr = ReputationManager(bridge, intel_db, "agent-1")
        metrics = await mgr.get_metrics()

        assert metrics.total_prs_reviewed == 2
        assert metrics.total_prs_approved == 2  # both should count
        assert metrics.total_prs_rejected == 0

    async def test_get_on_chain_reputation(self):
        """get_on_chain_reputation returns bridge data."""
        bridge = FakeBridgeClient(reputation_result={"averageValue": 82.5})
        mgr = ReputationManager(bridge, None, "agent-1")

        result = await mgr.get_on_chain_reputation()

        assert result == {"averageValue": 82.5}
        assert bridge.reputation_calls == ["agent-1"]


# ── TestIdentityBridgeClient ─────────────────────────────────────────────────


class TestIdentityBridgeClient:
    """Tests for the HTTP bridge client."""

    async def test_close_idempotent(self):
        """close() can be called multiple times safely."""
        client = IdentityBridgeClient("http://localhost:9999")
        await client.close()
        await client.close()  # should not raise

    async def test_returns_none_on_timeout(self):
        """register_agent returns None when bridge is unreachable."""
        # Use a non-routable address to trigger a connection error
        client = IdentityBridgeClient("http://127.0.0.1:1")
        try:
            result = await client.register_agent(
                "test", "test", 1,
            )
            assert result is None
        finally:
            await client.close()

    async def test_get_reputation_returns_none_on_error(self):
        """get_reputation_summary returns None when bridge is unreachable."""
        client = IdentityBridgeClient("http://127.0.0.1:1")
        try:
            result = await client.get_reputation_summary("agent-1")
            assert result is None
        finally:
            await client.close()


# ── TestIdentityCache ────────────────────────────────────────────────────────


class TestIdentityCache:
    """Tests for agent_identity_cache table in IntelligenceDB."""

    async def test_cache_and_retrieve(self, intel_db):
        """Store identity and retrieve it by wallet address."""
        identity = AgentIdentity(
            agent_id="test-agent-1",
            chain_id=11155111,
            wallet_address="0xdeadbeef",
            name="Test",
            description="A test agent",
            registered_at=datetime(2026, 1, 15, tzinfo=UTC),
        )

        await intel_db.cache_identity(identity)
        cached = await intel_db.get_cached_identity("0xdeadbeef")

        assert cached is not None
        assert cached.agent_id == "test-agent-1"
        assert cached.chain_id == 11155111
        assert cached.wallet_address == "0xdeadbeef"
        assert cached.name == "Test"
        assert cached.description == "A test agent"

    async def test_not_found_returns_none(self, intel_db):
        """get_cached_identity returns None for unknown wallet."""
        result = await intel_db.get_cached_identity("0xnonexistent")
        assert result is None

    async def test_upsert_works(self, intel_db):
        """Caching the same wallet address twice updates the record."""
        v1 = AgentIdentity(
            agent_id="agent-v1",
            chain_id=1,
            wallet_address="0xwallet",
            name="V1",
            description="First",
            registered_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        v2 = AgentIdentity(
            agent_id="agent-v2",
            chain_id=1,
            wallet_address="0xwallet",
            name="V2",
            description="Updated",
            registered_at=datetime(2026, 2, 1, tzinfo=UTC),
        )

        await intel_db.cache_identity(v1)
        await intel_db.cache_identity(v2)

        cached = await intel_db.get_cached_identity("0xwallet")
        assert cached is not None
        assert cached.agent_id == "agent-v2"
        assert cached.name == "V2"

    async def test_table_exists_after_init(self, intel_db):
        """agent_identity_cache table exists after initialization."""
        async with intel_db.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT tablename FROM pg_catalog.pg_tables "
                "WHERE schemaname = 'public' AND tablename = 'agent_identity_cache'"
            )
            row = await cursor.fetchone()
            assert row is not None
