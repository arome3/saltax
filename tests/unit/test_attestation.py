"""Tests for the attestation engine, store, and verifier."""

from __future__ import annotations

import os

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.attestation.engine import (
    AttestationEngine,
    _hash_data,
    _probe_image_digest,
    _probe_tee_platform_id,
    build_signing_message,
)
from src.attestation.store import AttestationStore
from src.attestation.verifier import (
    verify_chain,
    verify_input_hash,
    verify_output_hash,
    verify_signature,
)
from src.intelligence.database import IntelligenceDB
from src.models.attestation import AttestationProof

_ = pytest  # ensure pytest is used (fixture injection)

_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)

_ENGINE_MODULE = "src.attestation.engine"


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


@pytest.fixture()
def store(intel_db):
    """AttestationStore wrapping the real IntelligenceDB."""
    return AttestationStore(intel_db)


@pytest.fixture()
def wallet_ok():
    """Mock wallet that returns a fixed hex signature."""
    w = MagicMock()
    w.sign_message = MagicMock(return_value="ab" * 32)
    w.address = "0x" + "0" * 40
    return w


@pytest.fixture()
def wallet_fail():
    """Mock wallet that raises RuntimeError on sign."""
    w = MagicMock()
    w.sign_message = MagicMock(side_effect=RuntimeError("wallet not initialized"))
    w.address = "0x" + "0" * 40
    return w


@pytest.fixture()
def wallet_no_address():
    """Mock wallet where address is None (not initialized)."""
    w = MagicMock()
    w.sign_message = MagicMock(return_value="ab" * 32)
    w.address = None
    return w


@pytest.fixture()
def engine(wallet_ok, store, monkeypatch):
    """AttestationEngine with monkeypatched probes."""
    monkeypatch.setattr(f"{_ENGINE_MODULE}._probe_image_digest", lambda: "sha256:testdigest")
    monkeypatch.setattr(
        f"{_ENGINE_MODULE}._probe_tee_platform_id",
        AsyncMock(return_value="tee-test-123"),
    )
    return AttestationEngine(wallet=wallet_ok, store=store)


@pytest.fixture()
def engine_fail_wallet(wallet_fail, store, monkeypatch):
    """AttestationEngine with failing wallet."""
    monkeypatch.setattr(f"{_ENGINE_MODULE}._probe_image_digest", lambda: "sha256:testdigest")
    monkeypatch.setattr(
        f"{_ENGINE_MODULE}._probe_tee_platform_id",
        AsyncMock(return_value="tee-test-123"),
    )
    return AttestationEngine(wallet=wallet_fail, store=store)


@pytest.fixture()
def engine_no_address(wallet_no_address, store, monkeypatch):
    """AttestationEngine with wallet that has no address."""
    monkeypatch.setattr(f"{_ENGINE_MODULE}._probe_image_digest", lambda: "sha256:testdigest")
    monkeypatch.setattr(
        f"{_ENGINE_MODULE}._probe_tee_platform_id",
        AsyncMock(return_value="tee-test-123"),
    )
    return AttestationEngine(wallet=wallet_no_address, store=store)


def _proof_kwargs(**overrides):
    """Default kwargs for generate_proof()."""
    defaults = {
        "action_id": "attest-owner/repo#1-abc12345",
        "pr_id": "owner/repo#1",
        "repo": "owner/repo",
        "inputs": {"repo": "owner/repo", "commit_sha": "abc12345", "diff_hash": "deadbeef"},
        "outputs": {"findings_count": 2, "verdict": "APPROVE"},
    }
    defaults.update(overrides)
    return defaults


# ═══════════════════════════════════════════════════════════════════════════════
# A. Deterministic hashing
# ═══════════════════════════════════════════════════════════════════════════════


class TestDeterministicHashing:
    def test_same_inputs_same_hash(self) -> None:
        data = {"b": 2, "a": 1}
        assert _hash_data(data) == _hash_data(data)

    def test_key_order_irrelevant(self) -> None:
        """Different key order produces the same hash (sort_keys=True)."""
        assert _hash_data({"a": 1, "b": 2}) == _hash_data({"b": 2, "a": 1})

    def test_different_data_different_hash(self) -> None:
        assert _hash_data({"a": 1}) != _hash_data({"a": 2})

    def test_hash_is_64_char_hex(self) -> None:
        h = _hash_data({"key": "value"})
        assert len(h) == 64
        int(h, 16)  # must be valid hex


# ═══════════════════════════════════════════════════════════════════════════════
# B. generate_proof fields
# ═══════════════════════════════════════════════════════════════════════════════


class TestGenerateProofFields:
    async def test_all_fields_populated(self, engine) -> None:
        proof = await engine.generate_proof(**_proof_kwargs())
        assert proof.attestation_id == "attest-owner/repo#1-abc12345"
        assert proof.docker_image_digest == "sha256:testdigest"
        assert proof.tee_platform_id == "tee-test-123"
        assert len(proof.pipeline_input_hash) == 64
        assert len(proof.pipeline_output_hash) == 64
        assert proof.signature == "ab" * 32
        assert proof.timestamp is not None


# ═══════════════════════════════════════════════════════════════════════════════
# C. Genesis proof
# ═══════════════════════════════════════════════════════════════════════════════


class TestGenesisProof:
    async def test_first_proof_has_no_previous(self, engine) -> None:
        proof = await engine.generate_proof(**_proof_kwargs())
        assert proof.previous_attestation_id is None


# ═══════════════════════════════════════════════════════════════════════════════
# D. Chain integrity
# ═══════════════════════════════════════════════════════════════════════════════


class TestChainIntegrity:
    async def test_three_proofs_chain(self, engine) -> None:
        p1 = await engine.generate_proof(**_proof_kwargs(action_id="attest-1"))
        p2 = await engine.generate_proof(**_proof_kwargs(action_id="attest-2"))
        p3 = await engine.generate_proof(**_proof_kwargs(action_id="attest-3"))

        assert p1.previous_attestation_id is None
        assert p2.previous_attestation_id == "attest-1"
        assert p3.previous_attestation_id == "attest-2"


# ═══════════════════════════════════════════════════════════════════════════════
# E. Concurrent proofs serialized
# ═══════════════════════════════════════════════════════════════════════════════


class TestConcurrentProofsSerialized:
    async def test_concurrent_gather(self, engine) -> None:
        """Two concurrent generate_proof calls produce a valid chain."""
        p1, p2 = await asyncio.gather(
            engine.generate_proof(**_proof_kwargs(action_id="attest-c1")),
            engine.generate_proof(**_proof_kwargs(action_id="attest-c2")),
        )

        # One must be genesis, the other must link to it
        ids = {p1.attestation_id, p2.attestation_id}
        assert ids == {"attest-c1", "attest-c2"}

        # The chain must be valid: one is genesis, the other links to it
        if p1.previous_attestation_id is None:
            assert p2.previous_attestation_id == p1.attestation_id
        else:
            assert p1.previous_attestation_id == p2.attestation_id


# ═══════════════════════════════════════════════════════════════════════════════
# F. Signing failure degrades
# ═══════════════════════════════════════════════════════════════════════════════


class TestSigningFailureDegrades:
    async def test_wallet_failure_empty_signature(self, engine_fail_wallet) -> None:
        proof = await engine_fail_wallet.generate_proof(**_proof_kwargs())
        assert proof.signature == ""
        # Proof still stored
        assert proof.attestation_id == "attest-owner/repo#1-abc12345"


# ═══════════════════════════════════════════════════════════════════════════════
# G. Environment probes
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnvironmentProbes:
    def test_image_digest_non_container(self) -> None:
        """On macOS/non-container, _probe_image_digest returns 'unknown'."""
        assert _probe_image_digest() == "unknown"

    def test_image_digest_from_cgroup(self, monkeypatch, tmp_path) -> None:
        """Cgroup file with a 64-char hex container ID is parsed."""
        container_id = "a" * 64
        cgroup_content = (
            "12:devices:/docker/" + container_id + "\n"
            "11:memory:/docker/" + container_id + "\n"
        )
        cgroup_file = tmp_path / "cgroup"
        cgroup_file.write_text(cgroup_content)

        from pathlib import Path

        monkeypatch.setattr(Path, "read_text", lambda self: cgroup_content)  # noqa: ARG005
        result = _probe_image_digest()
        assert result == f"sha256:{container_id}"

    async def test_tee_platform_unavailable(self) -> None:
        """When TEE metadata endpoint is unreachable, returns 'unknown'."""
        result = await _probe_tee_platform_id()
        assert result == "unknown"

    async def test_tee_platform_html_rejected(self, monkeypatch) -> None:
        """HTML response (captive portal) is rejected."""
        import httpx

        class FakeResponse:
            status_code = 200
            text = "<html><body>Login Required</body></html>"

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                pass

            async def get(self, *_args, **_kwargs):
                return FakeResponse()

        monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
        result = await _probe_tee_platform_id()
        assert result == "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# H. Signature verification roundtrip
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifySignatureRoundtrip:
    async def test_real_eth_account_roundtrip(self, store, monkeypatch) -> None:
        """Sign with a real eth_account key and verify recovery matches."""
        from eth_account import Account

        acct = Account.create()

        real_wallet = MagicMock()
        real_wallet.address = acct.address
        from eth_account.messages import encode_defunct

        def _real_sign(msg_bytes):
            signable = encode_defunct(primitive=msg_bytes)
            signed = acct.sign_message(signable)
            return signed.signature.hex()

        real_wallet.sign_message = MagicMock(side_effect=_real_sign)

        monkeypatch.setattr(f"{_ENGINE_MODULE}._probe_image_digest", lambda: "sha256:abc")
        monkeypatch.setattr(
            f"{_ENGINE_MODULE}._probe_tee_platform_id",
            AsyncMock(return_value="tee-id"),
        )

        engine = AttestationEngine(wallet=real_wallet, store=store)
        proof = await engine.generate_proof(**_proof_kwargs())

        assert verify_signature(proof, acct.address)

    async def test_real_roundtrip_with_ai_provenance(self, store, monkeypatch) -> None:
        """AI provenance fields are included in the signed message."""
        from eth_account import Account

        acct = Account.create()

        real_wallet = MagicMock()
        real_wallet.address = acct.address
        from eth_account.messages import encode_defunct

        def _real_sign(msg_bytes):
            signable = encode_defunct(primitive=msg_bytes)
            signed = acct.sign_message(signable)
            return signed.signature.hex()

        real_wallet.sign_message = MagicMock(side_effect=_real_sign)

        monkeypatch.setattr(f"{_ENGINE_MODULE}._probe_image_digest", lambda: "sha256:abc")
        monkeypatch.setattr(
            f"{_ENGINE_MODULE}._probe_tee_platform_id",
            AsyncMock(return_value="tee-id"),
        )

        engine = AttestationEngine(wallet=real_wallet, store=store)
        proof = await engine.generate_proof(
            **_proof_kwargs(
                ai_seed=42,
                ai_output_hash="deadbeef" * 8,
                ai_system_fingerprint="gpt4-turbo-2024",
            ),
        )

        # Signature covers ai_seed, ai_output_hash, ai_system_fingerprint
        assert verify_signature(proof, acct.address)

        # Tampering with ai_seed should invalidate the signature
        tampered = AttestationProof(
            attestation_id=proof.attestation_id,
            docker_image_digest=proof.docker_image_digest,
            tee_platform_id=proof.tee_platform_id,
            pipeline_input_hash=proof.pipeline_input_hash,
            pipeline_output_hash=proof.pipeline_output_hash,
            ai_seed=999,  # changed
            ai_output_hash=proof.ai_output_hash,
            ai_system_fingerprint=proof.ai_system_fingerprint,
            signature=proof.signature,
            signer_address=proof.signer_address,
            timestamp=proof.timestamp,
            previous_attestation_id=proof.previous_attestation_id,
        )
        assert not verify_signature(tampered, acct.address)


# ═══════════════════════════════════════════════════════════════════════════════
# I. Hash verification
# ═══════════════════════════════════════════════════════════════════════════════


class TestHashVerification:
    async def test_verify_input_hash_match(self, engine) -> None:
        inputs = {"repo": "owner/repo", "commit_sha": "abc12345", "diff_hash": "deadbeef"}
        proof = await engine.generate_proof(**_proof_kwargs(inputs=inputs))
        assert verify_input_hash(proof, inputs)

    async def test_verify_output_hash_match(self, engine) -> None:
        outputs = {"findings_count": 2, "verdict": "APPROVE"}
        proof = await engine.generate_proof(**_proof_kwargs(outputs=outputs))
        assert verify_output_hash(proof, outputs)

    async def test_verify_input_hash_mismatch(self, engine) -> None:
        proof = await engine.generate_proof(**_proof_kwargs())
        assert not verify_input_hash(proof, {"different": "data"})


# ═══════════════════════════════════════════════════════════════════════════════
# J. Chain verification
# ═══════════════════════════════════════════════════════════════════════════════


class TestChainVerification:
    async def test_valid_chain(self, engine) -> None:
        p1 = await engine.generate_proof(**_proof_kwargs(action_id="a1"))
        p2 = await engine.generate_proof(**_proof_kwargs(action_id="a2"))
        p3 = await engine.generate_proof(**_proof_kwargs(action_id="a3"))

        # Chain is newest-first
        assert verify_chain([p3, p2, p1])

    async def test_broken_chain(self, engine) -> None:
        p1 = await engine.generate_proof(**_proof_kwargs(action_id="a1"))
        p2 = await engine.generate_proof(**_proof_kwargs(action_id="a2"))

        # Tamper with the link
        broken = AttestationProof(
            attestation_id=p2.attestation_id,
            docker_image_digest=p2.docker_image_digest,
            tee_platform_id=p2.tee_platform_id,
            pipeline_input_hash=p2.pipeline_input_hash,
            pipeline_output_hash=p2.pipeline_output_hash,
            signature=p2.signature,
            timestamp=p2.timestamp,
            previous_attestation_id="wrong-id",
        )
        assert not verify_chain([broken, p1])

    def test_empty_chain(self) -> None:
        assert not verify_chain([])


# ═══════════════════════════════════════════════════════════════════════════════
# K. Empty signature verification
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifySignatureEmpty:
    def test_empty_signature_returns_false(self) -> None:
        proof = AttestationProof(
            attestation_id="test",
            docker_image_digest="sha256:abc",
            tee_platform_id="tee-1",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
            signature="",
            timestamp=datetime.now(UTC),
        )
        assert not verify_signature(proof, "0x1234")


# ═══════════════════════════════════════════════════════════════════════════════
# L. API endpoint tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAPIEndpoint:
    async def test_get_attestation_200(self, intel_db) -> None:
        """Pre-populated DB returns 200 with correct data."""
        from fastapi.testclient import TestClient

        from src.api.routes.attestation import router

        # Store an attestation directly
        await intel_db.store_attestation(
            attestation_id="attest-test-123",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
            signature="sig123",
        )

        # Build a minimal FastAPI app
        from fastapi import FastAPI

        app = FastAPI()
        app.state.intel_db = intel_db
        app.include_router(router, prefix="/api/v1")

        client = TestClient(app)
        resp = client.get("/api/v1/attestation/attest-test-123")
        assert resp.status_code == 200
        data = resp.json()
        assert data["attestation_id"] == "attest-test-123"
        assert "signature_status" in data

    async def test_get_attestation_404(self, intel_db) -> None:
        """Unknown ID returns 404."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.routes.attestation import router

        app = FastAPI()
        app.state.intel_db = intel_db
        app.include_router(router, prefix="/api/v1")

        client = TestClient(app)
        resp = client.get("/api/v1/attestation/nonexistent")
        assert resp.status_code == 404

    async def test_api_unsigned_proof_returns_unsigned(self, intel_db) -> None:
        """Proof with empty signature returns signature_status='unsigned'."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.routes.attestation import router

        await intel_db.store_attestation(
            attestation_id="attest-unsigned",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
            signature="",
        )

        app = FastAPI()
        app.state.intel_db = intel_db
        app.include_router(router, prefix="/api/v1")

        client = TestClient(app)
        resp = client.get("/api/v1/attestation/attest-unsigned")
        assert resp.status_code == 200
        assert resp.json()["signature_status"] == "unsigned"

    async def test_api_unverifiable_proof(self, intel_db) -> None:
        """Proof with signature but no signer_address is 'unverifiable'."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.routes.attestation import router

        await intel_db.store_attestation(
            attestation_id="attest-nosigner",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
            signature="ab" * 32,
            signer_address="",
        )

        app = FastAPI()
        app.state.intel_db = intel_db
        app.include_router(router, prefix="/api/v1")

        client = TestClient(app)
        resp = client.get("/api/v1/attestation/attest-nosigner")
        assert resp.status_code == 200
        assert resp.json()["signature_status"] == "unverifiable"

    async def test_api_valid_signature(self, intel_db, monkeypatch) -> None:
        """Real-signed proof verified on API retrieval."""
        from eth_account import Account
        from eth_account.messages import encode_defunct
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.routes.attestation import router

        acct = Account.create()
        ts = datetime.now(UTC)

        # Build the signing message matching what the engine would produce
        input_hash = _hash_data({"key": "value"})
        output_hash = _hash_data({"result": "ok"})
        message = build_signing_message(
            chain_prefix="genesis",
            attestation_id="attest-valid-sig",
            docker_image_digest="sha256:abc",
            tee_platform_id="tee-1",
            pipeline_input_hash=input_hash,
            pipeline_output_hash=output_hash,
            timestamp=ts.isoformat(),
            ai_seed=42,
            ai_output_hash="beef" * 16,
            ai_system_fingerprint="fp-1",
        )
        signable = encode_defunct(primitive=message)
        signed = acct.sign_message(signable)
        sig_hex = signed.signature.hex()

        await intel_db.store_attestation(
            attestation_id="attest-valid-sig",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash=input_hash,
            pipeline_output_hash=output_hash,
            signature=sig_hex,
            docker_image_digest="sha256:abc",
            tee_platform_id="tee-1",
            previous_attestation_id=None,
            ai_seed=42,
            ai_output_hash="beef" * 16,
            ai_system_fingerprint="fp-1",
            signer_address=acct.address,
            created_at=ts.isoformat(),
        )

        app = FastAPI()
        app.state.intel_db = intel_db
        app.include_router(router, prefix="/api/v1")

        client = TestClient(app)
        resp = client.get("/api/v1/attestation/attest-valid-sig")
        assert resp.status_code == 200
        assert resp.json()["signature_status"] == "valid"


# ═══════════════════════════════════════════════════════════════════════════════
# M. Duplicate attestation_id handling
# ═══════════════════════════════════════════════════════════════════════════════


class TestDuplicateAttestationId:
    async def test_duplicate_id_preserves_original(self, engine, store) -> None:
        """INSERT OR IGNORE preserves the first proof; chain is not corrupted."""
        await engine.generate_proof(**_proof_kwargs(action_id="attest-dup"))

        # Generate a second proof with the same action_id
        p2 = await engine.generate_proof(**_proof_kwargs(action_id="attest-dup"))

        # p2 is returned (in-memory) but was NOT stored (duplicate)
        assert p2.attestation_id == "attest-dup"

        # The DB still has the original proof's chain linkage
        record = await store.get_attestation("attest-dup")
        assert record is not None
        # Original had previous_attestation_id = None (first proof)
        assert record["previous_attestation_id"] is None

    async def test_duplicate_does_not_break_chain(self, engine) -> None:
        """A retry after chain has advanced doesn't corrupt the chain."""
        await engine.generate_proof(**_proof_kwargs(action_id="attest-a"))
        await engine.generate_proof(**_proof_kwargs(action_id="attest-b"))

        # Retry p1 — should be a no-op, chain still points a→None, b→a
        p1_retry = await engine.generate_proof(**_proof_kwargs(action_id="attest-a"))
        assert p1_retry.attestation_id == "attest-a"

        # Chain tip should still be "attest-b"
        latest = await engine._store.get_latest_attestation_id()
        assert latest == "attest-b"


# ═══════════════════════════════════════════════════════════════════════════════
# N. AI provenance round-trip
# ═══════════════════════════════════════════════════════════════════════════════


class TestAIProvenanceRoundTrip:
    async def test_ai_fields_stored_and_retrieved(self, engine, store) -> None:
        """ai_seed, ai_output_hash, ai_system_fingerprint survive store/retrieve."""
        proof = await engine.generate_proof(
            **_proof_kwargs(
                ai_seed=12345,
                ai_output_hash="cafe" * 16,
                ai_system_fingerprint="gpt4-turbo-2024",
            ),
        )

        record = await store.get_attestation(proof.attestation_id)
        assert record is not None
        assert record["ai_seed"] == 12345
        assert record["ai_output_hash"] == "cafe" * 16
        assert record["ai_system_fingerprint"] == "gpt4-turbo-2024"

    async def test_ai_fields_none_when_not_provided(self, engine, store) -> None:
        """AI fields default to None when not provided."""
        proof = await engine.generate_proof(**_proof_kwargs())

        record = await store.get_attestation(proof.attestation_id)
        assert record is not None
        assert record["ai_seed"] is None
        assert record["ai_output_hash"] is None
        assert record["ai_system_fingerprint"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# O. Signer address
# ═══════════════════════════════════════════════════════════════════════════════


class TestSignerAddress:
    async def test_signer_address_from_wallet(self, engine) -> None:
        """Proof carries wallet.address as signer_address."""
        proof = await engine.generate_proof(**_proof_kwargs())
        assert proof.signer_address == "0x" + "0" * 40

    async def test_signer_address_stored(self, engine, store) -> None:
        """signer_address survives store/retrieve round-trip."""
        proof = await engine.generate_proof(**_proof_kwargs())
        record = await store.get_attestation(proof.attestation_id)
        assert record is not None
        assert record["signer_address"] == "0x" + "0" * 40

    async def test_signer_address_empty_when_wallet_uninitialized(
        self, engine_no_address,
    ) -> None:
        """wallet.address=None → signer_address=''."""
        proof = await engine_no_address.generate_proof(**_proof_kwargs())
        assert proof.signer_address == ""


# ═══════════════════════════════════════════════════════════════════════════════
# P. Domain-separated signing message
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuildSigningMessage:
    def test_deterministic(self) -> None:
        """Same fields → same message bytes."""
        kwargs = {
            "chain_prefix": "genesis",
            "attestation_id": "attest-1",
            "docker_image_digest": "sha256:abc",
            "tee_platform_id": "tee-1",
            "pipeline_input_hash": "a" * 64,
            "pipeline_output_hash": "b" * 64,
            "timestamp": "2026-01-01T00:00:00+00:00",
        }
        assert build_signing_message(**kwargs) == build_signing_message(**kwargs)

    def test_includes_all_fields(self) -> None:
        """Message JSON contains all expected keys."""
        msg = build_signing_message(
            chain_prefix="genesis",
            attestation_id="attest-1",
            docker_image_digest="sha256:abc",
            tee_platform_id="tee-1",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
            timestamp="2026-01-01T00:00:00+00:00",
            ai_seed=42,
            ai_output_hash="beef" * 16,
            ai_system_fingerprint="fp-1",
        )
        payload = json.loads(msg)
        assert payload["v"] == "saltax-attestation-v1"
        assert payload["ai_seed"] == 42
        assert payload["ai_output_hash"] == "beef" * 16
        assert payload["timestamp"] == "2026-01-01T00:00:00+00:00"

    def test_colons_in_fields_are_safe(self) -> None:
        """Fields containing ':' produce distinct messages (JSON escapes them)."""
        msg_a = build_signing_message(
            chain_prefix="genesis",
            attestation_id="attest:with:colons",
            docker_image_digest="sha256:abc",
            tee_platform_id="tee-1",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
            timestamp="2026-01-01T00:00:00+00:00",
        )
        msg_b = build_signing_message(
            chain_prefix="genesis",
            attestation_id="attest",
            docker_image_digest="with:colons:sha256:abc",
            tee_platform_id="tee-1",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
            timestamp="2026-01-01T00:00:00+00:00",
        )
        # These would collide in the old colon-delimited format but not in JSON
        assert msg_a != msg_b

    def test_ai_fields_change_message(self) -> None:
        """Changing AI provenance fields produces a different message."""
        base = {
            "chain_prefix": "genesis",
            "attestation_id": "attest-1",
            "docker_image_digest": "sha256:abc",
            "tee_platform_id": "tee-1",
            "pipeline_input_hash": "a" * 64,
            "pipeline_output_hash": "b" * 64,
            "timestamp": "2026-01-01T00:00:00+00:00",
        }
        msg_no_ai = build_signing_message(**base)
        msg_with_ai = build_signing_message(**base, ai_seed=42)
        assert msg_no_ai != msg_with_ai


# ═══════════════════════════════════════════════════════════════════════════════
# Q. store_attestation return value
# ═══════════════════════════════════════════════════════════════════════════════


class TestStoreReturnValue:
    async def test_first_insert_returns_true(self, intel_db) -> None:
        result = await intel_db.store_attestation(
            attestation_id="attest-new",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
        )
        assert result is True

    async def test_duplicate_returns_false(self, intel_db) -> None:
        await intel_db.store_attestation(
            attestation_id="attest-dup",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash="a" * 64,
            pipeline_output_hash="b" * 64,
        )
        result = await intel_db.store_attestation(
            attestation_id="attest-dup",
            pr_id="owner/repo#1",
            repo="owner/repo",
            pipeline_input_hash="x" * 64,
            pipeline_output_hash="y" * 64,
        )
        assert result is False

        # Original data preserved
        record = await intel_db.get_attestation("attest-dup")
        assert record is not None
        assert record["pipeline_input_hash"] == "a" * 64
