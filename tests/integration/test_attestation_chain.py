"""Integration tests: attestation chain with real crypto and real DB (Doc 27).

Uses real ``eth_account`` signing and real ``IntelligenceDB`` (SQLite on
``tmp_path``).  Verifies that proofs form a valid chain that survives DB
close/reopen and concurrent writes.
"""

from __future__ import annotations

import os

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from src.attestation.engine import AttestationEngine
from src.attestation.store import AttestationStore
from src.attestation.verifier import verify_chain
from src.intelligence.database import IntelligenceDB

_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)

if TYPE_CHECKING:
    from src.models.attestation import AttestationProof

_ = pytest  # ensure pytest is used (fixture injection)

_ENGINE_MODULE = "src.attestation.engine"


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_wallet() -> object:
    """Build a real eth_account wallet for signing."""
    from eth_account import Account  # noqa: PLC0415
    from eth_account.messages import encode_defunct  # noqa: PLC0415

    acct = Account.create()

    class _Wallet:
        address: str = acct.address

        def sign_message(self, message: bytes) -> str:
            signable = encode_defunct(primitive=message)
            signed = acct.sign_message(signable)
            return signed.signature.hex()

    return _Wallet()


def _engine(
    wallet: object, store: AttestationStore, monkeypatch: pytest.MonkeyPatch,
) -> AttestationEngine:
    """Build an AttestationEngine with env probes monkeypatched."""
    monkeypatch.setattr(f"{_ENGINE_MODULE}._probe_image_digest", lambda: "sha256:testdigest")
    monkeypatch.setattr(
        f"{_ENGINE_MODULE}._probe_tee_platform_id",
        AsyncMock(return_value="tee-test-123"),
    )
    return AttestationEngine(wallet=wallet, store=store)


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAttestationChainIntegration:
    """Real crypto + real DB chain verification."""

    async def test_generate_store_verify_three_proofs(
        self, mock_intel_db: IntelligenceDB, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Generate 3 proofs, store in real DB, verify chain integrity."""
        wallet = _make_wallet()
        store = AttestationStore(mock_intel_db)
        eng = _engine(wallet, store, monkeypatch)

        proofs: list[AttestationProof] = []
        for i in range(3):
            proof = await eng.generate_proof(
                action_id=f"action-{i}",
                pr_id=f"owner/repo#{i}",
                repo="owner/repo",
                inputs={"diff": f"diff-{i}"},
                outputs={"verdict": f"approve-{i}"},
            )
            proofs.append(proof)

        # Proofs are newest-first for verify_chain
        proofs_newest_first = list(reversed(proofs))
        assert verify_chain(proofs_newest_first)

        # Verify each proof's previous_attestation_id links correctly
        assert proofs[0].previous_attestation_id is None
        assert proofs[1].previous_attestation_id == proofs[0].attestation_id
        assert proofs[2].previous_attestation_id == proofs[1].attestation_id

    async def test_chain_survives_db_close_reopen(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Close and reopen DB — chain still valid after reload."""
        # First session: create 2 proofs
        db1 = IntelligenceDB(database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3)
        try:
            await db1.initialize()
            wallet = _make_wallet()
            store1 = AttestationStore(db1)
            eng1 = _engine(wallet, store1, monkeypatch)

            proof_0 = await eng1.generate_proof(
                action_id="reopen-0",
                pr_id="owner/repo#100",
                repo="owner/repo",
                inputs={"diff": "d0"},
                outputs={"verdict": "approve"},
            )
            proof_1 = await eng1.generate_proof(
                action_id="reopen-1",
                pr_id="owner/repo#101",
                repo="owner/repo",
                inputs={"diff": "d1"},
                outputs={"verdict": "approve"},
            )
        finally:
            await db1.close()

        # Second session: reopen, add 1 more proof
        db2 = IntelligenceDB(database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3)
        try:
            await db2.initialize()
            store2 = AttestationStore(db2)
            eng2 = _engine(wallet, store2, monkeypatch)

            proof_2 = await eng2.generate_proof(
                action_id="reopen-2",
                pr_id="owner/repo#102",
                repo="owner/repo",
                inputs={"diff": "d2"},
                outputs={"verdict": "reject"},
            )
        finally:
            await db2.close()

        # Chain should be valid across sessions
        chain = [proof_2, proof_1, proof_0]
        assert verify_chain(chain)
        assert proof_2.previous_attestation_id == proof_1.attestation_id

    async def test_concurrent_proofs_chain_valid(
        self, mock_intel_db: IntelligenceDB, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """asyncio.gather of 3 proofs → chain integrity preserved.

        The ``_chain_lock`` in ``AttestationEngine`` serializes proof
        generation, so concurrent calls should still produce a valid chain.
        """
        wallet = _make_wallet()
        store = AttestationStore(mock_intel_db)
        eng = _engine(wallet, store, monkeypatch)

        async def _gen(idx: int) -> AttestationProof:
            return await eng.generate_proof(
                action_id=f"concurrent-{idx}",
                pr_id=f"owner/repo#{idx}",
                repo="owner/repo",
                inputs={"diff": f"diff-{idx}"},
                outputs={"verdict": f"approve-{idx}"},
            )

        proofs = await asyncio.gather(_gen(0), _gen(1), _gen(2))

        # Sort by chain order (follow previous_attestation_id links)
        by_id = {p.attestation_id: p for p in proofs}
        ordered: list[AttestationProof] = []

        # Find the tail (newest — the one not referenced as previous by anyone)
        all_prev_ids = {p.previous_attestation_id for p in proofs}
        heads = [p for p in proofs if p.attestation_id not in all_prev_ids]
        if len(heads) != 1:
            raise RuntimeError(f"Expected 1 chain head, got {len(heads)}")

        current = heads[0]
        ordered.append(current)
        while current.previous_attestation_id is not None:
            current = by_id[current.previous_attestation_id]
            ordered.append(current)

        assert len(ordered) == 3
        assert verify_chain(ordered)
