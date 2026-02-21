"""Comprehensive tests for the x402 payment gateway."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.api.middleware.x402 import (
    BASE_NETWORK,
    USDC_CONTRACT_ADDRESS,
    X402_VERSION,
    PaymentRequirements,
    PaymentVerification,
    PaymentVerifier,
    build_payment_response_header,
)
from src.api.routes.audit import router as audit_router


@pytest.fixture(autouse=True)
def _reset_audit_dedup(monkeypatch):
    """Give each test a fresh _AuditDedup (clean caches, fresh asyncio.Lock)."""
    from src.api.routes import audit

    monkeypatch.setattr(audit, "_audit_dedup", audit._AuditDedup())


# ═══════════════════════════════════════════════════════════════════════════════
# PaymentRequirements
# ═══════════════════════════════════════════════════════════════════════════════


class TestPaymentRequirements:
    def test_to_header_value_encodes_valid_base64_json(self) -> None:
        """Header value decodes to valid JSON with x402 V2 structure."""
        req = PaymentRequirements(
            amount_atomic=5_000_000,
            resource="/api/v1/audit",
            description="SaltaX full audit",
            pay_to="0x" + "a" * 40,
        )
        header = req.to_header_value()

        decoded = json.loads(base64.b64decode(header))
        assert decoded["x402Version"] == X402_VERSION
        assert len(decoded["accepts"]) == 1
        accept = decoded["accepts"][0]
        assert accept["network"] == BASE_NETWORK
        assert accept["asset"] == USDC_CONTRACT_ADDRESS
        assert accept["payTo"] == "0x" + "a" * 40
        assert accept["resource"] == "/api/v1/audit"
        assert accept["scheme"] == "exact"

    def test_atomic_amount_integer_usdc(self) -> None:
        """5 USDC → '5000000' atomic units."""
        req = PaymentRequirements(
            amount_atomic=5_000_000,
            resource="/audit",
            description="test",
            pay_to="0xabc",
        )
        header = req.to_header_value()
        decoded = json.loads(base64.b64decode(header))
        assert decoded["accepts"][0]["maxAmountRequired"] == "5000000"

    def test_atomic_amount_fractional_usdc(self) -> None:
        """0.5 USDC → '500000' atomic units."""
        req = PaymentRequirements(
            amount_atomic=500_000,
            resource="/audit",
            description="test",
            pay_to="0xabc",
        )
        header = req.to_header_value()
        decoded = json.loads(base64.b64decode(header))
        assert decoded["accepts"][0]["maxAmountRequired"] == "500000"

    def test_amount_usdc_property(self) -> None:
        """amount_usdc property converts atomic → USDC float."""
        req = PaymentRequirements(
            amount_atomic=5_000_000,
            resource="/audit",
            description="test",
            pay_to="0xabc",
        )
        assert req.amount_usdc == 5.0


# ═══════════════════════════════════════════════════════════════════════════════
# build_payment_response_header
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuildPaymentResponseHeader:
    def test_encodes_valid_base64_json(self) -> None:
        header = build_payment_response_header("pay-123", "0x" + "b" * 64)
        decoded = json.loads(base64.b64decode(header))
        assert decoded["x402Version"] == X402_VERSION
        assert decoded["success"] is True
        assert decoded["paymentId"] == "pay-123"
        assert decoded["transactionHash"] == "0x" + "b" * 64


# ═══════════════════════════════════════════════════════════════════════════════
# PaymentVerifier
# ═══════════════════════════════════════════════════════════════════════════════


class TestPaymentVerifier:
    """Tests for the facilitator-based payment verification."""

    @pytest.fixture()
    def verifier(self) -> PaymentVerifier:
        return PaymentVerifier(
            facilitator_url="https://x402.org/facilitator",
            pay_to_address="0x" + "a" * 40,
        )

    @pytest.fixture()
    def requirements(self, verifier: PaymentVerifier) -> PaymentRequirements:
        return verifier.build_requirements(5.0, "/api/v1/audit", "SaltaX full audit")

    @staticmethod
    def _make_payment_header(payload: dict | None = None) -> str:
        """Encode a payment payload as base64 JSON."""
        if payload is None:
            payload = {"signature": "0xdeadbeef", "amount": "5000000"}
        return base64.b64encode(json.dumps(payload).encode()).decode()

    def test_build_requirements_uses_decimal_conversion(self) -> None:
        """Float→atomic conversion uses Decimal, not float arithmetic."""
        verifier = PaymentVerifier(
            facilitator_url="https://x402.org/facilitator",
            pay_to_address="0xabc",
        )
        # 0.1 + 0.2 = 0.30000000000000004 in float, but should be 300000 atomic
        req = verifier.build_requirements(0.3, "/audit", "test")
        assert req.amount_atomic == 300_000

    def test_facilitator_url_must_be_https(self) -> None:
        """HTTP facilitator URL raises ValueError."""
        with pytest.raises(ValueError, match="HTTPS"):
            PaymentVerifier(
                facilitator_url="http://x402.org/facilitator",
                pay_to_address="0x" + "a" * 40,
            )

    def test_facilitator_url_empty_raises(self) -> None:
        """Empty facilitator URL raises ValueError."""
        with pytest.raises(ValueError, match="HTTPS"):
            PaymentVerifier(facilitator_url="", pay_to_address="0xabc")

    async def test_missing_header_returns_invalid(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Empty header → invalid without making any HTTP call."""
        result = await verifier.verify("", requirements)
        assert not result.valid
        assert result.error == "missing_payment_header"
        assert result.amount_atomic == 0

    async def test_invalid_base64_returns_invalid(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Garbage base64 → invalid without making any HTTP call."""
        result = await verifier.verify("not-valid-base64!!!", requirements)
        assert not result.valid
        assert result.error == "invalid_base64"

    async def test_empty_payload_returns_invalid(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Base64 of empty bytes → treated as missing (encodes to empty string)."""
        empty = base64.b64encode(b"").decode()
        result = await verifier.verify(empty, requirements)
        assert not result.valid
        assert result.error == "missing_payment_header"

    async def test_oversized_header_returns_invalid(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Payment header exceeding 8KB → rejected before base64 decode."""
        huge_header = "A" * 9000
        result = await verifier.verify(huge_header, requirements)
        assert not result.valid
        assert result.error == "payment_header_too_large"

    @respx.mock
    async def test_valid_v2_facilitator_response(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """V2 response with ``verified=true`` → valid payment."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "verified": True,
                    "paymentId": "pay-123",
                    "transactionHash": "0x" + "b" * 64,
                    "payer": "0x" + "c" * 40,
                },
            )
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert result.valid
        assert result.tx_hash == "0x" + "b" * 64
        assert result.payer_address == "0x" + "c" * 40
        assert result.payment_id == "pay-123"
        assert result.amount_atomic == 5_000_000
        assert result.amount_usdc == 5.0
        assert result.error == ""

    @respx.mock
    async def test_valid_v1_facilitator_response(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """V1 response with ``valid=true`` → valid payment (backward compat)."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "valid": True,
                    "tx_hash": "0x" + "d" * 64,
                    "payer": "0x" + "e" * 40,
                },
            )
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert result.valid
        assert result.tx_hash == "0x" + "d" * 64
        assert result.payer_address == "0x" + "e" * 40
        assert result.error == ""

    @respx.mock
    async def test_facilitator_timeout(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Facilitator timeout → error='facilitator_timeout'."""
        respx.post("https://x402.org/facilitator/verify").mock(
            side_effect=httpx.ReadTimeout("read timed out")
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert not result.valid
        assert result.error == "facilitator_timeout"

    @respx.mock
    async def test_facilitator_500(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Facilitator 500 → error='facilitator_unavailable'."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(500)
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert not result.valid
        assert result.error == "facilitator_unavailable"

    @respx.mock
    async def test_facilitator_400_rejected(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Facilitator 400 → error='payment_rejected'."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(400, json={"error": "bad request"})
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert not result.valid
        assert result.error == "payment_rejected"

    @respx.mock
    async def test_facilitator_malformed_json(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Facilitator returns 200 with garbage body → error='facilitator_response_invalid'."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(200, content=b"not json at all")
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert not result.valid
        assert result.error == "facilitator_response_invalid"

    @respx.mock
    async def test_facilitator_says_not_verified(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Facilitator returns ``verified=false`` → valid=False."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(
                200,
                json={"verified": False, "reason": "insufficient funds"},
            )
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert not result.valid
        assert result.error == "payment_not_verified"

    @respx.mock
    async def test_insufficient_amount_from_facilitator(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Facilitator says verified but amount < required → insufficient_amount."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "verified": True,
                    "settledAmount": "1000000",  # 1 USDC, but 5 required
                    "transactionHash": "0x" + "a" * 64,
                    "payer": "0x" + "b" * 40,
                    "paymentId": "pay-low",
                },
            )
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert not result.valid
        assert result.error == "insufficient_amount"
        assert result.amount_atomic == 1_000_000

    @respx.mock
    async def test_sufficient_amount_from_facilitator(
        self, verifier: PaymentVerifier, requirements: PaymentRequirements
    ) -> None:
        """Facilitator says verified with amount >= required → accepted."""
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "verified": True,
                    "settledAmount": "5000000",  # exactly 5 USDC
                    "transactionHash": "0x" + "a" * 64,
                    "payer": "0x" + "b" * 40,
                    "paymentId": "pay-ok",
                },
            )
        )

        header = self._make_payment_header()
        result = await verifier.verify(header, requirements)

        assert result.valid
        assert result.amount_atomic == 5_000_000

    @respx.mock
    async def test_close_and_reuse(self) -> None:
        """After close(), verify() should lazily re-create the client."""
        verifier = PaymentVerifier(
            facilitator_url="https://x402.org/facilitator",
            pay_to_address="0x" + "a" * 40,
        )
        requirements = verifier.build_requirements(5.0, "/audit", "test")

        # First verify — creates client
        respx.post("https://x402.org/facilitator/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "verified": True,
                    "transactionHash": "0x" + "f" * 64,
                    "paymentId": "pay-456",
                },
            )
        )

        header = self._make_payment_header()
        result1 = await verifier.verify(header, requirements)
        assert result1.valid

        # Close — destroys client
        await verifier.close()
        assert verifier._client is None

        # Second verify — should lazily create new client
        result2 = await verifier.verify(header, requirements)
        assert result2.valid
        assert verifier._client is not None

        # Cleanup
        await verifier.close()


# ═══════════════════════════════════════════════════════════════════════════════
# TxHashStore
# ═══════════════════════════════════════════════════════════════════════════════


class TestTxHashStore:
    """Tests for the durable transaction hash store."""

    async def test_new_hash_returns_false(self, tmp_path) -> None:
        """First time seeing a tx_hash → returns False (not duplicate)."""
        from src.api.middleware.tx_store import TxHashStore

        store = TxHashStore(db_path=tmp_path / "tx.db")
        await store.initialize()
        try:
            result = await store.check_and_record("0x" + "a" * 64, "audit-001")
            assert result is False
        finally:
            await store.close()

    async def test_duplicate_hash_returns_true(self, tmp_path) -> None:
        """Second time seeing the same tx_hash → returns True (duplicate)."""
        from src.api.middleware.tx_store import TxHashStore

        store = TxHashStore(db_path=tmp_path / "tx.db")
        await store.initialize()
        try:
            await store.check_and_record("0x" + "b" * 64, "audit-001")
            result = await store.check_and_record("0x" + "b" * 64, "audit-002")
            assert result is True
        finally:
            await store.close()

    async def test_persistence_across_close_and_reopen(self, tmp_path) -> None:
        """tx_hash survives close() and reopen — durable storage."""
        from src.api.middleware.tx_store import TxHashStore

        db_path = tmp_path / "tx.db"

        # Write a hash and close
        store1 = TxHashStore(db_path=db_path)
        await store1.initialize()
        await store1.check_and_record("0x" + "c" * 64, "audit-001")
        await store1.close()

        # Reopen and check
        store2 = TxHashStore(db_path=db_path)
        await store2.initialize()
        try:
            result = await store2.check_and_record("0x" + "c" * 64, "audit-002")
            assert result is True  # Still seen after restart
        finally:
            await store2.close()

    async def test_empty_hash_returns_false(self, tmp_path) -> None:
        """Empty tx_hash is treated as 'not seen' (no-op)."""
        from src.api.middleware.tx_store import TxHashStore

        store = TxHashStore(db_path=tmp_path / "tx.db")
        await store.initialize()
        try:
            result = await store.check_and_record("", "audit-001")
            assert result is False
        finally:
            await store.close()

    async def test_uninitialized_raises_runtime_error(self, tmp_path) -> None:
        """Calling check_and_record before initialize() raises RuntimeError."""
        from src.api.middleware.tx_store import TxHashStore

        store = TxHashStore(db_path=tmp_path / "tx.db")
        with pytest.raises(RuntimeError, match="not initialized"):
            await store.check_and_record("0xabc", "audit-001")


# ═══════════════════════════════════════════════════════════════════════════════
# Audit Route Integration
# ═══════════════════════════════════════════════════════════════════════════════


def _make_test_app(
    *,
    verifier_mock: MagicMock | None = None,
    treasury_mock: MagicMock | None = None,
    pipeline_mock: AsyncMock | None = None,
    tx_store_mock: AsyncMock | None = None,
) -> FastAPI:
    """Build a minimal test app with mocked dependencies."""
    app = FastAPI()
    app.include_router(audit_router, prefix="/api/v1")

    config = MagicMock()
    config.audit_pricing.security_only_usdc = 5.0
    config.audit_pricing.quality_only_usdc = 3.0
    config.audit_pricing.full_audit_usdc = 10.0

    app.state.config = config
    app.state.pipeline = pipeline_mock or AsyncMock()
    if treasury_mock is None:
        treasury_mock = MagicMock()
        treasury_mock.record_incoming = AsyncMock()
    app.state.treasury_mgr = treasury_mock
    app.state.payment_verifier = verifier_mock or MagicMock()

    # Default tx_store mock: never seen any tx_hash
    if tx_store_mock is None:
        tx_store_mock = AsyncMock()
        tx_store_mock.check_and_record = AsyncMock(return_value=False)
    app.state.tx_store = tx_store_mock

    return app


def _mock_verifier(
    *,
    valid: bool = True,
    amount_atomic: int = 5_000_000,
    payer_address: str = "0x" + "c" * 40,
    tx_hash: str = "0x" + "b" * 64,
    payment_id: str = "pay-test-123",
    error: str = "",
) -> MagicMock:
    """Create a mock PaymentVerifier returning the given verification result."""
    mock = MagicMock()
    mock.build_requirements.return_value = PaymentRequirements(
        amount_atomic=amount_atomic,
        resource="/api/v1/audit",
        description="SaltaX full audit",
        pay_to="0x" + "a" * 40,
    )
    mock.verify = AsyncMock(
        return_value=PaymentVerification(
            valid=valid,
            amount_atomic=amount_atomic if valid else 0,
            payer_address=payer_address if valid else "",
            tx_hash=tx_hash if valid else "",
            payment_id=payment_id if valid else "",
            error=error,
        )
    )
    return mock


_AUDIT_BODY = {
    "repository_url": "https://github.com/owner/repo",
    "commit_sha": "abc123",
    "scope": "full",
}


class TestAuditRouteX402:
    """x402-specific audit route tests."""

    async def test_no_payment_returns_402_with_payment_required_header(self) -> None:
        """Missing payment header → 402 immediately (no facilitator call)."""
        mock_v = _mock_verifier(valid=False, error="missing_payment_header")
        app = _make_test_app(verifier_mock=mock_v)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post("/api/v1/audit", json=_AUDIT_BODY)

        assert r.status_code == 402
        assert "PAYMENT-REQUIRED" in r.headers
        data = r.json()
        assert data["error"] == "Payment Required"
        # Verify the mock verifier was NOT called (short-circuit)
        mock_v.verify.assert_not_called()

    async def test_payment_required_header_has_correct_structure(self) -> None:
        """PAYMENT-REQUIRED header decodes to valid x402 V2 JSON."""
        mock_v = _mock_verifier(valid=False, error="missing_payment_header")
        app = _make_test_app(verifier_mock=mock_v)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post("/api/v1/audit", json=_AUDIT_BODY)

        header = r.headers["PAYMENT-REQUIRED"]
        decoded = json.loads(base64.b64decode(header))
        assert decoded["x402Version"] == 2
        assert len(decoded["accepts"]) == 1
        accept = decoded["accepts"][0]
        assert accept["asset"] == USDC_CONTRACT_ADDRESS
        assert accept["network"] == BASE_NETWORK

    async def test_valid_payment_returns_202_with_receipt(self) -> None:
        """Valid payment → 202 with tx_hash, payment_id, and PAYMENT-RESPONSE header."""
        mock_v = _mock_verifier(valid=True)
        app = _make_test_app(verifier_mock=mock_v)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/repo-receipt",
                    "commit_sha": "receipt123",
                    "scope": "full",
                },
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )

        assert r.status_code == 202
        data = r.json()
        assert data["status"] == "accepted"
        assert data["payment_tx_hash"] == "0x" + "b" * 64
        assert data["payment_id"] == "pay-test-123"
        assert data["payment_amount_usdc"] == 5.0
        assert "PAYMENT-RESPONSE" in r.headers

        # Verify PAYMENT-RESPONSE header structure
        resp_header = json.loads(base64.b64decode(r.headers["PAYMENT-RESPONSE"]))
        assert resp_header["x402Version"] == 2
        assert resp_header["success"] is True
        assert resp_header["paymentId"] == "pay-test-123"

    async def test_facilitator_timeout_returns_503_and_releases_slot(self) -> None:
        """Facilitator timeout → 503 + Retry-After, slot released for retry."""
        mock_v = _mock_verifier(valid=False, error="facilitator_timeout")
        app = _make_test_app(verifier_mock=mock_v)
        unique_body = {
            "repository_url": "https://github.com/owner/timeout-repo",
            "commit_sha": "timeout123",
            "scope": "full",
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r1 = await c.post(
                "/api/v1/audit",
                json=unique_body,
                headers={"X-PAYMENT": "dGVzdA=="},
            )
            assert r1.status_code == 503
            assert r1.headers["Retry-After"] == "30"

            # Slot should be released — next request with valid payment should work
            mock_v_valid = _mock_verifier(valid=True, tx_hash="0x" + "1" * 64)
            app.state.payment_verifier = mock_v_valid
            r2 = await c.post(
                "/api/v1/audit",
                json=unique_body,
                headers={"X-PAYMENT": "dGVzdA=="},
            )
            assert r2.status_code == 202
            assert r2.json()["status"] == "accepted"

    async def test_facilitator_500_returns_503(self) -> None:
        """Facilitator 500 → 503 with Retry-After: 60."""
        mock_v = _mock_verifier(valid=False, error="facilitator_unavailable")
        app = _make_test_app(verifier_mock=mock_v)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/500-repo",
                    "commit_sha": "err500",
                    "scope": "full",
                },
                headers={"X-PAYMENT": "dGVzdA=="},
            )

        assert r.status_code == 503
        assert r.headers["Retry-After"] == "60"

    async def test_invalid_payment_releases_slot(self) -> None:
        """Invalid payment → 402, slot released so next valid payment works."""
        mock_v_invalid = _mock_verifier(valid=False, error="payment_not_verified")
        app = _make_test_app(verifier_mock=mock_v_invalid)
        unique_body = {
            "repository_url": "https://github.com/owner/invalid-then-valid",
            "commit_sha": "itv123",
            "scope": "full",
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # First attempt — bad payment
            r1 = await c.post(
                "/api/v1/audit",
                json=unique_body,
                headers={"X-PAYMENT": "dGVzdA=="},
            )
            assert r1.status_code == 402

            # Swap to valid verifier — slot should be free
            mock_v_valid = _mock_verifier(valid=True, tx_hash="0x" + "2" * 64)
            app.state.payment_verifier = mock_v_valid
            r2 = await c.post(
                "/api/v1/audit",
                json=unique_body,
                headers={"X-PAYMENT": "dGVzdA=="},
            )
            assert r2.status_code == 202
            assert r2.json()["status"] == "accepted"

    async def test_idempotent_request_returns_same_audit_id(self) -> None:
        """Two identical requests → same audit_id, second is 'already_processing'."""
        mock_v = _mock_verifier(valid=True)
        app = _make_test_app(verifier_mock=mock_v)
        unique_body = {
            "repository_url": "https://github.com/owner/idempotent-repo",
            "commit_sha": "idemp123",
            "scope": "full",
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r1 = await c.post(
                "/api/v1/audit",
                json=unique_body,
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )
            r2 = await c.post(
                "/api/v1/audit",
                json=unique_body,
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )

        d1 = r1.json()
        d2 = r2.json()
        assert r1.status_code == 202
        assert r2.status_code == 202
        assert d1["audit_id"] == d2["audit_id"]
        assert d1["status"] == "accepted"
        assert d2["status"] == "already_processing"
        # Second response should NOT contain unverified payment info
        assert "payment_tx_hash" not in d2
        assert "payment_id" not in d2

    async def test_concurrent_dedup_single_pipeline_run(self) -> None:
        """Two simultaneous requests → pipeline.run queued at most once."""
        import asyncio

        mock_v = _mock_verifier(valid=True)
        pipeline_mock = AsyncMock()
        pipeline_mock.run.return_value = {}
        app = _make_test_app(verifier_mock=mock_v, pipeline_mock=pipeline_mock)
        unique_body = {
            "repository_url": "https://github.com/owner/concurrent-repo",
            "commit_sha": "conc123",
            "scope": "full",
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r1, r2 = await asyncio.gather(
                c.post(
                    "/api/v1/audit",
                    json=unique_body,
                    headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
                ),
                c.post(
                    "/api/v1/audit",
                    json=unique_body,
                    headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
                ),
            )

        assert r1.status_code == 202
        assert r2.status_code == 202

        # Exactly one should be "accepted" (pipeline queued), the other "already_processing"
        statuses = sorted([r1.json()["status"], r2.json()["status"]])
        assert statuses == ["accepted", "already_processing"]

    async def test_revenue_recorded_on_valid_payment(self) -> None:
        """Valid payment records revenue with atomic amount and USDC currency."""
        mock_v = _mock_verifier(valid=True, amount_atomic=10_000_000)
        treasury_mock = MagicMock()
        treasury_mock.record_incoming = AsyncMock()
        app = _make_test_app(verifier_mock=mock_v, treasury_mock=treasury_mock)
        unique_body = {
            "repository_url": "https://github.com/owner/revenue-repo",
            "commit_sha": "rev123",
            "scope": "full",
        }

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post(
                "/api/v1/audit",
                json=unique_body,
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )

        assert r.status_code == 202
        treasury_mock.record_incoming.assert_called_once()
        call_kwargs = treasury_mock.record_incoming.call_args.kwargs
        assert call_kwargs["tx_type"] == "audit_fee_usdc"
        assert call_kwargs["amount_wei"] == 10_000_000  # Atomic units, not float
        assert call_kwargs["currency"] == "USDC"
        assert call_kwargs["counterparty"] == "0x" + "c" * 40
        assert call_kwargs["tx_hash"] == "0x" + "b" * 64

    async def test_supports_both_v1_and_v2_headers(self) -> None:
        """Both X-PAYMENT and PAYMENT-SIGNATURE headers are accepted."""
        mock_v = _mock_verifier(valid=True)

        # Test with V2 header (PAYMENT-SIGNATURE)
        app1 = _make_test_app(verifier_mock=mock_v)
        transport1 = ASGITransport(app=app1)
        async with AsyncClient(transport=transport1, base_url="http://test") as c:
            r1 = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/v2-header-repo",
                    "commit_sha": "v2h123",
                    "scope": "full",
                },
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )
        assert r1.status_code == 202

        # Test with V1 header (X-PAYMENT) — need new mock to reset
        mock_v2 = _mock_verifier(valid=True, tx_hash="0x" + "3" * 64)
        app2 = _make_test_app(verifier_mock=mock_v2)
        transport2 = ASGITransport(app=app2)
        async with AsyncClient(transport=transport2, base_url="http://test") as c:
            r2 = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/v1-header-repo",
                    "commit_sha": "v1h123",
                    "scope": "full",
                },
                headers={"X-PAYMENT": "dGVzdA=="},
            )
        assert r2.status_code == 202

        # Both should have passed a non-empty header to verify
        v1_call_header = mock_v2.verify.call_args[0][0]
        v2_call_header = mock_v.verify.call_args[0][0]
        assert v1_call_header == "dGVzdA=="
        assert v2_call_header == "dGVzdA=="

    async def test_tx_hash_replay_returns_409(self) -> None:
        """Same tx_hash used for different audits → 409 Conflict (via durable store)."""
        shared_tx_hash = "0x" + "9" * 64
        mock_v = _mock_verifier(valid=True, tx_hash=shared_tx_hash)

        # tx_store that says "already seen" on the second call
        tx_store_mock = AsyncMock()
        tx_store_mock.check_and_record = AsyncMock(side_effect=[False, True])

        app = _make_test_app(verifier_mock=mock_v, tx_store_mock=tx_store_mock)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # First audit — succeeds
            r1 = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/replay-repo-1",
                    "commit_sha": "replay1",
                    "scope": "full",
                },
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )
            assert r1.status_code == 202
            assert r1.json()["status"] == "accepted"

            # Second audit with SAME tx_hash but DIFFERENT repo → 409
            r2 = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/replay-repo-2",
                    "commit_sha": "replay2",
                    "scope": "full",
                },
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )
            assert r2.status_code == 409
            assert r2.json()["error"] == "Conflict"

    async def test_callback_url_ignored_as_extra_field(self) -> None:
        """callback_url is no longer a declared field — Pydantic ignores extra fields."""
        mock_v = _mock_verifier(valid=True)
        app = _make_test_app(verifier_mock=mock_v)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.post(
                "/api/v1/audit",
                json={
                    "repository_url": "https://github.com/owner/callback-test",
                    "commit_sha": "cb123",
                    "scope": "full",
                    "callback_url": "https://example.com/callback",
                },
                headers={"PAYMENT-SIGNATURE": "dGVzdA=="},
            )
        # Should not 422 — extra field is silently ignored
        assert r.status_code == 202
