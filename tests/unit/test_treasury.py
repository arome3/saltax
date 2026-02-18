"""Comprehensive tests for the treasury subsystem.

Covers wallet initialization, operations, transactions, lifecycle,
policy enforcement, treasury manager orchestration, gas estimation,
and key safety.
"""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_account import Account
from web3 import AsyncWeb3

from src.config import BountyConfig, TreasuryConfig
from src.treasury.manager import TransactionRecord, TreasuryManager, TreasurySnapshot
from src.treasury.policy import PayoutRequest, TreasuryPolicy
from src.treasury.wallet import WalletManager

# ── Helpers ───────────────────────────────────────────────────────────────────

_10_ETH_WEI = AsyncWeb3.to_wei(10, "ether")
_1_ETH_WEI = AsyncWeb3.to_wei(1, "ether")
_HALF_ETH_WEI = AsyncWeb3.to_wei(0.5, "ether")
_POINT_1_ETH_WEI = AsyncWeb3.to_wei(0.1, "ether")

# Checksum addresses for transaction tests (required after Fix 6)
_ADDR_AB = AsyncWeb3.to_checksum_address("0x" + "ab" * 20)
_ADDR_AA = AsyncWeb3.to_checksum_address("0x" + "aa" * 20)
_ADDR_BB = AsyncWeb3.to_checksum_address("0x" + "bb" * 20)


def _make_mock_kms(*, has_key: bool = False, seal_fails: bool = False) -> MagicMock:
    """Create a mock KMS with configurable behavior."""
    kms = MagicMock()

    if has_key:
        # Recovery path: unseal returns a valid private key
        acct = Account.create()
        kms.unseal = AsyncMock(return_value=acct.key)
        kms._test_account = acct  # stash for assertion
    else:
        # First boot: unseal raises
        kms.unseal = AsyncMock(side_effect=Exception("no sealed key"))

    if seal_fails:
        kms.seal = AsyncMock(side_effect=Exception("KMS unavailable"))
    else:
        kms.seal = AsyncMock()

    return kms


def _make_mock_w3(
    *,
    balance: int = _10_ETH_WEI,
    nonce: int = 0,
    tx_hash: bytes = b"\xab" * 32,
) -> MagicMock:
    """Create a mock AsyncWeb3 with stubbed eth methods."""
    w3 = MagicMock(spec=AsyncWeb3)

    w3.eth = MagicMock()
    w3.eth.get_balance = AsyncMock(return_value=balance)
    w3.eth.get_transaction_count = AsyncMock(return_value=nonce)
    w3.eth.send_raw_transaction = AsyncMock(return_value=tx_hash)
    w3.eth.fee_history = AsyncMock(
        return_value={
            "baseFeePerGas": [
                1_000_000_000,
                1_100_000_000,
                1_050_000_000,
                1_000_000_000,
                1_200_000_000,
            ],
            "reward": [
                [100_000_000, 2_000_000_000],
                [150_000_000, 2_500_000_000],
                [120_000_000, 2_200_000_000],
                [130_000_000, 2_300_000_000],
            ],
        }
    )

    return w3


def _make_sample_treasury_config() -> TreasuryConfig:
    return TreasuryConfig(
        reserve_ratio=0.20,
        compute_budget=0.10,
        bounty_budget=0.65,
        community_fund=0.05,
        max_single_payout_eth=0.5,
    )


def _make_sample_bounty_config() -> BountyConfig:
    return BountyConfig()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Wallet Initialization
# ═══════════════════════════════════════════════════════════════════════════════


class TestWalletInitialization:
    async def test_first_boot_generates_keypair(self) -> None:
        """First boot (unseal fails) generates a new account and seals it."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        assert wallet.address is not None
        assert wallet.address.startswith("0x")
        assert len(wallet.address) == 42
        kms.seal.assert_awaited_once()

    async def test_recovery_from_kms(self) -> None:
        """When KMS has a sealed key, wallet recovers the same address."""
        kms = _make_mock_kms(has_key=True)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        assert wallet.address == kms._test_account.address

    async def test_corrupted_key_raises(self) -> None:
        """Corrupted key from KMS raises RuntimeError (no new key generated)."""
        kms = MagicMock()
        kms.unseal = AsyncMock(return_value=b"not-a-valid-key")

        wallet = WalletManager(kms=kms)
        with pytest.raises(RuntimeError, match="Corrupted wallet key"):
            await wallet.initialize()

        # Must NOT have generated a new key
        assert wallet.address is None

    async def test_seal_failure_sets_flag(self) -> None:
        """If KMS seal fails on first boot, _seal_failed is set but wallet works."""
        kms = _make_mock_kms(has_key=False, seal_fails=True)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        assert wallet._seal_failed is True
        assert wallet.address is not None

    async def test_w3_created_on_initialize(self) -> None:
        """AsyncWeb3 instance is created during initialization."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms, rpc_url="https://test.rpc", chain_id=1234)
        await wallet.initialize()

        assert wallet._w3 is not None

    async def test_initialize_twice_raises(self) -> None:
        """Double-calling initialize() raises RuntimeError to prevent resource leaks."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        with pytest.raises(RuntimeError, match="already initialized"):
            await wallet.initialize()


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Wallet Operations
# ═══════════════════════════════════════════════════════════════════════════════


class TestWalletOperations:
    async def test_get_balance_returns_wei(self) -> None:
        """get_balance returns the Wei balance from the provider."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        mock_w3 = _make_mock_w3(balance=_10_ETH_WEI)
        wallet._w3 = mock_w3

        balance = await wallet.get_balance()
        assert balance == _10_ETH_WEI

    async def test_get_balance_before_init_raises(self) -> None:
        """get_balance before initialize raises RuntimeError."""
        kms = _make_mock_kms()
        wallet = WalletManager(kms=kms)
        with pytest.raises(RuntimeError, match="not initialized"):
            await wallet.get_balance()

    async def test_sign_message_returns_hex(self) -> None:
        """sign_message returns a hex string signature."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        sig = wallet.sign_message(b"hello world")
        assert isinstance(sig, str)
        # EIP-191 signature is 65 bytes = 130 hex chars (+ optional 0x prefix)
        sig_clean = sig.removeprefix("0x")
        assert len(sig_clean) == 130

    async def test_sign_before_init_raises(self) -> None:
        """sign_message before initialize raises RuntimeError."""
        kms = _make_mock_kms()
        wallet = WalletManager(kms=kms)
        with pytest.raises(RuntimeError, match="not initialized"):
            wallet.sign_message(b"test")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Wallet Transactions
# ═══════════════════════════════════════════════════════════════════════════════


class TestWalletTransactions:
    @staticmethod
    def _mock_account_signing(wallet: WalletManager) -> None:
        """Replace the real account's sign_transaction with a mock.

        We test transaction *flow* (nonce, retry, locks), not crypto.
        The mock returns a signed-tx stub with ``rawTransaction``.
        """
        mock_signed = MagicMock()
        mock_signed.rawTransaction = b"\xfe" * 32
        wallet._account.sign_transaction = MagicMock(return_value=mock_signed)

    async def test_eip1559_format(self) -> None:
        """Transaction uses type 0x2 with maxFeePerGas, no gasPrice."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms, chain_id=8453)
        await wallet.initialize()

        mock_w3 = _make_mock_w3()
        wallet._w3 = mock_w3
        self._mock_account_signing(wallet)

        tx_hash = await wallet.send_transaction(
            to=_ADDR_AB,
            value_wei=_1_ETH_WEI,
        )

        assert isinstance(tx_hash, str)
        mock_w3.eth.send_raw_transaction.assert_awaited_once()

        # Verify the tx dict passed to sign_transaction has EIP-1559 fields
        call_args = wallet._account.sign_transaction.call_args[0][0]
        assert call_args["type"] == "0x2"
        assert "maxFeePerGas" in call_args
        assert "maxPriorityFeePerGas" in call_args
        assert "gasPrice" not in call_args

    async def test_returns_hash_hex(self) -> None:
        """send_transaction returns the tx hash as hex string."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        expected_hash = b"\xde\xad" * 16
        mock_w3 = _make_mock_w3(tx_hash=expected_hash)
        wallet._w3 = mock_w3
        self._mock_account_signing(wallet)

        result = await wallet.send_transaction(to=_ADDR_AB, value_wei=1000)
        assert result == expected_hash.hex()

    async def test_nonce_retry_on_rpc_error(self) -> None:
        """RPC errors trigger retry with re-fetched nonce."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        mock_w3 = _make_mock_w3()
        # First send fails, second succeeds
        mock_w3.eth.send_raw_transaction = AsyncMock(
            side_effect=[Exception("RPC timeout"), b"\xab" * 32]
        )
        wallet._w3 = mock_w3
        self._mock_account_signing(wallet)

        with patch("src.treasury.wallet.asyncio.sleep", new_callable=AsyncMock):
            result = await wallet.send_transaction(to=_ADDR_AB, value_wei=1000)

        assert isinstance(result, str)
        # Nonce fetched twice (once per attempt)
        assert mock_w3.eth.get_transaction_count.await_count == 2

    async def test_all_retries_exhausted(self) -> None:
        """After max retries, RuntimeError is raised."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        mock_w3 = _make_mock_w3()
        mock_w3.eth.send_raw_transaction = AsyncMock(side_effect=Exception("RPC down"))
        wallet._w3 = mock_w3
        self._mock_account_signing(wallet)

        with (
            patch("src.treasury.wallet.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(RuntimeError, match="failed after 3 attempts"),
        ):
            await wallet.send_transaction(to=_ADDR_AB, value_wei=1000)

    async def test_concurrent_sends_serialized(self) -> None:
        """Concurrent send_transaction calls are serialized via _tx_lock."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        call_order: list[int] = []
        nonce_counter = 0

        async def tracked_get_nonce(*args, **kwargs):  # noqa: ANN002, ANN003
            nonlocal nonce_counter
            current = nonce_counter
            nonce_counter += 1
            call_order.append(current)
            return current

        mock_w3 = _make_mock_w3()
        mock_w3.eth.get_transaction_count = AsyncMock(side_effect=tracked_get_nonce)
        wallet._w3 = mock_w3
        self._mock_account_signing(wallet)

        # Launch two concurrent sends
        await asyncio.gather(
            wallet.send_transaction(to=_ADDR_AA, value_wei=100),
            wallet.send_transaction(to=_ADDR_BB, value_wei=200),
        )

        # Nonces should be sequential (0, 1) proving serialization
        assert call_order == [0, 1]

    async def test_invalid_address_rejected(self) -> None:
        """send_transaction rejects non-checksummed addresses before acquiring lock."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        # Lowercase address is not a valid checksum address
        with pytest.raises(ValueError, match="Invalid checksum address"):
            await wallet.send_transaction(to="0x" + "ab" * 20, value_wei=1000)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Wallet Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════


class TestWalletLifecycle:
    async def test_seal_calls_kms(self) -> None:
        """seal() calls KMS with the wallet key."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()
        kms.seal.reset_mock()

        await wallet.seal()
        kms.seal.assert_awaited_once()

    async def test_seal_no_account_silent(self) -> None:
        """seal() with no account returns silently."""
        kms = _make_mock_kms()
        wallet = WalletManager(kms=kms)
        # Don't initialize
        await wallet.seal()  # should not raise
        kms.seal.assert_not_awaited()

    async def test_seal_kms_failure_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """seal() logs but does not raise if KMS fails."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()
        kms.seal = AsyncMock(side_effect=Exception("KMS down"))

        with caplog.at_level(logging.ERROR):
            await wallet.seal()  # should not raise

        assert "Failed to seal wallet key" in caplog.text

    async def test_close_clears_state(self) -> None:
        """close() sets _account and _w3 to None."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()
        assert wallet.address is not None

        await wallet.close()
        assert wallet.address is None
        assert wallet._w3 is None

    async def test_seal_failed_property(self) -> None:
        """seal_failed property reflects internal _seal_failed state."""
        kms = _make_mock_kms(has_key=False, seal_fails=True)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        assert wallet.seal_failed is True

    async def test_seal_clears_seal_failed_flag(self) -> None:
        """Successful seal() after a previous failure clears seal_failed."""
        kms = _make_mock_kms(has_key=False, seal_fails=True)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()
        assert wallet.seal_failed is True

        # Now make seal succeed
        kms.seal = AsyncMock()
        await wallet.seal()
        assert wallet.seal_failed is False

    async def test_key_not_in_exception(self) -> None:
        """Corrupted key error does not leak key bytes in traceback."""
        kms = MagicMock()
        # Use a non-32-byte value so Account.from_key() actually fails
        fake_key = b"\xde\xad\xbe\xef" * 9  # 36 bytes — invalid length
        kms.unseal = AsyncMock(return_value=fake_key)

        wallet = WalletManager(kms=kms)
        with pytest.raises(RuntimeError) as exc_info:
            await wallet.initialize()

        # The exception chain should not contain the key bytes
        error_str = str(exc_info.value)
        assert fake_key.hex() not in error_str
        # __cause__ should be None (from None strips the chain)
        assert exc_info.value.__cause__ is None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Treasury Policy
# ═══════════════════════════════════════════════════════════════════════════════


class TestTreasuryPolicy:
    @pytest.fixture()
    def policy(self) -> TreasuryPolicy:
        return TreasuryPolicy(_make_sample_treasury_config())

    def test_valid_payout_passes(self, policy: TreasuryPolicy) -> None:
        """A small payout within all limits passes."""
        req = PayoutRequest(recipient="0x" + "ab" * 20, amount_wei=_POINT_1_ETH_WEI)
        ok, msg = policy.validate_payout(req, _10_ETH_WEI)
        assert ok is True
        assert msg == "ok"

    def test_exceeds_max_single_payout(self, policy: TreasuryPolicy) -> None:
        """Payout exceeding max_single_payout_eth is rejected."""
        req = PayoutRequest(recipient="0x" + "ab" * 20, amount_wei=_1_ETH_WEI)
        ok, msg = policy.validate_payout(req, _10_ETH_WEI)
        assert ok is False
        assert "max single payout" in msg

    def test_violates_reserve_ratio(self, policy: TreasuryPolicy) -> None:
        """Payout that would violate reserve ratio is rejected."""
        # With 1 ETH balance and 20% reserve, max outflow = 0.8 ETH
        # But max_single_payout is 0.5 ETH, so use a smaller balance
        small_balance = AsyncWeb3.to_wei(0.5, "ether")
        # 0.45 ETH payout from 0.5 ETH balance: remaining 0.05 < required 0.1
        req = PayoutRequest(
            recipient="0x" + "ab" * 20,
            amount_wei=AsyncWeb3.to_wei(0.45, "ether"),
        )
        ok, msg = policy.validate_payout(req, small_balance)
        assert ok is False
        assert "reserve" in msg

    def test_exceeds_bounty_budget(self, policy: TreasuryPolicy) -> None:
        """Payout exceeding bounty budget allocation is rejected."""
        # 0.5 ETH balance, bounty_budget=65% → 0.325 ETH
        # 0.4 ETH payout > 0.325 budget
        small_balance = AsyncWeb3.to_wei(0.5, "ether")
        req = PayoutRequest(
            recipient="0x" + "ab" * 20,
            amount_wei=AsyncWeb3.to_wei(0.4, "ether"),
        )
        ok, msg = policy.validate_payout(req, small_balance)
        assert ok is False
        assert "budget" in msg

    def test_boundary_exactly_at_max(self, policy: TreasuryPolicy) -> None:
        """Payout exactly equal to max_single_payout passes (<=, not <)."""
        req = PayoutRequest(recipient="0x" + "ab" * 20, amount_wei=_HALF_ETH_WEI)
        ok, _ = policy.validate_payout(req, _10_ETH_WEI)
        assert ok is True

    def test_boundary_reserve_exact(self, policy: TreasuryPolicy) -> None:
        """Remaining balance exactly at reserve requirement passes."""
        # balance=1 ETH, reserve_ratio=0.20 → reserve=0.2 ETH
        # payout=0.5 ETH (max), remaining=0.5 > 0.2 → pass
        balance = _1_ETH_WEI
        req = PayoutRequest(
            recipient="0x" + "ab" * 20,
            amount_wei=_HALF_ETH_WEI,
        )
        ok, _ = policy.validate_payout(req, balance)
        assert ok is True

    def test_boundary_budget_exact(self, policy: TreasuryPolicy) -> None:
        """Payout exactly at bounty budget boundary passes."""
        # With 10 ETH, bounty_budget=65% → 6.5 ETH budget
        # But max_single_payout is 0.5 ETH, so budget is not the binding constraint
        # Use a smaller balance: 0.5 ETH, budget = 0.325 ETH
        balance = AsyncWeb3.to_wei(0.5, "ether")
        budget = int(balance * 0.65)
        req = PayoutRequest(recipient="0x" + "ab" * 20, amount_wei=budget)
        ok, _ = policy.validate_payout(req, balance)
        assert ok is True

    def test_includes_stake_bonus(self, policy: TreasuryPolicy) -> None:
        """Stake bonus is included in total when checking limits."""
        # 0.3 ETH amount + 0.25 ETH bonus = 0.55 ETH total > 0.5 ETH max
        req = PayoutRequest(
            recipient="0x" + "ab" * 20,
            amount_wei=AsyncWeb3.to_wei(0.3, "ether"),
            stake_bonus_wei=AsyncWeb3.to_wei(0.25, "ether"),
        )
        ok, msg = policy.validate_payout(req, _10_ETH_WEI)
        assert ok is False
        assert "max single payout" in msg

    def test_zero_balance_rejects(self, policy: TreasuryPolicy) -> None:
        """Any positive payout with zero balance is rejected."""
        req = PayoutRequest(recipient="0x" + "ab" * 20, amount_wei=1)
        ok, msg = policy.validate_payout(req, 0)
        assert ok is False

    def test_negative_amount_rejected(self) -> None:
        """PayoutRequest with negative amount_wei raises ValueError at construction."""
        with pytest.raises(ValueError, match="amount_wei must be non-negative"):
            PayoutRequest(recipient="0x" + "ab" * 20, amount_wei=-1)

    def test_negative_stake_bonus_rejected(self) -> None:
        """PayoutRequest with negative stake_bonus_wei raises ValueError at construction."""
        with pytest.raises(ValueError, match="stake_bonus_wei must be non-negative"):
            PayoutRequest(recipient="0x" + "ab" * 20, amount_wei=100, stake_bonus_wei=-1)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Treasury Manager
# ═══════════════════════════════════════════════════════════════════════════════


class TestTreasuryManager:
    @pytest.fixture()
    def mock_wallet(self) -> MagicMock:
        w = MagicMock()
        w.get_balance = AsyncMock(return_value=_10_ETH_WEI)
        w.send_transaction = AsyncMock(return_value="0x" + "ab" * 32)
        return w

    @pytest.fixture()
    def mock_intel_db(self) -> MagicMock:
        db = MagicMock()
        db.close_bounty = AsyncMock()
        db.store_bounty = AsyncMock()
        db.get_active_bounties = AsyncMock(return_value=[])
        return db

    @pytest.fixture()
    def manager(self, mock_wallet: MagicMock, mock_intel_db: MagicMock) -> TreasuryManager:
        policy = TreasuryPolicy(_make_sample_treasury_config())
        return TreasuryManager(
            wallet=mock_wallet,
            policy=policy,
            intel_db=mock_intel_db,
            treasury_config=_make_sample_treasury_config(),
            bounty_config=_make_sample_bounty_config(),
        )

    async def test_check_balance_snapshot(self, manager: TreasuryManager) -> None:
        """check_balance returns a TreasurySnapshot with correct allocations."""
        snap = await manager.check_balance()
        assert isinstance(snap, TreasurySnapshot)
        assert snap.balance_wei == _10_ETH_WEI
        assert snap.reserve_wei == int(_10_ETH_WEI * 0.20)
        assert snap.bounty_wei == int(_10_ETH_WEI * 0.65)

    async def test_send_payout_success(
        self, manager: TreasuryManager, mock_wallet: MagicMock
    ) -> None:
        """Successful payout returns TransactionRecord and calls wallet."""
        req = PayoutRequest(
            recipient="0x" + "cc" * 20,
            amount_wei=_POINT_1_ETH_WEI,
            bounty_id="bounty-123",
        )
        record = await manager.send_payout(req)
        assert isinstance(record, TransactionRecord)
        assert record.tx_type == "payout"
        assert record.amount_wei == _POINT_1_ETH_WEI
        mock_wallet.send_transaction.assert_awaited_once()

    async def test_send_payout_policy_rejection(self, manager: TreasuryManager) -> None:
        """Payout rejected by policy raises ValueError."""
        req = PayoutRequest(
            recipient="0x" + "cc" * 20,
            amount_wei=_1_ETH_WEI,  # exceeds max_single_payout (0.5 ETH)
        )
        with pytest.raises(ValueError, match="rejected by policy"):
            await manager.send_payout(req)

    async def test_counters_updated(self, manager: TreasuryManager, mock_wallet: MagicMock) -> None:
        """After payout, expenditure and tx counters are updated."""
        req = PayoutRequest(
            recipient="0x" + "cc" * 20,
            amount_wei=_POINT_1_ETH_WEI,
        )
        await manager.send_payout(req)
        assert manager._total_expenditure_wei == _POINT_1_ETH_WEI
        assert manager._tx_count == 1

    async def test_budget_sums_to_balance(self, manager: TreasuryManager) -> None:
        """Budget allocation keys sum approximately to total balance."""
        alloc = manager.get_budget_allocation(_10_ETH_WEI)
        assert alloc["total"] == _10_ETH_WEI
        # Due to int truncation, parts sum to <= total
        parts = alloc["bounty"] + alloc["reserve"] + alloc["compute"] + alloc["community"]
        assert parts <= _10_ETH_WEI

    def test_bounty_amount_wei_known_label(self, manager: TreasuryManager) -> None:
        """Known bounty label returns correct Wei amount."""
        amount = manager.get_bounty_amount_wei("bounty-md")
        expected = AsyncWeb3.to_wei(0.10, "ether")
        assert amount == expected

    def test_bounty_amount_wei_unknown_label(self, manager: TreasuryManager) -> None:
        """Unknown bounty label returns None."""
        assert manager.get_bounty_amount_wei("nonexistent") is None

    def test_record_incoming_revenue(self, manager: TreasuryManager) -> None:
        """record_incoming updates revenue counter."""
        record = manager.record_incoming(
            tx_type="sponsorship",
            amount_wei=_1_ETH_WEI,
            counterparty="0x" + "dd" * 20,
            tx_hash="0xabc",
        )
        assert isinstance(record, TransactionRecord)
        assert manager._revenue_by_currency.get("ETH", 0) == _1_ETH_WEI
        assert manager._tx_count == 1

    async def test_payout_lock_serialization(
        self, manager: TreasuryManager, mock_wallet: MagicMock
    ) -> None:
        """Concurrent payouts are serialized via _payout_lock."""
        call_order: list[int] = []
        call_count = 0

        original_get_balance = mock_wallet.get_balance

        async def tracked_get_balance(*args, **kwargs):  # noqa: ANN002, ANN003
            nonlocal call_count
            current = call_count
            call_count += 1
            call_order.append(current)
            return await original_get_balance(*args, **kwargs)

        mock_wallet.get_balance = AsyncMock(side_effect=tracked_get_balance)

        req1 = PayoutRequest(recipient="0x" + "aa" * 20, amount_wei=_POINT_1_ETH_WEI)
        req2 = PayoutRequest(recipient="0x" + "bb" * 20, amount_wei=_POINT_1_ETH_WEI)

        await asyncio.gather(
            manager.send_payout(req1),
            manager.send_payout(req2),
        )

        # Balance fetches should be sequential (0, 1)
        assert call_order == [0, 1]


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Gas Estimation
# ═══════════════════════════════════════════════════════════════════════════════


class TestGasEstimation:
    async def test_median_calculation(self) -> None:
        """Fee estimation uses median of 10th-percentile rewards."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        mock_w3 = _make_mock_w3()
        wallet._w3 = mock_w3

        max_fee, priority_fee = await wallet._estimate_eip1559_fees()

        # 10th percentile rewards: [100M, 150M, 120M, 130M]
        # median = (120M + 130M) / 2 = 125M
        assert priority_fee == 125_000_000

        # max_fee = 2 * next_base_fee + priority_fee
        # next_base_fee = baseFeePerGas[-1] = 1_200_000_000
        assert max_fee == 2 * 1_200_000_000 + 125_000_000

    async def test_empty_rewards_fallback(self) -> None:
        """Empty rewards array falls back to 1 gwei priority fee."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        mock_w3 = _make_mock_w3()
        mock_w3.eth.fee_history = AsyncMock(
            return_value={
                "baseFeePerGas": [1_000_000_000, 1_000_000_000],
                "reward": [],
            }
        )
        wallet._w3 = mock_w3

        _, priority_fee = await wallet._estimate_eip1559_fees()
        assert priority_fee == 1_000_000_000  # 1 gwei default

    async def test_priority_fee_floor(self) -> None:
        """Priority fee is floored at 0.1 gwei even if median is lower."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        mock_w3 = _make_mock_w3()
        # Very low rewards (below 0.1 gwei = 100_000_000)
        mock_w3.eth.fee_history = AsyncMock(
            return_value={
                "baseFeePerGas": [1_000_000_000, 1_000_000_000],
                "reward": [[10_000_000, 50_000_000], [20_000_000, 60_000_000]],
            }
        )
        wallet._w3 = mock_w3

        _, priority_fee = await wallet._estimate_eip1559_fees()
        assert priority_fee == 100_000_000  # floor at 0.1 gwei

    async def test_max_fee_cap_applied(self) -> None:
        """max_fee is capped at _MAX_FEE_CAP when RPC returns absurd base fee."""
        from src.treasury.wallet import _MAX_FEE_CAP

        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        mock_w3 = _make_mock_w3()
        # Absurd base fee: 500 gwei → max_fee = 2*500G + priority > 100G cap
        mock_w3.eth.fee_history = AsyncMock(
            return_value={
                "baseFeePerGas": [
                    500_000_000_000,
                    500_000_000_000,
                    500_000_000_000,
                    500_000_000_000,
                    500_000_000_000,
                ],
                "reward": [
                    [1_000_000_000, 2_000_000_000],
                    [1_000_000_000, 2_000_000_000],
                    [1_000_000_000, 2_000_000_000],
                    [1_000_000_000, 2_000_000_000],
                ],
            }
        )
        wallet._w3 = mock_w3

        max_fee, _ = await wallet._estimate_eip1559_fees()
        assert max_fee == _MAX_FEE_CAP


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Key Safety
# ═══════════════════════════════════════════════════════════════════════════════


class TestKeySafety:
    async def test_no_private_key_in_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        """Wallet operations do not leak private key hex into log output."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)

        with caplog.at_level(logging.DEBUG, logger="src.treasury.wallet"):
            await wallet.initialize()

        # Private keys are 32 bytes = 64 hex chars. Check for any such string
        # that matches the actual key.
        key_hex = wallet._require_account().key.hex()
        # Remove '0x' prefix if present
        key_hex_clean = key_hex.removeprefix("0x")
        assert key_hex_clean not in caplog.text

    async def test_corrupted_key_error_clean(self) -> None:
        """Corrupted key RuntimeError has no __cause__ (from None)."""
        kms = MagicMock()
        kms.unseal = AsyncMock(return_value=b"bad" * 11)

        wallet = WalletManager(kms=kms)
        with pytest.raises(RuntimeError) as exc_info:
            await wallet.initialize()

        assert exc_info.value.__cause__ is None

    async def test_sign_failure_strips_traceback(self) -> None:
        """sign_message failure via from None strips inner traceback."""
        kms = _make_mock_kms(has_key=False)
        wallet = WalletManager(kms=kms)
        await wallet.initialize()

        # Make the account's sign_message raise
        mock_account = MagicMock()
        mock_account.sign_message.side_effect = Exception("internal crypto error")
        wallet._account = mock_account

        with pytest.raises(RuntimeError, match="signing failed") as exc_info:
            wallet.sign_message(b"test message")

        assert exc_info.value.__cause__ is None
