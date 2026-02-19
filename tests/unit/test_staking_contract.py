"""Comprehensive tests for the staking contract wrapper.

Covers initialization lifecycle, all five write methods, read operations,
receipt waiting, deposit verification, gas estimation, partial-init recovery,
confirmation depth, and not-initialized guards.
Mirrors test patterns from ``test_treasury.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from web3 import AsyncWeb3
from web3.exceptions import TransactionNotFound

from src.config import StakingConfig
from src.staking.contract import StakingContract

# ── Helpers ──────────────────────────────────────────────────────────────────

_CONTRACT_ADDR = AsyncWeb3.to_checksum_address("0x" + "cc" * 20)
_TX_HASH = "0x" + "ab" * 32
_STAKE_ID = b"\x01" * 32
_PR_ID = b"\x02" * 32


def _make_staking_config(
    *, address: str = _CONTRACT_ADDR, gas_limit: int = 200_000,
) -> StakingConfig:
    return StakingConfig(
        enabled=True,
        contract_address=address,
        fallback_gas_limit=gas_limit,
        bonus_rate_no_challenge=0.10,
        bonus_rate_challenged_upheld=0.20,
        slash_rate_challenged_overturned=0.50,
    )


def _make_mock_wallet() -> MagicMock:
    """Create a mock WalletManager with send_transaction returning a tx hash."""
    wallet = MagicMock()
    wallet.send_transaction = AsyncMock(return_value=_TX_HASH)
    return wallet


# ═══════════════════════════════════════════════════════════════════════════════
# A. Initialization lifecycle
# ═══════════════════════════════════════════════════════════════════════════════


class TestStakingContractInit:
    async def test_initialize_creates_read_w3(self) -> None:
        """initialize() creates the read-only Web3 instance."""
        sc = StakingContract(
            _make_mock_wallet(), _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()
        assert sc._initialized is True
        assert sc._read_w3 is not None
        await sc.close()

    async def test_double_init_raises(self) -> None:
        """Calling initialize() twice raises RuntimeError."""
        sc = StakingContract(
            _make_mock_wallet(), _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()
        with pytest.raises(RuntimeError, match="already initialized"):
            await sc.initialize()
        await sc.close()

    async def test_empty_contract_address_raises(self) -> None:
        """Empty contract_address raises on initialize()."""
        config = _make_staking_config(address="")
        sc = StakingContract(
            _make_mock_wallet(), config, "https://rpc.test",
        )
        with pytest.raises(RuntimeError, match="contract_address is empty"):
            await sc.initialize()

    async def test_close_clears_state(self) -> None:
        """close() resets _initialized and _read_w3."""
        sc = StakingContract(
            _make_mock_wallet(), _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()
        await sc.close()
        assert sc._initialized is False
        assert sc._read_w3 is None

    async def test_contract_address_checksummed(self) -> None:
        """initialize() converts the configured address to checksum format."""
        lower_addr = "0x" + "cc" * 20  # lowercase
        config = _make_staking_config(address=lower_addr)
        sc = StakingContract(
            _make_mock_wallet(), config, "https://rpc.test",
        )
        await sc.initialize()
        assert sc._contract_address == _CONTRACT_ADDR
        await sc.close()

    async def test_partial_init_recovery(self) -> None:
        """If initialize() fails mid-way, object state is rolled back cleanly."""
        config = _make_staking_config(address="not-a-valid-address")
        sc = StakingContract(
            _make_mock_wallet(), config, "https://rpc.test",
        )
        with pytest.raises(Exception):  # noqa: B017 — bad address format
            await sc.initialize()
        # Object should be cleanly reset — not stuck in partial state
        assert sc._initialized is False
        assert sc._read_w3 is None
        assert sc._contract_address == ""


# ═══════════════════════════════════════════════════════════════════════════════
# B. Write operations
# ═══════════════════════════════════════════════════════════════════════════════


class TestStakingContractWrites:
    """Each write method encodes ABI and calls wallet.send_transaction()."""

    @pytest.fixture()
    async def sc(self):
        """Initialized StakingContract with mock wallet + stubbed gas estimation."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()
        # Stub gas estimation so tests don't hit a real RPC.
        # Returns fallback_gas_limit (200_000) to match existing assertions.
        sc._estimate_gas = AsyncMock(return_value=200_000)
        yield sc, wallet
        await sc.close()

    async def test_deposit_stake_sends_value(self, sc) -> None:
        """deposit_stake sends value_wei=amount_wei (payable call)."""
        contract, wallet = sc
        tx = await contract.deposit_stake(_STAKE_ID, _PR_ID, 1_000_000)

        assert tx == _TX_HASH
        wallet.send_transaction.assert_awaited_once()
        call_kwargs = wallet.send_transaction.call_args
        assert call_kwargs.kwargs["value_wei"] == 1_000_000
        assert call_kwargs.kwargs["gas"] == 200_000
        assert len(call_kwargs.kwargs["data"]) > 0

    async def test_release_stake_zero_value(self, sc) -> None:
        """release_stake sends value_wei=0 (nonpayable)."""
        contract, wallet = sc
        await contract.release_stake(_STAKE_ID, bonus_amount=50_000)

        call_kwargs = wallet.send_transaction.call_args
        assert call_kwargs.kwargs["value_wei"] == 0

    async def test_slash_stake_zero_value(self, sc) -> None:
        """slash_stake sends value_wei=0 (nonpayable)."""
        contract, wallet = sc
        await contract.slash_stake(_STAKE_ID, slash_percent=50)

        call_kwargs = wallet.send_transaction.call_args
        assert call_kwargs.kwargs["value_wei"] == 0

    async def test_refund_stake_zero_value(self, sc) -> None:
        """refund_stake sends value_wei=0 (nonpayable)."""
        contract, wallet = sc
        await contract.refund_stake(_STAKE_ID)

        call_kwargs = wallet.send_transaction.call_args
        assert call_kwargs.kwargs["value_wei"] == 0

    async def test_withdraw_slashed_zero_value(self, sc) -> None:
        """withdraw_slashed sends value_wei=0 (nonpayable)."""
        contract, wallet = sc
        await contract.withdraw_slashed(amount_wei=100_000)

        call_kwargs = wallet.send_transaction.call_args
        assert call_kwargs.kwargs["value_wei"] == 0

    async def test_gas_parameter_passed(self, sc) -> None:
        """All write methods pass config.fallback_gas_limit as gas."""
        contract, wallet = sc
        await contract.deposit_stake(_STAKE_ID, _PR_ID, 1000)
        assert wallet.send_transaction.call_args.kwargs["gas"] == 200_000

    async def test_slash_percent_validation_zero(self, sc) -> None:
        """slash_percent=0 is rejected."""
        contract, _ = sc
        with pytest.raises(ValueError, match="1–100"):
            await contract.slash_stake(_STAKE_ID, slash_percent=0)

    async def test_slash_percent_validation_over_100(self, sc) -> None:
        """slash_percent>100 is rejected."""
        contract, _ = sc
        with pytest.raises(ValueError, match="1–100"):
            await contract.slash_stake(_STAKE_ID, slash_percent=101)

    async def test_slash_percent_boundary_1(self, sc) -> None:
        """slash_percent=1 is accepted."""
        contract, _ = sc
        tx = await contract.slash_stake(_STAKE_ID, slash_percent=1)
        assert tx == _TX_HASH

    async def test_slash_percent_boundary_100(self, sc) -> None:
        """slash_percent=100 is accepted."""
        contract, _ = sc
        tx = await contract.slash_stake(_STAKE_ID, slash_percent=100)
        assert tx == _TX_HASH

    async def test_deposit_returns_tx_hash(self, sc) -> None:
        """All write methods return the transaction hash string."""
        contract, _ = sc
        assert await contract.deposit_stake(_STAKE_ID, _PR_ID, 1000) == _TX_HASH
        assert await contract.release_stake(_STAKE_ID, 500) == _TX_HASH
        assert await contract.slash_stake(_STAKE_ID, 50) == _TX_HASH
        assert await contract.refund_stake(_STAKE_ID) == _TX_HASH
        assert await contract.withdraw_slashed(1000) == _TX_HASH


# ═══════════════════════════════════════════════════════════════════════════════
# C. Read operations
# ═══════════════════════════════════════════════════════════════════════════════


class TestStakingContractReads:
    async def test_get_stake_returns_parsed_dict(self) -> None:
        """get_stake() returns a dict with correct field mapping."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        staker_addr = "0x" + "aa" * 20
        mock_result = (staker_addr, 1_000_000, _PR_ID, False, 1700000000)

        mock_contract = MagicMock()
        mock_fn = MagicMock()
        mock_fn.call = AsyncMock(return_value=mock_result)
        mock_contract.functions.stakes.return_value = mock_fn

        with patch.object(sc._read_w3.eth, "contract", return_value=mock_contract):
            result = await sc.get_stake(_STAKE_ID)

        assert result["staker"] == staker_addr
        assert result["amount"] == 1_000_000
        assert result["pr_id"] == _PR_ID
        assert result["resolved"] is False
        assert result["timestamp"] == 1700000000

        await sc.close()


# ═══════════════════════════════════════════════════════════════════════════════
# D. Receipt waiting
# ═══════════════════════════════════════════════════════════════════════════════


class TestReceiptWaiting:
    async def test_receipt_found_immediately(self) -> None:
        """Receipt available on first poll returns immediately."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        mock_receipt = {"status": 1, "transactionHash": _TX_HASH}
        sc._read_w3.eth.get_transaction_receipt = AsyncMock(
            return_value=mock_receipt,
        )

        receipt = await sc.wait_for_receipt(_TX_HASH, timeout=10)
        assert receipt["status"] == 1

        await sc.close()

    async def test_receipt_reverted_raises(self) -> None:
        """Receipt with status=0 raises RuntimeError."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        mock_receipt = {"status": 0, "transactionHash": _TX_HASH}
        sc._read_w3.eth.get_transaction_receipt = AsyncMock(
            return_value=mock_receipt,
        )

        with pytest.raises(RuntimeError, match="reverted"):
            await sc.wait_for_receipt(_TX_HASH, timeout=10)

        await sc.close()

    async def test_receipt_timeout_raises(self) -> None:
        """Timeout when receipt never arrives raises RuntimeError."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        # Receipt always returns None (not mined yet)
        sc._read_w3.eth.get_transaction_receipt = AsyncMock(return_value=None)

        with (
            patch("src.staking.contract.asyncio.sleep", new_callable=AsyncMock),
            patch("src.staking.contract._RECEIPT_POLL_INTERVAL", 0),
            pytest.raises(RuntimeError, match="timeout"),
        ):
            await sc.wait_for_receipt(_TX_HASH, timeout=0)

        await sc.close()

    async def test_transaction_not_found_continues_polling(self) -> None:
        """TransactionNotFound from RPC is swallowed; polling continues."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        mock_receipt = {"status": 1, "transactionHash": _TX_HASH}
        # First call raises TransactionNotFound, second returns receipt
        sc._read_w3.eth.get_transaction_receipt = AsyncMock(
            side_effect=[TransactionNotFound("pending"), mock_receipt],
        )

        with patch("src.staking.contract.asyncio.sleep", new_callable=AsyncMock):
            receipt = await sc.wait_for_receipt(_TX_HASH, timeout=10)

        assert receipt["status"] == 1
        assert sc._read_w3.eth.get_transaction_receipt.await_count == 2

        await sc.close()

    async def test_unexpected_rpc_error_propagates(self) -> None:
        """Non-TransactionNotFound exceptions propagate immediately."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        sc._read_w3.eth.get_transaction_receipt = AsyncMock(
            side_effect=ConnectionError("RPC down"),
        )

        with pytest.raises(ConnectionError, match="RPC down"):
            await sc.wait_for_receipt(_TX_HASH, timeout=10)

        await sc.close()


# ═══════════════════════════════════════════════════════════════════════════════
# D-2. Gas estimation
# ═══════════════════════════════════════════════════════════════════════════════


class TestGasEstimation:
    async def test_estimate_gas_with_buffer(self) -> None:
        """_estimate_gas adds 20% buffer (integer arithmetic)."""
        sc = StakingContract(
            _make_mock_wallet(), _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        sc._read_w3.eth.estimate_gas = AsyncMock(return_value=100_000)
        gas = await sc._estimate_gas(b"\x00" * 4)
        # 100_000 * 120 // 100 = 120_000
        assert gas == 120_000

        await sc.close()

    async def test_estimate_gas_capped_at_fallback(self) -> None:
        """Buffered estimate is capped at fallback_gas_limit."""
        sc = StakingContract(
            _make_mock_wallet(), _make_staking_config(gas_limit=150_000), "https://rpc.test",
        )
        await sc.initialize()

        # 180_000 * 120 // 100 = 216_000, but fallback is 150_000
        sc._read_w3.eth.estimate_gas = AsyncMock(return_value=180_000)
        gas = await sc._estimate_gas(b"\x00" * 4)
        assert gas == 150_000

        await sc.close()

    async def test_estimate_gas_fallback_on_rpc_error(self) -> None:
        """RPC estimation failure falls back to config.fallback_gas_limit."""
        sc = StakingContract(
            _make_mock_wallet(), _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        sc._read_w3.eth.estimate_gas = AsyncMock(side_effect=Exception("RPC error"))
        gas = await sc._estimate_gas(b"\x00" * 4)
        assert gas == 200_000  # fallback_gas_limit

        await sc.close()


# ═══════════════════════════════════════════════════════════════════════════════
# E. Verify deposit
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifyDeposit:
    async def test_success_parses_event(self) -> None:
        """verify_deposit extracts StakeDeposited event data."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        # Mock wait_for_receipt
        mock_receipt = {"status": 1, "logs": []}
        sc.wait_for_receipt = AsyncMock(return_value=mock_receipt)

        # Mock contract event processing
        staker_addr = "0x" + "dd" * 20
        mock_event = {
            "args": {
                "stakeId": _STAKE_ID,
                "staker": staker_addr,
                "amount": 1_000_000,
                "prId": _PR_ID,
            }
        }
        mock_contract = MagicMock()
        mock_contract.events.StakeDeposited.return_value.process_receipt.return_value = [
            mock_event
        ]

        with patch.object(sc._read_w3.eth, "contract", return_value=mock_contract):
            result = await sc.verify_deposit(_TX_HASH)

        assert result["stake_id"] == _STAKE_ID
        assert result["staker"] == staker_addr
        assert result["amount"] == 1_000_000
        assert result["pr_id"] == _PR_ID

        await sc.close()

    async def test_no_event_raises(self) -> None:
        """verify_deposit raises when no StakeDeposited event is found."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        mock_receipt = {"status": 1, "logs": []}
        sc.wait_for_receipt = AsyncMock(return_value=mock_receipt)

        mock_contract = MagicMock()
        mock_contract.events.StakeDeposited.return_value.process_receipt.return_value = []

        with (
            patch.object(sc._read_w3.eth, "contract", return_value=mock_contract),
            pytest.raises(RuntimeError, match="No StakeDeposited event"),
        ):
            await sc.verify_deposit(_TX_HASH)

        await sc.close()

    async def test_confirmation_depth_waits(self) -> None:
        """verify_deposit with confirmations>1 waits for block depth."""
        wallet = _make_mock_wallet()
        sc = StakingContract(
            wallet, _make_staking_config(), "https://rpc.test",
        )
        await sc.initialize()

        mock_receipt = {"status": 1, "logs": [], "blockNumber": 100}
        sc.wait_for_receipt = AsyncMock(return_value=mock_receipt)

        staker_addr = "0x" + "dd" * 20
        mock_event = {
            "args": {
                "stakeId": _STAKE_ID,
                "staker": staker_addr,
                "amount": 1_000_000,
                "prId": _PR_ID,
            }
        }
        mock_contract = MagicMock()
        mock_contract.events.StakeDeposited.return_value.process_receipt.return_value = [
            mock_event
        ]

        # Block number advances: 101 (depth=2), then 103 (depth=4)
        sc._get_block_number = AsyncMock(side_effect=[101, 103])

        with (
            patch.object(sc._read_w3.eth, "contract", return_value=mock_contract),
            patch("src.staking.contract.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await sc.verify_deposit(_TX_HASH, confirmations=3)

        assert result["stake_id"] == _STAKE_ID
        # Should have polled block_number twice (depth 2 < 3, then depth 4 >= 3)
        assert sc._get_block_number.await_count == 2

        await sc.close()


# ═══════════════════════════════════════════════════════════════════════════════
# F. Not-initialized guards
# ═══════════════════════════════════════════════════════════════════════════════


class TestNotInitialized:
    """All methods raise RuntimeError before initialize()."""

    @pytest.fixture()
    def sc(self) -> StakingContract:
        return StakingContract(
            _make_mock_wallet(), _make_staking_config(), "https://rpc.test",
        )

    async def test_deposit_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.deposit_stake(_STAKE_ID, _PR_ID, 1000)

    async def test_release_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.release_stake(_STAKE_ID, 500)

    async def test_slash_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.slash_stake(_STAKE_ID, 50)

    async def test_refund_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.refund_stake(_STAKE_ID)

    async def test_withdraw_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.withdraw_slashed(1000)

    async def test_get_stake_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.get_stake(_STAKE_ID)

    async def test_wait_receipt_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.wait_for_receipt(_TX_HASH)

    async def test_verify_deposit_before_init(self, sc: StakingContract) -> None:
        with pytest.raises(RuntimeError, match="not initialized"):
            await sc.verify_deposit(_TX_HASH)


# ═══════════════════════════════════════════════════════════════════════════════
# G. ABI integrity and encoding verification
# ═══════════════════════════════════════════════════════════════════════════════


class TestABIIntegrity:
    """Verify the embedded ABI matches expected function selectors."""

    def test_deposit_stake_selector(self) -> None:
        """depositStake(bytes32,bytes32) selector matches keccak256."""
        sig = "depositStake(bytes32,bytes32)"
        expected = AsyncWeb3.keccak(text=sig)[:4]
        w3 = AsyncWeb3()
        from src.staking.contract import _STAKING_ABI
        contract = w3.eth.contract(address=_CONTRACT_ADDR, abi=_STAKING_ABI)
        encoded = contract.encode_abi(fn_name="depositStake", args=[_STAKE_ID, _PR_ID])
        # First 4 bytes of encoded data == function selector
        assert bytes.fromhex(encoded.removeprefix("0x"))[:4] == expected

    def test_release_stake_selector(self) -> None:
        """releaseStake(bytes32,uint256) selector matches keccak256."""
        sig = "releaseStake(bytes32,uint256)"
        expected = AsyncWeb3.keccak(text=sig)[:4]
        w3 = AsyncWeb3()
        from src.staking.contract import _STAKING_ABI
        contract = w3.eth.contract(address=_CONTRACT_ADDR, abi=_STAKING_ABI)
        encoded = contract.encode_abi(fn_name="releaseStake", args=[_STAKE_ID, 1000])
        assert bytes.fromhex(encoded.removeprefix("0x"))[:4] == expected

    def test_slash_stake_selector(self) -> None:
        """slashStake(bytes32,uint256) selector matches keccak256."""
        sig = "slashStake(bytes32,uint256)"
        expected = AsyncWeb3.keccak(text=sig)[:4]
        w3 = AsyncWeb3()
        from src.staking.contract import _STAKING_ABI
        contract = w3.eth.contract(address=_CONTRACT_ADDR, abi=_STAKING_ABI)
        encoded = contract.encode_abi(fn_name="slashStake", args=[_STAKE_ID, 50])
        assert bytes.fromhex(encoded.removeprefix("0x"))[:4] == expected

    def test_refund_stake_selector(self) -> None:
        """refundStake(bytes32) selector matches keccak256."""
        sig = "refundStake(bytes32)"
        expected = AsyncWeb3.keccak(text=sig)[:4]
        w3 = AsyncWeb3()
        from src.staking.contract import _STAKING_ABI
        contract = w3.eth.contract(address=_CONTRACT_ADDR, abi=_STAKING_ABI)
        encoded = contract.encode_abi(fn_name="refundStake", args=[_STAKE_ID])
        assert bytes.fromhex(encoded.removeprefix("0x"))[:4] == expected

    def test_withdraw_slashed_selector(self) -> None:
        """withdrawSlashed(uint256) selector matches keccak256."""
        sig = "withdrawSlashed(uint256)"
        expected = AsyncWeb3.keccak(text=sig)[:4]
        w3 = AsyncWeb3()
        from src.staking.contract import _STAKING_ABI
        contract = w3.eth.contract(address=_CONTRACT_ADDR, abi=_STAKING_ABI)
        encoded = contract.encode_abi(fn_name="withdrawSlashed", args=[100_000])
        assert bytes.fromhex(encoded.removeprefix("0x"))[:4] == expected

    def test_deposit_calldata_includes_arguments(self) -> None:
        """Encoded calldata for depositStake contains both bytes32 args."""
        w3 = AsyncWeb3()
        from src.staking.contract import _STAKING_ABI
        contract = w3.eth.contract(address=_CONTRACT_ADDR, abi=_STAKING_ABI)
        encoded = bytes.fromhex(
            contract.encode_abi(
                fn_name="depositStake", args=[_STAKE_ID, _PR_ID],
            ).removeprefix("0x")
        )
        # 4 bytes selector + 32 bytes stake_id + 32 bytes pr_id = 68
        assert len(encoded) == 68
        # Arguments are ABI-encoded after the selector
        assert encoded[4:36] == _STAKE_ID
        assert encoded[36:68] == _PR_ID

    def test_abi_function_count(self) -> None:
        """ABI has exactly 5 functions, 1 event, 1 receive."""
        from src.staking.contract import _STAKING_ABI
        functions = [e for e in _STAKING_ABI if e["type"] == "function"]
        events = [e for e in _STAKING_ABI if e["type"] == "event"]
        receives = [e for e in _STAKING_ABI if e["type"] == "receive"]
        assert len(functions) == 6  # 5 write + 1 view (stakes)
        assert len(events) == 1
        assert len(receives) == 1
