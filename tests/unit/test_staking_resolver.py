"""Comprehensive tests for the StakeResolver orchestration layer.

Covers pre-check validation, all four resolution methods, idempotency
guards, error propagation from the contract layer, and edge cases.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.config import StakingConfig
from src.staking.economics import StakingEconomics
from src.staking.resolver import StakeResolver

# ── Constants ────────────────────────────────────────────────────────────────

_TX_HASH = "0x" + "ab" * 32
_STAKE_ID = b"\x01" * 32
_PR_ID = b"\x02" * 32
_STAKER = "0x" + "aa" * 20
_1_ETH = 10**18


def _make_economics(
    *,
    bonus_nc: float = 0.10,
    bonus_up: float = 0.20,
    slash_rate: float = 0.50,
) -> StakingEconomics:
    config = StakingConfig(
        enabled=True,
        bonus_rate_no_challenge=bonus_nc,
        bonus_rate_challenged_upheld=bonus_up,
        slash_rate_challenged_overturned=slash_rate,
    )
    return StakingEconomics(config)


def _make_mock_contract(
    *,
    amount: int = _1_ETH,
    resolved: bool = False,
    tx_hash: str = _TX_HASH,
) -> MagicMock:
    """Create a mock StakingContract with get_stake and write stubs."""
    contract = MagicMock()
    contract.get_stake = AsyncMock(return_value={
        "staker": _STAKER,
        "amount": amount,
        "pr_id": _PR_ID,
        "resolved": resolved,
        "timestamp": 1700000000,
    })
    contract.release_stake = AsyncMock(return_value=tx_hash)
    contract.slash_stake = AsyncMock(return_value=tx_hash)
    contract.refund_stake = AsyncMock(return_value=tx_hash)
    return contract


# ═══════════════════════════════════════════════════════════════════════════════
# A. Pre-check validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestPreCheck:
    """_pre_check reads on-chain state and rejects invalid stakes."""

    async def test_already_resolved_raises(self) -> None:
        """Already-resolved stake is rejected."""
        contract = _make_mock_contract(resolved=True)
        resolver = StakeResolver(contract, _make_economics())
        with pytest.raises(RuntimeError, match="already resolved"):
            await resolver._pre_check(_STAKE_ID)

    async def test_zero_amount_raises(self) -> None:
        """Zero-amount stake (non-existent) is rejected."""
        contract = _make_mock_contract(amount=0)
        resolver = StakeResolver(contract, _make_economics())
        with pytest.raises(RuntimeError, match="zero amount"):
            await resolver._pre_check(_STAKE_ID)

    async def test_valid_stake_returns_data(self) -> None:
        """Valid unresolved stake returns the stake dict."""
        contract = _make_mock_contract()
        resolver = StakeResolver(contract, _make_economics())
        stake = await resolver._pre_check(_STAKE_ID)
        assert stake["amount"] == _1_ETH
        assert stake["resolved"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# B. No-challenge resolution
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveNoChallenge:
    async def test_calls_release_with_bonus(self) -> None:
        """resolve_no_challenge computes bonus and calls release_stake."""
        contract = _make_mock_contract()
        econ = _make_economics()
        resolver = StakeResolver(contract, econ)

        result = await resolver.resolve_no_challenge(_STAKE_ID)

        # Verify release_stake was called with correct bonus
        expected_bonus = _1_ETH * 1000 // 10_000  # 10% = 0.1 ETH
        contract.release_stake.assert_awaited_once_with(_STAKE_ID, expected_bonus)

        assert result["outcome"] == "no_challenge"
        assert result["bonus_amount"] == expected_bonus
        assert result["return_amount"] == _1_ETH + expected_bonus
        assert result["tx_hash"] == _TX_HASH

    async def test_small_stake(self) -> None:
        """Small stake (10_000 wei) computes correct bonus."""
        contract = _make_mock_contract(amount=10_000)
        resolver = StakeResolver(contract, _make_economics())

        result = await resolver.resolve_no_challenge(_STAKE_ID)
        assert result["bonus_amount"] == 1_000  # 10% of 10_000
        assert result["return_amount"] == 11_000


# ═══════════════════════════════════════════════════════════════════════════════
# C. Challenged upheld resolution
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveChallengedUpheld:
    async def test_calls_release_with_higher_bonus(self) -> None:
        """resolve_challenged_upheld uses the 20% bonus rate."""
        contract = _make_mock_contract()
        resolver = StakeResolver(contract, _make_economics())

        result = await resolver.resolve_challenged_upheld(_STAKE_ID)

        expected_bonus = _1_ETH * 2000 // 10_000  # 20% = 0.2 ETH
        contract.release_stake.assert_awaited_once_with(_STAKE_ID, expected_bonus)

        assert result["outcome"] == "challenged_upheld"
        assert result["bonus_amount"] == expected_bonus
        assert result["bonus_amount"] > _1_ETH * 1000 // 10_000  # > no-challenge bonus


# ═══════════════════════════════════════════════════════════════════════════════
# D. Challenged overturned resolution
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveChallengedOverturned:
    async def test_calls_slash_with_percent(self) -> None:
        """resolve_challenged_overturned converts bps to percent for contract."""
        contract = _make_mock_contract()
        resolver = StakeResolver(contract, _make_economics())

        result = await resolver.resolve_challenged_overturned(_STAKE_ID)

        # 50% slash → slash_percent=50
        contract.slash_stake.assert_awaited_once_with(_STAKE_ID, 50)

        assert result["outcome"] == "challenged_overturned"
        assert result["slash_percent"] == 50
        expected_slash = _1_ETH * 5000 // 10_000
        assert result["slash_amount"] == expected_slash
        assert result["return_amount"] == _1_ETH - expected_slash

    async def test_low_slash_rate_floors_to_1(self) -> None:
        """Slash rate too low for 1% still sends slash_percent=1."""
        contract = _make_mock_contract()
        econ = _make_economics(slash_rate=0.001)  # 0.1% = 10 bps → 0%
        resolver = StakeResolver(contract, econ)

        result = await resolver.resolve_challenged_overturned(_STAKE_ID)
        # Floors to 1 since contract requires 1-100
        assert result["slash_percent"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# E. Rejected resolution
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveRejected:
    async def test_calls_refund(self) -> None:
        """resolve_rejected calls refund_stake and returns full amount."""
        contract = _make_mock_contract()
        resolver = StakeResolver(contract, _make_economics())

        result = await resolver.resolve_rejected(_STAKE_ID)

        contract.refund_stake.assert_awaited_once_with(_STAKE_ID)
        assert result["outcome"] == "rejected"
        assert result["refund_amount"] == _1_ETH
        assert result["tx_hash"] == _TX_HASH


# ═══════════════════════════════════════════════════════════════════════════════
# F. Error propagation
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorPropagation:
    async def test_get_stake_failure_propagates(self) -> None:
        """RPC failure in get_stake propagates to caller."""
        contract = _make_mock_contract()
        contract.get_stake = AsyncMock(side_effect=ConnectionError("RPC down"))
        resolver = StakeResolver(contract, _make_economics())

        with pytest.raises(ConnectionError, match="RPC down"):
            await resolver.resolve_no_challenge(_STAKE_ID)

    async def test_release_failure_propagates(self) -> None:
        """Contract revert in release_stake propagates to caller."""
        contract = _make_mock_contract()
        contract.release_stake = AsyncMock(
            side_effect=RuntimeError("Transaction failed"),
        )
        resolver = StakeResolver(contract, _make_economics())

        with pytest.raises(RuntimeError, match="Transaction failed"):
            await resolver.resolve_no_challenge(_STAKE_ID)

    async def test_pre_check_prevents_contract_call(self) -> None:
        """When pre-check fails, no write method is called."""
        contract = _make_mock_contract(resolved=True)
        resolver = StakeResolver(contract, _make_economics())

        with pytest.raises(RuntimeError, match="already resolved"):
            await resolver.resolve_no_challenge(_STAKE_ID)

        contract.release_stake.assert_not_awaited()
        contract.slash_stake.assert_not_awaited()
        contract.refund_stake.assert_not_awaited()


# ═══════════════════════════════════════════════════════════════════════════════
# G. Immutability
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolverImmutability:
    def test_slots(self) -> None:
        """StakeResolver uses __slots__ — no arbitrary attributes."""
        contract = _make_mock_contract()
        resolver = StakeResolver(contract, _make_economics())
        assert not hasattr(resolver, "__dict__")

    def test_cannot_set_arbitrary_attr(self) -> None:
        contract = _make_mock_contract()
        resolver = StakeResolver(contract, _make_economics())
        with pytest.raises(AttributeError):
            resolver.foo = "bar"  # type: ignore[attr-defined]
