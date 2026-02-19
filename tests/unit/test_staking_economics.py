"""Comprehensive tests for the staking economics engine.

Covers basis-point conversion, all four calculation methods, precision
guarantees, input validation, custom rates, and overflow safety.
"""

from __future__ import annotations

import pytest
from web3 import AsyncWeb3

from src.config import StakingConfig
from src.staking.economics import StakingEconomics, _rate_to_bps

# ── Constants ────────────────────────────────────────────────────────────────

_1_ETH = AsyncWeb3.to_wei(1, "ether")  # 10^18
_9_ETH = AsyncWeb3.to_wei(9, "ether")


@pytest.fixture()
def default_config() -> StakingConfig:
    """Standard staking config: 10% / 20% bonus, 50% slash."""
    return StakingConfig(
        enabled=True,
        bonus_rate_no_challenge=0.10,
        bonus_rate_challenged_upheld=0.20,
        slash_rate_challenged_overturned=0.50,
    )


@pytest.fixture()
def econ(default_config: StakingConfig) -> StakingEconomics:
    return StakingEconomics(default_config)


# ═══════════════════════════════════════════════════════════════════════════════
# A. Basis-point conversion
# ═══════════════════════════════════════════════════════════════════════════════


class TestBasisPointConversion:
    """Test _rate_to_bps() edge cases and boundaries."""

    def test_ten_percent(self) -> None:
        assert _rate_to_bps(0.10) == 1_000

    def test_twenty_percent(self) -> None:
        assert _rate_to_bps(0.20) == 2_000

    def test_fifty_percent(self) -> None:
        assert _rate_to_bps(0.50) == 5_000

    def test_zero(self) -> None:
        assert _rate_to_bps(0.0) == 0

    def test_one_hundred_percent(self) -> None:
        assert _rate_to_bps(1.0) == 10_000

    def test_one_basis_point(self) -> None:
        """0.01% = 1 bps."""
        assert _rate_to_bps(0.0001) == 1

    def test_negative_rate_rejected(self) -> None:
        with pytest.raises(ValueError, match="bps"):
            _rate_to_bps(-0.01)

    def test_over_100_percent_rejected(self) -> None:
        with pytest.raises(ValueError, match="bps"):
            _rate_to_bps(1.01)


# ═══════════════════════════════════════════════════════════════════════════════
# B. Return — no challenge
# ═══════════════════════════════════════════════════════════════════════════════


class TestReturnNoChallenge:
    """Test calculate_return_no_challenge()."""

    def test_1_eth_10_percent(self, econ: StakingEconomics) -> None:
        """1 ETH stake at 10% bonus → 0.1 ETH bonus, 1.1 ETH return."""
        return_amount, bonus = econ.calculate_return_no_challenge(_1_ETH)
        assert bonus == _1_ETH // 10
        assert return_amount == _1_ETH + bonus

    def test_small_stake(self, econ: StakingEconomics) -> None:
        """10 000 wei at 10% → bonus=1000, return=11 000."""
        return_amount, bonus = econ.calculate_return_no_challenge(10_000)
        assert bonus == 1_000
        assert return_amount == 11_000

    def test_return_equals_stake_plus_bonus(self, econ: StakingEconomics) -> None:
        """Invariant: return_amount == stake + bonus for any positive stake."""
        for stake in [1, 100, 10_000, _1_ETH, _9_ETH]:
            ret, bonus = econ.calculate_return_no_challenge(stake)
            assert ret == stake + bonus


# ═══════════════════════════════════════════════════════════════════════════════
# C. Return — challenged upheld
# ═══════════════════════════════════════════════════════════════════════════════


class TestReturnChallengedUpheld:
    """Test calculate_return_challenged_upheld()."""

    def test_1_eth_20_percent(self, econ: StakingEconomics) -> None:
        """1 ETH stake at 20% bonus → 0.2 ETH bonus, 1.2 ETH return."""
        return_amount, bonus = econ.calculate_return_challenged_upheld(_1_ETH)
        assert bonus == _1_ETH * 2 // 10
        assert return_amount == _1_ETH + bonus

    def test_upheld_bonus_exceeds_no_challenge(self, econ: StakingEconomics) -> None:
        """Upheld bonus must be strictly greater than no-challenge bonus."""
        _, bonus_nc = econ.calculate_return_no_challenge(_1_ETH)
        _, bonus_up = econ.calculate_return_challenged_upheld(_1_ETH)
        assert bonus_up > bonus_nc


# ═══════════════════════════════════════════════════════════════════════════════
# D. Slash — challenged overturned
# ═══════════════════════════════════════════════════════════════════════════════


class TestSlashChallengedOverturned:
    """Test calculate_slash_challenged_overturned()."""

    def test_1_eth_50_percent_slash(self, econ: StakingEconomics) -> None:
        """1 ETH stake at 50% slash → 0.5 ETH slashed, 0.5 ETH returned."""
        return_amount, slash = econ.calculate_slash_challenged_overturned(_1_ETH)
        assert slash == _1_ETH // 2
        assert return_amount == _1_ETH - slash

    def test_return_plus_slash_equals_stake(self, econ: StakingEconomics) -> None:
        """Invariant: return_amount + slash_amount == stake_wei."""
        for stake in [1, 1_000, _1_ETH, _9_ETH]:
            ret, slash = econ.calculate_slash_challenged_overturned(stake)
            assert ret + slash == stake


# ═══════════════════════════════════════════════════════════════════════════════
# E. Refund — rejected
# ═══════════════════════════════════════════════════════════════════════════════


class TestRefundRejected:
    """Test calculate_refund_rejected()."""

    def test_returns_stake_unchanged(self, econ: StakingEconomics) -> None:
        assert econ.calculate_refund_rejected(_1_ETH) == _1_ETH

    def test_small_stake(self, econ: StakingEconomics) -> None:
        assert econ.calculate_refund_rejected(1) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# F. Input validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestInputValidation:
    """All four methods reject zero and negative stake."""

    def test_zero_stake_no_challenge(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_return_no_challenge(0)

    def test_negative_stake_no_challenge(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_return_no_challenge(-1)

    def test_zero_stake_upheld(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_return_challenged_upheld(0)

    def test_negative_stake_upheld(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_return_challenged_upheld(-1)

    def test_zero_stake_overturned(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_slash_challenged_overturned(0)

    def test_negative_stake_overturned(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_slash_challenged_overturned(-1)

    def test_zero_stake_refund(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_refund_rejected(0)

    def test_negative_stake_refund(self, econ: StakingEconomics) -> None:
        with pytest.raises(ValueError, match="positive"):
            econ.calculate_refund_rejected(-1)


# ═══════════════════════════════════════════════════════════════════════════════
# G. Precision — the critical fix this module exists for
# ═══════════════════════════════════════════════════════════════════════════════


class TestPrecision:
    """Verify integer arithmetic avoids IEEE 754 float precision loss."""

    def test_large_stake_precision(self, econ: StakingEconomics) -> None:
        """9 ETH + fractional wei: float multiplication gives wrong result.

        int((9 * 10**18 + 123456789) * 0.10) differs from the correct
        integer-only calculation.  Our method must give the exact result.
        """
        stake = 9 * 10**18 + 123_456_789
        _, bonus = econ.calculate_return_no_challenge(stake)

        # Correct result via integer arithmetic
        expected = stake * 1_000 // 10_000
        assert bonus == expected

        # Demonstrate that naive float would be wrong
        naive_float = int(stake * 0.10)
        assert naive_float != expected, (
            "If this fails, the test premise is invalid — "
            "float precision loss should occur at this scale"
        )

    def test_exact_1_eth_bonus(self, econ: StakingEconomics) -> None:
        """1 ETH should give exactly 10^17 bonus (not 10^17 ± epsilon)."""
        _, bonus = econ.calculate_return_no_challenge(_1_ETH)
        assert bonus == 10**17  # exactly 0.1 ETH


# ═══════════════════════════════════════════════════════════════════════════════
# H. Custom rates
# ═══════════════════════════════════════════════════════════════════════════════


class TestCustomRates:
    """Test with non-default rate configurations."""

    def test_zero_bonus_rate(self) -> None:
        """Zero bonus rate → zero bonus."""
        config = StakingConfig(
            bonus_rate_no_challenge=0.0,
            bonus_rate_challenged_upheld=0.0,
            slash_rate_challenged_overturned=0.50,
        )
        econ = StakingEconomics(config)
        ret, bonus = econ.calculate_return_no_challenge(_1_ETH)
        assert bonus == 0
        assert ret == _1_ETH

    def test_100_percent_slash(self) -> None:
        """100% slash → full stake slashed, zero returned."""
        config = StakingConfig(
            bonus_rate_no_challenge=0.10,
            bonus_rate_challenged_upheld=0.20,
            slash_rate_challenged_overturned=1.0,
        )
        econ = StakingEconomics(config)
        ret, slash = econ.calculate_slash_challenged_overturned(_1_ETH)
        assert slash == _1_ETH
        assert ret == 0

    def test_symmetric_rates_produce_symmetric_results(self) -> None:
        """When both bonus rates are equal, both methods give the same bonus."""
        config = StakingConfig(
            bonus_rate_no_challenge=0.15,
            bonus_rate_challenged_upheld=0.15,
            slash_rate_challenged_overturned=0.50,
        )
        econ = StakingEconomics(config)
        _, bonus_nc = econ.calculate_return_no_challenge(_1_ETH)
        _, bonus_up = econ.calculate_return_challenged_upheld(_1_ETH)
        assert bonus_nc == bonus_up


# ═══════════════════════════════════════════════════════════════════════════════
# I. Overflow safety
# ═══════════════════════════════════════════════════════════════════════════════


class TestOverflow:
    """Python ints are arbitrary precision — verify no overflow at extremes."""

    def test_very_large_stake(self, econ: StakingEconomics) -> None:
        """Stake of 2^128 wei (astronomical) should not overflow."""
        huge_stake = 2**128
        ret, bonus = econ.calculate_return_no_challenge(huge_stake)
        expected_bonus = huge_stake * 1_000 // 10_000
        assert bonus == expected_bonus
        assert ret == huge_stake + expected_bonus

    def test_very_large_slash(self, econ: StakingEconomics) -> None:
        """Slash on 2^128 wei should not overflow."""
        huge_stake = 2**128
        ret, slash = econ.calculate_slash_challenged_overturned(huge_stake)
        assert ret + slash == huge_stake


# ═══════════════════════════════════════════════════════════════════════════════
# J. __slots__ immutability
# ═══════════════════════════════════════════════════════════════════════════════


class TestImmutability:
    """StakingEconomics uses __slots__ — no arbitrary attributes allowed."""

    def test_no_dict(self, econ: StakingEconomics) -> None:
        assert not hasattr(econ, "__dict__")

    def test_cannot_set_arbitrary_attr(self, econ: StakingEconomics) -> None:
        with pytest.raises(AttributeError):
            econ.foo = "bar"  # type: ignore[attr-defined]
