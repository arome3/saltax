"""Pure staking economics engine — integer-only calculations.

Converts float config rates to basis points at construction time.
All calculation methods use integer arithmetic to avoid IEEE 754
precision loss on large Wei values.  Immutable after ``__init__``;
safe to share across concurrent coroutines without locks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.config import StakingConfig


def _rate_to_bps(rate: float) -> int:
    """Convert a 0.0–1.0 float rate to integer basis points (0–10 000).

    Uses ``round()`` to avoid truncation from float representation
    (e.g. ``0.10 * 10_000`` may evaluate to ``999.999…``).
    """
    bps = int(round(rate * 10_000))
    if not (0 <= bps <= 10_000):
        raise ValueError(
            f"Rate {rate} converts to {bps} bps, must be in 0–10 000"
        )
    return bps


class StakingEconomics:
    """Immutable staking calculator — no I/O, no async, no locks.

    Rates are stored as integer basis points (1 bps = 0.01%).
    All methods return Wei amounts using only integer division.

    Usage::

        econ = StakingEconomics(staking_config)
        return_amount, bonus = econ.calculate_return_no_challenge(stake_wei)
    """

    __slots__ = (
        "_bonus_bps_no_challenge",
        "_bonus_bps_upheld",
        "_slash_bps_overturned",
    )

    def __init__(self, config: StakingConfig) -> None:
        self._bonus_bps_no_challenge = _rate_to_bps(config.bonus_rate_no_challenge)
        self._bonus_bps_upheld = _rate_to_bps(config.bonus_rate_challenged_upheld)
        self._slash_bps_overturned = _rate_to_bps(config.slash_rate_challenged_overturned)

    @staticmethod
    def _validate_stake(stake_wei: int) -> None:
        if stake_wei <= 0:
            raise ValueError(f"stake_wei must be positive, got {stake_wei}")

    # ── Calculation methods ──────────────────────────────────────────────

    def calculate_return_no_challenge(self, stake_wei: int) -> tuple[int, int]:
        """Unchallenged window: contributor receives stake + bonus.

        Returns ``(return_amount, bonus_amount)`` in Wei.
        """
        self._validate_stake(stake_wei)
        bonus = stake_wei * self._bonus_bps_no_challenge // 10_000
        return (stake_wei + bonus, bonus)

    def calculate_return_challenged_upheld(self, stake_wei: int) -> tuple[int, int]:
        """Challenge upheld (original verdict correct): stake + higher bonus.

        Returns ``(return_amount, bonus_amount)`` in Wei.
        """
        self._validate_stake(stake_wei)
        bonus = stake_wei * self._bonus_bps_upheld // 10_000
        return (stake_wei + bonus, bonus)

    def calculate_slash_challenged_overturned(self, stake_wei: int) -> tuple[int, int]:
        """Challenge overturned (original verdict wrong): stake minus slash.

        Returns ``(return_amount, slash_amount)`` in Wei.
        """
        self._validate_stake(stake_wei)
        slash = stake_wei * self._slash_bps_overturned // 10_000
        return (stake_wei - slash, slash)

    def calculate_refund_rejected(self, stake_wei: int) -> int:
        """PR rejected before merge: full refund of stake.

        Returns the original ``stake_wei`` unchanged.
        """
        self._validate_stake(stake_wei)
        return stake_wei
