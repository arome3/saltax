"""Treasury payout policy enforcement.

Validates payout requests against three treasury constraints using
a single balance snapshot to prevent TOCTOU races.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from web3 import AsyncWeb3

if TYPE_CHECKING:
    from src.config import TreasuryConfig


@dataclass(frozen=True, slots=True)
class PayoutRequest:
    """A request to pay a contributor from the treasury."""

    recipient: str
    amount_wei: int
    stake_bonus_wei: int = 0
    bounty_id: str = ""
    label: str = ""

    def __post_init__(self) -> None:
        if self.amount_wei < 0:
            raise ValueError(f"amount_wei must be non-negative, got {self.amount_wei}")
        if self.stake_bonus_wei < 0:
            raise ValueError(f"stake_bonus_wei must be non-negative, got {self.stake_bonus_wei}")


class TreasuryPolicy:
    """Enforces three payout constraints against a balance snapshot.

    Checks (all applied to the same ``balance_wei``):

    1. **Max single payout** — total must not exceed ``max_single_payout_eth``
    2. **Reserve ratio** — remaining balance must satisfy ``reserve_ratio``
    3. **Bounty budget** — total must not exceed ``bounty_budget`` share
    """

    def __init__(self, config: TreasuryConfig) -> None:
        self._max_single_wei = AsyncWeb3.to_wei(config.max_single_payout_eth, "ether")
        self._reserve_ratio = config.reserve_ratio
        self._bounty_budget = config.bounty_budget

    def validate_payout(
        self,
        request: PayoutRequest,
        balance_wei: int,
    ) -> tuple[bool, str]:
        """Validate a payout against treasury policy.

        Returns ``(True, "ok")`` on success or ``(False, reason)`` on
        rejection.  All three checks use the same *balance_wei* snapshot.
        """
        total_wei = request.amount_wei + request.stake_bonus_wei

        # Check 1: max single payout
        if total_wei > self._max_single_wei:
            return (
                False,
                f"Payout {total_wei} wei exceeds max single payout {self._max_single_wei} wei",
            )

        # Check 2: reserve ratio — remaining balance must meet reserve
        if balance_wei > 0:
            remaining = balance_wei - total_wei
            required_reserve = int(balance_wei * self._reserve_ratio)
            if remaining < required_reserve:
                return (
                    False,
                    f"Remaining {remaining} wei would violate reserve "
                    f"requirement of {required_reserve} wei",
                )

        # Check 3: bounty budget — total must fit within bounty allocation
        if balance_wei > 0:
            budget_wei = int(balance_wei * self._bounty_budget)
            if total_wei > budget_wei:
                return (
                    False,
                    f"Payout {total_wei} wei exceeds bounty budget {budget_wei} wei",
                )

        # Zero balance with any positive payout fails reserve check implicitly
        if balance_wei == 0 and total_wei > 0:
            return (False, "Treasury balance is zero")

        return (True, "ok")
