"""Stake resolution orchestrator — connects economics and contract layers.

Pre-checks on-chain state before acting to prevent double-spend and
idempotency violations.  All write operations follow the pattern:

1. ``get_stake()`` → verify the stake exists and is not already resolved.
2. Compute amounts via ``StakingEconomics``.
3. Call the appropriate ``StakingContract`` method.
4. Return a structured result dict.

Concurrency model:
- No internal locks.  Nonce serialisation is handled by
  ``WalletManager._tx_lock`` (inherited through ``StakingContract``).
- The on-chain ``require(!stake.resolved)`` is the ultimate guard;
  the pre-check here is a fast-fail optimisation.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.staking.contract import StakingContract
    from src.staking.economics import StakingEconomics

logger = logging.getLogger(__name__)


class StakeResolver:
    """Orchestrates stake resolution with idempotency pre-checks.

    Usage::

        resolver = StakeResolver(contract, economics)
        result = await resolver.resolve_no_challenge(stake_id)
    """

    __slots__ = ("_contract", "_economics")

    def __init__(
        self,
        contract: StakingContract,
        economics: StakingEconomics,
    ) -> None:
        self._contract = contract
        self._economics = economics

    # ── Pre-check ─────────────────────────────────────────────────────────

    async def _pre_check(self, stake_id: bytes) -> dict[str, Any]:
        """Read on-chain stake and verify it's unresolved.

        Returns the stake data dict.
        Raises ``RuntimeError`` if the stake is already resolved or
        has zero amount (non-existent).
        """
        stake = await self._contract.get_stake(stake_id)
        if stake["resolved"]:
            raise RuntimeError(
                f"Stake {stake_id.hex()} is already resolved — "
                "cannot resolve again (idempotency violation)"
            )
        if stake["amount"] == 0:
            raise RuntimeError(
                f"Stake {stake_id.hex()} has zero amount — "
                "stake does not exist on-chain"
            )
        return stake

    # ── Resolution methods ────────────────────────────────────────────────

    async def resolve_no_challenge(
        self, stake_id: bytes,
    ) -> dict[str, Any]:
        """Resolve an unchallenged stake: contributor gets stake + bonus.

        Pre-checks on-chain state, computes bonus, calls ``release_stake``.
        """
        stake = await self._pre_check(stake_id)
        amount = stake["amount"]

        return_amount, bonus = self._economics.calculate_return_no_challenge(amount)
        tx_hash = await self._contract.release_stake(stake_id, bonus)

        logger.info(
            "Resolved stake (no challenge)",
            extra={
                "stake_id": stake_id.hex(),
                "amount": amount,
                "bonus": bonus,
                "return_amount": return_amount,
                "tx_hash": tx_hash,
            },
        )
        return {
            "outcome": "no_challenge",
            "stake_id": stake_id,
            "original_amount": amount,
            "bonus_amount": bonus,
            "return_amount": return_amount,
            "tx_hash": tx_hash,
        }

    async def resolve_challenged_upheld(
        self, stake_id: bytes,
    ) -> dict[str, Any]:
        """Resolve an upheld challenge: contributor gets stake + higher bonus.

        Pre-checks on-chain state, computes bonus, calls ``release_stake``.
        """
        stake = await self._pre_check(stake_id)
        amount = stake["amount"]

        return_amount, bonus = self._economics.calculate_return_challenged_upheld(amount)
        tx_hash = await self._contract.release_stake(stake_id, bonus)

        logger.info(
            "Resolved stake (challenged upheld)",
            extra={
                "stake_id": stake_id.hex(),
                "amount": amount,
                "bonus": bonus,
                "return_amount": return_amount,
                "tx_hash": tx_hash,
            },
        )
        return {
            "outcome": "challenged_upheld",
            "stake_id": stake_id,
            "original_amount": amount,
            "bonus_amount": bonus,
            "return_amount": return_amount,
            "tx_hash": tx_hash,
        }

    async def resolve_challenged_overturned(
        self, stake_id: bytes,
    ) -> dict[str, Any]:
        """Resolve an overturned challenge: contributor loses slash portion.

        Pre-checks on-chain state, computes slash percent, calls
        ``slash_stake``.  The slash_percent for the contract is derived
        from the config rate (e.g. 0.50 → 50).
        """
        stake = await self._pre_check(stake_id)
        amount = stake["amount"]

        return_amount, slash_amount = (
            self._economics.calculate_slash_challenged_overturned(amount)
        )
        # Convert slash bps to percentage for the contract (1-100)
        slash_percent = self._economics._slash_bps_overturned * 100 // 10_000
        if slash_percent < 1:
            slash_percent = 1  # Contract requires 1-100

        tx_hash = await self._contract.slash_stake(stake_id, slash_percent)

        logger.info(
            "Resolved stake (challenged overturned)",
            extra={
                "stake_id": stake_id.hex(),
                "amount": amount,
                "slash_amount": slash_amount,
                "return_amount": return_amount,
                "slash_percent": slash_percent,
                "tx_hash": tx_hash,
            },
        )
        return {
            "outcome": "challenged_overturned",
            "stake_id": stake_id,
            "original_amount": amount,
            "slash_amount": slash_amount,
            "return_amount": return_amount,
            "slash_percent": slash_percent,
            "tx_hash": tx_hash,
        }

    async def resolve_rejected(
        self, stake_id: bytes,
    ) -> dict[str, Any]:
        """Resolve a rejected PR: full refund of stake.

        Pre-checks on-chain state, calls ``refund_stake``.
        """
        stake = await self._pre_check(stake_id)
        amount = stake["amount"]

        refund_amount = self._economics.calculate_refund_rejected(amount)
        tx_hash = await self._contract.refund_stake(stake_id)

        logger.info(
            "Resolved stake (rejected)",
            extra={
                "stake_id": stake_id.hex(),
                "amount": amount,
                "refund_amount": refund_amount,
                "tx_hash": tx_hash,
            },
        )
        return {
            "outcome": "rejected",
            "stake_id": stake_id,
            "original_amount": amount,
            "refund_amount": refund_amount,
            "tx_hash": tx_hash,
        }
