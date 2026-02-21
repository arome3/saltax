"""Treasury orchestrator — coordinates wallet, policy, and intel DB.

Provides payout execution with two-layer lock serialization:
outer ``_payout_lock`` prevents TOCTOU on balance checks, inner
``WalletManager._tx_lock`` prevents nonce interleaving.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from web3 import AsyncWeb3

if TYPE_CHECKING:
    from src.config import BountyConfig, TreasuryConfig
    from src.intelligence.database import IntelligenceDB
    from src.observability.metrics import BudgetTracker
    from src.treasury.policy import PayoutRequest, TreasuryPolicy
    from src.treasury.wallet import WalletManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TreasurySnapshot:
    """Point-in-time view of treasury balance and allocations."""

    balance_wei: int
    reserve_wei: int
    compute_wei: int
    bounty_wei: int
    community_wei: int
    timestamp: str


@dataclass(frozen=True, slots=True)
class TransactionRecord:
    """Immutable record of a treasury transaction.

    ``amount_wei`` stores the amount in the smallest unit of the currency:
    Wei for ETH (10^18), atomic units for USDC (10^6).  The ``currency``
    field disambiguates.
    """

    tx_hash: str
    tx_type: str
    amount_wei: int
    counterparty: str
    timestamp: str
    currency: str = "ETH"
    bounty_id: str = ""
    audit_id: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


class TreasuryManager:
    """Orchestrates wallet, policy, and intel DB for treasury operations.

    All payout operations are serialized via ``_payout_lock`` to prevent
    TOCTOU races on balance checks.
    """

    def __init__(
        self,
        wallet: WalletManager,
        policy: TreasuryPolicy,
        intel_db: IntelligenceDB,
        treasury_config: TreasuryConfig,
        bounty_config: BountyConfig,
        budget_tracker: BudgetTracker | None = None,
    ) -> None:
        self._wallet = wallet
        self._policy = policy
        self._intel_db = intel_db
        self._treasury_config = treasury_config
        self._bounty_config = bounty_config
        self._budget_tracker = budget_tracker
        self._payout_lock = asyncio.Lock()
        self._tx_count: int = 0
        self._revenue_by_currency: dict[str, int] = {}  # currency → total atomic
        self._total_expenditure_wei: int = 0

    # ── Balance queries ───────────────────────────────────────────────────

    async def check_balance(self) -> TreasurySnapshot:
        """Fetch current balance and compute allocation breakdown."""
        balance = await self._wallet.get_balance()
        now = datetime.now(UTC).isoformat()
        cfg = self._treasury_config
        return TreasurySnapshot(
            balance_wei=balance,
            reserve_wei=int(balance * cfg.reserve_ratio),
            compute_wei=int(balance * cfg.compute_budget),
            bounty_wei=int(balance * cfg.bounty_budget),
            community_wei=int(balance * cfg.community_fund),
            timestamp=now,
        )

    def get_budget_allocation(self, balance_wei: int) -> dict[str, int]:
        """Compute live budget split from a balance snapshot."""
        cfg = self._treasury_config
        return {
            "bounty": int(balance_wei * cfg.bounty_budget),
            "reserve": int(balance_wei * cfg.reserve_ratio),
            "compute": int(balance_wei * cfg.compute_budget),
            "community": int(balance_wei * cfg.community_fund),
            "total": balance_wei,
        }

    def get_bounty_amount_wei(self, label: str) -> int | None:
        """Look up the Wei value for a bounty label.

        Returns ``None`` for unknown labels.
        """
        eth_amount = self._bounty_config.labels.get(label)
        if eth_amount is None:
            return None
        return AsyncWeb3.to_wei(eth_amount, "ether")

    # ── Payouts ───────────────────────────────────────────────────────────

    async def send_payout(self, request: PayoutRequest) -> TransactionRecord:
        """Execute a validated payout.

        Acquires ``_payout_lock`` to serialize:
        balance fetch → policy check → transaction send.

        Raises ``ValueError`` if policy rejects.
        Raises ``RuntimeError`` if wallet not initialized.
        """
        ctx = (
            self._budget_tracker.track("treasury_payout")
            if self._budget_tracker
            else nullcontext()
        )
        async with ctx, self._payout_lock:
            balance = await self._wallet.get_balance()

            ok, reason = self._policy.validate_payout(request, balance)
            if not ok:
                raise ValueError(f"Payout rejected by policy: {reason}")

            total_wei = request.amount_wei + request.stake_bonus_wei
            tx_hash = await self._wallet.send_transaction(
                to=request.recipient,
                value_wei=total_wei,
            )

            self._tx_count += 1
            self._total_expenditure_wei += total_wei

            now = datetime.now(UTC).isoformat()

            # Close the bounty in intel DB if a bounty_id was provided
            if request.bounty_id:
                try:
                    await self._intel_db.close_bounty(
                        request.bounty_id,
                        request.recipient,
                    )
                except Exception:
                    logger.exception(
                        "Failed to close bounty %s after payout",
                        request.bounty_id,
                    )

            record = TransactionRecord(
                tx_hash=tx_hash,
                tx_type="payout",
                amount_wei=total_wei,
                counterparty=request.recipient,
                timestamp=now,
                bounty_id=request.bounty_id,
            )

            try:
                await self._intel_db.record_transaction(
                    tx_id=str(uuid.uuid4()),
                    tx_hash=tx_hash,
                    tx_type="payout",
                    amount_wei=total_wei,
                    counterparty=request.recipient,
                    bounty_id=request.bounty_id,
                    timestamp=now,
                )
            except Exception:
                logger.exception("Failed to persist payout transaction")

            return record

    # ── Incoming transactions ─────────────────────────────────────────────

    async def record_incoming(
        self,
        *,
        tx_type: str,
        amount_wei: int,
        counterparty: str,
        currency: str = "ETH",
        tx_hash: str | None = None,
        audit_id: str | None = None,
    ) -> TransactionRecord:
        """Record an incoming transaction (sponsorship, audit fee, penalty).

        Updates the per-currency revenue counter and persists to the DB.
        ``amount_wei`` stores the value in the smallest unit of the given
        ``currency`` (Wei for ETH, atomic units for USDC).
        """
        self._revenue_by_currency[currency] = (
            self._revenue_by_currency.get(currency, 0) + amount_wei
        )
        self._tx_count += 1
        now = datetime.now(UTC).isoformat()
        record = TransactionRecord(
            tx_hash=tx_hash or "",
            tx_type=tx_type,
            amount_wei=amount_wei,
            counterparty=counterparty,
            timestamp=now,
            currency=currency,
            audit_id=audit_id or "",
        )

        try:
            await self._intel_db.record_transaction(
                tx_id=str(uuid.uuid4()),
                tx_hash=tx_hash or "",
                tx_type=tx_type,
                amount_wei=amount_wei,
                currency=currency,
                counterparty=counterparty,
                audit_id=audit_id,
                timestamp=now,
            )
        except Exception:
            logger.exception("Failed to persist incoming transaction")

        return record

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def close(self) -> None:
        """No-op — sub-services have their own lifecycle via teardown."""
