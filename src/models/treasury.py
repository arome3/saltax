"""Treasury operation models.

``TransactionRecord`` and ``TreasurySnapshot`` are frozen value objects.
``PayoutRequest`` is mutable — bounty payout logic may attach a stake bonus
after initial construction.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.models.enums import TransactionType

# ── Transaction record ──────────────────────────────────────────────────────


class TransactionRecord(BaseModel):
    """Immutable record of a single on-chain treasury transaction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tx_id: str
    tx_hash: str | None = None
    tx_type: TransactionType
    amount_wei: int
    counterparty: str
    pr_id: str | None = None
    audit_id: str | None = None
    timestamp: datetime
    attestation_id: str | None = None


# ── Treasury snapshot ───────────────────────────────────────────────────────


class TreasurySnapshot(BaseModel):
    """Point-in-time snapshot of treasury balances and lifetime counters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    balance_wei: int
    available_for_bounties_wei: int
    reserve_floor_wei: int
    compute_allocation_wei: int
    community_fund_wei: int
    total_revenue_lifetime_wei: int
    total_expenditure_lifetime_wei: int
    transaction_count: int
    last_updated: datetime


# ── Payout request ──────────────────────────────────────────────────────────


class PayoutRequest(BaseModel):
    """Request to disburse a bounty (and optional stake bonus) to a contributor."""

    model_config = ConfigDict(extra="forbid")

    recipient_address: str
    amount_wei: int
    pr_id: str
    bounty_label: str
    include_stake_bonus: bool = False
    stake_bonus_wei: int = 0
