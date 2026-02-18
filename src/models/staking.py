"""Contributor staking and challenge models.

``StakeDeposit`` and ``ChallengeEvent`` are mutable — their ``status``
fields transition through the staking lifecycle.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.models.enums import ChallengeStatus, DisputeType, StakeStatus

# ── Stake deposit ───────────────────────────────────────────────────────────


class StakeDeposit(BaseModel):
    """A contributor's stake deposit against a pull request."""

    model_config = ConfigDict(extra="forbid")

    stake_id: str
    pr_id: str
    contributor_address: str
    amount_wei: int
    deposit_tx_hash: str
    status: StakeStatus
    deposited_at: datetime
    resolved_at: datetime | None = None
    resolution_tx_hash: str | None = None


# ── Challenge event ─────────────────────────────────────────────────────────


class ChallengeEvent(BaseModel):
    """An optimistic-verification challenge filed against a verdict."""

    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    pr_id: str
    challenger_address: str
    stake_amount_wei: int
    rationale: str
    evidence_hash: str | None = None
    dispute_type: DisputeType
    status: ChallengeStatus
    filed_at: datetime
    resolved_at: datetime | None = None
    eigenverify_case_id: str | None = None
    moltcourt_case_id: str | None = None
