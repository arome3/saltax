"""Stateless verification-window domain logic.

All state lives in the intelligence DB.  This module provides pure functions
for window creation, expiry checks, challenge validation, and staking bonuses.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.config import StakingConfig, VerificationConfig
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

# ── State machine ─────────────────────────────────────────────────────────────

_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"executing", "challenged"}),
    "executing": frozenset({"executed", "open"}),  # open = retry on merge fail
    "challenged": frozenset({"resolved", "resolving"}),
    "resolving": frozenset({"resolved", "challenged"}),  # challenged = retry on merge fail
    "executed": frozenset(),  # terminal
    "resolved": frozenset(),  # terminal
}


def is_valid_transition(from_status: str, to_status: str) -> bool:
    """Return True if the state transition is allowed."""
    return to_status in _VALID_TRANSITIONS.get(from_status, frozenset())


# ── Window creation ───────────────────────────────────────────────────────────


async def create_window(
    *,
    intel_db: IntelligenceDB,
    config: VerificationConfig,
    pr_id: str,
    repo: str,
    pr_number: int,
    installation_id: int,
    attestation_id: str,
    verdict: dict[str, object],
    attestation: dict[str, object],
    contributor_address: str | None,
    bounty_amount_wei: int | None,
    stake_amount_wei: int | None = None,
    is_self_modification: bool,
) -> str:
    """Create a verification window and persist it. Returns the window ID."""
    window_id = uuid.uuid4().hex
    now = datetime.now(UTC)

    if is_self_modification:
        hours = config.self_modification_window_hours
    else:
        hours = config.standard_window_hours

    opens_at = now.isoformat()
    closes_at = (now + timedelta(hours=hours)).isoformat()

    await intel_db.store_verification_window(
        window_id=window_id,
        pr_id=pr_id,
        repo=repo,
        pr_number=pr_number,
        installation_id=installation_id,
        attestation_id=attestation_id,
        verdict_json=json.dumps(verdict, default=str),
        attestation_json=json.dumps(attestation, default=str),
        contributor_address=contributor_address,
        bounty_amount_wei=str(bounty_amount_wei or 0),
        stake_amount_wei=str(
            stake_amount_wei if stake_amount_wei is not None else (bounty_amount_wei or 0),
        ),
        window_hours=hours,
        opens_at=opens_at,
        closes_at=closes_at,
    )

    logger.info(
        "Verification window created",
        extra={
            "window_id": window_id,
            "pr_id": pr_id,
            "window_hours": hours,
            "closes_at": closes_at,
        },
    )
    return window_id


# ── Expiry ────────────────────────────────────────────────────────────────────


def is_expired(window: dict[str, object]) -> bool:
    """Return True if the window's challenge period has elapsed."""
    closes_at = datetime.fromisoformat(str(window["closes_at"]))
    return datetime.now(UTC) >= closes_at


# ── Challenge validation ──────────────────────────────────────────────────────


def validate_challenge_stake(
    window: dict[str, object],
    stake_wei: int,
    config: VerificationConfig,
) -> tuple[bool, str]:
    """Check that a challenge stake meets the minimum requirement.

    Returns ``(True, "ok")`` or ``(False, reason)``.
    """
    bounty = int(window.get("bounty_amount_wei", 0) or 0)
    required = int(bounty * config.min_challenge_stake_multiplier)

    # Zero-bounty edge case: any positive stake is sufficient
    if required == 0 and stake_wei >= 0:
        return (True, "ok")

    if stake_wei < required:
        return (
            False,
            f"Stake {stake_wei} wei below minimum {required} wei "
            f"(bounty {bounty} × multiplier {config.min_challenge_stake_multiplier})",
        )
    return (True, "ok")


# ── Staking bonus ─────────────────────────────────────────────────────────────


def compute_staking_bonus(
    window: dict[str, object],
    staking_config: StakingConfig,
) -> int:
    """Compute the staking bonus in Wei for a completed window.

    Returns 0 if staking is disabled or stake is zero.
    """
    if not staking_config.enabled:
        return 0

    stake = int(window.get("stake_amount_wei", 0) or 0)
    if stake == 0:
        return 0

    resolution = window.get("resolution")
    if resolution == "upheld":
        rate = staking_config.bonus_rate_challenged_upheld
    else:
        rate = staking_config.bonus_rate_no_challenge

    return int(stake * rate)
