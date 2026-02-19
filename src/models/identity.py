"""ERC-8004 identity and reputation models.

``ReputationMetrics`` tracks cumulative counters with computed properties for
derived rates.  ``AgentIdentity`` wraps the on-chain identity registration.

Only fields with active write paths are included.  Fields like
``disputes_filed`` and ``self_upgrade_count`` are omitted until the
verification and self-modification subsystems feed them.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, computed_field

# ── Reputation metrics ──────────────────────────────────────────────────────


class ReputationMetrics(BaseModel):
    """Cumulative reputation counters for the SaltaX agent.

    Every field here has at least one write path in ``ReputationManager``.
    """

    model_config = ConfigDict(extra="forbid")

    total_prs_reviewed: int = 0
    total_prs_approved: int = 0
    total_prs_rejected: int = 0
    vulnerabilities_caught: int = 0
    total_bounties_paid_wei: int = 0
    uptime_seconds: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def approval_rate(self) -> float:
        """Fraction of reviewed PRs that were approved."""
        if self.total_prs_reviewed == 0:
            return 0.0
        return self.total_prs_approved / self.total_prs_reviewed


# ── Agent identity ──────────────────────────────────────────────────────────


class AgentIdentity(BaseModel):
    """On-chain agent identity registered via ERC-8004."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str
    chain_id: int
    wallet_address: str
    name: str
    description: str
    registered_at: datetime
