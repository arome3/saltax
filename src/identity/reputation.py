"""Fire-and-forget reputation updates and local metrics aggregation.

Reputation events are mapped to on-chain feedback via the TS bridge.
Local metrics are aggregated from ``pipeline_history`` in the intel DB.
No method in this module raises on bridge failure — all calls degrade.
"""

from __future__ import annotations

import logging
import time
from enum import StrEnum
from typing import TYPE_CHECKING

from src.models.identity import ReputationMetrics

if TYPE_CHECKING:
    from src.identity.bridge_client import IdentityBridgeClient
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)


class ReputationEvent(StrEnum):
    """Events that affect the agent's on-chain reputation."""

    SUCCESSFUL_MERGE = "successful_merge"
    REJECTED_PR = "rejected_pr"
    CHALLENGE_UPHELD = "challenge_upheld"
    DISPUTE_RESOLVED = "dispute_resolved"
    AUDIT_COMPLETED = "audit_completed"
    VULNERABILITY_CAUGHT = "vulnerability_caught"


# Each event maps to (value, tag1, tag2) for the SDK's giveFeedback call.
_EVENT_FEEDBACK_MAP: dict[ReputationEvent, tuple[int, str, str]] = {
    ReputationEvent.SUCCESSFUL_MERGE: (85, "code-review", "merge"),
    ReputationEvent.REJECTED_PR: (30, "code-review", "reject"),
    ReputationEvent.CHALLENGE_UPHELD: (90, "verification", "challenge-upheld"),
    ReputationEvent.DISPUTE_RESOLVED: (70, "verification", "dispute-resolved"),
    ReputationEvent.AUDIT_COMPLETED: (80, "audit", "completed"),
    ReputationEvent.VULNERABILITY_CAUGHT: (95, "security", "vuln-caught"),
}


class ReputationManager:
    """Manages reputation updates and metrics aggregation.

    Reads from intel_db for local metrics, calls bridge for on-chain
    feedback.  All bridge calls are fire-and-forget — failures are
    logged but never raised.

    Concurrency: reads only from intel_db (no ``_write_lock`` needed).
    Bridge calls are independent (no shared mutable state).
    """

    def __init__(
        self,
        bridge_client: IdentityBridgeClient,
        intel_db: IntelligenceDB | None,
        agent_id: str,
    ) -> None:
        self._bridge_client = bridge_client
        self._intel_db = intel_db
        self._agent_id = agent_id
        self._boot_time = time.monotonic()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    async def update_reputation(self, event: ReputationEvent) -> None:
        """Submit a reputation event to the on-chain bridge.

        Fire-and-forget: never raises, logs failures.
        """
        if not self._agent_id:
            logger.warning("No agent_id set, skipping reputation update for %s", event)
            return

        feedback = _EVENT_FEEDBACK_MAP.get(event)
        if feedback is None:
            logger.warning("Unknown reputation event: %s", event)
            return

        value, tag1, tag2 = feedback
        try:
            result = await self._bridge_client.give_feedback(
                self._agent_id, value, tag1, tag2,
            )
            if result is not None:
                logger.info(
                    "Reputation updated: event=%s value=%d", event, value,
                )
            else:
                logger.warning(
                    "Reputation update failed (bridge returned None): event=%s",
                    event,
                )
        except Exception:
            logger.exception("Reputation update failed: event=%s", event)

    async def get_metrics(self) -> ReputationMetrics:
        """Aggregate local reputation metrics from ``pipeline_history``.

        Returns zeroed metrics if intel_db is unavailable or queries fail.
        """
        if self._intel_db is None:
            return ReputationMetrics()

        try:
            db = self._intel_db._require_db()

            # Total PRs reviewed
            async with db.execute(
                "SELECT COUNT(*) FROM pipeline_history",
            ) as cursor:
                row = await cursor.fetchone()
                total_reviewed = row[0] if row else 0

            # Approved PRs — json_extract for exact field matching
            async with db.execute(
                "SELECT COUNT(*) FROM pipeline_history "
                "WHERE LOWER(json_extract(verdict, '$.decision')) "
                "IN ('approve', 'approved')",
            ) as cursor:
                row = await cursor.fetchone()
                total_approved = row[0] if row else 0

            total_rejected = total_reviewed - total_approved

            # Vulnerability patterns discovered
            vuln_count = await self._intel_db.count_patterns()

            # Total bounties paid (claimed bounties, ETH → wei)
            async with db.execute(
                "SELECT COALESCE(SUM(amount_eth), 0.0) "
                "FROM active_bounties WHERE status = 'claimed'",
            ) as cursor:
                row = await cursor.fetchone()
                total_bounties_eth = row[0] if row else 0.0

            uptime = int(time.monotonic() - self._boot_time)

            return ReputationMetrics(
                total_prs_reviewed=total_reviewed,
                total_prs_approved=total_approved,
                total_prs_rejected=total_rejected,
                vulnerabilities_caught=vuln_count,
                total_bounties_paid_wei=int(total_bounties_eth * 10**18),
                uptime_seconds=uptime,
            )
        except Exception:
            logger.exception("Failed to aggregate reputation metrics")
            return ReputationMetrics()

    async def get_on_chain_reputation(self) -> dict | None:
        """Fetch the on-chain reputation summary from the bridge.

        Returns None if the bridge is unavailable.
        """
        if not self._agent_id:
            return None
        try:
            return await self._bridge_client.get_reputation_summary(self._agent_id)
        except Exception:
            logger.exception("Failed to fetch on-chain reputation")
            return None

    async def close(self) -> None:
        """Release reputation manager resources.

        Does NOT close the bridge client (owned by IdentityRegistrar).
        """
