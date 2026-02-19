"""Background dispute scheduler — retries, polls, enforces timeouts.

Runs as an asyncio task alongside the verification scheduler.  Each tick
has three phases:

1. **Retry pending**: Re-submit disputes that failed initial submission.
2. **Poll submitted**: Check providers for resolution of active disputes.
3. **Check timeouts**: Auto-resolve disputes past their provider deadline.

Timeout auto-resolution favors the **original verdict** (per doc 18):
timeout → challenge REJECTED → challenger slashed 100%.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from src.disputes.molt_court import CircuitBreakerOpenError
from src.disputes.router import DisputeRouter
from src.models.enums import DisputeType

if TYPE_CHECKING:
    from src.config import DisputeConfig
    from src.intelligence.database import IntelligenceDB
    from src.verification.scheduler import VerificationScheduler

logger = logging.getLogger(__name__)


class DisputeScheduler:
    """Background task that manages dispute lifecycle progression.

    Lifecycle::

        sched = DisputeScheduler(config, intel_db, router, verification_sched)
        task = asyncio.create_task(sched.run())
        # ... later ...
        await sched.stop()
        await sched.close()
    """

    def __init__(
        self,
        config: DisputeConfig,
        intel_db: IntelligenceDB,
        router: DisputeRouter,
        verification_scheduler: VerificationScheduler,
    ) -> None:
        self._config = config
        self._db = intel_db
        self._router = router
        self._verification = verification_scheduler
        self._stop_event = asyncio.Event()

    @property
    def running(self) -> bool:
        return not self._stop_event.is_set()

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Run the scheduler loop until :meth:`stop` is called."""
        logger.info("DisputeScheduler started")
        while not self._stop_event.is_set():
            try:
                await self._tick()
            except Exception:
                logger.exception("DisputeScheduler tick error")
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._config.poll_interval_seconds,
                )
                break
            except TimeoutError:
                pass

    async def stop(self) -> None:
        """Signal the scheduler to stop."""
        self._stop_event.set()

    async def close(self) -> None:
        """Resource-cleanup alias for :meth:`stop`."""
        await self.stop()

    # ── Tick ─────────────────────────────────────────────────────────────

    async def _tick(self) -> None:
        """Execute all three scheduler phases.

        Tracks dispute IDs mutated in earlier phases so that later phases
        skip them — prevents double-processing within a single tick.
        """
        mutated: set[str] = set()
        await self._retry_pending(mutated)
        await self._poll_submitted(mutated)
        await self._check_timeouts(mutated)

    # ── Phase 1: Retry pending ──────────────────────────────────────────

    async def _retry_pending(self, mutated: set[str]) -> None:
        """Re-submit disputes stuck in PENDING status."""
        pending = await self._db.get_disputes_by_status("pending")
        for record in pending:
            dispute_id = str(record["dispute_id"])
            attempts = int(record.get("submission_attempts", 0) or 0)

            if attempts >= self._config.max_submission_retries:
                logger.warning(
                    "Dispute exceeded max retries, marking FAILED",
                    extra={"dispute_id": dispute_id, "attempts": attempts},
                )
                await self._db.update_dispute_record(
                    dispute_id, status="failed",
                )
                mutated.add(dispute_id)
                continue

            try:
                dispute_type = str(record["dispute_type"])
                att_json = record.get("attestation_json")

                if dispute_type == DisputeType.COMPUTATION:
                    proof_data: dict[str, Any] = {}
                    if att_json:
                        with contextlib.suppress(json.JSONDecodeError, TypeError):
                            proof_data = json.loads(str(att_json))
                    result = await self._router._eigen.submit_dispute(
                        dispute_id, proof_data,
                    )
                else:
                    claim_data: dict[str, Any] = {
                        "claim_type": str(record["claim_type"]),
                        "window_id": str(record["window_id"]),
                        "challenge_id": str(record["challenge_id"]),
                    }
                    # Include rationale from attestation for subjective disputes
                    if att_json:
                        with contextlib.suppress(json.JSONDecodeError, TypeError):
                            att = json.loads(str(att_json))
                            if isinstance(att, dict) and att.get("challenge_rationale"):
                                claim_data["rationale"] = str(att["challenge_rationale"])
                    result = await self._router._molt.submit_dispute(
                        dispute_id, claim_data,
                    )

                await self._db.update_dispute_record(
                    dispute_id,
                    status="submitted",
                    provider_case_id=result.provider_case_id,
                    submission_attempts=attempts + 1,
                )
                mutated.add(dispute_id)
                logger.info(
                    "Pending dispute retried successfully",
                    extra={"dispute_id": dispute_id, "attempt": attempts + 1},
                )
            except CircuitBreakerOpenError:
                logger.warning(
                    "Circuit breaker open, skipping retry",
                    extra={"dispute_id": dispute_id},
                )
            except Exception:
                logger.exception(
                    "Retry failed for pending dispute",
                    extra={"dispute_id": dispute_id},
                )
                await self._db.update_dispute_record(
                    dispute_id,
                    submission_attempts=attempts + 1,
                )

    # ── Phase 2: Poll submitted ─────────────────────────────────────────

    async def _poll_submitted(self, mutated: set[str]) -> None:
        """Check providers for resolution of SUBMITTED disputes."""
        submitted = await self._db.get_disputes_by_status("submitted")
        for record in submitted:
            dispute_id = str(record["dispute_id"])
            if dispute_id in mutated:
                continue
            try:
                resolved, verdict = await self._router.check_dispute_resolution(
                    dispute_id,
                )
                if resolved and verdict is not None:
                    mutated.add(dispute_id)
                    await self._handle_resolution(record, verdict)
            except CircuitBreakerOpenError:
                logger.warning(
                    "Circuit breaker open, skipping poll",
                    extra={"dispute_id": dispute_id},
                )
            except Exception:
                logger.exception(
                    "Error polling dispute resolution",
                    extra={"dispute_id": dispute_id},
                )

    # ── Phase 3: Check timeouts ─────────────────────────────────────────

    async def _check_timeouts(self, mutated: set[str]) -> None:
        """Auto-resolve disputes past their provider deadline.

        Timeout → challenge REJECTED (original verdict stands, per doc 18).
        Challenger is slashed 100%, contributor gets stake + bonus.

        Skips disputes already mutated earlier in this tick.
        """
        now = datetime.now(UTC)

        for status in ("pending", "submitted"):
            records = await self._db.get_disputes_by_status(status)
            for record in records:
                dispute_id = str(record["dispute_id"])
                if dispute_id in mutated:
                    continue

                dispute_type = str(record["dispute_type"])
                created_at_str = str(record["created_at"])

                try:
                    created_at = datetime.fromisoformat(created_at_str)
                except (ValueError, TypeError):
                    logger.warning(
                        "Invalid created_at for dispute, skipping timeout check",
                        extra={"dispute_id": dispute_id},
                    )
                    continue

                # Determine deadline based on dispute type
                if dispute_type == DisputeType.COMPUTATION:
                    deadline_hours = self._config.eigenverify_deadline_hours
                else:
                    deadline_hours = self._config.moltcourt_deadline_hours

                deadline = created_at + timedelta(hours=deadline_hours)
                if now < deadline:
                    continue

                logger.warning(
                    "Dispute timed out, auto-resolving as challenge REJECTED",
                    extra={
                        "dispute_id": dispute_id,
                        "deadline_hours": deadline_hours,
                    },
                )
                await self._db.update_dispute_record(
                    dispute_id,
                    status="timed_out",
                    resolved_at=now.isoformat(),
                )
                mutated.add(dispute_id)
                # Timeout = challenger loses (original verdict stands)
                await self._handle_resolution(record, "rejected")

    # ── Resolution handler ──────────────────────────────────────────────

    async def _handle_resolution(
        self,
        record: dict[str, object],
        verdict: str,
    ) -> None:
        """Process a resolved dispute: update window, apply staking.

        Validates that the verdict is a known value before applying
        financial consequences.  Unknown verdicts route to MANUAL_REVIEW.

        Terminology mapping:
          verdict="upheld"    → doc 18 "challenge upheld" → challenger WINS
                              → existing resolve_challenge(upheld=False) [overturned]
          verdict="overturned" or "rejected"
                              → doc 18 "challenge rejected" → challenger LOSES
                              → existing resolve_challenge(upheld=True) [upheld]
        """
        dispute_id = str(record["dispute_id"])
        window_id = str(record["window_id"])

        # Validate verdict before applying financial consequences
        if not DisputeRouter.is_known_verdict(verdict):
            logger.error(
                "Unknown verdict from provider — routing to MANUAL_REVIEW",
                extra={"dispute_id": dispute_id, "verdict": verdict},
            )
            await self._db.update_dispute_record(
                dispute_id,
                status="manual_review",
            )
            return

        # Map verdict to challenger_won boolean
        # "upheld" = challenger wins (doc 18 semantics)
        challenger_won = verdict == "upheld"

        # Map to existing code semantics:
        # challenger_won=True  → resolve_challenge(upheld=False) [overturned in existing code]
        # challenger_won=False → resolve_challenge(upheld=True)  [upheld in existing code]
        existing_upheld = not challenger_won

        # Step 1: Resolve the verification window
        try:
            ok, msg = await self._verification.resolve_challenge(
                window_id, upheld=existing_upheld,
            )
            if not ok:
                logger.error(
                    "Failed to resolve challenge on window",
                    extra={"dispute_id": dispute_id, "window_id": window_id, "reason": msg},
                )
        except Exception:
            logger.exception(
                "Error resolving challenge on window",
                extra={"dispute_id": dispute_id, "window_id": window_id},
            )

        # Step 2: Apply staking consequences
        try:
            await self._router.apply_staking_consequences(
                dispute_id, challenger_won=challenger_won,
            )
        except Exception:
            logger.exception(
                "Error applying staking consequences",
                extra={"dispute_id": dispute_id},
            )
