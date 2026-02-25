"""Dispute router — classifies, persists, routes, and applies staking consequences.

Core orchestration layer between the external dispute providers (EigenVerify,
MoltCourt) and the internal verification/staking systems.

Concurrency model:
- DB writes use PostgreSQL MVCC (no application-level lock needed).
- On-chain operations are serialized through ``WalletManager._tx_lock``
  (via StakeResolver / StakingContract).
- Each dispute is independent — no shared mutable state between disputes.
"""

from __future__ import annotations

import contextlib
import json
import logging
import uuid
from typing import TYPE_CHECKING

from src.models.enums import ClaimType, DisputeType

if TYPE_CHECKING:
    from src.config import DisputeConfig
    from src.disputes.eigen_verify import EigenVerifyClient
    from src.disputes.molt_court import MoltCourtClient
    from src.intelligence.database import IntelligenceDB
    from src.staking.contract import StakingContract
    from src.staking.resolver import StakeResolver

logger = logging.getLogger(__name__)

# Valid verdicts from external providers.  Anything outside this set
# is routed to MANUAL_REVIEW instead of applying staking consequences.
_KNOWN_VERDICTS = frozenset({"upheld", "overturned", "rejected"})


class DisputeRouter:
    """Classifies disputes, routes to providers, applies staking consequences.

    Lifecycle::

        router = DisputeRouter(config, intel_db, eigen_client, molt_client,
                               stake_resolver, staking_contract)
        ok, msg = await router.open_dispute(window_id, challenge_id, claim_type)
        resolved, verdict = await router.check_dispute_resolution(dispute_id)
        await router.apply_staking_consequences(dispute_id, challenger_won=True)
    """

    def __init__(
        self,
        config: DisputeConfig,
        intel_db: IntelligenceDB,
        eigen_client: EigenVerifyClient,
        molt_client: MoltCourtClient,
        stake_resolver: StakeResolver,
        staking_contract: StakingContract,
    ) -> None:
        self._config = config
        self._db = intel_db
        self._eigen = eigen_client
        self._molt = molt_client
        self._resolver = stake_resolver
        self._contract = staking_contract

    # ── Classification ──────────────────────────────────────────────────

    @staticmethod
    def classify_dispute(
        attestation_json: str | None,
        claim_type: str,
    ) -> DisputeType:
        """Determine whether a dispute is computational or subjective.

        A dispute is COMPUTATION if and only if:
        1. The attestation JSON is valid and parseable.
        2. ``ai_seed`` is present and not None.
        3. ``ai_output_hash`` is present and not None.
        4. The claim type is ``AI_OUTPUT_INCORRECT``.

        All other cases default to SUBJECTIVE (safe fallback).
        This is a pure function — no I/O, deterministic.
        """
        if claim_type != ClaimType.AI_OUTPUT_INCORRECT:
            return DisputeType.SUBJECTIVE

        if not attestation_json:
            return DisputeType.SUBJECTIVE

        try:
            data = json.loads(attestation_json)
        except (json.JSONDecodeError, TypeError):
            return DisputeType.SUBJECTIVE

        if not isinstance(data, dict):
            return DisputeType.SUBJECTIVE

        if data.get("ai_seed") is not None and data.get("ai_output_hash") is not None:
            return DisputeType.COMPUTATION

        return DisputeType.SUBJECTIVE

    # ── Verdict validation ───────────────────────────────────────────────

    @staticmethod
    def is_known_verdict(verdict: str | None) -> bool:
        """Return True if the verdict string is a recognized value."""
        return verdict is not None and verdict in _KNOWN_VERDICTS

    # ── Open dispute ────────────────────────────────────────────────────

    async def open_dispute(
        self,
        window_id: str,
        challenge_id: str,
        claim_type: str,
    ) -> tuple[bool, str]:
        """Open a dispute for a challenged verification window.

        1. Validate the window exists and is challenged.
        2. Check no active dispute already exists (atomic under write lock).
        3. Classify the dispute type.
        4. **Persist to DB** (status=PENDING) — BEFORE external call.
        5. Submit to the appropriate provider.
        6. On success: update to SUBMITTED with provider_case_id.
        7. On failure: stays PENDING for scheduler retry.

        Returns ``(True, dispute_id)`` on success or ``(False, reason)``.
        """
        # Validate window
        window = await self._db.get_verification_window(window_id)
        if window is None:
            return (False, "Window not found")

        if str(window["status"]) != "challenged":
            return (False, f"Window status is '{window['status']}', expected 'challenged'")

        # Atomic check-and-insert under write lock to prevent duplicate disputes
        dispute_id = uuid.uuid4().hex
        attestation_json = window.get("attestation_json")
        att_str = str(attestation_json) if attestation_json else None
        dispute_type = self.classify_dispute(att_str, claim_type)

        inserted = await self._db.check_and_insert_dispute(
            dispute_id=dispute_id,
            challenge_id=challenge_id,
            window_id=window_id,
            dispute_type=dispute_type,
            claim_type=claim_type,
            challenger_address=str(window.get("challenger_address", "")),
            challenger_stake_wei=str(window.get("challenger_stake_wei", "0")),
            contributor_stake_id=window.get("contributor_stake_id"),
            challenger_stake_id=window.get("challenger_stake_id"),
            attestation_json=att_str,
        )
        if not inserted:
            return (False, "Active dispute already exists for this window")

        # Warn if stake IDs are absent (staking won't execute)
        if not window.get("contributor_stake_id"):
            logger.warning(
                "No contributor_stake_id on window — staking consequences "
                "will be skipped for contributor",
                extra={"window_id": window_id, "dispute_id": dispute_id},
            )
        if not window.get("challenger_stake_id"):
            logger.warning(
                "No challenger_stake_id on window — staking consequences "
                "will be skipped for challenger",
                extra={"window_id": window_id, "dispute_id": dispute_id},
            )

        # Submit to provider
        try:
            if dispute_type == DisputeType.COMPUTATION:
                proof_data = {}
                if att_str:
                    with contextlib.suppress(json.JSONDecodeError, TypeError):
                        proof_data = json.loads(att_str)
                result = await self._eigen.submit_dispute(dispute_id, proof_data)
            else:
                claim_data = {
                    "claim_type": claim_type,
                    "window_id": window_id,
                    "challenge_id": challenge_id,
                    "rationale": str(window.get("challenge_rationale", "")),
                }
                result = await self._molt.submit_dispute(dispute_id, claim_data)

            await self._db.update_dispute_record(
                dispute_id,
                status="submitted",
                provider_case_id=result.provider_case_id,
            )
            logger.info(
                "Dispute submitted to provider",
                extra={
                    "dispute_id": dispute_id,
                    "dispute_type": dispute_type,
                    "provider_case_id": result.provider_case_id,
                },
            )
        except Exception:
            # Submission failed — dispute stays PENDING for scheduler retry
            logger.exception(
                "Dispute submission failed, will retry",
                extra={"dispute_id": dispute_id, "dispute_type": dispute_type},
            )
            await self._db.update_dispute_record(
                dispute_id,
                submission_attempts=1,
            )

        return (True, dispute_id)

    # ── Check resolution ────────────────────────────────────────────────

    async def check_dispute_resolution(
        self,
        dispute_id: str,
    ) -> tuple[bool, str | None]:
        """Poll the appropriate provider for a dispute's resolution.

        Returns ``(True, verdict)`` if resolved, ``(False, None)`` otherwise.
        Updates the DB record on resolution.
        """
        record = await self._db.get_dispute_record(dispute_id)
        if record is None:
            return (False, None)

        provider_case_id = record.get("provider_case_id")
        if not provider_case_id:
            return (False, None)

        dispute_type = str(record["dispute_type"])
        case_id_str = str(provider_case_id)

        if dispute_type == DisputeType.COMPUTATION:
            result = await self._eigen.check_resolution(case_id_str)
        else:
            result = await self._molt.check_resolution(case_id_str)

        if result.resolved:
            from datetime import UTC, datetime  # noqa: PLC0415

            await self._db.update_dispute_record(
                dispute_id,
                status="resolved",
                provider_verdict=result.verdict,
                resolved_at=datetime.now(UTC).isoformat(),
            )
            logger.info(
                "Dispute resolved by provider",
                extra={
                    "dispute_id": dispute_id,
                    "verdict": result.verdict,
                },
            )
            return (True, result.verdict)

        return (False, None)

    # ── Staking consequences ────────────────────────────────────────────

    async def apply_staking_consequences(
        self,
        dispute_id: str,
        *,
        challenger_won: bool,
    ) -> None:
        """Apply staking consequences based on dispute outcome.

        If challenger_won (doc 18 "challenge upheld" = original verdict wrong):
          - Slash contributor 50% via StakeResolver.resolve_challenged_overturned
          - Return challenger full stake via StakeResolver.resolve_no_challenge

        If challenger_lost (doc 18 "challenge rejected" = original verdict correct):
          - Return contributor stake + bonus via StakeResolver.resolve_challenged_upheld
          - Slash challenger 100% via StakingContract.slash_stake

        Each operation is independently try/excepted — partial failure is
        logged but not fatal.  The ``staking_applied`` flag prevents
        double-execution on crash-restart.
        """
        record = await self._db.get_dispute_record(dispute_id)
        if record is None:
            logger.error(
                "Cannot apply staking: dispute not found",
                extra={"dispute_id": dispute_id},
            )
            return

        # Idempotency guard: skip if already applied
        if record.get("staking_applied"):
            logger.info(
                "Staking consequences already applied, skipping",
                extra={"dispute_id": dispute_id},
            )
            return

        contributor_stake_id = record.get("contributor_stake_id")
        challenger_stake_id = record.get("challenger_stake_id")

        if challenger_won:
            # Slash contributor 50%
            if contributor_stake_id:
                try:
                    await self._resolver.resolve_challenged_overturned(
                        bytes.fromhex(str(contributor_stake_id)),
                    )
                except Exception:
                    logger.exception(
                        "Failed to slash contributor stake",
                        extra={"dispute_id": dispute_id, "stake_id": contributor_stake_id},
                    )
            else:
                logger.warning(
                    "No contributor_stake_id — cannot slash contributor",
                    extra={"dispute_id": dispute_id},
                )

            # Return challenger full stake
            if challenger_stake_id:
                try:
                    await self._resolver.resolve_no_challenge(
                        bytes.fromhex(str(challenger_stake_id)),
                    )
                except Exception:
                    logger.exception(
                        "Failed to return challenger stake",
                        extra={"dispute_id": dispute_id, "stake_id": challenger_stake_id},
                    )
            else:
                logger.warning(
                    "No challenger_stake_id — cannot return challenger stake",
                    extra={"dispute_id": dispute_id},
                )
        else:
            # Return contributor stake + bonus
            if contributor_stake_id:
                try:
                    await self._resolver.resolve_challenged_upheld(
                        bytes.fromhex(str(contributor_stake_id)),
                    )
                except Exception:
                    logger.exception(
                        "Failed to return contributor stake",
                        extra={"dispute_id": dispute_id, "stake_id": contributor_stake_id},
                    )
            else:
                logger.warning(
                    "No contributor_stake_id — cannot return contributor stake",
                    extra={"dispute_id": dispute_id},
                )

            # Slash challenger 100%
            if challenger_stake_id:
                try:
                    await self._contract.slash_stake(
                        bytes.fromhex(str(challenger_stake_id)), 100,
                    )
                except Exception:
                    logger.exception(
                        "Failed to slash challenger stake",
                        extra={"dispute_id": dispute_id, "stake_id": challenger_stake_id},
                    )
            else:
                logger.warning(
                    "No challenger_stake_id — cannot slash challenger",
                    extra={"dispute_id": dispute_id},
                )

        # Mark staking as applied so crash-restart won't re-execute
        try:
            await self._db.update_dispute_record(dispute_id, staking_applied=1)
        except Exception:
            logger.exception(
                "Failed to mark staking_applied — may re-execute on restart",
                extra={"dispute_id": dispute_id},
            )

    async def close(self) -> None:
        """No-op — router holds no resources. Clients are closed separately."""
