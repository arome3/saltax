"""Optimistic verification window scheduler.

Manages the lifecycle of verification windows: polls for expired windows,
executes merge + payout, handles challenges, and recovers from crashes.

State machine::

         ┌──────────┐
         │   open   │
         └──┬───┬───┘
            │   │
   expires  │   │ challenge filed
            ▼   ▼
    ┌──────────┐ ┌───────────┐
    │executing │ │ challenged│──────────────┐
    └──┬───┬───┘ └─────┬─────┘              │
       │   │           │                upheld
  merge│  merge   overturned                │
  ok   │  fails       │               ┌────▼─────┐
       ▼   ▼          │               │resolving │
  ┌────────┐ ┌────┐   │               └──┬───┬───┘
  │executed│ │open│   │          merge ok │  merge
  └────────┘ └────┘   │                  │  fails
                       ▼                  │   │
                  ┌────────┐              │   ▼
                  │resolved│◄─────────────┘ (back to
                  └────────┘                challenged)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from src.verification.window import (
    compute_staking_bonus,
    is_expired,
    validate_challenge_stake,
)

if TYPE_CHECKING:
    from src.config import SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.intelligence.sealing import KMSSealManager
    from src.observability.metrics import BudgetTracker
    from src.treasury.manager import TreasuryManager

logger = logging.getLogger(__name__)

# Name of SaltaX's own check run — must match src/github/checks.py:_CHECK_NAME
_OWN_CHECK_NAME = "SaltaX Pipeline"

# Check-run conclusions treated as passing (matches Bulldozer's allowedCheckConclusions)
_PASSING_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})


class CIGateResult(StrEnum):
    """Outcome of the pre-merge CI status check."""

    PASSED = "passed"
    FAILED = "failed"
    PENDING = "pending"
    NO_CI = "no_ci"
    GATE_DISABLED = "gate_disabled"
    API_ERROR = "api_error"


class VerificationScheduler:
    """Manages optimistic verification windows and challenge resolution."""

    def __init__(
        self,
        config: SaltaXConfig,
        intel_db: IntelligenceDB,
        github_client: GitHubClient,
        treasury_mgr: TreasuryManager,
        kms: KMSSealManager | None = None,
        budget_tracker: BudgetTracker | None = None,
    ) -> None:
        self._config = config
        self._intel_db = intel_db
        self._github_client = github_client
        self._treasury_mgr = treasury_mgr
        self._kms = kms
        self._budget_tracker = budget_tracker
        self._stop_event = asyncio.Event()

    @property
    def running(self) -> bool:
        return not self._stop_event.is_set()

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def recover_pending_windows(self) -> None:
        """Recover from crash: reset transient states to retryable states.

        - ``executing`` → ``open`` (merge retry on next tick)
        - ``resolving`` → ``challenged`` (resolution retry)

        Logs counts at INFO.
        Expired windows are processed by the first ``_tick()`` call in ``run()``.
        """
        open_windows = await self._intel_db.get_open_windows()
        stale_executing = await self._intel_db.get_windows_by_status("executing")
        stale_resolving = await self._intel_db.get_windows_by_status("resolving")

        for window in stale_executing:
            transitioned = await self._intel_db.transition_window_status(
                str(window["id"]), "executing", "open",
            )
            if transitioned:
                logger.warning(
                    "Recovered stale executing window → open",
                    extra={"window_id": window["id"]},
                )

        for window in stale_resolving:
            transitioned = await self._intel_db.transition_window_status(
                str(window["id"]), "resolving", "challenged",
            )
            if transitioned:
                logger.warning(
                    "Recovered stale resolving window → challenged",
                    extra={"window_id": window["id"]},
                )

        total_open = len(open_windows) + len(stale_executing)
        logger.info(
            "Recovery complete: %d open windows, %d stale executing reset, "
            "%d stale resolving reset",
            len(open_windows),
            len(stale_executing),
            len(stale_resolving),
        )
        if total_open > 0:
            logger.info(
                "%d windows pending (will process on first tick)", total_open,
            )

    async def run(self) -> None:
        """Run the scheduler loop until :meth:`stop` is called."""
        while not self._stop_event.is_set():
            try:
                await self._tick()
            except Exception:
                logger.exception("Scheduler tick error")
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._config.verification.check_interval_seconds,
                )
                break  # stop event was set
            except TimeoutError:
                pass  # interval elapsed, loop again

    async def stop(self) -> None:
        """Signal the scheduler to stop."""
        self._stop_event.set()

    async def close(self) -> None:
        """Resource-cleanup alias for :meth:`stop`."""
        await self.stop()

    # ── Tick ─────────────────────────────────────────────────────────────

    async def _tick(self) -> None:
        """Process expired open windows and stale challenged windows."""
        ctx = (
            self._budget_tracker.track("verification_tick")
            if self._budget_tracker
            else nullcontext()
        )
        async with ctx:
            return await self._tick_impl()

    async def _tick_impl(self) -> None:
        """Inner tick logic, separated for budget tracking."""
        now = datetime.now(UTC)
        now_iso = now.isoformat()
        expired = await self._intel_db.get_expired_open_windows(now_iso)

        if expired:
            logger.info("Processing %d expired verification windows", len(expired))
            for window in expired:
                try:
                    await self._execute_window(window)
                except Exception:
                    logger.exception(
                        "Failed to execute window",
                        extra={"window_id": window["id"]},
                    )

        # Auto-resolve stale challenged windows past the deadline
        deadline_hours = self._config.verification.challenge_resolution_deadline_hours
        deadline = (now - timedelta(hours=deadline_hours)).isoformat()
        stale = await self._intel_db.get_stale_challenged_windows(deadline)
        for window in stale:
            window_id = str(window["id"])
            logger.warning(
                "Challenge deadline exceeded, auto-overturning",
                extra={"window_id": window_id},
            )
            try:
                await self.resolve_challenge(window_id, upheld=False)
            except Exception:
                logger.exception(
                    "Failed to auto-overturn stale challenge",
                    extra={"window_id": window_id},
                )

    # ── Window execution ─────────────────────────────────────────────────

    async def _execute_window(self, window: dict[str, object]) -> None:
        """Execute an expired verification window: merge PR + send payout.

        For self-modification windows, wraps the merge in a backup → merge →
        health-check → rollback cycle under :data:`_self_merge_lock`.

        Uses a transient ``executing`` state to prevent challenges during
        merge and to allow retry on merge failure.
        """
        window_id = str(window["id"])

        # Step 1: CAS open → executing
        transitioned = await self._intel_db.transition_window_status(
            window_id, "open", "executing",
        )
        if not transitioned:
            logger.debug(
                "Window already being processed or challenged",
                extra={"window_id": window_id},
            )
            return

        is_self_mod = bool(window.get("is_self_modification", 0))

        if is_self_mod and self._kms is not None:
            await self._execute_self_merge_window(window)
        else:
            await self._execute_normal_window(window)

    async def _execute_normal_window(self, window: dict[str, object]) -> None:
        """Standard merge + payout for non-self-modification windows."""
        window_id = str(window["id"])
        repo = str(window["repo"])
        pr_number = int(window["pr_number"])  # type: ignore[arg-type]
        installation_id = int(window["installation_id"])  # type: ignore[arg-type]

        # CI gate: block merge if external CI is failing or still running
        ci_result = await self._check_ci_status(repo, pr_number, installation_id)
        if ci_result in (CIGateResult.PENDING, CIGateResult.FAILED):
            logger.info(
                "CI gate blocked merge, reverting to open",
                extra={
                    "window_id": window_id,
                    "pr_number": pr_number,
                    "ci_result": ci_result.value,
                },
            )
            await self._intel_db.transition_window_status(
                window_id, "executing", "open",
            )
            return

        try:
            await self._github_client.merge_pr(
                repo, pr_number, installation_id,
                commit_title=f"SaltaX: auto-merge PR #{pr_number} (verification passed)",
            )
        except Exception:
            logger.exception(
                "Merge failed for window, reverting to open",
                extra={"window_id": window_id, "pr_number": pr_number},
            )
            await self._intel_db.transition_window_status(
                window_id, "executing", "open",
            )
            return

        await self._intel_db.transition_window_status(
            window_id, "executing", "executed", resolution="executed",
        )
        logger.info(
            "Verification window executed, PR merged",
            extra={"window_id": window_id, "pr_number": pr_number},
        )

        # Best-effort: collect reaction feedback before payout
        try:
            from src.feedback.reaction_handler import collect_reactions_for_pr  # noqa: PLC0415

            await collect_reactions_for_pr(
                repo=repo,
                pr_number=pr_number,
                installation_id=installation_id,
                github_client=self._github_client,
                intel_db=self._intel_db,
            )
        except Exception:
            logger.debug(
                "Reaction collection skipped after merge",
                exc_info=True,
                extra={"window_id": window_id},
            )

        await self._send_payout(window)

    async def _execute_self_merge_window(self, window: dict[str, object]) -> None:
        """Self-merge cycle: backup → merge → health-check → rollback if unhealthy.

        Acquires :data:`_self_merge_lock` to prevent concurrent self-merges.
        """
        from src.selfmerge.health_check import run_health_check  # noqa: PLC0415
        from src.selfmerge.rollback import (  # noqa: PLC0415
            ConfigRollback,
            _self_merge_lock,
        )
        from src.selfmerge.upgrade_logger import log_upgrade_event  # noqa: PLC0415

        window_id = str(window["id"])
        repo = str(window["repo"])
        pr_number = int(window["pr_number"])  # type: ignore[arg-type]
        installation_id = int(window["installation_id"])  # type: ignore[arg-type]

        # CI gate: block merge if external CI is failing or still running
        ci_result = await self._check_ci_status(repo, pr_number, installation_id)
        if ci_result in (CIGateResult.PENDING, CIGateResult.FAILED):
            logger.info(
                "CI gate blocked self-merge, reverting to open",
                extra={
                    "window_id": window_id,
                    "pr_number": pr_number,
                    "ci_result": ci_result.value,
                },
            )
            await self._intel_db.transition_window_status(
                window_id, "executing", "open",
            )
            return

        async with _self_merge_lock:
            # 1. Create backup
            config_path = "saltax.config.yaml"
            backup_name = f"selfmerge_{window_id}"
            rollback = ConfigRollback(kms=self._kms)
            rolled_back = False
            health_passed = False

            try:
                await rollback.initialize()
                await rollback.create_backup([config_path], backup_name)
            except Exception:
                logger.exception(
                    "Self-merge backup failed, reverting to open",
                    extra={"window_id": window_id},
                )
                await self._intel_db.transition_window_status(
                    window_id, "executing", "open",
                )
                return

            # 2. Merge PR
            try:
                await self._github_client.merge_pr(
                    repo, pr_number, installation_id,
                    commit_title=(
                        f"SaltaX: self-merge PR #{pr_number} "
                        f"(verification passed, backup={backup_name})"
                    ),
                )
            except Exception:
                logger.exception(
                    "Self-merge failed, reverting to open",
                    extra={"window_id": window_id, "pr_number": pr_number},
                )
                await self._intel_db.transition_window_status(
                    window_id, "executing", "open",
                )
                return

            # 3. Post-merge health check
            try:
                health = await run_health_check(config_path)
                health_passed = health.healthy
            except Exception:
                logger.exception(
                    "Health check crashed, treating as failure",
                    extra={"window_id": window_id},
                )
                health_passed = False

            # 4. Rollback if unhealthy
            if not health_passed:
                logger.critical(
                    "Self-merge health check FAILED — rolling back config",
                    extra={
                        "window_id": window_id,
                        "pr_number": pr_number,
                        "checks_failed": getattr(health, "checks_failed", []),
                    },
                )
                try:
                    await rollback.restore_backup(backup_name)
                    rolled_back = True
                except Exception:
                    logger.critical(
                        "Rollback FAILED after health check failure — "
                        "system may be in degraded state, halting scheduler",
                        extra={"window_id": window_id},
                    )
                    await self.stop()
                    return

            # 5. Mark executed (merge already happened on GitHub)
            await self._intel_db.transition_window_status(
                window_id, "executing", "executed", resolution="executed",
            )
            logger.info(
                "Self-merge window executed",
                extra={
                    "window_id": window_id,
                    "pr_number": pr_number,
                    "health_passed": health_passed,
                    "rolled_back": rolled_back,
                },
            )

            # 6. Log upgrade event (best-effort)
            try:
                await log_upgrade_event(
                    intel_db=self._intel_db,
                    pr_id=str(window.get("pr_id", "")),
                    repo=repo,
                    commit_sha="",
                    modified_files=frozenset(),
                    backup_name=backup_name,
                    health_check_passed=health_passed,
                    rolled_back=rolled_back,
                )
            except Exception:
                logger.exception(
                    "Failed to log upgrade event",
                    extra={"window_id": window_id},
                )

            # 7. Send payout only if health passed
            if health_passed:
                await self._send_payout(window)

    async def _send_payout(self, window: dict[str, object]) -> None:
        """Send bounty + staking bonus payout (best effort, never raises)."""
        contributor = window.get("contributor_address")
        if not contributor:
            return

        bounty_wei = int(window.get("bounty_amount_wei", 0) or 0)
        if bounty_wei == 0:
            return

        bonus_wei = compute_staking_bonus(window, self._config.staking)

        try:
            from src.treasury.policy import PayoutRequest  # noqa: PLC0415

            payout = PayoutRequest(
                recipient=str(contributor),
                amount_wei=bounty_wei,
                stake_bonus_wei=bonus_wei,
            )
            record = await self._treasury_mgr.send_payout(payout)
            logger.info(
                "Payout sent",
                extra={
                    "window_id": window["id"],
                    "tx_hash": record.tx_hash,
                    "amount_wei": record.amount_wei,
                },
            )
        except Exception:
            logger.exception(
                "Payout failed (merge already succeeded, manual intervention needed)",
                extra={"window_id": window["id"]},
            )

    # ── CI gate ───────────────────────────────────────────────────────────

    async def _check_ci_status(
        self,
        repo: str,
        pr_number: int,
        installation_id: int,
    ) -> CIGateResult:
        """Check external CI status for a PR before merging.

        Mirrors Bulldozer's dual-API approach: queries both the Check Runs
        API (GitHub Actions) and the combined Status API (legacy CI tools).
        Filters out SaltaX's own check run to avoid self-referential gating.

        Returns a :class:`CIGateResult` indicating whether to proceed.
        """
        if not self._config.verification.require_ci_pass:
            return CIGateResult.GATE_DISABLED

        # 1. Fetch PR to get HEAD SHA
        try:
            pr_data = await self._github_client.get_pr(
                repo, pr_number, installation_id,
            )
            head_sha: str = pr_data["head"]["sha"]
        except Exception:
            logger.warning(
                "CI gate: failed to fetch PR, proceeding with merge (fail-open)",
                extra={"repo": repo, "pr_number": pr_number},
            )
            return CIGateResult.API_ERROR

        # 2. Fetch check runs + combined status in parallel
        try:
            check_runs_result, combined_status = await asyncio.gather(
                self._github_client.list_check_runs_for_ref(
                    repo, head_sha, installation_id,
                ),
                self._github_client.get_combined_status_for_ref(
                    repo, head_sha, installation_id,
                ),
            )
        except Exception:
            logger.warning(
                "CI gate: failed to fetch CI status, proceeding with merge (fail-open)",
                extra={"repo": repo, "pr_number": pr_number, "head_sha": head_sha},
            )
            return CIGateResult.API_ERROR

        # 3. Filter out our own check run
        external_checks = [
            cr for cr in check_runs_result
            if cr.get("name") != _OWN_CHECK_NAME
        ]

        # 4. Evaluate combined status API
        status_state = combined_status.get("state", "")
        status_count = int(combined_status.get("total_count", 0))

        has_external_checks = len(external_checks) > 0
        has_status_checks = status_count > 0

        # 5. If no external checks at all, verify it's genuinely a repo
        #    without CI — not a freshly-pushed commit whose checks haven't
        #    started yet.  A queued/in-progress check_suite with zero check
        #    runs means GitHub Actions is still provisioning runners.
        if not has_external_checks and not has_status_checks:
            try:
                check_suites = await self._github_client.list_check_suites_for_ref(
                    repo, head_sha, installation_id,
                )
                pending_suites = [
                    cs for cs in check_suites
                    if cs.get("status") in ("queued", "in_progress")
                ]
                if pending_suites:
                    logger.info(
                        "CI gate: check suites pending but no runs yet, "
                        "treating as PENDING to avoid race",
                        extra={
                            "repo": repo,
                            "pr_number": pr_number,
                            "pending_suites": len(pending_suites),
                        },
                    )
                    return CIGateResult.PENDING
            except Exception:
                logger.debug(
                    "CI gate: failed to fetch check suites, treating as NO_CI",
                    extra={"repo": repo, "pr_number": pr_number},
                )

            logger.debug(
                "CI gate: no external CI checks found",
                extra={"repo": repo, "pr_number": pr_number},
            )
            return CIGateResult.NO_CI

        # 6. Check for pending/in-progress states
        for cr in external_checks:
            cr_status = cr.get("status", "")
            if cr_status in ("queued", "in_progress"):
                logger.info(
                    "CI gate: check run still running",
                    extra={
                        "repo": repo,
                        "pr_number": pr_number,
                        "check_name": cr.get("name"),
                        "status": cr_status,
                    },
                )
                return CIGateResult.PENDING

        if has_status_checks and status_state == "pending":
            logger.info(
                "CI gate: combined status pending",
                extra={"repo": repo, "pr_number": pr_number},
            )
            return CIGateResult.PENDING

        # 7. Check for failures
        for cr in external_checks:
            conclusion = cr.get("conclusion", "")
            if conclusion and conclusion not in _PASSING_CONCLUSIONS:
                logger.info(
                    "CI gate: check run failed",
                    extra={
                        "repo": repo,
                        "pr_number": pr_number,
                        "check_name": cr.get("name"),
                        "conclusion": conclusion,
                    },
                )
                return CIGateResult.FAILED

        if has_status_checks and status_state in ("failure", "error"):
            logger.info(
                "CI gate: combined status failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "state": status_state,
                },
            )
            return CIGateResult.FAILED

        # 8. All checks passed
        logger.info(
            "CI gate: all checks passed",
            extra={"repo": repo, "pr_number": pr_number},
        )
        return CIGateResult.PASSED

    # ── Challenge management ─────────────────────────────────────────────

    async def file_challenge(
        self,
        window_id: str,
        *,
        challenger_address: str,
        stake_wei: int,
        rationale: str,
    ) -> tuple[bool, str]:
        """File a challenge against a verification window.

        Returns ``(True, "ok")`` on success or ``(False, reason)`` on failure.
        """
        window = await self._intel_db.get_verification_window(window_id)
        if window is None:
            return (False, "Window not found")

        if str(window["status"]) != "open":
            return (False, f"Window status is '{window['status']}', expected 'open'")

        if is_expired(window):
            return (False, "Window has expired")

        ok, reason = validate_challenge_stake(
            window, stake_wei, self._config.verification,
        )
        if not ok:
            return (False, reason)

        challenge_id = uuid.uuid4().hex
        transitioned = await self._intel_db.transition_window_status(
            window_id,
            "open",
            "challenged",
            challenge_id=challenge_id,
            challenger_address=challenger_address,
            challenger_stake_wei=str(stake_wei),
            challenge_rationale=rationale,
        )

        if not transitioned:
            return (False, "Window was concurrently modified (race)")

        logger.info(
            "Challenge filed",
            extra={
                "window_id": window_id,
                "challenge_id": challenge_id,
                "challenger": challenger_address,
            },
        )
        return (True, challenge_id)

    async def resolve_challenge(
        self,
        window_id: str,
        *,
        upheld: bool,
    ) -> tuple[bool, str]:
        """Resolve a challenged window.

        If upheld: merge the PR and send payout.
        If overturned: no merge, no payout.

        The upheld path uses a transient ``resolving`` state to allow retry
        on merge failure (mirrors ``_execute_window``'s ``executing`` pattern).

        Returns ``(True, "ok")`` on success or ``(False, reason)`` on failure.
        """
        window = await self._intel_db.get_verification_window(window_id)
        if window is None:
            return (False, "Window not found")

        if str(window["status"]) != "challenged":
            return (
                False,
                f"Window status is '{window['status']}', expected 'challenged'",
            )

        resolution = "upheld" if upheld else "overturned"

        if not upheld:
            # Overturned: no merge needed, go directly to resolved
            transitioned = await self._intel_db.transition_window_status(
                window_id, "challenged", "resolved", resolution=resolution,
            )
            if not transitioned:
                return (False, "Window was concurrently modified")
            logger.info(
                "Challenge resolved (overturned)",
                extra={"window_id": window_id, "resolution": resolution},
            )
            return (True, "ok")

        # Upheld path: challenged → resolving → resolved (or → challenged on failure)
        transitioned = await self._intel_db.transition_window_status(
            window_id, "challenged", "resolving", resolution=resolution,
        )
        if not transitioned:
            return (False, "Window was concurrently modified")

        # Attempt merge
        repo = str(window["repo"])
        pr_number = int(window["pr_number"])  # type: ignore[arg-type]
        installation_id = int(window["installation_id"])  # type: ignore[arg-type]

        # CI gate: block merge if external CI is failing or still running
        ci_result = await self._check_ci_status(repo, pr_number, installation_id)
        if ci_result in (CIGateResult.PENDING, CIGateResult.FAILED):
            logger.info(
                "CI gate blocked upheld merge, reverting to challenged",
                extra={
                    "window_id": window_id,
                    "pr_number": pr_number,
                    "ci_result": ci_result.value,
                },
            )
            await self._intel_db.transition_window_status(
                window_id, "resolving", "challenged",
            )
            return (False, f"CI gate: {ci_result.value}")

        try:
            await self._github_client.merge_pr(
                repo, pr_number, installation_id,
                commit_title=(
                    f"SaltaX: auto-merge PR #{pr_number} "
                    f"(challenge upheld)"
                ),
            )
        except Exception:
            logger.exception(
                "Merge failed after challenge upheld, reverting to challenged",
                extra={"window_id": window_id, "pr_number": pr_number},
            )
            await self._intel_db.transition_window_status(
                window_id, "resolving", "challenged",
            )
            return (False, "Merge failed after challenge upheld")

        # Merge succeeded — mark resolved
        await self._intel_db.transition_window_status(
            window_id, "resolving", "resolved",
        )
        logger.info(
            "Challenge resolved (upheld, merged)",
            extra={"window_id": window_id, "resolution": resolution},
        )

        # Re-read window with updated resolution for bonus calculation
        updated = await self._intel_db.get_verification_window(window_id)
        if updated is not None:
            await self._send_payout(updated)

        return (True, "ok")
