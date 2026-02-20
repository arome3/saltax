"""Background event handlers dispatched from the webhook route.

These functions run inside FastAPI's ``BackgroundTasks`` — any exception is
swallowed silently, so every handler wraps its logic in try/except with
structured logging.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.pipeline.runner import Pipeline

logger = logging.getLogger(__name__)


async def handle_pr_event(
    pr_data: dict[str, Any],
    *,
    pipeline: Pipeline,
    github_client: GitHubClient,
    intel_db: IntelligenceDB,
    config: SaltaXConfig,
    env: EnvConfig | None = None,
) -> None:
    """Process a pull-request event through the analysis pipeline.

    Only ``opened`` and ``synchronize`` actions are processed — the webhook
    route pre-filters before dispatching to this handler.

    If the pipeline verdict is APPROVE, a verification window is created.
    """
    try:
        action = pr_data.get("action", "")
        if action not in ("opened", "synchronize"):
            return

        installation_id = pr_data.get("installation_id")
        if not installation_id:
            logger.warning(
                "PR event missing installation_id, skipping",
                extra={"pr_id": pr_data.get("pr_id")},
            )
            return

        repo = pr_data["repo_full_name"]
        pr_number = pr_data["pr_number"]

        # Look up contributor wallet
        author_login = pr_data["author_login"]
        contributor_wallet = await intel_db.get_contributor_wallet(author_login)

        # Compute bounty from PR labels
        bounty_amount_wei: int | None = None
        for label in pr_data.get("labels", []):
            if label.startswith("bounty-"):
                eth_amount = config.bounties.labels.get(label)
                if eth_amount is not None:
                    bounty_amount_wei = int(eth_amount * 10**18)
                    break  # first matching label wins

        # Fetch the diff via the GitHub client
        diff = await github_client.get_pr_diff(repo, pr_number, installation_id)

        # Self-modification detection
        is_self_mod = False
        if config.agent.repo and repo == config.agent.repo:
            try:
                from src.selfmerge.detector import (  # noqa: PLC0415
                    extract_modified_files,
                    is_self_modification,
                )

                modified_files = extract_modified_files(diff)
                is_self_mod = is_self_modification(modified_files)
                if is_self_mod:
                    logger.info(
                        "Self-modification detected",
                        extra={"pr_id": pr_data["pr_id"]},
                    )
            except Exception:
                logger.exception(
                    "Self-modification detection failed, defaulting to False",
                    extra={"pr_id": pr_data.get("pr_id")},
                )

        # Build pipeline state from PR data
        state_dict: dict[str, Any] = {
            "pr_id": pr_data["pr_id"],
            "repo": repo,
            "repo_url": pr_data["repo_url"],
            "commit_sha": pr_data["head_sha"],
            "diff": diff,
            "base_branch": pr_data["base_branch"],
            "head_branch": pr_data["head_branch"],
            "pr_author": author_login,
            "pr_number": pr_number,
            "installation_id": installation_id,
            "pr_author_wallet": contributor_wallet,
            "bounty_amount_wei": bounty_amount_wei,
            "is_self_modification": is_self_mod,
            "action": action,
        }

        # ── Triage dedup gate (advisory only) ───────────────────────
        if (
            env is not None
            and config.triage.enabled
            and config.triage.dedup.enabled
        ):
            try:
                from src.triage.dedup import (  # noqa: PLC0415
                    post_dedup_comment,
                    run_dedup_check,
                )

                duplicates = await run_dedup_check(
                    state_dict, config, env, intel_db,
                )
                state_dict["duplicate_candidates"] = duplicates
                if duplicates and (
                    action == "opened"
                    or config.triage.dedup.comment_on_synchronize
                ):
                    await post_dedup_comment(
                        state_dict, duplicates, github_client,
                    )
            except Exception:
                logger.warning(
                    "Dedup gate failed, continuing pipeline",
                    exc_info=True,
                    extra={"pr_id": pr_data.get("pr_id")},
                )

        state = await pipeline.run(state_dict)

        logger.info(
            "Pipeline completed for PR",
            extra={"pr_id": pr_data["pr_id"], "action": action},
        )

        # Create verification window on APPROVE verdict
        if (
            state.verdict
            and str(state.verdict.get("decision", "")).upper() == "APPROVE"
        ):
            from src.verification.window import create_window  # noqa: PLC0415

            attestation = state.attestation or {}
            await create_window(
                intel_db=intel_db,
                config=config.verification,
                pr_id=state.pr_id,
                repo=state.repo,
                pr_number=pr_number,
                installation_id=installation_id,
                attestation_id=str(attestation.get("attestation_id", "")),
                verdict=state.verdict,
                attestation=attestation,
                contributor_address=state.pr_author_wallet,
                bounty_amount_wei=state.bounty_amount_wei,
                stake_amount_wei=state.bounty_amount_wei,
                is_self_modification=state.is_self_modification,
            )

    except Exception:
        logger.exception(
            "Unhandled error in PR event handler",
            extra={"pr_id": pr_data.get("pr_id")},
        )


async def handle_issue_labeled(issue_data: dict[str, Any]) -> None:
    """Process an issue ``labeled`` event, detecting bounty labels.

    Stub: logs bounty detection for labels matching ``bounty-*``.
    When implemented, this will register the bounty with intel_db/treasury.
    """
    try:
        labels = issue_data.get("labels", [])
        bounty_labels = [label for label in labels if label.startswith("bounty-")]

        if not bounty_labels:
            return

        logger.info(
            "Bounty label detected on issue",
            extra={
                "issue_number": issue_data.get("issue_number"),
                "repo": issue_data.get("repo_full_name"),
                "bounty_labels": bounty_labels,
            },
        )

        # TODO: register bounty with intel_db and treasury
    except Exception:
        logger.exception(
            "Unhandled error in issue labeled handler",
            extra={"issue_number": issue_data.get("issue_number")},
        )
