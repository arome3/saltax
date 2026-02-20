"""Background event handlers dispatched from the webhook route.

These functions run inside FastAPI's ``BackgroundTasks`` — any exception is
swallowed silently, so every handler wraps its logic in try/except with
structured logging.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from src.github.exceptions import GitHubRateLimitError
from src.security.input_validation import sanitize_diff

if TYPE_CHECKING:
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.intelligence.vector_index import VectorIndexManager
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
    vector_index_manager: VectorIndexManager | None = None,
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

        # Fetch the diff via the GitHub client and sanitize at ingress
        diff = await github_client.get_pr_diff(repo, pr_number, installation_id)
        diff = sanitize_diff(diff)

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

        # ── Triage: extract target issue ──────────────────────────
        target_issue_number = None
        if config.triage.enabled and config.triage.ranking.enabled:
            try:
                from src.triage.issue_linker import (  # noqa: PLC0415
                    extract_target_issue,
                )

                target_issue_number = extract_target_issue(
                    title=pr_data.get("title", ""),
                    body=pr_data.get("body"),
                    head_branch=pr_data.get("head_branch", ""),
                )
                if target_issue_number is not None:
                    state_dict["target_issue_number"] = target_issue_number
                    # Backfill issue_number on existing embeddings that
                    # were stored before the fix (NULL → actual value)
                    try:
                        updated = await intel_db.backfill_embedding_issue_number(
                            pr_id=pr_data["pr_id"],
                            repo=repo,
                            issue_number=target_issue_number,
                        )
                        if updated > 0:
                            logger.info(
                                "Backfilled issue_number on %d embeddings",
                                updated,
                                extra={
                                    "pr_id": pr_data["pr_id"],
                                    "issue_number": target_issue_number,
                                },
                            )
                    except Exception:
                        logger.warning(
                            "Embedding issue_number backfill failed, continuing",
                            exc_info=True,
                            extra={"pr_id": pr_data.get("pr_id")},
                        )
            except Exception:
                logger.warning(
                    "Issue extraction failed, continuing pipeline",
                    exc_info=True,
                    extra={"pr_id": pr_data.get("pr_id")},
                )

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

                pr_vector_index = (
                    vector_index_manager.pr_index
                    if vector_index_manager else None
                )
                duplicates = await run_dedup_check(
                    state_dict, config, env, intel_db, pr_vector_index,
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

        # ── Triage: load vision document ──────────────────────────────
        if config.triage.enabled and config.triage.vision.enabled:
            try:
                from src.triage.vision import (  # noqa: PLC0415
                    load_vision_documents,
                )

                vision_doc = await load_vision_documents(
                    repo,
                    installation_id,
                    config=config,
                    intel_db=intel_db,
                    github_client=github_client,
                    env=env,
                )
                if vision_doc is not None:
                    state_dict["vision_document"] = vision_doc
            except GitHubRateLimitError:
                logger.warning(
                    "Vision load skipped: GitHub rate limit exceeded",
                    extra={"pr_id": pr_data.get("pr_id"), "repo": repo},
                )
            except Exception:
                logger.warning(
                    "Vision document load failed, continuing pipeline",
                    exc_info=True,
                    extra={"pr_id": pr_data.get("pr_id")},
                )

        state = await pipeline.run(state_dict)

        logger.info(
            "Pipeline completed for PR",
            extra={"pr_id": pr_data["pr_id"], "action": action},
        )

        # ── Triage: competitive ranking ──────────────────────────
        if (
            config.triage.enabled
            and config.triage.ranking.enabled
            and target_issue_number is not None
            and state.verdict
        ):
            try:
                from src.triage.ranking import (  # noqa: PLC0415
                    post_ranking_update,
                )

                await post_ranking_update(
                    repo=repo,
                    target_issue=target_issue_number,
                    installation_id=installation_id,
                    pr_number=pr_number,
                    ranking_config=config.triage.ranking,
                    github_client=github_client,
                    intel_db=intel_db,
                )
            except Exception:
                logger.warning(
                    "Ranking update failed, continuing",
                    exc_info=True,
                    extra={"pr_id": pr_data.get("pr_id")},
                )

        # ── Decision dispatch (advisory vs autonomous) ────────────
        if config.triage.enabled and state.verdict:
            from src.triage.advisory import dispatch_decision  # noqa: PLC0415

            await dispatch_decision(
                state, config, github_client, intel_db=intel_db,
            )
        elif (
            state.verdict
            and str(state.verdict.get("decision", "")).upper() == "APPROVE"
        ):
            # Triage disabled fallback — direct verification window
            from src.verification.window import create_window  # noqa: PLC0415

            attestation = state.attestation or {}
            try:
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
                logger.error(
                    "Verification window creation failed (triage-disabled fallback)",
                    exc_info=True,
                    extra={"pr_id": state.pr_id},
                )

    except Exception:
        logger.exception(
            "Unhandled error in PR event handler",
            extra={"pr_id": pr_data.get("pr_id")},
        )


async def handle_issue_event(
    issue_data: dict[str, Any],
    *,
    github_client: GitHubClient,
    intel_db: IntelligenceDB,
    config: SaltaXConfig,
    env: EnvConfig | None = None,
    vector_index_manager: VectorIndexManager | None = None,
) -> None:
    """Process an issue event for deduplication.

    Dispatches based on action:
    - ``closed`` → update embedding status
    - ``opened`` → run dedup check, post comment if duplicates found
    - ``edited`` → re-embed if body changed, update comment
    """
    try:
        action = issue_data.get("action", "")
        repo = issue_data.get("repo", issue_data.get("repo_full_name", ""))
        issue_number = issue_data.get("issue_number", 0)

        if action == "closed":
            try:
                await intel_db.update_issue_status(repo, issue_number, "closed")
            except Exception:
                logger.warning(
                    "Failed to update issue embedding status to closed",
                    exc_info=True,
                    extra={"repo": repo, "issue_number": issue_number},
                )
            return

        # Gate: triage + issue_dedup enabled + env available
        if env is None:
            return
        if not config.triage.enabled:
            return
        if not config.triage.issue_dedup.enabled:
            return

        issue_vector_index = (
            vector_index_manager.issue_index
            if vector_index_manager else None
        )

        if action == "opened":
            from src.triage.issue_dedup import (  # noqa: PLC0415
                post_issue_dedup_comment,
                run_issue_dedup_check,
            )

            duplicates = await run_issue_dedup_check(
                issue_data, config, env, intel_db, issue_vector_index,
            )
            if duplicates:
                await post_issue_dedup_comment(
                    issue_data, duplicates, github_client, config,
                )

        elif action == "edited":
            from src.triage.issue_dedup import (  # noqa: PLC0415
                handle_issue_edited,
            )

            await handle_issue_edited(
                issue_data, config, env, intel_db, github_client,
                issue_vector_index,
            )

    except Exception:
        logger.exception(
            "Unhandled error in issue event handler",
            extra={"issue_number": issue_data.get("issue_number")},
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
