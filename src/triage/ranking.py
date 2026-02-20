"""Competitive PR ranking: query, format, post, and label.

Post-pipeline step that compares PRs targeting the same GitHub issue and
posts a comparison table on the issue.  Runs after each pipeline completion
when triage ranking is enabled and the PR references a target issue.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from src.github.comments import format_ranking_update

if TYPE_CHECKING:
    from src.config import RankingConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)


async def post_ranking_update(
    *,
    repo: str,
    target_issue: int,
    installation_id: int,
    pr_number: int,
    ranking_config: RankingConfig,
    github_client: GitHubClient,
    intel_db: IntelligenceDB,
) -> None:
    """Query ranked PRs, post comparison table on the issue, and apply labels.

    Designed to never raise — all errors are caught and logged so that
    ranking failures cannot break the pipeline.
    """
    try:
        # 1. Rate limit check (fail-open: if DB check errors, proceed)
        try:
            if await intel_db.was_ranking_recently_posted(
                repo, target_issue, ranking_config.update_interval_seconds,
            ):
                logger.debug(
                    "Ranking update skipped (rate limited)",
                    extra={"repo": repo, "issue": target_issue},
                )
                return
        except Exception:
            logger.warning(
                "Rate limit check failed, proceeding with ranking update",
                exc_info=True,
            )

        # 2. Query ranked PRs
        ranking = await intel_db.get_ranked_prs(repo, target_issue)

        # 3. Guard: skip single-PR (no comparison needed)
        if len(ranking) <= 1:
            return

        # 4. Format the ranking table (with marker for dedup)
        body = format_ranking_update(
            ranking, repo=repo, issue_number=target_issue,
        )

        # 5. Update-or-create: find existing ranking comment, update it
        marker = f"<!-- saltax-ranking:{repo}:{target_issue} -->"
        existing_comment_id: int | None = None
        try:
            comments = await github_client.list_issue_comments(
                repo, target_issue, installation_id,
            )
            for comment in comments:
                if marker in (comment.get("body") or ""):
                    existing_comment_id = comment["id"]
                    break
        except Exception:
            logger.warning(
                "Failed to list comments for dedup, will create new",
                exc_info=True,
                extra={"repo": repo, "issue": target_issue},
            )

        if existing_comment_id is not None:
            await github_client.update_comment(
                repo, existing_comment_id, installation_id, body,
            )
        else:
            await github_client.create_comment(
                repo, target_issue, installation_id, body,
            )

        # 6. Apply ranking labels (best-effort)
        await _update_ranking_labels(
            ranking=ranking,
            repo=repo,
            installation_id=installation_id,
            ranking_config=ranking_config,
            github_client=github_client,
        )

        # 7. Record update for rate limiting
        try:
            ranking_json = json.dumps(
                [
                    {
                        "pr_number": r.get("pr_number"),
                        "composite_score": r.get("composite_score"),
                    }
                    for r in ranking
                ],
                default=str,
            )
            await intel_db.record_ranking_update(
                repo, target_issue, ranking_json,
            )
        except Exception:
            logger.warning(
                "Failed to record ranking update timestamp",
                exc_info=True,
            )

        logger.info(
            "Posted ranking update",
            extra={
                "repo": repo,
                "issue": target_issue,
                "num_prs": len(ranking),
            },
        )

    except Exception:
        logger.warning(
            "Ranking update failed",
            exc_info=True,
            extra={"repo": repo, "issue": target_issue, "pr_number": pr_number},
        )


async def _update_ranking_labels(
    *,
    ranking: list[dict[str, object]],
    repo: str,
    installation_id: int,
    ranking_config: RankingConfig,
    github_client: GitHubClient,
) -> None:
    """Apply recommended/superseded labels to ranked PRs.

    The top-ranked PR gets ``label_recommended``; all others get
    ``label_superseded``.  Label operations are best-effort — failures
    are logged but do not propagate.
    """
    try:
        # Ensure both labels exist in the repo
        await github_client.ensure_label(
            repo, installation_id, ranking_config.label_recommended,
            color="0e8a16", description="Top-ranked PR for this issue",
        )
        await github_client.ensure_label(
            repo, installation_id, ranking_config.label_superseded,
            color="cccccc", description="Superseded by a higher-ranked PR",
        )
    except Exception:
        logger.warning("Failed to ensure ranking labels, skipping label updates", exc_info=True)
        return

    for i, entry in enumerate(ranking):
        entry_pr = entry.get("pr_number")
        if entry_pr is None:
            continue
        pr_num = int(entry_pr)

        try:
            if i == 0:
                # Top PR: add recommended, remove superseded
                await github_client.add_label(
                    repo, pr_num, installation_id,
                    ranking_config.label_recommended,
                )
                await github_client.remove_label(
                    repo, pr_num, installation_id,
                    ranking_config.label_superseded,
                )
            else:
                # Other PRs: add superseded, remove recommended
                await github_client.add_label(
                    repo, pr_num, installation_id,
                    ranking_config.label_superseded,
                )
                await github_client.remove_label(
                    repo, pr_num, installation_id,
                    ranking_config.label_recommended,
                )
        except Exception:
            logger.warning(
                "Failed to update labels for PR #%d", pr_num,
                exc_info=True,
            )
