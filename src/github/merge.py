"""Merge execution helpers for SaltaX-attested pull requests."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.github.client import GitHubClient

logger = logging.getLogger(__name__)


def build_merge_commit_message(pr_number: int, attestation_id: str) -> str:
    """Build a merge commit title with SaltaX attestation stamp."""
    return f"Merge PR #{pr_number} [saltax-attested:{attestation_id}]"


async def execute_merge(
    client: GitHubClient,
    repo: str,
    pr_number: int,
    installation_id: int,
    attestation_id: str,
) -> dict[str, Any]:
    """Merge a PR with a SaltaX-attested commit message.

    Returns the GitHub merge response payload.
    """
    commit_title = build_merge_commit_message(pr_number, attestation_id)

    logger.info(
        "Executing merge",
        extra={
            "repo": repo,
            "pr_number": pr_number,
            "attestation_id": attestation_id,
        },
    )

    result = await client.merge_pr(
        repo,
        pr_number,
        installation_id,
        commit_title=commit_title,
    )

    logger.info(
        "Merge completed",
        extra={
            "repo": repo,
            "pr_number": pr_number,
            "merged": result.get("merged", False),
        },
    )

    return result
