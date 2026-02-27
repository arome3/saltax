"""Collect developer feedback from GitHub emoji reactions on SaltaX comments.

SaltaX embeds a ``<!-- saltax-findings:rule-a,rule-b -->`` HTML comment in
every advisory body listing the ``rule_id`` values of all flagged patterns.
When a developer reacts (thumbsup / thumbsdown) to that comment, this module
records those signals against each ``rule_id`` so the existing FP suppression
machinery (``get_false_positive_signatures()``) can learn over time.

Collection is idempotent — duplicate signals are ignored via the
``feedback_log`` UNIQUE constraint.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_FINDINGS_MARKER_RE = re.compile(r"<!-- saltax-findings:([^>]+) -->")
_ADVISORY_MARKER_PREFIX = "<!-- saltax-advisory:"
_BOT_SUFFIX = "[bot]"

_POSITIVE_REACTIONS = frozenset({"+1", "heart", "rocket"})
_NEGATIVE_REACTIONS = frozenset({"-1", "confused"})


# ── Pure helpers ─────────────────────────────────────────────────────────────


def extract_rule_ids(body: str) -> list[str]:
    """Extract rule IDs from the ``saltax-findings`` HTML comment marker.

    Returns an empty list if no marker is found.
    """
    match = _FINDINGS_MARKER_RE.search(body)
    if not match:
        return []
    raw = match.group(1).strip()
    if not raw:
        return []
    return [rid.strip() for rid in raw.split(",") if rid.strip()]


def is_saltax_comment(body: str | None) -> bool:
    """Return ``True`` if *body* contains the SaltaX advisory marker."""
    if body is None:
        return False
    return _ADVISORY_MARKER_PREFIX in body


# ── Main collection function ─────────────────────────────────────────────────


async def collect_reactions_for_pr(
    repo: str,
    pr_number: int,
    installation_id: int,
    github_client: GitHubClient,
    intel_db: IntelligenceDB,
    *,
    enabled: bool = True,
) -> int:
    """Collect reaction-based feedback for all SaltaX comments on a PR.

    Fetches comments, filters to SaltaX advisory comments, extracts
    ``rule_id`` markers, and records each reaction as a TP/FP signal.

    Returns the number of **new** signals recorded (0 for duplicates).
    Never raises — all errors are caught and logged.
    """
    if not enabled:
        return 0

    try:
        comments = await github_client.list_issue_comments(
            repo, pr_number, installation_id,
        )
    except Exception:
        logger.debug(
            "Failed to fetch comments for reaction collection",
            exc_info=True,
            extra={"repo": repo, "pr_number": pr_number},
        )
        return 0

    new_signals = 0

    for comment in comments:
        body = comment.get("body")
        if not is_saltax_comment(body):
            continue

        rule_ids = extract_rule_ids(body or "")
        if not rule_ids:
            continue

        comment_id = comment["id"]

        # Fetch positive and negative reactions
        try:
            reactions = await github_client.get_comment_reactions(
                repo, comment_id, installation_id,
            )
        except Exception:
            logger.debug(
                "Failed to fetch reactions for comment",
                exc_info=True,
                extra={"repo": repo, "comment_id": comment_id},
            )
            continue

        for rxn in reactions:
            login = rxn.get("user", {}).get("login", "")
            if login.endswith(_BOT_SUFFIX):
                continue

            content = rxn.get("content", "")
            if content in _POSITIVE_REACTIONS:
                signal = "+1"
            elif content in _NEGATIVE_REACTIONS:
                signal = "-1"
            else:
                continue

            for rule_id in rule_ids:
                try:
                    recorded = await intel_db.record_feedback_signal(
                        rule_id=rule_id,
                        repo=repo,
                        pr_number=pr_number,
                        comment_id=comment_id,
                        reactor_login=login,
                        reaction=signal,
                    )
                    if recorded:
                        new_signals += 1
                except Exception:
                    logger.debug(
                        "Failed to record feedback signal",
                        exc_info=True,
                        extra={
                            "rule_id": rule_id,
                            "repo": repo,
                            "pr_number": pr_number,
                        },
                    )

    if new_signals > 0:
        logger.info(
            "Recorded %d new feedback signals",
            new_signals,
            extra={"repo": repo, "pr_number": pr_number},
        )

    return new_signals
