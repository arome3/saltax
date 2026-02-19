"""Structured logging for self-merge upgrade events.

All writes are best-effort — failures are logged but never raised so that
the merge pipeline is not blocked by audit instrumentation.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class UpgradeEvent:
    """Immutable record of a self-merge upgrade."""

    event_id: str
    pr_id: str
    repo: str
    commit_sha: str
    modified_files: tuple[str, ...]
    backup_name: str
    health_check_passed: bool
    rolled_back: bool
    timestamp: str


async def log_upgrade_event(
    *,
    intel_db: IntelligenceDB,
    pr_id: str,
    repo: str,
    commit_sha: str,
    modified_files: frozenset[str],
    backup_name: str,
    health_check_passed: bool,
    rolled_back: bool,
) -> UpgradeEvent:
    """Create and persist an upgrade event.  Never raises."""
    event = UpgradeEvent(
        event_id=uuid.uuid4().hex,
        pr_id=pr_id,
        repo=repo,
        commit_sha=commit_sha,
        modified_files=tuple(sorted(modified_files)),
        backup_name=backup_name,
        health_check_passed=health_check_passed,
        rolled_back=rolled_back,
        timestamp=datetime.now(UTC).isoformat(),
    )

    # Always emit structured log
    logger.info(
        "Self-merge upgrade event",
        extra={
            "event_id": event.event_id,
            "pr_id": event.pr_id,
            "repo": event.repo,
            "commit_sha": event.commit_sha,
            "backup_name": event.backup_name,
            "health_check_passed": event.health_check_passed,
            "rolled_back": event.rolled_back,
        },
    )

    # Best-effort DB persistence
    try:
        knowledge = json.dumps({
            "type": "self_merge_upgrade",
            "event_id": event.event_id,
            "pr_id": event.pr_id,
            "commit_sha": event.commit_sha,
            "modified_files": list(event.modified_files),
            "backup_name": event.backup_name,
            "health_check_passed": event.health_check_passed,
            "rolled_back": event.rolled_back,
            "timestamp": event.timestamp,
        })
        await intel_db.store_codebase_knowledge(
            knowledge_id=event.event_id,
            repo=repo,
            file_path="__self_merge_log__",
            knowledge=knowledge,
        )
    except Exception:
        logger.exception(
            "Failed to persist upgrade event to intel_db",
            extra={"event_id": event.event_id},
        )

    return event
