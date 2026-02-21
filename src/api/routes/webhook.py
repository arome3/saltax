"""GitHub webhook ingress route with HMAC signature verification."""

from __future__ import annotations

import json
import logging
from contextlib import nullcontext
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request, Response

from src.api.middleware.dedup import DeliveryDedup
from src.api.middleware.github_signature import verify_github_signature
from src.security.input_validation import (
    sanitize_pr_body,
    sanitize_pr_title,
    validate_commit_sha,
    validate_repo_name,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Module-level dedup instance — shared across all requests in this process.
# TTL of 1 hour is sufficient; GitHub retries within minutes.
_delivery_dedup = DeliveryDedup(ttl_seconds=3600.0)


def _parse_pr_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract normalised PR event fields from the raw webhook payload."""
    pr = payload["pull_request"]
    repo = payload["repository"]

    repo_full_name = repo["full_name"]
    head_sha = pr["head"]["sha"]
    validate_repo_name(repo_full_name)
    validate_commit_sha(head_sha)

    return {
        "action": payload["action"],
        "pr_number": pr["number"],
        "pr_id": f"{repo_full_name}#{pr['number']}",
        "repo_full_name": repo_full_name,
        "repo_url": repo["html_url"],
        "clone_url": repo["clone_url"],
        "head_sha": head_sha,
        "base_branch": pr["base"]["ref"],
        "head_branch": pr["head"]["ref"],
        "author_login": pr["user"]["login"],
        "author_id": pr["user"]["id"],
        "title": sanitize_pr_title(pr["title"]),
        "body": sanitize_pr_body(pr.get("body")),
        "diff_url": pr["diff_url"],
        "labels": [label["name"] for label in pr.get("labels", [])],
        "created_at": pr["created_at"],
        "is_draft": pr.get("draft", False),
        "installation_id": payload.get("installation", {}).get("id"),
    }


def _parse_issue_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract normalised issue event fields from the raw webhook payload."""
    issue = payload["issue"]
    repo = payload["repository"]

    repo_full_name = repo["full_name"]
    validate_repo_name(repo_full_name)

    return {
        "action": payload["action"],
        "issue_number": issue["number"],
        "repo_full_name": repo_full_name,
        "repo": repo_full_name,
        "labels": [label["name"] for label in issue.get("labels", [])],
        "title": sanitize_pr_title(issue["title"]),
        "body": sanitize_pr_body(issue.get("body")),
        "state": issue.get("state", "open"),
        "body_changed": payload.get("changes", {}).get("body") is not None,
        "installation_id": payload.get("installation", {}).get("id"),
    }


async def _handle_check_run_completed(
    *,
    scheduler: object,
    intel_db: object,
    repo: str,
    pr_number: int,
) -> None:
    """Trigger merge for PRs with expired verification windows when CI completes.

    This is the event-driven complement to the scheduler's polling CI gate.
    When a ``check_run`` event with ``action: "completed"`` arrives, we check
    if any associated PR has an expired open window waiting for CI, and if so,
    trigger an immediate execution rather than waiting for the next tick.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    try:
        now_iso = datetime.now(UTC).isoformat()
        expired = await intel_db.get_expired_open_windows(now_iso)  # type: ignore[union-attr]

        matching = [
            w for w in expired
            if str(w.get("repo")) == repo and int(w.get("pr_number", 0)) == pr_number
        ]

        for window in matching:
            logger.info(
                "check_run completed → triggering merge for expired window",
                extra={
                    "window_id": window["id"],
                    "repo": repo,
                    "pr_number": pr_number,
                },
            )
            try:
                await scheduler._execute_window(window)  # type: ignore[union-attr]
            except Exception:
                logger.exception(
                    "check_run triggered merge failed",
                    extra={"window_id": window["id"]},
                )
    except Exception:
        logger.exception(
            "check_run handler error",
            extra={"repo": repo, "pr_number": pr_number},
        )


@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> Response:
    """Receive and verify GitHub webhook payloads.

    1. Read raw body bytes for HMAC verification.
    2. Verify ``X-Hub-Signature-256`` header.
    3. Deduplicate by ``X-GitHub-Delivery`` ID.
    4. Dispatch based on ``X-GitHub-Event`` header.
    """
    tracker = getattr(request.app.state, "budget_tracker", None)
    async with tracker.track("webhook_acceptance") if tracker else nullcontext():
        body = await request.body()

        # ── Signature verification ───────────────────────────────────
        signature = request.headers.get("X-Hub-Signature-256", "")
        webhook_secret: str = request.app.state.env.github_webhook_secret

        if not verify_github_signature(body, signature, webhook_secret):
            logger.warning(
                "Webhook signature verification failed",
                extra={"delivery": request.headers.get("X-GitHub-Delivery", "unknown")},
            )
            return Response(status_code=401, content="Invalid signature")

        # ── Parse event ──────────────────────────────────────────────
        event_type = request.headers.get("X-GitHub-Event", "")
        delivery_id = request.headers.get("X-GitHub-Delivery", "unknown")

        try:
            payload: dict[str, Any] = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning(
                "Webhook payload is not valid JSON",
                extra={"delivery": delivery_id},
            )
            return Response(status_code=400, content="Invalid JSON payload")

        # ── Replay protection ────────────────────────────────────────
        if await _delivery_dedup.is_duplicate(delivery_id):
            logger.info(
                "Duplicate webhook delivery ignored",
                extra={"delivery": delivery_id, "event": event_type},
            )
            return Response(status_code=200, content="OK")

        logger.info(
            "Webhook received",
            extra={
                "event": event_type,
                "delivery": delivery_id,
                "action": payload.get("action", ""),
            },
        )

        # ── Dispatch by event type ───────────────────────────────────
        if event_type == "pull_request":
            try:
                pr_data = _parse_pr_event(payload)
            except (KeyError, TypeError, ValueError):
                logger.exception("Failed to parse pull_request event")
                return Response(status_code=400, content="Malformed pull_request payload")

            logger.info(
                "PR event dispatched",
                extra={
                    "action": pr_data["action"],
                    "pr_id": pr_data["pr_id"],
                    "author": pr_data["author_login"],
                },
            )

            if pr_data["action"] in ("opened", "synchronize"):
                from src.api.handlers import handle_pr_event  # noqa: PLC0415

                background_tasks.add_task(
                    handle_pr_event,
                    pr_data,
                    pipeline=request.app.state.pipeline,
                    github_client=request.app.state.github_client,
                    intel_db=request.app.state.intel_db,
                    config=request.app.state.config,
                    env=request.app.state.env,
                    vector_index_manager=getattr(
                        request.app.state, "vector_index_manager", None,
                    ),
                )

            return Response(status_code=200, content="OK")

        if event_type == "issues":
            try:
                issue_data = _parse_issue_event(payload)
            except (KeyError, TypeError, ValueError):
                logger.exception("Failed to parse issues event")
                return Response(status_code=400, content="Malformed issues payload")

            logger.info(
                "Issue event dispatched",
                extra={
                    "action": issue_data["action"],
                    "issue_number": issue_data["issue_number"],
                    "repo": issue_data["repo_full_name"],
                },
            )

            if issue_data["action"] == "labeled":
                from src.api.handlers import handle_issue_labeled  # noqa: PLC0415

                background_tasks.add_task(handle_issue_labeled, issue_data)

            if issue_data["action"] in ("opened", "edited", "closed"):
                from src.api.handlers import handle_issue_event  # noqa: PLC0415

                background_tasks.add_task(
                    handle_issue_event,
                    issue_data,
                    github_client=request.app.state.github_client,
                    intel_db=request.app.state.intel_db,
                    config=request.app.state.config,
                    env=request.app.state.env,
                    vector_index_manager=getattr(
                        request.app.state, "vector_index_manager", None,
                    ),
                )

            return Response(status_code=200, content="OK")

        if event_type == "check_run" and payload.get("action") == "completed":
            check_run = payload.get("check_run", {})
            pr_list = check_run.get("pull_requests", [])

            if pr_list:
                scheduler = getattr(request.app.state, "scheduler", None)
                intel_db = getattr(request.app.state, "intel_db", None)

                if scheduler is not None and intel_db is not None:
                    for pr in pr_list:
                        pr_number = pr.get("number")
                        repo_full_name = (
                            payload.get("repository", {}).get("full_name", "")
                        )
                        if not pr_number or not repo_full_name:
                            continue

                        background_tasks.add_task(
                            _handle_check_run_completed,
                            scheduler=scheduler,
                            intel_db=intel_db,
                            repo=repo_full_name,
                            pr_number=pr_number,
                        )

                logger.info(
                    "check_run.completed dispatched",
                    extra={
                        "check_name": check_run.get("name"),
                        "conclusion": check_run.get("conclusion"),
                        "pr_count": len(pr_list),
                    },
                )

            return Response(status_code=200, content="OK")

        # Acknowledge unknown event types — returning 4xx makes GitHub mark the hook unhealthy
        logger.debug("Ignoring unhandled event type", extra={"event": event_type})
        return Response(status_code=200, content="Event type not handled")
