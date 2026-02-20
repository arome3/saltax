"""GitHub webhook ingress route with HMAC signature verification."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request, Response

from src.api.middleware.dedup import DeliveryDedup
from src.api.middleware.github_signature import verify_github_signature

logger = logging.getLogger(__name__)

router = APIRouter()

# Module-level dedup instance — shared across all requests in this process.
# TTL of 1 hour is sufficient; GitHub retries within minutes.
_delivery_dedup = DeliveryDedup(ttl_seconds=3600.0)


def _parse_pr_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract normalised PR event fields from the raw webhook payload."""
    pr = payload["pull_request"]
    repo = payload["repository"]
    return {
        "action": payload["action"],
        "pr_number": pr["number"],
        "pr_id": f"{repo['full_name']}#{pr['number']}",
        "repo_full_name": repo["full_name"],
        "repo_url": repo["html_url"],
        "clone_url": repo["clone_url"],
        "head_sha": pr["head"]["sha"],
        "base_branch": pr["base"]["ref"],
        "head_branch": pr["head"]["ref"],
        "author_login": pr["user"]["login"],
        "author_id": pr["user"]["id"],
        "title": pr["title"],
        "body": pr.get("body"),
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
    return {
        "action": payload["action"],
        "issue_number": issue["number"],
        "repo_full_name": repo["full_name"],
        "labels": [label["name"] for label in issue.get("labels", [])],
        "title": issue["title"],
        "body": issue.get("body"),
        "installation_id": payload.get("installation", {}).get("id"),
    }


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
    body = await request.body()

    # ── Signature verification ───────────────────────────────────────
    signature = request.headers.get("X-Hub-Signature-256", "")
    webhook_secret: str = request.app.state.env.github_webhook_secret

    if not verify_github_signature(body, signature, webhook_secret):
        logger.warning(
            "Webhook signature verification failed",
            extra={"delivery": request.headers.get("X-GitHub-Delivery", "unknown")},
        )
        return Response(status_code=401, content="Invalid signature")

    # ── Parse event ──────────────────────────────────────────────────
    event_type = request.headers.get("X-GitHub-Event", "")
    delivery_id = request.headers.get("X-GitHub-Delivery", "unknown")

    try:
        payload: dict[str, Any] = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Webhook payload is not valid JSON", extra={"delivery": delivery_id})
        return Response(status_code=400, content="Invalid JSON payload")

    # ── Replay protection ────────────────────────────────────────────
    if _delivery_dedup.is_duplicate(delivery_id):
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

    # ── Dispatch by event type ───────────────────────────────────────
    if event_type == "pull_request":
        try:
            pr_data = _parse_pr_event(payload)
        except (KeyError, TypeError):
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
            )

        return Response(status_code=200, content="OK")

    if event_type == "issues":
        try:
            issue_data = _parse_issue_event(payload)
        except (KeyError, TypeError):
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

        return Response(status_code=200, content="OK")

    # Acknowledge unknown event types — returning 4xx makes GitHub mark the hook unhealthy
    logger.debug("Ignoring unhandled event type", extra={"event": event_type})
    return Response(status_code=200, content="Event type not handled")
