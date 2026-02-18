"""Integration tests for the full webhook → handler background task flow."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.api.routes.webhook import router

_SECRET = "integration-test-secret"


def _sign(body: bytes, secret: str = _SECRET) -> str:
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _make_app(
    *,
    pipeline: AsyncMock | None = None,
    github_client: AsyncMock | None = None,
) -> FastAPI:
    """Create a minimal app with the webhook router and configurable mocks."""
    app = FastAPI()
    app.include_router(router)

    env_mock = MagicMock()
    env_mock.github_webhook_secret = _SECRET

    app.state.env = env_mock
    app.state.pipeline = pipeline or AsyncMock()
    app.state.github_client = github_client or AsyncMock()

    return app


def _pr_payload(*, action: str = "opened") -> dict[str, Any]:
    return {
        "action": action,
        "pull_request": {
            "number": 42,
            "title": "Fix typo",
            "body": "Fixes a small typo",
            "user": {"login": "octocat", "id": 1},
            "head": {"sha": "abc123", "ref": "fix-typo"},
            "base": {"ref": "main"},
            "diff_url": "https://github.com/owner/repo/pull/42.diff",
            "labels": [],
            "created_at": "2026-01-15T10:00:00Z",
            "draft": False,
        },
        "repository": {
            "full_name": "owner/repo",
            "html_url": "https://github.com/owner/repo",
            "clone_url": "https://github.com/owner/repo.git",
        },
        "installation": {"id": 99},
    }


def _issue_labeled_payload() -> dict[str, Any]:
    return {
        "action": "labeled",
        "issue": {
            "number": 7,
            "title": "Add feature",
            "body": "Please add this",
            "labels": [{"name": "bounty-sm"}, {"name": "enhancement"}],
        },
        "repository": {"full_name": "owner/repo"},
        "installation": {"id": 99},
    }


async def _send_webhook(
    client: AsyncClient,
    body: bytes,
    *,
    event: str,
    delivery_id: str,
) -> Any:
    """Helper to send a signed webhook request."""
    return await client.post(
        "/webhook/github",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(body),
            "X-GitHub-Event": event,
            "X-GitHub-Delivery": delivery_id,
            "Content-Type": "application/json",
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PR → Pipeline Flow
# ═══════════════════════════════════════════════════════════════════════════════


class TestPRWebhookFlow:
    async def test_pr_opened_triggers_background_handler(self) -> None:
        """PR opened webhook should return 200 immediately and schedule handler."""
        pipeline_mock = AsyncMock()
        github_client_mock = AsyncMock()
        github_client_mock.get_pr_diff.return_value = "diff --git ..."

        app = _make_app(pipeline=pipeline_mock, github_client=github_client_mock)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps(_pr_payload(action="opened")).encode()
            response = await _send_webhook(
                c, body, event="pull_request", delivery_id="integ-flow-1"
            )

        assert response.status_code == 200
        assert response.text == "OK"

        github_client_mock.get_pr_diff.assert_awaited_once_with("owner/repo", 42, 99)
        pipeline_mock.run.assert_awaited_once()

    async def test_pr_closed_does_not_trigger_handler(self) -> None:
        """PR closed events should NOT trigger the background handler."""
        pipeline_mock = AsyncMock()
        github_client_mock = AsyncMock()

        app = _make_app(pipeline=pipeline_mock, github_client=github_client_mock)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps(_pr_payload(action="closed")).encode()
            response = await _send_webhook(
                c, body, event="pull_request", delivery_id="integ-flow-2"
            )

        assert response.status_code == 200
        pipeline_mock.run.assert_not_awaited()
        github_client_mock.get_pr_diff.assert_not_awaited()

    async def test_pr_synchronize_triggers_handler(self) -> None:
        """PR synchronize (new push) should also trigger the pipeline."""
        pipeline_mock = AsyncMock()
        github_client_mock = AsyncMock()
        github_client_mock.get_pr_diff.return_value = "diff --git ..."

        app = _make_app(pipeline=pipeline_mock, github_client=github_client_mock)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = json.dumps(_pr_payload(action="synchronize")).encode()
            response = await _send_webhook(
                c, body, event="pull_request", delivery_id="integ-flow-3"
            )

        assert response.status_code == 200
        pipeline_mock.run.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════════════════
# Issue Labeled → Handler Flow
# ═══════════════════════════════════════════════════════════════════════════════


class TestIssueLabeledFlow:
    async def test_issue_labeled_triggers_handler(self) -> None:
        """Issue labeled event should schedule handle_issue_labeled."""
        app = _make_app()
        transport = ASGITransport(app=app)

        with patch("src.api.handlers.handle_issue_labeled") as mock_handler:
            mock_handler.return_value = None

            async with AsyncClient(transport=transport, base_url="http://test") as c:
                body = json.dumps(_issue_labeled_payload()).encode()
                response = await _send_webhook(
                    c, body, event="issues", delivery_id="integ-flow-4"
                )

            assert response.status_code == 200
            mock_handler.assert_called_once()
            call_args = mock_handler.call_args
            issue_data = call_args[0][0]
            assert issue_data["action"] == "labeled"
            assert issue_data["issue_number"] == 7

    async def test_issue_opened_does_not_trigger_labeled_handler(self) -> None:
        """Issue opened events should NOT trigger the labeled handler."""
        app = _make_app()
        transport = ASGITransport(app=app)

        payload = _issue_labeled_payload()
        payload["action"] = "opened"

        with patch("src.api.handlers.handle_issue_labeled") as mock_handler:
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                body = json.dumps(payload).encode()
                response = await _send_webhook(
                    c, body, event="issues", delivery_id="integ-flow-5"
                )

            assert response.status_code == 200
            mock_handler.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# Replay Protection
# ═══════════════════════════════════════════════════════════════════════════════


class TestReplayProtection:
    async def test_duplicate_delivery_does_not_trigger_pipeline(self) -> None:
        """Replaying the same X-GitHub-Delivery ID should not re-trigger the pipeline."""
        pipeline_mock = AsyncMock()
        github_client_mock = AsyncMock()
        github_client_mock.get_pr_diff.return_value = "diff --git ..."

        app = _make_app(pipeline=pipeline_mock, github_client=github_client_mock)
        transport = ASGITransport(app=app)

        delivery_id = "integ-replay-test-unique-1"
        body = json.dumps(_pr_payload(action="opened")).encode()

        async with AsyncClient(transport=transport, base_url="http://test") as c:
            # First delivery — should process
            r1 = await _send_webhook(
                c, body, event="pull_request", delivery_id=delivery_id
            )
            assert r1.status_code == 200

            # Second delivery with same ID — should be deduped
            r2 = await _send_webhook(
                c, body, event="pull_request", delivery_id=delivery_id
            )
            assert r2.status_code == 200

        # Pipeline should have been called only ONCE
        pipeline_mock.run.assert_awaited_once()
