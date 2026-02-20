"""Tests for the GitHub webhook ingress route (src/api/routes/webhook.py)."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.api.routes.webhook import router

_SECRET = "test-webhook-secret"


def _sign(body: bytes, secret: str = _SECRET) -> str:
    """Compute a valid X-Hub-Signature-256 header value."""
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _make_app() -> FastAPI:
    """Create a minimal FastAPI app with the webhook router for testing."""
    app = FastAPI()
    app.include_router(router)

    # Wire up the minimal state the route expects
    env_mock = MagicMock()
    env_mock.github_webhook_secret = _SECRET
    app.state.env = env_mock
    app.state.pipeline = AsyncMock()
    app.state.github_client = AsyncMock()
    app.state.intel_db = AsyncMock()
    config_mock = MagicMock()
    config_mock.triage.enabled = False  # match default; prevents dedup from running with mocks
    app.state.config = config_mock

    return app


@pytest.fixture()
async def client() -> AsyncClient:
    app = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c  # type: ignore[misc]


def _pr_payload(
    *,
    action: str = "opened",
    pr_number: int = 42,
    draft: bool = False,
) -> dict[str, Any]:
    """Build a realistic pull_request webhook payload."""
    return {
        "action": action,
        "pull_request": {
            "number": pr_number,
            "title": "Fix typo",
            "body": "Fixes a small typo",
            "user": {"login": "octocat", "id": 1},
            "head": {"sha": "abc123", "ref": "fix-typo"},
            "base": {"ref": "main"},
            "diff_url": "https://github.com/owner/repo/pull/42.diff",
            "labels": [{"name": "bug"}],
            "created_at": "2026-01-15T10:00:00Z",
            "draft": draft,
        },
        "repository": {
            "full_name": "owner/repo",
            "html_url": "https://github.com/owner/repo",
            "clone_url": "https://github.com/owner/repo.git",
        },
        "installation": {"id": 99},
    }


def _issue_payload(*, action: str = "opened", issue_number: int = 7) -> dict[str, Any]:
    """Build a realistic issues webhook payload."""
    return {
        "action": action,
        "issue": {
            "number": issue_number,
            "title": "Bug report",
            "body": "Something is broken",
            "labels": [{"name": "bug"}, {"name": "help wanted"}],
        },
        "repository": {
            "full_name": "owner/repo",
        },
        "installation": {"id": 99},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Signature Verification (at route level)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSignatureVerification:
    async def test_valid_signature_accepted(self, client: AsyncClient) -> None:
        body = json.dumps(_pr_payload()).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "test-delivery-1",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200

    async def test_invalid_signature_rejected(self, client: AsyncClient) -> None:
        body = json.dumps(_pr_payload()).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": "sha256=invalid",
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "test-delivery-2",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 401

    async def test_missing_signature_rejected(self, client: AsyncClient) -> None:
        body = json.dumps(_pr_payload()).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# Pull Request Events
# ═══════════════════════════════════════════════════════════════════════════════


class TestPullRequestEvent:
    async def test_pr_opened_returns_200(self, client: AsyncClient) -> None:
        payload = _pr_payload(action="opened")
        body = json.dumps(payload).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "pr-delivery-1",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200
        assert response.text == "OK"

    async def test_pr_synchronize_returns_200(self, client: AsyncClient) -> None:
        payload = _pr_payload(action="synchronize")
        body = json.dumps(payload).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "pr-delivery-2",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200

    async def test_malformed_pr_payload_returns_400(self, client: AsyncClient) -> None:
        """Missing required 'pull_request' key should return 400."""
        body = json.dumps({"action": "opened"}).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "pr-delivery-3",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# Issue Events
# ═══════════════════════════════════════════════════════════════════════════════


class TestIssueEvent:
    async def test_issue_opened_returns_200(self, client: AsyncClient) -> None:
        payload = _issue_payload(action="opened")
        body = json.dumps(payload).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "issues",
                "X-GitHub-Delivery": "issue-delivery-1",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200
        assert response.text == "OK"

    async def test_malformed_issue_payload_returns_400(self, client: AsyncClient) -> None:
        body = json.dumps({"action": "opened"}).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "issues",
                "X-GitHub-Delivery": "issue-delivery-2",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# Unhandled Events & Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    async def test_unknown_event_returns_200(self, client: AsyncClient) -> None:
        """GitHub marks hooks unhealthy on 4xx, so unhandled events get 200."""
        body = json.dumps({"zen": "Keep it logically awesome."}).encode()
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "ping",
                "X-GitHub-Delivery": "ping-delivery-1",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200
        assert response.text == "Event type not handled"

    async def test_invalid_json_returns_400(self, client: AsyncClient) -> None:
        body = b"not json at all"
        response = await client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "bad-json-1",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 400
        assert "Invalid JSON" in response.text
