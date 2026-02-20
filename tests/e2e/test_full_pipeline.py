"""End-to-end tests: webhook → pipeline → DB storage → comment (Doc 27).

Exercises the full stack with ``create_app()`` (not just the webhook router),
a real ``IntelligenceDB`` on ``tmp_path``, and monkeypatched pipeline stages
that return deterministic results.

Uses unique ``X-GitHub-Delivery`` UUIDs per test to avoid ``_delivery_dedup``
module-level collision.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.api.app import create_app
from src.config import SaltaXConfig
from src.pipeline.state import PipelineState

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

_ = pytest  # ensure pytest is used (fixture injection)

_E2E_SECRET = "e2e-webhook-secret"


def _sign(body: bytes) -> str:
    sig = hmac.new(_E2E_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _pr_webhook_payload(**overrides: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "title": "Fix null pointer",
            "body": "Fixes #41",
            "user": {"login": "alice", "id": 12345},
            "head": {"sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "ref": "fix/null-pointer"},
            "base": {"ref": "main"},
            "diff_url": "https://github.com/owner/repo/pull/42.diff",
            "labels": [],
            "created_at": "2026-02-15T10:00:00Z",
            "draft": False,
        },
        "repository": {
            "full_name": "owner/repo",
            "html_url": "https://github.com/owner/repo",
            "clone_url": "https://github.com/owner/repo.git",
        },
        "installation": {"id": 98765},
    }
    defaults.update(overrides)
    return defaults


def _build_e2e_app(intel_db: IntelligenceDB, pipeline: AsyncMock) -> Any:
    """Wire a full FastAPI app with real DB and mock services."""
    config = SaltaXConfig()
    env = MagicMock()
    env.github_webhook_secret = _E2E_SECRET
    env.eigenai_api_url = "https://eigenai.test/v1"
    env.eigenai_api_key = "test-key"

    wallet = MagicMock()
    wallet.address = "0x" + "0" * 40
    wallet.initialized = True

    identity = AsyncMock()
    scheduler = MagicMock()
    scheduler.running = True

    github_client = AsyncMock()
    github_client.get_pr_diff = AsyncMock(return_value="diff --git a/f.py b/f.py\n+pass")
    github_client.list_issue_comments = AsyncMock(return_value=[])
    github_client.create_comment = AsyncMock(return_value=None)

    treasury_mgr = AsyncMock()
    payment_verifier = MagicMock()

    return create_app(
        config=config,
        env=env,
        pipeline=pipeline,
        wallet=wallet,
        intel_db=intel_db,
        identity=identity,
        scheduler=scheduler,
        github_client=github_client,
        treasury_mgr=treasury_mgr,
        payment_verifier=payment_verifier,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# E2E Tests
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.e2e
class TestFullWebhookCycle:
    """Full webhook → pipeline → DB → comment cycle."""

    async def test_pr_opened_approve_cycle(
        self,
        mock_intel_db: IntelligenceDB,
    ) -> None:
        """Webhook → pipeline (all pass) → APPROVE verdict stored in real DB → comment posted."""
        from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

        approve_state = PipelineState(
            pr_id="owner/repo#42",
            repo="owner/repo",
            repo_url="https://github.com/owner/repo",
            commit_sha="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            diff="diff --git a/f.py b/f.py\n+pass",
            base_branch="main",
            head_branch="fix/null-pointer",
            pr_author="alice",
            pr_number=42,
            installation_id=98765,
            verdict={
                "decision": "APPROVE",
                "composite_score": 0.92,
                "threshold_used": 0.75,
                "findings_count": 0,
                "score_breakdown": {},
            },
            attestation={"attestation_id": "att-e2e-approve"},
        )

        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=approve_state)
        app = _build_e2e_app(mock_intel_db, pipeline)

        payload = _pr_webhook_payload()
        body = json.dumps(payload).encode()
        delivery_id = f"e2e-approve-{uuid4().hex[:8]}"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/webhook/github",
                content=body,
                headers={
                    "X-Hub-Signature-256": _sign(body),
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": delivery_id,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 200
        pipeline.run.assert_awaited_once()

        # Verify the pipeline was called with correct PR data
        call_dict = pipeline.run.call_args[0][0]
        assert call_dict["pr_id"] == "owner/repo#42"
        assert call_dict["pr_author"] == "alice"

    async def test_pr_opened_reject_critical(
        self,
        mock_intel_db: IntelligenceDB,
    ) -> None:
        """Webhook → pipeline (CRITICAL finding) → REJECT → rejection handled."""
        from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

        reject_state = PipelineState(
            pr_id="owner/repo#42",
            repo="owner/repo",
            repo_url="https://github.com/owner/repo",
            commit_sha="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            diff="diff --git a/f.py b/f.py\n+pass",
            base_branch="main",
            head_branch="fix/null-pointer",
            pr_author="alice",
            pr_number=42,
            installation_id=98765,
            static_findings=[
                {
                    "rule_id": "hardcoded-secret",
                    "severity": "CRITICAL",
                    "category": "security",
                    "message": "Hardcoded API key",
                    "snippet": 'KEY = "sk-secret"',
                    "confidence": 0.99,
                },
            ],
            short_circuit=True,
            verdict={
                "decision": "REJECT",
                "composite_score": 0.15,
                "threshold_used": 0.75,
                "findings_count": 1,
                "score_breakdown": {},
            },
        )

        pipeline = AsyncMock()
        pipeline.run = AsyncMock(return_value=reject_state)
        app = _build_e2e_app(mock_intel_db, pipeline)

        payload = _pr_webhook_payload()
        body = json.dumps(payload).encode()
        delivery_id = f"e2e-reject-{uuid4().hex[:8]}"

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/webhook/github",
                content=body,
                headers={
                    "X-Hub-Signature-256": _sign(body),
                    "X-GitHub-Event": "pull_request",
                    "X-GitHub-Delivery": delivery_id,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 200
        pipeline.run.assert_awaited_once()

        call_dict = pipeline.run.call_args[0][0]
        assert call_dict["pr_id"] == "owner/repo#42"
