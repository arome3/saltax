"""Shared fixtures and helpers for integration tests (Doc 27)."""

from __future__ import annotations

import os

import hashlib
import hmac
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.intelligence.database import IntelligenceDB

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_DATABASE_URL = os.environ.get(
    "SALTAX_TEST_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/saltax_test",
)

INTEGRATION_WEBHOOK_SECRET = "integration-webhook-secret-42"


# ---------------------------------------------------------------------------
# Helper functions (not fixtures — callable directly)
# ---------------------------------------------------------------------------


def sign_webhook(body: bytes, secret: str = INTEGRATION_WEBHOOK_SECRET) -> str:
    """Compute a valid ``X-Hub-Signature-256`` header value."""
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def pr_webhook_payload(**overrides: Any) -> dict[str, Any]:
    """Build a realistic pull_request webhook JSON payload."""
    defaults: dict[str, Any] = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "title": "Fix null pointer in config parser",
            "body": "Fixes #41",
            "user": {"login": "contributor-alice", "id": 12345},
            "head": {
                "sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "ref": "fix/config-null-pointer",
            },
            "base": {"ref": "main"},
            "diff_url": "https://github.com/owner/repo/pull/42.diff",
            "labels": [{"name": "bug"}],
            "created_at": "2026-02-15T10:30:00Z",
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


def issue_webhook_payload(**overrides: Any) -> dict[str, Any]:
    """Build a realistic issues webhook JSON payload."""
    defaults: dict[str, Any] = {
        "action": "opened",
        "issue": {
            "number": 7,
            "title": "Bug report: crash on startup",
            "body": "App crashes when config file is missing",
            "labels": [{"name": "bug"}, {"name": "help wanted"}],
            "state": "open",
        },
        "repository": {"full_name": "owner/repo"},
        "installation": {"id": 98765},
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def real_intel_db() -> IntelligenceDB:
    """Real ``IntelligenceDB`` backed by PostgreSQL for integration tests."""
    db = IntelligenceDB(database_url=_TEST_DATABASE_URL, pool_min_size=1, pool_max_size=3)
    try:
        await db.initialize()
        yield db  # type: ignore[misc]
    finally:
        await db.close()


@pytest.fixture()
def integration_app(real_intel_db: IntelligenceDB) -> Any:
    """Full FastAPI app via ``create_app()`` with real DB + mocked services.

    Tests the full middleware + exception handler stack, unlike unit tests
    that mount just the webhook router.
    """
    from src.api.app import create_app  # noqa: PLC0415
    from src.config import SaltaXConfig  # noqa: PLC0415

    config = SaltaXConfig()
    env = MagicMock()
    env.github_webhook_secret = INTEGRATION_WEBHOOK_SECRET
    env.eigenai_api_url = "https://eigenai.test/v1"
    env.eigenai_api_key = "test-key"

    pipeline = AsyncMock()
    wallet = MagicMock()
    wallet.address = "0x" + "0" * 40
    wallet.initialized = True

    identity = AsyncMock()
    scheduler = MagicMock()
    scheduler.running = True

    github_client = AsyncMock()
    github_client.get_pr_diff = AsyncMock(
        return_value="diff --git a/f.py b/f.py\n+pass",
    )
    github_client.list_issue_comments = AsyncMock(return_value=[])
    github_client.create_comment = AsyncMock(return_value=None)

    treasury_mgr = AsyncMock()
    payment_verifier = MagicMock()

    app = create_app(
        config=config,
        env=env,
        pipeline=pipeline,
        wallet=wallet,
        intel_db=real_intel_db,
        identity=identity,
        scheduler=scheduler,
        github_client=github_client,
        treasury_mgr=treasury_mgr,
        payment_verifier=payment_verifier,
    )
    return app


@pytest.fixture()
async def integration_client(integration_app: Any) -> Any:
    """``httpx.AsyncClient`` with ``ASGITransport`` for integration tests."""
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    transport = ASGITransport(app=integration_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
