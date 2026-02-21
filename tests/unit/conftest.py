"""Shared factory functions for unit tests (Doc 27).

These are plain functions — **not** fixtures — so tests can call them directly
with explicit ``**overrides``.  Existing per-file ``_make_state()`` helpers
continue to work; new and migrated tests import from here instead.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

from src.pipeline.state import PipelineState

# ---------------------------------------------------------------------------
# PipelineState factory
# ---------------------------------------------------------------------------


def make_pipeline_state(**overrides: Any) -> PipelineState:
    """Build a ``PipelineState`` with maximal sensible defaults.

    Covers every required field plus the most commonly-used optional ones.
    Override any field by passing a keyword argument.
    """
    defaults: dict[str, Any] = {
        "pr_id": "owner/repo#42",
        "repo": "owner/repo",
        "repo_url": "https://github.com/owner/repo.git",
        "commit_sha": "abc12345deadbeef",
        "diff": "diff --git a/f.py b/f.py\n+pass",
        "base_branch": "main",
        "head_branch": "fix/stuff",
        "pr_author": "dev",
        "pr_number": 42,
        "installation_id": 1,
    }
    defaults.update(overrides)
    return PipelineState(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Mock IntelligenceDB (pure mock — no real SQLite)
# ---------------------------------------------------------------------------


def make_mock_intel_db() -> AsyncMock:
    """Return a fully-mocked ``IntelligenceDB`` for pure unit tests.

    Pre-stubs the most commonly asserted methods.  Tests can override
    return values or side effects on the returned mock.
    """
    db = AsyncMock()
    db.initialized = True
    db.ingest_pipeline_results = AsyncMock()
    db.get_contributor_wallet = AsyncMock(return_value=None)
    db.store_attestation = AsyncMock(return_value=True)
    db.get_latest_attestation_id = AsyncMock(return_value=None)
    db.get_attestation_chain = AsyncMock(return_value=[])
    db.update_issue_status = AsyncMock()
    db.backfill_embedding_issue_number = AsyncMock(return_value=0)
    return db


# ---------------------------------------------------------------------------
# Mock AttestationEngine
# ---------------------------------------------------------------------------


def make_mock_attestation_engine() -> AsyncMock:
    """Return a mock ``AttestationEngine`` that yields a fixed proof dict."""
    eng = AsyncMock()
    eng.generate_proof = AsyncMock(
        return_value=MagicMock(
            attestation_id="att-test-001",
            signature="ab" * 32,
            signer_address="0x" + "0" * 40,
        ),
    )
    return eng


# ---------------------------------------------------------------------------
# Mock GitHubClient (callable, not a fixture)
# ---------------------------------------------------------------------------


def make_mock_github_client(
    *,
    existing_comments: list[dict[str, Any]] | None = None,
) -> AsyncMock:
    """Return a pre-configured ``AsyncMock`` GitHubClient.

    Same structure as the root ``mock_github_client`` fixture but callable
    from test code directly.
    """
    client = AsyncMock()
    client.get_pr_diff = AsyncMock(
        return_value="diff --git a/f.py b/f.py\n+pass",
    )
    client.list_issue_comments = AsyncMock(
        return_value=existing_comments if existing_comments is not None else [],
    )
    client.post_pr_comment = AsyncMock(return_value=None)
    client.create_comment = AsyncMock(return_value=None)
    client.merge_pr = AsyncMock(return_value={"merged": True})
    client.add_labels = AsyncMock(return_value=None)
    # CI gate defaults — no external CI → NO_CI → merge proceeds
    client.get_pr = AsyncMock(return_value={"head": {"sha": "abc123"}})
    client.list_check_runs_for_ref = AsyncMock(return_value=[])
    client.get_combined_status_for_ref = AsyncMock(
        return_value={"state": "", "total_count": 0},
    )
    return client
