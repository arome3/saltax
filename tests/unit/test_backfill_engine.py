"""Unit tests for the backfill engine."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from src.backfill.engine import BackfillEngine, BackfillMode, ItemResult
from src.github.exceptions import GitHubNotFoundError, GitHubRateLimitError


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_config() -> Any:
    """Build a minimal mock SaltaXConfig for backfill tests."""
    config = MagicMock()
    config.backfill.per_page = 100
    config.backfill.page_delay_seconds = 0.0  # no delay in tests
    config.backfill.concurrency = 3
    config.backfill.batch_save_interval = 10
    config.backfill.max_failures_before_abort = 50
    config.backfill.rate_limit_max_wait_seconds = 3600
    config.triage.dedup.embedding_model = "text-embedding"
    config.triage.dedup.embedding_api_timeout_seconds = 30
    config.triage.issue_dedup.embedding_model = "text-embedding"
    config.triage.issue_dedup.max_candidates = 500
    return config


def _make_env() -> Any:
    """Build a minimal mock EnvConfig."""
    env = MagicMock()
    env.eigenai_api_url = "https://test.local/v1"
    env.eigenai_api_key = "test-key"
    return env


def _make_intel_db() -> AsyncMock:
    """Build a mock IntelligenceDB with common defaults."""
    db = AsyncMock()
    db.get_backfill_progress.return_value = None
    db.get_pr_embedding.return_value = None
    db.get_issue_embedding.return_value = None
    db.store_embedding.return_value = None
    db.store_issue_embedding.return_value = None
    db.save_backfill_progress.return_value = None
    return db


def _make_github() -> AsyncMock:
    """Build a mock GitHubClient."""
    gh = AsyncMock()
    gh.get_repo_installation_id.return_value = 12345
    return gh


def _fake_pr(number: int) -> dict[str, Any]:
    """Build a minimal PR dict as GitHub API would return."""
    return {
        "number": number,
        "title": f"Test PR #{number}",
        "body": f"Fixes #{number + 100}",
        "head": {"sha": f"abc{number:04d}", "ref": f"fix-{number}"},
        "base": {"ref": "main"},
        "html_url": f"https://github.com/owner/repo/pull/{number}",
        "user": {"login": "contributor"},
    }


def _fake_issue(number: int) -> dict[str, Any]:
    """Build a minimal issue dict (no pull_request key)."""
    return {
        "number": number,
        "title": f"Bug #{number}",
        "body": f"Description for issue {number}",
        "labels": [{"name": "bug"}],
    }


_FAKE_EMBEDDING = np.ones(128, dtype=np.float32)


# ── Test 1: embedding_only happy path ────────────────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_embedding_only_processes_prs(mock_embed, tmp_path):
    """Embedding-only mode fetches diffs, embeds, and stores embeddings."""
    mock_embed.return_value = _FAKE_EMBEDDING

    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    # Single page of 2 PRs, then empty page
    gh.list_pull_requests.side_effect = [
        [_fake_pr(1), _fake_pr(2)],
        [],
    ]
    gh.get_pr_diff.return_value = "diff --git a/foo.py\n+hello"

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    if results["processed"] != 2:
        raise RuntimeError(f"Expected 2 processed, got {results['processed']}")
    if intel_db.store_embedding.call_count != 2:
        raise RuntimeError(
            f"Expected 2 store_embedding calls, got {intel_db.store_embedding.call_count}"
        )


# ── Test 2: idempotency skips existing ───────────────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_idempotency_skips_existing(mock_embed):
    """PRs with existing embeddings are skipped (idempotent)."""
    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    # PR #1 already has an embedding
    intel_db.get_pr_embedding.return_value = {"id": "exists"}

    gh.list_pull_requests.side_effect = [[_fake_pr(1)], []]

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    if results["skipped"] != 1:
        raise RuntimeError(f"Expected 1 skipped, got {results['skipped']}")
    mock_embed.assert_not_called()


# ── Test 3: resume from checkpoint ───────────────────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_resume_from_checkpoint(mock_embed):
    """Engine resumes from the last saved page + 1."""
    mock_embed.return_value = _FAKE_EMBEDDING

    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    # Simulate checkpoint at page 3 with 10 processed
    intel_db.get_backfill_progress.return_value = {
        "status": "paused",
        "last_page": 3,
        "processed": 10,
        "failed": 0,
        "skipped": 5,
    }

    # Page 4 has items, page 5 is empty
    gh.list_pull_requests.side_effect = [[_fake_pr(30)], []]
    gh.get_pr_diff.return_value = "diff content"

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    # Should have resumed counters: 10 + 1 = 11 processed
    if results["processed"] != 11:
        raise RuntimeError(f"Expected 11 processed, got {results['processed']}")

    # Verify list_pull_requests was called with page=4 first (not 1)
    first_call = gh.list_pull_requests.call_args_list[0]
    if first_call.kwargs.get("page") != 4:
        raise RuntimeError(
            f"Expected first page=4, got page={first_call.kwargs.get('page')}"
        )


# ── Test 4: stop event pauses ───────────────────────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_stop_event_pauses(mock_embed):
    """Calling engine.stop() mid-run saves progress as 'paused'."""
    mock_embed.return_value = _FAKE_EMBEDDING

    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    # Return items forever (2 pages then stop kicks in)
    async def _list_prs(*args, **kwargs):
        return [_fake_pr(kwargs.get("page", 1))]

    gh.list_pull_requests.side_effect = _list_prs
    gh.get_pr_diff.return_value = "diff"

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )

    # Stop after first page is processed
    original_save = intel_db.save_backfill_progress
    call_count = 0

    async def _save_and_stop(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count >= 2:
            engine.stop()
        return await original_save(*args, **kwargs)

    intel_db.save_backfill_progress = _save_and_stop

    results = await engine.run()

    # Should have "paused" status in final progress save
    last_save_call = original_save.call_args_list[-1]
    if last_save_call.kwargs.get("status") != "paused":
        raise RuntimeError(
            f"Expected status='paused', got '{last_save_call.kwargs.get('status')}'"
        )


# ── Test 5: issue backfill filters PRs from issues list ─────────────────────


@patch("src.backfill.engine.embed_issue", new_callable=AsyncMock)
async def test_issue_backfill_skips_prs(mock_embed_issue):
    """Issues-only mode filters out items with pull_request key."""
    mock_embed_issue.return_value = _FAKE_EMBEDDING

    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    # Mix of PR-linked issue and real issue
    pr_item = _fake_issue(1)
    pr_item["pull_request"] = {"url": "..."}  # GitHub marks PRs this way
    real_issue = _fake_issue(2)

    gh.list_issues.side_effect = [[pr_item, real_issue], []]

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.ISSUES_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    # Only the real issue should be processed
    if results["processed"] != 1:
        raise RuntimeError(f"Expected 1 processed, got {results['processed']}")


# ── Test 6: rate limit waits then retries ────────────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_rate_limit_waits(mock_embed):
    """Engine waits on 429 then retries the page successfully."""
    mock_embed.return_value = _FAKE_EMBEDDING

    config = _make_config()
    config.backfill.rate_limit_max_wait_seconds = 3600
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    import time  # noqa: PLC0415

    rate_limit_exc = GitHubRateLimitError(
        "rate limited",
        status_code=429,
        reset_timestamp=time.time() + 0.1,  # very short wait
    )

    # First call: rate limit. Second call: success. Third: empty.
    gh.list_pull_requests.side_effect = [
        rate_limit_exc,
        [_fake_pr(1)],
        [],
    ]
    gh.get_pr_diff.return_value = "diff"

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    if results["processed"] != 1:
        raise RuntimeError(f"Expected 1 processed, got {results['processed']}")


# ── Test 7: rate limit pauses on long wait ───────────────────────────────────


async def test_rate_limit_pauses_on_long_wait():
    """Engine pauses when rate limit wait exceeds max_wait_seconds."""
    config = _make_config()
    config.backfill.rate_limit_max_wait_seconds = 60
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    import time  # noqa: PLC0415

    rate_limit_exc = GitHubRateLimitError(
        "rate limited",
        status_code=429,
        reset_timestamp=time.time() + 9999,  # way too long
    )

    gh.list_pull_requests.side_effect = [rate_limit_exc]

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    # Should have saved as "paused"
    save_call = intel_db.save_backfill_progress.call_args_list[-1]
    if save_call.kwargs.get("status") != "paused":
        raise RuntimeError(
            f"Expected paused, got {save_call.kwargs.get('status')}"
        )


# ── Test 8: failure limit aborts ────────────────────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_failure_limit_aborts(mock_embed):
    """Engine aborts when failures exceed max_failures_before_abort."""
    mock_embed.side_effect = RuntimeError("embed broken")

    config = _make_config()
    config.backfill.max_failures_before_abort = 2
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    # Page with 3 PRs — all will fail embedding
    gh.list_pull_requests.side_effect = [
        [_fake_pr(1), _fake_pr(2), _fake_pr(3)],
    ]
    gh.get_pr_diff.return_value = "diff"

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    if results["failed"] < 2:
        raise RuntimeError(f"Expected >= 2 failed, got {results['failed']}")

    # Should have saved as "failed" with error message
    save_call = intel_db.save_backfill_progress.call_args_list[-1]
    if save_call.kwargs.get("status") != "failed":
        raise RuntimeError(
            f"Expected status='failed', got '{save_call.kwargs.get('status')}'"
        )


# ── Test 9: issue embedding skips existing ───────────────────────────────────


@patch("src.backfill.engine.embed_issue", new_callable=AsyncMock)
async def test_issue_embedding_skips_existing(mock_embed_issue):
    """Issues with existing embeddings are skipped."""
    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    intel_db.get_issue_embedding.return_value = {"id": "exists"}
    gh.list_issues.side_effect = [[_fake_issue(1)], []]

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.ISSUES_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    if results["skipped"] != 1:
        raise RuntimeError(f"Expected 1 skipped, got {results['skipped']}")
    mock_embed_issue.assert_not_called()


# ── Test 10: full mode requires pipeline ─────────────────────────────────────


async def test_full_mode_requires_pipeline():
    """Full mode raises RuntimeError when pipeline_runner is None."""
    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.FULL,
        pipeline_runner=None,
        installation_id=99,
    )

    with pytest.raises(RuntimeError, match="pipeline runner"):
        await engine.run()


# ── Test 11: concurrency bounded by semaphore ────────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_concurrency_bounded_by_semaphore(mock_embed):
    """Verify that max concurrent processing equals the configured concurrency."""
    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    max_concurrent = 0
    current_concurrent = 0
    lock = asyncio.Lock()

    original_embed = mock_embed

    async def _slow_embed(*args, **kwargs):
        nonlocal max_concurrent, current_concurrent
        async with lock:
            current_concurrent += 1
            if current_concurrent > max_concurrent:
                max_concurrent = current_concurrent
        await asyncio.sleep(0.1)  # simulate I/O — long enough to saturate
        async with lock:
            current_concurrent -= 1
        return _FAKE_EMBEDDING

    mock_embed.side_effect = _slow_embed

    concurrency_limit = 2
    # Page with 8 PRs — enough to saturate semaphore(2) while items run 0.1s
    gh.list_pull_requests.side_effect = [
        [_fake_pr(i) for i in range(1, 9)],
        [],
    ]
    gh.get_pr_diff.return_value = "diff"

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
        concurrency=concurrency_limit,
    )
    await engine.run()

    # Must equal exactly the limit — proves saturation occurred
    if max_concurrent != concurrency_limit:
        raise RuntimeError(
            f"Expected max_concurrent == {concurrency_limit}, got {max_concurrent}"
        )


# ── Test 12: stop before any page saves page zero ────────────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_stop_before_any_page_saves_page_zero(mock_embed):
    """Pre-setting _stop_event before run() saves progress at page 0 as paused."""
    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    gh.list_pull_requests.return_value = [_fake_pr(1)]
    gh.get_pr_diff.return_value = "diff"
    mock_embed.return_value = _FAKE_EMBEDDING

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    engine.stop()  # pre-set before run

    results = await engine.run()

    # Nothing should have been processed
    if results["processed"] != 0:
        raise RuntimeError(f"Expected 0 processed, got {results['processed']}")

    # Should have saved "paused" at page 0
    save_calls = intel_db.save_backfill_progress.call_args_list
    if not save_calls:
        raise RuntimeError("Expected at least one save_backfill_progress call")
    last_call = save_calls[-1]
    if last_call.kwargs.get("status") != "paused":
        raise RuntimeError(
            f"Expected status='paused', got '{last_call.kwargs.get('status')}'"
        )
    # page - 1 = start_page - 1 = 1 - 1 = 0
    if last_call.kwargs.get("last_page") != 0:
        raise RuntimeError(
            f"Expected last_page=0, got {last_call.kwargs.get('last_page')}"
        )


# ── Test 13: rate limit on diff fetch triggers handler ───────────────────────


@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_rate_limit_on_diff_fetch_triggers_handler(mock_embed):
    """GitHubRateLimitError from get_pr_diff triggers rate limit handler, not failure count."""
    mock_embed.return_value = _FAKE_EMBEDDING

    config = _make_config()
    config.backfill.rate_limit_max_wait_seconds = 3600
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    import time as _time  # noqa: PLC0415

    rate_exc = GitHubRateLimitError(
        "rate limited",
        status_code=429,
        reset_timestamp=_time.time() + 0.1,
    )

    # First page: PR #1 diff raises rate limit error
    # After rate limit handler, retry the page: PR #1 succeeds
    call_count = 0

    async def _get_diff(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise rate_exc
        return "diff --git a/file.py\n+hello"

    gh.list_pull_requests.side_effect = [
        [_fake_pr(1)],   # first attempt at page 1
        [_fake_pr(1)],   # retry of page 1 after rate limit
        [],               # page 2: empty
    ]
    gh.get_pr_diff.side_effect = _get_diff

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    results = await engine.run()

    # The rate-limited item should NOT count as a failure
    if results["failed"] != 0:
        raise RuntimeError(f"Expected 0 failed, got {results['failed']}")
    # After retry, PR #1 should be processed (or skipped if already embedded)
    if results["processed"] + results["skipped"] < 1:
        raise RuntimeError(
            f"Expected at least 1 processed/skipped, got "
            f"processed={results['processed']} skipped={results['skipped']}"
        )


# ── Test 14: full mode runs both phases ──────────────────────────────────────


@patch("src.backfill.engine.embed_issue", new_callable=AsyncMock)
@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_full_mode_runs_both_phases(mock_embed_diff, mock_embed_issue):
    """Full mode calls both list_pull_requests and list_issues."""
    mock_embed_diff.return_value = _FAKE_EMBEDDING
    mock_embed_issue.return_value = _FAKE_EMBEDDING

    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    gh.list_pull_requests.side_effect = [[_fake_pr(1)], []]
    gh.get_pr_diff.return_value = "diff content"
    gh.list_issues.side_effect = [[_fake_issue(10)], []]

    mock_runner = AsyncMock()
    mock_attest = MagicMock()

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.FULL,
        pipeline_runner=mock_runner,
        attestation_engine=mock_attest,
        installation_id=99,
    )
    results = await engine.run()

    # Both list endpoints should have been called
    assert gh.list_pull_requests.call_count >= 1
    assert gh.list_issues.call_count >= 1
    # Both items processed
    if results["processed"] != 2:
        raise RuntimeError(f"Expected 2 processed, got {results['processed']}")


# ── Test 15: consecutive 404 aborts ──────────────────────────────────────────


async def test_consecutive_404_aborts():
    """3 consecutive 404s from list_pull_requests sets status to failed."""
    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    not_found = GitHubNotFoundError(
        "Not found", status_code=404,
    )
    gh.list_pull_requests.side_effect = [not_found, not_found, not_found]

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.EMBEDDING_ONLY,
        installation_id=99,
    )
    await engine.run()

    # Final progress should be "failed"
    save_calls = intel_db.save_backfill_progress.call_args_list
    if not save_calls:
        raise RuntimeError("Expected save_backfill_progress to be called")
    last_call = save_calls[-1]
    if last_call.kwargs.get("status") != "failed":
        raise RuntimeError(
            f"Expected status='failed', got '{last_call.kwargs.get('status')}'"
        )
    if "404" not in str(last_call.kwargs.get("error_msg", "")):
        raise RuntimeError("Expected error_msg to mention 404")


# ── Test 16: full mode counters isolated ─────────────────────────────────────


@patch("src.backfill.engine.embed_issue", new_callable=AsyncMock)
@patch("src.backfill.engine.embed_diff", new_callable=AsyncMock)
async def test_full_mode_counters_isolated(mock_embed_diff, mock_embed_issue):
    """Full mode returns summed totals with isolated per-phase counting."""
    mock_embed_diff.return_value = _FAKE_EMBEDDING
    mock_embed_issue.return_value = _FAKE_EMBEDDING

    config = _make_config()
    env = _make_env()
    intel_db = _make_intel_db()
    gh = _make_github()

    # PR phase: 2 PRs processed
    gh.list_pull_requests.side_effect = [
        [_fake_pr(1), _fake_pr(2)],
        [],
    ]
    gh.get_pr_diff.return_value = "diff"

    # Issue phase: 1 issue processed
    gh.list_issues.side_effect = [
        [_fake_issue(10)],
        [],
    ]

    mock_runner = AsyncMock()
    mock_attest = MagicMock()

    engine = BackfillEngine(
        config=config, env=env, intel_db=intel_db, github_client=gh,
        repo="owner/repo", mode=BackfillMode.FULL,
        pipeline_runner=mock_runner,
        attestation_engine=mock_attest,
        installation_id=99,
    )
    results = await engine.run()

    # 2 PRs + 1 issue = 3 total
    if results["processed"] != 3:
        raise RuntimeError(f"Expected 3 processed, got {results['processed']}")
    if results["failed"] != 0:
        raise RuntimeError(f"Expected 0 failed, got {results['failed']}")

    # Verify that per-phase progress was saved with independent counters
    save_calls = intel_db.save_backfill_progress.call_args_list
    # Find the "full:pr" completed/running calls and "full:issue" calls
    pr_saves = [c for c in save_calls if c.kwargs.get("mode") == "full:pr"]
    issue_saves = [c for c in save_calls if c.kwargs.get("mode") == "full:issue"]

    if not pr_saves:
        raise RuntimeError("Expected at least one save for full:pr")
    if not issue_saves:
        raise RuntimeError("Expected at least one save for full:issue")
