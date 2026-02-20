"""Backfill engine — batch-process historical PRs and issues.

Retroactively embeds and optionally pipeline-processes historical items
when SaltaX is installed on a repo with existing history.  Resumable,
idempotent, rate-limit-aware, and crash-safe.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from src.github.exceptions import GitHubNotFoundError, GitHubRateLimitError
from src.intelligence.similarity import ndarray_to_blob
from src.triage.dedup import embed_diff
from src.triage.issue_dedup import embed_issue
from src.triage.issue_linker import extract_target_issue

if TYPE_CHECKING:
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)


# ── Metrics helper ───────────────────────────────────────────────────────────


def _emit_metric(name: str, value: object, **tags: object) -> None:
    """Emit a structured metric via the JSON logger."""
    logger.info(
        "metric",
        extra={"metric_name": name, "metric_value": value, **tags},
    )


# ── Enums ────────────────────────────────────────────────────────────────────


class BackfillMode(StrEnum):
    EMBEDDING_ONLY = "embedding_only"
    FULL = "full"
    ISSUES_ONLY = "issues_only"


class ItemResult(StrEnum):
    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"


# ── Engine ───────────────────────────────────────────────────────────────────


class BackfillEngine:
    """Batch-process historical PRs/issues for a single repository.

    Concurrency is bounded by an ``asyncio.Semaphore``.  Progress is
    checkpointed to the intelligence DB after each page so that a
    crash or rate-limit pause can be resumed without reprocessing.
    """

    def __init__(
        self,
        config: SaltaXConfig,
        env: EnvConfig,
        intel_db: IntelligenceDB,
        github_client: GitHubClient,
        repo: str,
        mode: BackfillMode,
        *,
        pipeline_runner: Any | None = None,
        attestation_engine: Any | None = None,
        installation_id: int | None = None,
        concurrency: int = 3,
    ) -> None:
        self._config = config
        self._env = env
        self._intel_db = intel_db
        self._github = github_client
        self._repo = repo
        self._mode = mode
        self._pipeline_runner = pipeline_runner
        self._attestation_engine = attestation_engine
        self._installation_id = installation_id
        self._concurrency = concurrency

        self._semaphore = asyncio.Semaphore(concurrency)
        self._stop_event = asyncio.Event()

        # Counters
        self._processed = 0
        self._failed = 0
        self._skipped = 0

    def stop(self) -> None:
        """Signal the engine to stop after the current page completes."""
        self._stop_event.set()

    # ── Public entry point ───────────────────────────────────────────────

    async def run(self) -> dict[str, int]:
        """Run the backfill and return counters.

        Resolves the installation ID if not provided, validates that
        full mode has a pipeline runner, then dispatches to the
        appropriate phase(s).
        """
        if self._installation_id is None:
            self._installation_id = await self._github.get_repo_installation_id(
                self._repo,
            )

        if self._mode == BackfillMode.FULL:
            if self._pipeline_runner is None:
                raise RuntimeError(
                    "Full backfill mode requires a pipeline runner"
                )
            await self._run_pr_phase("full:pr")
            # Save PR-phase counters and reset for issue phase
            pr_processed, pr_failed, pr_skipped = (
                self._processed, self._failed, self._skipped,
            )
            self._processed = 0
            self._failed = 0
            self._skipped = 0
            if not self._stop_event.is_set():
                await self._run_issue_phase("full:issue")
            # Combine totals from both phases
            self._processed += pr_processed
            self._failed += pr_failed
            self._skipped += pr_skipped
        elif self._mode == BackfillMode.EMBEDDING_ONLY:
            await self._run_pr_phase("embedding_only")
        elif self._mode == BackfillMode.ISSUES_ONLY:
            await self._run_issue_phase("issues_only")

        _emit_metric(
            "backfill.run.completed",
            1,
            repo=self._repo,
            mode=self._mode.value,
            processed=self._processed,
            failed=self._failed,
            skipped=self._skipped,
        )

        return {
            "processed": self._processed,
            "failed": self._failed,
            "skipped": self._skipped,
        }

    # ── PR phase ─────────────────────────────────────────────────────────

    async def _run_pr_phase(self, progress_mode: str) -> None:
        """Paginate through PRs, processing each page concurrently."""
        bcfg = self._config.backfill
        start_page = 1

        # Resume from checkpoint
        progress = await self._intel_db.get_backfill_progress(
            self._repo, progress_mode,
        )
        if progress is not None and progress.get("status") in ("running", "paused"):
            start_page = int(progress["last_page"]) + 1
            self._processed = int(progress.get("processed", 0))
            self._failed = int(progress.get("failed", 0))
            self._skipped = int(progress.get("skipped", 0))
            logger.info(
                "Resuming PR backfill from page %d (processed=%d, failed=%d, skipped=%d)",
                start_page, self._processed, self._failed, self._skipped,
            )

        consecutive_404s = 0
        page = start_page

        while not self._stop_event.is_set():
            try:
                items = await self._github.list_pull_requests(
                    self._repo,
                    self._installation_id,
                    state="all",
                    sort="created",
                    direction="asc",
                    page=page,
                    per_page=bcfg.per_page,
                )
            except GitHubNotFoundError:
                consecutive_404s += 1
                if consecutive_404s >= 3:
                    await self._save_progress(
                        progress_mode, "failed", page,
                        error_msg=f"Repository not found after {consecutive_404s} consecutive 404s",
                    )
                    return
                page += 1
                continue
            except GitHubRateLimitError as exc:
                await self._handle_rate_limit(exc, progress_mode, page)
                if self._stop_event.is_set():
                    return
                continue

            consecutive_404s = 0

            if not items:
                # No more pages
                break

            # Process items concurrently within the page
            page_start = time.monotonic()
            tasks = [
                self._process_pr(pr, progress_mode)
                for pr in items
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Scan for rate-limit errors from item-level processing
            rate_limit_exc = next(
                (r for r in results if isinstance(r, GitHubRateLimitError)),
                None,
            )
            if rate_limit_exc is not None:
                _emit_metric("backfill.rate_limit.hit", 1, repo=self._repo)
                await self._handle_rate_limit(rate_limit_exc, progress_mode, page)
                if self._stop_event.is_set():
                    return
                continue  # retry the same page

            page_processed = 0
            page_failed = 0
            page_skipped = 0
            for result in results:
                if isinstance(result, Exception):
                    self._failed += 1
                    page_failed += 1
                    logger.warning(
                        "Backfill PR task raised: %s", result,
                    )
                elif result == ItemResult.OK:
                    self._processed += 1
                    page_processed += 1
                elif result == ItemResult.SKIPPED:
                    self._skipped += 1
                    page_skipped += 1
                elif result == ItemResult.FAILED:
                    self._failed += 1
                    page_failed += 1

            _emit_metric(
                "backfill.page.duration_seconds",
                time.monotonic() - page_start,
                repo=self._repo,
                page=page,
            )
            _emit_metric("backfill.item.processed", page_processed, repo=self._repo, page=page)
            _emit_metric("backfill.item.skipped", page_skipped, repo=self._repo, page=page)
            _emit_metric("backfill.item.failed", page_failed, repo=self._repo, page=page)

            # Check failure limit
            if self._failed >= bcfg.max_failures_before_abort:
                await self._save_progress(
                    progress_mode, "failed", page,
                    error_msg=f"Aborted: {self._failed} failures exceeded limit",
                )
                return

            await self._save_progress(progress_mode, "running", page)
            page += 1

            # Page delay
            if bcfg.page_delay_seconds > 0 and not self._stop_event.is_set():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=bcfg.page_delay_seconds,
                    )

        status = "paused" if self._stop_event.is_set() else "completed"
        await self._save_progress(progress_mode, status, page - 1)

    # ── Issue phase ──────────────────────────────────────────────────────

    async def _run_issue_phase(self, progress_mode: str) -> None:
        """Paginate through issues, processing each page concurrently."""
        bcfg = self._config.backfill
        start_page = 1

        # Resume from checkpoint
        progress = await self._intel_db.get_backfill_progress(
            self._repo, progress_mode,
        )
        if progress is not None and progress.get("status") in ("running", "paused"):
            start_page = int(progress["last_page"]) + 1
            self._processed = int(progress.get("processed", 0))
            self._failed = int(progress.get("failed", 0))
            self._skipped = int(progress.get("skipped", 0))

        consecutive_404s = 0
        page = start_page

        while not self._stop_event.is_set():
            try:
                items = await self._github.list_issues(
                    self._repo,
                    self._installation_id,
                    state="all",
                    sort="created",
                    direction="asc",
                    page=page,
                    per_page=bcfg.per_page,
                )
            except GitHubNotFoundError:
                consecutive_404s += 1
                if consecutive_404s >= 3:
                    await self._save_progress(
                        progress_mode, "failed", page,
                        error_msg=f"Repository not found after {consecutive_404s} consecutive 404s",
                    )
                    return
                page += 1
                continue
            except GitHubRateLimitError as exc:
                await self._handle_rate_limit(exc, progress_mode, page)
                if self._stop_event.is_set():
                    return
                continue

            consecutive_404s = 0

            if not items:
                break

            # Filter out PRs (GitHub issues API returns both)
            issues = [i for i in items if "pull_request" not in i]

            page_start = time.monotonic()
            tasks = [
                self._process_issue(issue)
                for issue in issues
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Scan for rate-limit errors from item-level processing
            rate_limit_exc = next(
                (r for r in results if isinstance(r, GitHubRateLimitError)),
                None,
            )
            if rate_limit_exc is not None:
                _emit_metric("backfill.rate_limit.hit", 1, repo=self._repo)
                await self._handle_rate_limit(rate_limit_exc, progress_mode, page)
                if self._stop_event.is_set():
                    return
                continue  # retry the same page

            page_processed = 0
            page_failed = 0
            page_skipped = 0
            for result in results:
                if isinstance(result, Exception):
                    self._failed += 1
                    page_failed += 1
                    logger.warning("Backfill issue task raised: %s", result)
                elif result == ItemResult.OK:
                    self._processed += 1
                    page_processed += 1
                elif result == ItemResult.SKIPPED:
                    self._skipped += 1
                    page_skipped += 1
                elif result == ItemResult.FAILED:
                    self._failed += 1
                    page_failed += 1

            _emit_metric(
                "backfill.page.duration_seconds",
                time.monotonic() - page_start,
                repo=self._repo,
                page=page,
            )
            _emit_metric("backfill.item.processed", page_processed, repo=self._repo, page=page)
            _emit_metric("backfill.item.skipped", page_skipped, repo=self._repo, page=page)
            _emit_metric("backfill.item.failed", page_failed, repo=self._repo, page=page)

            if self._failed >= bcfg.max_failures_before_abort:
                await self._save_progress(
                    progress_mode, "failed", page,
                    error_msg=f"Aborted: {self._failed} failures exceeded limit",
                )
                return

            await self._save_progress(progress_mode, "running", page)
            page += 1

            if bcfg.page_delay_seconds > 0 and not self._stop_event.is_set():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=bcfg.page_delay_seconds,
                    )

        status = "paused" if self._stop_event.is_set() else "completed"
        await self._save_progress(progress_mode, status, page - 1)

    # ── Item processors ──────────────────────────────────────────────────

    async def _process_pr(
        self,
        pr: dict[str, Any],
        progress_mode: str,
    ) -> ItemResult:
        """Process a single PR: embed and optionally run full pipeline."""
        async with self._semaphore:
            if self._stop_event.is_set():
                return ItemResult.SKIPPED

            pr_number: int = pr["number"]
            repo = self._repo

            # Idempotency check
            existing = await self._intel_db.get_pr_embedding(repo, pr_number)
            if existing is not None:
                return ItemResult.SKIPPED

            # Fetch diff
            try:
                diff = await self._github.get_pr_diff(
                    repo, pr_number, self._installation_id,
                )
            except GitHubRateLimitError:
                raise  # Let gather propagate, handled at page level
            except Exception:
                logger.warning(
                    "Failed to fetch diff for PR #%d", pr_number,
                    exc_info=True,
                )
                return ItemResult.FAILED

            if not diff or not diff.strip():
                return ItemResult.SKIPPED

            # Embed
            try:
                embedding = await embed_diff(
                    diff, env=self._env, config=self._config,
                )
            except Exception:
                logger.warning(
                    "Failed to embed PR #%d", pr_number, exc_info=True,
                )
                return ItemResult.FAILED

            # Extract issue link
            issue_number = extract_target_issue(
                title=pr.get("title", ""),
                body=pr.get("body") or "",
                head_branch=pr.get("head", {}).get("ref", ""),
            )

            # Store embedding
            pr_id = f"{repo}#{pr_number}"
            commit_sha = pr.get("head", {}).get("sha", "")
            embedding_blob = ndarray_to_blob(embedding)
            try:
                await self._intel_db.store_embedding(
                    pr_id=pr_id,
                    repo=repo,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    embedding_blob=embedding_blob,
                    embedding_model=self._config.triage.dedup.embedding_model,
                    issue_number=issue_number,
                )
            except Exception:
                logger.warning(
                    "Failed to store embedding for PR #%d", pr_number,
                    exc_info=True,
                )
                return ItemResult.FAILED

            # Full mode: run pipeline
            if (
                progress_mode.startswith("full")
                and self._pipeline_runner is not None
                and self._attestation_engine is not None
            ):
                try:
                    state = self._build_pipeline_state(
                        pr, diff, issue_number,
                    )
                    from src.pipeline.state import PipelineState  # noqa: PLC0415

                    ps = PipelineState(**state)
                    await self._pipeline_runner(
                        ps,
                        self._config,
                        self._env,
                        self._intel_db,
                        self._attestation_engine,
                    )
                except Exception:
                    logger.warning(
                        "Pipeline failed for backfill PR #%d",
                        pr_number,
                        exc_info=True,
                    )
                    # Embedding stored successfully — count as OK, pipeline is best-effort
                    pass

            return ItemResult.OK

    async def _process_issue(self, issue: dict[str, Any]) -> ItemResult:
        """Process a single issue: embed and store."""
        async with self._semaphore:
            if self._stop_event.is_set():
                return ItemResult.SKIPPED

            issue_number: int = issue["number"]
            repo = self._repo
            title: str = issue.get("title", "")
            body: str | None = issue.get("body")

            # Idempotency check
            existing = await self._intel_db.get_issue_embedding(repo, issue_number)
            if existing is not None:
                return ItemResult.SKIPPED

            # Embed
            try:
                embedding = await embed_issue(
                    title,
                    body,
                    self._env,
                    self._config.triage.issue_dedup,
                )
            except Exception:
                logger.warning(
                    "Failed to embed issue #%d", issue_number,
                    exc_info=True,
                )
                return ItemResult.FAILED

            # Store
            embedding_blob = ndarray_to_blob(embedding)
            issue_id = f"{repo}:{issue_number}"
            labels = [
                lbl.get("name", "") if isinstance(lbl, dict) else str(lbl)
                for lbl in issue.get("labels", [])
            ]
            try:
                await self._intel_db.store_issue_embedding(
                    issue_id=issue_id,
                    repo=repo,
                    issue_number=issue_number,
                    title=title,
                    embedding=embedding_blob,
                    labels=labels if labels else None,
                )
            except Exception:
                logger.warning(
                    "Failed to store issue embedding #%d", issue_number,
                    exc_info=True,
                )
                return ItemResult.FAILED

            return ItemResult.OK

    # ── Helpers ──────────────────────────────────────────────────────────

    async def _handle_rate_limit(
        self,
        exc: GitHubRateLimitError,
        progress_mode: str,
        current_page: int,
    ) -> None:
        """Handle a rate limit error: wait or pause depending on duration."""
        bcfg = self._config.backfill
        wait = max(exc.reset_timestamp - time.time(), 0) + 1

        if wait > bcfg.rate_limit_max_wait_seconds:
            logger.warning(
                "Rate limit wait %.0fs exceeds max %ds — pausing backfill",
                wait, bcfg.rate_limit_max_wait_seconds,
            )
            await self._save_progress(
                progress_mode, "paused", current_page,
                error_msg=f"Rate limited, wait {wait:.0f}s exceeds max",
            )
            self._stop_event.set()
            return

        logger.info(
            "Rate limited — sleeping %.0fs before retry", wait,
        )
        await self._save_progress(progress_mode, "running", current_page)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                self._stop_event.wait(), timeout=wait,
            )

    async def _save_progress(
        self,
        mode: str,
        status: str,
        last_page: int,
        *,
        error_msg: str | None = None,
    ) -> None:
        """Persist progress to DB (best-effort, non-fatal on failure)."""
        try:
            await self._intel_db.save_backfill_progress(
                repo=self._repo,
                mode=mode,
                status=status,
                last_page=last_page,
                processed=self._processed,
                failed=self._failed,
                skipped=self._skipped,
                error_msg=error_msg,
            )
        except Exception:
            logger.warning(
                "Failed to save backfill progress (best-effort)",
                exc_info=True,
            )

    def _build_pipeline_state(
        self,
        pr: dict[str, Any],
        diff: str,
        issue_number: int | None,
    ) -> dict[str, Any]:
        """Construct a dict compatible with PipelineState fields."""
        head = pr.get("head", {})
        base = pr.get("base", {})
        return {
            "pr_id": f"{self._repo}#{pr['number']}",
            "repo": self._repo,
            "repo_url": pr.get("html_url", ""),
            "commit_sha": head.get("sha", ""),
            "diff": diff,
            "base_branch": base.get("ref", ""),
            "head_branch": head.get("ref", ""),
            "pr_author": (pr.get("user") or {}).get("login", ""),
            "pr_number": pr["number"],
            "installation_id": self._installation_id,
            "target_issue_number": issue_number,
        }
