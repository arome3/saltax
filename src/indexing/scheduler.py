"""Indexing scheduler — periodic codebase graph building for monitored repos.

Follows the same ``asyncio.Event``-based loop pattern as
``PatrolScheduler``: loop → work → interruptible sleep → repeat.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from src.indexing.graph import build_codebase_graph

if TYPE_CHECKING:
    from src.config import SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)


class IndexingScheduler:
    """Background task that periodically indexes codebases to build dependency graphs."""

    def __init__(
        self,
        config: SaltaXConfig,
        github_client: GitHubClient,
        intel_db: IntelligenceDB,
    ) -> None:
        self._config = config
        self._github = github_client
        self._db = intel_db
        self._stop_event = asyncio.Event()

    async def run(self) -> None:
        """Main loop: index all monitored repos, then sleep until next cycle."""
        interval = self._config.indexing.interval_seconds
        max_files = self._config.indexing.max_files_per_repo
        repos = self._config.patrol.repos  # Reuse patrol's monitored repos list

        logger.info(
            "Indexing scheduler started: %d repos, interval=%ds, max_files=%d",
            len(repos), interval, max_files,
        )

        while not self._stop_event.is_set():
            for repo in repos:
                if self._stop_event.is_set():
                    break
                await self._index_repo(repo, max_files)

            # Interruptible sleep
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._stop_event.wait(), timeout=interval,
                )

        logger.info("Indexing scheduler stopped")

    async def _index_repo(self, repo: str, max_files: int) -> None:
        """Clone a repo, build its codebase graph, and clean up."""
        tmp_dir = tempfile.mkdtemp(prefix="saltax-index-")
        try:
            repo_path = Path(tmp_dir) / "repo"
            clone_url = f"https://github.com/{repo}.git"
            # TODO: detect default branch via GitHub API instead of hardcoding "main"
            await self._github.clone_repo(clone_url, repo_path, "main")

            summary = await build_codebase_graph(
                repo_dir=repo_path,
                repo=repo,
                intel_db=self._db,
                max_files=max_files,
            )
            logger.info("Indexed %s: %s", repo, summary)
        except Exception:
            logger.exception("Failed to index %s", repo)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def stop(self) -> None:
        """Signal the scheduler to stop after the current cycle."""
        self._stop_event.set()

    async def close(self) -> None:
        """Resource-cleanup alias for :meth:`stop`."""
        await self.stop()
