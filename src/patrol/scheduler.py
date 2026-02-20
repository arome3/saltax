"""Patrol scheduler — orchestrates periodic repo scanning cycles.

Follows the same ``asyncio.Event``-based loop pattern as
``DisputeScheduler``: loop → work → interruptible sleep → repeat.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import time
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.patrol.bounty_issuer import BountyIssuer
from src.patrol.codebase_scan import CodebaseScanner
from src.patrol.dependency_audit import DependencyAuditor
from src.patrol.osv_client import OSVClient
from src.patrol.patch_generator import PatchGenerator

if TYPE_CHECKING:
    from pathlib import Path

    from src.attestation.engine import AttestationEngine
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.treasury.manager import TreasuryManager

logger = logging.getLogger(__name__)


class PatrolScheduler:
    """Background task that runs periodic patrol cycles across monitored repos."""

    def __init__(
        self,
        config: SaltaXConfig,
        env: EnvConfig,
        github_client: GitHubClient,
        intel_db: IntelligenceDB,
        treasury_manager: TreasuryManager,
        attestation_engine: AttestationEngine,
    ) -> None:
        self._config = config
        self._env = env
        self._github = github_client
        self._db = intel_db
        self._treasury = treasury_manager
        self._attestation = attestation_engine
        self._stop_event = asyncio.Event()

        self._osv = OSVClient()
        self._auditor = DependencyAuditor(
            config.patrol.dependency_audit, self._osv,
        )
        self._scanner = CodebaseScanner()
        self._patcher = PatchGenerator(github_client, intel_db)
        self._bounty_issuer = BountyIssuer(
            config.patrol, github_client, treasury_manager, intel_db,
        )

    @property
    def running(self) -> bool:
        return not self._stop_event.is_set()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Run the patrol scheduler loop until :meth:`stop` is called."""
        logger.info("PatrolScheduler started (interval=%ds)", self._config.patrol.interval_seconds)
        while not self._stop_event.is_set():
            try:
                await self._patrol_cycle()
            except Exception:
                logger.exception("Patrol cycle error")
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._config.patrol.interval_seconds,
                )
                break  # stop requested
            except TimeoutError:
                pass  # timer expired, next cycle

    async def stop(self) -> None:
        """Signal the scheduler to stop."""
        self._stop_event.set()

    async def close(self) -> None:
        """Stop and release resources."""
        await self.stop()
        await self._osv.close()

    # ── Patrol cycle ──────────────────────────────────────────────────────

    async def _patrol_cycle(self) -> None:
        """Run one full patrol cycle across all monitored repos."""
        repos = self._get_monitored_repos()
        if not repos:
            logger.debug("No repos configured for patrol")
            return

        logger.info("Starting patrol cycle for %d repo(s)", len(repos))

        max_concurrent = self._config.patrol.max_concurrent_repos
        if max_concurrent > 1 and len(repos) > 1:
            # Bounded concurrency via semaphore
            sem = asyncio.Semaphore(max_concurrent)

            async def _guarded(repo: str) -> None:
                async with sem:
                    if self._stop_event.is_set():
                        return
                    try:
                        await self._patrol_repo(repo)
                    except Exception:
                        logger.exception("Patrol failed for %s", repo)

            await asyncio.gather(*[_guarded(r) for r in repos])
        else:
            # Sequential (default when max_concurrent_repos == 1)
            for repo in repos:
                if self._stop_event.is_set():
                    break
                try:
                    await self._patrol_repo(repo)
                except Exception:
                    logger.exception("Patrol failed for %s", repo)

    async def _patrol_repo(self, repo: str) -> None:
        """Run patrol for a single repository."""
        start_time = time.monotonic()

        installation_id = await self._github.get_repo_installation_id(repo)

        # Clone to temp directory
        tmp_dir = tempfile.mkdtemp(prefix="patrol-scan-")
        try:
            from pathlib import Path  # noqa: PLC0415

            repo_path = Path(tmp_dir) / "repo"
            clone_url = f"https://github.com/{repo}.git"
            await self._github.clone_repo(clone_url, repo_path, "main")

            # Detect languages
            languages = self._detect_languages(repo_path)

            # Dependency audit (all detected languages)
            dep_findings = []
            if self._config.patrol.dependency_audit.enabled:
                for language in languages:
                    lang_findings = await self._auditor.audit(repo_path, language)
                    dep_findings.extend(lang_findings)
                logger.info("Found %d dependency findings for %s", len(dep_findings), repo)

            # Codebase scan
            code_findings = []
            if self._config.patrol.codebase_scan.enabled:
                raw_findings = await self._scanner.scan(
                    repo_path, self._config.patrol.codebase_scan,
                )
                code_findings = await self._scanner.diff_against_previous(
                    raw_findings, repo, self._db,
                    rescan_interval_hours=self._config.patrol.codebase_scan.rescan_interval_hours,
                )
                logger.info("Found %d code findings for %s", len(code_findings), repo)

            # Process findings: try patch → else bounty
            patches_generated = 0
            issues_created = 0
            bounties_wei = 0

            for finding in dep_findings:
                if self._stop_event.is_set():
                    break

                # Try auto-patch first
                pr_number = None
                if self._config.patrol.dependency_audit.auto_patch and finding.fixed_version:
                    pr_number = await self._patcher.generate_and_submit(
                        repo, finding, installation_id,
                        source_repo_path=repo_path,
                    )

                if pr_number is not None:
                    patches_generated += 1
                    continue

                # Patch failed or not attempted — check bounty_for_breaking
                # When auto_patch was attempted but failed (pr_number is None after attempt),
                # bounty_for_breaking creates a bounty even though a patch was tried.
                patch_was_attempted = (
                    self._config.patrol.dependency_audit.auto_patch
                    and finding.fixed_version
                )
                if (
                    patch_was_attempted
                    and not self._config.patrol.dependency_audit.bounty_for_breaking
                ):
                    continue  # patch failed but bounty_for_breaking is off

                if self._config.patrol.bounty_assignment.enabled:
                    issue_num = await self._bounty_issuer.create_bounty_for_dependency(
                        repo, finding, installation_id,
                    )
                    if issue_num is not None:
                        issues_created += 1

            for finding in code_findings:
                if self._stop_event.is_set():
                    break
                if self._config.patrol.bounty_assignment.enabled:
                    issue_num = await self._bounty_issuer.create_bounty_for_code(
                        repo, finding, installation_id,
                    )
                    if issue_num is not None:
                        issues_created += 1

            # Generate attestation proof
            duration_ms = int((time.monotonic() - start_time) * 1000)
            now = datetime.now(UTC).isoformat()
            run_id = uuid.uuid4().hex[:16]

            proof = await self._attestation.generate_proof(
                action_id=f"patrol-{run_id}",
                pr_id=f"patrol-{repo}",
                repo=repo,
                inputs={
                    "repo": repo,
                    "languages": languages,
                    "dep_findings_count": len(dep_findings),
                    "code_findings_count": len(code_findings),
                },
                outputs={
                    "patches_generated": patches_generated,
                    "issues_created": issues_created,
                    "bounties_assigned_wei": str(bounties_wei),
                    "duration_ms": duration_ms,
                },
            )

            # Record patrol run
            await self._db.record_patrol_run(
                run_id=run_id,
                repo=repo,
                timestamp=now,
                dependency_findings_count=len(dep_findings),
                code_findings_count=len(code_findings),
                patches_generated=patches_generated,
                issues_created=issues_created,
                bounties_assigned_wei=str(bounties_wei),
                attestation_id=proof.attestation_id,
                duration_ms=duration_ms,
            )

            logger.info(
                "Patrol complete for %s: deps=%d code=%d patches=%d issues=%d (%.1fs)",
                repo, len(dep_findings), len(code_findings),
                patches_generated, issues_created, duration_ms / 1000,
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _get_monitored_repos(self) -> list[str]:
        """Return the list of repos this agent monitors.

        For now, uses the agent's own repo from config. Future: dynamic
        repo discovery via GitHub App installations.
        """
        agent_repo = self._config.agent.repo
        if agent_repo:
            return [agent_repo]
        return []

    @staticmethod
    def _detect_languages(repo_path: Path) -> list[str]:
        """Best-effort language detection based on manifest files.

        Returns all detected languages so multi-language repos are fully audited.
        Falls back to ``["python"]`` when no manifests are found.
        """
        languages: list[str] = []
        if (repo_path / "requirements.txt").exists() or (repo_path / "pyproject.toml").exists():
            languages.append("python")
        if (repo_path / "package.json").exists():
            languages.append("node")
        if (repo_path / "Cargo.toml").exists():
            languages.append("rust")
        return languages or ["python"]
