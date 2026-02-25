"""Tests for the patrol scheduler."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import (
    CodebaseScanConfig,
    DependencyAuditConfig,
    PatrolConfig,
    SaltaXConfig,
)
from src.patrol.scheduler import PatrolScheduler

_ = pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_config(*, patrol_enabled: bool = True, agent_repo: str = "owner/repo") -> SaltaXConfig:
    """Build a SaltaXConfig with patrol settings."""
    return SaltaXConfig(
        agent={"name": "test", "description": "test", "repo": agent_repo},
        patrol=PatrolConfig(
            enabled=patrol_enabled,
            interval_seconds=1,
            repos=["owner/repo"],
        ),
    )


def _make_scheduler(
    config: SaltaXConfig | None = None,
) -> tuple[PatrolScheduler, dict[str, AsyncMock]]:
    """Build a PatrolScheduler with mocked dependencies."""
    cfg = config or _make_config()
    env = MagicMock()
    github = AsyncMock()
    intel_db = AsyncMock()
    treasury = AsyncMock()
    treasury.check_balance = AsyncMock(return_value=MagicMock(balance_wei=10**18))
    treasury.get_budget_allocation = MagicMock(return_value={"bounty": 10**18})
    treasury.get_bounty_amount_wei = MagicMock(return_value=10**16)
    attestation = AsyncMock()
    attestation.generate_proof = AsyncMock(
        return_value=MagicMock(attestation_id="att-123"),
    )

    scheduler = PatrolScheduler(
        cfg, env, github, intel_db, treasury, attestation,
    )

    mocks = {
        "github": github,
        "intel_db": intel_db,
        "treasury": treasury,
        "attestation": attestation,
    }
    return scheduler, mocks


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestPatrolSchedulerLifecycle:
    """Scheduler lifecycle tests."""

    async def test_run_stops_on_event(self) -> None:
        """stop() causes run() to return promptly."""
        scheduler, _ = _make_scheduler()

        # Patch _patrol_cycle to avoid actual work
        scheduler._patrol_cycle = AsyncMock()

        async def _stop_after_delay() -> None:
            await asyncio.sleep(0.05)
            await scheduler.stop()

        task = asyncio.create_task(scheduler.run())
        stop_task = asyncio.create_task(_stop_after_delay())

        await asyncio.wait_for(
            asyncio.gather(task, stop_task), timeout=5.0,
        )
        assert not scheduler.running

    async def test_close_stops_and_closes_osv(self) -> None:
        """close() stops the loop AND closes the OSV client."""
        scheduler, _ = _make_scheduler()
        scheduler._osv = AsyncMock()
        scheduler._patrol_cycle = AsyncMock()

        task = asyncio.create_task(scheduler.run())
        await asyncio.sleep(0.05)
        await scheduler.close()

        await asyncio.wait_for(task, timeout=5.0)
        scheduler._osv.close.assert_awaited_once()

    async def test_patrol_cycle_per_repo_error_isolation(self) -> None:
        """One repo failure doesn't crash the cycle for others."""
        cfg = _make_config()
        scheduler, mocks = _make_scheduler(cfg)

        call_count = 0

        async def _mock_patrol_repo(repo: str) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("first repo failed")

        scheduler._get_monitored_repos = MagicMock(
            return_value=["owner/repo1", "owner/repo2"],
        )
        scheduler._patrol_repo = AsyncMock(side_effect=_mock_patrol_repo)

        await scheduler._patrol_cycle()

        assert scheduler._patrol_repo.await_count == 2

    async def test_patrol_repo_generates_attestation(self) -> None:
        """Verify generate_proof is called with correct parameters."""
        scheduler, mocks = _make_scheduler()

        # Stub all inner dependencies
        mocks["github"].get_repo_installation_id = AsyncMock(return_value=42)
        mocks["github"].clone_repo = AsyncMock()
        mocks["intel_db"].record_patrol_run = AsyncMock()
        mocks["intel_db"].get_latest_patrol_run = AsyncMock(return_value=None)

        with (
            patch.object(scheduler._auditor, "audit", new_callable=AsyncMock, return_value=[]),
            patch.object(scheduler._scanner, "scan", new_callable=AsyncMock, return_value=[]),
            patch("tempfile.mkdtemp", return_value="/tmp/test-patrol"),
            patch("shutil.rmtree"),
            patch(
                "src.patrol.scheduler.PatrolScheduler._detect_languages",
                return_value=["python"],
            ),
        ):
            await scheduler._patrol_repo("owner/repo")

        mocks["attestation"].generate_proof.assert_awaited_once()
        call_kwargs = mocks["attestation"].generate_proof.call_args.kwargs
        assert call_kwargs["repo"] == "owner/repo"
        assert "patrol-" in call_kwargs["action_id"]

    async def test_patrol_repo_records_history(self) -> None:
        """Verify record_patrol_run is called."""
        scheduler, mocks = _make_scheduler()

        mocks["github"].get_repo_installation_id = AsyncMock(return_value=42)
        mocks["github"].clone_repo = AsyncMock()
        mocks["intel_db"].record_patrol_run = AsyncMock()
        mocks["intel_db"].get_latest_patrol_run = AsyncMock(return_value=None)

        with (
            patch.object(scheduler._auditor, "audit", new_callable=AsyncMock, return_value=[]),
            patch.object(scheduler._scanner, "scan", new_callable=AsyncMock, return_value=[]),
            patch("tempfile.mkdtemp", return_value="/tmp/test-patrol"),
            patch("shutil.rmtree"),
            patch(
                "src.patrol.scheduler.PatrolScheduler._detect_languages",
                return_value=["python"],
            ),
        ):
            await scheduler._patrol_repo("owner/repo")

        mocks["intel_db"].record_patrol_run.assert_awaited_once()
        call_kwargs = mocks["intel_db"].record_patrol_run.call_args.kwargs
        assert call_kwargs["repo"] == "owner/repo"

    async def test_patrol_cycle_cleans_temp_dir(self) -> None:
        """Temp dir is removed even on error."""
        scheduler, mocks = _make_scheduler()

        mocks["github"].get_repo_installation_id = AsyncMock(return_value=42)
        mocks["github"].clone_repo = AsyncMock(side_effect=RuntimeError("clone failed"))

        with (
            patch("tempfile.mkdtemp", return_value="/tmp/test-patrol-cleanup"),
            patch("shutil.rmtree") as mock_rmtree,
            pytest.raises(RuntimeError, match="clone failed"),
        ):
            await scheduler._patrol_repo("owner/repo")

        mock_rmtree.assert_called_once_with(
            "/tmp/test-patrol-cleanup", ignore_errors=True,
        )


# ── _get_monitored_repos tests ────────────────────────────────────────────────


class TestGetMonitoredRepos:
    async def test_uses_patrol_repos(self) -> None:
        """patrol.repos takes priority over agent.repo."""
        cfg = SaltaXConfig(
            agent={"name": "test", "description": "test", "repo": "owner/self"},
            patrol=PatrolConfig(repos=["owner/other1", "owner/other2"]),
        )
        scheduler, _ = _make_scheduler(cfg)
        assert scheduler._get_monitored_repos() == ["owner/other1", "owner/other2"]

    async def test_falls_back_to_agent_repo(self) -> None:
        """Empty patrol.repos falls back to agent.repo."""
        cfg = SaltaXConfig(
            agent={"name": "test", "description": "test", "repo": "owner/self"},
            patrol=PatrolConfig(repos=[]),
        )
        scheduler, _ = _make_scheduler(cfg)
        assert scheduler._get_monitored_repos() == ["owner/self"]

    async def test_returns_empty_when_nothing_configured(self) -> None:
        """No patrol.repos and no agent.repo returns empty list."""
        cfg = SaltaXConfig(
            agent={"name": "test", "description": "test", "repo": ""},
            patrol=PatrolConfig(repos=[]),
        )
        scheduler, _ = _make_scheduler(cfg)
        assert scheduler._get_monitored_repos() == []


# ── _detect_languages tests (T2) ────────────────────────────────────────────


class TestDetectLanguages:
    def test_detect_python_by_requirements(self, tmp_path) -> None:
        """requirements.txt -> ['python']."""
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        result = PatrolScheduler._detect_languages(tmp_path)
        assert result == ["python"]

    def test_detect_python_by_pyproject(self, tmp_path) -> None:
        """pyproject.toml -> ['python']."""
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
        result = PatrolScheduler._detect_languages(tmp_path)
        assert result == ["python"]

    def test_detect_node(self, tmp_path) -> None:
        """package.json -> ['node']."""
        (tmp_path / "package.json").write_text("{}")
        result = PatrolScheduler._detect_languages(tmp_path)
        assert result == ["node"]

    def test_detect_rust(self, tmp_path) -> None:
        """Cargo.toml -> ['rust']."""
        (tmp_path / "Cargo.toml").write_text("[package]\n")
        result = PatrolScheduler._detect_languages(tmp_path)
        assert result == ["rust"]

    def test_detect_multi_language(self, tmp_path) -> None:
        """requirements.txt + package.json -> ['python', 'node']."""
        (tmp_path / "requirements.txt").write_text("flask\n")
        (tmp_path / "package.json").write_text("{}")
        result = PatrolScheduler._detect_languages(tmp_path)
        assert result == ["python", "node"]

    def test_detect_no_manifest_fallback(self, tmp_path) -> None:
        """Empty dir -> ['python'] fallback."""
        result = PatrolScheduler._detect_languages(tmp_path)
        assert result == ["python"]


# ── Config flag branch tests (T10) ──────────────────────────────────────────


class TestConfigFlags:
    async def test_patrol_repo_dep_audit_disabled(self) -> None:
        """dependency_audit.enabled=False -> auditor.audit never called."""
        cfg = SaltaXConfig(
            agent={"name": "test", "description": "test", "repo": "owner/repo"},
            patrol=PatrolConfig(
                dependency_audit=DependencyAuditConfig(
                    enabled=False, severity_threshold="LOW",
                ),
            ),
        )
        scheduler, mocks = _make_scheduler(cfg)

        mocks["github"].get_repo_installation_id = AsyncMock(return_value=42)
        mocks["github"].clone_repo = AsyncMock()
        mocks["intel_db"].record_patrol_run = AsyncMock()
        mocks["intel_db"].get_latest_patrol_run = AsyncMock(return_value=None)

        with (
            patch.object(
                scheduler._auditor, "audit",
                new_callable=AsyncMock, return_value=[],
            ) as mock_audit,
            patch.object(
                scheduler._scanner, "scan",
                new_callable=AsyncMock, return_value=[],
            ),
            patch("tempfile.mkdtemp", return_value="/tmp/test-flag-dep"),
            patch("shutil.rmtree"),
            patch(
                "src.patrol.scheduler.PatrolScheduler._detect_languages",
                return_value=["python"],
            ),
        ):
            await scheduler._patrol_repo("owner/repo")

        mock_audit.assert_not_awaited()

    async def test_patrol_repo_codebase_scan_disabled(self) -> None:
        """codebase_scan.enabled=False -> scanner.scan never called."""
        cfg = SaltaXConfig(
            agent={"name": "test", "description": "test", "repo": "owner/repo"},
            patrol=PatrolConfig(
                codebase_scan=CodebaseScanConfig(enabled=False),
            ),
        )
        scheduler, mocks = _make_scheduler(cfg)

        mocks["github"].get_repo_installation_id = AsyncMock(return_value=42)
        mocks["github"].clone_repo = AsyncMock()
        mocks["intel_db"].record_patrol_run = AsyncMock()
        mocks["intel_db"].get_latest_patrol_run = AsyncMock(return_value=None)

        with (
            patch.object(
                scheduler._auditor, "audit",
                new_callable=AsyncMock, return_value=[],
            ),
            patch.object(
                scheduler._scanner, "scan",
                new_callable=AsyncMock, return_value=[],
            ) as mock_scan,
            patch("tempfile.mkdtemp", return_value="/tmp/test-flag-scan"),
            patch("shutil.rmtree"),
            patch(
                "src.patrol.scheduler.PatrolScheduler._detect_languages",
                return_value=["python"],
            ),
        ):
            await scheduler._patrol_repo("owner/repo")

        mock_scan.assert_not_awaited()


# ── Rescan interval test (T13) ──────────────────────────────────────────────


class TestRescanInterval:
    async def test_rescan_interval_skips_recent_scan(self) -> None:
        """Last scan within interval -> diff_against_previous returns []."""
        from datetime import UTC, datetime  # noqa: PLC0415

        from src.models.patrol import PatrolFinding  # noqa: PLC0415
        from src.patrol.codebase_scan import CodebaseScanner  # noqa: PLC0415

        scanner = CodebaseScanner()
        intel_db = AsyncMock()

        # Last run was 1 hour ago
        recent_ts = datetime.now(UTC).isoformat()
        intel_db.get_latest_patrol_run = AsyncMock(
            return_value={"timestamp": recent_ts},
        )
        intel_db.get_known_finding_signatures = AsyncMock(return_value=set())
        intel_db.upsert_finding_signatures = AsyncMock()

        findings = [
            PatrolFinding(
                rule_id="xss", file_path="app.py",
                line_start=10, line_end=10,
                severity="HIGH", message="XSS",
            ),
        ]

        # rescan_interval_hours=24 means skip if last scan < 24h ago
        result = await scanner.diff_against_previous(
            findings, "owner/repo", intel_db, rescan_interval_hours=24,
        )
        assert result == []
        # Signatures NOT upserted since we skipped
        intel_db.upsert_finding_signatures.assert_not_awaited()


# ── bounty_for_breaking test (T14) ──────────────────────────────────────────


class TestBountyForBreaking:
    async def test_bounty_for_breaking_on_patch_failure(self) -> None:
        """Patch attempt fails + bounty_for_breaking=True -> bounty created."""
        cfg = SaltaXConfig(
            agent={"name": "test", "description": "test", "repo": "owner/repo"},
            patrol=PatrolConfig(
                dependency_audit=DependencyAuditConfig(
                    auto_patch=True,
                    bounty_for_breaking=True,
                    severity_threshold="LOW",
                ),
            ),
        )
        scheduler, mocks = _make_scheduler(cfg)

        mocks["github"].get_repo_installation_id = AsyncMock(return_value=42)
        mocks["github"].clone_repo = AsyncMock()
        mocks["intel_db"].record_patrol_run = AsyncMock()
        mocks["intel_db"].get_latest_patrol_run = AsyncMock(return_value=None)

        from src.models.enums import Severity  # noqa: PLC0415
        from src.models.patrol import DependencyFinding  # noqa: PLC0415

        finding = DependencyFinding(
            package_name="requests",
            current_version="2.25.0",
            vulnerable_range="<2.31.0",
            cve_id="CVE-2023-1234",
            severity=Severity.HIGH,
            advisory_url="https://example.com",
            fixed_version="2.31.0",
            is_direct=True,
            language="python",
        )

        with (
            patch.object(
                scheduler._auditor, "audit",
                new_callable=AsyncMock, return_value=[finding],
            ),
            patch.object(
                scheduler._scanner, "scan",
                new_callable=AsyncMock, return_value=[],
            ),
            # Patch attempt returns None (failed)
            patch.object(
                scheduler._patcher, "generate_and_submit",
                new_callable=AsyncMock, return_value=None,
            ),
            patch.object(
                scheduler._bounty_issuer, "create_bounty_for_dependency",
                new_callable=AsyncMock, return_value=42,
            ) as mock_bounty,
            patch("tempfile.mkdtemp", return_value="/tmp/test-bfb"),
            patch("shutil.rmtree"),
            patch(
                "src.patrol.scheduler.PatrolScheduler._detect_languages",
                return_value=["python"],
            ),
        ):
            await scheduler._patrol_repo("owner/repo")

        # bounty_for_breaking=True -> bounty created even though patch was attempted
        mock_bounty.assert_awaited_once()
