"""Tests for the self-merge protocol: detection, rollback, health check,
upgrade logging, concurrency, handler integration, and scheduler orchestration.
"""

from __future__ import annotations

import asyncio
import json
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.selfmerge.detector import (
    SELF_MODIFICATION_PATHS,
    extract_modified_files,
    is_self_modification,
)
from src.selfmerge.health_check import HealthResult, run_health_check
from src.selfmerge.rollback import BACKUP_DIR, ConfigRollback, _self_merge_lock
from src.selfmerge.upgrade_logger import UpgradeEvent, log_upgrade_event

_ = pytest  # ensure pytest is used (fixture injection)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def mock_kms():
    """In-memory KMS mock backed by a plain dict."""
    store: dict[str, bytes] = {}
    kms = AsyncMock()

    async def _seal(key: str, data: bytes) -> bytes:
        store[key] = data
        return b"sealed:" + key.encode()

    async def _unseal(key: str) -> bytes:
        if key not in store:
            raise RuntimeError(f"Key not found: {key}")
        return store[key]

    kms.seal = AsyncMock(side_effect=_seal)
    kms.unseal = AsyncMock(side_effect=_unseal)
    kms._store = store  # expose for assertions
    return kms


@pytest.fixture()
def mock_intel_db():
    """Minimal IntelligenceDB mock with store_codebase_knowledge."""
    db = AsyncMock()
    db.store_codebase_knowledge = AsyncMock()
    return db


# ═══════════════════════════════════════════════════════════════════════════════
# Section A — Detector: extract_modified_files
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractModifiedFiles:
    """Parse unified diffs into file path sets."""

    def test_standard_diff(self):
        diff = textwrap.dedent("""\
            diff --git a/src/config.py b/src/config.py
            --- a/src/config.py
            +++ b/src/config.py
            @@ -1,3 +1,4 @@
            +# new line
        """)
        result = extract_modified_files(diff)
        assert "src/config.py" in result

    def test_new_file(self):
        diff = textwrap.dedent("""\
            diff --git a/src/new_module.py b/src/new_module.py
            new file mode 100644
            --- /dev/null
            +++ b/src/new_module.py
            @@ -0,0 +1,5 @@
            +# new file
        """)
        result = extract_modified_files(diff)
        assert "src/new_module.py" in result

    def test_deleted_file(self):
        diff = textwrap.dedent("""\
            diff --git a/old_file.py b/old_file.py
            deleted file mode 100644
            --- a/old_file.py
            +++ /dev/null
            @@ -1,5 +0,0 @@
            -# deleted
        """)
        result = extract_modified_files(diff)
        assert "old_file.py" in result

    def test_renamed_file(self):
        diff = textwrap.dedent("""\
            diff --git a/old_name.py b/new_name.py
            similarity index 100%
            rename from old_name.py
            rename to new_name.py
        """)
        result = extract_modified_files(diff)
        assert "new_name.py" in result

    def test_multiple_files(self):
        diff = textwrap.dedent("""\
            diff --git a/file_a.py b/file_a.py
            --- a/file_a.py
            +++ b/file_a.py
            @@ -1 +1 @@
            -old
            +new
            diff --git a/file_b.py b/file_b.py
            --- a/file_b.py
            +++ b/file_b.py
            @@ -1 +1 @@
            -old
            +new
        """)
        result = extract_modified_files(diff)
        assert result == frozenset({"file_a.py", "file_b.py"})

    def test_empty_diff(self):
        assert extract_modified_files("") == frozenset()

    def test_binary_file(self):
        diff = textwrap.dedent("""\
            diff --git a/image.png b/image.png
            Binary files differ
        """)
        result = extract_modified_files(diff)
        assert "image.png" in result

    def test_quoted_path_with_spaces(self):
        diff = 'diff --git "a/path with spaces/file.py" "b/path with spaces/file.py"\n'
        result = extract_modified_files(diff)
        assert "path with spaces/file.py" in result


# ═══════════════════════════════════════════════════════════════════════════════
# Section B — Detector: is_self_modification
# ═══════════════════════════════════════════════════════════════════════════════


class TestIsSelfModification:
    """Classify file sets as self-modification or not."""

    def test_src_directory_prefix(self):
        assert is_self_modification(frozenset({"src/config.py"})) is True

    def test_nested_src(self):
        assert is_self_modification(frozenset({"src/pipeline/runner.py"})) is True

    def test_config_yaml_exact(self):
        assert is_self_modification(frozenset({"saltax.config.yaml"})) is True

    def test_dockerfile_exact(self):
        assert is_self_modification(frozenset({"Dockerfile"})) is True

    def test_pyproject_exact(self):
        assert is_self_modification(frozenset({"pyproject.toml"})) is True

    def test_github_proxy_prefix(self):
        assert is_self_modification(frozenset({"github-proxy/src/index.ts"})) is True

    def test_readme_not_protected(self):
        assert is_self_modification(frozenset({"README.md"})) is False

    def test_docs_not_protected(self):
        assert is_self_modification(frozenset({"docs/guide.md"})) is False

    def test_empty_set(self):
        assert is_self_modification(frozenset()) is False

    def test_mixed_protected_and_unprotected(self):
        files = frozenset({"README.md", "src/main.py", "docs/notes.txt"})
        assert is_self_modification(files) is True

    def test_paths_is_frozenset(self):
        assert isinstance(SELF_MODIFICATION_PATHS, frozenset)

    def test_all_five_paths_present(self):
        expected = {
            "src/", "saltax.config.yaml", "Dockerfile",
            "pyproject.toml", "github-proxy/src/",
        }
        assert expected == SELF_MODIFICATION_PATHS


# ═══════════════════════════════════════════════════════════════════════════════
# Section C — ConfigRollback
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfigRollback:
    """KMS-backed backup and restore lifecycle."""

    async def test_create_and_restore_cycle(self, tmp_path, mock_kms):
        """Backup → corrupt → restore recovers the original content."""
        src_file = tmp_path / "test.yaml"
        src_file.write_text("original: true")

        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()

        await rollback.create_backup([str(src_file)], "bk1")

        # Corrupt
        src_file.write_text("corrupted: true")
        assert src_file.read_text() == "corrupted: true"

        # Restore
        restored = await rollback.restore_backup("bk1")
        assert str(src_file) in restored
        assert src_file.read_text() == "original: true"

    async def test_missing_source_file(self, tmp_path, mock_kms):
        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()

        with pytest.raises(RuntimeError, match="file not found"):
            await rollback.create_backup(["/nonexistent/file.yaml"], "bk_missing")

    async def test_kms_seal_failure_no_temp_leak(self, tmp_path, mock_kms):
        src_file = tmp_path / "f.yaml"
        src_file.write_text("data")

        mock_kms.seal = AsyncMock(side_effect=RuntimeError("KMS down"))
        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()

        with pytest.raises(RuntimeError, match="KMS down"):
            await rollback.create_backup([str(src_file)], "bk_fail")

        # No temp files left behind
        backup_dir = tmp_path / "backups"
        leftover = list(backup_dir.glob("*.tmp"))
        assert leftover == []

    async def test_kms_unseal_failure(self, tmp_path, mock_kms):
        mock_kms.unseal = AsyncMock(side_effect=RuntimeError("KMS unreachable"))
        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()

        with pytest.raises(RuntimeError, match="KMS unseal failed"):
            await rollback.restore_backup("nonexistent_backup")

    async def test_nonexistent_backup(self, tmp_path, mock_kms):
        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()

        with pytest.raises(RuntimeError):
            await rollback.restore_backup("no_such_backup")

    async def test_list_backups_empty(self, tmp_path, mock_kms):
        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()

        result = await rollback.list_backups()
        assert result == []

    async def test_list_backups_after_creates(self, tmp_path, mock_kms):
        f1 = tmp_path / "a.yaml"
        f1.write_text("a")
        f2 = tmp_path / "b.yaml"
        f2.write_text("b")

        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()

        await rollback.create_backup([str(f1)], "bk_a")
        await rollback.create_backup([str(f2)], "bk_b")

        backups = await rollback.list_backups()
        names = [b["backup_name"] for b in backups]
        assert "bk_a" in names
        assert "bk_b" in names
        assert len(backups) == 2

    async def test_closed_rollback_raises(self, tmp_path, mock_kms):
        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()
        await rollback.close()

        with pytest.raises(RuntimeError, match="closed"):
            await rollback.create_backup([], "bk_closed")

    async def test_double_initialize_safe(self, tmp_path, mock_kms):
        rollback = ConfigRollback(kms=mock_kms, backup_dir=tmp_path / "backups")
        await rollback.initialize()
        await rollback.initialize()  # should not raise


# ═══════════════════════════════════════════════════════════════════════════════
# Section D — Health Check
# ═══════════════════════════════════════════════════════════════════════════════


class TestHealthCheck:
    """Post-merge health validation."""

    async def test_valid_config_healthy(self, valid_config_yaml):
        result = await run_health_check(valid_config_yaml)
        assert result.healthy is True
        assert "config_parse" in result.checks_passed
        # Syntax checks should also pass for valid code
        syntax_checks = [c for c in result.checks_passed if c.startswith("syntax:")]
        assert len(syntax_checks) > 0
        assert result.error is None

    async def test_missing_config_unhealthy(self, tmp_path):
        result = await run_health_check(tmp_path / "nonexistent.yaml")
        assert result.healthy is False
        assert "config_parse" in result.checks_failed

    async def test_invalid_config_unhealthy(self, tmp_path):
        bad_cfg = tmp_path / "bad.yaml"
        bad_cfg.write_text("not: valid: yaml: [")
        result = await run_health_check(bad_cfg)
        assert result.healthy is False
        assert "config_parse" in result.checks_failed

    async def test_does_not_propagate_exceptions(self, tmp_path):
        """Health check must never raise, even for BaseException subclasses."""
        result = await run_health_check(tmp_path / "missing.yaml")
        # If we get here, no exception propagated.
        assert isinstance(result, HealthResult)
        assert result.healthy is False

    def test_health_result_defaults(self):
        r = HealthResult()
        assert r.healthy is False
        assert r.checks_passed == []
        assert r.checks_failed == []
        assert r.error is None


# ═══════════════════════════════════════════════════════════════════════════════
# Section E — Upgrade Logger
# ═══════════════════════════════════════════════════════════════════════════════


class TestUpgradeLogger:
    """Structured upgrade event recording."""

    async def test_records_event_and_calls_db(self, mock_intel_db):
        event = await log_upgrade_event(
            intel_db=mock_intel_db,
            pr_id="PR-42",
            repo="owner/saltax",
            commit_sha="abc123",
            modified_files=frozenset({"src/config.py"}),
            backup_name="bk_42",
            health_check_passed=True,
            rolled_back=False,
        )

        assert isinstance(event, UpgradeEvent)
        assert event.pr_id == "PR-42"
        assert event.repo == "owner/saltax"
        assert event.health_check_passed is True
        assert event.rolled_back is False
        assert event.modified_files == ("src/config.py",)

        mock_intel_db.store_codebase_knowledge.assert_awaited_once()
        call_kwargs = mock_intel_db.store_codebase_knowledge.call_args.kwargs
        assert call_kwargs["file_path"] == "__self_merge_log__"
        stored = json.loads(call_kwargs["knowledge"])
        assert stored["type"] == "self_merge_upgrade"

    async def test_db_failure_does_not_raise(self, mock_intel_db):
        mock_intel_db.store_codebase_knowledge = AsyncMock(
            side_effect=RuntimeError("DB down"),
        )

        # Must not raise
        event = await log_upgrade_event(
            intel_db=mock_intel_db,
            pr_id="PR-99",
            repo="owner/saltax",
            commit_sha="def456",
            modified_files=frozenset(),
            backup_name="bk_99",
            health_check_passed=False,
            rolled_back=True,
        )
        assert isinstance(event, UpgradeEvent)
        assert event.rolled_back is True

    def test_upgrade_event_is_frozen(self):
        event = UpgradeEvent(
            event_id="e1",
            pr_id="pr1",
            repo="r",
            commit_sha="sha",
            modified_files=("a.py",),
            backup_name="bk",
            health_check_passed=True,
            rolled_back=False,
            timestamp="2026-01-01T00:00:00",
        )
        with pytest.raises(AttributeError):
            event.pr_id = "changed"  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════════════
# Section F — Concurrency
# ═══════════════════════════════════════════════════════════════════════════════


class TestConcurrency:
    """Module-level lock prevents concurrent self-merges."""

    async def test_lock_blocks_concurrent_merges(self):
        order: list[str] = []

        async def task(label: str) -> None:
            async with _self_merge_lock:
                order.append(f"{label}:start")
                await asyncio.sleep(0.01)
                order.append(f"{label}:end")

        await asyncio.gather(task("A"), task("B"))

        # One must complete before the other starts.
        a_start = order.index("A:start")
        a_end = order.index("A:end")
        b_start = order.index("B:start")
        b_end = order.index("B:end")

        # Either A fully before B, or B fully before A.
        assert (a_end < b_start) or (b_end < a_start)

    def test_lock_is_module_level_singleton(self):
        from src.selfmerge.rollback import (
            _self_merge_lock as lock_direct,
        )

        assert lock_direct is _self_merge_lock

    def test_backup_dir_constant(self):
        assert Path("/tmp/saltax_config_backups") == BACKUP_DIR


# ═══════════════════════════════════════════════════════════════════════════════
# Section G — Handler Integration
# ═══════════════════════════════════════════════════════════════════════════════


class TestHandlerIntegration:
    """Verify handle_pr_event wires self-modification detection."""

    async def _build_pr_data(self, repo: str = "owner/saltax"):
        return {
            "action": "opened",
            "installation_id": 12345,
            "repo_full_name": repo,
            "pr_number": 1,
            "pr_id": f"{repo}#1",
            "repo_url": f"https://github.com/{repo}",
            "head_sha": "abc123",
            "base_branch": "main",
            "head_branch": "feat",
            "author_login": "contributor",
            "labels": [],
        }

    async def test_self_mod_detected_for_matching_repo(
        self, sample_config, monkeypatch,
    ):
        """When agent.repo matches and diff touches src/, is_self_mod is True."""
        monkeypatch.setattr(sample_config.agent, "repo", "owner/saltax")

        captured_state: dict[str, object] = {}
        pipeline = AsyncMock()

        async def fake_run(state_dict):
            captured_state.update(state_dict)
            return MagicMock(
                verdict=None,
                is_self_modification=state_dict.get("is_self_modification"),
            )

        pipeline.run = AsyncMock(side_effect=fake_run)

        github_client = AsyncMock()
        diff = (
            "diff --git a/src/config.py b/src/config.py\n"
            "--- a/src/config.py\n"
            "+++ b/src/config.py\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        github_client.get_pr_diff = AsyncMock(return_value=diff)

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        from src.api.handlers import handle_pr_event

        await handle_pr_event(
            await self._build_pr_data("owner/saltax"),
            pipeline=pipeline,
            github_client=github_client,
            intel_db=intel_db,
            config=sample_config,
        )

        assert captured_state["is_self_modification"] is True

    async def test_self_mod_false_for_different_repo(
        self, sample_config, monkeypatch,
    ):
        """When repo doesn't match agent.repo, is_self_mod stays False."""
        monkeypatch.setattr(sample_config.agent, "repo", "owner/saltax")

        captured_state: dict[str, object] = {}
        pipeline = AsyncMock()

        async def fake_run(state_dict):
            captured_state.update(state_dict)
            return MagicMock(verdict=None)

        pipeline.run = AsyncMock(side_effect=fake_run)

        github_client = AsyncMock()
        github_client.get_pr_diff = AsyncMock(return_value="diff --git a/src/x.py b/src/x.py\n")

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        from src.api.handlers import handle_pr_event

        await handle_pr_event(
            await self._build_pr_data("other/repo"),
            pipeline=pipeline,
            github_client=github_client,
            intel_db=intel_db,
            config=sample_config,
        )

        assert captured_state["is_self_modification"] is False

    async def test_self_mod_false_when_agent_repo_empty(
        self, sample_config,
    ):
        """When agent.repo is empty, detection is skipped."""
        # Default is ""
        assert sample_config.agent.repo == ""

        captured_state: dict[str, object] = {}
        pipeline = AsyncMock()

        async def fake_run(state_dict):
            captured_state.update(state_dict)
            return MagicMock(verdict=None)

        pipeline.run = AsyncMock(side_effect=fake_run)

        github_client = AsyncMock()
        github_client.get_pr_diff = AsyncMock(return_value="diff --git a/src/x.py b/src/x.py\n")

        intel_db = AsyncMock()
        intel_db.get_contributor_wallet = AsyncMock(return_value=None)

        from src.api.handlers import handle_pr_event

        await handle_pr_event(
            await self._build_pr_data("owner/saltax"),
            pipeline=pipeline,
            github_client=github_client,
            intel_db=intel_db,
            config=sample_config,
        )

        assert captured_state["is_self_modification"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# Section H — Scheduler Self-Merge Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════


class TestSchedulerSelfMerge:
    """Verify the scheduler's self-merge orchestration cycle."""

    @pytest.fixture()
    async def intel_db(self, tmp_path, monkeypatch):
        from src.intelligence.database import IntelligenceDB

        monkeypatch.setattr(
            "src.intelligence.database.DB_PATH", tmp_path / "test.db",
        )
        kms = AsyncMock()
        kms.unseal = AsyncMock(side_effect=Exception("no sealed data"))
        db = IntelligenceDB(kms=kms)
        await db.initialize()
        yield db
        await db.close()

    async def _store_window(
        self, intel_db, *, is_self_mod: bool = False, window_id: str = "win-sm",
    ):
        now = datetime.now(UTC)
        await intel_db.store_verification_window(
            window_id=window_id,
            pr_id="owner/saltax#1",
            repo="owner/saltax",
            pr_number=1,
            installation_id=12345,
            attestation_id="attest-1",
            verdict_json='{"decision": "APPROVE"}',
            attestation_json='{"attestation_id": "attest-1"}',
            contributor_address="0xcontrib",
            bounty_amount_wei="1000",
            stake_amount_wei="500",
            window_hours=72 if is_self_mod else 24,
            opens_at=(now - timedelta(hours=100)).isoformat(),
            closes_at=(now - timedelta(hours=1)).isoformat(),
            is_self_modification=is_self_mod,
        )
        return await intel_db.get_verification_window(window_id)

    async def test_self_merge_backup_merge_health_pass(
        self, intel_db, mock_kms, tmp_path, monkeypatch,
    ):
        """Full self-merge cycle: backup → merge → health passes → executed."""
        from src.config import SaltaXConfig
        from src.verification.scheduler import VerificationScheduler

        # Write a real config file so health check passes
        from tests.conftest import VALID_YAML
        cfg_file = tmp_path / "saltax.config.yaml"
        cfg_file.write_text(VALID_YAML)
        monkeypatch.chdir(tmp_path)

        window = await self._store_window(intel_db, is_self_mod=True)

        mock_github = AsyncMock()
        mock_github.merge_pr = AsyncMock(return_value={"merged": True})
        mock_treasury = AsyncMock()
        mock_treasury.send_payout = AsyncMock(
            return_value=MagicMock(tx_hash="0xdead", amount_wei=1000),
        )

        scheduler = VerificationScheduler(
            SaltaXConfig(), intel_db, mock_github, mock_treasury, kms=mock_kms,
        )

        await scheduler._execute_window(window)

        # Verify merge was called
        mock_github.merge_pr.assert_awaited_once()
        merge_title = mock_github.merge_pr.call_args.kwargs.get("commit_title", "")
        assert "self-merge" in merge_title

        # Verify window marked as executed
        updated = await intel_db.get_verification_window("win-sm")
        assert updated["status"] == "executed"

    async def test_self_merge_health_fail_triggers_rollback(
        self, intel_db, mock_kms, tmp_path, monkeypatch,
    ):
        """When health check fails after merge, config is rolled back."""
        from src.config import SaltaXConfig
        from src.verification.scheduler import VerificationScheduler

        # Write a config that will be backed up, then corrupted
        from tests.conftest import VALID_YAML
        cfg_file = tmp_path / "saltax.config.yaml"
        cfg_file.write_text(VALID_YAML)
        monkeypatch.chdir(tmp_path)

        window = await self._store_window(intel_db, is_self_mod=True)

        mock_github = AsyncMock()
        mock_github.merge_pr = AsyncMock(return_value={"merged": True})
        mock_treasury = AsyncMock()

        scheduler = VerificationScheduler(
            SaltaXConfig(), intel_db, mock_github, mock_treasury, kms=mock_kms,
        )

        # Corrupt config after merge but before health check
        async def merge_and_corrupt(*a, **kw):
            cfg_file.write_text("this: is: [broken yaml")
            return {"merged": True}

        mock_github.merge_pr = AsyncMock(side_effect=merge_and_corrupt)

        await scheduler._execute_window(window)

        # Config should be restored to original
        assert cfg_file.read_text() == VALID_YAML

        # Window still marked executed (merge happened on GitHub)
        updated = await intel_db.get_verification_window("win-sm")
        assert updated["status"] == "executed"

    async def test_normal_window_skips_self_merge_cycle(
        self, intel_db, tmp_path, monkeypatch,
    ):
        """Non-self-modification windows use the normal merge path."""
        from src.config import SaltaXConfig
        from src.verification.scheduler import VerificationScheduler

        window = await self._store_window(intel_db, is_self_mod=False)

        mock_github = AsyncMock()
        mock_github.merge_pr = AsyncMock(return_value={"merged": True})
        mock_treasury = AsyncMock()
        mock_treasury.send_payout = AsyncMock(
            return_value=MagicMock(tx_hash="0xdead", amount_wei=1000),
        )

        scheduler = VerificationScheduler(
            SaltaXConfig(), intel_db, mock_github, mock_treasury, kms=None,
        )

        await scheduler._execute_window(window)

        # Verify normal merge (no "self-merge" in title)
        mock_github.merge_pr.assert_awaited_once()
        merge_title = mock_github.merge_pr.call_args.kwargs.get("commit_title", "")
        assert "self-merge" not in merge_title

        updated = await intel_db.get_verification_window("win-sm")
        assert updated["status"] == "executed"

    async def test_is_self_modification_stored_in_window(self, intel_db):
        """Verify is_self_modification persists in the DB."""
        window = await self._store_window(intel_db, is_self_mod=True)
        assert bool(window["is_self_modification"]) is True

        window_normal = await self._store_window(
            intel_db, is_self_mod=False, window_id="win-normal",
        )
        assert bool(window_normal["is_self_modification"]) is False
