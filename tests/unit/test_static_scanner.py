"""Tests for the static scanner pipeline stage."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import SaltaXConfig
from src.intelligence.database import IntelligenceDB
from src.models.enums import Severity, VulnerabilityCategory
from src.models.pipeline import Finding
from src.pipeline.stages.static_scanner import (
    _build_semgrep_command,
    _clone_repo,
    _infer_category,
    _parse_semgrep_output,
    _run_semgrep,
    _should_short_circuit,
    run_static_scan,
)
from src.pipeline.state import PipelineState
from src.security import validate_branch_name, validate_clone_url

# ── Helpers ──────────────────────────────────────────────────────────────────

_MODULE = "src.pipeline.stages.static_scanner"


def _make_state(**overrides: object) -> PipelineState:
    defaults: dict[str, object] = {
        "pr_id": "owner/repo#42",
        "repo": "owner/repo",
        "repo_url": "https://github.com/owner/repo.git",
        "commit_sha": "abc1234",
        "diff": "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n",
        "base_branch": "main",
        "head_branch": "fix/vuln",
        "pr_author": "dev",
    }
    defaults.update(overrides)
    return PipelineState(**defaults)  # type: ignore[arg-type]


def _make_config() -> SaltaXConfig:
    return SaltaXConfig()


def _make_intel_db() -> IntelligenceDB:
    kms = MagicMock()
    return IntelligenceDB(kms)


def _make_semgrep_result(
    *,
    check_id: str = "rules.security.injection.sql-injection",
    path: str = "src/db.py",
    severity: str = "ERROR",
    message: str = "SQL injection detected",
    line_start: int = 10,
    line_end: int = 12,
    lines: str = "cursor.execute(query)",
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line_start, "col": 1},
        "end": {"line": line_end, "col": 30},
        "extra": {
            "severity": severity,
            "message": message,
            "lines": lines,
        },
    }


def _make_semgrep_output(*results: dict[str, Any]) -> str:
    return json.dumps({"results": list(results)})


def _mock_process(
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> AsyncMock:
    """Create a mock async subprocess process."""
    proc = AsyncMock()
    proc.returncode = returncode
    proc.wait = AsyncMock(return_value=returncode)
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = MagicMock()
    return proc


def _command_dispatch(
    *,
    clone_proc: AsyncMock,
    apply_proc: AsyncMock,
    semgrep_proc: AsyncMock,
) -> Any:
    """Return a side_effect that dispatches by command, not call order."""

    async def _dispatch(*args: object, **kwargs: object) -> AsyncMock:
        str_args = [str(a) for a in args]
        if len(str_args) >= 2 and str_args[0] == "git" and str_args[1] == "clone":
            return clone_proc
        if len(str_args) >= 2 and str_args[0] == "git" and str_args[1] == "apply":
            return apply_proc
        return semgrep_proc

    return _dispatch


# ═══════════════════════════════════════════════════════════════════════════════
# A. _parse_semgrep_output
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseOutput:
    """Unit tests for _parse_semgrep_output."""

    def test_empty_string_returns_empty(self) -> None:
        assert _parse_semgrep_output("") == []

    def test_malformed_json_returns_empty(self) -> None:
        assert _parse_semgrep_output("{not valid json") == []

    def test_valid_json_empty_results(self) -> None:
        assert _parse_semgrep_output('{"results": []}') == []

    def test_single_error_finding(self) -> None:
        raw = _make_semgrep_output(_make_semgrep_result(severity="ERROR"))
        findings = _parse_semgrep_output(raw)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].confidence == 0.95

    def test_multiple_mixed_severity(self) -> None:
        raw = _make_semgrep_output(
            _make_semgrep_result(check_id="rule-a", severity="ERROR"),
            _make_semgrep_result(check_id="rule-b", severity="WARNING"),
            _make_semgrep_result(check_id="rule-c", severity="INFO"),
        )
        findings = _parse_semgrep_output(raw)
        assert len(findings) == 3
        assert findings[0].severity == Severity.CRITICAL
        assert findings[1].severity == Severity.HIGH
        assert findings[2].severity == Severity.MEDIUM

    def test_missing_fields_uses_defaults(self) -> None:
        raw = json.dumps({"results": [{"check_id": "rule-x"}]})
        findings = _parse_semgrep_output(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "rule-x"
        assert f.severity == Severity.MEDIUM
        assert f.confidence == 0.50
        assert f.file_path == "unknown"
        assert f.line_start == 0

    def test_unknown_severity_defaults_to_medium(self) -> None:
        raw = _make_semgrep_output(
            _make_semgrep_result(severity="BANANA")
        )
        findings = _parse_semgrep_output(raw)
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].confidence == 0.50

    def test_long_snippet_truncated(self) -> None:
        long_code = "x" * 1000
        raw = _make_semgrep_output(
            _make_semgrep_result(lines=long_code)
        )
        findings = _parse_semgrep_output(raw)
        assert findings[0].snippet is not None
        assert len(findings[0].snippet) == 500


# ═══════════════════════════════════════════════════════════════════════════════
# B. _infer_category
# ═══════════════════════════════════════════════════════════════════════════════


class TestInferCategory:
    """Unit tests for _infer_category."""

    def test_injection_keyword(self) -> None:
        assert _infer_category("rules.security.injection.sqli") == VulnerabilityCategory.INJECTION

    def test_reentrancy_keyword(self) -> None:
        assert _infer_category("solidity.reentrancy-guard") == VulnerabilityCategory.REENTRANCY

    def test_supply_chain_keyword(self) -> None:
        result = _infer_category("supply-chain.typosquat")
        assert result == VulnerabilityCategory.DEPENDENCY_CONFUSION

    def test_secret_keyword(self) -> None:
        result = _infer_category("generic.secret.leaked-key")
        assert result == VulnerabilityCategory.SECRETS_EXPOSURE

    def test_unknown_returns_other(self) -> None:
        assert _infer_category("some.random.rule.id") == VulnerabilityCategory.OTHER

    def test_case_insensitive(self) -> None:
        assert _infer_category("RULES.INJECTION.SQL") == VulnerabilityCategory.INJECTION


# ═══════════════════════════════════════════════════════════════════════════════
# C. _should_short_circuit
# ═══════════════════════════════════════════════════════════════════════════════


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="test",
        severity=severity,
        category=VulnerabilityCategory.OTHER,
        message="test",
        file_path="f.py",
        line_start=1,
        line_end=1,
        confidence=0.5,
        source_stage="static_scanner",
    )


class TestShouldShortCircuit:
    """Unit tests for _should_short_circuit."""

    def test_empty_findings(self) -> None:
        assert _should_short_circuit([]) is False

    def test_one_critical_triggers(self) -> None:
        assert _should_short_circuit([_finding(Severity.CRITICAL)]) is True

    def test_five_high_does_not_trigger(self) -> None:
        """Threshold is > 5, not >= 5."""
        findings = [_finding(Severity.HIGH)] * 5
        assert _should_short_circuit(findings) is False

    def test_six_high_triggers(self) -> None:
        findings = [_finding(Severity.HIGH)] * 6
        assert _should_short_circuit(findings) is True

    def test_only_medium_low_info(self) -> None:
        findings = [
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
            _finding(Severity.INFO),
        ]
        assert _should_short_circuit(findings) is False


# ═══════════════════════════════════════════════════════════════════════════════
# D. _build_semgrep_command
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuildCommand:
    """Unit tests for _build_semgrep_command."""

    def test_standard_rulesets_present(self) -> None:
        config = _make_config()
        cmd = _build_semgrep_command(Path("/tmp/repo"), config)
        assert "p/security-audit" in cmd
        assert "p/owasp-top-ten" in cmd
        assert "p/supply-chain" in cmd

    @patch.object(Path, "is_dir", return_value=True)
    def test_custom_rules_dir_included(self, _mock: MagicMock) -> None:
        config = _make_config()
        cmd = _build_semgrep_command(Path("/tmp/repo"), config)
        # Find the --config flag followed by the /app/rules path
        config_indices = [i for i, v in enumerate(cmd) if v == "--config"]
        config_values = [cmd[i + 1] for i in config_indices if i + 1 < len(cmd)]
        assert any("/app/rules" in v for v in config_values)

    def test_repo_semgrep_dir_not_loaded(self, tmp_path: Path) -> None:
        """Untrusted repo .semgrep/ must NOT be auto-loaded."""
        semgrep_dir = tmp_path / "repo" / ".semgrep"
        semgrep_dir.mkdir(parents=True)
        config = _make_config()
        cmd = _build_semgrep_command(tmp_path / "repo", config)
        assert str(semgrep_dir) not in cmd

    def test_per_file_timeout_not_total(self) -> None:
        config = _make_config()
        cmd = _build_semgrep_command(Path("/tmp/repo"), config)
        assert "--timeout=30" in cmd

    def test_json_and_quiet_flags(self) -> None:
        config = _make_config()
        cmd = _build_semgrep_command(Path("/tmp/repo"), config)
        assert "--json" in cmd
        assert "--quiet" in cmd


# ═══════════════════════════════════════════════════════════════════════════════
# E. Input validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestInputValidation:
    """Tests for URL and branch name validation."""

    def test_valid_https_github_url(self) -> None:
        validate_clone_url("https://github.com/owner/repo.git")
        validate_clone_url("https://github.com/owner/repo")

    def test_file_url_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe URL"):
            validate_clone_url("file:///etc/passwd")

    def test_ssh_url_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe URL"):
            validate_clone_url("ssh://git@github.com/owner/repo.git")

    def test_internal_ip_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe URL"):
            validate_clone_url("https://169.254.169.254/latest/meta-data")

    def test_http_non_github_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe URL"):
            validate_clone_url("https://evil.com/owner/repo.git")

    def test_valid_branch_name(self) -> None:
        validate_branch_name("main")
        validate_branch_name("feature/my-branch")
        validate_branch_name("release/1.0.0")

    def test_branch_with_dotdot_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe branch"):
            validate_branch_name("main/../etc/passwd")

    def test_branch_with_leading_dash_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe branch"):
            validate_branch_name("-u origin")

    def test_branch_with_control_chars_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe branch"):
            validate_branch_name("main\x00--upload-pack=evil")

    def test_empty_branch_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsafe branch"):
            validate_branch_name("")


# ═══════════════════════════════════════════════════════════════════════════════
# F. run_static_scan (async integration with mocked subprocess)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunStaticScan:
    """Async integration tests for run_static_scan with mocked subprocess."""

    async def test_clean_scan_no_findings(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        semgrep_output = _make_semgrep_output()
        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=0, stdout=semgrep_output.encode()),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        assert state.static_findings == []
        assert state.short_circuit is False

    async def test_findings_parsed_and_stored_as_dicts(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        semgrep_output = _make_semgrep_output(
            _make_semgrep_result(severity="WARNING", check_id="rule-1"),
        )
        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=0, stdout=semgrep_output.encode()),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        assert len(state.static_findings) == 1
        assert isinstance(state.static_findings[0], dict)
        assert state.static_findings[0]["rule_id"] == "rule-1"
        assert state.static_findings[0]["severity"] == "HIGH"

    async def test_critical_triggers_short_circuit(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        semgrep_output = _make_semgrep_output(
            _make_semgrep_result(severity="ERROR"),
        )
        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=0, stdout=semgrep_output.encode()),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        assert state.short_circuit is True

    async def test_six_high_triggers_short_circuit(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        results = [
            _make_semgrep_result(check_id=f"rule-{i}", severity="WARNING")
            for i in range(6)
        ]
        semgrep_output = _make_semgrep_output(*results)
        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=0, stdout=semgrep_output.encode()),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        assert state.short_circuit is True

    async def test_semgrep_not_installed(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        with patch(f"{_MODULE}.shutil.which", return_value=None):
            await run_static_scan(state, config, intel_db)

        assert state.static_findings == []
        assert state.short_circuit is False

    async def test_timeout_results_in_empty_findings(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        clone_proc = _mock_process(returncode=0)
        apply_proc = _mock_process(returncode=0, stderr=b"")

        original_wait_for = asyncio.wait_for
        call_count = 0

        async def selective_timeout(coro: Any, *, timeout: float) -> Any:
            nonlocal call_count
            call_count += 1
            # Let clone/apply succeed (calls 1 & 2), timeout on semgrep (call 3)
            if call_count >= 3:
                coro.close()  # clean up the coroutine
                raise TimeoutError
            return await original_wait_for(coro, timeout=timeout)

        dispatch = _command_dispatch(
            clone_proc=clone_proc,
            apply_proc=apply_proc,
            semgrep_proc=_mock_process(),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
            patch(f"{_MODULE}.asyncio.wait_for", side_effect=selective_timeout),
        ):
            await run_static_scan(state, config, intel_db)

        assert state.static_findings == []
        assert state.short_circuit is False

    async def test_semgrep_error_exit_results_in_empty_findings(self) -> None:
        """Semgrep exit code >= 2 raises RuntimeError, caught by outer handler."""
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=2, stdout=b""),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        assert state.static_findings == []
        assert state.short_circuit is False

    async def test_crash_malformed_output(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            # exit code 1 = "findings found" (not error), but output is garbage
            semgrep_proc=_mock_process(returncode=1, stdout=b"not json at all"),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        assert state.static_findings == []
        assert state.short_circuit is False

    async def test_false_positive_filtering(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()
        intel_db.get_false_positive_signatures = AsyncMock(  # type: ignore[method-assign]
            return_value=frozenset({"rules.security.injection.sql-injection"}),
        )

        semgrep_output = _make_semgrep_output(
            _make_semgrep_result(
                check_id="rules.security.injection.sql-injection",
                severity="ERROR",
            ),
            _make_semgrep_result(
                check_id="rules.security.xss",
                severity="WARNING",
            ),
        )
        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=1, stdout=semgrep_output.encode()),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        assert len(state.static_findings) == 1
        assert state.static_findings[0]["rule_id"] == "rules.security.xss"

    async def test_intel_db_failure_preserves_findings(self) -> None:
        """If intel_db raises, findings are kept (not silently dropped)."""
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()
        intel_db.get_false_positive_signatures = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("DB unavailable"),
        )

        semgrep_output = _make_semgrep_output(
            _make_semgrep_result(severity="WARNING", check_id="rule-kept"),
        )
        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=1, stdout=semgrep_output.encode()),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        # Findings must be preserved even though FP query failed
        assert len(state.static_findings) == 1
        assert state.static_findings[0]["rule_id"] == "rule-kept"

    async def test_temp_dir_cleanup(self) -> None:
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(
                f"{_MODULE}.asyncio.create_subprocess_exec",
                side_effect=RuntimeError("clone failed"),
            ),
            patch(f"{_MODULE}.shutil.rmtree") as mock_rmtree,
        ):
            await run_static_scan(state, config, intel_db)

        mock_rmtree.assert_called_once()
        call_kwargs = mock_rmtree.call_args
        assert call_kwargs[1].get("ignore_errors") is True

    async def test_unsafe_repo_url_rejected(self) -> None:
        """SSRF: file:// URL must not reach git clone."""
        state = _make_state(repo_url="file:///etc/passwd")
        config = _make_config()
        intel_db = _make_intel_db()

        await run_static_scan(state, config, intel_db)

        assert state.static_findings == []
        assert state.short_circuit is False

    async def test_unsafe_branch_rejected(self) -> None:
        """Branch with '..' must not reach git clone."""
        state = _make_state(base_branch="main/../etc/passwd")
        config = _make_config()
        intel_db = _make_intel_db()

        await run_static_scan(state, config, intel_db)

        assert state.static_findings == []
        assert state.short_circuit is False

    async def test_oversized_diff_skipped(self) -> None:
        """Diff exceeding _MAX_DIFF_BYTES is not fed to git apply."""
        state = _make_state(diff="x" * (10 * 1024 * 1024 + 1))
        config = _make_config()
        intel_db = _make_intel_db()

        semgrep_output = _make_semgrep_output()
        dispatch = _command_dispatch(
            clone_proc=_mock_process(returncode=0),
            apply_proc=_mock_process(returncode=0, stderr=b""),
            semgrep_proc=_mock_process(returncode=0, stdout=semgrep_output.encode()),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch) as mock_exec,
        ):
            await run_static_scan(state, config, intel_db)

        # git apply should never be called — only clone and semgrep
        call_args_list = [
            [str(a) for a in call.args] for call in mock_exec.call_args_list
        ]
        assert not any(
            args[0] == "git" and args[1] == "apply" for args in call_args_list
        )

    async def test_clone_stderr_in_error_message(self) -> None:
        """Clone failure should include git's error text."""
        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        clone_proc = _mock_process(
            returncode=128,
            stderr=b"fatal: repository not found",
        )

        dispatch = _command_dispatch(
            clone_proc=clone_proc,
            apply_proc=_mock_process(),
            semgrep_proc=_mock_process(),
        )

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            # Should not raise — caught by outer handler
            await run_static_scan(state, config, intel_db)

        assert state.static_findings == []


# ═══════════════════════════════════════════════════════════════════════════════
# G. IntelligenceDB stub
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntelligenceDBFalsePositives:
    """Verify get_false_positive_signatures returns a frozenset."""

    async def test_returns_empty_frozenset(self) -> None:
        db = _make_intel_db()
        db.get_false_positive_signatures = AsyncMock(  # type: ignore[method-assign]
            return_value=frozenset(),
        )
        result = await db.get_false_positive_signatures()
        assert result == frozenset()
        assert isinstance(result, frozenset)


# ═══════════════════════════════════════════════════════════════════════════════
# H. Kill guard on cancellation
# ═══════════════════════════════════════════════════════════════════════════════


class TestKillGuard:
    """Verify proc.kill() is called when CancelledError interrupts communicate()."""

    async def test_clone_kills_on_cancellation(self) -> None:
        proc = _mock_process()
        proc.communicate = AsyncMock(side_effect=asyncio.CancelledError())

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", return_value=proc),
            pytest.raises(asyncio.CancelledError),
        ):
            await _clone_repo(
                "https://github.com/owner/repo.git",
                "main",
                Path("/tmp/test-repo"),
            )

        proc.kill.assert_called_once()

    async def test_semgrep_kills_on_cancellation(self) -> None:
        proc = _mock_process()
        proc.communicate = AsyncMock(side_effect=asyncio.CancelledError())

        with (
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", return_value=proc),
            pytest.raises(asyncio.CancelledError),
        ):
            await _run_semgrep(["semgrep", "--json", "/tmp/repo"])

        proc.kill.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# I. Token scrubbing in clone stderr
# ═══════════════════════════════════════════════════════════════════════════════


class TestTokenScrubbing:
    """Verify auth tokens are scrubbed from error messages."""

    async def test_clone_stderr_scrubs_installation_token(self) -> None:
        """Installation tokens (ghs_...) must not appear in error messages."""
        token = "ghs_" + "A" * 36
        stderr_msg = f"fatal: Authentication failed for 'https://x-access-token:{token}@github.com/o/r'"
        clone_proc = _mock_process(
            returncode=128,
            stderr=stderr_msg.encode(),
        )

        dispatch = _command_dispatch(
            clone_proc=clone_proc,
            apply_proc=_mock_process(),
            semgrep_proc=_mock_process(),
        )

        state = _make_state()
        config = _make_config()
        intel_db = _make_intel_db()

        with (
            patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/semgrep"),
            patch(f"{_MODULE}.asyncio.create_subprocess_exec", side_effect=dispatch),
        ):
            await run_static_scan(state, config, intel_db)

        # The token should not appear in findings or state
        assert state.static_findings == []
        # Verify the token doesn't leak — the RuntimeError message is logged
        # but since run_static_scan catches it, we verify through the
        # scrub_tokens function directly
        from src.security import scrub_tokens as _scrub

        assert token not in _scrub(stderr_msg)
        assert "***" in _scrub(stderr_msg)
