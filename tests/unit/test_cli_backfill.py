"""Unit tests for the backfill CLI entry point (src/cli/backfill.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from src.backfill.engine import BackfillMode
from src.cli.backfill import main


def _make_config() -> MagicMock:
    """Minimal mock config returned by SaltaXConfig.load()."""
    cfg = MagicMock()
    cfg.backfill.default_mode = "embedding_only"
    cfg.backfill.concurrency = 3
    return cfg


# ── Tests ────────────────────────────────────────────────────────────────────


@patch("src.cli.backfill.SaltaXConfig.load", return_value=_make_config())
@patch("src.cli.backfill._run_backfill", new_callable=AsyncMock)
def test_cli_passes_repo_and_mode(mock_run, mock_load):
    """--repo and --mode are forwarded to _run_backfill."""
    mock_run.return_value = {"processed": 0, "failed": 0, "skipped": 0}

    runner = CliRunner()
    result = runner.invoke(main, ["--repo", "owner/repo", "--mode", "full"])

    assert result.exit_code == 0
    mock_run.assert_called_once()
    call_args = mock_run.call_args
    assert call_args[0][0] == "owner/repo"
    assert call_args[0][1] == BackfillMode.FULL


@patch("src.cli.backfill.SaltaXConfig.load", return_value=_make_config())
@patch("src.cli.backfill._run_backfill", new_callable=AsyncMock)
def test_cli_defaults_mode_from_config(mock_run, mock_load):
    """When --mode is omitted, uses config.backfill.default_mode."""
    mock_run.return_value = {"processed": 5, "failed": 0, "skipped": 1}

    runner = CliRunner()
    result = runner.invoke(main, ["--repo", "owner/repo"])

    assert result.exit_code == 0
    call_args = mock_run.call_args
    # Default from mock config is "embedding_only"
    assert call_args[0][1] == BackfillMode.EMBEDDING_ONLY


@patch("src.cli.backfill.SaltaXConfig.load", return_value=_make_config())
@patch("src.cli.backfill._run_backfill", new_callable=AsyncMock)
def test_cli_exit_code_zero_on_success(mock_run, mock_load):
    """Exit code is 0 when no failures."""
    mock_run.return_value = {"processed": 10, "failed": 0, "skipped": 2}

    runner = CliRunner()
    result = runner.invoke(main, ["--repo", "owner/repo"])

    assert result.exit_code == 0
    assert "processed=10" in result.output


@patch("src.cli.backfill.SaltaXConfig.load", return_value=_make_config())
@patch("src.cli.backfill._run_backfill", new_callable=AsyncMock)
def test_cli_exit_code_one_on_failures(mock_run, mock_load):
    """Exit code is 1 when there are failures."""
    mock_run.return_value = {"processed": 8, "failed": 3, "skipped": 0}

    runner = CliRunner()
    result = runner.invoke(main, ["--repo", "owner/repo"])

    assert result.exit_code == 1
    assert "failed=3" in result.output


@patch("src.cli.backfill.SaltaXConfig.load", return_value=_make_config())
@patch("src.cli.backfill._run_backfill", new_callable=AsyncMock)
def test_no_resume_flag_passed_through(mock_run, mock_load):
    """--no-resume flag is forwarded as True to _run_backfill."""
    mock_run.return_value = {"processed": 0, "failed": 0, "skipped": 0}

    runner = CliRunner()
    result = runner.invoke(main, ["--repo", "owner/repo", "--no-resume"])

    assert result.exit_code == 0
    call_args = mock_run.call_args
    # no_resume is the 5th positional arg
    assert call_args[0][4] is True
