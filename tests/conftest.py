"""Shared pytest fixtures for SaltaX tests."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.config import EnvConfig, SaltaXConfig
from src.intelligence.database import IntelligenceDB

# ---------------------------------------------------------------------------
# Valid YAML content matching the production saltax.config.yaml structure
# ---------------------------------------------------------------------------
VALID_YAML = textwrap.dedent("""\
    version: "1.0"
    agent:
      name: "SaltaX"
      description: "Sovereign Code Organism"
      repo: ""

    pipeline:
      approval_threshold: 0.75
      self_modification_threshold: 0.90
      review_threshold: 0.50
      stages:
        static_scanner:
          enabled: true
          timeout_seconds: 120
          rulesets: ["p/security-audit", "p/owasp-top-ten"]
        ai_analyzer:
          enabled: true
          model: "gpt-oss-120b-f16"
          timeout_seconds: 60
          semaphore_timeout_seconds: 30
        test_executor:
          enabled: true
          timeout_seconds: 300
          memory_limit_mb: 512
        decision_engine:
          weights:
            static_clear: 0.25
            ai_quality: 0.25
            ai_security: 0.25
            tests_pass: 0.25

    treasury:
      reserve_ratio: 0.20
      compute_budget: 0.10
      bounty_budget: 0.65
      community_fund: 0.05
      max_single_payout_eth: 0.5

    bounties:
      labels:
        "bounty-xs": 0.01
        "bounty-sm": 0.05
        "bounty-md": 0.10
        "bounty-lg": 0.25
        "bounty-xl": 0.50

    optimistic_verification:
      standard_window_hours: 24
      self_modification_window_hours: 72
      min_challenge_stake_multiplier: 1.0

    staking:
      enabled: true
      contract_address: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
      bonus_rate_no_challenge: 0.10
      bonus_rate_challenged_upheld: 0.20
      slash_rate_challenged_overturned: 0.50

    disputes:
      enabled: true
      eigenverify_deadline_hours: 24
      moltcourt_deadline_hours: 72
      poll_interval_seconds: 300
      max_submission_retries: 3
      circuit_breaker_failure_threshold: 5
      circuit_breaker_reset_seconds: 300

    audit_pricing:
      security_only_usdc: 5
      quality_only_usdc: 3
      full_audit_usdc: 10

    triage:
      enabled: false
      mode: "autonomous"
      dedup:
        enabled: true
        similarity_threshold: 0.85
        embedding_model: "text-embedding"
      issue_dedup:
        enabled: true
        similarity_threshold: 0.90
        embedding_model: "text-embedding"
        max_candidates: 500
        apply_label: false
        label_name: "duplicate-candidate"
      ranking:
        enabled: true
        label_superseded: "superseded"
        label_recommended: "saltax-recommended"
        update_interval_seconds: 3600
      vision:
        enabled: false
        alignment_weight: 0.15
        source: "repo"
      advisory:
        review_type: "COMMENT"
        label_recommends_merge: "saltax-recommends-merge"
        label_recommends_reject: "saltax-recommends-reject"

    backfill:
      per_page: 100
      page_delay_seconds: 1.0
      concurrency: 3
      max_failures_before_abort: 50
      rate_limit_max_wait_seconds: 3600
      default_mode: "full"

    patrol:
      enabled: false
      interval_seconds: 21600
      max_concurrent_repos: 3
      dependency_audit:
        enabled: true
        severity_threshold: "HIGH"
        auto_patch: true
        bounty_for_breaking: true
      codebase_scan:
        enabled: true
        semgrep_config: "auto"
        rescan_interval_hours: 168
      bounty_assignment:
        enabled: true
        severity_to_label:
          CRITICAL: "bounty-xl"
          HIGH: "bounty-lg"
          MEDIUM: "bounty-md"
          LOW: "bounty-sm"
        max_open_bounties_per_repo: 10
""")

# ---------------------------------------------------------------------------
# Required environment variable values
# ---------------------------------------------------------------------------
REQUIRED_ENV_VARS: dict[str, str] = {
    "SALTAX_GITHUB_APP_ID": "999",
    "SALTAX_GITHUB_APP_PRIVATE_KEY": "base64-test-pem",
    "SALTAX_GITHUB_WEBHOOK_SECRET": "whsec_test",
    "SALTAX_EIGENCLOUD_KMS_ENDPOINT": "https://kms.test.local",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_config_yaml(tmp_path: Path) -> Path:
    """Write a valid ``saltax.config.yaml`` to *tmp_path* and return the path."""
    cfg_file = tmp_path / "saltax.config.yaml"
    cfg_file.write_text(VALID_YAML)
    return cfg_file


@pytest.fixture()
def valid_env_vars(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Set all required SALTAX_* environment variables and return them."""
    for key, value in REQUIRED_ENV_VARS.items():
        monkeypatch.setenv(key, value)
    return dict(REQUIRED_ENV_VARS)


@pytest.fixture()
def sample_config(valid_config_yaml: Path) -> SaltaXConfig:
    """Return a fully loaded and validated ``SaltaXConfig``."""
    return SaltaXConfig.load(valid_config_yaml)


@pytest.fixture()
def sample_env(valid_env_vars: dict[str, str]) -> EnvConfig:
    """Return a loaded ``EnvConfig`` from the monkeypatched environment."""
    return EnvConfig(_env_file=None)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Shared fixtures — available to all test files (Doc 27)
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
async def mock_intel_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IntelligenceDB:
    """Real IntelligenceDB on ``tmp_path`` with mocked KMS and full production schema.

    Named ``mock_intel_db`` (not ``intel_db``) to avoid shadowing per-file
    fixtures in existing tests.
    """
    monkeypatch.setattr("src.intelligence.database.DB_PATH", tmp_path / "test.db")
    kms = AsyncMock()
    kms.unseal = AsyncMock(side_effect=Exception("no sealed data"))
    db = IntelligenceDB(kms=kms)
    try:
        await db.initialize()
        yield db  # type: ignore[misc]
    finally:
        await db.close()


@pytest.fixture()
def mock_github_client() -> AsyncMock:
    """Pre-configured ``AsyncMock`` mimicking ``GitHubClient`` methods."""
    client = AsyncMock()
    client.get_pr_diff = AsyncMock(
        return_value="diff --git a/f.py b/f.py\n+pass",
    )
    client.list_issue_comments = AsyncMock(return_value=[])
    client.post_pr_comment = AsyncMock(return_value=None)
    client.create_comment = AsyncMock(return_value=None)
    client.merge_pr = AsyncMock(return_value={"merged": True})
    client.add_labels = AsyncMock(return_value=None)
    return client


@pytest.fixture()
def sample_pr_diff() -> str:
    """Clean single-file bugfix diff — no security issues."""
    return (_FIXTURES_DIR / "sample_prs" / "clean_bugfix.diff").read_text()


@pytest.fixture()
def sample_malicious_diff() -> str:
    """Diff containing SQL injection and a hardcoded secret."""
    return (_FIXTURES_DIR / "sample_prs" / "sql_injection.diff").read_text()
