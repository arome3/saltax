"""Tests for the bounty issuer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.config import BountyAssignmentConfig, PatrolConfig
from src.models.enums import Severity
from src.models.patrol import DependencyFinding, PatrolFinding
from src.patrol.bounty_issuer import BountyIssuer

_ = pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_dep_finding(
    severity: Severity = Severity.HIGH,
    cve_id: str | None = "CVE-2023-32681",
) -> DependencyFinding:
    return DependencyFinding(
        package_name="requests",
        current_version="2.25.0",
        vulnerable_range="<2.31.0",
        cve_id=cve_id,
        severity=severity,
        advisory_url="https://example.com",
        fixed_version="2.31.0",
        is_direct=True,
        language="python",
    )


def _make_code_finding(severity: Severity = Severity.HIGH) -> PatrolFinding:
    return PatrolFinding(
        rule_id="sql-injection",
        file_path="src/app.py",
        line_start=42,
        line_end=42,
        severity=severity,
        message="SQL injection detected",
    )


def _make_issuer(
    *,
    max_bounties: int = 10,
    balance_wei: int = 10**18,
    bounty_wei: int | None = 10**16,
) -> tuple[BountyIssuer, dict[str, AsyncMock]]:
    config = PatrolConfig(
        bounty_assignment=BountyAssignmentConfig(
            max_open_bounties_per_repo=max_bounties,
        ),
    )
    github = AsyncMock()
    github.create_issue = AsyncMock(return_value={"number": 123})

    treasury = MagicMock()
    treasury.get_bounty_amount_wei = MagicMock(return_value=bounty_wei)
    treasury.check_balance = AsyncMock(
        return_value=MagicMock(balance_wei=balance_wei),
    )
    treasury.get_budget_allocation = MagicMock(
        return_value={"bounty": balance_wei},
    )

    intel_db = AsyncMock()
    intel_db.count_open_patrol_bounties = AsyncMock(return_value=0)
    intel_db.get_known_vulnerability = AsyncMock(return_value=None)
    intel_db.store_bounty = AsyncMock()
    intel_db.upsert_known_vulnerability = AsyncMock()
    intel_db.get_code_finding_bounty = AsyncMock(return_value=None)
    intel_db.set_finding_bounty = AsyncMock()

    issuer = BountyIssuer(config, github, treasury, intel_db)
    mocks = {"github": github, "treasury": treasury, "intel_db": intel_db}
    return issuer, mocks


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestBountyIssuer:
    async def test_budget_insufficient(self) -> None:
        """bounty_wei > allocation -> None."""
        issuer, mocks = _make_issuer(balance_wei=100, bounty_wei=10**16)
        mocks["treasury"].get_budget_allocation = MagicMock(
            return_value={"bounty": 10},
        )
        result = await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        assert result is None

    async def test_max_bounties_reached(self) -> None:
        """count >= max -> None."""
        issuer, mocks = _make_issuer(max_bounties=5)
        mocks["intel_db"].count_open_patrol_bounties = AsyncMock(return_value=5)
        result = await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        assert result is None

    async def test_duplicate_open_issue(self) -> None:
        """Known vuln with open bounty_issue_number -> None."""
        issuer, mocks = _make_issuer()
        mocks["intel_db"].get_known_vulnerability = AsyncMock(
            return_value={
                "bounty_issue_number": 100,
                "status": "open",
            },
        )
        result = await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        assert result is None

    async def test_closed_duplicate_creates_new(self) -> None:
        """Existing closed vuln -> creates new issue."""
        issuer, mocks = _make_issuer()
        mocks["intel_db"].get_known_vulnerability = AsyncMock(
            return_value={
                "bounty_issue_number": 100,
                "status": "closed",
            },
        )
        result = await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        assert result == 123

    async def test_successful_creation(self) -> None:
        """Full happy path -> issue number."""
        issuer, mocks = _make_issuer()
        result = await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        assert result == 123
        mocks["github"].create_issue.assert_awaited_once()
        mocks["intel_db"].store_bounty.assert_awaited_once()

    async def test_stores_bounty_with_patrol_source(self) -> None:
        """store_bounty called with source='patrol'."""
        issuer, mocks = _make_issuer()
        await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        call_kwargs = mocks["intel_db"].store_bounty.call_args.kwargs
        assert call_kwargs["source"] == "patrol"

    async def test_unknown_severity_label(self) -> None:
        """Severity not in mapping -> None."""
        issuer, _ = _make_issuer()
        finding = _make_dep_finding(severity=Severity.INFO)
        result = await issuer.create_bounty_for_dependency(
            "owner/repo", finding, 42,
        )
        assert result is None

    async def test_issue_body_format_dependency(self) -> None:
        """Body contains CVE, package, severity."""
        issuer, mocks = _make_issuer()
        await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        call_kwargs = mocks["github"].create_issue.call_args.kwargs
        body = call_kwargs["body"]
        assert "CVE-2023-32681" in body
        assert "requests" in body
        assert "HIGH" in body

    async def test_issue_body_format_code(self) -> None:
        """Body contains rule_id, file_path."""
        issuer, mocks = _make_issuer()
        result = await issuer.create_bounty_for_code(
            "owner/repo", _make_code_finding(), 42,
        )
        assert result == 123
        call_kwargs = mocks["github"].create_issue.call_args.kwargs
        body = call_kwargs["body"]
        assert "sql-injection" in body
        assert "src/app.py" in body

    async def test_upsert_called_on_success(self) -> None:
        """upsert_known_vulnerability called with correct dedup_key and issue number (T5)."""
        issuer, mocks = _make_issuer()
        await issuer.create_bounty_for_dependency(
            "owner/repo", _make_dep_finding(), 42,
        )
        mocks["intel_db"].upsert_known_vulnerability.assert_awaited_once()
        call_kwargs = mocks["intel_db"].upsert_known_vulnerability.call_args.kwargs
        assert call_kwargs["cve_id"] == "CVE-2023-32681"
        assert call_kwargs["bounty_issue_number"] == 123
        # dedup_key should be the cve_id since it's not None
        assert call_kwargs["dedup_key"] == "CVE-2023-32681"

    async def test_upsert_called_for_null_cve(self) -> None:
        """Null cve_id -> upsert still called with composite dedup_key (T5)."""
        issuer, mocks = _make_issuer()
        finding = _make_dep_finding(cve_id=None)
        await issuer.create_bounty_for_dependency(
            "owner/repo", finding, 42,
        )
        mocks["intel_db"].upsert_known_vulnerability.assert_awaited_once()
        call_kwargs = mocks["intel_db"].upsert_known_vulnerability.call_args.kwargs
        assert call_kwargs["cve_id"] is None
        # Composite dedup_key: package_name:language:vulnerable_range
        assert "requests" in call_kwargs["dedup_key"]
        assert "python" in call_kwargs["dedup_key"]

    async def test_create_bounty_for_code_dedup(self) -> None:
        """Existing code finding bounty -> returns None (T6)."""
        issuer, mocks = _make_issuer()
        mocks["intel_db"].get_code_finding_bounty = AsyncMock(return_value=99)
        result = await issuer.create_bounty_for_code(
            "owner/repo", _make_code_finding(), 42,
        )
        assert result is None
        mocks["github"].create_issue.assert_not_awaited()

    async def test_create_bounty_for_code_records_finding(self) -> None:
        """set_finding_bounty called after code bounty creation (T6)."""
        issuer, mocks = _make_issuer()
        await issuer.create_bounty_for_code(
            "owner/repo", _make_code_finding(), 42,
        )
        mocks["intel_db"].set_finding_bounty.assert_awaited_once()
        call_kwargs = mocks["intel_db"].set_finding_bounty.call_args
        assert call_kwargs[0][3] == 42  # line_start
        assert call_kwargs[0][4] == 123  # issue_number
