"""Bounty issuer — creates GitHub issues with bounty labels for patrol findings.

Composes TreasuryManager's ``check_balance``, ``get_budget_allocation``, and
``get_bounty_amount_wei`` to verify budget before issuing.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.config import PatrolConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.models.patrol import DependencyFinding, PatrolFinding
    from src.treasury.manager import TreasuryManager

logger = logging.getLogger(__name__)

_DEP_ISSUE_BODY = """\
## Security Vulnerability — Dependency

**Package**: `{package_name}` (`{language}`)
**Current version**: `{current_version}`
**Vulnerable range**: `{vulnerable_range}`
**Severity**: {severity}
{cve_line}
{fixed_line}
{advisory_line}

### Remediation

{remediation}

---
*This issue was automatically created by SaltaX Patrol.*
{budget_note}
"""

_CODE_ISSUE_BODY = """\
## Security Finding — Codebase Scan

**Rule**: `{rule_id}`
**File**: `{file_path}:{line_start}`
**Severity**: {severity}

### Description

{message}

---
*This issue was automatically created by SaltaX Patrol.*
{budget_note}
"""


class BountyIssuer:
    """Creates bounty-backed GitHub issues for patrol findings."""

    def __init__(
        self,
        config: PatrolConfig,
        github_client: GitHubClient,
        treasury_manager: TreasuryManager,
        intel_db: IntelligenceDB,
    ) -> None:
        self._config = config
        self._github = github_client
        self._treasury = treasury_manager
        self._db = intel_db

    async def create_bounty_for_dependency(
        self,
        repo: str,
        finding: DependencyFinding,
        installation_id: int,
    ) -> int | None:
        """Create a bounty issue for a dependency vulnerability.

        Returns issue number on success, or ``None`` if skipped.
        """
        severity_key = finding.severity.value
        label = self._config.bounty_assignment.severity_to_label.get(severity_key)
        if label is None:
            logger.info(
                "No bounty label for severity %s, skipping",
                severity_key,
            )
            return None

        # Dedup: check existing open bounty using dedup_key (handles NULL cve_id)
        from src.intelligence.database import IntelligenceDB  # noqa: PLC0415

        dedup_key = IntelligenceDB.compute_dedup_key(
            finding.cve_id, finding.package_name,
            finding.language, finding.vulnerable_range,
        )
        existing = await self._db.get_known_vulnerability(repo, dedup_key)
        if (
            existing
            and existing.get("bounty_issue_number")
            and existing.get("status") == "open"
        ):
            logger.info(
                "Existing open bounty for %s in %s, skipping",
                dedup_key, repo,
            )
            return None

        # Budget + capacity checks
        can_issue, snapshot = await self._check_budget_and_capacity(repo, label)
        if not can_issue:
            return None

        # Build issue body
        cve_line = (
            f"**CVE**: [{finding.cve_id}]"
            f"(https://nvd.nist.gov/vuln/detail/{finding.cve_id})"
            if finding.cve_id else ""
        )
        fixed_line = (
            f"**Fixed version**: `{finding.fixed_version}`"
            if finding.fixed_version
            else "**Fixed version**: No known fix"
        )
        advisory_line = (
            f"**Advisory**: {finding.advisory_url}"
            if finding.advisory_url else ""
        )
        remediation = (
            f"Upgrade `{finding.package_name}` to version `{finding.fixed_version}` or later."
            if finding.fixed_version
            else "No automated fix available. Manual investigation required."
        )

        budget_note = await self._budget_note(label, snapshot)

        body = _DEP_ISSUE_BODY.format(
            package_name=finding.package_name,
            language=finding.language,
            current_version=finding.current_version,
            vulnerable_range=finding.vulnerable_range,
            severity=finding.severity.value,
            cve_line=cve_line,
            fixed_line=fixed_line,
            advisory_line=advisory_line,
            remediation=remediation,
            budget_note=budget_note,
        )

        title = f"[Security] {finding.package_name}: {finding.cve_id or 'vulnerability detected'}"
        return await self._create_and_record(
            repo, installation_id, title, body, label,
            finding.cve_id, dedup_key, finding.package_name, finding.language,
            finding.severity.value, finding.vulnerable_range,
            finding.fixed_version, finding.advisory_url,
        )

    async def create_bounty_for_code(
        self,
        repo: str,
        finding: PatrolFinding,
        installation_id: int,
    ) -> int | None:
        """Create a bounty issue for a codebase scan finding.

        Returns issue number on success, or ``None`` if skipped.
        """
        severity_key = finding.severity.value
        label = self._config.bounty_assignment.severity_to_label.get(severity_key)
        if label is None:
            logger.info("No bounty label for severity %s, skipping", severity_key)
            return None

        # Dedup: check if we already created a bounty for this finding (Fix 13)
        existing_bounty = await self._db.get_code_finding_bounty(
            repo, finding.rule_id, finding.file_path, finding.line_start,
        )
        if existing_bounty is not None:
            logger.info(
                "Existing bounty #%d for %s at %s:%d, skipping",
                existing_bounty, finding.rule_id,
                finding.file_path, finding.line_start,
            )
            return None

        can_issue, snapshot = await self._check_budget_and_capacity(repo, label)
        if not can_issue:
            return None

        budget_note = await self._budget_note(label, snapshot)

        body = _CODE_ISSUE_BODY.format(
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            line_start=finding.line_start,
            severity=finding.severity.value,
            message=finding.message,
            budget_note=budget_note,
        )

        title = f"[Security] {finding.rule_id}: {finding.file_path}:{finding.line_start}"
        issue_data = await self._github.create_issue(
            repo,
            installation_id,
            title=title,
            body=body,
            labels=[label],
        )
        issue_number = int(issue_data["number"])

        bounty_id = uuid.uuid4().hex[:16]
        await self._db.store_bounty(
            bounty_id=bounty_id,
            repo=repo,
            issue_number=issue_number,
            label=label,
            source="patrol",
        )

        # Record bounty link in finding signatures
        await self._db.set_finding_bounty(
            repo, finding.rule_id, finding.file_path,
            finding.line_start, issue_number,
        )

        logger.info(
            "Created bounty issue #%d for %s in %s",
            issue_number, finding.rule_id, repo,
        )
        return issue_number

    # ── Helpers ───────────────────────────────────────────────────────────

    async def _check_budget_and_capacity(
        self, repo: str, label: str,
    ) -> tuple[bool, object]:
        """Verify budget availability and open-bounty capacity.

        Returns ``(can_issue, snapshot)`` where *snapshot* can be reused
        by ``_budget_note`` to avoid a redundant ``check_balance()`` call.
        """
        # Check max bounties per repo
        open_count = await self._db.count_open_patrol_bounties(repo)
        max_bounties = self._config.bounty_assignment.max_open_bounties_per_repo
        if open_count >= max_bounties:
            logger.info(
                "Max open patrol bounties (%d) reached for %s",
                max_bounties, repo,
            )
            return False, None

        # Check treasury budget
        bounty_wei = self._treasury.get_bounty_amount_wei(label)
        if bounty_wei is None:
            logger.info("Unknown bounty label %s, skipping", label)
            return False, None

        snapshot = await self._treasury.check_balance()
        allocation = self._treasury.get_budget_allocation(snapshot.balance_wei)
        if bounty_wei > allocation["bounty"]:
            logger.info(
                "Insufficient bounty budget for label %s (need %s, have %s)",
                label, bounty_wei, allocation["bounty"],
            )
            return False, snapshot

        return True, snapshot

    async def _budget_note(self, label: str, snapshot: object = None) -> str:
        """Generate a budget note for the issue body.

        Accepts an optional *snapshot* to avoid a redundant balance check.
        """
        bounty_wei = self._treasury.get_bounty_amount_wei(label)
        if bounty_wei is None:
            return ""
        try:
            if snapshot is None:
                snapshot = await self._treasury.check_balance()
            allocation = self._treasury.get_budget_allocation(snapshot.balance_wei)
            if bounty_wei > allocation["bounty"]:
                return "\n> **Note**: Bounty pending treasury funding."
        except Exception:
            pass
        return ""

    async def _create_and_record(
        self,
        repo: str,
        installation_id: int,
        title: str,
        body: str,
        label: str,
        cve_id: str | None,
        dedup_key: str,
        package_name: str,
        language: str,
        severity: str,
        affected_range: str,
        fixed_version: str | None,
        advisory_url: str | None,
    ) -> int | None:
        """Create GitHub issue, store bounty, and upsert vulnerability record."""
        issue_data = await self._github.create_issue(
            repo,
            installation_id,
            title=title,
            body=body,
            labels=[label],
        )
        issue_number = int(issue_data["number"])

        bounty_id = uuid.uuid4().hex[:16]
        await self._db.store_bounty(
            bounty_id=bounty_id,
            repo=repo,
            issue_number=issue_number,
            label=label,
            source="patrol",
        )

        # Deterministic vuln_id from dedup_key (Fix 14)
        vuln_id = hashlib.sha256(f"{repo}:{dedup_key}".encode()).hexdigest()[:16]
        await self._db.upsert_known_vulnerability(
            vuln_id=vuln_id,
            cve_id=cve_id,
            dedup_key=dedup_key,
            package_name=package_name,
            language=language,
            severity=severity,
            affected_range=affected_range,
            fixed_version=fixed_version,
            advisory_url=advisory_url,
            repo=repo,
            status="open",
            bounty_issue_number=issue_number,
        )

        logger.info(
            "Created bounty issue #%d for %s in %s",
            issue_number, dedup_key, repo,
        )
        return issue_number
