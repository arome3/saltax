"""Dependency auditor — runs pip-audit, npm audit, cargo audit.

Parses structured JSON output from each tool and normalises findings
into ``DependencyFinding`` objects.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from contextlib import suppress
from typing import TYPE_CHECKING

from src.models.enums import Severity
from src.models.patrol import DependencyFinding

if TYPE_CHECKING:
    from pathlib import Path

    from src.config import DependencyAuditConfig
    from src.patrol.osv_client import OSVClient

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 120  # seconds

# npm severity → Severity enum
_NPM_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class DependencyAuditor:
    """Runs language-specific dependency audit tools and collects findings."""

    def __init__(
        self,
        config: DependencyAuditConfig,
        osv_client: OSVClient | None = None,
    ) -> None:
        self._config = config
        self._osv = osv_client

    async def audit(self, repo_path: Path, language: str) -> list[DependencyFinding]:
        """Run the appropriate audit tool for *language*.

        Returns an empty list if the tool is unavailable or produces no output.
        Enriches severity via OSV when available and filters by threshold.
        """
        if language == "python":
            findings = await self._audit_pip(repo_path)
        elif language == "node":
            findings = await self._audit_npm(repo_path)
        elif language == "rust":
            findings = await self._audit_cargo(repo_path)
        else:
            logger.warning("Unsupported language for dependency audit: %s", language)
            return []

        findings = await self._enrich_severity(findings)
        return self._filter_by_threshold(findings)

    # ── pip-audit ─────────────────────────────────────────────────────────

    async def _audit_pip(self, repo_path: Path) -> list[DependencyFinding]:
        cmd = ["pip-audit", "--format=json", "--output=-"]
        stdout, rc = await self._run_tool(cmd, repo_path, "pip-audit")
        if stdout is None:
            return []

        # Exit 2+ = tool error; 0/1 both contain valid JSON
        if rc is not None and rc >= 2:
            logger.error("pip-audit exited with error code %d", rc)
            return []
        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("pip-audit returned invalid JSON")
            return []

        # pip-audit JSON is a bare array of dependency objects
        if not isinstance(data, list):
            data = data.get("dependencies", [])

        findings: list[DependencyFinding] = []
        for dep in data:
            pkg_name = dep.get("name", "")
            version = dep.get("version", "")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "")
                aliases = vuln.get("aliases", [])
                cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                fix_versions = vuln.get("fix_versions", [])
                fixed = fix_versions[0] if fix_versions else None
                findings.append(DependencyFinding(
                    package_name=pkg_name,
                    current_version=version,
                    vulnerable_range=vuln_id,
                    cve_id=cve if cve else None,
                    severity=Severity.MEDIUM,  # pip-audit doesn't provide severity text
                    advisory_url=f"https://osv.dev/vulnerability/{vuln_id}",
                    fixed_version=fixed,
                    is_direct=True,
                    language="python",
                ))
        return findings

    # ── npm audit ─────────────────────────────────────────────────────────

    async def _audit_npm(self, repo_path: Path) -> list[DependencyFinding]:
        cmd = ["npm", "audit", "--json"]
        stdout, rc = await self._run_tool(cmd, repo_path, "npm")
        if stdout is None:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("npm audit returned invalid JSON")
            return []

        vulns_dict = data.get("vulnerabilities", {})
        findings: list[DependencyFinding] = []
        for pkg_name, info in vulns_dict.items():
            severity_str = info.get("severity", "moderate")
            severity = _NPM_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            is_direct = info.get("isDirect", False)

            # via can be list of dicts (advisory) or strings (transitive ref)
            for via_item in info.get("via", []):
                if not isinstance(via_item, dict):
                    continue  # skip transitive string references
                vuln_url = via_item.get("url", "")
                cve = via_item.get("cve") or None
                vuln_range = via_item.get("range", "*")
                findings.append(DependencyFinding(
                    package_name=pkg_name,
                    current_version=info.get("version", ""),
                    vulnerable_range=vuln_range,
                    cve_id=cve,
                    severity=severity,
                    advisory_url=vuln_url,
                    fixed_version=self._extract_npm_fix(info),
                    is_direct=is_direct,
                    language="node",
                ))
        return findings

    @staticmethod
    def _extract_npm_fix(info: dict) -> str | None:
        """Extract fixed version from npm's ``fixAvailable`` field.

        ``fixAvailable`` can be a bool or an object with ``version``.
        """
        fix = info.get("fixAvailable")
        if isinstance(fix, dict):
            return fix.get("version")
        return None

    # ── cargo audit ───────────────────────────────────────────────────────

    async def _audit_cargo(self, repo_path: Path) -> list[DependencyFinding]:
        cmd = ["cargo", "audit", "--json"]
        stdout, rc = await self._run_tool(cmd, repo_path, "cargo")
        if stdout is None:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("cargo audit returned invalid JSON")
            return []

        vuln_list = data.get("vulnerabilities", {}).get("list", [])
        findings: list[DependencyFinding] = []
        for entry in vuln_list:
            advisory = entry.get("advisory", {})
            package = entry.get("package", {})
            versions = entry.get("versions", {})
            patched = versions.get("patched", [])

            vuln_id = advisory.get("id", "")
            aliases = advisory.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), None)

            findings.append(DependencyFinding(
                package_name=package.get("name", ""),
                current_version=package.get("version", ""),
                vulnerable_range=vuln_id,
                cve_id=cve,
                severity=Severity.MEDIUM,  # derive from CVSS if available
                advisory_url=advisory.get("url", ""),
                fixed_version=patched[0] if patched else None,
                is_direct=True,
                language="rust",
            ))
        return findings

    # ── Severity enrichment ──────────────────────────────────────────────

    async def _enrich_severity(
        self, findings: list[DependencyFinding],
    ) -> list[DependencyFinding]:
        """Enrich MEDIUM-severity findings via OSV when the client is available."""
        if self._osv is None:
            return findings
        enriched: list[DependencyFinding] = []
        for f in findings:
            # MEDIUM is the default when tool doesn't provide severity — enrich it
            if f.severity == Severity.MEDIUM and f.cve_id:
                vuln_data = await self._osv.get_vulnerability(f.cve_id)
                if vuln_data:
                    severity = self._parse_osv_severity(vuln_data)
                    if severity != f.severity:
                        f = f.model_copy(update={"severity": severity})
            enriched.append(f)
        return enriched

    @staticmethod
    def _parse_osv_severity(vuln_data: dict) -> Severity:
        """Extract severity from an OSV vulnerability response.

        Checks ``database_specific.severity`` first, then CVSS vectors
        in the ``severity`` array.
        """
        # Check database_specific.severity (e.g. GitHub advisories)
        db_specific = vuln_data.get("database_specific", {})
        if isinstance(db_specific, dict):
            sev_str = db_specific.get("severity", "").upper()
            if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return Severity(sev_str)

        # Check severity array with CVSS vectors
        for entry in vuln_data.get("severity", []):
            if not isinstance(entry, dict):
                continue
            score_str = entry.get("score", "")
            # Extract base score from CVSS vector if present
            if "CVSS:" in score_str:
                # Parse CVSS base score — look for a numeric score
                # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
                pass
            # Try direct type mapping
            sev_type = entry.get("type", "").upper()
            if sev_type in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return Severity(sev_type)

        return Severity.MEDIUM  # default if parsing fails

    # Severity ordering for threshold filtering (higher index = more severe)
    _SEVERITY_ORDER: dict[Severity, int] = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    def _filter_by_threshold(
        self, findings: list[DependencyFinding],
    ) -> list[DependencyFinding]:
        """Filter findings below the configured severity threshold."""
        threshold_str = self._config.severity_threshold.upper()
        try:
            threshold = Severity(threshold_str)
        except ValueError:
            return findings  # invalid threshold → don't filter

        min_order = self._SEVERITY_ORDER.get(threshold, 0)
        return [
            f for f in findings
            if self._SEVERITY_ORDER.get(f.severity, 0) >= min_order
        ]

    # ── Subprocess helper ─────────────────────────────────────────────────

    async def _run_tool(
        self,
        cmd: list[str],
        cwd: Path,
        tool_name: str,
    ) -> tuple[str | None, int | None]:
        """Run a subprocess tool. Returns ``(stdout, returncode)`` or ``(None, None)``."""
        if shutil.which(cmd[0]) is None:
            logger.warning("%s not found, skipping %s audit", cmd[0], tool_name)
            return None, None

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_SUBPROCESS_TIMEOUT,
            )
        except TimeoutError:
            with suppress(ProcessLookupError):
                proc.kill()
            with suppress(BaseException):
                await proc.wait()
            logger.error("%s timed out for %s", tool_name, cwd)
            return None, None

        stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
        return stdout, proc.returncode
