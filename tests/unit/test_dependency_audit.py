"""Tests for the dependency auditor."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import DependencyAuditConfig
from src.patrol.dependency_audit import DependencyAuditor

_ = pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def auditor() -> DependencyAuditor:
    # Use LOW threshold so existing tests pass (no filtering)
    config = DependencyAuditConfig(severity_threshold="LOW")
    return DependencyAuditor(config)


def _make_process(stdout: bytes = b"", returncode: int = 0) -> AsyncMock:
    """Build a mock subprocess process."""
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    proc.returncode = returncode
    proc.kill = MagicMock()
    proc.wait = AsyncMock()
    return proc


# ── pip-audit tests ───────────────────────────────────────────────────────────


class TestPipAudit:
    async def test_pip_audit_not_installed(self, auditor, tmp_path) -> None:
        """shutil.which returns None -> returns []."""
        with patch("shutil.which", return_value=None):
            result = await auditor.audit(tmp_path, "python")
        assert result == []

    async def test_pip_audit_clean(self, auditor, tmp_path) -> None:
        """Exit 0 with empty deps array -> returns [] (no vulns in JSON)."""
        proc = _make_process(b"[]", 0)
        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch(
                "src.patrol.dependency_audit.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
        ):
            result = await auditor.audit(tmp_path, "python")
        assert result == []

    async def test_pip_audit_vulns_found(self, auditor, tmp_path) -> None:
        """Exit 1 with JSON -> parsed DependencyFinding list."""
        vuln_data = [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "PYSEC-2023-100",
                        "fix_versions": ["2.31.0"],
                        "aliases": ["CVE-2023-32681"],
                    }
                ],
            }
        ]
        proc = _make_process(json.dumps(vuln_data).encode(), 1)
        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch("src.patrol.dependency_audit.asyncio.create_subprocess_exec", return_value=proc),
        ):
            result = await auditor.audit(tmp_path, "python")
        assert len(result) == 1
        assert result[0].package_name == "requests"
        assert result[0].cve_id == "CVE-2023-32681"
        assert result[0].fixed_version == "2.31.0"
        assert result[0].language == "python"

    async def test_pip_audit_timeout(self, auditor, tmp_path) -> None:
        """TimeoutError -> proc.kill(), returns []."""
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)
        proc.kill = MagicMock()
        proc.wait = AsyncMock()

        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch("src.patrol.dependency_audit.asyncio.create_subprocess_exec", return_value=proc),
            patch("src.patrol.dependency_audit.asyncio.wait_for", side_effect=TimeoutError),
        ):
            result = await auditor.audit(tmp_path, "python")
        assert result == []

    async def test_pip_audit_crash(self, auditor, tmp_path) -> None:
        """Exit 2 -> returns []."""
        proc = _make_process(b"error output", 2)
        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch("src.patrol.dependency_audit.asyncio.create_subprocess_exec", return_value=proc),
        ):
            result = await auditor.audit(tmp_path, "python")
        assert result == []


# ── npm audit tests ───────────────────────────────────────────────────────────


class TestNpmAudit:
    async def test_npm_audit_vulns_found(self, auditor, tmp_path) -> None:
        """JSON parsed correctly with type-checking on via items."""
        npm_data = {
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "isDirect": True,
                    "version": "4.17.20",
                    "via": [
                        {
                            "url": "https://npmjs.com/advisories/1523",
                            "cve": "CVE-2021-23337",
                            "range": "<4.17.21",
                        }
                    ],
                    "fixAvailable": {"version": "4.17.21"},
                }
            }
        }
        proc = _make_process(json.dumps(npm_data).encode(), 1)
        with (
            patch("shutil.which", return_value="/usr/bin/npm"),
            patch("src.patrol.dependency_audit.asyncio.create_subprocess_exec", return_value=proc),
        ):
            result = await auditor.audit(tmp_path, "node")
        assert len(result) == 1
        assert result[0].package_name == "lodash"
        assert result[0].cve_id == "CVE-2021-23337"
        assert result[0].fixed_version == "4.17.21"
        assert result[0].language == "node"

    async def test_npm_audit_transitive_via_string(self, auditor, tmp_path) -> None:
        """via=[string] skipped, only dict entries parsed."""
        npm_data = {
            "vulnerabilities": {
                "nested-dep": {
                    "severity": "moderate",
                    "isDirect": False,
                    "version": "1.0.0",
                    "via": ["some-transitive-pkg"],
                    "fixAvailable": True,
                }
            }
        }
        proc = _make_process(json.dumps(npm_data).encode(), 1)
        with (
            patch("shutil.which", return_value="/usr/bin/npm"),
            patch("src.patrol.dependency_audit.asyncio.create_subprocess_exec", return_value=proc),
        ):
            result = await auditor.audit(tmp_path, "node")
        assert result == []


# ── cargo audit tests ─────────────────────────────────────────────────────────


class TestCargoAudit:
    async def test_cargo_audit_vulns_found(self, auditor, tmp_path) -> None:
        """JSON parsed from vulnerabilities.list."""
        cargo_data = {
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2023-0001",
                            "aliases": ["CVE-2023-99999"],
                            "url": "https://rustsec.org/advisories/RUSTSEC-2023-0001",
                        },
                        "package": {
                            "name": "serde",
                            "version": "1.0.0",
                        },
                        "versions": {
                            "patched": ["1.0.1"],
                        },
                    }
                ]
            }
        }
        proc = _make_process(json.dumps(cargo_data).encode(), 0)
        with (
            patch("shutil.which", return_value="/usr/bin/cargo"),
            patch("src.patrol.dependency_audit.asyncio.create_subprocess_exec", return_value=proc),
        ):
            result = await auditor.audit(tmp_path, "rust")
        assert len(result) == 1
        assert result[0].package_name == "serde"
        assert result[0].cve_id == "CVE-2023-99999"
        assert result[0].fixed_version == "1.0.1"
        assert result[0].language == "rust"


# ── Severity enrichment tests (T8) ──────────────────────────────────────────


class TestSeverityEnrichment:
    async def test_pip_audit_severity_enriched_via_osv(self, tmp_path) -> None:
        """OSV returns CRITICAL -> finding upgraded from MEDIUM."""
        from unittest.mock import AsyncMock  # noqa: PLC0415

        from src.patrol.osv_client import OSVClient  # noqa: PLC0415

        osv = AsyncMock(spec=OSVClient)
        osv.get_vulnerability = AsyncMock(return_value={
            "database_specific": {"severity": "CRITICAL"},
        })
        config = DependencyAuditConfig(severity_threshold="LOW")
        enriched_auditor = DependencyAuditor(config, osv_client=osv)

        vuln_data = [
            {
                "name": "flask",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "PYSEC-2024-001",
                        "fix_versions": ["2.0.0"],
                        "aliases": ["CVE-2024-0001"],
                    }
                ],
            }
        ]
        proc = _make_process(json.dumps(vuln_data).encode(), 1)
        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch(
                "src.patrol.dependency_audit.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
        ):
            result = await enriched_auditor.audit(tmp_path, "python")
        assert len(result) == 1
        assert result[0].severity.value == "CRITICAL"
        osv.get_vulnerability.assert_awaited_once_with("CVE-2024-0001")

    async def test_pip_audit_severity_osv_unavailable(self, tmp_path) -> None:
        """OSV client is None -> stays MEDIUM."""
        config = DependencyAuditConfig(severity_threshold="LOW")
        no_osv_auditor = DependencyAuditor(config, osv_client=None)

        vuln_data = [
            {
                "name": "flask",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "PYSEC-2024-002",
                        "fix_versions": ["2.0.0"],
                        "aliases": ["CVE-2024-0002"],
                    }
                ],
            }
        ]
        proc = _make_process(json.dumps(vuln_data).encode(), 1)
        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch(
                "src.patrol.dependency_audit.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
        ):
            result = await no_osv_auditor.audit(tmp_path, "python")
        assert len(result) == 1
        assert result[0].severity.value == "MEDIUM"


# ── Severity threshold filtering test (T9) ──────────────────────────────────


class TestSeverityThreshold:
    async def test_severity_threshold_filters_low(self, tmp_path) -> None:
        """threshold=HIGH -> LOW/MEDIUM findings filtered out."""
        config = DependencyAuditConfig(severity_threshold="HIGH")
        strict_auditor = DependencyAuditor(config)

        vuln_data = [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "PYSEC-2024-010",
                        "fix_versions": ["2.31.0"],
                        "aliases": ["CVE-2024-0010"],
                    }
                ],
            }
        ]
        proc = _make_process(json.dumps(vuln_data).encode(), 1)
        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch(
                "src.patrol.dependency_audit.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
        ):
            # pip-audit findings default to MEDIUM, threshold is HIGH → filtered
            result = await strict_auditor.audit(tmp_path, "python")
        assert result == []
