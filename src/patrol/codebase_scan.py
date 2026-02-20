"""Codebase scanner — full-repo Semgrep scans for patrol cycles.

Reuses the same Semgrep invocation pattern as
``src/pipeline/stages/static_scanner.py`` but targets the entire
repo directory rather than a diff.
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
from src.models.patrol import PatrolFinding

if TYPE_CHECKING:
    from pathlib import Path

    from src.config import CodebaseScanConfig
    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

_SEMGREP_TIMEOUT = 300  # seconds
_SEMGREP_MAX_MEMORY_MB = 2048

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class CodebaseScanner:
    """Runs Semgrep on a full repository checkout."""

    async def scan(
        self, repo_path: Path, config: CodebaseScanConfig,
    ) -> list[PatrolFinding]:
        """Run Semgrep and return parsed findings."""
        if shutil.which("semgrep") is None:
            logger.warning("semgrep not found, skipping codebase scan")
            return []

        cmd = self._build_command(repo_path, config)
        raw_json = await self._run_semgrep(cmd)
        return self._parse_output(raw_json)

    async def diff_against_previous(
        self,
        current: list[PatrolFinding],
        repo: str,
        intel_db: IntelligenceDB,
        rescan_interval_hours: int = 0,
    ) -> list[PatrolFinding]:
        """Filter *current* to only genuinely new findings.

        Uses ``(rule_id, file_path, line_start)`` as the dedup signature,
        backed by the ``patrol_finding_signatures`` table.

        When *rescan_interval_hours* > 0 and the last patrol run is within
        that window, returns an empty list (skip scan entirely).
        """
        # Check rescan interval (Fix 11)
        if rescan_interval_hours > 0:
            previous_run = await intel_db.get_latest_patrol_run(repo)
            if previous_run is not None:
                from datetime import UTC, datetime  # noqa: PLC0415

                last_ts = previous_run.get("timestamp", "")
                if isinstance(last_ts, str) and last_ts:
                    try:
                        last_dt = datetime.fromisoformat(last_ts)
                        if last_dt.tzinfo is None:
                            last_dt = last_dt.replace(tzinfo=UTC)
                        now = datetime.now(UTC)
                        hours_since = (now - last_dt).total_seconds() / 3600
                        if hours_since < rescan_interval_hours:
                            logger.info(
                                "Skipping scan for %s — last scan %.1fh ago "
                                "(interval=%dh)",
                                repo, hours_since, rescan_interval_hours,
                            )
                            return []
                    except (ValueError, TypeError):
                        pass  # parse failure → don't skip

        # Fetch known signatures from DB
        known = await intel_db.get_known_finding_signatures(repo)

        # Filter to genuinely new findings
        new_findings = [
            f for f in current
            if (f.rule_id, f.file_path, f.line_start) not in known
        ]

        # Upsert ALL current signatures (updates last_seen for existing)
        all_sigs = [(f.rule_id, f.file_path, f.line_start) for f in current]
        await intel_db.upsert_finding_signatures(repo, all_sigs)

        return new_findings

    @staticmethod
    def _build_command(repo_path: Path, config: CodebaseScanConfig) -> list[str]:
        cmd: list[str] = [
            "semgrep",
            "--json",
            "--quiet",
            f"--max-memory={_SEMGREP_MAX_MEMORY_MB}",
        ]
        cmd.extend(["--config", config.semgrep_config])
        cmd.append(str(repo_path))
        return cmd

    @staticmethod
    async def _run_semgrep(cmd: list[str]) -> str:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=_SEMGREP_TIMEOUT,
            )
        except TimeoutError:
            with suppress(ProcessLookupError):
                proc.kill()
            with suppress(BaseException):
                await proc.wait()
            logger.error("Semgrep timed out")
            return ""

        if stderr_bytes:
            stderr_text = stderr_bytes.decode(errors="replace").strip()
            if stderr_text:
                logger.debug("Semgrep stderr: %s", stderr_text[:500])

        rc = proc.returncode
        if rc is not None and rc >= 2:
            logger.error("Semgrep exited with error code %d", rc)
            return ""

        return stdout_bytes.decode(errors="replace") if stdout_bytes else ""

    @staticmethod
    def _parse_output(raw_json: str) -> list[PatrolFinding]:
        if not raw_json.strip():
            return []

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Semgrep JSON output")
            return []

        results = data.get("results", [])
        findings: list[PatrolFinding] = []
        for item in results:
            try:
                check_id = str(item.get("check_id", "unknown"))
                path = str(item.get("path", "unknown"))
                start = item.get("start") or {}
                end = item.get("end") or {}
                extra = item.get("extra") or {}
                severity_str = str(extra.get("severity", "")).upper()
                severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
                message = str(extra.get("message", ""))

                findings.append(PatrolFinding(
                    rule_id=check_id,
                    file_path=path,
                    line_start=int(start.get("line", 0)),
                    line_end=int(end.get("line", 0)),
                    severity=severity,
                    message=message,
                    category=str(extra.get("metadata", {}).get("category", "uncategorized")),
                ))
            except Exception:
                logger.debug("Skipping unparseable Semgrep result: %s", item)
        return findings
