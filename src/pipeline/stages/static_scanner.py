"""Static analysis stage — runs Semgrep and produces normalized findings."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.models.enums import Severity, VulnerabilityCategory
from src.models.pipeline import Finding
from src.security import scrub_tokens, validate_branch_name, validate_clone_url

if TYPE_CHECKING:
    from src.config import SaltaXConfig
    from src.intelligence.database import IntelligenceDB
    from src.pipeline.state import PipelineState

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_SEMGREP_RULESETS = ("p/security-audit", "p/owasp-top-ten", "p/supply-chain")
_CUSTOM_RULES_DIR = Path("/app/rules/")
_SEMGREP_MAX_MEMORY_MB = 1024
_SEMGREP_PER_FILE_TIMEOUT = 30  # seconds per file; total timeout is via wait_for
_SNIPPET_MAX_LEN = 500
_MAX_DIFF_BYTES = 10 * 1024 * 1024  # 10 MB
_CLONE_TIMEOUT = 60  # seconds
_APPLY_TIMEOUT = 30  # seconds

# Semgrep severity → (Severity enum, confidence)
_SEVERITY_MAP: dict[str, tuple[Severity, float]] = {
    "ERROR": (Severity.CRITICAL, 0.95),
    "WARNING": (Severity.HIGH, 0.85),
    "INFO": (Severity.MEDIUM, 0.70),
}

# check_id keyword → VulnerabilityCategory
_CATEGORY_MAP: dict[str, VulnerabilityCategory] = {
    "reentrancy": VulnerabilityCategory.REENTRANCY,
    "injection": VulnerabilityCategory.INJECTION,
    "sqli": VulnerabilityCategory.INJECTION,
    "xss": VulnerabilityCategory.INJECTION,
    "overflow": VulnerabilityCategory.OVERFLOW,
    "access-control": VulnerabilityCategory.ACCESS_CONTROL,
    "access_control": VulnerabilityCategory.ACCESS_CONTROL,
    "secret": VulnerabilityCategory.SECRETS_EXPOSURE,
    "supply-chain": VulnerabilityCategory.DEPENDENCY_CONFUSION,
    "supply_chain": VulnerabilityCategory.DEPENDENCY_CONFUSION,
    "deserialization": VulnerabilityCategory.UNSAFE_DESERIALIZATION,
    "logic": VulnerabilityCategory.LOGIC_ERROR,
}


# ── Public entry point ───────────────────────────────────────────────────────


async def run_static_scan(
    state: PipelineState,
    config: SaltaXConfig,
    intel_db: IntelligenceDB,
) -> None:
    """Run Semgrep against the repo and populate ``state.static_findings``.

    Mutates *state* in place. Never raises — all errors are caught, logged,
    and result in empty findings.
    """
    state.current_stage = "static_scanner"
    t0 = time.monotonic()
    logger.info("Static scan started for %s", state.pr_id)

    tmp_dir: str | None = None
    try:
        validate_clone_url(state.repo_url)
        validate_branch_name(state.base_branch)

        if shutil.which("semgrep") is None:
            logger.error("Semgrep binary not found — skipping static scan")
            return

        tmp_dir = tempfile.mkdtemp(prefix="saltax-scan-")
        repo_dir = Path(tmp_dir) / "repo"

        await asyncio.wait_for(
            _clone_repo(state.repo_url, state.base_branch, repo_dir),
            timeout=_CLONE_TIMEOUT,
        )

        if state.diff:
            diff_bytes = len(state.diff.encode())
            if diff_bytes > _MAX_DIFF_BYTES:
                logger.warning(
                    "Diff too large (%d bytes, max %d) — skipping patch",
                    diff_bytes,
                    _MAX_DIFF_BYTES,
                )
            else:
                await asyncio.wait_for(
                    _apply_diff(state.diff, repo_dir),
                    timeout=_APPLY_TIMEOUT,
                )

        cmd = _build_semgrep_command(
            repo_dir, config,
            include_paths=state.scan_include,
            exclude_paths=state.scan_exclude,
        )
        raw_json = await asyncio.wait_for(
            _run_semgrep(cmd),
            timeout=config.pipeline.static_scanner_timeout,
        )

        findings = _parse_semgrep_output(raw_json)

        # Post-filter findings to changed files only
        if state.diff:
            from src.selfmerge.detector import extract_modified_files  # noqa: PLC0415

            changed = extract_modified_files(state.diff)
            if changed:
                before = len(findings)
                findings = [f for f in findings if f.file_path in changed]
                filtered_count = before - len(findings)
                if filtered_count:
                    logger.info("Filtered %d finding(s) outside changed files", filtered_count)

        # Filter known false positives — preserve findings if DB query fails
        try:
            fp_sigs = await intel_db.get_false_positive_signatures()
            if fp_sigs:
                before = len(findings)
                findings = [f for f in findings if f.rule_id not in fp_sigs]
                filtered = before - len(findings)
                if filtered:
                    logger.info("Filtered %d known false-positive(s)", filtered)
        except Exception:
            logger.warning("Failed to query false-positive signatures — skipping filter")

        state.static_findings = [f.model_dump() for f in findings]
        state.short_circuit = _should_short_circuit(findings)

        counts = _count_by_severity(findings)
        elapsed = time.monotonic() - t0

        # Log individual findings for traceability
        for f in findings:
            logger.info(
                "  finding: %s | %s | %s:%d-%d | %s",
                f.severity.value,
                f.rule_id,
                f.file_path,
                f.line_start,
                f.line_end,
                f.message[:120],
            )

        logger.info(
            "Static scan completed: %d finding(s) in %.1fs | %s | short_circuit=%s",
            len(findings),
            elapsed,
            counts,
            state.short_circuit,
        )

    except TimeoutError:
        logger.error(
            "Semgrep timed out after %ds",
            config.pipeline.static_scanner_timeout,
        )
    except Exception:
        logger.exception("Static scan failed unexpectedly")
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Private helpers ──────────────────────────────────────────────────────────


async def _kill_proc(proc: asyncio.subprocess.Process) -> None:
    """Terminate a subprocess and wait for it to exit.

    Uses ``BaseException`` suppression on ``wait()`` because after ``kill()``,
    the reap is best-effort — the process is already dead.  This ensures
    ``CancelledError`` during cleanup doesn't prevent ``kill()`` from running.
    """
    with contextlib.suppress(ProcessLookupError):
        proc.kill()
    with contextlib.suppress(BaseException):
        await proc.wait()


async def _clone_repo(repo_url: str, branch: str, target_dir: Path) -> None:
    """Shallow-clone *branch* from *repo_url* into *target_dir*."""
    proc = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth=1",
        "--single-branch",
        f"--branch={branch}",
        repo_url,
        str(target_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _, stderr_bytes = await proc.communicate()
    except BaseException:
        await _kill_proc(proc)
        raise
    if proc.returncode != 0:
        stderr_text = ""
        if stderr_bytes:
            stderr_text = scrub_tokens(stderr_bytes.decode(errors="replace").strip()[:300])
        raise RuntimeError(
            f"git clone exited with code {proc.returncode}: {stderr_text}"
        )


async def _apply_diff(diff: str, repo_dir: Path) -> None:
    """Apply *diff* via ``git apply`` — warn on failure, don't abort."""
    if not diff.strip():
        return

    proc = await asyncio.create_subprocess_exec(
        "git",
        "apply",
        "--allow-empty",
        "-",
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=str(repo_dir),
    )
    try:
        _, stderr = await proc.communicate(input=diff.encode())
    except BaseException:
        await _kill_proc(proc)
        raise
    if proc.returncode != 0:
        stderr_text = scrub_tokens(stderr.decode(errors="replace").strip()[:200]) if stderr else ""
        logger.warning(
            "git apply failed (rc=%d): %s — scanning base branch only",
            proc.returncode,
            stderr_text,
        )


def _build_semgrep_command(
    repo_dir: Path,
    config: SaltaXConfig,
    *,
    include_paths: tuple[str, ...] = (),
    exclude_paths: tuple[str, ...] = (),
) -> list[str]:
    """Assemble the Semgrep CLI invocation.

    Only operator-controlled rulesets are loaded. The cloned repo's
    ``.semgrep/`` directory is intentionally NOT loaded — the entity being
    audited must not influence the auditing tool's ruleset.

    *include_paths* and *exclude_paths* map to Semgrep's ``--include`` /
    ``--exclude`` CLI flags for scan-scope filtering from the rules file's
    ``## Scan Configuration`` section.
    """
    cmd: list[str] = [
        "semgrep",
        "--json",
        "--quiet",
        f"--max-memory={_SEMGREP_MAX_MEMORY_MB}",
        f"--timeout={_SEMGREP_PER_FILE_TIMEOUT}",
    ]

    for ruleset in _SEMGREP_RULESETS:
        cmd.extend(["--config", ruleset])

    if _CUSTOM_RULES_DIR.is_dir():
        cmd.extend(["--config", str(_CUSTOM_RULES_DIR)])

    for pattern in include_paths:
        cmd.extend(["--include", pattern])
    for pattern in exclude_paths:
        cmd.extend(["--exclude", pattern])

    cmd.append(str(repo_dir))
    return cmd


async def _run_semgrep(cmd: list[str]) -> str:
    """Execute Semgrep and return stdout. Raise on error exit codes."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await proc.communicate()
    except BaseException:
        await _kill_proc(proc)
        raise

    if stderr_bytes:
        stderr_text = stderr_bytes.decode(errors="replace").strip()
        if stderr_text:
            logger.debug("Semgrep stderr: %s", stderr_text[:500])

    rc = proc.returncode
    # Semgrep: 0 = clean, 1 = findings, 2+ = error
    if rc is not None and rc >= 2:
        raise RuntimeError(f"Semgrep exited with error code {rc}")

    return stdout_bytes.decode(errors="replace") if stdout_bytes else ""


def _parse_semgrep_output(raw_json: str) -> list[Finding]:
    """Parse Semgrep JSON output into a list of ``Finding`` objects."""
    if not raw_json.strip():
        return []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Semgrep JSON output")
        return []

    results = data.get("results", [])
    findings: list[Finding] = []
    for item in results:
        try:
            findings.append(_semgrep_result_to_finding(item))
        except Exception:
            logger.debug("Skipping unparseable Semgrep result: %s", item)
    return findings


def _semgrep_result_to_finding(item: dict[str, Any]) -> Finding:
    """Convert a single Semgrep result dict to a ``Finding``."""
    check_id = str(item.get("check_id", "unknown"))
    path = str(item.get("path", "unknown"))

    start: dict[str, Any] = item.get("start") or {}
    end: dict[str, Any] = item.get("end") or {}
    line_start = int(start.get("line", 0))
    line_end = int(end.get("line", line_start))

    extra: dict[str, Any] = item.get("extra") or {}
    severity_str = str(extra.get("severity", "")).upper()
    message = str(extra.get("message", ""))
    snippet_raw = str(extra.get("lines", ""))
    snippet = snippet_raw[:_SNIPPET_MAX_LEN] if snippet_raw else None

    severity, confidence = _SEVERITY_MAP.get(
        severity_str, (Severity.MEDIUM, 0.50)
    )
    category = _infer_category(check_id)

    return Finding(
        rule_id=check_id,
        severity=severity,
        category=category,
        message=message,
        file_path=path,
        line_start=line_start,
        line_end=line_end,
        confidence=confidence,
        source_stage="static_scanner",
        snippet=snippet,
    )


def _infer_category(check_id: str) -> VulnerabilityCategory:
    """Map a Semgrep check_id to a ``VulnerabilityCategory`` via keyword match."""
    lower = check_id.lower()
    for keyword, category in _CATEGORY_MAP.items():
        if keyword in lower:
            return category
    return VulnerabilityCategory.OTHER


def _should_short_circuit(findings: list[Finding]) -> bool:
    """Decide whether to skip remaining pipeline stages."""
    counts = _count_by_severity(findings)
    return counts.get("CRITICAL", 0) > 0 or counts.get("HIGH", 0) > 5


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity level."""
    counts: dict[str, int] = {}
    for f in findings:
        key = f.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts
