"""Patrol module domain models.

Frozen Pydantic models for dependency audit findings and codebase scan findings.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.models.enums import Severity

# ── Dependency finding ────────────────────────────────────────────────────────


class DependencyFinding(BaseModel):
    """A single dependency vulnerability discovered by the auditor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str
    current_version: str
    vulnerable_range: str
    cve_id: str | None = None
    severity: Severity
    advisory_url: str = ""
    fixed_version: str | None = None
    is_direct: bool = True
    language: str = "python"


# ── Patrol (codebase scan) finding ────────────────────────────────────────────


class PatrolFinding(BaseModel):
    """A single Semgrep finding from a full-codebase patrol scan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: Severity
    message: str
    category: str = "uncategorized"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
