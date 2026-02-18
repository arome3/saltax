"""GitHub webhook payload models.

These models normalise raw GitHub webhook JSON into typed, validated objects
consumed by the ingress controller and triage layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# ── Pull-request event ──────────────────────────────────────────────────────


class PREvent(BaseModel):
    """Normalised pull-request webhook payload."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["opened", "synchronize", "closed", "reopened"]
    pr_number: int
    pr_id: str  # "{owner}/{repo}#{number}"
    repo_full_name: str
    repo_url: str
    clone_url: str
    head_sha: str
    base_branch: str
    head_branch: str
    author_login: str
    author_id: int
    title: str
    body: str | None = None
    diff_url: str
    labels: list[str] = Field(default_factory=list)
    created_at: datetime
    is_draft: bool


# ── Issue event ─────────────────────────────────────────────────────────────


class IssueEvent(BaseModel):
    """Normalised issue webhook payload."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["labeled", "unlabeled", "opened", "closed"]
    issue_number: int
    repo_full_name: str
    labels: list[str] = Field(default_factory=list)
    title: str
    body: str | None = None


# ── Bounty info ─────────────────────────────────────────────────────────────


class BountyInfo(BaseModel):
    """Metadata for a bounty attached to a GitHub issue."""

    model_config = ConfigDict(extra="forbid")

    issue_number: int
    repo_full_name: str
    label: str
    amount_wei: int
    currency: str = "ETH"
    created_at: datetime
    claimed_by_pr: int | None = None
