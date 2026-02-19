"""Shared API response and error models for the HTTP interface."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Consistent JSON error shape returned by all endpoints."""

    status_code: int
    error: str
    detail: str


# ── Challenge / verification models ──────────────────────────────────────


class ChallengeRequest(BaseModel):
    window_id: str
    challenger_address: str
    stake_wei: int = Field(ge=0)
    rationale: str = Field(min_length=1, max_length=4000)


class ChallengeResponse(BaseModel):
    success: bool
    message: str
    challenge_id: str | None = None


class ResolveRequest(BaseModel):
    upheld: bool


class ResolveResponse(BaseModel):
    success: bool
    message: str


class VerificationWindowResponse(BaseModel):
    id: str
    pr_id: str
    repo: str
    pr_number: int
    status: str
    contributor_address: str | None
    bounty_amount_wei: str
    stake_amount_wei: str
    window_hours: int
    opens_at: str
    closes_at: str
    challenge_id: str | None
    challenger_address: str | None
    resolution: str | None
    created_at: str
    updated_at: str


class VerificationWindowListResponse(BaseModel):
    windows: list[VerificationWindowResponse]
    count: int
