"""Shared API response and error models for the HTTP interface."""

from __future__ import annotations

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Consistent JSON error shape returned by all endpoints."""

    status_code: int
    error: str
    detail: str
