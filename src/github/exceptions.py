"""Custom exception hierarchy for GitHub API interactions."""

from __future__ import annotations


class GitHubError(Exception):
    """Base exception for all GitHub API errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_body: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class GitHubRateLimitError(GitHubError):
    """Raised when the GitHub API rate limit is exhausted."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_body: str = "",
        reset_timestamp: float = 0.0,
    ) -> None:
        super().__init__(message, status_code=status_code, response_body=response_body)
        self.reset_timestamp = reset_timestamp


class GitHubAuthError(GitHubError):
    """Raised on JWT or installation-token authentication failures."""


class GitHubNotFoundError(GitHubError):
    """Raised when a GitHub resource returns 404."""


class GitHubMergeConflictError(GitHubError):
    """Raised when a PR merge fails with 409 Conflict."""
