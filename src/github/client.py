"""Async GitHub App client with JWT authentication and installation-token caching.

Includes retry with exponential backoff and a per-installation circuit breaker
to handle transient failures and sustained GitHub outages gracefully.
"""

from __future__ import annotations

import asyncio
import logging
import time
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import httpx
import jwt

from src.github.exceptions import (
    GitHubAuthError,
    GitHubError,
    GitHubMergeConflictError,
    GitHubNotFoundError,
    GitHubRateLimitError,
)
from src.security import SAFE_BRANCH_RE, SAFE_CLONE_URL_RE

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
_TOKEN_TTL_SECONDS = 3000  # 50 min (tokens expire at 60 min)
_RATE_LIMIT_WARNING_THRESHOLD = 100

# Retry configuration
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # seconds — backoff: 1s, 2s, 4s
_RETRYABLE_STATUS_CODES = frozenset({500, 502, 503, 504})

# Circuit breaker configuration
_CB_FAILURE_THRESHOLD = 5
_CB_COOLDOWN_SECONDS = 60.0

# Connection pool limits
_MAX_CONNECTIONS = 20
_MAX_KEEPALIVE_CONNECTIONS = 10


# ── Circuit breaker ──────────────────────────────────────────────────────────


class _CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class _CircuitBreaker:
    """Per-installation circuit breaker.

    State machine: CLOSED → OPEN → HALF_OPEN → CLOSED (on success) or OPEN (on failure).
    """

    def __init__(
        self,
        failure_threshold: int = _CB_FAILURE_THRESHOLD,
        cooldown_seconds: float = _CB_COOLDOWN_SECONDS,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._state = _CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = 0.0

    @property
    def state(self) -> _CircuitState:
        if (
            self._state == _CircuitState.OPEN
            and time.monotonic() - self._opened_at >= self._cooldown_seconds
        ):
            self._state = _CircuitState.HALF_OPEN
        return self._state

    def record_success(self) -> None:
        if self._state != _CircuitState.CLOSED:
            logger.info("Circuit breaker closed after recovery")
        self._consecutive_failures = 0
        self._state = _CircuitState.CLOSED

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            if self._state != _CircuitState.OPEN:
                logger.warning(
                    "Circuit breaker opened after %d consecutive failures",
                    self._consecutive_failures,
                )
            self._state = _CircuitState.OPEN
            self._opened_at = time.monotonic()

    def check(self) -> None:
        """Raise if the circuit is open."""
        current = self.state
        if current == _CircuitState.OPEN:
            remaining = self._cooldown_seconds - (time.monotonic() - self._opened_at)
            raise GitHubError(
                f"Circuit breaker open, retry in {remaining:.0f}s",
                status_code=None,
            )


# ── Client ───────────────────────────────────────────────────────────────────


class GitHubClient:
    """Async client for the GitHub API, authenticated as a GitHub App.

    Parameters
    ----------
    app_id:
        The GitHub App ID (string, matching ``EnvConfig.github_app_id``).
    private_key:
        PEM-encoded RSA private key for JWT signing.
    max_retries:
        Maximum retry attempts for transient (5xx / network) failures.
    """

    def __init__(
        self,
        app_id: str,
        private_key: str,
        *,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        self._app_id = app_id
        self._private_key = private_key
        self._max_retries = max_retries
        self._client = httpx.AsyncClient(
            base_url=_GITHUB_API_BASE,
            headers={"Accept": "application/vnd.github+json"},
            timeout=30.0,
            limits=httpx.Limits(
                max_connections=_MAX_CONNECTIONS,
                max_keepalive_connections=_MAX_KEEPALIVE_CONNECTIONS,
            ),
        )
        self._token_cache: dict[int, tuple[str, float]] = {}
        self._token_locks: dict[int, asyncio.Lock] = {}
        self._circuit_breakers: dict[int, _CircuitBreaker] = {}

    def _get_lock(self, installation_id: int) -> asyncio.Lock:
        """Return a per-installation lock, creating if needed."""
        if installation_id not in self._token_locks:
            self._token_locks[installation_id] = asyncio.Lock()
        return self._token_locks[installation_id]

    def _get_circuit_breaker(self, installation_id: int) -> _CircuitBreaker:
        """Return a per-installation circuit breaker, creating if needed."""
        if installation_id not in self._circuit_breakers:
            self._circuit_breakers[installation_id] = _CircuitBreaker()
        return self._circuit_breakers[installation_id]

    # ── JWT generation ───────────────────────────────────────────────────

    def _generate_jwt(self) -> str:
        """Create a short-lived JWT for GitHub App authentication."""
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now - 60 + 600,
            "iss": self._app_id,
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    # ── Installation token management ────────────────────────────────────

    async def _get_installation_token(self, installation_id: int) -> str:
        """Return a cached installation token, refreshing if expired."""
        lock = self._get_lock(installation_id)
        async with lock:
            cached = self._token_cache.get(installation_id)
            if cached is not None:
                token, expires_at = cached
                if time.time() < expires_at:
                    return token

            token_jwt = self._generate_jwt()
            response = await self._client.post(
                f"/app/installations/{installation_id}/access_tokens",
                headers={"Authorization": f"Bearer {token_jwt}"},
            )
            if response.status_code != 201:
                raise GitHubAuthError(
                    f"Failed to get installation token: {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text[:500],
                )

            data: dict[str, Any] = response.json()
            token_value: str | None = data.get("token")
            if not token_value:
                raise GitHubAuthError(
                    "Installation token response missing 'token' field",
                    status_code=201,
                    response_body=response.text[:500],
                )
            token = token_value
            self._token_cache[installation_id] = (token, time.time() + _TOKEN_TTL_SECONDS)
            logger.debug(
                "Refreshed installation token",
                extra={"installation_id": installation_id},
            )
            return token

    # ── Central request handler ──────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        installation_id: int,
        accept: str | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Send an authenticated request to the GitHub API.

        Handles token injection, retries with exponential backoff for transient
        failures, circuit breaker checks, rate-limit awareness, and error mapping.
        """
        cb = self._get_circuit_breaker(installation_id)
        cb.check()

        token = await self._get_installation_token(installation_id)
        headers: dict[str, str] = {"Authorization": f"token {token}"}
        if accept is not None:
            headers["Accept"] = accept

        last_error: Exception | None = None

        for attempt in range(1, self._max_retries + 1):
            try:
                response = await self._client.request(
                    method,
                    path,
                    headers=headers,
                    json=json_body,
                )
            except httpx.TransportError as exc:
                last_error = exc
                if attempt < self._max_retries:
                    delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                    logger.warning(
                        "GitHub request network error (attempt %d/%d), retrying in %.1fs",
                        attempt,
                        self._max_retries,
                        delay,
                        extra={"path": path, "error": str(exc)},
                    )
                    await asyncio.sleep(delay)
                    continue
                cb.record_failure()
                raise GitHubError(
                    f"GitHub API network error after {self._max_retries} retries: {exc}",
                ) from exc

            # Retryable server errors (5xx)
            if response.status_code in _RETRYABLE_STATUS_CODES:
                last_error = GitHubError(
                    f"GitHub API error {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text[:500],
                )
                if attempt < self._max_retries:
                    delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                    logger.warning(
                        "GitHub %d response (attempt %d/%d), retrying in %.1fs",
                        response.status_code,
                        attempt,
                        self._max_retries,
                        delay,
                        extra={"path": path},
                    )
                    await asyncio.sleep(delay)
                    continue
                cb.record_failure()
                raise last_error

            # Success or non-retryable error — break out of retry loop
            break

        cb.record_success()

        # Rate-limit awareness (warn only — don't discard valid responses)
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            remaining_int = int(remaining)
            if remaining_int == 0:
                reset_ts = float(response.headers.get("X-RateLimit-Reset", "0"))
                logger.warning(
                    "GitHub rate limit exhausted, next request will fail",
                    extra={"remaining": 0, "reset_timestamp": reset_ts},
                )
            elif remaining_int < _RATE_LIMIT_WARNING_THRESHOLD:
                logger.warning(
                    "GitHub rate limit low",
                    extra={"remaining": remaining_int},
                )

        # Error mapping (4xx — not retried)
        if response.status_code >= 400:
            body = response.text[:500]
            if response.status_code == 404:
                raise GitHubNotFoundError(
                    f"GitHub resource not found: {path}",
                    status_code=404,
                    response_body=body,
                )
            if response.status_code == 409:
                raise GitHubError(
                    f"Conflict on {path}",
                    status_code=409,
                    response_body=body,
                )
            if response.status_code == 403 and "rate limit" in response.text.lower():
                reset_ts = float(response.headers.get("X-RateLimit-Reset", "0"))
                raise GitHubRateLimitError(
                    "GitHub API rate limit exceeded (403)",
                    status_code=403,
                    response_body=body,
                    reset_timestamp=reset_ts,
                )
            raise GitHubError(
                f"GitHub API error {response.status_code}: {body}",
                status_code=response.status_code,
                response_body=body,
            )

        return response

    # ── API methods ──────────────────────────────────────────────────────

    async def get_pr_diff(
        self,
        repo: str,
        pr_number: int,
        installation_id: int,
    ) -> str:
        """Fetch the unified diff for a pull request."""
        response = await self._request(
            "GET",
            f"/repos/{repo}/pulls/{pr_number}",
            installation_id=installation_id,
            accept="application/vnd.github.diff",
        )
        return response.text

    async def create_check_run(
        self,
        repo: str,
        head_sha: str,
        installation_id: int,
        *,
        name: str,
        status: str,
        conclusion: str | None = None,
        output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a check run on a commit."""
        payload: dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }
        if conclusion is not None:
            payload["conclusion"] = conclusion
        if output is not None:
            payload["output"] = output

        response = await self._request(
            "POST",
            f"/repos/{repo}/check-runs",
            installation_id=installation_id,
            json_body=payload,
        )
        result: dict[str, Any] = response.json()
        return result

    async def merge_pr(
        self,
        repo: str,
        pr_number: int,
        installation_id: int,
        *,
        commit_title: str | None = None,
        merge_method: str = "squash",
    ) -> dict[str, Any]:
        """Merge a pull request.

        Raises :class:`GitHubMergeConflictError` on HTTP 409.
        """
        payload: dict[str, Any] = {"merge_method": merge_method}
        if commit_title is not None:
            payload["commit_title"] = commit_title

        try:
            response = await self._request(
                "PUT",
                f"/repos/{repo}/pulls/{pr_number}/merge",
                installation_id=installation_id,
                json_body=payload,
            )
        except GitHubError as exc:
            if exc.status_code == 409:
                raise GitHubMergeConflictError(
                    f"Merge conflict on PR #{pr_number}",
                    status_code=409,
                    response_body=exc.response_body,
                ) from exc
            raise
        result: dict[str, Any] = response.json()
        return result

    async def create_comment(
        self,
        repo: str,
        pr_number: int,
        installation_id: int,
        body: str,
    ) -> dict[str, Any]:
        """Post a comment on a PR (via the issues API)."""
        response = await self._request(
            "POST",
            f"/repos/{repo}/issues/{pr_number}/comments",
            installation_id=installation_id,
            json_body={"body": body},
        )
        result: dict[str, Any] = response.json()
        return result

    async def list_issue_comments(
        self,
        repo: str,
        issue_number: int,
        installation_id: int,
    ) -> list[dict[str, Any]]:
        """List all comments on an issue (or PR)."""
        response = await self._request(
            "GET",
            f"/repos/{repo}/issues/{issue_number}/comments",
            installation_id=installation_id,
        )
        result: list[dict[str, Any]] = response.json()
        return result

    async def update_comment(
        self,
        repo: str,
        comment_id: int,
        installation_id: int,
        body: str,
    ) -> dict[str, Any]:
        """Update an existing issue/PR comment by ID."""
        response = await self._request(
            "PATCH",
            f"/repos/{repo}/issues/comments/{comment_id}",
            installation_id=installation_id,
            json_body={"body": body},
        )
        result: dict[str, Any] = response.json()
        return result

    async def add_label(
        self,
        repo: str,
        issue_number: int,
        installation_id: int,
        label: str,
    ) -> dict[str, Any]:
        """Add a label to an issue or PR."""
        response = await self._request(
            "POST",
            f"/repos/{repo}/issues/{issue_number}/labels",
            installation_id=installation_id,
            json_body={"labels": [label]},
        )
        result: dict[str, Any] = response.json()
        return result

    async def remove_label(
        self,
        repo: str,
        issue_number: int,
        installation_id: int,
        label: str,
    ) -> None:
        """Remove a label from an issue or PR; silently ignores 404."""
        from contextlib import suppress  # noqa: PLC0415

        with suppress(GitHubNotFoundError):
            await self._request(
                "DELETE",
                f"/repos/{repo}/issues/{issue_number}/labels/{label}",
                installation_id=installation_id,
            )

    async def ensure_label(
        self,
        repo: str,
        installation_id: int,
        label: str,
        *,
        color: str = "0e8a16",
        description: str = "",
    ) -> None:
        """Create a label in the repo if it doesn't already exist.

        Catches the 422 "already_exists" response from GitHub and treats
        it as success.  Other errors propagate normally.
        """
        try:
            await self._request(
                "POST",
                f"/repos/{repo}/labels",
                installation_id=installation_id,
                json_body={
                    "name": label,
                    "color": color,
                    "description": description,
                },
            )
        except GitHubError as exc:
            if exc.status_code == 422 and "already_exists" in exc.response_body:
                return
            raise

    async def clone_repo(
        self,
        clone_url: str,
        target_dir: Path,
        branch: str,
    ) -> None:
        """Shallow-clone a repository branch using ``git clone``.

        Uses ``--depth=1 --single-branch`` for minimal bandwidth.
        ``stdout`` is sent to DEVNULL; ``stderr`` is captured for error reporting.

        Validates ``clone_url`` and ``branch`` to prevent git argument injection.
        """
        import subprocess  # noqa: PLC0415 — lazy import, only needed for clone

        if not SAFE_CLONE_URL_RE.match(clone_url):
            raise GitHubError(f"Refusing clone: unsafe URL: {clone_url}")
        if not SAFE_BRANCH_RE.match(branch):
            raise GitHubError(f"Refusing clone: unsafe branch name: {branch}")

        process = await asyncio.create_subprocess_exec(
            "git",
            "clone",
            "--depth=1",
            "--single-branch",
            "--branch",
            branch,
            clone_url,
            str(target_dir),
            stdout=subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode(errors="replace").strip()
            raise GitHubError(
                f"git clone failed (exit {process.returncode}): {error_msg}",
            )

    # ── Cleanup ──────────────────────────────────────────────────────────

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
