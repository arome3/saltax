"""Tests for the GitHub App client (src/github/client.py)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from src.github.client import (
    GitHubClient,
    _CircuitBreaker,
    _CircuitState,
    _GITHUB_API_BASE,
    _TOKEN_TTL_SECONDS,
)
from src.github.exceptions import (
    GitHubError,
    GitHubMergeConflictError,
    GitHubNotFoundError,
)

# ── Test RSA key (generated once at module level) ────────────────────────────

_TEST_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_PEM = _TEST_RSA_KEY.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
).decode()
_TEST_APP_ID = "12345"
_TEST_INSTALLATION_ID = 99


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
async def github_client() -> AsyncIterator[GitHubClient]:
    client = GitHubClient(app_id=_TEST_APP_ID, private_key=_TEST_PEM)
    try:
        yield client
    finally:
        await client.close()


def _mock_token_response() -> httpx.Response:
    return httpx.Response(
        201,
        json={"token": "ghs_test_token_abc123"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# JWT Generation
# ═══════════════════════════════════════════════════════════════════════════════


class TestGenerateJWT:
    def test_jwt_has_valid_structure(self, github_client: GitHubClient) -> None:
        token = github_client._generate_jwt()
        decoded = pyjwt.decode(
            token,
            _TEST_RSA_KEY.public_key(),
            algorithms=["RS256"],
            options={"verify_exp": False},
        )
        assert "iat" in decoded
        assert "exp" in decoded
        assert "iss" in decoded

    def test_jwt_uses_rs256(self, github_client: GitHubClient) -> None:
        token = github_client._generate_jwt()
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "RS256"

    def test_jwt_iat_is_backdated(self, github_client: GitHubClient) -> None:
        now = int(time.time())
        token = github_client._generate_jwt()
        decoded = pyjwt.decode(
            token,
            _TEST_RSA_KEY.public_key(),
            algorithms=["RS256"],
            options={"verify_exp": False},
        )
        assert decoded["iat"] == pytest.approx(now - 60, abs=5)

    def test_jwt_exp_is_iat_plus_600(self, github_client: GitHubClient) -> None:
        token = github_client._generate_jwt()
        decoded = pyjwt.decode(
            token,
            _TEST_RSA_KEY.public_key(),
            algorithms=["RS256"],
            options={"verify_exp": False},
        )
        assert decoded["exp"] == decoded["iat"] + 600

    def test_jwt_iss_is_app_id_string(self, github_client: GitHubClient) -> None:
        token = github_client._generate_jwt()
        decoded = pyjwt.decode(
            token,
            _TEST_RSA_KEY.public_key(),
            algorithms=["RS256"],
            options={"verify_exp": False},
        )
        assert decoded["iss"] == _TEST_APP_ID


# ═══════════════════════════════════════════════════════════════════════════════
# Installation Token Caching
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetInstallationToken:
    async def test_cache_miss_fetches_token(self, github_client: GitHubClient) -> None:
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(
                f"/app/installations/{_TEST_INSTALLATION_ID}/access_tokens"
            ).mock(return_value=_mock_token_response())

            token = await github_client._get_installation_token(_TEST_INSTALLATION_ID)

            assert token == "ghs_test_token_abc123"
            assert mock.calls.call_count == 1

    async def test_cache_hit_skips_fetch(self, github_client: GitHubClient) -> None:
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(
                f"/app/installations/{_TEST_INSTALLATION_ID}/access_tokens"
            ).mock(return_value=_mock_token_response())

            await github_client._get_installation_token(_TEST_INSTALLATION_ID)
            await github_client._get_installation_token(_TEST_INSTALLATION_ID)

            assert mock.calls.call_count == 1

    async def test_expired_cache_refetches(self, github_client: GitHubClient) -> None:
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(
                f"/app/installations/{_TEST_INSTALLATION_ID}/access_tokens"
            ).mock(return_value=_mock_token_response())

            await github_client._get_installation_token(_TEST_INSTALLATION_ID)

            # Manually expire the cache
            github_client._token_cache[_TEST_INSTALLATION_ID] = (
                "expired",
                time.time() - 1,
            )

            token = await github_client._get_installation_token(_TEST_INSTALLATION_ID)
            assert token == "ghs_test_token_abc123"
            assert mock.calls.call_count == 2

    async def test_concurrent_calls_fetch_token_once(
        self, github_client: GitHubClient
    ) -> None:
        """N concurrent callers should trigger exactly 1 token fetch."""
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(
                f"/app/installations/{_TEST_INSTALLATION_ID}/access_tokens"
            ).mock(return_value=_mock_token_response())

            tokens = await asyncio.gather(*[
                github_client._get_installation_token(_TEST_INSTALLATION_ID)
                for _ in range(10)
            ])

            assert all(t == "ghs_test_token_abc123" for t in tokens)
            assert mock.calls.call_count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# PR Diff
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetPrDiff:
    async def test_success_returns_diff_text(self, github_client: GitHubClient) -> None:
        diff_text = "diff --git a/file.py b/file.py\n+hello"
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            mock.get("/repos/owner/repo/pulls/42").mock(
                return_value=httpx.Response(200, text=diff_text)
            )

            result = await github_client.get_pr_diff("owner/repo", 42, _TEST_INSTALLATION_ID)

            assert result == diff_text

    async def test_404_raises_not_found(self, github_client: GitHubClient) -> None:
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            mock.get("/repos/owner/repo/pulls/999").mock(
                return_value=httpx.Response(404, json={"message": "Not Found"})
            )

            with pytest.raises(GitHubNotFoundError):
                await github_client.get_pr_diff("owner/repo", 999, _TEST_INSTALLATION_ID)


# ═══════════════════════════════════════════════════════════════════════════════
# Check Run
# ═══════════════════════════════════════════════════════════════════════════════


class TestCreateCheckRun:
    async def test_sends_correct_payload(self, github_client: GitHubClient) -> None:
        output = {"title": "Test", "summary": "OK", "annotations": []}
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            route = mock.post("/repos/owner/repo/check-runs").mock(
                return_value=httpx.Response(201, json={"id": 1})
            )

            result = await github_client.create_check_run(
                "owner/repo",
                "abc123sha",
                _TEST_INSTALLATION_ID,
                name="SaltaX Pipeline",
                status="completed",
                conclusion="success",
                output=output,
            )

            assert result == {"id": 1}
            sent = route.calls[0].request
            import json

            body = json.loads(sent.content)
            assert body["name"] == "SaltaX Pipeline"
            assert body["head_sha"] == "abc123sha"
            assert body["status"] == "completed"
            assert body["conclusion"] == "success"
            assert body["output"] == output


# ═══════════════════════════════════════════════════════════════════════════════
# Merge PR
# ═══════════════════════════════════════════════════════════════════════════════


class TestMergePr:
    async def test_success(self, github_client: GitHubClient) -> None:
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            mock.put("/repos/owner/repo/pulls/42/merge").mock(
                return_value=httpx.Response(200, json={"merged": True, "sha": "abc"})
            )

            result = await github_client.merge_pr(
                "owner/repo", 42, _TEST_INSTALLATION_ID
            )
            assert result["merged"] is True

    async def test_409_raises_merge_conflict(self, github_client: GitHubClient) -> None:
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            mock.put("/repos/owner/repo/pulls/42/merge").mock(
                return_value=httpx.Response(409, json={"message": "Conflict"})
            )

            with pytest.raises(GitHubMergeConflictError):
                await github_client.merge_pr(
                    "owner/repo", 42, _TEST_INSTALLATION_ID
                )


# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limit
# ═══════════════════════════════════════════════════════════════════════════════


class TestRateLimit:
    async def test_zero_remaining_warns_but_returns_response(
        self, github_client: GitHubClient
    ) -> None:
        """A 200 with Remaining: 0 should return the response (not raise)."""
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            mock.get("/repos/owner/repo/pulls/1").mock(
                return_value=httpx.Response(
                    200,
                    text="diff --git a/file.py",
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "1700000000",
                    },
                )
            )

            result = await github_client.get_pr_diff("owner/repo", 1, _TEST_INSTALLATION_ID)
            assert result == "diff --git a/file.py"

    async def test_403_rate_limit_raises(self, github_client: GitHubClient) -> None:
        """A 403 with 'rate limit' in the body should raise GitHubRateLimitError."""
        from src.github.exceptions import GitHubRateLimitError

        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            mock.get("/repos/owner/repo/pulls/1").mock(
                return_value=httpx.Response(
                    403,
                    json={"message": "API rate limit exceeded"},
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": "1700000000",
                    },
                )
            )

            with pytest.raises(GitHubRateLimitError) as exc_info:
                await github_client.get_pr_diff("owner/repo", 1, _TEST_INSTALLATION_ID)

            assert exc_info.value.reset_timestamp == 1700000000.0


# ═══════════════════════════════════════════════════════════════════════════════
# Clone Repo
# ═══════════════════════════════════════════════════════════════════════════════


class TestCloneRepo:
    async def test_clone_calls_git_with_correct_args(
        self, github_client: GitHubClient, tmp_path: Path
    ) -> None:
        target = tmp_path / "repo"

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("src.github.client.asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await github_client.clone_repo(
                "https://github.com/owner/repo.git", target, "main"
            )

            mock_exec.assert_called_once()
            args = mock_exec.call_args[0]
            assert args[0] == "git"
            assert "clone" in args
            assert "--depth=1" in args
            assert "--single-branch" in args
            assert "--branch" in args
            assert "main" in args
            assert "https://github.com/owner/repo.git" in args
            assert str(target) in args

    async def test_clone_failure_raises_error(
        self, github_client: GitHubClient, tmp_path: Path
    ) -> None:
        target = tmp_path / "repo"

        mock_proc = AsyncMock()
        mock_proc.returncode = 128
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"fatal: repository not found")
        )

        with patch("src.github.client.asyncio.create_subprocess_exec", return_value=mock_proc):
            with pytest.raises(GitHubError, match="git clone failed"):
                await github_client.clone_repo(
                    "https://github.com/owner/nonexistent.git", target, "main"
                )

    async def test_clone_rejects_unsafe_url(
        self, github_client: GitHubClient, tmp_path: Path
    ) -> None:
        """URLs not matching https://github.com/... should be rejected."""
        with pytest.raises(GitHubError, match="unsafe URL"):
            await github_client.clone_repo(
                "ext::sh -c evil", tmp_path / "repo", "main"
            )

    async def test_clone_rejects_unsafe_branch(
        self, github_client: GitHubClient, tmp_path: Path
    ) -> None:
        """Branch names that could be interpreted as git flags are rejected."""
        with pytest.raises(GitHubError, match="unsafe branch"):
            await github_client.clone_repo(
                "https://github.com/owner/repo.git",
                tmp_path / "repo",
                "--upload-pack=evil",
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Retry Logic
# ═══════════════════════════════════════════════════════════════════════════════


class TestRetry:
    async def test_retries_on_502_then_succeeds(self, github_client: GitHubClient) -> None:
        """A transient 502 followed by a 200 should succeed after one retry."""
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            route = mock.get("/repos/owner/repo/pulls/1")
            route.side_effect = [
                httpx.Response(502, text="Bad Gateway"),
                httpx.Response(200, text="diff --git a/file.py"),
            ]

            result = await github_client.get_pr_diff("owner/repo", 1, _TEST_INSTALLATION_ID)

            assert result == "diff --git a/file.py"
            assert route.call_count == 2

    async def test_retries_on_network_error_then_succeeds(
        self, github_client: GitHubClient
    ) -> None:
        """A transient network error followed by success should retry transparently."""
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            route = mock.get("/repos/owner/repo/pulls/1")
            route.side_effect = [
                httpx.ConnectError("Connection refused"),
                httpx.Response(200, text="diff text"),
            ]

            result = await github_client.get_pr_diff("owner/repo", 1, _TEST_INSTALLATION_ID)

            assert result == "diff text"
            assert route.call_count == 2

    async def test_exhausted_retries_raises(self, github_client: GitHubClient) -> None:
        """All retries returning 500 should raise GitHubError."""
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            mock.get("/repos/owner/repo/pulls/1").mock(
                return_value=httpx.Response(500, text="Internal Server Error")
            )

            with pytest.raises(GitHubError, match="500"):
                await github_client.get_pr_diff("owner/repo", 1, _TEST_INSTALLATION_ID)

    async def test_no_retry_on_4xx(self, github_client: GitHubClient) -> None:
        """4xx errors (non-retryable) should fail immediately without retry."""
        with respx.mock(base_url=_GITHUB_API_BASE) as mock:
            mock.post(url__regex=r"/app/installations/.*/access_tokens").mock(
                return_value=_mock_token_response()
            )
            route = mock.get("/repos/owner/repo/pulls/1").mock(
                return_value=httpx.Response(404, json={"message": "Not Found"})
            )

            with pytest.raises(GitHubNotFoundError):
                await github_client.get_pr_diff("owner/repo", 1, _TEST_INSTALLATION_ID)

            assert route.call_count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Circuit Breaker
# ═══════════════════════════════════════════════════════════════════════════════


class TestCircuitBreaker:
    def test_starts_closed(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, cooldown_seconds=10.0)
        assert cb.state == _CircuitState.CLOSED

    def test_opens_after_threshold_failures(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, cooldown_seconds=10.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == _CircuitState.OPEN

    def test_stays_closed_below_threshold(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, cooldown_seconds=10.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == _CircuitState.CLOSED

    def test_success_resets_failure_count(self) -> None:
        cb = _CircuitBreaker(failure_threshold=3, cooldown_seconds=10.0)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        # Only 1 failure since last success — should still be closed
        assert cb.state == _CircuitState.CLOSED

    def test_check_raises_when_open(self) -> None:
        cb = _CircuitBreaker(failure_threshold=1, cooldown_seconds=60.0)
        cb.record_failure()
        assert cb.state == _CircuitState.OPEN
        with pytest.raises(GitHubError, match="Circuit breaker open"):
            cb.check()

    def test_transitions_to_half_open_after_cooldown(self) -> None:
        cb = _CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        cb.record_failure()
        # With 0s cooldown, should immediately transition to half-open
        assert cb.state == _CircuitState.HALF_OPEN

    def test_half_open_to_closed_on_success(self) -> None:
        cb = _CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        cb.record_failure()
        assert cb.state == _CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == _CircuitState.CLOSED

    def test_half_open_to_open_on_failure(self) -> None:
        cb = _CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        cb.record_failure()
        assert cb.state == _CircuitState.HALF_OPEN
        # A failure in half-open should re-open with a fresh cooldown.
        # Use a long cooldown so the state property doesn't immediately transition back.
        cb._cooldown_seconds = 60.0
        cb.record_failure()
        assert cb.state == _CircuitState.OPEN

    async def test_circuit_breaker_blocks_requests(
        self, github_client: GitHubClient
    ) -> None:
        """Once the circuit opens, subsequent requests should fail fast."""
        # Manually open the circuit for the test installation
        cb = github_client._get_circuit_breaker(_TEST_INSTALLATION_ID)
        for _ in range(5):
            cb.record_failure()

        with pytest.raises(GitHubError, match="Circuit breaker open"):
            await github_client.get_pr_diff("owner/repo", 1, _TEST_INSTALLATION_ID)


# ═══════════════════════════════════════════════════════════════════════════════
# Cleanup
# ═══════════════════════════════════════════════════════════════════════════════


class TestClose:
    async def test_close_shuts_down_client(self, github_client: GitHubClient) -> None:
        await github_client.close()
        assert github_client._client.is_closed
