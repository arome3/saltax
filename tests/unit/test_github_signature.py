"""Tests for GitHub webhook HMAC signature verification."""

from __future__ import annotations

import hashlib
import hmac

from src.api.middleware.github_signature import verify_github_signature

_SECRET = "test-webhook-secret"


def _sign(payload: bytes, secret: str = _SECRET) -> str:
    """Compute a valid sha256 signature header."""
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


class TestVerifySignature:
    def test_valid_signature(self) -> None:
        payload = b'{"action": "opened"}'
        sig = _sign(payload)
        assert verify_github_signature(payload, sig, _SECRET) is True

    def test_invalid_signature(self) -> None:
        payload = b'{"action": "opened"}'
        assert verify_github_signature(payload, "sha256=badhex", _SECRET) is False

    def test_missing_sha256_prefix(self) -> None:
        payload = b'{"action": "opened"}'
        sig = _sign(payload).removeprefix("sha256=")
        assert verify_github_signature(payload, sig, _SECRET) is False

    def test_empty_payload(self) -> None:
        payload = b""
        sig = _sign(payload)
        assert verify_github_signature(payload, sig, _SECRET) is True

    def test_wrong_secret(self) -> None:
        payload = b'{"action": "opened"}'
        sig = _sign(payload, secret="wrong-secret")
        assert verify_github_signature(payload, sig, _SECRET) is False

    def test_empty_header(self) -> None:
        payload = b'{"action": "opened"}'
        assert verify_github_signature(payload, "", _SECRET) is False
