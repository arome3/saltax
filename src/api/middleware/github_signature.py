"""HMAC-SHA256 signature verification for GitHub webhook payloads."""

from __future__ import annotations

import hashlib
import hmac
import logging

logger = logging.getLogger(__name__)


def verify_github_signature(
    payload_body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """Verify a GitHub webhook ``X-Hub-Signature-256`` header.

    Parameters
    ----------
    payload_body:
        Raw request body bytes.
    signature_header:
        Value of the ``X-Hub-Signature-256`` header (e.g. ``sha256=abc...``).
    secret:
        The webhook secret configured for the GitHub App.

    Returns
    -------
    bool
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    if not signature_header.startswith("sha256="):
        logger.warning("Signature header missing sha256= prefix")
        return False

    expected_sig = hmac.new(
        secret.encode(),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    received_sig = signature_header.removeprefix("sha256=")

    if hmac.compare_digest(expected_sig, received_sig):
        return True

    logger.warning("GitHub webhook signature mismatch")
    return False
