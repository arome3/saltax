"""Classified error hierarchy for SaltaX.

Each error class maps to a specific HTTP status code and operational
meaning, enabling structured error handling in the API layer.
"""

from __future__ import annotations


class SaltaXError(Exception):
    """Base class for all SaltaX domain errors."""

    http_status: int = 500


class TransientError(SaltaXError):
    """Upstream timeout, rate limit, or 502/503/504.

    Indicates the operation may succeed on retry.
    """

    http_status: int = 503


class DegradedError(SaltaXError):
    """Non-critical dependency unavailable (e.g. EigenAI down).

    The request can still complete with reduced quality.
    Response: 200 + ``X-SaltaX-Degraded: true`` header.
    """

    http_status: int = 200


class DataError(SaltaXError):
    """Malformed input or unparseable output.

    Response: 400 Bad Request.
    """

    http_status: int = 400


class CriticalError(SaltaXError):
    """Wallet key lost, KMS unreachable, DB corruption.

    Response: 500 Internal Server Error.
    """

    http_status: int = 500


class SecurityError(SaltaXError):
    """Invalid signature, forged payment, injection detected.

    Response: 403 Forbidden (no detail to prevent oracle attacks).
    """

    http_status: int = 403
