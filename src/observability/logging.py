"""Structured JSON logging with sensitive field redaction.

Replaces the inline ``_configure_logging()`` that lived in ``main.py``.
The :class:`SensitiveFieldFilter` scrubs secrets from log record attributes
before the JSON formatter serialises them, preventing accidental credential
leakage in structured log output.
"""

from __future__ import annotations

import logging
import os
import sys

# ── Sensitive field patterns ─────────────────────────────────────────────────

_SENSITIVE_FIELDS: frozenset[str] = frozenset({
    "private_key",
    "api_key",
    "webhook_secret",
    "password",
    "secret",
    "token",
    "authorization",
    "cookie",
    "mnemonic",
    "credential",
})

_SENSITIVE_SUBSTRINGS: tuple[str, ...] = (
    "_key",
    "_secret",
    "_token",
    "_password",
    "_credential",
    "bearer",
    "jwt",
)

_REDACTED = "[REDACTED]"


# ── Filter ───────────────────────────────────────────────────────────────────


class SensitiveFieldFilter(logging.Filter):
    """Redact values of sensitive fields on every log record.

    Iterates ``record.__dict__`` and replaces string values whose key matches
    either an exact entry in :data:`_SENSITIVE_FIELDS` or contains one of
    :data:`_SENSITIVE_SUBSTRINGS`.  Always returns ``True`` (never drops a
    record).
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        for key in list(record.__dict__):
            lower = key.lower()
            is_sensitive = lower in _SENSITIVE_FIELDS or any(
                sub in lower for sub in _SENSITIVE_SUBSTRINGS
            )
            if is_sensitive and isinstance(
                record.__dict__[key], str | bytes | bytearray | dict | list,
            ):
                record.__dict__[key] = _REDACTED
        return True


# ── Formatter construction ───────────────────────────────────────────────────


def _build_json_formatter() -> logging.Formatter:
    """Build a JSON log formatter, falling back to stdlib if library missing."""
    try:
        from pythonjsonlogger.jsonlogger import JsonFormatter  # noqa: PLC0415

        return JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    except ImportError:
        print(  # noqa: T201
            "WARNING: python-json-logger not installed, "
            "falling back to stdlib formatter",
            file=sys.stderr,
        )
        return logging.Formatter(
            '{"time": "%(asctime)s", "name": "%(name)s", '
            '"level": "%(levelname)s", "message": "%(message)s"}'
        )


# ── Public configure function ────────────────────────────────────────────────


def configure_logging() -> None:
    """Install JSON-formatted, secret-redacted logging on the root logger.

    Reads ``SALTAX_LOG_LEVEL`` from the environment (before
    :class:`~src.config.EnvConfig` is available) and defaults to ``INFO``.

    Idempotent — safe to call more than once (clears handlers first).
    """
    level_name = os.environ.get("SALTAX_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    formatter = _build_json_formatter()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(SensitiveFieldFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

