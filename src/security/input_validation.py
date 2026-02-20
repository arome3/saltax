"""Boundary input sanitization for all external inputs.

Pure functions, no I/O, no async.  Applied at the webhook ingress layer
before any data reaches the pipeline or AI analyzer.
"""

from __future__ import annotations

import re

from src.security import neutralize_injection_patterns, neutralize_xml_closing_tags

# ── Compile-once regexes ─────────────────────────────────────────────────────

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SCRIPT_TAG_RE = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_JS_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,100}/[A-Za-z0-9._\-]{1,100}$")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

_MAX_TITLE_LEN = 256
_MAX_BODY_LEN = 65_536
_MAX_DIFF_LEN = 1_048_576  # 1 MB


# ── PR title / body sanitization ─────────────────────────────────────────────


def sanitize_pr_title(title: str) -> str:
    """Sanitize a PR title from webhook input.

    1. Strip control chars
    2. Neutralize XML closing tags
    3. Neutralize injection patterns (replaces spans, not keywords)
    4. Truncate to 256 chars
    5. Strip whitespace
    6. Return ``"[untitled]"`` if empty
    """
    result = _CONTROL_CHAR_RE.sub("", title)
    result = neutralize_xml_closing_tags(result)
    result = neutralize_injection_patterns(result)
    result = result[:_MAX_TITLE_LEN]
    result = result.strip()
    return result if result else "[untitled]"


def sanitize_pr_body(body: str | None) -> str | None:
    """Sanitize a PR body from webhook input.

    Returns ``None`` if input is ``None``.  Otherwise:
    1. Strip control chars
    2. Strip ``<script>`` tags and ``javascript:`` URIs
    3. Neutralize XML closing tags
    4. Neutralize injection patterns
    5. Truncate to 64 KB
    6. Strip whitespace
    """
    if body is None:
        return None

    result = _CONTROL_CHAR_RE.sub("", body)
    result = _SCRIPT_TAG_RE.sub("", result)
    result = _JS_URI_RE.sub("", result)
    result = neutralize_xml_closing_tags(result)
    result = neutralize_injection_patterns(result)
    result = result[:_MAX_BODY_LEN]
    result = result.strip()
    return result


# ── Diff sanitization ────────────────────────────────────────────────────────


def sanitize_diff(diff: str) -> str:
    r"""Sanitize a diff fetched from GitHub.

    1. Strip null bytes (``\x00``)
    2. Truncate to 1 MB

    Does NOT strip injection patterns — the AI analyzer handles
    detection separately and needs to see the raw content.
    """
    result = diff.replace("\x00", "")
    return result[:_MAX_DIFF_LEN]


# ── Field validators ─────────────────────────────────────────────────────────


def validate_repo_name(repo: str) -> None:
    """Validate a ``owner/name`` repository identifier.

    Raises :class:`ValueError` on invalid input (path traversal,
    missing slash, overlength, etc.).
    """
    if not _REPO_NAME_RE.match(repo):
        raise ValueError(f"Invalid repository name: {repo!r}")


def validate_commit_sha(sha: str) -> None:
    """Validate a 40-character hex commit SHA.

    Raises :class:`ValueError` on invalid input.
    """
    if not _COMMIT_SHA_RE.match(sha):
        raise ValueError(f"Invalid commit SHA: {sha!r}")
