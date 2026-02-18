"""Shared security validation utilities.

Single source of truth for git-related input validation and credential
scrubbing.  Consumed by both :mod:`src.github.client` and the pipeline
stages.
"""

from __future__ import annotations

import re

# ── Clone-URL / branch allowlists ────────────────────────────────────────────

# Only HTTPS GitHub URLs — prevents SSRF via file://, ssh://, or internal IPs.
SAFE_CLONE_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+(?:\.git)?$"
)

# No leading dashes, no control chars, no "..", reasonable length.
SAFE_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,255}$")

# ── Token patterns ───────────────────────────────────────────────────────────

# Matches GitHub fine-grained PATs, classic PATs, installation tokens,
# and ``x-access-token:<secret>@`` in clone URLs.
_TOKEN_RE = re.compile(
    r"(ghs_[A-Za-z0-9]{36}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|github_pat_[A-Za-z0-9_]{82}"
    r"|x-access-token:[^\s@]+)"
)


# ── Public helpers ───────────────────────────────────────────────────────────


def validate_clone_url(url: str) -> None:
    """Reject non-HTTPS or non-GitHub clone URLs (SSRF prevention).

    Raises :class:`ValueError` for disallowed URLs.
    """
    if not SAFE_CLONE_URL_RE.match(url):
        raise ValueError(f"Refusing clone: unsafe URL: {url}")


def validate_branch_name(branch: str) -> None:
    """Reject branch names with control chars, ``..``, or leading dashes.

    Raises :class:`ValueError` for disallowed branch names.
    """
    if ".." in branch or not SAFE_BRANCH_RE.match(branch):
        raise ValueError(f"Refusing clone: unsafe branch name: {branch}")


def scrub_tokens(text: str) -> str:
    """Replace GitHub auth tokens in *text* with ``***``.

    Defense-in-depth: the URL regex already blocks auth-bearing URLs,
    but this protects against future regex relaxation or tokens appearing
    in unexpected places (e.g. git stderr).
    """
    return _TOKEN_RE.sub("***", text)


# ── Prompt injection detection ──────────────────────────────────────────────

_INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|rules|prompts)",
        re.IGNORECASE,
    ),
    "role_assumption": re.compile(
        r"you\s+are\s+now\s+(a|an|the)\s+",
        re.IGNORECASE,
    ),
    "identity_override": re.compile(
        r"(forget|disregard)\s+(your|all)\s+(instructions|rules|identity|purpose)",
        re.IGNORECASE,
    ),
    "xml_tag_escape": re.compile(
        r"</\s*(pr_diff|vision_document|system|assistant)\s*>",
        re.IGNORECASE,
    ),
    "new_instructions": re.compile(
        r"(new|updated|revised)\s+instructions?\s*:",
        re.IGNORECASE,
    ),
    "prompt_leak": re.compile(
        r"(repeat|reveal|show|print)\s+(your|the)\s+(system\s+)?(prompt|instructions)",
        re.IGNORECASE,
    ),
}

_XML_CLOSING_TAG_RE = re.compile(
    r"</\s*(pr_diff|vision_document|system|assistant)\s*>",
    re.IGNORECASE,
)


def detect_injection_markers(text: str) -> list[str]:
    """Scan *text* for common prompt-injection patterns.

    Returns a list of matched marker names (e.g. ``["ignore_instructions",
    "xml_tag_escape"]``).  An empty list means no patterns were detected.
    """
    return [
        name
        for name, pattern in _INJECTION_PATTERNS.items()
        if pattern.search(text)
    ]


def neutralize_xml_closing_tags(text: str) -> str:
    """Escape XML closing tags that could break prompt boundaries.

    Replaces ``</pr_diff>``, ``</vision_document>``, etc. with their
    HTML-entity equivalents so the LLM sees them as literal text rather
    than structural delimiters.
    """
    def _escape(m: re.Match[str]) -> str:
        return f"&lt;/{m.group(1)}&gt;"

    return _XML_CLOSING_TAG_RE.sub(_escape, text)
