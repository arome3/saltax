"""Extract target issue numbers from PR metadata.

Pure extraction — no I/O, no async.  Used by the ranking module to link
PRs to the GitHub issues they intend to resolve.
"""

from __future__ import annotations

import re

# Closing keywords recognized by GitHub, case-insensitive.
# Covers: fix, fixes, fixed, close, closes, closed, resolve, resolves, resolved
_CLOSING_KEYWORD_RE = re.compile(
    r"(?:fix(?:e[sd])?|close[sd]?|resolve[sd]?)\s+#(\d+)",
    re.IGNORECASE,
)

# Branch naming conventions that embed an issue number.
# Matches: fix-123, issue/456, bug-789, feat/42
_BRANCH_ISSUE_RE = re.compile(
    r"(?:fix|issue|bug|feat)[/-](\d+)",
    re.IGNORECASE,
)


def extract_target_issue(
    *,
    title: str,
    body: str | None,
    head_branch: str,
) -> int | None:
    """Return the issue number a PR targets, or ``None`` if undetectable.

    Priority: title → body → branch name.  When multiple issues are
    referenced, only the first match is returned (documented limitation).
    """
    # 1. Title — most intentional reference
    match = _CLOSING_KEYWORD_RE.search(title)
    if match:
        return int(match.group(1))

    # 2. Body — detailed description
    if body:
        match = _CLOSING_KEYWORD_RE.search(body)
        if match:
            return int(match.group(1))

    # 3. Branch name — convention-based
    match = _BRANCH_ISSUE_RE.search(head_branch)
    if match:
        return int(match.group(1))

    return None
