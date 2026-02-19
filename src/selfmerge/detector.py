"""Self-modification detection for SaltaX sovereignty boundary.

Pure functions — no shared state, no I/O, no locks.
"""

from __future__ import annotations

import re

SELF_MODIFICATION_PATHS: frozenset[str] = frozenset({
    "src/",
    "saltax.config.yaml",
    "Dockerfile",
    "pyproject.toml",
    "github-proxy/src/",
})

# Matches: diff --git a/foo b/bar  (unquoted paths, no spaces)
_DIFF_GIT_RE = re.compile(r"^diff --git a/\S+ b/(\S+)$", re.MULTILINE)
# Matches: diff --git "a/path with spaces" "b/path with spaces"  (quoted)
_DIFF_GIT_QUOTED_RE = re.compile(r'^diff --git "a/.+" "b/(.+)"$', re.MULTILINE)
# Matches: rename to <path>
_RENAME_TO_RE = re.compile(r"^rename to (.+)$", re.MULTILINE)
# Matches: +++ b/<path>  (but not +++ /dev/null)
_PLUS_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
# Matches: --- a/<path>  (but not --- /dev/null)
_MINUS_RE = re.compile(r"^--- a/(.+)$", re.MULTILINE)

# Partition protected paths into directory prefixes vs exact file names.
_DIR_PREFIXES: tuple[str, ...] = tuple(
    p for p in SELF_MODIFICATION_PATHS if p.endswith("/")
)
_EXACT_FILES: frozenset[str] = frozenset(
    p for p in SELF_MODIFICATION_PATHS if not p.endswith("/")
)


def extract_modified_files(diff: str) -> frozenset[str]:
    """Extract deduplicated file paths from a unified diff.

    Handles standard changes, new files, deleted files, renames, and binary
    files by parsing ``diff --git``, ``rename to``, and ``+++ b/`` headers.
    """
    paths: set[str] = set()
    paths.update(_DIFF_GIT_RE.findall(diff))
    paths.update(_DIFF_GIT_QUOTED_RE.findall(diff))
    paths.update(_RENAME_TO_RE.findall(diff))
    paths.update(_PLUS_RE.findall(diff))
    paths.update(_MINUS_RE.findall(diff))
    return frozenset(paths)


def is_self_modification(modified_files: frozenset[str]) -> bool:
    """Return ``True`` if any *modified_files* fall within protected paths."""
    for path in modified_files:
        if path in _EXACT_FILES:
            return True
        for prefix in _DIR_PREFIXES:
            if path.startswith(prefix):
                return True
    return False
