"""File metrics and centrality computation for codebase graph indexing."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.indexing.models import FileNode, ImportEdge

# ── LOC counting ─────────────────────────────────────────────────────────────

_SINGLE_LINE_COMMENT_RE = re.compile(r"^\s*(?:#|//)")


def count_loc(source: str) -> int:
    """Count non-blank, non-comment lines of code.

    Handles ``#``, ``//`` single-line comments and ``/* ... */`` block comments.
    """
    count = 0
    in_block = False

    for line in source.splitlines():
        stripped = line.strip()

        # Track block comment state
        if in_block:
            if "*/" in stripped:
                in_block = False
            continue

        if "/*" in stripped:
            # Check if block comment closes on same line
            if "*/" not in stripped or stripped.index("/*") > stripped.index("*/"):
                in_block = True
            continue

        # Skip blank lines
        if not stripped:
            continue

        # Skip single-line comments
        if _SINGLE_LINE_COMMENT_RE.match(stripped):
            continue

        count += 1

    return count


# ── Function/class counting ──────────────────────────────────────────────────

_PY_FUNCTION_RE = re.compile(r"^\s*(?:async\s+)?def\s+\w+", re.MULTILINE)
_PY_CLASS_RE = re.compile(r"^\s*class\s+\w+", re.MULTILINE)

_JS_FUNCTION_RE = re.compile(
    r"(?:"
    r"(?:export\s+)?(?:async\s+)?function\s+\w+"          # function declarations
    r"|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w]+)\s*=>"  # arrow functions
    r")",
    re.MULTILINE,
)
_JS_CLASS_RE = re.compile(r"(?:export\s+)?class\s+\w+", re.MULTILINE)


def count_functions(source: str, language: str) -> int:
    """Count function definitions in source code for the given language."""
    if language == "python":
        return len(_PY_FUNCTION_RE.findall(source))
    if language in ("javascript", "typescript"):
        return len(_JS_FUNCTION_RE.findall(source))
    return 0


def count_classes(source: str, language: str) -> int:
    """Count class definitions in source code for the given language."""
    if language == "python":
        return len(_PY_CLASS_RE.findall(source))
    if language in ("javascript", "typescript"):
        return len(_JS_CLASS_RE.findall(source))
    return 0


# ── PageRank centrality ─────────────────────────────────────────────────────


def compute_pagerank(
    nodes: dict[str, FileNode],
    edges: list[ImportEdge],
    *,
    damping: float = 0.85,
    iterations: int = 20,
) -> dict[str, float]:
    """Compute PageRank centrality for each file in the codebase graph.

    Parameters
    ----------
    nodes:
        Mapping of file_path → FileNode for all files in the graph.
    edges:
        All resolved internal import edges (``target_file`` is not None,
        ``is_external`` is False).
    damping:
        Damping factor (probability of following a link). Standard value 0.85.
    iterations:
        Number of power iterations. 20 is sufficient for small-medium graphs.

    Returns
    -------
    dict[str, float]
        Mapping of file_path → PageRank score, normalized to [0.0, 1.0].
    """
    n = len(nodes)
    if n == 0:
        return {}
    if n == 1:
        path = next(iter(nodes))
        return {path: 1.0}

    # Build adjacency: outgoing edges per file
    outgoing: dict[str, list[str]] = {path: [] for path in nodes}
    for edge in edges:
        if edge.target_file is not None and edge.source_file in outgoing:
            outgoing[edge.source_file].append(edge.target_file)

    # Initialize uniform scores
    base = (1.0 - damping) / n
    scores: dict[str, float] = {path: 1.0 / n for path in nodes}

    # Power iteration
    for _ in range(iterations):
        new_scores: dict[str, float] = {}
        for path in nodes:
            rank = base
            # Accumulate incoming contributions — iterate all nodes and check
            # if they link to this path
            new_scores[path] = rank
        # Two-pass: first compute contributions, then distribute
        contributions: dict[str, float] = {path: 0.0 for path in nodes}
        for source, targets in outgoing.items():
            if not targets:
                # Dangling node: distribute rank equally to all nodes
                share = scores[source] / n
                for path in nodes:
                    contributions[path] += share
            else:
                share = scores[source] / len(targets)
                for target in targets:
                    if target in contributions:
                        contributions[target] += share
        for path in nodes:
            new_scores[path] = base + damping * contributions[path]
        scores = new_scores

    # Normalize to [0.0, 1.0]
    max_score = max(scores.values()) if scores else 1.0
    if max_score > 0:
        scores = {path: score / max_score for path, score in scores.items()}

    return scores
