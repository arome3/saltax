"""Codebase graph builder — walks a repo, extracts imports, computes centrality."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.indexing.metrics import (
    compute_pagerank,
    count_classes,
    count_functions,
    count_loc,
)
from src.indexing.models import FileNode, ImportEdge
from src.indexing.parsers import LANGUAGE_EXTENSIONS

if TYPE_CHECKING:
    from pathlib import Path

    from src.intelligence.database import IntelligenceDB

logger = logging.getLogger(__name__)

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", "venv", ".venv",
    "dist", "build", ".tox", ".mypy_cache", ".ruff_cache",
    ".pytest_cache", "egg-info", ".eggs", ".next", ".nuxt",
    "vendor", "target", "coverage", ".coverage",
})

_MAX_FILE_SIZE = 512 * 1024  # 512 KB


def _walk_source_files(repo_dir: Path) -> list[tuple[str, str]]:
    """Walk the repo and return ``(relative_path, language)`` for each source file.

    Skips directories in ``_SKIP_DIRS``, files larger than 512 KB,
    and files with unrecognized extensions.
    """
    results: list[tuple[str, str]] = []

    for path in repo_dir.rglob("*"):
        if not path.is_file():
            continue

        # Check if any parent directory should be skipped
        if any(part in _SKIP_DIRS for part in path.relative_to(repo_dir).parts):
            continue

        # Check extension
        language = LANGUAGE_EXTENSIONS.get(path.suffix)
        if language is None:
            continue

        # Check size
        try:
            if path.stat().st_size > _MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        rel_path = str(path.relative_to(repo_dir))
        results.append((rel_path, language))

    return results


def _extract_imports(
    source: str,
    file_path: str,
    language: str,
    repo_root: Path,
) -> list[ImportEdge]:
    """Dispatch to the appropriate language parser."""
    if language == "python":
        from src.indexing.parsers.python import extract_python_imports  # noqa: PLC0415

        return extract_python_imports(source, file_path, repo_root)

    if language in ("javascript", "typescript"):
        from src.indexing.parsers.javascript import extract_js_imports  # noqa: PLC0415

        return extract_js_imports(source, file_path, repo_root)

    # Go, Rust — recognized for metrics but no parser yet
    return []


async def build_codebase_graph(
    *,
    repo_dir: Path,
    repo: str,
    intel_db: IntelligenceDB,
    max_files: int,
) -> dict[str, Any]:
    """Build the codebase dependency graph and store results.

    Parameters
    ----------
    repo_dir:
        Absolute path to the cloned repository.
    repo:
        Repository slug (e.g. ``owner/repo``).
    intel_db:
        Intelligence database for storing knowledge entries.
    max_files:
        Maximum number of source files to index. Repos exceeding
        this limit are skipped.

    Returns
    -------
    dict
        Summary with keys: ``files_indexed``, ``edges_found``,
        ``external_deps``, ``languages``, and optionally ``skipped``.
    """
    run_start = datetime.now(UTC).isoformat()

    # Step 1: Walk source files
    files = _walk_source_files(repo_dir)

    if len(files) > max_files:
        logger.warning(
            "Repo %s has %d source files (limit %d), skipping indexing",
            repo, len(files), max_files,
        )
        return {"skipped": True, "file_count": len(files), "limit": max_files}

    if not files:
        logger.info("No source files found in %s", repo)
        return {"files_indexed": 0, "edges_found": 0, "external_deps": 0, "languages": {}}

    # Step 2: Parse each file — extract imports and compute metrics
    nodes: dict[str, FileNode] = {}
    all_edges: list[ImportEdge] = []
    language_counts: dict[str, int] = {}
    external_deps: set[str] = set()

    for rel_path, language in files:
        abs_path = repo_dir / rel_path
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.debug("Cannot read %s, skipping", rel_path)
            continue

        # Extract imports
        edges = _extract_imports(source, rel_path, language, repo_dir)
        all_edges.extend(edges)

        # Compute metrics
        loc = count_loc(source)
        func_count = count_functions(source, language)
        cls_count = count_classes(source, language)

        # Track external dependencies
        for edge in edges:
            if edge.is_external:
                external_deps.add(edge.target_module)

        nodes[rel_path] = FileNode(
            file_path=rel_path,
            language=language,
            loc=loc,
            function_count=func_count,
            class_count=cls_count,
            imports=edges,
        )
        language_counts[language] = language_counts.get(language, 0) + 1

    # Step 3: Build reverse edges (imported_by)
    for edge in all_edges:
        if edge.target_file is not None and not edge.is_external:
            target_node = nodes.get(edge.target_file)
            if target_node is not None:
                target_node.imported_by.append(edge.source_file)
                target_node.in_degree = len(target_node.imported_by)

    # Step 4: Compute centrality (PageRank + in-degree)
    internal_edges = [
        e for e in all_edges
        if e.target_file is not None and not e.is_external
    ]
    pagerank_scores = compute_pagerank(nodes, internal_edges)
    for path, score in pagerank_scores.items():
        nodes[path].centrality_score = score

    # Step 5: Store to database
    for node in nodes.values():
        knowledge_id = f"{repo}:{node.file_path}"
        await intel_db.store_codebase_knowledge(
            knowledge_id=knowledge_id,
            repo=repo,
            file_path=node.file_path,
            knowledge=node.to_knowledge_json(),
        )

    # Step 6: Clean up stale entries (files deleted from repo since last index)
    deleted_count = await intel_db.delete_stale_codebase_knowledge(repo, run_start)
    if deleted_count > 0:
        logger.info("Removed %d stale codebase knowledge entries for %s", deleted_count, repo)

    summary = {
        "files_indexed": len(nodes),
        "edges_found": len(internal_edges),
        "external_deps": len(external_deps),
        "languages": language_counts,
    }
    logger.info("Codebase graph for %s: %s", repo, summary)
    return summary
