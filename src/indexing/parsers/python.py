"""Python import extraction via regex parsing."""

from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING

from src.indexing.models import ImportEdge

if TYPE_CHECKING:
    from pathlib import Path

# Matches: import foo.bar  |  from foo.bar import baz
_IMPORT_RE = re.compile(
    r"^(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))",
    re.MULTILINE,
)

# Matches: from . import x  |  from ..pkg import y
_RELATIVE_IMPORT_RE = re.compile(
    r"^from\s+(\.+)([\w.]*)\s+import",
    re.MULTILINE,
)

_STDLIB_MODULES = sys.stdlib_module_names


def _resolve_python_module(
    module: str,
    repo_root: Path,
) -> str | None:
    """Try to resolve a dotted Python module to a file path relative to repo root.

    Returns the relative path (e.g. ``src/config.py``) or ``None`` if not found.
    """
    parts = module.replace(".", "/")

    # Try as a .py file
    candidate = repo_root / f"{parts}.py"
    if candidate.is_file():
        return str(candidate.relative_to(repo_root))

    # Try as a package (__init__.py)
    candidate = repo_root / parts / "__init__.py"
    if candidate.is_file():
        return str(candidate.relative_to(repo_root))

    return None


def extract_python_imports(
    source: str,
    file_path: str,
    repo_root: Path,
) -> list[ImportEdge]:
    """Extract import edges from Python source code.

    Parameters
    ----------
    source:
        The raw Python source code.
    file_path:
        Path of the source file relative to *repo_root*.
    repo_root:
        Absolute path to the repository root.

    Returns
    -------
    list[ImportEdge]
        Edges to resolved internal files or external packages.
        Stdlib imports are excluded.
    """
    edges: list[ImportEdge] = []
    file_dir = (repo_root / file_path).parent

    # Absolute imports
    for match in _IMPORT_RE.finditer(source):
        module = match.group(1) or match.group(2)
        if not module:
            continue

        line_number = source[:match.start()].count("\n") + 1
        top_level = module.split(".")[0]

        # Skip stdlib
        if top_level in _STDLIB_MODULES:
            continue

        resolved = _resolve_python_module(module, repo_root)
        if resolved is not None:
            edges.append(ImportEdge(
                source_file=file_path,
                target_module=module,
                target_file=resolved,
                is_external=False,
                line_number=line_number,
            ))
        else:
            edges.append(ImportEdge(
                source_file=file_path,
                target_module=module,
                is_external=True,
                line_number=line_number,
            ))

    # Relative imports (from . import x, from ..pkg import y)
    for match in _RELATIVE_IMPORT_RE.finditer(source):
        dots = match.group(1)
        module_part = match.group(2)
        line_number = source[:match.start()].count("\n") + 1

        # Navigate up directories based on dot count
        target_dir = file_dir
        for _ in range(len(dots) - 1):
            target_dir = target_dir.parent

        if module_part:
            rel_parts = module_part.replace(".", "/")
            # Try as .py file
            candidate = target_dir / f"{rel_parts}.py"
            if candidate.is_file():
                resolved = str(candidate.relative_to(repo_root))
                edges.append(ImportEdge(
                    source_file=file_path,
                    target_module=f"{dots}{module_part}",
                    target_file=resolved,
                    line_number=line_number,
                ))
                continue
            # Try as package
            candidate = target_dir / rel_parts / "__init__.py"
            if candidate.is_file():
                resolved = str(candidate.relative_to(repo_root))
                edges.append(ImportEdge(
                    source_file=file_path,
                    target_module=f"{dots}{module_part}",
                    target_file=resolved,
                    line_number=line_number,
                ))
                continue

        # Try the directory itself as __init__.py
        candidate = target_dir / "__init__.py"
        if candidate.is_file():
            resolved = str(candidate.relative_to(repo_root))
            edges.append(ImportEdge(
                source_file=file_path,
                target_module=f"{dots}{module_part}",
                target_file=resolved,
                line_number=line_number,
            ))

    return edges
