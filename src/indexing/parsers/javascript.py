"""JavaScript/TypeScript import extraction via regex parsing."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from src.indexing.models import ImportEdge

if TYPE_CHECKING:
    from pathlib import Path

# Matches:
#   import ... from '...'  |  import ... from "..."
#   require('...')  |  require("...")
#   import('...')  |  import("...")
#   export ... from '...'  |  export ... from "..."
_JS_IMPORT_RE = re.compile(
    r"""(?:"""
    r"""import\s+(?:[\w{},*\s]+\s+from\s+)?['"]([^'"]+)['"]"""  # import/from
    r"""|require\(\s*['"]([^'"]+)['"]\s*\)"""                    # require()
    r"""|import\(\s*['"]([^'"]+)['"]\s*\)"""                     # dynamic import()
    r"""|export\s+(?:[\w{},*\s]+\s+from\s+)['"]([^'"]+)['"]"""  # export from
    r""")""",
    re.MULTILINE,
)

# Extensions to try when resolving relative imports
_JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx")
_JS_INDEX_FILES = ("index.js", "index.jsx", "index.ts", "index.tsx")


def _resolve_js_module(
    specifier: str,
    file_path: str,
    repo_root: Path,
) -> str | None:
    """Resolve a relative JS/TS import specifier to a file path.

    Returns the path relative to *repo_root*, or ``None`` if not found.
    """
    file_dir = (repo_root / file_path).parent
    target = (file_dir / specifier).resolve()

    # Exact match (e.g. './foo.js')
    if target.is_file():
        try:
            return str(target.relative_to(repo_root))
        except ValueError:
            return None

    # Extension fallback (e.g. './foo' → 'foo.ts')
    for ext in _JS_EXTENSIONS:
        candidate = target.with_suffix(ext)
        if candidate.is_file():
            try:
                return str(candidate.relative_to(repo_root))
            except ValueError:
                return None

    # Directory index fallback (e.g. './components' → 'components/index.tsx')
    if target.is_dir():
        for idx in _JS_INDEX_FILES:
            candidate = target / idx
            if candidate.is_file():
                try:
                    return str(candidate.relative_to(repo_root))
                except ValueError:
                    return None

    return None


def extract_js_imports(
    source: str,
    file_path: str,
    repo_root: Path,
) -> list[ImportEdge]:
    """Extract import edges from JavaScript/TypeScript source code.

    Parameters
    ----------
    source:
        Raw JS/TS source code.
    file_path:
        Path of the source file relative to *repo_root*.
    repo_root:
        Absolute path to the repository root.

    Returns
    -------
    list[ImportEdge]
        Edges to resolved internal files or external packages.
    """
    edges: list[ImportEdge] = []

    for match in _JS_IMPORT_RE.finditer(source):
        specifier = match.group(1) or match.group(2) or match.group(3) or match.group(4)
        if not specifier:
            continue

        line_number = source[:match.start()].count("\n") + 1
        is_relative = (
            specifier.startswith("./")
            or specifier.startswith("../")
            or specifier.startswith("/")
        )

        if is_relative:
            resolved = _resolve_js_module(specifier, file_path, repo_root)
            edges.append(ImportEdge(
                source_file=file_path,
                target_module=specifier,
                target_file=resolved,
                is_external=False,
                line_number=line_number,
            ))
        else:
            edges.append(ImportEdge(
                source_file=file_path,
                target_module=specifier,
                is_external=True,
                line_number=line_number,
            ))

    return edges
