"""Data models for codebase graph indexing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ImportEdge:
    """A directed edge from a source file to an imported module/file."""

    source_file: str
    target_module: str
    target_file: str | None = None
    is_external: bool = False
    line_number: int = 0


@dataclass
class FileNode:
    """A node in the codebase dependency graph representing a single source file."""

    file_path: str
    language: str
    loc: int = 0
    function_count: int = 0
    class_count: int = 0
    imports: list[ImportEdge] = field(default_factory=list)
    imported_by: list[str] = field(default_factory=list)
    centrality_score: float = 0.0  # PageRank (normalized 0.0–1.0)
    in_degree: int = 0  # Raw count of files that import this file

    def to_knowledge_json(self) -> str:
        """Serialize to JSON for codebase_knowledge.knowledge column."""
        internal_imports = [
            e.target_file for e in self.imports
            if e.target_file is not None and not e.is_external
        ]
        external_deps = sorted({
            e.target_module for e in self.imports if e.is_external
        })

        data = {
            "language": self.language,
            "loc": self.loc,
            "function_count": self.function_count,
            "class_count": self.class_count,
            "imports": internal_imports,
            "imported_by": self.imported_by,
            "external_deps": external_deps,
            "centrality": self.centrality_score,
            "in_degree": self.in_degree,
        }
        return json.dumps(data, separators=(",", ":"))
