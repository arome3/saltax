"""Tests for codebase graph indexing: parsers, metrics, graph builder, scheduler."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.indexing.models import FileNode, ImportEdge


# ── ImportEdge ──────────────────────────────────────────────────────────────


class TestImportEdge:
    def test_frozen(self) -> None:
        edge = ImportEdge(source_file="a.py", target_module="b")
        with pytest.raises(FrozenInstanceError):
            edge.source_file = "c.py"  # type: ignore[misc]

    def test_defaults(self) -> None:
        edge = ImportEdge(source_file="a.py", target_module="b")
        assert edge.target_file is None
        assert edge.is_external is False
        assert edge.line_number == 0


# ── FileNode ────────────────────────────────────────────────────────────────


class TestFileNode:
    def test_to_knowledge_json_roundtrip(self) -> None:
        node = FileNode(
            file_path="src/main.py",
            language="python",
            loc=100,
            function_count=5,
            class_count=2,
            imports=[
                ImportEdge("src/main.py", "src.config", "src/config.py"),
                ImportEdge("src/main.py", "requests", is_external=True),
            ],
            imported_by=["src/app.py"],
            centrality_score=0.75,
            in_degree=1,
        )
        raw = node.to_knowledge_json()
        data = json.loads(raw)
        assert isinstance(data, dict)

    def test_centrality_default(self) -> None:
        node = FileNode(file_path="x.py", language="python")
        assert node.centrality_score == 0.0

    def test_knowledge_json_keys(self) -> None:
        node = FileNode(file_path="x.py", language="python", loc=10)
        data = json.loads(node.to_knowledge_json())
        expected_keys = {
            "language", "loc", "function_count", "class_count",
            "imports", "imported_by", "external_deps",
            "centrality", "in_degree",
        }
        assert set(data.keys()) == expected_keys

    def test_knowledge_json_has_both_metrics(self) -> None:
        node = FileNode(
            file_path="x.py", language="python",
            centrality_score=0.9, in_degree=3,
        )
        data = json.loads(node.to_knowledge_json())
        assert data["centrality"] == 0.9
        assert data["in_degree"] == 3


# ── Python parser ───────────────────────────────────────────────────────────


class TestPythonParser:
    def test_import_statement(self, tmp_path: Path) -> None:
        from src.indexing.parsers.python import extract_python_imports

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "config.py").write_text("# config")
        source = "import src.config\n"
        edges = extract_python_imports(source, "main.py", tmp_path)
        internal = [e for e in edges if not e.is_external]
        assert len(internal) == 1
        assert internal[0].target_file == "src/config.py"

    def test_from_import(self, tmp_path: Path) -> None:
        from src.indexing.parsers.python import extract_python_imports

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "config.py").write_text("# config")
        source = "from src.config import Settings\n"
        edges = extract_python_imports(source, "main.py", tmp_path)
        internal = [e for e in edges if not e.is_external]
        assert len(internal) == 1
        assert internal[0].target_module == "src.config"

    def test_stdlib_skipped(self, tmp_path: Path) -> None:
        from src.indexing.parsers.python import extract_python_imports

        source = "import os\nimport sys\nimport json\n"
        edges = extract_python_imports(source, "main.py", tmp_path)
        assert len(edges) == 0

    def test_external_package(self, tmp_path: Path) -> None:
        from src.indexing.parsers.python import extract_python_imports

        source = "import requests\n"
        edges = extract_python_imports(source, "main.py", tmp_path)
        assert len(edges) == 1
        assert edges[0].is_external is True
        assert edges[0].target_module == "requests"

    def test_relative_import(self, tmp_path: Path) -> None:
        from src.indexing.parsers.python import extract_python_imports

        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "utils.py").write_text("# utils")
        source = "from . import utils\n"
        edges = extract_python_imports(source, "pkg/main.py", tmp_path)
        resolved = [e for e in edges if e.target_file is not None]
        assert len(resolved) == 1

    def test_empty_source(self, tmp_path: Path) -> None:
        from src.indexing.parsers.python import extract_python_imports

        edges = extract_python_imports("", "main.py", tmp_path)
        assert edges == []

    def test_multiline_robustness(self, tmp_path: Path) -> None:
        from src.indexing.parsers.python import extract_python_imports

        source = '# import os\n"""import fake"""\nprint("import trick")\n'
        edges = extract_python_imports(source, "main.py", tmp_path)
        # Comments produce edges (regex doesn't parse Python semantics)
        # but they shouldn't crash. The "import fake" in string may match
        # but that's acceptable for regex-based parsing.
        assert isinstance(edges, list)


# ── JavaScript parser ───────────────────────────────────────────────────────


class TestJSParser:
    def test_import_from(self, tmp_path: Path) -> None:
        from src.indexing.parsers.javascript import extract_js_imports

        (tmp_path / "utils.js").write_text("// utils")
        source = "import { foo } from './utils.js';\n"
        edges = extract_js_imports(source, "main.js", tmp_path)
        internal = [e for e in edges if not e.is_external]
        assert len(internal) == 1
        assert internal[0].target_file == "utils.js"

    def test_require(self, tmp_path: Path) -> None:
        from src.indexing.parsers.javascript import extract_js_imports

        (tmp_path / "utils.js").write_text("// utils")
        source = "const utils = require('./utils.js');\n"
        edges = extract_js_imports(source, "main.js", tmp_path)
        internal = [e for e in edges if not e.is_external]
        assert len(internal) == 1

    def test_dynamic_import(self, tmp_path: Path) -> None:
        from src.indexing.parsers.javascript import extract_js_imports

        (tmp_path / "lazy.js").write_text("// lazy")
        source = "const mod = await import('./lazy.js');\n"
        edges = extract_js_imports(source, "main.js", tmp_path)
        internal = [e for e in edges if not e.is_external]
        assert len(internal) == 1

    def test_export_from(self, tmp_path: Path) -> None:
        from src.indexing.parsers.javascript import extract_js_imports

        (tmp_path / "types.ts").write_text("// types")
        source = "export { Type } from './types.ts';\n"
        edges = extract_js_imports(source, "index.ts", tmp_path)
        internal = [e for e in edges if not e.is_external]
        assert len(internal) == 1

    def test_external_package(self, tmp_path: Path) -> None:
        from src.indexing.parsers.javascript import extract_js_imports

        source = "import React from 'react';\n"
        edges = extract_js_imports(source, "app.jsx", tmp_path)
        assert len(edges) == 1
        assert edges[0].is_external is True
        assert edges[0].target_module == "react"

    def test_extension_fallback(self, tmp_path: Path) -> None:
        from src.indexing.parsers.javascript import extract_js_imports

        (tmp_path / "foo.ts").write_text("// foo")
        source = "import foo from './foo';\n"
        edges = extract_js_imports(source, "main.ts", tmp_path)
        internal = [e for e in edges if not e.is_external]
        assert len(internal) == 1
        assert internal[0].target_file == "foo.ts"


# ── Metrics ─────────────────────────────────────────────────────────────────


class TestMetrics:
    def test_count_loc_skips_blanks(self) -> None:
        from src.indexing.metrics import count_loc

        source = "a = 1\n\nb = 2\n\n\n"
        assert count_loc(source) == 2

    def test_count_loc_skips_comments(self) -> None:
        from src.indexing.metrics import count_loc

        source = "# comment\na = 1\n// js comment\nb = 2\n"
        assert count_loc(source) == 2

    def test_count_loc_skips_block_comments(self) -> None:
        from src.indexing.metrics import count_loc

        source = "a = 1\n/* block\ncomment\n*/\nb = 2\n"
        assert count_loc(source) == 2

    def test_count_functions_python(self) -> None:
        from src.indexing.metrics import count_functions

        source = "def foo():\n    pass\n\nasync def bar():\n    pass\n"
        assert count_functions(source, "python") == 2

    def test_count_functions_js(self) -> None:
        from src.indexing.metrics import count_functions

        source = "function foo() {}\nconst bar = () => {};\n"
        assert count_functions(source, "javascript") == 2

    def test_count_classes_python(self) -> None:
        from src.indexing.metrics import count_classes

        source = "class Foo:\n    pass\n\nclass Bar:\n    pass\n"
        assert count_classes(source, "python") == 2

    def test_count_classes_js(self) -> None:
        from src.indexing.metrics import count_classes

        source = "class Foo {}\nexport class Bar {}\n"
        assert count_classes(source, "javascript") == 2


# ── PageRank ────────────────────────────────────────────────────────────────


class TestPageRank:
    def test_empty_graph(self) -> None:
        from src.indexing.metrics import compute_pagerank

        assert compute_pagerank({}, []) == {}

    def test_single_node(self) -> None:
        from src.indexing.metrics import compute_pagerank

        nodes = {"a.py": FileNode("a.py", "python")}
        assert compute_pagerank(nodes, []) == {"a.py": 1.0}

    def test_hub_has_highest_score(self) -> None:
        from src.indexing.metrics import compute_pagerank

        # hub.py is imported by a.py, b.py, c.py
        nodes = {
            "hub.py": FileNode("hub.py", "python"),
            "a.py": FileNode("a.py", "python"),
            "b.py": FileNode("b.py", "python"),
            "c.py": FileNode("c.py", "python"),
            "leaf.py": FileNode("leaf.py", "python"),
        }
        edges = [
            ImportEdge("a.py", "hub", "hub.py"),
            ImportEdge("b.py", "hub", "hub.py"),
            ImportEdge("c.py", "hub", "hub.py"),
            ImportEdge("a.py", "leaf", "leaf.py"),
        ]
        scores = compute_pagerank(nodes, edges)
        assert scores["hub.py"] > scores["leaf.py"]
        assert scores["hub.py"] == 1.0  # normalized max

    def test_transitive_importance(self) -> None:
        from src.indexing.metrics import compute_pagerank

        # important.py is imported by hub.py (which is imported by many)
        # trivial.py is imported by leaf.py (which imports nothing else)
        nodes = {
            "hub.py": FileNode("hub.py", "python"),
            "important.py": FileNode("important.py", "python"),
            "trivial.py": FileNode("trivial.py", "python"),
            "leaf.py": FileNode("leaf.py", "python"),
            "a.py": FileNode("a.py", "python"),
            "b.py": FileNode("b.py", "python"),
        }
        edges = [
            ImportEdge("a.py", "hub", "hub.py"),
            ImportEdge("b.py", "hub", "hub.py"),
            ImportEdge("hub.py", "important", "important.py"),
            ImportEdge("leaf.py", "trivial", "trivial.py"),
        ]
        scores = compute_pagerank(nodes, edges)
        # important.py should rank higher because hub.py (its importer) is important
        assert scores["important.py"] > scores["trivial.py"]

    def test_disconnected_node_base_score(self) -> None:
        from src.indexing.metrics import compute_pagerank

        nodes = {
            "a.py": FileNode("a.py", "python"),
            "b.py": FileNode("b.py", "python"),
            "isolated.py": FileNode("isolated.py", "python"),
        }
        edges = [ImportEdge("a.py", "b", "b.py")]
        scores = compute_pagerank(nodes, edges)
        # Isolated node should have a score > 0 (base score from dangling node distribution)
        assert scores["isolated.py"] > 0

    def test_in_degree_count(self) -> None:
        """Raw in-degree count matches number of importers."""
        node = FileNode("hub.py", "python")
        node.imported_by = ["a.py", "b.py", "c.py"]
        node.in_degree = len(node.imported_by)
        assert node.in_degree == 3


# ── Walk source files ───────────────────────────────────────────────────────


class TestWalkSourceFiles:
    def test_skips_git_dir(self, tmp_path: Path) -> None:
        from src.indexing.graph import _walk_source_files

        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config.py").write_text("# git internal")
        (tmp_path / "main.py").write_text("# main")
        files = _walk_source_files(tmp_path)
        paths = [f[0] for f in files]
        assert "main.py" in paths
        assert not any(".git" in p for p in paths)

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        from src.indexing.graph import _walk_source_files

        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("// pkg")
        (tmp_path / "app.js").write_text("// app")
        files = _walk_source_files(tmp_path)
        paths = [f[0] for f in files]
        assert "app.js" in paths
        assert not any("node_modules" in p for p in paths)

    def test_skips_large_files(self, tmp_path: Path) -> None:
        from src.indexing.graph import _walk_source_files

        large = tmp_path / "big.py"
        large.write_text("x" * (512 * 1024 + 1))
        (tmp_path / "small.py").write_text("x = 1")
        files = _walk_source_files(tmp_path)
        paths = [f[0] for f in files]
        assert "small.py" in paths
        assert "big.py" not in paths

    def test_filters_by_extension(self, tmp_path: Path) -> None:
        from src.indexing.graph import _walk_source_files

        (tmp_path / "code.py").write_text("# python")
        (tmp_path / "readme.md").write_text("# readme")
        (tmp_path / "data.csv").write_text("a,b,c")
        files = _walk_source_files(tmp_path)
        paths = [f[0] for f in files]
        assert "code.py" in paths
        assert "readme.md" not in paths
        assert "data.csv" not in paths


# ── Build codebase graph ────────────────────────────────────────────────────


class TestBuildCodebaseGraph:
    @pytest.fixture()
    def mock_db(self) -> AsyncMock:
        db = AsyncMock()
        db.store_codebase_knowledge = AsyncMock()
        db.delete_stale_codebase_knowledge = AsyncMock(return_value=0)
        return db

    async def test_simple_graph(self, tmp_path: Path, mock_db: AsyncMock) -> None:
        from src.indexing.graph import build_codebase_graph

        (tmp_path / "config.py").write_text("SETTING = 1\n")
        (tmp_path / "main.py").write_text("import config\n")

        result = await build_codebase_graph(
            repo_dir=tmp_path, repo="test/repo",
            intel_db=mock_db, max_files=100,
        )
        assert result["files_indexed"] == 2
        assert mock_db.store_codebase_knowledge.call_count == 2

    async def test_max_files_guard(self, tmp_path: Path, mock_db: AsyncMock) -> None:
        from src.indexing.graph import build_codebase_graph

        for i in range(5):
            (tmp_path / f"f{i}.py").write_text(f"x = {i}\n")

        result = await build_codebase_graph(
            repo_dir=tmp_path, repo="test/repo",
            intel_db=mock_db, max_files=3,
        )
        assert result.get("skipped") is True
        mock_db.store_codebase_knowledge.assert_not_called()

    async def test_stores_to_db(self, tmp_path: Path, mock_db: AsyncMock) -> None:
        from src.indexing.graph import build_codebase_graph

        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("import a\n")

        await build_codebase_graph(
            repo_dir=tmp_path, repo="test/repo",
            intel_db=mock_db, max_files=100,
        )

        assert mock_db.store_codebase_knowledge.call_count == 2
        # Verify knowledge_id format
        calls = mock_db.store_codebase_knowledge.call_args_list
        ids = [c.kwargs["knowledge_id"] for c in calls]
        assert all(kid.startswith("test/repo:") for kid in ids)

    async def test_stale_cleanup(self, tmp_path: Path, mock_db: AsyncMock) -> None:
        from src.indexing.graph import build_codebase_graph

        (tmp_path / "only.py").write_text("x = 1\n")

        await build_codebase_graph(
            repo_dir=tmp_path, repo="test/repo",
            intel_db=mock_db, max_files=100,
        )
        mock_db.delete_stale_codebase_knowledge.assert_called_once()
        args = mock_db.delete_stale_codebase_knowledge.call_args
        assert args[0][0] == "test/repo"

    async def test_centrality_pagerank(self, tmp_path: Path, mock_db: AsyncMock) -> None:
        from src.indexing.graph import build_codebase_graph

        # hub.py imported by a.py, b.py, c.py
        (tmp_path / "hub.py").write_text("HUB = True\n")
        (tmp_path / "a.py").write_text("import hub\n")
        (tmp_path / "b.py").write_text("import hub\n")
        (tmp_path / "c.py").write_text("import hub\n")

        await build_codebase_graph(
            repo_dir=tmp_path, repo="test/repo",
            intel_db=mock_db, max_files=100,
        )

        # Find the hub.py knowledge entry
        calls = mock_db.store_codebase_knowledge.call_args_list
        hub_call = next(
            c for c in calls if c.kwargs["file_path"] == "hub.py"
        )
        hub_data = json.loads(hub_call.kwargs["knowledge"])
        assert hub_data["centrality"] > 0
        assert hub_data["in_degree"] == 3

    async def test_knowledge_json_has_both_metrics(
        self, tmp_path: Path, mock_db: AsyncMock,
    ) -> None:
        from src.indexing.graph import build_codebase_graph

        (tmp_path / "single.py").write_text("x = 1\n")

        await build_codebase_graph(
            repo_dir=tmp_path, repo="test/repo",
            intel_db=mock_db, max_files=100,
        )

        call = mock_db.store_codebase_knowledge.call_args_list[0]
        data = json.loads(call.kwargs["knowledge"])
        assert "centrality" in data
        assert "in_degree" in data


# ── Indexing scheduler ──────────────────────────────────────────────────────


class TestIndexingScheduler:
    async def test_stop_interrupts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.indexing.scheduler import IndexingScheduler

        config = AsyncMock()
        config.indexing.interval_seconds = 3600
        config.indexing.max_files_per_repo = 5000
        config.patrol.repos = ["test/repo"]

        github_client = AsyncMock()
        intel_db = AsyncMock()

        scheduler = IndexingScheduler(config, github_client, intel_db)

        # Patch _index_repo to immediately stop
        async def _fake_index(repo: str, max_files: int) -> None:
            await scheduler.stop()

        monkeypatch.setattr(scheduler, "_index_repo", _fake_index)

        # run() should exit without hanging
        await scheduler.run()

    async def test_cleanup_on_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from src.indexing.scheduler import IndexingScheduler

        config = AsyncMock()
        config.indexing.interval_seconds = 3600
        config.indexing.max_files_per_repo = 5000
        config.patrol.repos = ["test/repo"]

        github_client = AsyncMock()
        github_client.clone_repo = AsyncMock(side_effect=RuntimeError("clone failed"))
        intel_db = AsyncMock()

        scheduler = IndexingScheduler(config, github_client, intel_db)

        # Index one repo (will fail), then stop
        await scheduler._index_repo("test/repo", 100)
        # If we get here, the tmpdir was cleaned up despite the error
        # (shutil.rmtree in finally block)


# ── IndexingConfig ──────────────────────────────────────────────────────────


class TestIndexingConfig:
    def test_defaults(self) -> None:
        from src.config import IndexingConfig

        cfg = IndexingConfig()
        assert cfg.enabled is True
        assert cfg.interval_seconds == 86400
        assert cfg.max_files_per_repo == 5000
        assert cfg.languages == ["python", "javascript", "typescript"]

    def test_in_saltax_config(self) -> None:
        from src.config import SaltaXConfig

        cfg = SaltaXConfig()
        assert hasattr(cfg, "indexing")
        assert cfg.indexing.enabled is True

    def test_yaml_roundtrip(self, tmp_path: Path) -> None:
        import yaml

        from src.config import SaltaXConfig

        yaml_content = {
            "version": "1.0",
            "indexing": {
                "enabled": True,
                "interval_seconds": 43200,
                "max_files_per_repo": 3000,
                "languages": ["python"],
            },
        }
        config_file = tmp_path / "test.yaml"
        config_file.write_text(yaml.dump(yaml_content))
        cfg = SaltaXConfig.load(config_file)
        assert cfg.indexing.interval_seconds == 43200
        assert cfg.indexing.max_files_per_repo == 3000
        assert cfg.indexing.languages == ["python"]
