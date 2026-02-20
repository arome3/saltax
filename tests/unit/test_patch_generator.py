"""Tests for the patch generator."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models.enums import Severity
from src.models.patrol import DependencyFinding
from src.patrol.patch_generator import (
    PatchGenerator,
    _bump_node,
    _bump_python,
    _bump_rust,
    _sanitize_branch_name,
)

_ = pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_finding(
    *,
    package_name: str = "requests",
    current_version: str = "2.25.0",
    fixed_version: str | None = "2.31.0",
    language: str = "python",
) -> DependencyFinding:
    return DependencyFinding(
        package_name=package_name,
        current_version=current_version,
        vulnerable_range="<2.31.0",
        cve_id="CVE-2023-32681",
        severity=Severity.HIGH,
        advisory_url="https://example.com",
        fixed_version=fixed_version,
        is_direct=True,
        language=language,
    )


@pytest.fixture()
def patcher() -> PatchGenerator:
    github = AsyncMock()
    intel_db = AsyncMock()
    return PatchGenerator(github, intel_db)


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestPatchGenerator:
    async def test_no_fixed_version_returns_none(self, patcher) -> None:
        """fixed_version=None -> None."""
        finding = _make_finding(fixed_version=None)
        result = await patcher.generate_and_submit("owner/repo", finding, 42)
        assert result is None

    async def test_successful_patch_pr(self, patcher) -> None:
        """Full happy path -> PR number."""
        finding = _make_finding()
        patcher._github.clone_repo = AsyncMock()
        patcher._github.create_pull_request = AsyncMock(
            return_value={"number": 99},
        )
        patcher._db.record_patrol_patch = AsyncMock()

        with (
            patch.object(patcher, "_apply_bump", return_value=True),
            patch.object(patcher, "_run_tests", new_callable=AsyncMock, return_value=True),
            patch("tempfile.mkdtemp", return_value="/tmp/patrol-test"),
            patch("shutil.rmtree"),
        ):
            result = await patcher.generate_and_submit("owner/repo", finding, 42)

        assert result == 99
        patcher._github.create_pull_request.assert_awaited_once()

    async def test_clone_failure_cleanup(self, patcher) -> None:
        """Clone raises -> temp dir cleaned, None returned."""
        finding = _make_finding()
        patcher._github.clone_repo = AsyncMock(
            side_effect=RuntimeError("clone failed"),
        )

        with (
            patch("tempfile.mkdtemp", return_value="/tmp/patrol-cleanup-test"),
            patch("shutil.rmtree") as mock_rmtree,
        ):
            result = await patcher.generate_and_submit("owner/repo", finding, 42)

        assert result is None
        mock_rmtree.assert_called_once_with(
            "/tmp/patrol-cleanup-test", ignore_errors=True,
        )

    async def test_test_timeout_cleanup(self, patcher) -> None:
        """Tests timeout -> temp dir cleaned, None returned."""
        finding = _make_finding()
        patcher._github.clone_repo = AsyncMock()

        with (
            patch.object(patcher, "_apply_bump", return_value=True),
            patch.object(
                patcher, "_run_tests",
                new_callable=AsyncMock, return_value=False,
            ),
            patch("tempfile.mkdtemp", return_value="/tmp/patrol-timeout-test"),
            patch("shutil.rmtree") as mock_rmtree,
        ):
            result = await patcher.generate_and_submit("owner/repo", finding, 42)

        assert result is None
        mock_rmtree.assert_called_once()

    async def test_records_patrol_patch(self, patcher) -> None:
        """record_patrol_patch called on success."""
        finding = _make_finding()
        patcher._github.clone_repo = AsyncMock()
        patcher._github.create_pull_request = AsyncMock(
            return_value={"number": 77},
        )
        patcher._db.record_patrol_patch = AsyncMock()

        with (
            patch.object(patcher, "_apply_bump", return_value=True),
            patch.object(patcher, "_run_tests", new_callable=AsyncMock, return_value=True),
            patch("tempfile.mkdtemp", return_value="/tmp/patrol-record"),
            patch("shutil.rmtree"),
        ):
            await patcher.generate_and_submit("owner/repo", finding, 42)

        patcher._db.record_patrol_patch.assert_awaited_once()
        call_kwargs = patcher._db.record_patrol_patch.call_args.kwargs
        assert call_kwargs["pr_number"] == 77
        assert call_kwargs["package_name"] == "requests"
        assert call_kwargs["status"] == "submitted"

    async def test_apply_bump_failure_returns_none(self, patcher) -> None:
        """_apply_bump returns False -> None, no PR created (T11)."""
        finding = _make_finding()
        patcher._github.clone_repo = AsyncMock()

        with (
            patch.object(patcher, "_apply_bump", return_value=False),
            patch("tempfile.mkdtemp", return_value="/tmp/patrol-bump-fail"),
            patch("shutil.rmtree") as mock_rmtree,
        ):
            result = await patcher.generate_and_submit("owner/repo", finding, 42)

        assert result is None
        patcher._github.create_pull_request.assert_not_awaited()
        mock_rmtree.assert_called_once()

    async def test_pr_creation_failure_cleanup(self, patcher) -> None:
        """create_pull_request raises -> temp dir still cleaned up (T12)."""
        finding = _make_finding()
        patcher._github.clone_repo = AsyncMock()
        patcher._github.get_ref = AsyncMock(return_value="abc123")
        patcher._github.create_ref = AsyncMock()
        patcher._github.create_or_update_contents = AsyncMock()
        patcher._github._request = AsyncMock(
            return_value=MagicMock(json=MagicMock(return_value={"sha": "def456"})),
        )
        patcher._github.create_pull_request = AsyncMock(
            side_effect=RuntimeError("PR creation failed"),
        )

        with (
            patch.object(patcher, "_apply_bump", return_value=True),
            patch.object(patcher, "_run_tests", new_callable=AsyncMock, return_value=True),
            patch.object(patcher, "_find_changed_files", return_value=["requirements.txt"]),
            patch("tempfile.mkdtemp", return_value="/tmp/patrol-pr-fail"),
            patch("shutil.rmtree") as mock_rmtree,
            patch("builtins.open", create=True),
        ):
            # Simulate the target file existing with content
            import pathlib  # noqa: PLC0415

            original_exists = pathlib.Path.exists

            def fake_exists(self):
                if "requirements.txt" in str(self):
                    return True
                return original_exists(self)

            original_read_bytes = pathlib.Path.read_bytes

            def fake_read_bytes(self):
                if "requirements.txt" in str(self):
                    return b"requests==2.31.0\n"
                return original_read_bytes(self)

            with (
                patch.object(pathlib.Path, "exists", fake_exists),
                patch.object(pathlib.Path, "read_bytes", fake_read_bytes),
            ):
                result = await patcher.generate_and_submit("owner/repo", finding, 42)

        assert result is None
        mock_rmtree.assert_called_once_with(
            "/tmp/patrol-pr-fail", ignore_errors=True,
        )


# ── Bump helper tests (T1) ──────────────────────────────────────────────────


class TestBumpPython:
    def test_bump_python_requirements_txt(self, tmp_path) -> None:
        """requirements.txt: requests==2.25.0 -> requests==2.31.0."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.0.0\nrequests==2.25.0\nclick>=8.0\n")
        finding = _make_finding()
        assert _bump_python(tmp_path, finding) is True
        assert "requests==2.31.0" in req.read_text()
        assert "flask==2.0.0" in req.read_text()

    def test_bump_python_pyproject_toml(self, tmp_path) -> None:
        """pyproject.toml: bumps version in [project.dependencies]."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "myapp"\ndependencies = [\n'
            '  "requests>=2.25.0",\n  "flask>=2.0.0",\n]\n'
        )
        finding = _make_finding()
        assert _bump_python(tmp_path, finding) is True
        content = pyproject.read_text()
        assert "2.31.0" in content
        assert "flask>=2.0.0" in content

    def test_bump_python_package_not_found(self, tmp_path) -> None:
        """Package not in any manifest -> returns False."""
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.0.0\nclick>=8.0\n")
        finding = _make_finding(package_name="nonexistent", current_version="1.0.0")
        assert _bump_python(tmp_path, finding) is False


class TestBumpNode:
    def test_bump_node_package_json(self, tmp_path) -> None:
        """package.json: dependencies version updated."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.20"},
            "devDependencies": {"jest": "^27.0.0"},
        }))
        finding = _make_finding(
            package_name="lodash", current_version="4.17.20",
            fixed_version="4.17.21", language="node",
        )
        assert _bump_node(tmp_path, finding) is True
        data = json.loads(pkg.read_text())
        assert data["dependencies"]["lodash"] == "^4.17.21"
        assert data["devDependencies"]["jest"] == "^27.0.0"

    def test_bump_node_dev_dependencies(self, tmp_path) -> None:
        """devDependencies also updated."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {},
            "devDependencies": {"eslint": "^7.0.0"},
        }))
        finding = _make_finding(
            package_name="eslint", current_version="7.0.0",
            fixed_version="8.0.0", language="node",
        )
        assert _bump_node(tmp_path, finding) is True
        data = json.loads(pkg.read_text())
        assert data["devDependencies"]["eslint"] == "^8.0.0"


class TestBumpRust:
    def test_bump_rust_cargo_toml(self, tmp_path) -> None:
        """Cargo.toml: version string replaced."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(
            '[dependencies]\nserde = "1.0.0"\ntokio = "1.28.0"\n'
        )
        finding = _make_finding(
            package_name="serde", current_version="1.0.0",
            fixed_version="1.0.1", language="rust",
        )
        assert _bump_rust(tmp_path, finding) is True
        content = cargo.read_text()
        assert '"1.0.1"' in content
        assert '"1.28.0"' in content


# ── Sanitize branch name tests ──────────────────────────────────────────────


class TestSanitizeBranchName:
    def test_scoped_npm_package(self) -> None:
        """@scope/package -> sanitized without @ (Fix 9)."""
        result = _sanitize_branch_name("patrol/bump-@scope/package-1.2.3")
        assert "@" not in result
        assert "//" not in result

    def test_spaces_replaced(self) -> None:
        """Spaces replaced with dashes."""
        result = _sanitize_branch_name("patrol/my branch name")
        assert " " not in result

    def test_truncation(self) -> None:
        """Long names truncated to 255."""
        result = _sanitize_branch_name("a" * 300)
        assert len(result) <= 255
