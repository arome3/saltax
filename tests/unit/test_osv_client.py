"""Tests for the OSV client."""

from __future__ import annotations

import httpx
import pytest

from src.patrol.osv_client import OSVClient

_ = pytest


# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_response(status_code: int, *, json_data: dict | None = None) -> httpx.Response:
    """Build an httpx.Response with a fake request (needed for raise_for_status)."""
    request = httpx.Request("GET", "https://osv.dev/test")
    if json_data is not None:
        return httpx.Response(status_code, json=json_data, request=request)
    return httpx.Response(status_code, request=request)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def osv_client() -> OSVClient:
    return OSVClient()


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestOSVQueryPackage:
    async def test_query_package_success(self, osv_client, monkeypatch) -> None:
        """Returns vulns list on successful query."""
        response_data = {"vulns": [{"id": "PYSEC-2023-100"}]}

        async def mock_post(url, *, json, **kwargs):
            return _mock_response(200, json_data=response_data)

        monkeypatch.setattr(osv_client._client, "post", mock_post)
        result = await osv_client.query_package("requests", "2.25.0", "PyPI")
        assert len(result) == 1
        assert result[0]["id"] == "PYSEC-2023-100"

    async def test_query_package_not_found(self, osv_client, monkeypatch) -> None:
        """Empty vulns array returns empty list."""
        response_data = {"vulns": []}

        async def mock_post(url, *, json, **kwargs):
            return _mock_response(200, json_data=response_data)

        monkeypatch.setattr(osv_client._client, "post", mock_post)
        result = await osv_client.query_package("nonexistent", "1.0.0", "PyPI")
        assert result == []

    async def test_query_package_api_error(self, osv_client, monkeypatch) -> None:
        """httpx.HTTPError -> returns []."""

        async def mock_post(url, *, json, **kwargs):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(osv_client._client, "post", mock_post)
        result = await osv_client.query_package("requests", "2.25.0", "PyPI")
        assert result == []


class TestOSVGetVulnerability:
    async def test_get_vulnerability_success(self, osv_client, monkeypatch) -> None:
        """Returns dict on success."""
        vuln_data = {"id": "PYSEC-2023-100", "summary": "Test vuln"}

        async def mock_get(url, **kwargs):
            return _mock_response(200, json_data=vuln_data)

        monkeypatch.setattr(osv_client._client, "get", mock_get)
        result = await osv_client.get_vulnerability("PYSEC-2023-100")
        assert result is not None
        assert result["id"] == "PYSEC-2023-100"

    async def test_get_vulnerability_not_found(self, osv_client, monkeypatch) -> None:
        """404 -> returns None."""

        async def mock_get(url, **kwargs):
            return _mock_response(404)

        monkeypatch.setattr(osv_client._client, "get", mock_get)
        result = await osv_client.get_vulnerability("NONEXISTENT")
        assert result is None

    async def test_get_vulnerability_partial_data(self, osv_client, monkeypatch) -> None:
        """Missing severity is handled gracefully."""
        vuln_data = {"id": "TEST-001"}  # no severity field

        async def mock_get(url, **kwargs):
            return _mock_response(200, json_data=vuln_data)

        monkeypatch.setattr(osv_client._client, "get", mock_get)
        result = await osv_client.get_vulnerability("TEST-001")
        assert result is not None
        assert result["id"] == "TEST-001"

    async def test_get_vulnerability_server_error(self, osv_client, monkeypatch) -> None:
        """500 -> returns None (T4)."""

        async def mock_get(url, **kwargs):
            return _mock_response(500)

        monkeypatch.setattr(osv_client._client, "get", mock_get)
        result = await osv_client.get_vulnerability("TEST-500")
        assert result is None

    async def test_get_vulnerability_invalid_json(self, osv_client, monkeypatch) -> None:
        """200 with non-JSON body -> returns None (T4)."""

        async def mock_get(url, **kwargs):
            request = httpx.Request("GET", "https://osv.dev/test")
            return httpx.Response(200, content=b"not json", request=request)

        monkeypatch.setattr(osv_client._client, "get", mock_get)
        result = await osv_client.get_vulnerability("TEST-BAD-JSON")
        assert result is None

    async def test_close(self, osv_client, monkeypatch) -> None:
        """Client closes without error."""
        closed = False

        async def mock_aclose():
            nonlocal closed
            closed = True

        monkeypatch.setattr(osv_client._client, "aclose", mock_aclose)
        await osv_client.close()
        assert closed


# ── Error variant tests (T4) ────────────────────────────────────────────────


class TestOSVErrorVariants:
    async def test_query_package_rate_limited(self, osv_client, monkeypatch) -> None:
        """429 -> returns [] (T4)."""

        async def mock_post(url, *, json, **kwargs):
            return _mock_response(429)

        monkeypatch.setattr(osv_client._client, "post", mock_post)
        result = await osv_client.query_package("requests", "2.25.0", "PyPI")
        assert result == []

    async def test_query_package_server_error(self, osv_client, monkeypatch) -> None:
        """500 -> returns [] (T4)."""

        async def mock_post(url, *, json, **kwargs):
            return _mock_response(500)

        monkeypatch.setattr(osv_client._client, "post", mock_post)
        result = await osv_client.query_package("requests", "2.25.0", "PyPI")
        assert result == []

    async def test_query_package_invalid_json(self, osv_client, monkeypatch) -> None:
        """200 with non-JSON body -> returns [] (T4)."""

        async def mock_post(url, *, json, **kwargs):
            request = httpx.Request("POST", "https://osv.dev/test")
            return httpx.Response(200, content=b"not json at all", request=request)

        monkeypatch.setattr(osv_client._client, "post", mock_post)
        result = await osv_client.query_package("requests", "2.25.0", "PyPI")
        assert result == []
