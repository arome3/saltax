"""Async client for the OSV.dev vulnerability database API.

Provides package-level vulnerability queries and individual vuln lookups.
Ecosystem names are **case-sensitive**: ``PyPI``, ``npm``, ``crates.io``.
"""

from __future__ import annotations

import json
import logging

import httpx

logger = logging.getLogger(__name__)

_OSV_BASE_URL = "https://api.osv.dev/v1"

# Language → OSV ecosystem (case-sensitive)
ECOSYSTEM_MAP: dict[str, str] = {
    "python": "PyPI",
    "node": "npm",
    "rust": "crates.io",
}


class OSVClient:
    """Lightweight async client for OSV.dev."""

    def __init__(self, *, timeout: float = 15.0) -> None:
        self._client = httpx.AsyncClient(
            base_url=_OSV_BASE_URL,
            timeout=timeout,
        )

    async def query_package(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict]:
        """Query OSV for vulnerabilities affecting a specific package version.

        Parameters
        ----------
        ecosystem:
            OSV ecosystem name — must be exact case (``PyPI``, ``npm``, ``crates.io``).

        Returns an empty list on error or when no vulnerabilities are found.
        """
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
        }
        try:
            response = await self._client.post("/query", json=payload)
            response.raise_for_status()
            data = response.json()
            vulns: list[dict] = data.get("vulns", [])
            return vulns
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                logger.warning("OSV rate-limited for %s/%s", ecosystem, package_name)
            elif exc.response.status_code == 404:
                return []
            else:
                logger.warning("OSV HTTP %d for %s", exc.response.status_code, package_name)
            return []
        except httpx.HTTPError as exc:
            logger.warning("OSV network error for %s: %s", package_name, exc)
            return []
        except json.JSONDecodeError:
            logger.warning("OSV returned invalid JSON for %s", package_name)
            return []

    async def get_vulnerability(self, vuln_id: str) -> dict | None:
        """Fetch a single vulnerability by ID. Returns ``None`` if not found."""
        try:
            response = await self._client.get(f"/vulns/{vuln_id}")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            result: dict = response.json()
            return result
        except httpx.HTTPStatusError:
            logger.warning("OSV HTTP error fetching %s", vuln_id)
            return None
        except httpx.HTTPError as exc:
            logger.warning("OSV network error fetching %s: %s", vuln_id, exc)
            return None
        except json.JSONDecodeError:
            logger.warning("OSV returned invalid JSON for %s", vuln_id)
            return None

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
