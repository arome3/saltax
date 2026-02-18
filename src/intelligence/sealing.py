"""KMS-backed seal/unseal manager for intelligence data at rest."""

from __future__ import annotations

import base64
import logging

import httpx

logger = logging.getLogger(__name__)


class KMSSealManager:
    """Wraps the EigenCloud KMS endpoint for envelope encryption.

    Seal/unseal operations POST base64-encoded data to the configured
    KMS endpoint, which handles the actual AES key-wrapping.
    """

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint
        self._client: httpx.AsyncClient | None = None

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def seal(self, key: str, data: bytes) -> bytes:
        """Seal *data* under *key* via the KMS endpoint.

        Returns the sealed ciphertext bytes.
        """
        client = self._get_client()
        payload = {"key": key, "data": base64.b64encode(data).decode()}
        resp = await client.post(f"{self._endpoint}/v1/seal", json=payload)
        resp.raise_for_status()
        body = resp.json()
        return base64.b64decode(body["sealed"])

    async def unseal(self, key: str) -> bytes:
        """Unseal the data stored under *key* via the KMS endpoint.

        Returns the plaintext bytes.
        """
        client = self._get_client()
        payload = {"key": key}
        resp = await client.post(f"{self._endpoint}/v1/unseal", json=payload)
        resp.raise_for_status()
        body = resp.json()
        return base64.b64decode(body["data"])

    async def close(self) -> None:
        """Release KMS connection resources."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
