"""KMS-backed seal/unseal manager for intelligence data at rest."""

from __future__ import annotations


class KMSSealManager:
    """Wraps the EigenCloud KMS endpoint for envelope encryption.

    Real implementation will use KMS to seal/unseal AES data-keys.
    """

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    @property
    def endpoint(self) -> str:
        return self._endpoint

    async def seal(self, key: str, data: bytes) -> bytes:
        raise NotImplementedError("KMS seal not yet implemented")

    async def unseal(self, key: str) -> bytes:
        raise NotImplementedError("KMS unseal not yet implemented")

    async def close(self) -> None:
        """Release KMS connection resources."""
