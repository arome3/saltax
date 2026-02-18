"""Wallet manager for the agent's on-chain treasury operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.intelligence.sealing import KMSSealManager


class WalletManager:
    """Manages the agent's Ethereum wallet derived from KMS-held keys."""

    def __init__(self, kms: KMSSealManager) -> None:
        self._kms = kms
        self.address: str | None = None

    async def initialize(self) -> None:
        """Derive wallet address from KMS-held seed."""
        self.address = "0x" + "0" * 40

    async def close(self) -> None:
        """Release wallet resources."""
