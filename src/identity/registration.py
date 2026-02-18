"""On-chain identity registration and recovery for the agent."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.treasury.wallet import WalletManager


class IdentityRegistrar:
    """Registers the agent's identity on the identity chain or recovers an existing one."""

    def __init__(self, wallet: WalletManager, rpc_url: str, chain_id: int) -> None:
        self._wallet = wallet
        self._rpc_url = rpc_url
        self._chain_id = chain_id
        self.agent_id: str | None = None

    async def register_or_recover(self) -> None:
        """Register a new on-chain identity or recover an existing one."""
        self.agent_id = f"saltax-agent-{self._chain_id}"

    async def close(self) -> None:
        """Release identity registrar resources."""
