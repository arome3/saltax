"""On-chain identity registration and recovery for the agent.

Implements a multi-tier fallback:

1. Return cached ``_identity`` if already registered (idempotent).
2. Check ``intel_db`` cache for a prior registration.
3. Try the TS bridge for live on-chain registration.
   a. On 409 (already registered), attempt recovery via ``get_agent()``.
4. Fall back to a deterministic placeholder (SHA-256 of wallet address).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.identity.bridge_client import AlreadyRegisteredError
from src.models.identity import AgentIdentity

if TYPE_CHECKING:
    from src.identity.bridge_client import IdentityBridgeClient
    from src.intelligence.database import IntelligenceDB
    from src.treasury.wallet import WalletManager

logger = logging.getLogger(__name__)


class IdentityRegistrar:
    """Registers the agent's identity on the identity chain or recovers an existing one.

    Constructor takes the bridge client and optional intel_db.  The
    ``intel_db`` can be set after construction (Phase 3 bootstrap) via
    the ``intel_db`` property setter.
    """

    def __init__(
        self,
        wallet: WalletManager,
        bridge_client: IdentityBridgeClient,
        chain_id: int,
        intel_db: IntelligenceDB | None = None,
        *,
        agent_name: str = "SaltaX",
        agent_description: str = "Sovereign Code Organism",
    ) -> None:
        self._wallet = wallet
        self._bridge_client = bridge_client
        self._chain_id = chain_id
        self._intel_db = intel_db
        self._agent_name = agent_name
        self._agent_description = agent_description
        self._identity: AgentIdentity | None = None
        self.agent_id: str | None = None

    @property
    def intel_db(self) -> IntelligenceDB | None:
        return self._intel_db

    @intel_db.setter
    def intel_db(self, value: IntelligenceDB | None) -> None:
        self._intel_db = value

    @property
    def identity(self) -> AgentIdentity | None:
        return self._identity

    async def register_or_recover(self) -> AgentIdentity:
        """Register a new on-chain identity or recover an existing one.

        Idempotent — returns the cached identity on subsequent calls.
        """
        # 1. Already registered — return immediately
        if self._identity is not None:
            return self._identity

        # 2. Guard: wallet must be initialized
        address = self._wallet.address
        if address is None:
            raise RuntimeError(
                "WalletManager not initialized — cannot register identity without wallet address"
            )

        # 3. Try intel_db cache (cross-boot recovery)
        if self._intel_db is not None:
            try:
                cached = await self._intel_db.get_cached_identity(address)
                if cached is not None:
                    logger.info(
                        "Recovered identity from cache: agent_id=%s",
                        cached.agent_id,
                    )
                    self._identity = cached
                    self.agent_id = cached.agent_id
                    return cached
            except Exception:
                logger.warning("Failed to read identity cache, continuing to bridge")

        # 4. Try bridge registration
        result = None
        try:
            result = await self._bridge_client.register_agent(
                name=self._agent_name,
                description=self._agent_description,
                chain_id=self._chain_id,
            )
        except AlreadyRegisteredError:
            # 4a. Agent already registered on-chain — recover via get_agent
            logger.info("Agent already registered on-chain, attempting recovery")
            result = await self._bridge_client.get_agent(address)
            if result is not None:
                logger.info(
                    "Recovered existing agent from bridge: %s",
                    result.get("agentId", result.get("id", "")),
                )

        if result is not None:
            agent_id = result.get("agentId", "") or result.get("id", "")
            if not agent_id:
                logger.warning("Bridge returned empty agentId, falling through to placeholder")
            else:
                return await self._accept_identity(address, agent_id)

        # 5. Fallback — deterministic placeholder
        identity = self._make_placeholder(address)
        self._identity = identity
        self.agent_id = identity.agent_id
        logger.warning(
            "Bridge unavailable, using placeholder identity: %s",
            identity.agent_id,
        )
        return identity

    async def _accept_identity(self, address: str, agent_id: str) -> AgentIdentity:
        """Build, cache, and store an identity from a successful bridge response."""
        now = datetime.now(UTC)
        identity = AgentIdentity(
            agent_id=agent_id,
            chain_id=self._chain_id,
            wallet_address=address,
            name=self._agent_name,
            description=self._agent_description,
            registered_at=now,
        )
        self._identity = identity
        self.agent_id = identity.agent_id
        logger.info("Accepted identity: agent_id=%s", identity.agent_id)

        # Cache for next boot — failure is non-fatal
        if self._intel_db is not None:
            try:
                await self._intel_db.cache_identity(identity)
            except Exception:
                logger.warning("Failed to cache identity, continuing")

        return identity

    def _make_placeholder(self, wallet_address: str) -> AgentIdentity:
        """Build a deterministic placeholder identity from the wallet address.

        The SHA-256 ensures the same wallet always maps to the same
        placeholder ID, preventing identity proliferation on transient
        bridge failures.
        """
        addr_hash = hashlib.sha256(wallet_address.encode()).hexdigest()[:16]
        return AgentIdentity(
            agent_id=f"{self._chain_id}:placeholder-{addr_hash}",
            chain_id=self._chain_id,
            wallet_address=wallet_address,
            name=self._agent_name,
            description=self._agent_description,
            registered_at=datetime.now(UTC),
        )

    async def close(self) -> None:
        """Release identity registrar resources."""
        await self._bridge_client.close()
