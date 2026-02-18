"""Optimistic verification window scheduler."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.config import SaltaXConfig
    from src.intelligence.database import IntelligenceDB
    from src.treasury.wallet import WalletManager


class VerificationScheduler:
    """Manages optimistic verification windows and challenge resolution."""

    def __init__(
        self,
        config: SaltaXConfig,
        wallet: WalletManager,
        intel_db: IntelligenceDB,
    ) -> None:
        self._config = config
        self._wallet = wallet
        self._intel_db = intel_db
        self._stop_event = asyncio.Event()

    @property
    def running(self) -> bool:
        return not self._stop_event.is_set()

    async def recover_pending_windows(self) -> None:
        """Restore any verification windows that were in progress before shutdown."""

    async def run(self) -> None:
        """Run the scheduler loop until :meth:`stop` is called."""
        await self._stop_event.wait()

    async def stop(self) -> None:
        """Signal the scheduler to stop."""
        self._stop_event.set()

    async def close(self) -> None:
        """Resource-cleanup alias for :meth:`stop`."""
        await self.stop()
