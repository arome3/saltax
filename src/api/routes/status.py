"""Agent status endpoint — health, treasury, reputation, intelligence."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends

from src.api.deps import get_config, get_identity, get_intel_db, get_treasury_manager, get_wallet

if TYPE_CHECKING:
    from src.config import SaltaXConfig
    from src.identity.registration import IdentityRegistrar
    from src.intelligence.database import IntelligenceDB
    from src.treasury.manager import TreasuryManager
    from src.treasury.wallet import WalletManager

router = APIRouter()

_BOOT_TIME = time.monotonic()


@router.get("/status")
async def agent_status(
    config: SaltaXConfig = Depends(get_config),  # noqa: B008
    wallet: WalletManager = Depends(get_wallet),  # noqa: B008
    identity: IdentityRegistrar = Depends(get_identity),  # noqa: B008
    intel_db: IntelligenceDB = Depends(get_intel_db),  # noqa: B008
    treasury_mgr: TreasuryManager = Depends(get_treasury_manager),  # noqa: B008
) -> dict[str, Any]:
    """Return full agent status: identity, treasury, reputation, intelligence."""
    pattern_count = await intel_db.count_patterns()
    uptime = time.monotonic() - _BOOT_TIME

    try:
        snap = await treasury_mgr.check_balance()
        treasury_data: dict[str, object] = {
            "balance_wei": snap.balance_wei,
            "reserve_wei": snap.reserve_wei,
            "bounty_wei": snap.bounty_wei,
            "available": True,
        }
    except Exception:
        treasury_data = {"balance_wei": 0, "available": False}

    return {
        "agent": {
            "name": config.agent.name,
            "version": config.version,
            "wallet_address": wallet.address,
            "erc8004_id": identity.agent_id,
            "uptime_seconds": round(uptime, 1),
        },
        "treasury": treasury_data,
        "reputation": {
            "total_prs_reviewed": 0,
            "approval_rate": 0.0,
            "dispute_accuracy": 0.0,
            "total_audits": 0,
        },
        "intelligence": {
            "total_patterns": pattern_count,
            "db_initialized": intel_db.initialized,
        },
    }
