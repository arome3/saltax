"""Identity endpoint — combines on-chain identity with local reputation metrics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends

from src.api.deps import get_identity, get_reputation_manager

if TYPE_CHECKING:
    from src.identity.registration import IdentityRegistrar
    from src.identity.reputation import ReputationManager

router = APIRouter()


@router.get("/identity")
async def get_agent_identity(
    identity: IdentityRegistrar = Depends(get_identity),  # noqa: B008
    reputation_mgr: ReputationManager = Depends(get_reputation_manager),  # noqa: B008
) -> dict[str, Any]:
    """Return agent identity, local metrics, and on-chain reputation."""
    id_data: dict[str, Any] = {
        "agent_id": identity.agent_id,
        "chain_id": None,
        "wallet_address": None,
        "name": None,
        "description": None,
    }
    if identity.identity is not None:
        id_model = identity.identity
        id_data.update({
            "chain_id": id_model.chain_id,
            "wallet_address": id_model.wallet_address,
            "name": id_model.name,
            "description": id_model.description,
            "registered_at": id_model.registered_at.isoformat(),
        })

    # Local metrics (from pipeline_history)
    try:
        local_metrics = await reputation_mgr.get_metrics()
        metrics_data = local_metrics.model_dump()
    except Exception:
        metrics_data = {}

    # On-chain reputation (from bridge)
    try:
        on_chain = await reputation_mgr.get_on_chain_reputation()
    except Exception:
        on_chain = None

    return {
        "identity": id_data,
        "local_metrics": metrics_data,
        "on_chain_reputation": on_chain,
    }
