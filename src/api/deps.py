"""FastAPI dependency-injection helpers.

Each function extracts a service from ``request.app.state`` so that route
handlers can declare dependencies via ``Depends(get_pipeline)`` instead of
reaching into application state directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request  # noqa: TC002 — FastAPI resolves annotations at runtime

if TYPE_CHECKING:
    from src.api.middleware.tx_store import TxHashStore
    from src.api.middleware.x402 import PaymentVerifier
    from src.config import EnvConfig, SaltaXConfig
    from src.disputes.router import DisputeRouter
    from src.github.client import GitHubClient
    from src.identity.registration import IdentityRegistrar
    from src.identity.reputation import ReputationManager
    from src.intelligence.database import IntelligenceDB
    from src.pipeline.runner import Pipeline
    from src.treasury.manager import TreasuryManager
    from src.treasury.wallet import WalletManager
    from src.verification.scheduler import VerificationScheduler


def get_config(request: Request) -> SaltaXConfig:
    """Return the YAML configuration object."""
    return request.app.state.config  # type: ignore[no-any-return]


def get_env(request: Request) -> EnvConfig:
    """Return the runtime environment configuration."""
    return request.app.state.env  # type: ignore[no-any-return]


def get_pipeline(request: Request) -> Pipeline:
    """Return the code-review pipeline runner."""
    return request.app.state.pipeline  # type: ignore[no-any-return]


def get_wallet(request: Request) -> WalletManager:
    """Return the treasury wallet manager."""
    return request.app.state.wallet  # type: ignore[no-any-return]


def get_intel_db(request: Request) -> IntelligenceDB:
    """Return the intelligence pattern database."""
    return request.app.state.intel_db  # type: ignore[no-any-return]


def get_identity(request: Request) -> IdentityRegistrar:
    """Return the on-chain identity registrar."""
    return request.app.state.identity  # type: ignore[no-any-return]


def get_scheduler(request: Request) -> VerificationScheduler:
    """Return the verification window scheduler."""
    return request.app.state.scheduler  # type: ignore[no-any-return]


def get_github_client(request: Request) -> GitHubClient:
    """Return the GitHub API client."""
    return request.app.state.github_client  # type: ignore[no-any-return]


def get_treasury_manager(request: Request) -> TreasuryManager:
    """Return the treasury manager."""
    return request.app.state.treasury_mgr  # type: ignore[no-any-return]


def get_payment_verifier(request: Request) -> PaymentVerifier:
    """Return the x402 payment verifier."""
    return request.app.state.payment_verifier  # type: ignore[no-any-return]


def get_tx_store(request: Request) -> TxHashStore:
    """Return the durable transaction hash store."""
    return request.app.state.tx_store  # type: ignore[no-any-return]


def get_reputation_manager(request: Request) -> ReputationManager:
    """Return the reputation manager."""
    return request.app.state.reputation_mgr  # type: ignore[no-any-return]


def get_dispute_router(request: Request) -> DisputeRouter:
    """Return the dispute router."""
    return request.app.state.dispute_router  # type: ignore[no-any-return]
