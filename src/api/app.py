"""FastAPI application factory for the SaltaX HTTP interface."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.api.middleware.rate_limiter import RateLimiterMiddleware
from src.api.routes.attestation import router as attestation_router
from src.api.routes.audit import router as audit_router
from src.api.routes.bounties import router as bounties_router
from src.api.routes.intelligence import router as intelligence_router
from src.api.routes.status import router as status_router
from src.api.routes.vision import router as vision_router
from src.api.routes.webhook import router as webhook_router

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from src.api.middleware.tx_store import TxHashStore
    from src.api.middleware.x402 import PaymentVerifier
    from src.config import EnvConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.identity.registration import IdentityRegistrar
    from src.intelligence.database import IntelligenceDB
    from src.pipeline.runner import Pipeline
    from src.treasury.manager import TreasuryManager
    from src.treasury.wallet import WalletManager
    from src.verification.scheduler import VerificationScheduler

logger = logging.getLogger(__name__)


def create_app(
    config: SaltaXConfig,
    env: EnvConfig,
    pipeline: Pipeline,
    wallet: WalletManager,
    intel_db: IntelligenceDB,
    identity: IdentityRegistrar,
    scheduler: VerificationScheduler,
    github_client: GitHubClient,
    treasury_mgr: TreasuryManager,
    payment_verifier: PaymentVerifier,
    tx_store: TxHashStore | None = None,
) -> FastAPI:
    """Build the FastAPI application with all dependencies wired to ``app.state``."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="SaltaX — Sovereign Code Organism",
        description="Sovereign Code Organism API",
        version=config.version,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )

    app.state.config = config
    app.state.env = env
    app.state.pipeline = pipeline
    app.state.wallet = wallet
    app.state.intel_db = intel_db
    app.state.identity = identity
    app.state.scheduler = scheduler
    app.state.github_client = github_client
    app.state.treasury_mgr = treasury_mgr
    app.state.payment_verifier = payment_verifier
    app.state.tx_store = tx_store

    # ── Global exception handlers ────────────────────────────────────
    _register_exception_handlers(app)

    # ── Middleware (rate limiter runs first for all requests) ─────────
    app.add_middleware(RateLimiterMiddleware, global_rpm=60, audit_rpm=10)

    # ── Routers ──────────────────────────────────────────────────────
    app.include_router(webhook_router)
    app.include_router(status_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(attestation_router, prefix="/api/v1")
    app.include_router(bounties_router, prefix="/api/v1")
    app.include_router(intelligence_router, prefix="/api/v1")
    app.include_router(vision_router, prefix="/api/v1")

    # ── Liveness probe ───────────────────────────────────────────────
    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        """Kubernetes liveness probe with downstream service checks."""
        checks: dict[str, bool] = {
            "intel_db": app.state.intel_db.initialized,
            "scheduler": app.state.scheduler.running,
            "wallet": app.state.wallet.address is not None,
        }
        all_healthy = all(checks.values())
        return JSONResponse(
            status_code=200 if all_healthy else 503,
            content={"status": "ok" if all_healthy else "degraded", "checks": checks},
        )

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    """Wire global exception handlers that return sanitized ErrorResponse JSON."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status_code": exc.status_code,
                "error": _status_phrase(exc.status_code),
                "detail": str(exc.detail),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "status_code": 422,
                "error": "Unprocessable Entity",
                "detail": str(exc.errors()),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        logger.exception(
            "Unhandled exception on %s %s",
            request.method,
            request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content={
                "status_code": 500,
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred",
            },
        )


def _status_phrase(code: int) -> str:
    """Map HTTP status codes to standard reason phrases."""
    phrases = {
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }
    return phrases.get(code, "Error")
