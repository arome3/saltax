"""SaltaX bootstrap — 5-phase ordered initialization of the sovereign agent.

Entry points
~~~~~~~~~~~~
- ``pyproject.toml`` console script: ``saltax = "src.main:main"``
- Docker: ``python -m src.main``

Phase sequence
~~~~~~~~~~~~~~
1. Configuration  — load YAML + env, cross-validate
2. Cryptographic Identity — KMS, wallet, on-chain identity
3. State Recovery — intelligence database
4. Build Connections — pipeline, verification scheduler
5. Start Services — FastAPI + uvicorn, scheduler task, TS proxy
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
from contextlib import suppress
from typing import Any

import uvicorn
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

from src.api.app import create_app
from src.api.middleware.tx_store import TxHashStore
from src.api.middleware.x402 import PaymentVerifier
from src.config import EnvConfig, SaltaXConfig, validate_config
from src.disputes.eigen_verify import EigenVerifyClient
from src.disputes.molt_court import MoltCourtClient
from src.disputes.router import DisputeRouter
from src.disputes.scheduler import DisputeScheduler
from src.github.client import GitHubClient
from src.identity.bridge_client import IdentityBridgeClient
from src.identity.registration import IdentityRegistrar
from src.identity.reputation import ReputationManager
from src.intelligence.database import IntelligenceDB
from src.intelligence.sealing import KMSSealManager
from src.intelligence.vector_index import VectorIndexManager, maybe_enable_vector_index
from src.observability import configure_logging
from src.observability.metrics import BudgetTracker
from src.patrol.scheduler import PatrolScheduler
from src.pipeline.runner import build_pipeline
from src.staking import StakeResolver, StakingContract, StakingEconomics
from src.treasury.manager import TreasuryManager
from src.treasury.policy import TreasuryPolicy
from src.treasury.wallet import WalletManager
from src.verification.scheduler import VerificationScheduler

logger = logging.getLogger("saltax.bootstrap")

_SHUTDOWN_TIMEOUT = 30.0

# Ownable2Step function selectors (keccak256 of signature, first 4 bytes)
_ACCEPT_OWNERSHIP_SELECTOR = bytes.fromhex("79ba5097")
_PENDING_OWNER_SELECTOR = bytes.fromhex("e30c3978")


async def _try_accept_ownership(
    wallet: WalletManager,
    contract_address: str,
    label: str,
) -> None:
    """Accept pending ownership on an Ownable2Step contract if this wallet is pendingOwner.

    Idempotent: no-ops if wallet is not the pending owner or if the call fails.
    """
    try:
        w3 = AsyncWeb3(AsyncHTTPProvider(wallet._rpc_url))
        result = await w3.eth.call({
            "to": AsyncWeb3.to_checksum_address(contract_address),
            "data": _PENDING_OWNER_SELECTOR,
        })
        raw_hex = result[-20:].hex()
        pending = AsyncWeb3.to_checksum_address(raw_hex if raw_hex.startswith("0x") else "0x" + raw_hex)
        if pending.lower() != (wallet.address or "").lower():
            return  # not the pending owner — nothing to do
        tx_hash = await wallet.send_transaction(
            to=AsyncWeb3.to_checksum_address(contract_address),
            value_wei=0,
            data=_ACCEPT_OWNERSHIP_SELECTOR,
            gas=60_000,
        )
        logger.info(
            "Accepted ownership of %s contract: tx=%s", label, tx_hash
        )
    except Exception:
        logger.debug("acceptOwnership skipped for %s", label, exc_info=True)


# ── TS proxy subprocess manager ──────────────────────────────────────────────


class TSProxyManager:
    """Manages the TypeScript GitHub-proxy subprocess lifecycle."""

    def __init__(
        self,
        *,
        max_retries: int = 3,
        check_interval: float = 5.0,
        terminate_timeout: float = 10.0,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        self._max_retries = max_retries
        self._check_interval = check_interval
        self._terminate_timeout = terminate_timeout
        self._extra_env = extra_env or {}
        self._process: subprocess.Popen[bytes] | None = None
        self._monitor_task: asyncio.Task[None] | None = None
        self._retries = 0
        self._stopped = False

    def _start_process(self) -> subprocess.Popen[bytes]:
        env = {**os.environ, **self._extra_env} if self._extra_env else None
        return subprocess.Popen(
            ["node", "dist/index.js"],
            cwd="github-proxy",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

    def start(self) -> None:
        """Launch the TS proxy and begin monitoring."""
        self._stopped = False
        self._retries = 0
        self._process = self._start_process()
        loop = asyncio.get_running_loop()
        self._monitor_task = loop.create_task(self._monitor())

    async def _monitor(self) -> None:
        """Poll the subprocess and restart on crash up to *max_retries*."""
        while not self._stopped:
            await asyncio.sleep(self._check_interval)
            if self._stopped:
                break
            if self._process is not None and self._process.poll() is not None:
                self._retries += 1
                if self._retries > self._max_retries:
                    logger.error(
                        "TS proxy exceeded max retries (%d), giving up",
                        self._max_retries,
                    )
                    break
                logger.warning(
                    "TS proxy crashed (attempt %d/%d), restarting",
                    self._retries,
                    self._max_retries,
                )
                try:
                    self._process = self._start_process()
                except Exception:
                    logger.exception(
                        "Failed to restart TS proxy (attempt %d/%d)",
                        self._retries,
                        self._max_retries,
                    )

    async def stop(self) -> None:
        """Gracefully stop the TS proxy subprocess."""
        self._stopped = True

        if self._monitor_task is not None:
            self._monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._monitor_task

        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            loop = asyncio.get_running_loop()
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, self._process.wait),
                    timeout=self._terminate_timeout,
                )
            except TimeoutError:
                self._process.kill()
                await loop.run_in_executor(None, self._process.wait)

    async def close(self) -> None:
        """Resource-cleanup alias for :meth:`stop`."""
        await self.stop()


# ── Teardown ─────────────────────────────────────────────────────────────────


async def _teardown(resources: list[tuple[str, Any]]) -> None:
    """Close resources in reverse initialization order.

    Each entry is ``(label, resource)``.  Resources must have an async
    ``close()`` method.  Errors are logged but never re-raised so that all
    resources get a chance to clean up.
    """
    for label, resource in reversed(resources):
        try:
            await resource.close()
            logger.info("Closed %s", label)
        except Exception:
            logger.exception("Error closing %s", label)


# ── Graceful shutdown ────────────────────────────────────────────────────────


async def _graceful_shutdown(
    *,
    server: uvicorn.Server,
    server_task: asyncio.Task[None],
    scheduler: VerificationScheduler,
    scheduler_task: asyncio.Task[None],
    dispute_scheduler: DisputeScheduler,
    dispute_scheduler_task: asyncio.Task[None],
    intel_db: IntelligenceDB,
    kms: KMSSealManager,
    wallet: WalletManager,
    identity: IdentityRegistrar,
    ts_proxy: TSProxyManager,
    patrol_scheduler: PatrolScheduler | None = None,
    patrol_scheduler_task: asyncio.Task[None] | None = None,
    timeout: float = _SHUTDOWN_TIMEOUT,
) -> None:
    """Execute the ordered shutdown sequence with a timeout.

    Each step is individually wrapped so that a failure in one does not
    prevent the remaining steps from executing.  A global timeout guards
    against any single step hanging indefinitely.
    """
    logger.info("Beginning graceful shutdown")
    try:
        async with asyncio.timeout(timeout):
            server.should_exit = True

            # Stop patrol BEFORE dispute_scheduler (patrol creates work that
            # dispute processes).
            if patrol_scheduler is not None:
                try:
                    await patrol_scheduler.close()
                except Exception:
                    logger.exception("Error stopping patrol scheduler")

            try:
                await dispute_scheduler.stop()
            except Exception:
                logger.exception("Error stopping dispute scheduler")

            try:
                await scheduler.stop()
            except Exception:
                logger.exception("Error stopping scheduler")

            try:
                await intel_db.seal(kms)
            except Exception:
                logger.exception("Error sealing intelligence DB")

            try:
                await wallet.seal()
            except Exception:
                logger.exception("Error sealing wallet key")

            # Close identity (and its bridge httpx client) before stopping
            # the TS proxy — the client talks to the proxy.
            try:
                await identity.close()
            except Exception:
                logger.exception("Error closing identity registrar")

            try:
                await ts_proxy.stop()
            except Exception:
                logger.exception("Error stopping TS proxy")

            try:
                await server_task
            except Exception:
                logger.exception("Error awaiting server shutdown")
    except TimeoutError:
        logger.error("Graceful shutdown timed out after %.0fs", timeout)
    finally:
        all_tasks = tuple(
            t for t in (
                server_task, scheduler_task,
                dispute_scheduler_task, patrol_scheduler_task,
            )
            if t is not None
        )
        for task in all_tasks:
            if not task.done():
                task.cancel()
        with suppress(asyncio.CancelledError):
            await asyncio.gather(*all_tasks, return_exceptions=True)
    logger.info("SaltaX shutdown complete")


# ── Bootstrap ────────────────────────────────────────────────────────────────


async def bootstrap() -> None:  # noqa: C901
    """Execute the 5-phase bootstrap sequence."""
    configure_logging()
    logger.info("SaltaX bootstrap starting")

    resources: list[tuple[str, Any]] = []

    # ── Phase 1: Configuration ───────────────────────────────────────────
    try:
        logger.info("Phase 1: Configuration")
        config = SaltaXConfig.load()
        env = EnvConfig()
        errors = validate_config(config)
        if errors:
            for err in errors:
                logger.error("Config validation: %s", err)
            sys.exit(1)
        logger.info("Phase 1 complete — config validated")
    except SystemExit:
        raise
    except Exception:
        logger.exception("Phase 1 failed")
        sys.exit(1)

    # ── Phase 2: Cryptographic Identity ──────────────────────────────────
    try:
        logger.info("Phase 2: Cryptographic Identity")
        kms = KMSSealManager(env.eigencloud_kms_endpoint)
        resources.append(("kms", kms))
        wallet = WalletManager(kms=kms, rpc_url=env.rpc_url, chain_id=env.chain_id)
        resources.append(("wallet", wallet))
        await wallet.initialize()
        bridge_client = IdentityBridgeClient(env.identity_bridge_url)
        resources.append(("bridge_client", bridge_client))
        identity = IdentityRegistrar(
            wallet,
            bridge_client,
            env.identity_chain_id,
            agent_name=config.agent.name,
            agent_description=config.agent.description,
        )
        resources.append(("identity", identity))
        # register_or_recover() deferred to Phase 3 (needs intel_db for cache)
        logger.info("Phase 2 complete — wallet=%s", wallet.address)
    except Exception:
        logger.exception("Phase 2 failed")
        await _teardown(resources)
        sys.exit(1)

    # ── Phase 3: State Recovery ──────────────────────────────────────────
    try:
        logger.info("Phase 3: State Recovery")
        intel_db = IntelligenceDB(kms=kms)
        await intel_db.initialize()
        resources.append(("intel_db", intel_db))
        pattern_count = await intel_db.count_patterns()

        # Vector index (ephemeral HNSW acceleration layer)
        vector_index_manager = VectorIndexManager(config)
        await vector_index_manager.initialize(intel_db)
        await maybe_enable_vector_index(intel_db, config, vector_index_manager)
        resources.append(("vector_index_manager", vector_index_manager))

        # Wire intel_db to identity for cache recovery, then register
        identity.intel_db = intel_db
        await identity.register_or_recover()
        logger.info(
            "Phase 3 complete — %d patterns loaded, agent_id=%s",
            pattern_count,
            identity.agent_id,
        )
    except Exception:
        logger.exception("Phase 3 failed")
        await _teardown(resources)
        sys.exit(1)

    # ── Phase 4: Build Connections ───────────────────────────────────────
    try:
        logger.info("Phase 4: Build Connections")
        from src.attestation.engine import AttestationEngine  # noqa: PLC0415
        from src.attestation.store import AttestationStore  # noqa: PLC0415

        budget_tracker = BudgetTracker()
        attestation_store = AttestationStore(intel_db)
        attestation_engine = AttestationEngine(wallet=wallet, store=attestation_store)
        pipeline = build_pipeline(
            config, env, intel_db, attestation_engine,
            budget_tracker=budget_tracker,
        )
        github_client = GitHubClient(
            app_id=env.github_app_id,
            private_key=env.github_app_private_key,
        )
        resources.append(("github_client", github_client))
        treasury_policy = TreasuryPolicy(config.treasury)
        treasury_mgr = TreasuryManager(
            wallet=wallet,
            policy=treasury_policy,
            intel_db=intel_db,
            treasury_config=config.treasury,
            bounty_config=config.bounties,
            budget_tracker=budget_tracker,
        )
        resources.append(("treasury_mgr", treasury_mgr))
        scheduler = VerificationScheduler(
            config, intel_db, github_client, treasury_mgr, kms=kms,
            budget_tracker=budget_tracker,
        )
        resources.append(("scheduler", scheduler))
        await scheduler.recover_pending_windows()

        payment_verifier = PaymentVerifier(
            facilitator_url=env.facilitator_url,
            pay_to_address=env.payment_wallet_address or wallet.address,
        )
        resources.append(("payment_verifier", payment_verifier))

        tx_store = TxHashStore(db_path="data/tx_hashes.db")
        await tx_store.initialize()
        resources.append(("tx_store", tx_store))

        reputation_mgr = ReputationManager(
            bridge_client, intel_db, identity.agent_id or "",
        )
        resources.append(("reputation_mgr", reputation_mgr))

        # Dispute resolution subsystem
        eigen_client = EigenVerifyClient(config.disputes, env.eigenverify_api_key)
        resources.append(("eigen_client", eigen_client))
        molt_client = MoltCourtClient(config.disputes, env.moltcourt_api_key)
        resources.append(("molt_client", molt_client))
        staking_economics = StakingEconomics(config.staking)
        staking_contract = StakingContract(wallet, config.staking, env.rpc_url)
        if config.staking.enabled and config.staking.contract_address:
            await staking_contract.initialize()
            resources.append(("staking_contract", staking_contract))
            await _try_accept_ownership(wallet, config.staking.contract_address, "Staking")
        if config.treasury.contract_address:
            await _try_accept_ownership(wallet, config.treasury.contract_address, "Treasury")
        stake_resolver = StakeResolver(staking_contract, staking_economics)
        dispute_router = DisputeRouter(
            config.disputes, intel_db, eigen_client, molt_client,
            stake_resolver, staking_contract,
        )
        resources.append(("dispute_router", dispute_router))
        dispute_scheduler = DisputeScheduler(
            config.disputes, intel_db, dispute_router, scheduler,
        )
        resources.append(("dispute_scheduler", dispute_scheduler))

        # Patrol scheduler (autonomous repo scanning)
        patrol_scheduler: PatrolScheduler | None = None
        if config.patrol.enabled:
            patrol_scheduler = PatrolScheduler(
                config, env, github_client, intel_db,
                treasury_mgr, attestation_engine,
            )
            resources.append(("patrol_scheduler", patrol_scheduler))

        logger.info("Phase 4 complete — pipeline, GitHub client, scheduler, and treasury ready")
    except Exception:
        logger.exception("Phase 4 failed")
        await _teardown(resources)
        sys.exit(1)

    # ── Phase 5: Start Services ──────────────────────────────────────────
    scheduler_task: asyncio.Task[None] | None = None
    dispute_scheduler_task: asyncio.Task[None] | None = None
    patrol_scheduler_task: asyncio.Task[None] | None = None
    server_task: asyncio.Task[None] | None = None
    try:
        logger.info("Phase 5: Start Services")
        app = create_app(
            config,
            env,
            pipeline,
            wallet,
            intel_db,
            identity,
            scheduler,
            github_client,
            treasury_mgr=treasury_mgr,
            payment_verifier=payment_verifier,
            tx_store=tx_store,
            reputation_mgr=reputation_mgr,
            dispute_router_inst=dispute_router,
            kms=kms,
            budget_tracker=budget_tracker,
            vector_index_manager=vector_index_manager,
        )

        scheduler_task = asyncio.create_task(scheduler.run())
        dispute_scheduler_task = asyncio.create_task(dispute_scheduler.run())

        if patrol_scheduler is not None:
            patrol_scheduler_task = asyncio.create_task(patrol_scheduler.run())

        # Build identity env for the TS proxy subprocess
        identity_env: dict[str, str] = {
            "IDENTITY_RPC_URL": env.identity_rpc_url,
            "IDENTITY_CHAIN_ID": str(env.identity_chain_id),
        }
        if env.pinata_jwt:
            identity_env["PINATA_JWT"] = env.pinata_jwt
        # Pass wallet private key for on-chain tx signing (both in same TEE)
        if wallet.address is not None:
            try:
                identity_env["IDENTITY_PRIVATE_KEY"] = wallet._require_account().key.hex()
            except RuntimeError:
                logger.warning("Wallet not initialized, skipping IDENTITY_PRIVATE_KEY")

        ts_proxy = TSProxyManager(extra_env=identity_env)
        ts_proxy.start()
        resources.append(("ts_proxy", ts_proxy))

        uvicorn_config = uvicorn.Config(
            app,
            host=env.host,
            port=env.port,
            log_level=env.log_level.lower(),
        )
        server = uvicorn.Server(uvicorn_config)

        shutdown_event = asyncio.Event()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown_event.set)

        server_task = asyncio.create_task(server.serve())

        logger.info("Phase 5 complete — SaltaX is live on %s:%d", env.host, env.port)

        # Block until shutdown signal
        await shutdown_event.wait()
        logger.info("Shutdown signal received")

    except Exception:
        logger.exception("Phase 5 failed")
        for task in (scheduler_task, dispute_scheduler_task, patrol_scheduler_task, server_task):
            if task is not None:
                task.cancel()
        await _teardown(resources)
        sys.exit(1)

    # ── Graceful shutdown ────────────────────────────────────────────────
    await _graceful_shutdown(
        server=server,
        server_task=server_task,
        scheduler=scheduler,
        scheduler_task=scheduler_task,
        dispute_scheduler=dispute_scheduler,
        dispute_scheduler_task=dispute_scheduler_task,
        intel_db=intel_db,
        kms=kms,
        wallet=wallet,
        identity=identity,
        ts_proxy=ts_proxy,
        patrol_scheduler=patrol_scheduler,
        patrol_scheduler_task=patrol_scheduler_task,
    )


# ── Sync entry point ─────────────────────────────────────────────────────────


def main() -> None:
    """Sync entry point for ``pyproject.toml`` console script."""
    asyncio.run(bootstrap())


if __name__ == "__main__":
    main()
