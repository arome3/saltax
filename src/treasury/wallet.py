"""Wallet manager for the agent's on-chain treasury operations.

Manages an autonomous Ethereum wallet whose private key exists only in
Python process memory and is sealed to KMS for crash recovery.  All
transactions use EIP-1559 (type 2) fee estimation on Base L2.
"""

from __future__ import annotations

import asyncio
import logging
import os
import statistics
from typing import TYPE_CHECKING

from eth_account import Account
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

if TYPE_CHECKING:
    from eth_account.signers.local import LocalAccount

    from src.intelligence.sealing import KMSSealManager

logger = logging.getLogger(__name__)

_KMS_KEY = "saltax_wallet_key"

_SIMPLE_GAS = 21_000
_CONTRACT_GAS = 100_000
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds
_MIN_PRIORITY_FEE = 100_000_000  # 0.1 gwei
_DEFAULT_PRIORITY_FEE = 1_000_000_000  # 1 gwei
_MAX_FEE_CAP = 100_000_000_000  # 100 gwei — safety cap against buggy RPC


class WalletManager:
    """Manages the agent's Ethereum wallet derived from KMS-held keys.

    Lifecycle::

        wallet = WalletManager(kms, rpc_url, chain_id)
        await wallet.initialize()   # keygen or recovery
        ...
        await wallet.seal()         # persist key to KMS
        await wallet.close()        # release resources
    """

    def __init__(
        self,
        kms: KMSSealManager,
        rpc_url: str = "https://mainnet.base.org",
        chain_id: int = 8453,
    ) -> None:
        self._kms = kms
        self._rpc_url = rpc_url
        self._chain_id = chain_id
        self._account: LocalAccount | None = None
        self._w3: AsyncWeb3 | None = None
        self._tx_lock = asyncio.Lock()
        self._seal_failed: bool = False

    @property
    def address(self) -> str | None:
        """Return the wallet's checksum address, or ``None`` before init."""
        if self._account is None:
            return None
        return self._account.address

    @property
    def seal_failed(self) -> bool:
        """Whether the last KMS seal attempt failed."""
        return self._seal_failed

    # ── Guards ────────────────────────────────────────────────────────────

    def _require_account(self) -> LocalAccount:
        if self._account is None:
            raise RuntimeError("WalletManager not initialized — call initialize() first")
        return self._account

    def _require_w3(self) -> AsyncWeb3:
        if self._w3 is None:
            raise RuntimeError("WalletManager not initialized — call initialize() first")
        return self._w3

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Derive or recover the wallet key.

        Priority order:

        1. ``MNEMONIC`` env var (injected by ecloud KMS) → deterministic wallet
           that survives upgrades/restarts.  Uses BIP-44 path m/44'/60'/0'/0/0.
        2. KMS unseal succeeds → recovery from sealed key.
        3. KMS unseal fails → first boot, generate new keypair.
           a. KMS seal succeeds → normal operation.
           b. KMS seal fails → ``_seal_failed=True``, continue in-memory.
        4. Unsealed bytes are corrupted → ``RuntimeError`` (do NOT generate
           new key — that would create a second wallet with different address).

        Raises ``RuntimeError`` if called more than once (leaks the old provider).
        """
        if self._account is not None:
            raise RuntimeError("WalletManager already initialized — cannot call initialize() twice")

        # Path 1: Derive from TEE-injected mnemonic (stable across upgrades)
        mnemonic = os.environ.get("MNEMONIC")
        if mnemonic and mnemonic.strip():
            Account.enable_unaudited_hdwallet_features()
            self._account = Account.from_mnemonic(mnemonic.strip())
            logger.info(
                "Wallet derived from TEE mnemonic: %s", self._account.address
            )
            self._w3 = AsyncWeb3(AsyncHTTPProvider(self._rpc_url))
            return

        # Path 2: Try KMS recovery
        try:
            sealed_key = await self._kms.unseal(_KMS_KEY)
        except Exception:
            logger.info("No sealed wallet key found, generating new keypair (first boot)")
            sealed_key = None

        if sealed_key is not None:
            # Recovery path
            try:
                self._account = Account.from_key(sealed_key)
            except Exception:
                raise RuntimeError(
                    "Corrupted wallet key from KMS — manual intervention required"
                ) from None
            logger.info("Recovered wallet from KMS: %s", self._account.address)
        else:
            # Path 3: First boot — generate new keypair
            self._account = Account.create()
            logger.info("Generated new wallet: %s", self._account.address)
            try:
                await self._kms.seal(_KMS_KEY, self._account.key)
                logger.info("Sealed new wallet key to KMS")
            except Exception:
                self._seal_failed = True
                logger.critical("Failed to seal wallet key to KMS — key exists only in memory!")

        self._w3 = AsyncWeb3(AsyncHTTPProvider(self._rpc_url))

    # ── Read operations ───────────────────────────────────────────────────

    async def get_balance(self) -> int:
        """Return the wallet balance in Wei."""
        account = self._require_account()
        w3 = self._require_w3()
        return await w3.eth.get_balance(account.address, block_identifier="latest")

    # ── Fee estimation ────────────────────────────────────────────────────

    async def _estimate_eip1559_fees(self) -> tuple[int, int]:
        """Estimate EIP-1559 fees from recent block history.

        Returns ``(max_fee_per_gas, max_priority_fee_per_gas)`` in Wei.

        Uses ``eth_feeHistory`` with 4 blocks and 10th/90th percentile
        reward tiers.  The priority fee is the median of the 10th-percentile
        rewards (conservative), floored at 0.1 gwei.

        ``max_fee = 2 * next_base_fee + priority_fee`` provides headroom
        for 2 consecutive full blocks of base fee increases.
        """
        w3 = self._require_w3()
        fee_history = await w3.eth.fee_history(4, "latest", [10, 90])

        # next_base_fee is the predicted base fee for the next block
        next_base_fee = fee_history["baseFeePerGas"][-1]

        # Collect 10th-percentile priority fees from each block
        rewards_10th = [r[0] for r in fee_history["reward"] if r]

        if rewards_10th:
            priority_fee = statistics.median(rewards_10th)
            priority_fee = max(int(priority_fee), _MIN_PRIORITY_FEE)
        else:
            # Fallback: empty rewards (e.g. empty blocks)
            priority_fee = _DEFAULT_PRIORITY_FEE

        max_fee = 2 * next_base_fee + priority_fee
        if max_fee > _MAX_FEE_CAP:
            logger.warning(
                "Computed max_fee %d exceeds cap %d — capping to prevent overpay",
                max_fee,
                _MAX_FEE_CAP,
            )
            max_fee = _MAX_FEE_CAP
        return max_fee, priority_fee

    # ── Transactions ──────────────────────────────────────────────────────

    async def send_transaction(
        self,
        to: str,
        value_wei: int,
        data: bytes = b"",
        gas: int | None = None,
    ) -> str:
        """Build, sign, and broadcast an EIP-1559 transaction.

        Acquires ``_tx_lock`` for the entire retry loop to prevent nonce
        interleaving between concurrent callers.  Retries up to 3 times
        with exponential backoff (1s, 2s, 4s).

        Returns the transaction hash as a hex string.
        """
        if not AsyncWeb3.is_checksum_address(to):
            raise ValueError(f"Invalid checksum address: {to}")

        account = self._require_account()
        w3 = self._require_w3()

        async with self._tx_lock:
            last_exc: Exception | None = None
            for attempt in range(_MAX_RETRIES):
                try:
                    nonce = await w3.eth.get_transaction_count(
                        account.address, block_identifier="pending"
                    )
                    max_fee, priority_fee = await self._estimate_eip1559_fees()

                    gas_limit = gas if gas is not None else (
                        _CONTRACT_GAS if data else _SIMPLE_GAS
                    )

                    tx = {
                        "type": "0x2",
                        "chainId": self._chain_id,
                        "to": to,
                        "value": value_wei,
                        "nonce": nonce,
                        "gas": gas_limit,
                        "maxFeePerGas": max_fee,
                        "maxPriorityFeePerGas": priority_fee,
                        "data": data,
                    }

                    try:
                        signed = account.sign_transaction(tx)
                    except Exception:
                        raise RuntimeError("Transaction signing failed") from None

                    tx_hash = await w3.eth.send_raw_transaction(signed.rawTransaction)
                    return tx_hash.hex()

                except RuntimeError:
                    # signing failure — don't retry
                    raise
                except Exception as exc:
                    last_exc = exc
                    delay = _RETRY_BACKOFF_BASE * (2**attempt)
                    logger.warning(
                        "Transaction attempt %d/%d failed: %s, retrying in %.1fs",
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)

            raise RuntimeError(f"Transaction failed after {_MAX_RETRIES} attempts: {last_exc}")

    # ── Signing ───────────────────────────────────────────────────────────

    def sign_message(self, message: bytes) -> str:
        """Sign a message using EIP-191 and return the signature hex.

        Import ``encode_defunct`` at call site to keep it out of module scope.
        """
        account = self._require_account()
        from eth_account.messages import encode_defunct

        try:
            signable = encode_defunct(primitive=message)
            signed = account.sign_message(signable)
            return signed.signature.hex()
        except Exception:
            raise RuntimeError("Message signing failed") from None

    # ── Seal / Close ──────────────────────────────────────────────────────

    async def seal(self) -> None:
        """Persist the private key to KMS for crash recovery.

        Must be called explicitly before ``close()``.  Exceptions are
        caught and logged — shutdown must be robust.
        """
        if self._account is None:
            return
        try:
            await self._kms.seal(_KMS_KEY, self._account.key)
            if self._seal_failed:
                logger.info("Seal recovered — previously failed KMS seal now succeeded")
                self._seal_failed = False
            logger.info("Sealed wallet key to KMS")
        except Exception:
            self._seal_failed = True
            logger.exception("Failed to seal wallet key to KMS during shutdown")

    async def close(self) -> None:
        """Release wallet resources.  Does NOT call ``seal()``."""
        self._account = None
        self._w3 = None
