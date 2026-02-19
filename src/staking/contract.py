"""On-chain staking contract wrapper.

Encodes function calls using the embedded ABI, delegates transaction
signing and nonce management to :class:`WalletManager`, and provides
receipt polling and event parsing for deposit verification.

Concurrency model:
- **Writes**: All write methods call ``wallet.send_transaction()`` which
  serialises nonce management via ``WalletManager._tx_lock``.
- **Reads**: Use a separate ``AsyncWeb3`` instance (``_read_w3``) for
  receipt polling and view calls — no lock needed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from web3 import AsyncWeb3
from web3.exceptions import TransactionNotFound
from web3.providers import AsyncHTTPProvider

if TYPE_CHECKING:
    from src.config import StakingConfig
    from src.treasury.wallet import WalletManager

logger = logging.getLogger(__name__)

# ── ABI ──────────────────────────────────────────────────────────────────────
# Derived from the ContributorStaking Solidity contract (doc 25).

_STAKING_ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "depositStake",
        "stateMutability": "payable",
        "inputs": [
            {"name": "stakeId", "type": "bytes32"},
            {"name": "prId", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "releaseStake",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "stakeId", "type": "bytes32"},
            {"name": "bonusAmount", "type": "uint256"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "slashStake",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "stakeId", "type": "bytes32"},
            {"name": "slashPercent", "type": "uint256"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "refundStake",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "stakeId", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "withdrawSlashed",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "stakes",
        "stateMutability": "view",
        "inputs": [
            {"name": "stakeId", "type": "bytes32"},
        ],
        "outputs": [
            {"name": "staker", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "prId", "type": "bytes32"},
            {"name": "resolved", "type": "bool"},
            {"name": "timestamp", "type": "uint256"},
        ],
    },
    {
        "type": "event",
        "name": "StakeDeposited",
        "inputs": [
            {"name": "stakeId", "type": "bytes32", "indexed": True},
            {"name": "staker", "type": "address", "indexed": True},
            {"name": "amount", "type": "uint256", "indexed": False},
            {"name": "prId", "type": "bytes32", "indexed": False},
        ],
    },
    {
        "type": "receive",
        "stateMutability": "payable",
    },
]

_RECEIPT_POLL_INTERVAL = 2  # seconds


class StakingContract:
    """Wrapper around the on-chain ContributorStaking contract.

    Lifecycle::

        sc = StakingContract(wallet, config, rpc_url)
        await sc.initialize()
        tx = await sc.deposit_stake(stake_id, pr_id, amount)
        await sc.close()
    """

    def __init__(
        self,
        wallet: WalletManager,
        config: StakingConfig,
        rpc_url: str,
    ) -> None:
        self._wallet = wallet
        self._config = config
        self._rpc_url = rpc_url
        self._read_w3: AsyncWeb3 | None = None
        self._contract_address: str = ""
        self._initialized: bool = False

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Set up the read-only Web3 provider and validate config.

        Raises ``RuntimeError`` on double-init or empty contract address.
        Uses ``try/finally`` so a partial failure (e.g. bad address format)
        doesn't leave the object in an inconsistent state.
        """
        if self._initialized:
            raise RuntimeError("StakingContract already initialized")
        if not self._config.contract_address:
            raise RuntimeError(
                "StakingConfig.contract_address is empty — "
                "deploy the contract and set the address before initializing"
            )
        try:
            self._contract_address = AsyncWeb3.to_checksum_address(
                self._config.contract_address
            )
            self._read_w3 = AsyncWeb3(AsyncHTTPProvider(self._rpc_url))
            self._initialized = True
        except Exception:
            # Roll back partial state so the object can be retried or discarded
            self._read_w3 = None
            self._contract_address = ""
            self._initialized = False
            raise
        logger.info(
            "StakingContract initialized",
            extra={"contract": self._contract_address},
        )

    async def close(self) -> None:
        """Release resources."""
        self._read_w3 = None
        self._initialized = False

    def _require_init(self) -> AsyncWeb3:
        if not self._initialized or self._read_w3 is None:
            raise RuntimeError(
                "StakingContract not initialized — call initialize() first"
            )
        return self._read_w3

    # ── ABI encoding helper ──────────────────────────────────────────────

    def _encode(self, fn_name: str, args: list[Any]) -> bytes:
        """Encode a contract function call using the embedded ABI."""
        w3 = self._require_init()
        contract = w3.eth.contract(
            address=self._contract_address, abi=_STAKING_ABI,
        )
        return bytes.fromhex(
            contract.encode_abi(fn_name=fn_name, args=args).removeprefix("0x")
        )

    async def _estimate_gas(self, data: bytes, value_wei: int = 0) -> int:
        """Try ``eth_estimateGas`` with a 20% buffer, fall back to config limit.

        Returns the gas limit to use for the transaction. Uses
        ``estimate * 120 // 100`` (integer arithmetic, no floats) to
        add headroom for EVM gas variance, capped at ``fallback_gas_limit``.
        """
        w3 = self._require_init()
        try:
            estimate = await w3.eth.estimate_gas({
                "to": self._contract_address,
                "data": data,
                "value": value_wei,
            })
            buffered = estimate * 120 // 100
            return min(buffered, self._config.fallback_gas_limit)
        except Exception:  # noqa: BLE001 — RPC may not support estimation
            logger.debug(
                "Gas estimation failed, using fallback %d",
                self._config.fallback_gas_limit,
            )
            return self._config.fallback_gas_limit

    async def _get_block_number(self) -> int:
        """Read the current block number. Extracted for testability."""
        w3 = self._require_init()
        return await w3.eth.block_number

    # ── Write operations ─────────────────────────────────────────────────
    # All writes delegate to wallet.send_transaction() which serialises
    # via _tx_lock for nonce management.

    async def deposit_stake(
        self, stake_id: bytes, pr_id: bytes, amount_wei: int,
    ) -> str:
        """Deposit ETH into the staking contract for a PR.

        This is the only ``payable`` call — sends ``amount_wei`` as value.
        Returns the transaction hash.
        """
        self._require_init()
        data = self._encode("depositStake", [stake_id, pr_id])
        gas = await self._estimate_gas(data, value_wei=amount_wei)
        tx_hash = await self._wallet.send_transaction(
            to=self._contract_address,
            value_wei=amount_wei,
            data=data,
            gas=gas,
        )
        logger.info(
            "deposit_stake tx sent",
            extra={"tx_hash": tx_hash, "stake_id": stake_id.hex()},
        )
        return tx_hash

    async def release_stake(
        self, stake_id: bytes, bonus_amount: int,
    ) -> str:
        """Release stake + bonus to contributor (nonpayable).

        Bonus comes from the contract's pre-funded balance.
        """
        self._require_init()
        data = self._encode("releaseStake", [stake_id, bonus_amount])
        gas = await self._estimate_gas(data)
        tx_hash = await self._wallet.send_transaction(
            to=self._contract_address,
            value_wei=0,
            data=data,
            gas=gas,
        )
        logger.info(
            "release_stake tx sent",
            extra={"tx_hash": tx_hash, "stake_id": stake_id.hex()},
        )
        return tx_hash

    async def slash_stake(
        self, stake_id: bytes, slash_percent: int,
    ) -> str:
        """Slash a contributor's stake (nonpayable).

        ``slash_percent`` is 1–100 (not basis points) — matches the
        Solidity ``require(slashPercent <= 100)``.
        """
        if not (1 <= slash_percent <= 100):
            raise ValueError(
                f"slash_percent must be 1–100, got {slash_percent}"
            )
        self._require_init()
        data = self._encode("slashStake", [stake_id, slash_percent])
        gas = await self._estimate_gas(data)
        tx_hash = await self._wallet.send_transaction(
            to=self._contract_address,
            value_wei=0,
            data=data,
            gas=gas,
        )
        logger.info(
            "slash_stake tx sent",
            extra={
                "tx_hash": tx_hash,
                "stake_id": stake_id.hex(),
                "slash_percent": slash_percent,
            },
        )
        return tx_hash

    async def refund_stake(self, stake_id: bytes) -> str:
        """Full refund of a rejected PR's stake (nonpayable)."""
        self._require_init()
        data = self._encode("refundStake", [stake_id])
        gas = await self._estimate_gas(data)
        tx_hash = await self._wallet.send_transaction(
            to=self._contract_address,
            value_wei=0,
            data=data,
            gas=gas,
        )
        logger.info(
            "refund_stake tx sent",
            extra={"tx_hash": tx_hash, "stake_id": stake_id.hex()},
        )
        return tx_hash

    async def withdraw_slashed(self, amount_wei: int) -> str:
        """Withdraw accumulated slashed funds to the agent wallet (nonpayable)."""
        self._require_init()
        data = self._encode("withdrawSlashed", [amount_wei])
        gas = await self._estimate_gas(data)
        tx_hash = await self._wallet.send_transaction(
            to=self._contract_address,
            value_wei=0,
            data=data,
            gas=gas,
        )
        logger.info(
            "withdraw_slashed tx sent",
            extra={"tx_hash": tx_hash, "amount_wei": amount_wei},
        )
        return tx_hash

    # ── Read operations ──────────────────────────────────────────────────

    async def get_stake(self, stake_id: bytes) -> dict[str, Any]:
        """Read on-chain stake data (view call, no gas cost)."""
        w3 = self._require_init()
        contract = w3.eth.contract(
            address=self._contract_address, abi=_STAKING_ABI,
        )
        result = await contract.functions.stakes(stake_id).call()
        return {
            "staker": result[0],
            "amount": result[1],
            "pr_id": result[2],
            "resolved": result[3],
            "timestamp": result[4],
        }

    async def wait_for_receipt(
        self, tx_hash: str, timeout: int = 120,
    ) -> dict[str, Any]:
        """Poll for a transaction receipt until confirmed or timeout.

        Raises ``RuntimeError`` if the transaction reverted (status=0)
        or if the timeout is exceeded.
        """
        w3 = self._require_init()
        loop = asyncio.get_running_loop()
        start = loop.time()
        while True:
            try:
                receipt = await w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                receipt = None  # tx not yet mined — continue polling

            if receipt is not None:
                if receipt["status"] == 0:
                    raise RuntimeError(
                        f"Transaction {tx_hash} reverted (status=0)"
                    )
                return dict(receipt)

            elapsed = loop.time() - start
            if elapsed >= timeout:
                raise RuntimeError(
                    f"Receipt timeout after {timeout}s for tx {tx_hash}"
                )
            await asyncio.sleep(_RECEIPT_POLL_INTERVAL)

    async def verify_deposit(
        self, tx_hash: str, *, confirmations: int = 1,
    ) -> dict[str, Any]:
        """Parse a deposit receipt and extract the StakeDeposited event.

        Waits for ``confirmations`` block confirmations before accepting.
        Raises ``RuntimeError`` if the event is not found or insufficient
        confirmations within the receipt-wait timeout.
        """
        w3 = self._require_init()
        receipt = await self.wait_for_receipt(tx_hash)

        if confirmations > 1:
            tx_block = receipt["blockNumber"]
            loop = asyncio.get_running_loop()
            start = loop.time()
            while True:
                current_block = await self._get_block_number()
                depth = current_block - tx_block + 1
                if depth >= confirmations:
                    break
                if loop.time() - start >= 120:
                    raise RuntimeError(
                        f"Confirmation timeout: need {confirmations}, "
                        f"got {depth} for tx {tx_hash}"
                    )
                await asyncio.sleep(_RECEIPT_POLL_INTERVAL)

        contract = w3.eth.contract(
            address=self._contract_address, abi=_STAKING_ABI,
        )
        logs = contract.events.StakeDeposited().process_receipt(receipt)
        if not logs:
            raise RuntimeError(
                f"No StakeDeposited event found in tx {tx_hash}"
            )
        event = logs[0]
        return {
            "stake_id": event["args"]["stakeId"],
            "staker": event["args"]["staker"],
            "amount": event["args"]["amount"],
            "pr_id": event["args"]["prId"],
        }
