"""Attestation engine — generates tamper-evident proofs for pipeline runs.

Each proof binds: Docker image digest, TEE platform ID, input hash,
output hash, and agent wallet signature into a hash chain where every
proof links to its predecessor.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from src.models.attestation import AttestationProof

if TYPE_CHECKING:
    from src.attestation.store import AttestationStore
    from src.treasury.wallet import WalletManager

logger = logging.getLogger(__name__)

_TEE_METADATA_URL = "http://169.254.169.254/latest/attestation/platform-id"
_TEE_TIMEOUT = 2.0  # seconds
_TEE_RESPONSE_MAX_LEN = 256
_TEE_RESPONSE_PATTERN = re.compile(r"^[a-zA-Z0-9\-]+$")

_SIGNING_VERSION = "saltax-attestation-v1"


# ── Module-level helpers ──────────────────────────────────────────────────────


def _hash_data(data: object) -> str:
    """Deterministic SHA-256 of JSON-serialized data."""
    encoded = json.dumps(
        data, sort_keys=True, separators=(",", ":"), default=str,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_signing_message(
    *,
    chain_prefix: str,
    attestation_id: str,
    docker_image_digest: str,
    tee_platform_id: str,
    pipeline_input_hash: str,
    pipeline_output_hash: str,
    timestamp: str,
    ai_seed: int | None = None,
    ai_output_hash: str | None = None,
    ai_system_fingerprint: str | None = None,
) -> bytes:
    """Build the canonical signing message for an attestation proof.

    Uses domain-separated canonical JSON so that field values containing
    special characters (like ``:``) cannot cause structural ambiguity.
    All fields that affect proof integrity are included.
    """
    payload = {
        "v": _SIGNING_VERSION,
        "chain_prefix": chain_prefix,
        "attestation_id": attestation_id,
        "docker_image_digest": docker_image_digest,
        "tee_platform_id": tee_platform_id,
        "pipeline_input_hash": pipeline_input_hash,
        "pipeline_output_hash": pipeline_output_hash,
        "timestamp": timestamp,
        "ai_seed": ai_seed,
        "ai_output_hash": ai_output_hash,
        "ai_system_fingerprint": ai_system_fingerprint,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _probe_image_digest() -> str:
    """Read the Docker image digest from ``/proc/self/cgroup``.

    Returns ``"unknown"`` when not running inside a container.
    """
    try:
        cgroup = Path("/proc/self/cgroup").read_text()
        for line in cgroup.splitlines():
            parts = line.strip().split("/")
            for part in reversed(parts):
                if len(part) >= 64 and all(c in "0123456789abcdef" for c in part):
                    return f"sha256:{part}"
    except OSError:
        pass
    return "unknown"


async def _probe_tee_platform_id() -> str:
    """Read TEE platform ID from the metadata API.

    Returns ``"unknown"`` when the endpoint is unreachable or returns
    invalid data (e.g. HTML from a captive portal).
    """
    try:
        import httpx  # noqa: PLC0415

        async with httpx.AsyncClient() as client:
            resp = await client.get(_TEE_METADATA_URL, timeout=_TEE_TIMEOUT)
            if resp.status_code == 200:
                text = resp.text.strip()
                if (
                    text
                    and len(text) < _TEE_RESPONSE_MAX_LEN
                    and _TEE_RESPONSE_PATTERN.match(text)
                ):
                    return text
            logger.debug(
                "TEE metadata returned status=%d, body length=%d",
                resp.status_code,
                len(resp.text),
            )
    except Exception:
        logger.debug("TEE metadata probe failed", exc_info=True)
    return "unknown"


# ── AttestationEngine ─────────────────────────────────────────────────────────


class AttestationEngine:
    """Generates chained, signed attestation proofs for pipeline runs."""

    def __init__(
        self, wallet: WalletManager, store: AttestationStore,
    ) -> None:
        self._wallet = wallet
        self._store = store
        self._chain_lock = asyncio.Lock()

    async def generate_proof(
        self,
        *,
        action_id: str,
        pr_id: str,
        repo: str,
        inputs: dict[str, object],
        outputs: dict[str, object],
        ai_seed: int | None = None,
        ai_output_hash: str | None = None,
        ai_system_fingerprint: str | None = None,
    ) -> AttestationProof:
        """Generate a chained, signed attestation proof.

        Serialized via ``_chain_lock`` to prevent chain interleaving.
        Uses ``INSERT OR IGNORE`` — duplicate ``action_id`` preserves the
        original proof and chain integrity (idempotent on retry).
        DB write failures propagate to the caller.
        """
        async with self._chain_lock:
            # 1. Read chain tip
            previous_id = await self._store.get_latest_attestation_id()

            # 2. Hash inputs and outputs
            input_hash = _hash_data(inputs)
            output_hash = _hash_data(outputs)

            # 3. Probe environment
            docker_digest = _probe_image_digest()
            tee_id = await _probe_tee_platform_id()

            # 4. Build signing message (domain-separated canonical JSON)
            timestamp = datetime.now(UTC)
            chain_prefix = previous_id or "genesis"
            message = build_signing_message(
                chain_prefix=chain_prefix,
                attestation_id=action_id,
                docker_image_digest=docker_digest,
                tee_platform_id=tee_id,
                pipeline_input_hash=input_hash,
                pipeline_output_hash=output_hash,
                timestamp=timestamp.isoformat(),
                ai_seed=ai_seed,
                ai_output_hash=ai_output_hash,
                ai_system_fingerprint=ai_system_fingerprint,
            )

            # 5. Sign — degrade to empty signature on failure
            signer_address = self._wallet.address or ""
            signature = ""
            try:
                signature = self._wallet.sign_message(message)
            except RuntimeError:
                logger.warning(
                    "Wallet signing failed for %s, degrading to unsigned proof",
                    action_id,
                )

            # 6. Construct proof
            proof = AttestationProof(
                attestation_id=action_id,
                docker_image_digest=docker_digest,
                tee_platform_id=tee_id,
                pipeline_input_hash=input_hash,
                pipeline_output_hash=output_hash,
                ai_seed=ai_seed,
                ai_output_hash=ai_output_hash,
                ai_system_fingerprint=ai_system_fingerprint,
                signature=signature,
                signer_address=signer_address,
                timestamp=timestamp,
                previous_attestation_id=previous_id,
            )

            # 7. Store (INSERT OR IGNORE — duplicate action_id is a no-op)
            inserted = await self._store.store_attestation(
                proof, pr_id=pr_id, repo=repo,
            )
            if not inserted:
                logger.info(
                    "Attestation %s already exists (idempotent retry)", action_id,
                )

            return proof
