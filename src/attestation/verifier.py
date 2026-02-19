"""Attestation verification utilities — pure functions, no I/O.

All functions return ``bool`` and never raise.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.attestation.engine import _hash_data, build_signing_message

if TYPE_CHECKING:
    from src.models.attestation import AttestationProof

logger = logging.getLogger(__name__)


def verify_signature(proof: AttestationProof, expected_address: str) -> bool:
    """Verify that the proof was signed by *expected_address*.

    Uses EIP-191 ``encode_defunct`` and ``Account.recover_message``.
    Returns ``False`` for empty signatures or any recovery failure.
    """
    if not proof.signature:
        return False
    try:
        from eth_account import Account  # noqa: PLC0415
        from eth_account.messages import encode_defunct  # noqa: PLC0415

        message = build_signing_message(
            chain_prefix=proof.previous_attestation_id or "genesis",
            attestation_id=proof.attestation_id,
            docker_image_digest=proof.docker_image_digest,
            tee_platform_id=proof.tee_platform_id,
            pipeline_input_hash=proof.pipeline_input_hash,
            pipeline_output_hash=proof.pipeline_output_hash,
            timestamp=proof.timestamp.isoformat(),
            ai_seed=proof.ai_seed,
            ai_output_hash=proof.ai_output_hash,
            ai_system_fingerprint=proof.ai_system_fingerprint,
        )
        signable = encode_defunct(primitive=message)
        sig_hex = proof.signature.removeprefix("0x")
        recovered = Account.recover_message(
            signable, signature=bytes.fromhex(sig_hex),
        )
        return recovered.lower() == expected_address.lower()
    except Exception:
        logger.debug("Signature verification failed", exc_info=True)
        return False


def verify_input_hash(proof: AttestationProof, original_inputs: dict[str, object]) -> bool:
    """Verify that the proof's input hash matches the original inputs."""
    try:
        return _hash_data(original_inputs) == proof.pipeline_input_hash
    except Exception:
        return False


def verify_output_hash(proof: AttestationProof, original_outputs: dict[str, object]) -> bool:
    """Verify that the proof's output hash matches the original outputs."""
    try:
        return _hash_data(original_outputs) == proof.pipeline_output_hash
    except Exception:
        return False


def verify_chain(proofs: list[AttestationProof]) -> bool:
    """Verify that a list of proofs forms a valid chain.

    *proofs* must be ordered newest-first (each proof's
    ``previous_attestation_id`` should match the next proof's
    ``attestation_id``).  Returns ``False`` for empty lists.
    """
    if not proofs:
        return False
    for i in range(len(proofs) - 1):
        if proofs[i].previous_attestation_id != proofs[i + 1].attestation_id:
            return False
    return True
