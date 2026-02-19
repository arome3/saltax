"""Attestation engine — cryptographic proof generation and verification."""

from src.attestation.engine import AttestationEngine, build_signing_message
from src.attestation.store import AttestationStore
from src.attestation.verifier import (
    verify_chain,
    verify_input_hash,
    verify_output_hash,
    verify_signature,
)

__all__ = [
    "AttestationEngine",
    "AttestationStore",
    "build_signing_message",
    "verify_chain",
    "verify_input_hash",
    "verify_output_hash",
    "verify_signature",
]
