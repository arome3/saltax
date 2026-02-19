"""TEE attestation proof and signed-verdict models.

``AttestationProof`` is frozen — once generated inside the TEE, the proof is
immutable.  ``SignedVerdict`` bundles a verdict with its attestation and the
agent identity that produced it.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from src.models.pipeline import Verdict

# ── Attestation proof ───────────────────────────────────────────────────────


class AttestationProof(BaseModel):
    """Cryptographic proof generated inside the TEE after pipeline execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    attestation_id: str
    docker_image_digest: str
    tee_platform_id: str
    pipeline_input_hash: str
    pipeline_output_hash: str
    ai_seed: int | None = None
    ai_output_hash: str | None = None
    ai_system_fingerprint: str | None = None
    signature: str
    signer_address: str = ""
    timestamp: datetime
    previous_attestation_id: str | None = None


# ── Signed verdict ──────────────────────────────────────────────────────────


class SignedVerdict(BaseModel):
    """A ``Verdict`` bundled with its TEE attestation and agent identity."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    attestation: AttestationProof
    agent_identity: str
