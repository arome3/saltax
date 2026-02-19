"""Attestation store — thin adapter over IntelligenceDB for AttestationProof."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB
    from src.models.attestation import AttestationProof


class AttestationStore:
    """Translates between :class:`AttestationProof` and :class:`IntelligenceDB`."""

    def __init__(self, intel_db: IntelligenceDB) -> None:
        self._db = intel_db

    async def store_attestation(
        self,
        proof: AttestationProof,
        *,
        pr_id: str,
        repo: str,
    ) -> bool:
        """Persist an attestation proof.

        Returns ``True`` if inserted, ``False`` if a proof with the same
        ``attestation_id`` already existed (idempotent on retry).
        """
        return await self._db.store_attestation(
            attestation_id=proof.attestation_id,
            pr_id=pr_id,
            repo=repo,
            pipeline_input_hash=proof.pipeline_input_hash,
            pipeline_output_hash=proof.pipeline_output_hash,
            signature=proof.signature,
            docker_image_digest=proof.docker_image_digest,
            tee_platform_id=proof.tee_platform_id,
            previous_attestation_id=proof.previous_attestation_id,
            ai_seed=proof.ai_seed,
            ai_output_hash=proof.ai_output_hash,
            ai_system_fingerprint=proof.ai_system_fingerprint,
            signer_address=proof.signer_address,
            created_at=proof.timestamp.isoformat(),
        )

    async def get_attestation(self, attestation_id: str) -> dict[str, object] | None:
        """Retrieve an attestation by ID."""
        return await self._db.get_attestation(attestation_id)

    async def get_latest_attestation_id(self) -> str | None:
        """Return the most recent attestation ID, or None for empty chain."""
        return await self._db.get_latest_attestation_id()

    async def get_attestation_chain(
        self, start_id: str, count: int = 10,
    ) -> list[dict[str, object]]:
        """Walk the chain backwards from *start_id*."""
        return await self._db.get_attestation_chain(start_id, count)
