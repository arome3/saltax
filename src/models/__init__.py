"""SaltaX domain model re-exports.

Import any model or enum directly from ``src.models``::

    from src.models import Severity, Finding, Verdict, PREvent
"""

from __future__ import annotations

from src.models.attestation import AttestationProof, SignedVerdict
from src.models.audit import AuditReport, AuditRequest
from src.models.enums import (
    AuditScope,
    ChallengeStatus,
    Decision,
    DisputeType,
    Severity,
    StakeStatus,
    TransactionType,
    VulnerabilityCategory,
)
from src.models.github import BountyInfo, IssueEvent, PREvent
from src.models.identity import AgentIdentity, ReputationMetrics
from src.models.pipeline import AIAnalysisResult, Finding, TestResult, Verdict
from src.models.staking import ChallengeEvent, StakeDeposit
from src.models.treasury import PayoutRequest, TransactionRecord, TreasurySnapshot

__all__ = [
    # Enums
    "AuditScope",
    "ChallengeStatus",
    "Decision",
    "DisputeType",
    "Severity",
    "StakeStatus",
    "TransactionType",
    "VulnerabilityCategory",
    # Pipeline
    "AIAnalysisResult",
    "Finding",
    "TestResult",
    "Verdict",
    # Treasury
    "PayoutRequest",
    "TransactionRecord",
    "TreasurySnapshot",
    # GitHub
    "BountyInfo",
    "IssueEvent",
    "PREvent",
    # Staking
    "ChallengeEvent",
    "StakeDeposit",
    # Audit
    "AuditReport",
    "AuditRequest",
    # Identity
    "AgentIdentity",
    "ReputationMetrics",
    # Attestation
    "AttestationProof",
    "SignedVerdict",
]
