"""Centralized enumeration types for the SaltaX domain model.

All enums inherit from ``StrEnum`` so they serialize as plain strings in JSON.
Every other model file imports enums from here — this module has zero
intra-project dependencies.
"""

from __future__ import annotations

from enum import StrEnum

# ── Severity ────────────────────────────────────────────────────────────────


class Severity(StrEnum):
    """Static / AI finding severity levels, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ── Vulnerability category ──────────────────────────────────────────────────


class VulnerabilityCategory(StrEnum):
    """Taxonomy of vulnerability types detected by the pipeline."""

    REENTRANCY = "reentrancy"
    INJECTION = "injection"
    OVERFLOW = "overflow"
    ACCESS_CONTROL = "access_control"
    SECRETS_EXPOSURE = "secrets_exposure"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    LOGIC_ERROR = "logic_error"
    OTHER = "other"


# ── Decision ────────────────────────────────────────────────────────────────


class Decision(StrEnum):
    """Pipeline verdict decisions."""

    APPROVE = "APPROVE"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    REJECT = "REJECT"


# ── Transaction type ────────────────────────────────────────────────────────


class TransactionType(StrEnum):
    """On-chain treasury transaction categories."""

    SPONSORSHIP_IN = "sponsorship_in"
    AUDIT_FEE_IN = "audit_fee_in"
    STAKE_PENALTY_IN = "stake_penalty_in"
    BOUNTY_OUT = "bounty_out"
    COMPUTE_FEE_OUT = "compute_fee_out"
    COMMUNITY_GRANT_OUT = "community_grant_out"
    STAKE_RETURN_OUT = "stake_return_out"
    STAKE_BONUS_OUT = "stake_bonus_out"


# ── Stake status ────────────────────────────────────────────────────────────


class StakeStatus(StrEnum):
    """Lifecycle states for a contributor stake deposit."""

    ACTIVE = "active"
    PENDING_RELEASE = "pending"
    RETURNED = "returned"
    SLASHED = "slashed"
    REFUNDED = "refunded"


# ── Challenge status ────────────────────────────────────────────────────────


class ChallengeStatus(StrEnum):
    """Resolution states for an optimistic-verification challenge."""

    OPEN = "open"
    UPHELD = "upheld"
    OVERTURNED = "overturned"
    EXPIRED = "expired"


# ── Dispute type ────────────────────────────────────────────────────────────


class DisputeType(StrEnum):
    """Dispute resolution mechanism used for a challenge."""

    COMPUTATION = "computation"  # EigenVerify
    SUBJECTIVE = "subjective"  # MoltCourt


# ── Dispute status ──────────────────────────────────────────────────────────


class DisputeStatus(StrEnum):
    """Lifecycle states for a dispute record."""

    PENDING = "pending"
    SUBMITTED = "submitted"
    RESOLVED = "resolved"
    TIMED_OUT = "timed_out"
    MANUAL_REVIEW = "manual_review"
    FAILED = "failed"


# ── Claim type ──────────────────────────────────────────────────────────────


class ClaimType(StrEnum):
    """Types of dispute claims a challenger can file."""

    AI_OUTPUT_INCORRECT = "ai_output_incorrect"
    SCORING_UNFAIR = "scoring_unfair"


# ── Audit scope ─────────────────────────────────────────────────────────────


class AuditScope(StrEnum):
    """Scope options for the paid audit service."""

    SECURITY_ONLY = "security-only"
    QUALITY_ONLY = "quality-only"
    FULL = "full"
