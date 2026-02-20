"""Tests for the SaltaX domain model type system (src/models/)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

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
from src.pipeline.state import PipelineState

# ---------------------------------------------------------------------------
# Factory helpers — construct valid instances with minimal boilerplate
# ---------------------------------------------------------------------------

_NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "rule_id": "SEC-001",
        "severity": Severity.HIGH,
        "category": VulnerabilityCategory.INJECTION,
        "message": "SQL injection detected",
        "file_path": "src/db.py",
        "line_start": 42,
        "line_end": 42,
        "confidence": 0.95,
        "source_stage": "static_scanner",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def make_verdict(**overrides: object) -> Verdict:
    defaults: dict[str, object] = {
        "decision": Decision.APPROVE,
        "composite_score": 0.85,
        "score_breakdown": {"static_clear": 0.9, "ai_quality": 0.8},
        "is_self_modification": False,
        "threshold_used": 0.75,
        "timestamp": _NOW,
        "pipeline_duration_seconds": 12.5,
    }
    defaults.update(overrides)
    return Verdict(**defaults)  # type: ignore[arg-type]


def make_pr_event(**overrides: object) -> PREvent:
    defaults: dict[str, object] = {
        "action": "opened",
        "pr_number": 123,
        "pr_id": "owner/repo#123",
        "repo_full_name": "owner/repo",
        "repo_url": "https://github.com/owner/repo",
        "clone_url": "https://github.com/owner/repo.git",
        "head_sha": "abc1234",
        "base_branch": "main",
        "head_branch": "feature/x",
        "author_login": "contributor",
        "author_id": 42,
        "title": "Add feature X",
        "diff_url": "https://github.com/owner/repo/pull/123.diff",
        "created_at": _NOW,
        "is_draft": False,
    }
    defaults.update(overrides)
    return PREvent(**defaults)  # type: ignore[arg-type]


def make_pipeline_state(**overrides: object) -> PipelineState:
    defaults: dict[str, object] = {
        "pr_id": "owner/repo#1",
        "repo": "owner/repo",
        "repo_url": "https://github.com/owner/repo",
        "commit_sha": "deadbeef",
        "diff": "diff --git a/f.py b/f.py",
        "base_branch": "main",
        "head_branch": "fix/bug",
        "pr_author": "dev",
    }
    defaults.update(overrides)
    return PipelineState(**defaults)  # type: ignore[arg-type]


# ═══════════════════════════════════════════════════════════════════════════════
# A. Enum coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnums:
    """Validate every enum's values, str subclassing, and member counts."""

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.INFO.value == "INFO"
        assert len(Severity) == 5

    def test_severity_is_str(self) -> None:
        assert isinstance(Severity.HIGH, str)

    def test_vulnerability_category_values(self) -> None:
        assert VulnerabilityCategory.REENTRANCY.value == "reentrancy"
        assert VulnerabilityCategory.OTHER.value == "other"
        assert len(VulnerabilityCategory) == 9

    def test_vulnerability_category_is_str(self) -> None:
        assert isinstance(VulnerabilityCategory.INJECTION, str)

    def test_decision_values(self) -> None:
        assert Decision.APPROVE.value == "APPROVE"
        assert Decision.REQUEST_CHANGES.value == "REQUEST_CHANGES"
        assert Decision.REJECT.value == "REJECT"
        assert len(Decision) == 3

    def test_transaction_type_values(self) -> None:
        assert TransactionType.SPONSORSHIP_IN.value == "sponsorship_in"
        assert TransactionType.STAKE_BONUS_OUT.value == "stake_bonus_out"
        assert len(TransactionType) == 8

    def test_stake_status_values(self) -> None:
        assert StakeStatus.ACTIVE.value == "active"
        assert StakeStatus.PENDING_RELEASE.value == "pending"
        assert StakeStatus.SLASHED.value == "slashed"
        assert len(StakeStatus) == 5

    def test_challenge_status_values(self) -> None:
        assert ChallengeStatus.OPEN.value == "open"
        assert ChallengeStatus.EXPIRED.value == "expired"
        assert len(ChallengeStatus) == 4

    def test_dispute_type_values(self) -> None:
        assert DisputeType.COMPUTATION.value == "computation"
        assert DisputeType.SUBJECTIVE.value == "subjective"
        assert len(DisputeType) == 2

    def test_audit_scope_values(self) -> None:
        assert AuditScope.SECURITY_ONLY.value == "security-only"
        assert AuditScope.QUALITY_ONLY.value == "quality-only"
        assert AuditScope.FULL.value == "full"
        assert len(AuditScope) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# B. Round-trip serialization
# ═══════════════════════════════════════════════════════════════════════════════


class TestRoundTrip:
    """Construct → model_dump() → re-parse → assert equality."""

    def test_finding_round_trip(self) -> None:
        f = make_finding(snippet="x = input()")
        data = f.model_dump()
        f2 = Finding(**data)
        assert f == f2

    def test_ai_analysis_result_round_trip(self) -> None:
        ar = AIAnalysisResult(
            quality_score=8.5,
            risk_score=2.0,
            confidence=0.9,
            concerns=["Possible race condition"],
            recommendations=["Add locking"],
            architectural_fit="good",
            findings=[make_finding()],
            reasoning="The code is mostly safe.",
        )
        data = ar.model_dump()
        ar2 = AIAnalysisResult(**data)
        assert ar == ar2

    def test_test_result_round_trip(self) -> None:
        tr = TestResult(
            passed=True,
            total_tests=10,
            passed_tests=9,
            failed_tests=1,
            skipped_tests=0,
            coverage_percent=87.5,
            execution_time_seconds=4.2,
            exit_code=0,
            stdout_tail="OK",
            stderr_tail="",
        )
        data = tr.model_dump()
        tr2 = TestResult(**data)
        assert tr == tr2

    def test_verdict_round_trip(self) -> None:
        v = make_verdict(findings_count=3, attestation_id="att-001")
        data = v.model_dump()
        v2 = Verdict(**data)
        assert v == v2

    def test_transaction_record_round_trip(self) -> None:
        rec = TransactionRecord(
            tx_id="tx-1",
            tx_hash="0xabc",
            tx_type=TransactionType.BOUNTY_OUT,
            amount_wei=1_000_000,
            counterparty="0xdev",
            pr_id="owner/repo#1",
            timestamp=_NOW,
        )
        data = rec.model_dump()
        rec2 = TransactionRecord(**data)
        assert rec == rec2

    def test_treasury_snapshot_round_trip(self) -> None:
        snap = TreasurySnapshot(
            balance_wei=10**18,
            available_for_bounties_wei=5 * 10**17,
            reserve_floor_wei=2 * 10**17,
            compute_allocation_wei=10**17,
            community_fund_wei=5 * 10**16,
            total_revenue_lifetime_wei=2 * 10**18,
            total_expenditure_lifetime_wei=10**18,
            transaction_count=42,
            last_updated=_NOW,
        )
        data = snap.model_dump()
        snap2 = TreasurySnapshot(**data)
        assert snap == snap2

    def test_payout_request_round_trip(self) -> None:
        pr = PayoutRequest(
            recipient_address="0xdev",
            amount_wei=50_000,
            pr_id="owner/repo#5",
            bounty_label="bounty-sm",
        )
        data = pr.model_dump()
        pr2 = PayoutRequest(**data)
        assert pr == pr2

    def test_pr_event_round_trip(self) -> None:
        ev = make_pr_event(labels=["bounty-md"])
        data = ev.model_dump()
        ev2 = PREvent(**data)
        assert ev == ev2

    def test_issue_event_round_trip(self) -> None:
        ie = IssueEvent(
            action="labeled",
            issue_number=10,
            repo_full_name="owner/repo",
            labels=["bug"],
            title="Fix crash",
        )
        data = ie.model_dump()
        ie2 = IssueEvent(**data)
        assert ie == ie2

    def test_bounty_info_round_trip(self) -> None:
        bi = BountyInfo(
            issue_number=10,
            repo_full_name="owner/repo",
            label="bounty-lg",
            amount_wei=250_000,
            created_at=_NOW,
        )
        data = bi.model_dump()
        bi2 = BountyInfo(**data)
        assert bi == bi2

    def test_stake_deposit_round_trip(self) -> None:
        sd = StakeDeposit(
            stake_id="stake-1",
            pr_id="owner/repo#1",
            contributor_address="0xdev",
            amount_wei=100_000,
            deposit_tx_hash="0xtx",
            status=StakeStatus.ACTIVE,
            deposited_at=_NOW,
        )
        data = sd.model_dump()
        sd2 = StakeDeposit(**data)
        assert sd == sd2

    def test_challenge_event_round_trip(self) -> None:
        ce = ChallengeEvent(
            challenge_id="ch-1",
            pr_id="owner/repo#1",
            challenger_address="0xchallenger",
            stake_amount_wei=200_000,
            rationale="Missed reentrancy bug",
            dispute_type=DisputeType.COMPUTATION,
            status=ChallengeStatus.OPEN,
            filed_at=_NOW,
        )
        data = ce.model_dump()
        ce2 = ChallengeEvent(**data)
        assert ce == ce2

    def test_audit_request_round_trip(self) -> None:
        ar = AuditRequest(
            audit_id="audit-1",
            repository_url="https://github.com/org/repo",
            commit_sha="abc123",
            scope=AuditScope.FULL,
            payment_amount_usdc=10.0,
            payment_proof="proof-hash",
            requested_at=_NOW,
        )
        data = ar.model_dump()
        ar2 = AuditRequest(**data)
        assert ar == ar2

    def test_audit_report_round_trip(self) -> None:
        report = AuditReport(
            audit_id="audit-1",
            repository_url="https://github.com/org/repo",
            commit_sha="abc123",
            scope=AuditScope.SECURITY_ONLY,
            verdict={"decision": "APPROVE"},
            findings=[{"rule_id": "SEC-001"}],
            attestation={"id": "att-1"},
            completed_at=_NOW,
            pipeline_duration_seconds=30.0,
        )
        data = report.model_dump()
        report2 = AuditReport(**data)
        assert report == report2

    def test_reputation_metrics_round_trip(self) -> None:
        rm = ReputationMetrics(total_prs_reviewed=100, total_prs_approved=80)
        # Exclude computed_field properties — they're derived, not input fields
        computed = {"approval_rate"}
        data = rm.model_dump(exclude=computed)
        rm2 = ReputationMetrics(**data)
        assert rm2.total_prs_reviewed == 100
        assert rm2.total_prs_approved == 80
        assert rm2.approval_rate == rm.approval_rate

    def test_agent_identity_round_trip(self) -> None:
        ai = AgentIdentity(
            agent_id="saltax-01",
            chain_id=8453,
            wallet_address="0xagent",
            name="SaltaX",
            description="Sovereign Code Organism",
            registered_at=_NOW,
        )
        data = ai.model_dump(exclude={"approval_rate"})
        ai2 = AgentIdentity(**data)
        assert ai2.agent_id == ai.agent_id

    def test_attestation_proof_round_trip(self) -> None:
        ap = AttestationProof(
            attestation_id="att-1",
            docker_image_digest="sha256:abc",
            tee_platform_id="sgx-v2",
            pipeline_input_hash="hash-in",
            pipeline_output_hash="hash-out",
            signature="sig-bytes",
            timestamp=_NOW,
        )
        data = ap.model_dump()
        ap2 = AttestationProof(**data)
        assert ap == ap2

    def test_attestation_proof_with_ai_fields(self) -> None:
        ap = AttestationProof(
            attestation_id="att-2",
            docker_image_digest="sha256:def",
            tee_platform_id="sgx-v2",
            pipeline_input_hash="hash-in",
            pipeline_output_hash="hash-out",
            ai_seed=12345,
            ai_output_hash="sha256:output",
            ai_system_fingerprint="fp_abc123",
            signature="sig-bytes",
            timestamp=_NOW,
        )
        data = ap.model_dump()
        ap2 = AttestationProof(**data)
        assert ap2.ai_seed == 12345
        assert ap2.ai_output_hash == "sha256:output"
        assert ap2.ai_system_fingerprint == "fp_abc123"
        assert ap == ap2

    def test_attestation_proof_ai_fields_default_none(self) -> None:
        ap = AttestationProof(
            attestation_id="att-3",
            docker_image_digest="sha256:ghi",
            tee_platform_id="sgx-v2",
            pipeline_input_hash="hash-in",
            pipeline_output_hash="hash-out",
            signature="sig-bytes",
            timestamp=_NOW,
        )
        assert ap.ai_seed is None
        assert ap.ai_output_hash is None
        assert ap.ai_system_fingerprint is None

    def test_signed_verdict_round_trip(self) -> None:
        sv = SignedVerdict(
            verdict=make_verdict(),
            attestation=AttestationProof(
                attestation_id="att-1",
                docker_image_digest="sha256:abc",
                tee_platform_id="sgx-v2",
                pipeline_input_hash="hash-in",
                pipeline_output_hash="hash-out",
                signature="sig-bytes",
                timestamp=_NOW,
            ),
            agent_identity="saltax-01",
        )
        data = sv.model_dump()
        sv2 = SignedVerdict(**data)
        assert sv2.agent_identity == "saltax-01"


# ═══════════════════════════════════════════════════════════════════════════════
# C. Frozen enforcement
# ═══════════════════════════════════════════════════════════════════════════════


class TestFrozen:
    """Frozen models must reject attribute assignment."""

    def test_finding_is_frozen(self) -> None:
        f = make_finding()
        with pytest.raises(ValidationError, match="frozen"):
            f.rule_id = "NEW"  # type: ignore[misc]

    def test_ai_analysis_result_is_frozen(self) -> None:
        ar = AIAnalysisResult(
            quality_score=8.0,
            risk_score=1.0,
            confidence=0.9,
            architectural_fit="good",
            reasoning="Safe code.",
        )
        with pytest.raises(ValidationError, match="frozen"):
            ar.quality_score = 9.0  # type: ignore[misc]

    def test_test_result_is_frozen(self) -> None:
        tr = TestResult(
            passed=True,
            total_tests=5,
            passed_tests=5,
            failed_tests=0,
            skipped_tests=0,
            execution_time_seconds=1.0,
            exit_code=0,
        )
        with pytest.raises(ValidationError, match="frozen"):
            tr.passed = False  # type: ignore[misc]

    def test_transaction_record_is_frozen(self) -> None:
        rec = TransactionRecord(
            tx_id="tx-1",
            tx_type=TransactionType.BOUNTY_OUT,
            amount_wei=1000,
            counterparty="0xdev",
            timestamp=_NOW,
        )
        with pytest.raises(ValidationError, match="frozen"):
            rec.amount_wei = 999  # type: ignore[misc]

    def test_treasury_snapshot_is_frozen(self) -> None:
        snap = TreasurySnapshot(
            balance_wei=100,
            available_for_bounties_wei=50,
            reserve_floor_wei=20,
            compute_allocation_wei=10,
            community_fund_wei=5,
            total_revenue_lifetime_wei=200,
            total_expenditure_lifetime_wei=100,
            transaction_count=1,
            last_updated=_NOW,
        )
        with pytest.raises(ValidationError, match="frozen"):
            snap.balance_wei = 0  # type: ignore[misc]

    def test_attestation_proof_is_frozen(self) -> None:
        ap = AttestationProof(
            attestation_id="att-1",
            docker_image_digest="sha256:abc",
            tee_platform_id="sgx",
            pipeline_input_hash="in",
            pipeline_output_hash="out",
            signature="sig",
            timestamp=_NOW,
        )
        with pytest.raises(ValidationError, match="frozen"):
            ap.signature = "tampered"  # type: ignore[misc]

    def test_audit_report_is_frozen(self) -> None:
        report = AuditReport(
            audit_id="a-1",
            repository_url="https://github.com/o/r",
            commit_sha="abc",
            scope=AuditScope.FULL,
            verdict={},
            findings=[],
            attestation={},
            completed_at=_NOW,
            pipeline_duration_seconds=1.0,
        )
        with pytest.raises(ValidationError, match="frozen"):
            report.audit_id = "tampered"  # type: ignore[misc]

    def test_verdict_is_mutable(self) -> None:
        """Verdict is deliberately NOT frozen."""
        v = make_verdict()
        v.attestation_id = "att-99"
        v.findings_count = 7
        assert v.attestation_id == "att-99"
        assert v.findings_count == 7

    def test_payout_request_is_mutable(self) -> None:
        """PayoutRequest is NOT frozen."""
        pr = PayoutRequest(
            recipient_address="0xdev",
            amount_wei=1000,
            pr_id="o/r#1",
            bounty_label="bounty-sm",
        )
        pr.include_stake_bonus = True
        pr.stake_bonus_wei = 500
        assert pr.include_stake_bonus is True

    def test_stake_deposit_is_mutable(self) -> None:
        """StakeDeposit is NOT frozen — status transitions are required."""
        sd = StakeDeposit(
            stake_id="s-1",
            pr_id="o/r#1",
            contributor_address="0xdev",
            amount_wei=1000,
            deposit_tx_hash="0xtx",
            status=StakeStatus.ACTIVE,
            deposited_at=_NOW,
        )
        sd.status = StakeStatus.RETURNED
        assert sd.status == StakeStatus.RETURNED


# ═══════════════════════════════════════════════════════════════════════════════
# D. Field constraints
# ═══════════════════════════════════════════════════════════════════════════════


class TestFieldConstraints:
    """Boundary tests for ge/le/max_length constraints."""

    def test_finding_confidence_too_low(self) -> None:
        with pytest.raises(ValidationError):
            make_finding(confidence=-0.1)

    def test_finding_confidence_too_high(self) -> None:
        with pytest.raises(ValidationError):
            make_finding(confidence=1.1)

    def test_finding_confidence_at_boundaries(self) -> None:
        f0 = make_finding(confidence=0.0)
        f1 = make_finding(confidence=1.0)
        assert f0.confidence == 0.0
        assert f1.confidence == 1.0

    def test_verdict_composite_score_too_low(self) -> None:
        with pytest.raises(ValidationError):
            make_verdict(composite_score=-0.01)

    def test_verdict_composite_score_too_high(self) -> None:
        with pytest.raises(ValidationError):
            make_verdict(composite_score=1.01)

    def test_verdict_composite_score_boundaries(self) -> None:
        v0 = make_verdict(composite_score=0.0)
        v1 = make_verdict(composite_score=1.0)
        assert v0.composite_score == 0.0
        assert v1.composite_score == 1.0

    def test_ai_quality_score_too_high(self) -> None:
        with pytest.raises(ValidationError):
            AIAnalysisResult(
                quality_score=10.1,
                risk_score=0.0,
                confidence=0.5,
                architectural_fit="good",
                reasoning="x",
            )

    def test_ai_risk_score_too_low(self) -> None:
        with pytest.raises(ValidationError):
            AIAnalysisResult(
                quality_score=5.0,
                risk_score=-0.1,
                confidence=0.5,
                architectural_fit="good",
                reasoning="x",
            )

    def test_test_result_stdout_max_length(self) -> None:
        """stdout_tail exceeding 10000 chars is rejected."""
        with pytest.raises(ValidationError):
            TestResult(
                passed=True,
                total_tests=1,
                passed_tests=1,
                failed_tests=0,
                skipped_tests=0,
                execution_time_seconds=1.0,
                exit_code=0,
                stdout_tail="x" * 10_001,
            )

    def test_test_result_stderr_max_length(self) -> None:
        """stderr_tail exceeding 10000 chars is rejected."""
        with pytest.raises(ValidationError):
            TestResult(
                passed=True,
                total_tests=1,
                passed_tests=1,
                failed_tests=0,
                skipped_tests=0,
                execution_time_seconds=1.0,
                exit_code=0,
                stderr_tail="e" * 10_001,
            )

    def test_test_result_stdout_at_boundary(self) -> None:
        """stdout_tail at exactly 10000 chars is accepted."""
        tr = TestResult(
            passed=True,
            total_tests=1,
            passed_tests=1,
            failed_tests=0,
            skipped_tests=0,
            execution_time_seconds=1.0,
            exit_code=0,
            stdout_tail="x" * 10_000,
        )
        assert len(tr.stdout_tail) == 10_000

    def test_extra_fields_rejected_on_finding(self) -> None:
        """extra='forbid' rejects unknown fields."""
        with pytest.raises(ValidationError):
            make_finding(unknown_field="bad")  # type: ignore[arg-type]


# ═══════════════════════════════════════════════════════════════════════════════
# E. Literal validation (PREvent / IssueEvent)
# ═══════════════════════════════════════════════════════════════════════════════


class TestLiteralValidation:
    """Invalid Literal values must be rejected."""

    def test_pr_event_invalid_action(self) -> None:
        with pytest.raises(ValidationError):
            make_pr_event(action="merged")

    def test_pr_event_valid_actions(self) -> None:
        for action in ("opened", "synchronize", "closed", "reopened"):
            ev = make_pr_event(action=action)
            assert ev.action == action

    def test_issue_event_invalid_action(self) -> None:
        with pytest.raises(ValidationError):
            IssueEvent(
                action="deleted",  # type: ignore[arg-type]
                issue_number=1,
                repo_full_name="o/r",
                title="T",
            )

    def test_issue_event_valid_actions(self) -> None:
        for action in ("labeled", "unlabeled", "opened", "closed"):
            ie = IssueEvent(
                action=action,  # type: ignore[arg-type]
                issue_number=1,
                repo_full_name="o/r",
                title="T",
            )
            assert ie.action == action


# ═══════════════════════════════════════════════════════════════════════════════
# F. PipelineState mutations
# ═══════════════════════════════════════════════════════════════════════════════


class TestPipelineState:
    """Verify the mutable dataclass behaves correctly."""

    def test_required_fields(self) -> None:
        ps = make_pipeline_state()
        assert ps.pr_id == "owner/repo#1"
        assert ps.repo == "owner/repo"
        assert ps.commit_sha == "deadbeef"

    def test_default_values(self) -> None:
        ps = make_pipeline_state()
        assert ps.pr_author_wallet is None
        assert ps.bounty_amount_wei is None
        assert ps.is_self_modification is False
        assert ps.target_issue_number is None
        assert ps.duplicate_candidates == []
        assert ps.static_findings == []
        assert ps.ai_analysis is None
        assert ps.test_results is None
        assert ps.verdict is None
        assert ps.attestation is None
        assert ps.pipeline_start_time == ""
        assert ps.current_stage == ""
        assert ps.error is None
        assert ps.short_circuit is False

    def test_append_to_lists(self) -> None:
        ps = make_pipeline_state()
        ps.static_findings.append({"rule_id": "SEC-001"})
        assert len(ps.static_findings) == 1
        ps.duplicate_candidates.append({"pr_id": "o/r#2", "similarity": 0.9})
        assert len(ps.duplicate_candidates) == 1

    def test_assign_optional_fields(self) -> None:
        ps = make_pipeline_state()
        ps.ai_analysis = {"quality_score": 8.0}
        ps.verdict = {"decision": "APPROVE"}
        ps.error = "timeout"
        ps.short_circuit = True
        assert ps.ai_analysis["quality_score"] == 8.0
        assert ps.verdict["decision"] == "APPROVE"
        assert ps.error == "timeout"
        assert ps.short_circuit is True

    def test_default_factory_isolation(self) -> None:
        """Each PipelineState instance must have independent list instances."""
        ps1 = make_pipeline_state()
        ps2 = make_pipeline_state()
        ps1.static_findings.append({"rule_id": "A"})
        assert ps2.static_findings == []
        assert len(ps1.static_findings) == 1

    def test_set_metadata(self) -> None:
        ps = make_pipeline_state()
        ps.pipeline_start_time = "2025-06-01T00:00:00Z"
        ps.current_stage = "static_scanner"
        assert ps.pipeline_start_time == "2025-06-01T00:00:00Z"
        assert ps.current_stage == "static_scanner"


# ═══════════════════════════════════════════════════════════════════════════════
# G. Identity / reputation computed fields
# ═══════════════════════════════════════════════════════════════════════════════


class TestReputationMetrics:
    """Verify computed properties on ReputationMetrics."""

    def test_approval_rate_zero_reviews(self) -> None:
        rm = ReputationMetrics()
        assert rm.approval_rate == 0.0

    def test_approval_rate_computed(self) -> None:
        rm = ReputationMetrics(total_prs_reviewed=100, total_prs_approved=75)
        assert rm.approval_rate == 0.75

    def test_vulnerabilities_caught_default(self) -> None:
        rm = ReputationMetrics()
        assert rm.vulnerabilities_caught == 0

    def test_uptime_seconds_default(self) -> None:
        rm = ReputationMetrics()
        assert rm.uptime_seconds == 0


# ═══════════════════════════════════════════════════════════════════════════════
# H. Package-level imports
# ═══════════════════════════════════════════════════════════════════════════════


class TestPackageImports:
    """Verify that src.models re-exports all public types."""

    def test_all_exports(self) -> None:
        import src.models

        expected = {
            "AuditScope",
            "ChallengeStatus",
            "Decision",
            "DisputeType",
            "Severity",
            "StakeStatus",
            "TransactionType",
            "VulnerabilityCategory",
            "AIAnalysisResult",
            "Finding",
            "TestResult",
            "Verdict",
            "PayoutRequest",
            "TransactionRecord",
            "TreasurySnapshot",
            "BountyInfo",
            "IssueEvent",
            "PREvent",
            "ChallengeEvent",
            "StakeDeposit",
            "AuditReport",
            "AuditRequest",
            "AgentIdentity",
            "ReputationMetrics",
            "AttestationProof",
            "SignedVerdict",
            "DependencyFinding",
            "PatrolFinding",
        }
        actual = set(src.models.__all__)
        assert expected == actual
