"""Tests for the SaltaX configuration system (src/config.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from src.config import (
    AuditPricingConfig,
    BountyConfig,
    DedupConfig,
    EnvConfig,
    PipelineConfig,
    PipelineWeights,
    SaltaXConfig,
    StakingConfig,
    TreasuryConfig,
    VerificationConfig,
    VisionConfig,
    validate_config,
)


# ═══════════════════════════════════════════════════════════════════════════════
# A. Valid config loading (happy path)
# ═══════════════════════════════════════════════════════════════════════════════


class TestLoadValidConfig:
    def test_load_valid_config(self, sample_config: SaltaXConfig) -> None:
        """Loading the fixture YAML populates all top-level sections."""
        assert sample_config.version == "1.0"
        assert sample_config.agent.name == "SaltaX"
        assert sample_config.pipeline.approval_threshold == 0.75
        assert sample_config.treasury.bounty_budget == 0.65
        assert sample_config.bounties.labels["bounty-xl"] == 0.50
        assert sample_config.verification.standard_window_hours == 24
        assert sample_config.staking.enabled is True
        assert sample_config.audit_pricing.full_audit_usdc == 10
        assert sample_config.triage.mode == "autonomous"

    def test_default_values(self) -> None:
        """Constructing SaltaXConfig() with no args gives sane defaults."""
        cfg = SaltaXConfig()
        assert cfg.version == "1.0"
        assert cfg.pipeline.approval_threshold == 0.75
        assert cfg.treasury.reserve_ratio == 0.20
        assert cfg.staking.enabled is True
        assert cfg.triage.enabled is False

    def test_env_config_loads(self, sample_env: EnvConfig) -> None:
        """EnvConfig loads required fields from env vars."""
        assert sample_env.eigenai_api_key == "test-key-123"
        assert sample_env.github_app_id == "999"
        assert sample_env.host == "0.0.0.0"
        assert sample_env.port == 8080
        assert sample_env.internal_bridge_port == 8081

    def test_env_config_defaults(self, sample_env: EnvConfig) -> None:
        """EnvConfig provides sensible defaults for optional fields."""
        assert sample_env.eigenai_api_url == "https://eigenai.eigencloud.xyz/v1"
        assert sample_env.chain_id == 8453
        assert sample_env.log_level == "INFO"


# ═══════════════════════════════════════════════════════════════════════════════
# B. Pipeline validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestPipelineValidation:
    def test_pipeline_weights_sum_valid(self) -> None:
        """Weights that sum to 1.0 pass validation."""
        w = PipelineWeights(static_clear=0.4, ai_quality=0.3, ai_security=0.2, tests_pass=0.1)
        assert abs(w.static_clear + w.ai_quality + w.ai_security + w.tests_pass - 1.0) < 0.001

    def test_pipeline_weights_sum_invalid(self) -> None:
        """Weights not summing to 1.0 raise ValueError."""
        with pytest.raises(ValidationError, match="sum to 1.0"):
            PipelineWeights(static_clear=0.5, ai_quality=0.5, ai_security=0.5, tests_pass=0.5)

    def test_pipeline_yaml_stages_flattened(self, sample_config: SaltaXConfig) -> None:
        """Nested YAML ``stages`` are correctly flattened into PipelineConfig fields."""
        p = sample_config.pipeline
        assert p.static_scanner_timeout == 120
        assert p.ai_analyzer_model == "gpt-oss-120b-f16"
        assert p.test_executor_timeout == 300
        assert p.test_executor_memory_mb == 512
        assert p.weights.static_clear == 0.25

    def test_pipeline_from_flat_dict(self) -> None:
        """PipelineConfig also works with pre-flattened data (no stages key)."""
        p = PipelineConfig(
            approval_threshold=0.80,
            self_modification_threshold=0.95,
            review_threshold=0.40,
            static_scanner_timeout=60,
            ai_analyzer_model="test-model",
            test_executor_timeout=180,
            test_executor_memory_mb=256,
        )
        assert p.approval_threshold == 0.80
        assert p.static_scanner_timeout == 60


# ═══════════════════════════════════════════════════════════════════════════════
# C. Treasury validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestTreasuryValidation:
    def test_treasury_allocations_sum_valid(self) -> None:
        """Ratios summing to 1.0 pass."""
        t = TreasuryConfig(
            reserve_ratio=0.25,
            compute_budget=0.25,
            bounty_budget=0.25,
            community_fund=0.25,
        )
        assert t.reserve_ratio == 0.25

    def test_treasury_allocations_sum_invalid(self) -> None:
        """Ratios not summing to 1.0 raise ValueError."""
        with pytest.raises(ValidationError, match="sum to 1.0"):
            TreasuryConfig(
                reserve_ratio=0.50,
                compute_budget=0.50,
                bounty_budget=0.50,
                community_fund=0.50,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# D. Field constraints
# ═══════════════════════════════════════════════════════════════════════════════


class TestFieldConstraints:
    def test_approval_threshold_too_low(self) -> None:
        """approval_threshold below 0.5 is rejected."""
        with pytest.raises(ValidationError):
            PipelineConfig(approval_threshold=0.3)

    def test_approval_threshold_too_high(self) -> None:
        """approval_threshold above 1.0 is rejected."""
        with pytest.raises(ValidationError):
            PipelineConfig(approval_threshold=1.1)

    def test_vision_alignment_weight_capped(self) -> None:
        """alignment_weight > 0.30 is rejected."""
        with pytest.raises(ValidationError):
            VisionConfig(alignment_weight=0.35)

    def test_vision_alignment_weight_at_boundary(self) -> None:
        """alignment_weight exactly 0.30 is valid."""
        v = VisionConfig(alignment_weight=0.30)
        assert v.alignment_weight == 0.30

    def test_staking_rates_range(self) -> None:
        """Staking rates outside [0.0, 1.0] are rejected."""
        with pytest.raises(ValidationError):
            StakingConfig(bonus_rate_no_challenge=1.5)

    def test_audit_pricing_positive(self) -> None:
        """Zero pricing is rejected (gt=0)."""
        with pytest.raises(ValidationError):
            AuditPricingConfig(security_only_usdc=0)

    def test_audit_pricing_negative(self) -> None:
        """Negative pricing is rejected."""
        with pytest.raises(ValidationError):
            AuditPricingConfig(quality_only_usdc=-1)

    def test_dedup_similarity_threshold_bounds(self) -> None:
        """similarity_threshold below 0.5 or above 0.99 is rejected."""
        with pytest.raises(ValidationError):
            DedupConfig(similarity_threshold=0.3)
        with pytest.raises(ValidationError):
            DedupConfig(similarity_threshold=1.0)

    def test_verification_window_positive(self) -> None:
        """Window hours must be > 0."""
        with pytest.raises(ValidationError):
            VerificationConfig(standard_window_hours=0)


# ═══════════════════════════════════════════════════════════════════════════════
# E. Cross-validation (validate_config)
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrossValidation:
    def test_validate_config_valid(self, sample_config: SaltaXConfig) -> None:
        """Default/fixture config produces no errors."""
        errors = validate_config(sample_config)
        assert errors == []

    def test_validate_self_mod_threshold_ordering(self) -> None:
        """self_modification_threshold <= approval_threshold → error."""
        cfg = SaltaXConfig()
        cfg.pipeline.self_modification_threshold = 0.70
        cfg.pipeline.approval_threshold = 0.75
        errors = validate_config(cfg)
        assert any("self_modification_threshold" in e for e in errors)

    def test_validate_self_mod_equal_to_approval(self) -> None:
        """self_modification_threshold == approval_threshold → error."""
        cfg = SaltaXConfig()
        cfg.pipeline.self_modification_threshold = 0.75
        cfg.pipeline.approval_threshold = 0.75
        errors = validate_config(cfg)
        assert any("self_modification_threshold" in e for e in errors)

    def test_validate_review_threshold_ordering(self) -> None:
        """review_threshold >= approval_threshold → error."""
        cfg = SaltaXConfig()
        cfg.pipeline.review_threshold = 0.80
        cfg.pipeline.approval_threshold = 0.75
        errors = validate_config(cfg)
        assert any("review_threshold" in e for e in errors)

    def test_validate_bounty_exceeds_max_payout(self) -> None:
        """Bounty label value > max_single_payout_eth → error."""
        cfg = SaltaXConfig()
        cfg.bounties.labels["bounty-mega"] = 2.0
        cfg.treasury.max_single_payout_eth = 0.5
        errors = validate_config(cfg)
        assert any("bounty label value" in e.lower() or "exceeds" in e.lower() for e in errors)

    def test_validate_upheld_bonus_ordering(self) -> None:
        """bonus_rate_challenged_upheld <= bonus_rate_no_challenge → error."""
        cfg = SaltaXConfig()
        cfg.staking.bonus_rate_challenged_upheld = 0.05
        cfg.staking.bonus_rate_no_challenge = 0.10
        errors = validate_config(cfg)
        assert any("bonus_rate_challenged_upheld" in e for e in errors)

    def test_validate_verification_window_ordering(self) -> None:
        """self_modification_window_hours <= standard_window_hours → error."""
        cfg = SaltaXConfig()
        cfg.verification.self_modification_window_hours = 12
        cfg.verification.standard_window_hours = 24
        errors = validate_config(cfg)
        assert any("self_modification_window_hours" in e for e in errors)

    def test_validate_ranking_requires_dedup(self) -> None:
        """GAP 5: ranking on + dedup off → warning present."""
        cfg = SaltaXConfig()
        cfg.triage.enabled = True
        cfg.triage.ranking.enabled = True
        cfg.triage.dedup.enabled = False
        errors = validate_config(cfg)
        assert any("ranking" in e and "dedup" in e for e in errors)

    def test_validate_ranking_with_dedup_ok(self) -> None:
        """GAP 5: ranking on + dedup on → no ranking-related warning."""
        cfg = SaltaXConfig()
        cfg.triage.enabled = True
        cfg.triage.ranking.enabled = True
        cfg.triage.dedup.enabled = True
        errors = validate_config(cfg)
        assert not any("ranking" in e and "dedup" in e for e in errors)

    def test_validate_ranking_disabled_no_warning(self) -> None:
        """GAP 5: ranking off → no warning regardless of dedup."""
        cfg = SaltaXConfig()
        cfg.triage.enabled = True
        cfg.triage.ranking.enabled = False
        cfg.triage.dedup.enabled = False
        errors = validate_config(cfg)
        assert not any("ranking" in e and "dedup" in e for e in errors)


# ═══════════════════════════════════════════════════════════════════════════════
# F. Edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_load_missing_yaml_file(self) -> None:
        """Loading a non-existent YAML file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            SaltaXConfig.load("/nonexistent/saltax.config.yaml")

    def test_load_malformed_yaml(self, tmp_path: Path) -> None:
        """Loading invalid YAML raises an appropriate error."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("pipeline:\n  approval_threshold: [invalid")
        with pytest.raises(Exception):  # yaml.scanner.ScannerError
            SaltaXConfig.load(bad_file)

    def test_env_missing_required_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing required env vars produce a clear ValidationError."""
        # Clear any existing SALTAX_ vars
        for key in list(monkeypatch._env_patchings if hasattr(monkeypatch, '_env_patchings') else []):
            pass
        monkeypatch.delenv("SALTAX_EIGENAI_API_KEY", raising=False)
        monkeypatch.delenv("SALTAX_GITHUB_APP_ID", raising=False)
        monkeypatch.delenv("SALTAX_GITHUB_APP_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SALTAX_GITHUB_WEBHOOK_SECRET", raising=False)
        monkeypatch.delenv("SALTAX_EIGENCLOUD_KMS_ENDPOINT", raising=False)
        with pytest.raises(ValidationError):
            EnvConfig(_env_file=None)  # type: ignore[call-arg]

    def test_yaml_alias_optimistic_verification(self, valid_config_yaml: Path) -> None:
        """The YAML key ``optimistic_verification`` maps to ``verification`` field."""
        cfg = SaltaXConfig.load(valid_config_yaml)
        assert cfg.verification.standard_window_hours == 24
        assert cfg.verification.self_modification_window_hours == 72

    def test_extra_yaml_fields_rejected(self, tmp_path: Path) -> None:
        """Unknown YAML keys are rejected by extra='forbid'."""
        bad_yaml = tmp_path / "extra.yaml"
        bad_yaml.write_text('version: "1.0"\nunknown_section: true\n')
        with pytest.raises(ValidationError, match="unknown_section"):
            SaltaXConfig.load(bad_yaml)

    def test_extra_pipeline_fields_rejected(self) -> None:
        """Unknown fields inside pipeline section are rejected."""
        with pytest.raises(ValidationError):
            PipelineConfig(approval_threshold=0.75, typo_field=True)  # type: ignore[call-arg]

    def test_empty_yaml_uses_defaults(self, tmp_path: Path) -> None:
        """An empty YAML file produces a config with all defaults."""
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        cfg = SaltaXConfig.load(empty_file)
        assert cfg.version == "1.0"
        assert cfg.pipeline.approval_threshold == 0.75


# ═══════════════════════════════════════════════════════════════════════════════
# G. Literal type validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestLiteralTypes:
    def test_triage_mode_invalid(self) -> None:
        """Triage mode not in ['autonomous', 'advisory'] is rejected."""
        with pytest.raises(ValidationError):
            SaltaXConfig(triage={"mode": "manual"})

    def test_triage_mode_valid_autonomous(self) -> None:
        cfg = SaltaXConfig(triage={"mode": "autonomous"})
        assert cfg.triage.mode == "autonomous"

    def test_triage_mode_valid_advisory(self) -> None:
        cfg = SaltaXConfig(triage={"mode": "advisory"})
        assert cfg.triage.mode == "advisory"

    def test_vision_source_invalid(self) -> None:
        """Vision source not in ['repo', 'api'] is rejected."""
        with pytest.raises(ValidationError):
            VisionConfig(source="local")  # type: ignore[arg-type]

    def test_vision_source_valid(self) -> None:
        v = VisionConfig(source="api")
        assert v.source == "api"

    def test_advisory_review_type_invalid(self) -> None:
        """Advisory review_type not 'COMMENT' is rejected."""
        with pytest.raises(ValidationError):
            SaltaXConfig(triage={"advisory": {"review_type": "APPROVE"}})


# ═══════════════════════════════════════════════════════════════════════════════
# H. Dead config removal (I3) and weight starvation (I7)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVisionConfigCleaned:
    def test_alignment_warn_threshold_rejected(self) -> None:
        """I3: alignment_warn_threshold is removed — extra fields are rejected."""
        with pytest.raises(ValidationError):
            VisionConfig(alignment_warn_threshold=5)  # type: ignore[call-arg]


class TestWeightStarvation:
    def test_validate_weight_starvation_warning(self) -> None:
        """I7: combined > 0.50 with vision enabled → warning."""
        cfg = SaltaXConfig()
        cfg.triage.vision.enabled = True
        cfg.triage.vision.alignment_weight = 0.30
        cfg.pipeline.history_weight = 0.25
        errors = validate_config(cfg)
        assert any("starved" in e.lower() or "exceeds 0.50" in e for e in errors)

    def test_validate_weight_starvation_ok(self) -> None:
        """I7: combined <= 0.50 → no warning."""
        cfg = SaltaXConfig()
        cfg.triage.vision.enabled = True
        cfg.triage.vision.alignment_weight = 0.15
        cfg.pipeline.history_weight = 0.10
        errors = validate_config(cfg)
        assert not any("starved" in e.lower() or "exceeds 0.50" in e for e in errors)

    def test_validate_weight_starvation_vision_disabled(self) -> None:
        """I7: vision disabled → no warning even with high weights."""
        cfg = SaltaXConfig()
        cfg.triage.vision.enabled = False
        cfg.triage.vision.alignment_weight = 0.30
        cfg.pipeline.history_weight = 0.30
        errors = validate_config(cfg)
        assert not any("starved" in e.lower() or "exceeds 0.50" in e for e in errors)


# ═══════════════════════════════════════════════════════════════════════════════
# L. Document types config (Feature 5)
# ═══════════════════════════════════════════════════════════════════════════════


class TestDocumentTypesConfig:
    def test_document_types_default(self) -> None:
        """Default document_types is ['vision']."""
        vc = VisionConfig()
        assert vc.document_types == ["vision"]

    def test_validate_config_invalid_doc_type(self) -> None:
        """Unknown document type triggers a validation error."""
        cfg = SaltaXConfig()
        cfg.triage.vision.document_types = ["vision", "unknown"]
        errors = validate_config(cfg)
        assert any("unknown type 'unknown'" in e for e in errors)

    def test_validate_config_valid_doc_types(self) -> None:
        """All valid types pass validation."""
        cfg = SaltaXConfig()
        cfg.triage.vision.document_types = ["vision", "architecture", "roadmap"]
        errors = validate_config(cfg)
        assert not any("unknown type" in e for e in errors)
