"""SaltaX three-tier configuration system.

Tier 1 — Immutable: Docker image parameters (not modelled here).
Tier 2 — Self-modifiable YAML: ``saltax.config.yaml`` loaded into ``SaltaXConfig``.
Tier 3 — Runtime environment: ``.env`` loaded into ``EnvConfig`` via pydantic-settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_DEFAULT_CONFIG_PATH = Path("saltax.config.yaml")


# ── Pipeline sub-models ──────────────────────────────────────────────────────


class PipelineWeights(BaseModel):
    """Decision-engine scoring weights — must sum to 1.0 (±0.001)."""

    model_config = ConfigDict(extra="forbid")

    static_clear: float = 0.25
    ai_quality: float = 0.25
    ai_security: float = 0.25
    tests_pass: float = 0.25

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> PipelineWeights:
        total = self.static_clear + self.ai_quality + self.ai_security + self.tests_pass
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Pipeline weights must sum to 1.0, got {total:.4f}")
        return self


class PipelineConfig(BaseModel):
    """Flat representation of the pipeline section.

    The YAML uses a nested ``stages:`` structure for operator readability.
    The ``model_validator(mode="before")`` flattens those nested keys into the
    fields expected by the Python model.
    """

    model_config = ConfigDict(extra="forbid")

    approval_threshold: float = Field(default=0.75, ge=0.5, le=1.0)
    self_modification_threshold: float = Field(default=0.90, ge=0.5, le=1.0)
    review_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    weights: PipelineWeights = Field(default_factory=PipelineWeights)
    static_scanner_timeout: int = Field(default=120, gt=0)
    ai_analyzer_model: str = "gpt-oss-120b-f16"
    ai_analyzer_timeout: int = Field(default=60, gt=0)
    ai_analyzer_semaphore_timeout: int = Field(default=30, gt=0)
    test_executor_timeout: int = Field(default=300, gt=0)
    test_executor_memory_mb: int = Field(default=512, gt=0)

    @model_validator(mode="before")
    @classmethod
    def _flatten_stages(cls, data: Any) -> Any:
        """Transform the nested YAML ``stages`` map into flat fields."""
        if not isinstance(data, dict):
            return data

        stages = data.pop("stages", None)
        if stages is None:
            return data

        # static_scanner → static_scanner_timeout
        scanner = stages.get("static_scanner") or {}
        if "timeout_seconds" in scanner:
            data.setdefault("static_scanner_timeout", scanner["timeout_seconds"])

        # ai_analyzer → ai_analyzer_model, ai_analyzer_timeout
        ai = stages.get("ai_analyzer") or {}
        if "model" in ai:
            data.setdefault("ai_analyzer_model", ai["model"])
        if "timeout_seconds" in ai:
            data.setdefault("ai_analyzer_timeout", ai["timeout_seconds"])
        if "semaphore_timeout_seconds" in ai:
            data.setdefault("ai_analyzer_semaphore_timeout", ai["semaphore_timeout_seconds"])

        # test_executor → test_executor_timeout, test_executor_memory_mb
        tests = stages.get("test_executor") or {}
        if "timeout_seconds" in tests:
            data.setdefault("test_executor_timeout", tests["timeout_seconds"])
        if "memory_limit_mb" in tests:
            data.setdefault("test_executor_memory_mb", tests["memory_limit_mb"])

        # decision_engine → weights
        engine = stages.get("decision_engine") or {}
        if "weights" in engine:
            data.setdefault("weights", engine["weights"])

        return data


# ── Treasury ─────────────────────────────────────────────────────────────────


class TreasuryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reserve_ratio: float = Field(default=0.20, ge=0.0, le=1.0)
    compute_budget: float = Field(default=0.10, ge=0.0, le=1.0)
    bounty_budget: float = Field(default=0.65, ge=0.0, le=1.0)
    community_fund: float = Field(default=0.05, ge=0.0, le=1.0)
    max_single_payout_eth: float = Field(default=0.5, gt=0)

    @model_validator(mode="after")
    def _allocations_sum_to_one(self) -> TreasuryConfig:
        total = (
            self.reserve_ratio + self.compute_budget + self.bounty_budget + self.community_fund
        )
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Treasury allocations must sum to 1.0, got {total:.4f}")
        return self


# ── Bounties ─────────────────────────────────────────────────────────────────


class BountyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    labels: dict[str, float] = Field(
        default_factory=lambda: {
            "bounty-xs": 0.01,
            "bounty-sm": 0.05,
            "bounty-md": 0.10,
            "bounty-lg": 0.25,
            "bounty-xl": 0.50,
        }
    )


# ── Verification ─────────────────────────────────────────────────────────────


class VerificationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    standard_window_hours: int = Field(default=24, gt=0)
    self_modification_window_hours: int = Field(default=72, gt=0)
    min_challenge_stake_multiplier: float = Field(default=1.0, ge=0.0)


# ── Staking ──────────────────────────────────────────────────────────────────


class StakingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    bonus_rate_no_challenge: float = Field(default=0.10, ge=0.0, le=1.0)
    bonus_rate_challenged_upheld: float = Field(default=0.20, ge=0.0, le=1.0)
    slash_rate_challenged_overturned: float = Field(default=0.50, ge=0.0, le=1.0)


# ── Audit pricing ────────────────────────────────────────────────────────────


class AuditPricingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    security_only_usdc: float = Field(default=5, gt=0)
    quality_only_usdc: float = Field(default=3, gt=0)
    full_audit_usdc: float = Field(default=10, gt=0)


# ── Triage sub-models ────────────────────────────────────────────────────────


class DedupConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    similarity_threshold: float = Field(default=0.85, ge=0.5, le=0.99)
    embedding_model: str = "text-embedding"


class RankingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    label_superseded: str = "superseded"
    label_recommended: str = "saltax-recommended"


class VisionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    alignment_weight: float = Field(default=0.15, ge=0.0, le=0.30)
    alignment_warn_threshold: int = Field(default=5, ge=1, le=9)
    source: Literal["repo", "api"] = "repo"


class AdvisoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_type: Literal["COMMENT"] = "COMMENT"
    label_recommends_merge: str = "saltax-recommends-merge"
    label_recommends_reject: str = "saltax-recommends-reject"


class TriageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    mode: Literal["autonomous", "advisory"] = "autonomous"
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    ranking: RankingConfig = Field(default_factory=RankingConfig)
    vision: VisionConfig = Field(default_factory=VisionConfig)
    advisory: AdvisoryConfig = Field(default_factory=AdvisoryConfig)


# ── Agent ────────────────────────────────────────────────────────────────────


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "SaltaX"
    description: str = "Sovereign Code Organism"


# ── Root config ──────────────────────────────────────────────────────────────


class SaltaXConfig(BaseModel):
    """Root configuration loaded from ``saltax.config.yaml``."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    agent: AgentConfig = Field(default_factory=AgentConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    treasury: TreasuryConfig = Field(default_factory=TreasuryConfig)
    bounties: BountyConfig = Field(default_factory=BountyConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    staking: StakingConfig = Field(default_factory=StakingConfig)
    audit_pricing: AuditPricingConfig = Field(default_factory=AuditPricingConfig)
    triage: TriageConfig = Field(default_factory=TriageConfig)

    @model_validator(mode="before")
    @classmethod
    def _remap_yaml_keys(cls, data: Any) -> Any:
        """Handle YAML key aliases that differ from Python field names."""
        if not isinstance(data, dict):
            return data

        # optimistic_verification → verification
        if "optimistic_verification" in data and "verification" not in data:
            data["verification"] = data.pop("optimistic_verification")

        return data

    @classmethod
    def load(cls, path: Path | str = _DEFAULT_CONFIG_PATH) -> SaltaXConfig:
        """Load and validate configuration from a YAML file."""
        config_path = Path(path)
        with config_path.open() as fh:
            raw = yaml.safe_load(fh)
        if raw is None:
            raw = {}
        return cls(**raw)


# ── Environment config (Tier 3) ─────────────────────────────────────────────


class EnvConfig(BaseSettings):
    """Runtime environment variables loaded from ``.env`` or the OS environment.

    Required secrets have no default — instantiation fails if they are absent.
    """

    model_config = SettingsConfigDict(
        env_prefix="SALTAX_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Required (no defaults — must be provided)
    eigenai_api_key: str
    github_app_id: str
    github_app_private_key: str
    github_webhook_secret: str
    eigencloud_kms_endpoint: str

    # Optional with sensible defaults
    eigenai_api_url: str = "https://eigenai.eigencloud.xyz/v1"
    rpc_url: str = "https://mainnet.base.org"
    chain_id: int = 8453
    identity_rpc_url: str = "https://ethereum-sepolia-rpc.publicnode.com"
    identity_chain_id: int = 11155111
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8080
    internal_bridge_port: int = 8081


# ── Cross-tier validation ────────────────────────────────────────────────────


def validate_config(cfg: SaltaXConfig) -> list[str]:
    """Run cross-field validation rules that span multiple config sections.

    Returns a list of human-readable error/warning strings.  An empty list
    means the configuration is consistent.
    """
    errors: list[str] = []

    # 1. self_modification_threshold must exceed approval_threshold
    if cfg.pipeline.self_modification_threshold <= cfg.pipeline.approval_threshold:
        errors.append(
            "pipeline.self_modification_threshold "
            f"({cfg.pipeline.self_modification_threshold}) must be greater than "
            f"pipeline.approval_threshold ({cfg.pipeline.approval_threshold})"
        )

    # 2. review_threshold must be below approval_threshold
    if cfg.pipeline.review_threshold >= cfg.pipeline.approval_threshold:
        errors.append(
            "pipeline.review_threshold "
            f"({cfg.pipeline.review_threshold}) must be less than "
            f"pipeline.approval_threshold ({cfg.pipeline.approval_threshold})"
        )

    # 3. Largest bounty payout must not exceed max_single_payout_eth
    if cfg.bounties.labels:
        max_bounty = max(cfg.bounties.labels.values())
        if max_bounty > cfg.treasury.max_single_payout_eth:
            errors.append(
                f"Largest bounty label value ({max_bounty}) exceeds "
                f"treasury.max_single_payout_eth ({cfg.treasury.max_single_payout_eth})"
            )

    # 4. Advisory mode + triage enabled → staking inactive informational note
    if cfg.triage.enabled and cfg.triage.mode == "advisory" and not cfg.staking.enabled:
        errors.append(
            "Triage is enabled in advisory mode but staking is disabled — "
            "contributors will not earn staking bonuses"
        )

    # 5. Upheld bonus should exceed unchallenged bonus
    if cfg.staking.bonus_rate_challenged_upheld <= cfg.staking.bonus_rate_no_challenge:
        errors.append(
            "staking.bonus_rate_challenged_upheld "
            f"({cfg.staking.bonus_rate_challenged_upheld}) should be greater than "
            f"staking.bonus_rate_no_challenge ({cfg.staking.bonus_rate_no_challenge})"
        )

    # 6. Self-modification window must exceed standard window
    if (
        cfg.verification.self_modification_window_hours
        <= cfg.verification.standard_window_hours
    ):
        errors.append(
            "verification.self_modification_window_hours "
            f"({cfg.verification.self_modification_window_hours}) must be greater than "
            f"verification.standard_window_hours ({cfg.verification.standard_window_hours})"
        )

    return errors
