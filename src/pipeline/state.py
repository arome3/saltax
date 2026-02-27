"""Mutable pipeline state passed through each async stage function.

``PipelineState`` is a stdlib ``@dataclass`` — not a Pydantic model — because
stages mutate it in place.  Stage outputs are stored as ``dict`` to decouple
stages from each other's internal schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PipelineState:
    """Accumulated state for a single pipeline execution.

    Required fields are set at pipeline entry from the incoming ``PREvent``.
    Optional and list fields are populated progressively by each stage.
    """

    # ── Input fields (set at pipeline entry) ────────────────────────────────
    pr_id: str
    repo: str
    repo_url: str
    commit_sha: str
    diff: str
    base_branch: str
    head_branch: str
    pr_author: str
    pr_number: int | None = None
    installation_id: int | None = None
    pr_author_wallet: str | None = None
    bounty_amount_wei: int | None = None
    is_self_modification: bool = False

    # ── Triage fields (populated by pre-pipeline triage layer) ──────────────
    target_issue_number: int | None = None
    duplicate_candidates: list[dict[str, object]] = field(default_factory=list)
    vision_document: str | None = None
    custom_rules_text: str | None = None
    scan_include: tuple[str, ...] = ()
    scan_exclude: tuple[str, ...] = ()

    # ── Stage output fields (populated as pipeline executes) ────────────────
    static_findings: list[dict[str, object]] = field(default_factory=list)
    ai_analysis: dict[str, object] | None = None
    test_results: dict[str, object] | None = None
    verdict: dict[str, object] | None = None
    attestation: dict[str, object] | None = None

    # ── Pipeline metadata ───────────────────────────────────────────────────
    trace_id: str = ""
    pipeline_start_time: str = ""
    current_stage: str = ""
    error: str | None = None
    short_circuit: bool = False
    ai_seed: int | None = None
    ai_output_hash: str | None = None
    ai_system_fingerprint: str | None = None
