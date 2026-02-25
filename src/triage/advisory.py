"""Advisory mode: post issue comments with recommendation labels.

Advisory mode is the human-in-the-loop dispatch path.  When
``config.triage.mode == "advisory"``, SaltaX posts an issue comment
with its recommendation and applies mutually exclusive labels
(recommends-merge / recommends-reject) but **never merges**.

HARD CONSTRAINT — this module must never:
  - call ``merge_pr``
  - post reviews with ``event="APPROVE"`` or ``event="REQUEST_CHANGES"``
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.github.comments import escape_cell

if TYPE_CHECKING:
    from src.config import AdvisoryConfig, SaltaXConfig
    from src.github.client import GitHubClient
    from src.intelligence.database import IntelligenceDB
    from src.pipeline.state import PipelineState

logger = logging.getLogger(__name__)


# -- Body builder -------------------------------------------------------------


def _build_advisory_body(state: PipelineState) -> str:
    """Build the Markdown body for an advisory issue comment.

    Pure function — no I/O.  All data comes from *state* attributes.
    """
    verdict = state.verdict or {}
    decision = str(verdict.get("decision", "")).upper()
    composite = verdict.get("composite_score", 0)
    threshold = verdict.get("threshold_used", 0)
    composite = composite if isinstance(composite, int | float) else 0
    threshold = threshold if isinstance(threshold, int | float) else 0
    breakdown = verdict.get("score_breakdown", {})

    attestation = state.attestation or {}
    attestation_id = attestation.get("attestation_id", "pending")

    # Decision -> human label
    recommendation = "Recommends Merge" if decision == "APPROVE" else "Recommends Reject"

    lines: list[str] = [
        f"<!-- saltax-advisory:{state.repo}:{state.pr_number} -->",
        f"## SaltaX Advisory: **{recommendation}**",
        "",
        f"**Composite score:** {composite:.2f} "
        f"(threshold: {threshold:.2f})  ",
        f"**Attestation:** `{attestation_id}`",
        "",
    ]

    # Score breakdown table
    if breakdown:
        lines.extend([
            "### Score Breakdown",
            "",
            "| Component | Score |",
            "|-----------|-------|",
        ])
        for component, score in sorted(breakdown.items()):
            score_val = score if isinstance(score, int | float) else 0
            lines.append(
                f"| {escape_cell(str(component))} | {score_val:.2f} |"
            )
        lines.append("")

    # Stage results table
    lines.extend([
        "### Stage Results",
        "",
        "| Stage | Result |",
        "|-------|--------|",
    ])

    # Static findings
    findings_count = len(state.static_findings)
    if findings_count > 0:
        severity_counts: dict[str, int] = {}
        for finding in state.static_findings:
            sev = str(finding.get("severity", "unknown"))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
        lines.append(
            f"| Static Analysis | {escape_cell(f'{findings_count} findings ({sev_str})')} |"
        )
    else:
        lines.append("| Static Analysis | Clean |")

    # AI analysis
    ai = state.ai_analysis or {}
    quality = ai.get("quality_score")
    risk = ai.get("risk_score")
    if quality is not None or risk is not None:
        q_str = f"{quality:.2f}" if isinstance(quality, int | float) else "N/A"
        r_str = f"{risk:.2f}" if isinstance(risk, int | float) else "N/A"
        lines.append(f"| AI Analysis | Quality: {q_str}, Risk: {r_str} |")
    else:
        lines.append("| AI Analysis | N/A |")

    # Vision alignment
    vision_score = ai.get("vision_alignment_score")
    if vision_score is not None and isinstance(vision_score, int | float):
        lines.append(f"| Vision Alignment | {vision_score:.2f} |")

    # Test results
    tests = state.test_results or {}
    passed = tests.get("passed")
    total = tests.get("total_tests")
    if passed is not None and total is not None:
        lines.append(f"| Tests | {passed}/{total} passed |")
    else:
        lines.append("| Tests | N/A |")

    lines.append("")

    # Duplicates section
    if state.duplicate_candidates:
        lines.extend([
            "### Potential Duplicates",
            "",
        ])
        for dup in state.duplicate_candidates:
            dup_pr = dup.get("pr_number", "?")
            dup_sim = dup.get("similarity", 0)
            sim_val = dup_sim if isinstance(dup_sim, int | float) else 0
            lines.append(f"- PR #{dup_pr} (similarity: {sim_val:.2f})")
        lines.append("")

    # Self-modification disclaimer
    if state.is_self_modification:
        lines.extend([
            "> **Note:** This PR modifies SaltaX's own code. "
            "Advisory mode is enforced regardless of triage configuration.",
            "",
        ])

    # Footer
    lines.extend([
        "---",
        f"*SaltaX attestation: `{attestation_id}`*",
    ])

    return "\n".join(lines)


# -- Label management ----------------------------------------------------------


async def _manage_advisory_labels(
    state: PipelineState,
    decision: str,
    advisory_config: AdvisoryConfig,
    github_client: GitHubClient,
) -> None:
    """Apply mutually exclusive recommendation labels.

    Idempotent — ensures labels exist before adding/removing.
    Never raises; all errors are logged.

    Concurrency note: label operations are sequential within a single call,
    but concurrent calls for the same PR (e.g. rapid pushes) may interleave.
    This is acceptable — the last writer wins, and labels converge to the
    correct state on the next event.
    """
    if state.pr_number is None or state.installation_id is None:
        return

    repo = state.repo
    pr_number = state.pr_number
    inst_id = state.installation_id
    merge_label = advisory_config.label_recommends_merge
    reject_label = advisory_config.label_recommends_reject

    # Ensure both labels exist in the repo
    try:
        await github_client.ensure_label(
            repo, inst_id, merge_label,
            color="0e8a16", description="SaltaX recommends merge",
        )
        await github_client.ensure_label(
            repo, inst_id, reject_label,
            color="b60205", description="SaltaX recommends reject",
        )
    except Exception:
        logger.warning(
            "Failed to ensure advisory labels, skipping label updates",
            exc_info=True,
            extra={"repo": repo, "pr_number": pr_number},
        )
        return

    # Apply the appropriate label, remove the other
    try:
        if decision == "APPROVE":
            await github_client.add_label(repo, pr_number, inst_id, merge_label)
            await github_client.remove_label(repo, pr_number, inst_id, reject_label)
        else:
            await github_client.add_label(repo, pr_number, inst_id, reject_label)
            await github_client.remove_label(repo, pr_number, inst_id, merge_label)
    except Exception:
        logger.warning(
            "Failed to update advisory labels",
            exc_info=True,
            extra={"repo": repo, "pr_number": pr_number},
        )


# -- Comment posting -----------------------------------------------------------


async def post_advisory_review(
    state: PipelineState,
    advisory_config: AdvisoryConfig,
    github_client: GitHubClient,
) -> None:
    """Post advisory comment and apply recommendation labels.

    Raises
    ------
    RuntimeError
        If ``advisory_config.review_type`` is not ``"COMMENT"``
        (defense-in-depth guard against config schema relaxation).

    All network/API errors are caught and logged — only the config
    guard raises.
    """
    if state.pr_number is None or state.installation_id is None:
        logger.warning(
            "Cannot post advisory review: missing pr_number or installation_id",
            extra={"pr_id": state.pr_id},
        )
        return

    body = _build_advisory_body(state)

    # Runtime guard: only COMMENT is allowed in advisory mode
    if advisory_config.review_type != "COMMENT":
        raise RuntimeError(
            f"Advisory review_type must be 'COMMENT', "
            f"got {advisory_config.review_type!r}. "
            f"Refusing to post a non-comment review in advisory mode."
        )

    # Update-or-create: find existing advisory comment, update it
    marker = f"<!-- saltax-advisory:{state.repo}:{state.pr_number} -->"
    try:
        existing = await github_client.list_issue_comments(
            state.repo, state.pr_number, state.installation_id,
        )
        existing_id: int | None = None
        for comment in existing:
            if marker in (comment.get("body") or ""):
                existing_id = comment["id"]
                break

        if existing_id is not None:
            await github_client.update_comment(
                state.repo, existing_id, state.installation_id, body,
            )
        else:
            await github_client.create_comment(
                state.repo, state.pr_number, state.installation_id, body,
            )
    except Exception as exc:
        status_code = getattr(exc, "status_code", None)
        if status_code == 422:
            logger.warning(
                "Advisory comment failed: PR may be closed/merged (422)",
                extra={"repo": state.repo, "pr_number": state.pr_number},
            )
        else:
            logger.error(
                "Advisory comment posting failed",
                exc_info=True,
                extra={"repo": state.repo, "pr_number": state.pr_number},
            )

    # Labels run even if comment posting failed (independent operation)
    verdict = state.verdict or {}
    decision = str(verdict.get("decision", "")).upper()
    await _manage_advisory_labels(state, decision, advisory_config, github_client)


# -- Master dispatch -----------------------------------------------------------


async def dispatch_decision(
    state: PipelineState,
    config: SaltaXConfig,
    github_client: GitHubClient,
    *,
    intel_db: IntelligenceDB,
) -> None:
    """Route the pipeline verdict to advisory review or verification window.

    Routing rules (priority order):
    1. No verdict -> log warning, return
    2. Self-modification -> ALWAYS advisory (regardless of mode)
    3. mode == "advisory" -> post_advisory_review
    4. mode == "autonomous" + APPROVE -> create_window (verification)
    """
    if not state.verdict:
        logger.warning(
            "dispatch_decision called with no verdict",
            extra={"pr_id": state.pr_id},
        )
        return

    decision = str(state.verdict.get("decision", "")).upper()

    # Self-modification: ALWAYS advisory — explicit return prevents fallthrough
    if state.is_self_modification:
        logger.info(
            "Self-modification detected, forcing advisory mode",
            extra={"pr_id": state.pr_id, "decision": decision},
        )
        try:
            await post_advisory_review(state, config.triage.advisory, github_client)
        except Exception:
            logger.error(
                "Advisory review failed for self-modification PR",
                exc_info=True,
                extra={"pr_id": state.pr_id},
            )
        return  # HARD CONSTRAINT: never reach create_window for self-mod

    # Advisory mode: post review + labels, never merge
    if config.triage.mode == "advisory":
        try:
            await post_advisory_review(state, config.triage.advisory, github_client)
        except Exception:
            logger.error(
                "Advisory review failed",
                exc_info=True,
                extra={"pr_id": state.pr_id},
            )
        return  # HARD CONSTRAINT: explicit return — create_window unreachable

    # Autonomous mode
    if config.triage.mode == "autonomous":
        if decision == "APPROVE":
            # APPROVE: open verification window → auto-merge → bounty payout
            from src.verification.window import create_window  # noqa: PLC0415

            attestation = state.attestation or {}
            if state.pr_number is not None and state.installation_id is not None:
                try:
                    await create_window(
                        intel_db=intel_db,
                        config=config.verification,
                        pr_id=state.pr_id,
                        repo=state.repo,
                        pr_number=state.pr_number,
                        installation_id=state.installation_id,
                        attestation_id=str(attestation.get("attestation_id", "")),
                        verdict=state.verdict,
                        attestation=attestation,
                        contributor_address=state.pr_author_wallet,
                        bounty_amount_wei=state.bounty_amount_wei,
                        stake_amount_wei=None,
                        is_self_modification=state.is_self_modification,
                    )
                except Exception:
                    logger.error(
                        "Verification window creation failed",
                        exc_info=True,
                        extra={"pr_id": state.pr_id},
                    )
        else:
            # Non-APPROVE (REQUEST_CHANGES / COMMENT): post advisory review
            # so the contributor receives feedback on what to fix.
            try:
                await post_advisory_review(
                    state, config.triage.advisory, github_client,
                )
            except Exception:
                logger.error(
                    "Advisory review failed for non-approve autonomous decision",
                    exc_info=True,
                    extra={"pr_id": state.pr_id, "decision": decision},
                )
