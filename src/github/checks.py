"""Check run creation helpers for the SaltaX pipeline."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from src.models.enums import Decision, Severity

if TYPE_CHECKING:
    from src.github.client import GitHubClient
    from src.models.pipeline import Finding, Verdict

logger = logging.getLogger(__name__)

_CHECK_NAME = "SaltaX Pipeline"
_MAX_ANNOTATIONS = 50

_SEVERITY_TO_ANNOTATION_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "failure",
    Severity.HIGH: "failure",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}

_DECISION_TO_CONCLUSION: dict[Decision, str] = {
    Decision.APPROVE: "success",
    Decision.REQUEST_CHANGES: "action_required",
    Decision.REJECT: "failure",
}


def build_check_output(verdict: Verdict, findings: list[Finding]) -> dict[str, Any]:
    """Convert a verdict and findings into a GitHub check-run ``output`` payload."""
    annotations: list[dict[str, Any]] = []
    for finding in findings[:_MAX_ANNOTATIONS]:
        annotations.append({
            "path": finding.file_path,
            "start_line": finding.line_start,
            "end_line": finding.line_end,
            "annotation_level": _SEVERITY_TO_ANNOTATION_LEVEL.get(
                finding.severity, "notice"
            ),
            "message": finding.message,
            "title": f"[{finding.severity.value}] {finding.rule_id}",
        })

    summary = (
        f"**Decision:** {verdict.decision.value}\n"
        f"**Score:** {verdict.composite_score:.2f} "
        f"(threshold: {verdict.threshold_used:.2f})\n"
        f"**Findings:** {len(findings)}"
    )

    if len(findings) > _MAX_ANNOTATIONS:
        summary += (
            f"\n\n*Showing {_MAX_ANNOTATIONS} of {len(findings)} annotations "
            f"(GitHub API limit).*"
        )

    return {
        "title": f"SaltaX: {verdict.decision.value}",
        "summary": summary,
        "annotations": annotations,
    }


async def create_saltax_check(
    client: GitHubClient,
    repo: str,
    head_sha: str,
    installation_id: int,
    verdict: Verdict,
    findings: list[Finding],
) -> dict[str, Any]:
    """Create a completed SaltaX check run on a commit."""
    conclusion = _DECISION_TO_CONCLUSION.get(verdict.decision, "failure")
    output = build_check_output(verdict, findings)

    logger.info(
        "Creating check run",
        extra={
            "repo": repo,
            "head_sha": head_sha[:12],
            "conclusion": conclusion,
            "findings_count": len(findings),
        },
    )

    return await client.create_check_run(
        repo,
        head_sha,
        installation_id,
        name=_CHECK_NAME,
        status="completed",
        conclusion=conclusion,
        output=output,
    )
