"""PR comment formatting functions for SaltaX pipeline results.

All functions are pure — they accept domain objects and return Markdown strings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.models.pipeline import Finding, Verdict

_MAX_FINDINGS_DISPLAYED = 20


def _escape_cell(value: str) -> str:
    """Escape characters that break Markdown table cells."""
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", "")


def format_pipeline_result(verdict: Verdict, findings: list[Finding]) -> str:
    """Format a pipeline verdict and findings as a Markdown PR comment."""
    lines: list[str] = [
        f"## SaltaX Pipeline Result: **{verdict.decision.value}**",
        "",
        f"**Composite score:** {verdict.composite_score:.2f} "
        f"(threshold: {verdict.threshold_used:.2f})",
        "",
        "### Score Breakdown",
        "",
        "| Component | Score |",
        "|-----------|-------|",
    ]

    for component, score in sorted(verdict.score_breakdown.items()):
        lines.append(f"| {component} | {score:.2f} |")

    if findings:
        displayed = findings[:_MAX_FINDINGS_DISPLAYED]
        lines.extend([
            "",
            f"### Findings ({len(findings)} total)",
            "",
            "| Severity | Category | File | Message |",
            "|----------|----------|------|---------|",
        ])
        for f in displayed:
            lines.append(
                f"| {f.severity.value} | {f.category.value} | "
                f"`{_escape_cell(f.file_path)}:{f.line_start}` | {_escape_cell(f.message)} |"
            )
        if len(findings) > _MAX_FINDINGS_DISPLAYED:
            lines.append(
                f"\n*… and {len(findings) - _MAX_FINDINGS_DISPLAYED} more findings.*"
            )
    else:
        lines.extend(["", "No findings reported."])

    return "\n".join(lines)


def format_ranking_update(
    rankings: list[dict[str, object]],
    *,
    repo: str = "",
    issue_number: int = 0,
) -> str:
    """Format a competitive PR ranking table as Markdown.

    Each entry is expected to contain ``pr_number``, ``pr_author``,
    ``composite_score``, and ``verdict`` (JSON string with a ``decision`` key).
    The top-ranked PR is marked as ``(recommended)``.

    When *repo* and *issue_number* are provided, an invisible HTML marker
    is prepended to enable comment deduplication (update-or-create pattern).
    """
    lines: list[str] = []
    if repo and issue_number:
        lines.append(f"<!-- saltax-ranking:{repo}:{issue_number} -->")
    lines.extend([
        "## SaltaX PR Rankings",
        "",
        "| Rank | PR | Author | Score | Status |",
        "|------|----|--------|-------|--------|",
    ])

    for i, entry in enumerate(rankings, start=1):
        pr_number = entry.get("pr_number", "?")
        author = entry.get("pr_author", "?")
        score = entry.get("composite_score", 0)
        score_str = f"{score:.2f}" if isinstance(score, int | float) else str(score)

        # Parse verdict JSON to extract decision string
        verdict_raw = entry.get("verdict", "")
        status = "—"
        if isinstance(verdict_raw, str) and verdict_raw:
            try:
                import json  # noqa: PLC0415
                verdict_data = json.loads(verdict_raw)
                status = str(verdict_data.get("decision", "—"))
            except (json.JSONDecodeError, TypeError):
                status = "—"

        pr_label = f"#{pr_number}"
        if i == 1:
            pr_label += " (recommended)"

        lines.append(
            f"| {i} | {_escape_cell(str(pr_label))} "
            f"| {_escape_cell(str(author))} | {score_str} "
            f"| {_escape_cell(status)} |"
        )

    return "\n".join(lines)


def format_advisory_review(
    verdict: Verdict,
    findings: list[Finding],
    recommendations: list[str],
) -> str:
    """Format a full advisory review comment with recommendation header."""
    lines: list[str] = [
        f"## SaltaX Advisory Review: **{verdict.decision.value}**",
        "",
        f"**Composite score:** {verdict.composite_score:.2f}",
        "",
    ]

    # Recommendations
    if recommendations:
        lines.append("### Recommendations")
        lines.append("")
        for rec in recommendations:
            lines.append(f"- {rec}")
        lines.append("")

    # Findings
    if findings:
        displayed = findings[:_MAX_FINDINGS_DISPLAYED]
        lines.extend([
            f"### Findings ({len(findings)} total)",
            "",
            "| Severity | Category | File | Message |",
            "|----------|----------|------|---------|",
        ])
        for f in displayed:
            lines.append(
                f"| {f.severity.value} | {f.category.value} | "
                f"`{_escape_cell(f.file_path)}:{f.line_start}` | {_escape_cell(f.message)} |"
            )
        if len(findings) > _MAX_FINDINGS_DISPLAYED:
            lines.append(
                f"\n*… and {len(findings) - _MAX_FINDINGS_DISPLAYED} more findings.*"
            )
        lines.append("")

    # Attestation footer
    attestation_id = verdict.attestation_id or "pending"
    lines.extend([
        "---",
        f"*SaltaX attestation: `{attestation_id}`*",
    ])

    return "\n".join(lines)
