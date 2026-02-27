"""PR summary comment builder — visual analysis with mermaid diagrams.

This module builds a *visual summary* comment posted on every pipeline run.
It is distinct from the advisory comment (``src/triage/advisory.py``), which
only posts when triage is enabled.  The summary provides an at-a-glance
picture: score waterfall chart, module dependency graph, file risk heatmap,
stage results table, and collapsible findings detail.

All ``_build_*`` functions are pure — they accept domain dicts and return
Markdown strings, making them trivially testable.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

from src.feedback.confidence import _safe_confidence, confidence_badge_compact
from src.github.comments import escape_cell

if TYPE_CHECKING:
    from src.github.client import GitHubClient

logger = logging.getLogger(__name__)

_SUMMARY_MARKER = "<!-- saltax-summary:{repo}:{pr_number} -->"
_DIFF_FILE_RE = re.compile(r"^diff --git a/.+? b/(.+?)$", re.MULTILINE)
_MAX_FINDINGS_DISPLAYED = 30
_MAX_COMMENT_LENGTH = 65_000  # GitHub limit is 65535; leave margin

_RISK_ICONS: dict[str, str] = {
    "critical": ":red_circle:",
    "high": ":orange_circle:",
    "medium": ":yellow_circle:",
    "low": ":green_circle:",
    "info": ":white_circle:",
}
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}
_STAGE_DISPLAY: dict[str, str] = {
    "static_clear": "Static",
    "ai_quality": "AI Quality",
    "ai_security": "AI Security",
    "tests_pass": "Tests",
    "vision_alignment": "Vision",
    "history": "History",
}


# ── Helper utilities ─────────────────────────────────────────────────────────


def _extract_changed_files(diff: str) -> list[str]:
    """Extract unique file paths from a unified diff (``b/`` side)."""
    seen: set[str] = set()
    result: list[str] = []
    for match in _DIFF_FILE_RE.finditer(diff):
        path = match.group(1)
        if path not in seen:
            seen.add(path)
            result.append(path)
    return result


def _truncate_path(file_path: str, segments: int = 3) -> str:
    """Return the last *segments* path components for readability."""
    parts = file_path.split("/")
    if len(parts) > segments:
        return "/".join(parts[-segments:])
    return file_path


# ── Section builders (pure functions) ────────────────────────────────────────


def _build_score_waterfall(breakdown: dict[str, float]) -> str:
    """Build a mermaid xychart-beta bar chart showing stage contributions."""
    labels: list[str] = []
    values: list[float] = []
    for key, display in _STAGE_DISPLAY.items():
        if key in breakdown:
            labels.append(f'"{display}"')
            values.append(round(breakdown[key], 3))

    if not labels:
        return ""

    y_max = max(max(values) * 1.2, 0.30)
    value_str = ", ".join(str(v) for v in values)
    label_str = ", ".join(labels)

    return (
        "### Score Waterfall\n\n"
        "```mermaid\n"
        "xychart-beta\n"
        '  title "Stage Contributions"\n'
        f"  x-axis [{label_str}]\n"
        f'  y-axis "Score" 0 --> {y_max:.2f}\n'
        f"  bar [{value_str}]\n"
        "```\n"
    )


def _build_module_diagram(
    changed_files: list[str],
    knowledge: list[dict[str, Any]],
) -> str | None:
    """Build a mermaid graph LR showing dependency edges among changed files.

    Returns ``None`` if the graph would have fewer than 2 nodes and no edges.
    """
    if not knowledge or len(changed_files) < 2:
        return None

    changed_set = set(changed_files)
    # Map file_path → list of imported paths (from knowledge JSON)
    imports_map: dict[str, list[str]] = {}
    for entry in knowledge:
        fp = entry.get("file_path", "")
        if fp not in changed_set:
            continue
        raw = entry.get("knowledge", "")
        if not raw:
            continue
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, dict) and isinstance(parsed.get("imports"), list):
                imports_map[fp] = [
                    imp for imp in parsed["imports"] if imp in changed_set
                ]
        except (json.JSONDecodeError, TypeError):
            continue

    # Build edges
    edges: list[tuple[str, str]] = []
    for src, targets in imports_map.items():
        for tgt in targets:
            if src != tgt:
                edges.append((src, tgt))

    # Cap nodes and edges
    capped_files = changed_files[:10]
    capped_set = set(capped_files)
    edges = [(s, t) for s, t in edges if s in capped_set and t in capped_set][:15]

    if len(capped_files) < 2 and not edges:
        return None

    # Assign node IDs
    node_ids: dict[str, str] = {}
    for i, fp in enumerate(capped_files):
        node_ids[fp] = f"N{i}"

    lines = ["### Module Dependencies\n", "```mermaid", "graph LR"]
    for fp, nid in node_ids.items():
        short = fp.rsplit("/", 1)[-1]
        lines.append(f'  {nid}["{short}"]')

    for src, tgt in edges:
        lines.append(f"  {node_ids[src]} --> {node_ids[tgt]}")

    # Style changed files
    ids = " ".join(node_ids.values())
    lines.append(f"  style {ids} fill:#ff9,stroke:#333")
    lines.append("```\n")

    return "\n".join(lines)


def _build_file_risk_heatmap(
    changed_files: list[str],
    findings: list[dict[str, object]],
) -> str:
    """Build a markdown table mapping files to finding counts and severity."""
    # Group findings by file_path
    file_findings: dict[str, list[dict[str, object]]] = {}
    for f in findings:
        fp = str(f.get("file_path", ""))
        file_findings.setdefault(fp, []).append(f)

    lines = [
        "### File Risk Heatmap\n",
        "| File | Findings | Severity | Risk |",
        "|------|----------|----------|------|",
    ]

    for fp in changed_files:
        ff = file_findings.get(fp, [])
        count = len(ff)
        if count == 0:
            lines.append(
                f"| `{escape_cell(_truncate_path(fp))}` | 0 | — | :green_circle: |"
            )
            continue

        severities = sorted(
            {str(f.get("severity", "INFO")).upper() for f in ff},
            key=lambda s: _SEVERITY_ORDER.get(s, 99),
        )
        max_sev = severities[0] if severities else "INFO"
        icon = _RISK_ICONS.get(max_sev.lower(), ":white_circle:")
        sev_str = ", ".join(severities)
        lines.append(
            f"| `{escape_cell(_truncate_path(fp))}` | {count} "
            f"| {escape_cell(sev_str)} | {icon} |"
        )

    return "\n".join(lines)


def _build_stage_results(
    static_findings: list[dict[str, object]],
    ai_analysis: dict[str, object] | None,
    test_results: dict[str, object] | None,
    vision_score: float | None,
) -> str:
    """Build a stage-by-stage results table."""
    lines = [
        "### Stage Results\n",
        "| Stage | Status | Detail |",
        "|-------|--------|--------|",
    ]

    # Static Scanner
    n_findings = len(static_findings)
    if n_findings > 0:
        sev_counts: dict[str, int] = {}
        for f in static_findings:
            sev = str(f.get("severity", "INFO")).upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_detail = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items()))
        lines.append(
            f"| Static Scanner | {n_findings} findings | {escape_cell(sev_detail)} |"
        )
    else:
        lines.append("| Static Scanner | Clean | No findings |")

    # AI Quality
    if ai_analysis:
        quality = ai_analysis.get("quality_score")
        if quality is not None:
            arch = ai_analysis.get("architectural_fit")
            detail = f"architectural_fit: {arch}" if arch is not None else "—"
            lines.append(
                f"| AI Quality | {float(quality):.1f} / 10 | {escape_cell(detail)} |"
            )
        else:
            lines.append("| AI Quality | N/A | — |")

        risk = ai_analysis.get("risk_score")
        if risk is not None:
            concerns = ai_analysis.get("security_concerns", [])
            n_concerns = len(concerns) if isinstance(concerns, list) else 0
            lines.append(
                f"| AI Security | {float(risk):.1f} / 10 | {n_concerns} concerns |"
            )
        else:
            lines.append("| AI Security | N/A | — |")
    else:
        lines.append("| AI Quality | N/A | — |")
        lines.append("| AI Security | N/A | — |")

    # Tests
    if test_results:
        passed = test_results.get("passed_tests", 0)
        total = test_results.get("total_tests", 0)
        coverage = test_results.get("coverage_percent")
        status_raw = str(test_results.get("status", "")).upper()
        status = "PASSED" if status_raw == "PASSED" else (
            "FAILED" if status_raw == "FAILED" else status_raw or "N/A"
        )
        cov_str = f", {coverage}% coverage" if coverage is not None else ""
        lines.append(f"| Tests | {status} | {passed}/{total} tests{cov_str} |")
    else:
        lines.append("| Tests | N/A | — |")

    # Vision (optional)
    if vision_score is not None:
        lines.append(f"| Vision | {vision_score:.2f} | — |")

    return "\n".join(lines)


def _build_findings_detail(findings: list[dict[str, object]]) -> str:
    """Build a collapsible ``<details>`` section with a findings table."""
    if not findings:
        return ""

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -(_safe_confidence(f.get("confidence")) or 0.0),
            _SEVERITY_ORDER.get(str(f.get("severity", "INFO")).upper(), 99),
            str(f.get("file_path", "")),
        ),
    )

    displayed = sorted_findings[:_MAX_FINDINGS_DISPLAYED]
    remaining = len(sorted_findings) - len(displayed)

    lines = [
        "<details>",
        f"<summary>Findings Detail ({len(sorted_findings)} total)</summary>\n",
        "| # | Severity | Rule | File | Line | Message | Confidence |",
        "|---|----------|------|------|------|---------|------------|",
    ]

    for i, f in enumerate(displayed, start=1):
        sev = str(f.get("severity", "INFO")).upper()
        rule = escape_cell(str(f.get("rule_id", f.get("check_id", "\u2014"))))
        fp = escape_cell(_truncate_path(str(f.get("file_path", "\u2014"))))
        line_no = f.get("line_start", f.get("line", "\u2014"))
        msg = escape_cell(str(f.get("message", "\u2014")))
        conf_val = _safe_confidence(f.get("confidence"))
        conf_display = confidence_badge_compact(conf_val) if conf_val is not None else "\u2014"
        lines.append(f"| {i} | {sev} | {rule} | `{fp}` | {line_no} | {msg} | {conf_display} |")

    if remaining > 0:
        lines.append(f"\n*… and {remaining} more findings.*")

    lines.append("\n</details>")
    return "\n".join(lines)


# ── Main builder ─────────────────────────────────────────────────────────────


def build_pr_summary(
    *,
    repo: str,
    pr_number: int,
    diff: str,
    static_findings: list[dict[str, object]],
    ai_analysis: dict[str, object] | None,
    test_results: dict[str, object] | None,
    verdict: dict[str, object],
    attestation_id: str,
    codebase_knowledge: list[dict[str, object]] | None = None,
    vision_score: float | None = None,
    score_breakdown: dict[str, float] | None = None,
) -> str:
    """Assemble the full PR summary comment body.

    All parameters come from ``PipelineState`` fields; this function is a pure
    transformation with no side effects.
    """
    marker = _SUMMARY_MARKER.format(repo=repo, pr_number=pr_number)
    changed_files = _extract_changed_files(diff)

    composite = verdict.get("composite_score", 0)
    threshold = verdict.get("threshold_used", 0)
    decision = str(verdict.get("decision", "—")).upper()

    sections: list[str] = [
        marker,
        "## SaltaX Analysis Summary\n",
        (
            f"**Verdict:** {decision} — "
            f"**Score:** {float(composite):.2f} / {float(threshold):.2f} threshold\n"
        ),
    ]

    # Score waterfall (only with breakdown data)
    if score_breakdown:
        waterfall = _build_score_waterfall(score_breakdown)
        if waterfall:
            sections.append(waterfall)

    # Module diagram (only with knowledge + multiple files)
    if codebase_knowledge and len(changed_files) >= 2:
        diagram = _build_module_diagram(changed_files, codebase_knowledge)
        if diagram:
            sections.append(diagram)

    # Always-present sections
    sections.append(_build_file_risk_heatmap(changed_files, static_findings))
    sections.append("")
    sections.append(
        _build_stage_results(static_findings, ai_analysis, test_results, vision_score)
    )

    # Collapsible findings
    if static_findings:
        sections.append("")
        sections.append(_build_findings_detail(static_findings))

    # Footer
    sections.append("")
    sections.append(f"---\n*Attestation:* `{attestation_id}`")

    body = "\n".join(sections)

    # Truncate if over GitHub comment limit
    if len(body) > _MAX_COMMENT_LENGTH:
        truncation_note = "\n\n*… summary truncated (exceeds GitHub comment limit).*"
        body = body[: _MAX_COMMENT_LENGTH - len(truncation_note)] + truncation_note

    return body


# ── Async posting ────────────────────────────────────────────────────────────


async def post_or_update_summary(
    *,
    repo: str,
    pr_number: int,
    installation_id: int,
    summary_body: str,
    github_client: GitHubClient,
) -> None:
    """Post or update the visual summary comment on a PR.

    Uses the same update-or-create pattern as ``src/triage/advisory.py``.
    Never raises — all exceptions are caught and logged.
    """
    marker = _SUMMARY_MARKER.format(repo=repo, pr_number=pr_number)
    try:
        existing = await github_client.list_issue_comments(
            repo, pr_number, installation_id,
        )
        existing_id: int | None = None
        for comment in existing:
            if marker in (comment.get("body") or ""):
                existing_id = comment["id"]
                break

        if existing_id is not None:
            await github_client.update_comment(
                repo, existing_id, installation_id, summary_body,
            )
        else:
            await github_client.create_comment(
                repo, pr_number, installation_id, summary_body,
            )
    except Exception as exc:
        status_code = getattr(exc, "status_code", None)
        if status_code == 422:
            logger.warning(
                "Summary comment failed: PR may be closed/merged (422)",
                extra={"repo": repo, "pr_number": pr_number},
            )
        else:
            logger.error(
                "Summary comment posting failed",
                exc_info=True,
                extra={"repo": repo, "pr_number": pr_number},
            )
