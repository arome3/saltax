"""Extract normalized vulnerability patterns from pipeline findings.

Converts raw static-scanner and AI-analysis findings into pattern dicts
suitable for upserting into the ``vulnerability_patterns`` table.
"""

from __future__ import annotations

from src.intelligence.similarity import _normalize_pattern


def extract_patterns(
    static_findings: list[dict[str, object]],
    ai_findings: list[object],
) -> list[dict[str, object]]:
    """Build pattern dicts from static and AI findings.

    Each returned dict contains:
    - ``rule_id``: identifier for the finding rule
    - ``severity``: severity level string
    - ``category``: finding category
    - ``normalized_pattern``: normalized code snippet / description
    - ``confidence``: float 0–1
    - ``source_stage``: ``"static_scanner"`` or ``"ai_analyzer"``

    Findings whose normalized pattern is empty after normalization are skipped.
    """
    patterns: list[dict[str, object]] = []

    for finding in static_findings:
        snippet = str(finding.get("snippet") or finding.get("message") or "")
        normalized = _normalize_pattern(snippet)
        if not normalized:
            continue
        patterns.append({
            "rule_id": str(finding.get("rule_id", "unknown")),
            "severity": str(finding.get("severity", "MEDIUM")).upper(),
            "category": str(finding.get("category", "static-analysis")),
            "normalized_pattern": normalized,
            "confidence": float(finding.get("confidence", 0.8)),
            "source_stage": "static_scanner",
        })

    for item in ai_findings:
        if not isinstance(item, dict):
            continue
        desc = str(item.get("description") or item.get("message") or "")
        normalized = _normalize_pattern(desc)
        if not normalized:
            continue
        patterns.append({
            "rule_id": str(item.get("rule_id", "ai-finding")),
            "severity": str(item.get("severity", "MEDIUM")).upper(),
            "category": str(item.get("category", "ai-analysis")),
            "normalized_pattern": normalized,
            "confidence": float(item.get("confidence", 0.7)),
            "source_stage": "ai_analyzer",
        })

    return patterns
