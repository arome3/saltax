"""Confidence scoring, tiering, and calibration for pipeline findings.

Surfaces per-finding confidence in review comments, advisory bodies, and
PR summaries.  Provides calibration via historical TP/FP feedback and
configurable filtering to suppress low-confidence noise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.intelligence.database import IntelligenceDB

# ── Tier thresholds ──────────────────────────────────────────────────────────

_HIGH_THRESHOLD = 0.80
_MEDIUM_THRESHOLD = 0.50

# ── Calibration constants ────────────────────────────────────────────────────

_RAW_WEIGHT = 0.60
_FEEDBACK_WEIGHT = 0.40
_MIN_FEEDBACK_SIGNALS = 3

# ── Tier icons ───────────────────────────────────────────────────────────────

_TIER_ICONS: dict[str, str] = {
    "High": ":green_circle:",
    "Medium": ":yellow_circle:",
    "Low": ":white_circle:",
}


# ── Core functions ───────────────────────────────────────────────────────────


def confidence_tier(score: float) -> str:
    """Map a 0.0-1.0 confidence score to "High" / "Medium" / "Low"."""
    if score >= _HIGH_THRESHOLD:
        return "High"
    if score >= _MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def confidence_badge(score: float) -> str:
    """Full badge with emoji icon: ':green_circle: **High** (85%)'."""
    tier = confidence_tier(score)
    icon = _TIER_ICONS[tier]
    pct = round(score * 100)
    return f"{icon} **{tier}** ({pct}%)"


def confidence_badge_compact(score: float) -> str:
    """Compact badge for table cells: 'High (85%)'.

    Returns "—" if *score* is not a numeric type (float or int).
    Existing test data uses string tier names like ``"HIGH"`` — those
    must be coerced via :func:`_safe_confidence` before calling this.
    """
    if not isinstance(score, int | float):
        return "\u2014"
    tier = confidence_tier(float(score))
    pct = round(float(score) * 100)
    return f"{tier} ({pct}%)"


def _safe_confidence(value: object) -> float | None:
    """Coerce a confidence value to float, returning ``None`` if not numeric.

    Handles:
    - ``float`` / ``int`` — pass through (clamped to [0.0, 1.0])
    - ``str`` that parses as float — coerce
    - ``None``, string tier names ("HIGH", "LOW") — return ``None``
    """
    if value is None:
        return None
    if isinstance(value, float):
        return max(0.0, min(1.0, value))
    if isinstance(value, int):
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        try:
            parsed = float(value)
            return max(0.0, min(1.0, parsed))
        except ValueError:
            return None
    return None


async def calibrated_confidence(
    *,
    raw_confidence: float,
    rule_id: str,
    intel_db: IntelligenceDB,
) -> float:
    """Blend raw confidence with observed TP rate (60/40 weight).

    Uses ``intel_db.get_rule_feedback_stats()`` — never accesses private
    pool internals.  Requires a minimum of ``_MIN_FEEDBACK_SIGNALS``
    total feedback signals before adjusting.

    Returns
    -------
    float
        Calibrated confidence clamped to [0.0, 1.0].
    """
    stats = await intel_db.get_rule_feedback_stats(rule_id)
    if stats is None:
        return raw_confidence

    tp = stats.get("confirmed_true_positive", 0)
    fp = stats.get("confirmed_false_positive", 0)
    total = tp + fp

    if total < _MIN_FEEDBACK_SIGNALS:
        return raw_confidence

    tp_rate = tp / total
    blended = (_RAW_WEIGHT * raw_confidence) + (_FEEDBACK_WEIGHT * tp_rate)
    return max(0.0, min(1.0, blended))


def filter_findings_by_confidence(
    findings: list[dict[str, object]],
    min_confidence: float = 0.0,
) -> list[dict[str, object]]:
    """Filter findings below *min_confidence* for display purposes.

    Uses :func:`_safe_confidence` to handle mixed types.  Findings with
    missing or non-numeric confidence are treated as 0.5 (neutral) so
    they survive moderate thresholds but are filtered by strict ones.
    """
    if min_confidence <= 0.0:
        return findings

    default_confidence = 0.5
    result: list[dict[str, object]] = []
    for f in findings:
        conf = _safe_confidence(f.get("confidence"))
        effective = conf if conf is not None else default_confidence
        if effective >= min_confidence:
            result.append(f)
    return result
