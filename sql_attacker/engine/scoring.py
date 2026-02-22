"""
Confidence Scoring with Per-feature Contributions
==================================================
Provides an improved confidence-scoring API where each detection signal carries
an explicit weight and the final score is accompanied by a structured breakdown
of which features contributed.

This replaces the single ``compute_confidence(signals)`` call in
``response_normalizer.py`` with a richer API while remaining fully backwards
compatible (the old signature still works through the compatibility shim at the
bottom of this module).

Classes
-------
FeatureContribution
    Represents the contribution of a single detection signal to the overall
    score.

ScoringResult
    Returned by :func:`compute_confidence`.  Contains the numeric score, a
    human-readable verdict, and the ordered list of per-feature contributions.

Functions
---------
compute_confidence(features) → ScoringResult
    Compute a combined confidence score from a dict of feature names and their
    raw values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Feature definitions
# ---------------------------------------------------------------------------

# Each feature has a *weight* that represents how strongly it contributes to
# the overall confidence score when fully active.  Weights are in [0, 1].
_FEATURE_WEIGHTS: Dict[str, float] = {
    # Error-based signals
    "sql_error_pattern": 0.90,
    # Time-delay signals
    "timing_delta_significant": 0.80,
    # Boolean differential
    "boolean_diff": 0.75,
    # Body similarity delta (large drop compared to baseline)
    "similarity_delta": 0.65,
    # General content change
    "content_change": 0.60,
    # HTTP error code change
    "http_error_code": 0.50,
    # JavaScript error / stack trace
    "js_error": 0.50,
    # Repeatability — finding persisted across multiple probes
    "repeatability": 0.70,
    # Benign control was negative (did NOT trigger detection)
    "benign_control_negative": 0.40,
}

# Minimum number of distinct features required for "confirmed" verdict
_MIN_CONFIRMED_FEATURES = 2
# Minimum score threshold for "confirmed" verdict
_MIN_CONFIRMED_SCORE = 0.70
# Minimum score threshold for "likely" verdict
_MIN_LIKELY_SCORE = 0.45


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FeatureContribution:
    """Contribution of a single detection feature to the confidence score.

    Attributes
    ----------
    name:    Feature identifier (e.g. ``"sql_error_pattern"``).
    weight:  Configured maximum weight for this feature in ``[0, 1]``.
    value:   Actual value passed by the caller, normalised to ``[0, 1]``.
             For boolean signals pass ``1.0`` (active) or ``0.0`` (inactive).
    contribution: Effective contribution = ``weight × value``.
    """

    name: str
    weight: float
    value: float
    contribution: float = field(init=False)

    def __post_init__(self) -> None:
        self.contribution = round(self.weight * max(0.0, min(1.0, self.value)), 4)


@dataclass
class ScoringResult:
    """Result returned by :func:`compute_confidence`.

    Attributes
    ----------
    score:         Combined confidence score in ``[0, 1]``.
    verdict:       One of ``"confirmed"``, ``"likely"``, ``"uncertain"``.
    contributions: Per-feature breakdown, sorted by contribution descending.
    rationale:     Human-readable explanation of the verdict.
    """

    score: float
    verdict: str
    contributions: List[FeatureContribution]
    rationale: str


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------


def compute_confidence(
    features: Dict[str, float],
    *,
    extra_weights: Optional[Dict[str, float]] = None,
) -> ScoringResult:
    """Compute a combined confidence score with per-feature contributions.

    Parameters
    ----------
    features:
        Mapping of feature name → value in ``[0, 1]``.  Boolean features
        should use ``1.0`` (active) or ``0.0`` (inactive).  Unknown feature
        names are accepted and assigned a default weight of ``0.30``.
    extra_weights:
        Optional dict of additional or overriding feature weights.

    Returns
    -------
    :class:`ScoringResult`
    """
    weights = dict(_FEATURE_WEIGHTS)
    if extra_weights:
        weights.update(extra_weights)

    contributions: List[FeatureContribution] = []
    for name, value in features.items():
        w = weights.get(name, 0.30)
        contributions.append(FeatureContribution(name=name, weight=w, value=float(value)))

    # Sort by descending contribution so the most important signals appear first
    contributions.sort(key=lambda c: c.contribution, reverse=True)

    active = [c for c in contributions if c.contribution > 0]

    if not active:
        return ScoringResult(
            score=0.0,
            verdict="uncertain",
            contributions=contributions,
            rationale="No active detection features.",
        )

    # Combined score: 1 − ∏(1 − cᵢ)  (probabilistic union under independence)
    combined = 1.0
    for c in active:
        combined *= 1.0 - c.contribution
    score = round(1.0 - combined, 4)

    n_active = len(active)
    if n_active >= _MIN_CONFIRMED_FEATURES and score >= _MIN_CONFIRMED_SCORE:
        verdict = "confirmed"
    elif score >= _MIN_LIKELY_SCORE:
        verdict = "likely"
    else:
        verdict = "uncertain"

    top_names = ", ".join(c.name for c in active[:3])
    rationale = (
        f"score={score:.3f}, verdict={verdict}, "
        f"active_features={n_active} (top: {top_names})"
    )

    return ScoringResult(
        score=score,
        verdict=verdict,
        contributions=contributions,
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# Backwards-compatibility shim
# ---------------------------------------------------------------------------
# The legacy ``response_normalizer.compute_confidence(signals: List[str])``
# accepted a flat list of signal name strings.  The shim below allows callers
# that pass a list of strings to continue working.


def compute_confidence_from_signals(signals: Sequence[str]) -> Tuple[float, str]:
    """Backwards-compatible wrapper for the old ``(signals: List[str])`` API.

    Converts the signal list to the new ``{name: 1.0}`` dict and returns
    ``(score, verdict)`` matching the previous return type.
    """
    features = {s: 1.0 for s in signals}
    result = compute_confidence(features)
    return result.score, result.verdict
