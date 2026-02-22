"""
sql_attacker.engine – Focused sub-modules for the SQL injection testing engine.

Sub-modules
-----------
normalization  – Response normalisation utilities (HTML stripping, token scrubbing,
                 stable fingerprints).
baseline       – Multi-sample baseline collection, median/IQR timing statistics,
                 canary-set scheduling, and baseline caching.
scoring        – Confidence scoring with per-feature contribution breakdown.
"""

from .normalization import (
    strip_html,
    normalize_whitespace,
    scrub_dynamic_tokens,
    normalize_response_body,
    fingerprint,
)
from .baseline import (
    BaselineResult,
    BaselineCollector,
    BaselineCache,
    CanaryScheduler,
)
from .scoring import (
    FeatureContribution,
    ScoringResult,
    compute_confidence,
)

__all__ = [
    # normalization
    "strip_html",
    "normalize_whitespace",
    "scrub_dynamic_tokens",
    "normalize_response_body",
    "fingerprint",
    # baseline
    "BaselineResult",
    "BaselineCollector",
    "BaselineCache",
    "CanaryScheduler",
    # scoring
    "FeatureContribution",
    "ScoringResult",
    "compute_confidence",
]
