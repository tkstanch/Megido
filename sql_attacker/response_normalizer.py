"""
Response Normalization and Confidence Scoring Utilities

Provides helpers for:
- Stripping volatile tokens (timestamps, CSRF tokens, request IDs, …) from
  HTTP response bodies so that baseline vs. injected response diffs are
  meaningful.
- Computing a confidence score for a potential SQL injection finding by
  requiring at least two corroborating signals.
- Time-based confirmation helpers that are bounded and retry-based to reduce
  flakiness.
"""

import re
import time
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response normalisation
# ---------------------------------------------------------------------------

# Patterns for common volatile tokens found in web responses.
_VOLATILE_PATTERNS: List[Tuple[str, str]] = [
    # ISO-8601 / RFC-2822 timestamps
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TIMESTAMP>"),
    # UUID / GUID – must come before the generic EPOCH / HEX patterns
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>"),
    # Unix epoch integers (10-13 digit numbers)
    (r"\b\d{10,13}\b", "<EPOCH>"),
    # Hexadecimal tokens (16+ hex chars – CSRF tokens, nonces, …)
    (r"\b[0-9a-fA-F]{16,}\b", "<HEX_TOKEN>"),
    # Request/trace/correlation IDs in common header-value formats
    (r'(?i)(x-request-id|x-trace-id|x-correlation-id)["\s:]+[^\s"<>]+', "<REQUEST_ID>"),
    # Session cookies / JWT-like base64 blobs
    (r"[A-Za-z0-9+/]{32,}={0,2}", "<B64_TOKEN>"),
]

_COMPILED_VOLATILE: List[Tuple[re.Pattern, str]] = [
    (re.compile(pat), repl) for pat, repl in _VOLATILE_PATTERNS
]


def normalize_response(text: str) -> str:
    """
    Return a version of *text* with volatile tokens replaced by stable
    placeholders so that two responses can be meaningfully compared.
    """
    for pattern, replacement in _COMPILED_VOLATILE:
        text = pattern.sub(replacement, text)
    return text


def diff_responses(baseline: str, candidate: str) -> Dict[str, Any]:
    """
    Compare two (possibly normalised) response bodies and return a summary
    describing what changed.

    Returns a dict with keys:
        ``ratio``       – SequenceMatcher similarity ratio (1.0 = identical).
        ``changed``     – True when the responses differ meaningfully.
        ``length_delta``– Character-count difference (candidate - baseline).
        ``summary``     – Short human-readable description of the change.
    """
    baseline_norm = normalize_response(baseline)
    candidate_norm = normalize_response(candidate)

    ratio = SequenceMatcher(None, baseline_norm, candidate_norm).ratio()
    length_delta = len(candidate) - len(baseline)
    changed = ratio < 0.98

    if not changed:
        summary = "Responses are effectively identical after normalisation."
    elif ratio < 0.5:
        summary = f"Substantial difference detected (similarity={ratio:.2f}, Δlen={length_delta:+d})."
    else:
        summary = f"Minor difference detected (similarity={ratio:.2f}, Δlen={length_delta:+d})."

    return {
        "ratio": ratio,
        "changed": changed,
        "length_delta": length_delta,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

class Signal:
    """Named constants for individual detection signals."""

    SQL_ERROR = "sql_error"
    RESPONSE_ANOMALY = "response_anomaly"
    TIME_DELAY = "time_delay"
    BOOLEAN_DIFF = "boolean_diff"
    HTTP_ERROR_CODE = "http_error_code"
    JS_ERROR = "js_error"
    CONTENT_CHANGE = "content_change"


# Weights assigned to each signal type.
_SIGNAL_WEIGHTS: Dict[str, float] = {
    Signal.SQL_ERROR: 0.9,
    Signal.TIME_DELAY: 0.8,
    Signal.BOOLEAN_DIFF: 0.75,
    Signal.CONTENT_CHANGE: 0.6,
    Signal.RESPONSE_ANOMALY: 0.55,
    Signal.HTTP_ERROR_CODE: 0.5,
    Signal.JS_ERROR: 0.5,
}

# Minimum number of distinct signals required to call a finding *confirmed*.
MIN_CORROBORATING_SIGNALS = 2


def compute_confidence(signals: List[str]) -> Tuple[float, str]:
    """
    Compute a confidence score from a list of detected signal names.

    A finding requires **at least** :data:`MIN_CORROBORATING_SIGNALS`
    distinct signal types to be considered ``"confirmed"``.

    Args:
        signals: List of signal name strings (duplicates are deduplicated).

    Returns:
        A tuple ``(score, verdict)`` where *score* is a float in ``[0, 1]``
        and *verdict* is one of ``"confirmed"``, ``"likely"``, or
        ``"uncertain"``.
    """
    unique_signals = list(dict.fromkeys(signals))  # deduplicate, preserve order
    if not unique_signals:
        return 0.0, "uncertain"

    weights = [_SIGNAL_WEIGHTS.get(s, 0.3) for s in unique_signals]
    # Combined score: 1 − ∏(1 − wᵢ)  (probability union assuming independence)
    score = 1.0
    for w in weights:
        score *= 1.0 - w
    score = round(1.0 - score, 4)

    n = len(unique_signals)
    if n >= MIN_CORROBORATING_SIGNALS and score >= 0.7:
        verdict = "confirmed"
    elif n >= 1 and score >= 0.5:
        verdict = "likely"
    else:
        verdict = "uncertain"

    return score, verdict


# ---------------------------------------------------------------------------
# Time-based confirmation helpers
# ---------------------------------------------------------------------------

def confirm_time_based(
    probe_fn,
    sleep_seconds: float = 5.0,
    retries: int = 3,
    tolerance: float = 0.8,
) -> bool:
    """
    Call *probe_fn()* up to *retries* times and return True if the measured
    elapsed time is consistently close to *sleep_seconds*.

    This reduces flakiness compared to a single measurement by requiring the
    delay to appear in at least two out of *retries* attempts.

    Args:
        probe_fn: Zero-argument callable that triggers the time-based payload
            and returns the HTTP response (return value is ignored; only the
            elapsed wall-clock time matters).
        sleep_seconds: Expected server-side delay in seconds.
        retries: How many times to repeat the probe.
        tolerance: Fraction of *sleep_seconds* that the measured delay must
            meet (e.g. 0.8 means ≥4 s for a 5 s probe).

    Returns:
        True if at least ``ceil(retries / 2)`` probes confirmed the delay.
    """
    import math

    threshold = sleep_seconds * tolerance
    confirmed_count = 0
    required = math.ceil(retries / 2)

    for attempt in range(1, retries + 1):
        t0 = time.monotonic()
        try:
            probe_fn()
        except Exception as exc:
            logger.debug("Time-based probe attempt %d raised: %s", attempt, exc)
        elapsed = time.monotonic() - t0
        logger.debug(
            "Time-based probe attempt %d: elapsed=%.2fs threshold=%.2fs",
            attempt,
            elapsed,
            threshold,
        )
        if elapsed >= threshold:
            confirmed_count += 1
        if confirmed_count >= required:
            logger.info(
                "Time-based injection confirmed after %d/%d probes ≥ %.1fs",
                confirmed_count,
                attempt,
                threshold,
            )
            return True

    logger.info(
        "Time-based injection NOT confirmed: only %d/%d probes met threshold",
        confirmed_count,
        retries,
    )
    return False
