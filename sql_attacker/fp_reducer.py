"""
False Positive Reducer for SQL Injection findings.

Scores each SQLInjectionResult for false-positive likelihood using a set of
heuristic signals.  A score of 0.0 means the finding is almost certainly real;
a score of 1.0 means it is almost certainly a false positive.

Auto-marks findings with fp_score > 0.85 as ``likely_false_positive``.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal weights (must sum to 1.0 for a normalised score)
# ---------------------------------------------------------------------------
_WEIGHT_WAF_TRIGGER = 0.20
_WEIGHT_GENERIC_ERROR_PAGE = 0.20
_WEIGHT_LOW_CONFIDENCE = 0.20
_WEIGHT_DUPLICATE_PAYLOAD = 0.15
_WEIGHT_RESPONSE_SIMILARITY = 0.25

# Generic WAF / security device error strings that indicate a false trigger
_WAF_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"access denied",
        r"forbidden by (security|waf|policy)",
        r"request blocked",
        r"suspicious activity",
        r"security violation",
        r"mod_security",
        r"cloudflare.*ray id",
        r"incapsula incident",
        r"akamai.*reference",
    ]
]

# Generic error pages that are NOT useful SQL error evidence
_GENERIC_ERROR_PAGE_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"<title>\s*(404|403|500|503|400)\s*</title>",
        r"page not found",
        r"internal server error",
        r"service unavailable",
        r"the page you requested does not exist",
    ]
]

# Threshold above which a finding is considered likely FP
_FP_THRESHOLD = 0.85


class FalsePositiveReducer:
    """Analyse a SQLInjectionResult and produce an FP score with explanations.

    Usage::

        reducer = FalsePositiveReducer()
        indicators = reducer.analyse(result)
        # indicators['fp_score'] is between 0.0 and 1.0
        # indicators['fp_indicators'] is a list of human-readable reason strings
    """

    def __init__(
        self,
        confidence_threshold: float = 0.65,
        fp_threshold: float = _FP_THRESHOLD,
    ):
        self._confidence_threshold = confidence_threshold
        self._fp_threshold = fp_threshold
        self._seen_payloads: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self, result: Any) -> Dict[str, Any]:
        """Analyse a single SQLInjectionResult-like object.

        Args:
            result: A SQLInjectionResult model instance (or any object with the
                    same attributes used below).

        Returns:
            A dict with:
            - ``fp_score`` (float, 0.0–1.0)
            - ``fp_indicators`` (list of str)
            - ``likely_false_positive`` (bool, True when fp_score > 0.85)
        """
        indicators: List[str] = []
        weighted_score = 0.0

        # 1. WAF false-trigger detection
        waf_signal = self._check_waf_trigger(result)
        if waf_signal:
            weighted_score += _WEIGHT_WAF_TRIGGER
            indicators.append(f"WAF/security-device response detected: {waf_signal}")

        # 2. Generic error page detection
        generic_signal = self._check_generic_error_page(result)
        if generic_signal:
            weighted_score += _WEIGHT_GENERIC_ERROR_PAGE
            indicators.append(f"Generic error page detected: {generic_signal}")

        # 3. Low confidence score
        conf_penalty = self._check_low_confidence(result)
        if conf_penalty > 0:
            weighted_score += conf_penalty * _WEIGHT_LOW_CONFIDENCE
            confidence_score = getattr(result, 'confidence_score', 1.0)
            indicators.append(
                f"Below confidence threshold ({confidence_score:.2f} < {self._confidence_threshold:.2f})"
            )

        # 4. Duplicate payload detection
        dup_signal = self._check_duplicate_payload(result)
        if dup_signal:
            weighted_score += _WEIGHT_DUPLICATE_PAYLOAD
            indicators.append(f"Duplicate payload seen {dup_signal} time(s) previously")

        # 5. Response similarity – if baseline and injected responses look the same
        sim_penalty = self._check_response_similarity(result)
        if sim_penalty > 0:
            weighted_score += sim_penalty * _WEIGHT_RESPONSE_SIMILARITY
            indicators.append(
                "Injected response appears highly similar to baseline (possible false diff)"
            )

        fp_score = min(weighted_score, 1.0)
        return {
            'fp_score': round(fp_score, 4),
            'fp_indicators': indicators,
            'likely_false_positive': fp_score > self._fp_threshold,
        }

    def reset_seen_payloads(self) -> None:
        """Clear the duplicate-payload tracking state."""
        self._seen_payloads.clear()

    # ------------------------------------------------------------------
    # Private signal checkers
    # ------------------------------------------------------------------

    def _check_waf_trigger(self, result: Any) -> Optional[str]:
        """Return a short description if the response body looks like a WAF block."""
        response_data: Dict = getattr(result, 'response_data', None) or {}
        body: str = response_data.get('body_snippet', '') or ''
        detection_evidence: str = getattr(result, 'detection_evidence', '') or ''
        text = body + detection_evidence
        for pattern in _WAF_PATTERNS:
            m = pattern.search(text)
            if m:
                return m.group(0)[:60]
        return None

    def _check_generic_error_page(self, result: Any) -> Optional[str]:
        """Return a description if the response looks like a generic error page."""
        response_data: Dict = getattr(result, 'response_data', None) or {}
        body: str = response_data.get('body_snippet', '') or ''
        status_code: int = response_data.get('status_code', 200)
        # A 404/403/500 without SQL error evidence strongly suggests FP
        if status_code in (403, 404, 500, 503):
            return f"HTTP {status_code} response"
        for pattern in _GENERIC_ERROR_PAGE_PATTERNS:
            m = pattern.search(body)
            if m:
                return m.group(0)[:60]
        return None

    def _check_low_confidence(self, result: Any) -> float:
        """Return a 0–1 penalty proportional to how far below threshold confidence is."""
        confidence_score: float = getattr(result, 'confidence_score', 1.0)
        if confidence_score >= self._confidence_threshold:
            return 0.0
        # Linear penalty: 0 at threshold, 1 when confidence=0
        return 1.0 - (confidence_score / self._confidence_threshold)

    def _check_duplicate_payload(self, result: Any) -> int:
        """Track how many times the same payload has been seen; return the count if > 0."""
        payload: str = (getattr(result, 'test_payload', '') or '').strip()
        if not payload:
            return 0
        count = self._seen_payloads.get(payload, 0)
        self._seen_payloads[payload] = count + 1
        return count  # 0 on first occurrence = not a duplicate yet

    def _check_response_similarity(self, result: Any) -> float:
        """
        Return a 0–1 score for response similarity between baseline and injected.

        Uses the evidence_packet 'verdict' field if present; falls back to
        checking the detection_evidence text for any SQL error keywords.
        """
        evidence_packet: Dict = getattr(result, 'evidence_packet', None) or {}
        verdict: str = evidence_packet.get('verdict', '')

        # If the discovery scanner marked it as a genuine finding, trust that.
        if verdict in ('confirmed', 'likely'):
            return 0.0

        # No positive SQL error keywords in detection evidence ⟹ suspicious
        detection_evidence: str = getattr(result, 'detection_evidence', '') or ''
        sql_error_keywords = [
            'sql', 'syntax', 'mysql', 'oracle', 'postgresql', 'sqlite',
            'mssql', 'odbc', 'jdbc', 'error in your sql',
        ]
        evidence_lower = detection_evidence.lower()
        if not any(kw in evidence_lower for kw in sql_error_keywords):
            # If no SQL keywords present and injection type is error_based, suspicious
            injection_type: str = getattr(result, 'injection_type', '') or ''
            if injection_type == 'error_based':
                return 0.6
        return 0.0


def reduce_false_positives(results: List[Any]) -> List[Dict[str, Any]]:
    """Convenience function: run FalsePositiveReducer over a list of results.

    Returns a list of indicator dicts in the same order as the input list.
    Duplicate-payload tracking is scoped to this single call.
    """
    reducer = FalsePositiveReducer()
    return [reducer.analyse(r) for r in results]
