"""
Validation Rules Engine

Pre-report validation for vulnerability findings.

Each finding passes through a sequence of validation rules before being
marked "confirmed". Rules check:

- Response diff validation (baseline vs injected response)
- Timing validation for time-based attacks
- Callback validation for OOB attacks
- Content validation (reflected content in response)

Validation results: confirmed | likely | unconfirmed | false_positive

Usage::

    from scanner.validation_engine import ValidationEngine, ValidationStatus

    engine = ValidationEngine()
    result = engine.validate(finding)
    print(result.status, result.confidence)
"""

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums / constants
# ---------------------------------------------------------------------------

class ValidationStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCONFIRMED = "unconfirmed"
    FALSE_POSITIVE = "false_positive"


# Minimum timing difference (seconds) to consider a time-based finding valid
DEFAULT_MIN_TIMING_DELTA: float = 2.0

# Minimum response body similarity change for diff-based validation
DEFAULT_MIN_DIFF_THRESHOLD: float = 0.05


# ---------------------------------------------------------------------------
# ValidationResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Result of running all validation rules against a finding."""

    finding_id: str
    status: ValidationStatus
    confidence: float  # 0.0 – 1.0

    # Individual rule results
    rule_results: Dict[str, Any] = field(default_factory=dict)

    # Human-readable explanation
    summary: str = ""

    # Set to True if this result should override any prior status
    is_definitive: bool = False


# ---------------------------------------------------------------------------
# Validation rule type alias
# ---------------------------------------------------------------------------

# A rule takes a finding dict and returns (passed: bool, score_delta: float, note: str)
ValidationRule = Callable[[Dict[str, Any]], Tuple[bool, float, str]]


# ---------------------------------------------------------------------------
# Built-in validation rules
# ---------------------------------------------------------------------------

def _rule_response_diff(finding: Dict[str, Any]) -> Tuple[bool, float, str]:
    """
    Compare baseline response vs injected response.

    Passes if the response body changed enough to indicate a reflection or
    error triggered by the payload.
    """
    baseline = finding.get("baseline_response_body", "")
    injected = finding.get("response_body", "")

    if not baseline or not injected:
        return False, 0.0, "No baseline/injected response available"

    if len(baseline) == 0:
        return False, 0.0, "Empty baseline response"

    # Simple length-based diff ratio
    len_diff = abs(len(injected) - len(baseline)) / max(len(baseline), 1)

    # Count distinct lines that changed
    baseline_lines = set(baseline.splitlines())
    injected_lines = set(injected.splitlines())
    new_lines = injected_lines - baseline_lines
    pct_new = len(new_lines) / max(len(baseline_lines), 1)

    diff_score = max(len_diff, pct_new)

    if diff_score >= DEFAULT_MIN_DIFF_THRESHOLD:
        return True, 0.15, f"Response changed by {diff_score:.1%}"
    return False, 0.0, f"Insufficient response change ({diff_score:.1%})"


def _rule_timing_validation(finding: Dict[str, Any]) -> Tuple[bool, float, str]:
    """
    Verify that a time-based payload caused a measurable delay.
    """
    is_time_based = finding.get("is_time_based") or "time" in str(finding.get("technique", "")).lower()
    if not is_time_based:
        return True, 0.0, "Not a time-based attack — rule skipped"

    response_time = float(finding.get("response_time", 0))
    baseline_time = float(finding.get("baseline_response_time", 0))
    expected_delay = float(finding.get("expected_delay", 5.0))

    actual_delta = response_time - baseline_time

    if actual_delta >= expected_delay * 0.8:
        return True, 0.25, f"Timing confirmed: delta={actual_delta:.1f}s (expected {expected_delay:.1f}s)"
    return False, -0.1, f"Timing not confirmed: delta={actual_delta:.1f}s (expected {expected_delay:.1f}s)"


def _rule_callback_validation(finding: Dict[str, Any]) -> Tuple[bool, float, str]:
    """
    Verify that an OOB (out-of-band) callback was received.
    """
    is_oob = finding.get("is_oob") or "oob" in str(finding.get("technique", "")).lower()
    if not is_oob:
        return True, 0.0, "Not an OOB attack — rule skipped"

    callback_received = finding.get("callback_received") or finding.get("oob_callback_received")
    if callback_received:
        return True, 0.30, "OOB callback confirmed"
    return False, -0.15, "OOB callback not received"


def _rule_content_reflection(finding: Dict[str, Any]) -> Tuple[bool, float, str]:
    """
    Verify that the injected payload (or a transformation of it) appears in
    the response body.
    """
    payload = str(finding.get("payload") or finding.get("injected_payload") or "")
    response_body = str(finding.get("response_body") or "")

    if not payload or not response_body:
        return False, 0.0, "No payload or response body to check"

    # Check raw reflection
    if payload in response_body:
        return True, 0.20, "Payload reflected verbatim in response"

    # Check partial reflection (first 20 chars of payload)
    snippet = payload[:20]
    if snippet and snippet in response_body:
        return True, 0.10, f"Partial payload reflection ({snippet!r})"

    return False, 0.0, "Payload not reflected in response"


def _rule_http_status_check(finding: Dict[str, Any]) -> Tuple[bool, float, str]:
    """
    Accept findings where the response status code indicates a server-side
    change (non-200 in baseline becoming 200, or 500 errors triggered).
    """
    status = int(finding.get("response_status_code", 0))
    baseline_status = int(finding.get("baseline_status_code", 200))

    if status == 500 and baseline_status != 500:
        return True, 0.10, "Server returned 500 after injection (potential error-based SQLi / injection)"
    if status == 200 and baseline_status in (401, 403):
        return True, 0.20, "Authentication bypass: 200 response where 401/403 was expected"
    return True, 0.0, f"HTTP status {status} (baseline {baseline_status})"


# ---------------------------------------------------------------------------
# Default rule set
# ---------------------------------------------------------------------------

DEFAULT_RULES: List[ValidationRule] = [
    _rule_response_diff,
    _rule_timing_validation,
    _rule_callback_validation,
    _rule_content_reflection,
    _rule_http_status_check,
]


# ---------------------------------------------------------------------------
# ValidationEngine
# ---------------------------------------------------------------------------

class ValidationEngine:
    """
    Runs validation rules against findings and assigns a ``ValidationStatus``.

    Parameters
    ----------
    rules:
        List of validation rule callables.  Defaults to ``DEFAULT_RULES``.
    confirmed_threshold:
        Minimum accumulated confidence to reach ``CONFIRMED`` status.
    likely_threshold:
        Minimum accumulated confidence to reach ``LIKELY`` status.
    base_confidence:
        Starting confidence from the finding's own ``confidence`` field.
    """

    def __init__(
        self,
        rules: Optional[List[ValidationRule]] = None,
        confirmed_threshold: float = 0.70,
        likely_threshold: float = 0.45,
        base_confidence: float = 0.50,
    ) -> None:
        self._rules = rules if rules is not None else list(DEFAULT_RULES)
        self._confirmed_threshold = confirmed_threshold
        self._likely_threshold = likely_threshold
        self._base_confidence = base_confidence

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Run all validation rules against *finding* and return a result.
        """
        finding_id = finding.get("id") or finding.get("finding_id") or str(id(finding))

        # Start from the finding's own confidence score
        confidence = float(finding.get("confidence", self._base_confidence))
        rule_results: Dict[str, Any] = {}
        notes: List[str] = []

        for rule in self._rules:
            try:
                passed, delta, note = rule(finding)
                rule_results[rule.__name__] = {
                    "passed": passed,
                    "score_delta": delta,
                    "note": note,
                }
                confidence += delta
                notes.append(note)
            except Exception as exc:
                logger.warning("Validation rule %s raised: %s", rule.__name__, exc)
                rule_results[rule.__name__] = {"error": str(exc)}

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        status = self._assign_status(finding, confidence)

        return ValidationResult(
            finding_id=finding_id,
            status=status,
            confidence=confidence,
            rule_results=rule_results,
            summary="; ".join(n for n in notes if n),
        )

    def validate_batch(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[ValidationResult]:
        """Validate a list of findings."""
        return [self.validate(f) for f in findings]

    def add_rule(self, rule: ValidationRule) -> None:
        """Add a custom validation rule."""
        self._rules.append(rule)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _assign_status(
        self,
        finding: Dict[str, Any],
        confidence: float,
    ) -> ValidationStatus:
        # Explicit false positive markers take precedence
        if finding.get("is_false_positive"):
            return ValidationStatus.FALSE_POSITIVE

        if confidence >= self._confirmed_threshold:
            return ValidationStatus.CONFIRMED
        if confidence >= self._likely_threshold:
            return ValidationStatus.LIKELY
        if confidence > 0.15:
            return ValidationStatus.UNCONFIRMED
        return ValidationStatus.FALSE_POSITIVE
