"""
HTTP Transport Utilities for Megido SQL Attacker

Provides centralized response classification, adaptive backoff, and circuit-breaker
logic for responsible authorized security testing.

Outcome values:
  ALLOWED          - Request succeeded and was processed normally.
  BLOCKED          - Request was explicitly blocked (403/406 or block-page body markers).
  RATE_LIMITED     - Server signalled too many requests (429 or Retry-After header).
  CHALLENGE        - A CAPTCHA / JS-challenge page was detected (e.g. Cloudflare).
  AUTH_REQUIRED    - Authentication is required (401 / login page redirect).
  TRANSIENT_ERROR  - Temporary network/server error (5xx, connection failure).
"""

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# Outcome constants
ALLOWED = "ALLOWED"
BLOCKED = "BLOCKED"
RATE_LIMITED = "RATE_LIMITED"
CHALLENGE = "CHALLENGE"
AUTH_REQUIRED = "AUTH_REQUIRED"
TRANSIENT_ERROR = "TRANSIENT_ERROR"

# Title / body markers grouped by outcome
_BLOCK_BODY_MARKERS: List[str] = [
    "access denied",
    "request blocked",
    "blocked by",
    "your request has been blocked",
    "this page isn't working",
    "security policy",
    "forbidden",
    "you have been blocked",
    "403 forbidden",
    "406 not acceptable",
    # Akamai / Edgesuite
    "reference #",
    "akamai ghost",
    "ghost error",
    # Imperva / Incapsula
    "incapsula incident",
    "powered by incapsula",
    # AWS WAF
    "aws waf",
    "sorry, you have been blocked",
]

_CHALLENGE_BODY_MARKERS: List[str] = [
    # Cloudflare
    "checking your browser",
    "cloudflare ray id",
    "cf-ray",
    "ddos protection by cloudflare",
    "please wait while",
    # Generic JS challenge
    "enable javascript",
    "javascript required",
    "please complete the security check",
    "recaptcha",
    "g-recaptcha",
    "hcaptcha",
    "turnstile",
]

_AUTH_BODY_MARKERS: List[str] = [
    "login required",
    "please log in",
    "sign in to continue",
    "authentication required",
    "401 unauthorized",
    "you must be logged in",
]

_RATE_LIMIT_BODY_MARKERS: List[str] = [
    "rate limit",
    "too many requests",
    "slow down",
    "request limit exceeded",
]

# Header markers to identify vendor
_VENDOR_HEADER_PATTERNS: List[Tuple[str, str, str]] = [
    # (header_name, pattern, vendor_name)
    ("server", r"akamai|akamaighost|edgesuite", "akamai"),
    ("server", r"cloudflare", "cloudflare"),
    ("server", r"imperva|incapsula", "imperva"),
    ("x-powered-by", r"imperva|incapsula", "imperva"),
    ("x-cdn", r"incapsula", "imperva"),
    ("cf-ray", r".*", "cloudflare"),
    ("x-amzn-requestid", r".*", "aws_waf"),
    ("x-amz-cf-id", r".*", "aws_waf"),
    ("x-cache", r"Error from cloudfront", "aws_waf"),
    ("server", r"awselb|aws", "aws_waf"),
    ("server", r"sucuri", "sucuri"),
    ("x-sucuri-id", r".*", "sucuri"),
    ("server", r"barracuda", "barracuda"),
    ("server", r"f5", "f5"),
]


@dataclass
class Classification:
    """Structured result of a response classification."""

    outcome: str
    vendor: Optional[str] = None
    reason: str = ""
    evidence: Dict = field(default_factory=dict)


def classify_response(response: Optional[requests.Response]) -> Classification:
    """
    Classify an HTTP response to determine whether access was allowed, blocked,
    rate-limited, challenged, etc.

    Args:
        response: A ``requests.Response`` object, or ``None`` for connection errors.

    Returns:
        A :class:`Classification` instance.
    """
    if response is None:
        return Classification(
            outcome=TRANSIENT_ERROR,
            reason="No response received (connection error or timeout)",
            evidence={"status_code": None},
        )

    status = response.status_code

    # Collect a small body snippet (case-insensitive comparisons later)
    try:
        body_snippet = response.text[:2000]
    except Exception:
        body_snippet = ""

    body_lower = body_snippet.lower()

    # Detect vendor from headers
    vendor = _detect_vendor(response)

    # -----------------------------------------------------------------------
    # Status-code based routing (fast path)
    # -----------------------------------------------------------------------
    if status == 429:
        retry_after = response.headers.get("Retry-After")
        return Classification(
            outcome=RATE_LIMITED,
            vendor=vendor,
            reason=f"HTTP 429 Too Many Requests (Retry-After: {retry_after})",
            evidence={
                "status_code": status,
                "retry_after": retry_after,
                "server": response.headers.get("server"),
            },
        )

    if status == 401:
        return Classification(
            outcome=AUTH_REQUIRED,
            vendor=vendor,
            reason="HTTP 401 Unauthorized",
            evidence={
                "status_code": status,
                "www_authenticate": response.headers.get("www-authenticate"),
            },
        )

    if status in (403, 406):
        outcome, reason, marker = _classify_block_or_challenge(body_lower, status)
        return Classification(
            outcome=outcome,
            vendor=vendor,
            reason=reason,
            evidence={
                "status_code": status,
                "matched_marker": marker,
                "snippet": body_snippet[:300],
                "server": response.headers.get("server"),
            },
        )

    if status in (503, 502, 504):
        # Could be a WAF block page or genuine transient error
        outcome, reason, marker = _classify_block_or_challenge(body_lower, status)
        if outcome == ALLOWED:
            outcome = TRANSIENT_ERROR
            reason = f"HTTP {status} transient server error"
        return Classification(
            outcome=outcome,
            vendor=vendor,
            reason=reason,
            evidence={
                "status_code": status,
                "matched_marker": marker,
                "snippet": body_snippet[:300],
            },
        )

    if status >= 500:
        return Classification(
            outcome=TRANSIENT_ERROR,
            vendor=vendor,
            reason=f"HTTP {status} server error",
            evidence={"status_code": status},
        )

    # -----------------------------------------------------------------------
    # 2xx / 3xx: inspect body for soft-block / challenge pages
    # -----------------------------------------------------------------------
    outcome, reason, marker = _classify_block_or_challenge(body_lower, status)
    if outcome != ALLOWED:
        return Classification(
            outcome=outcome,
            vendor=vendor,
            reason=reason,
            evidence={
                "status_code": status,
                "matched_marker": marker,
                "snippet": body_snippet[:300],
                "server": response.headers.get("server"),
            },
        )

    return Classification(
        outcome=ALLOWED,
        vendor=vendor,
        reason="Request allowed",
        evidence={"status_code": status},
    )


def _detect_vendor(response: requests.Response) -> Optional[str]:
    """Detect WAF/CDN vendor from response headers."""
    for header_name, pattern, vendor in _VENDOR_HEADER_PATTERNS:
        value = response.headers.get(header_name, "")
        if value and re.search(pattern, value, re.IGNORECASE):
            return vendor
    return None


def _classify_block_or_challenge(
    body_lower: str, status: int
) -> Tuple[str, str, Optional[str]]:
    """
    Inspect body text for block / challenge / rate-limit / auth markers.

    Returns (outcome, reason, matched_marker).
    """
    for marker in _RATE_LIMIT_BODY_MARKERS:
        if marker in body_lower:
            return RATE_LIMITED, f"Rate-limit body marker: '{marker}'", marker

    for marker in _AUTH_BODY_MARKERS:
        if marker in body_lower:
            return AUTH_REQUIRED, f"Auth-required body marker: '{marker}'", marker

    for marker in _CHALLENGE_BODY_MARKERS:
        if marker in body_lower:
            return CHALLENGE, f"Challenge page body marker: '{marker}'", marker

    for marker in _BLOCK_BODY_MARKERS:
        if marker in body_lower:
            return BLOCKED, f"Block page body marker: '{marker}'", marker

    return ALLOWED, "", None


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """
    Simple per-host/endpoint circuit breaker.

    After ``threshold`` consecutive BLOCKED or CHALLENGE outcomes the circuit
    opens and further calls raise :class:`CircuitOpenError`.  It resets when
    ``reset_after`` seconds have elapsed (half-open state).

    Args:
        threshold: Number of consecutive adverse outcomes before opening.
        reset_after: Seconds to wait before resetting an open circuit.
        trip_on: Set of outcome strings that count as adverse.
    """

    def __init__(
        self,
        threshold: int = 5,
        reset_after: float = 60.0,
        trip_on: Optional[set] = None,
    ):
        self.threshold = threshold
        self.reset_after = reset_after
        self.trip_on = trip_on if trip_on is not None else {BLOCKED, CHALLENGE}
        self._counts: Dict[str, int] = {}
        self._open_since: Dict[str, float] = {}

    def record(self, key: str, outcome: str) -> None:
        """Record an outcome for *key*.  Resets counter on ALLOWED."""
        # Auto-reset if enough time has passed
        if key in self._open_since:
            if time.monotonic() - self._open_since[key] >= self.reset_after:
                logger.info(f"Circuit breaker for '{key}' reset after timeout.")
                del self._open_since[key]
                self._counts[key] = 0

        if outcome in self.trip_on:
            self._counts[key] = self._counts.get(key, 0) + 1
            if self._counts[key] >= self.threshold:
                if key not in self._open_since:
                    self._open_since[key] = time.monotonic()
                    logger.warning(
                        f"Circuit breaker OPEN for '{key}' after "
                        f"{self._counts[key]} consecutive {outcome} outcomes."
                    )
        else:
            # Any non-adverse outcome resets the counter
            self._counts[key] = 0

    def is_open(self, key: str) -> bool:
        """Return True if the circuit is currently open for *key*."""
        if key not in self._open_since:
            return False
        if time.monotonic() - self._open_since[key] >= self.reset_after:
            logger.info(f"Circuit breaker for '{key}' reset after timeout.")
            del self._open_since[key]
            self._counts[key] = 0
            return False
        return True

    def consecutive_count(self, key: str) -> int:
        """Return current consecutive adverse-outcome count for *key*."""
        return self._counts.get(key, 0)


class CircuitOpenError(Exception):
    """Raised when a request is attempted while the circuit breaker is open."""

    def __init__(self, key: str):
        self.key = key
        super().__init__(
            f"Circuit breaker is open for '{key}'. Aborting further tests."
        )


# ---------------------------------------------------------------------------
# Adaptive Backoff
# ---------------------------------------------------------------------------

def compute_backoff(attempt: int, base: float = 1.0, cap: float = 60.0) -> float:
    """
    Compute exponential back-off delay with optional cap.

    Args:
        attempt: Zero-based retry attempt number.
        base: Base delay in seconds.
        cap: Maximum delay in seconds.

    Returns:
        Delay in seconds.
    """
    delay = min(base * (2 ** attempt), cap)
    return delay


def get_retry_after(response: Optional[requests.Response], default: float = 5.0) -> float:
    """
    Parse the ``Retry-After`` header from a response.

    Args:
        response: HTTP response (may be None).
        default: Fallback delay when the header is absent or unparseable.

    Returns:
        Seconds to wait.
    """
    if response is None:
        return default
    header = response.headers.get("Retry-After")
    if header is None:
        return default
    try:
        return float(header)
    except ValueError:
        pass
    # RFC 7231 allows HTTP-date format; approximate with default
    return default
