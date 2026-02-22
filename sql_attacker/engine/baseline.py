"""
Multi-sample Baseline Collection and Canary-set Scheduling
===========================================================

BaselineResult   – Immutable snapshot: median/IQR response time + body signature.
BaselineCollector – Sends N benign requests to a target and derives a BaselineResult.
BaselineCache    – Thread-safe LRU cache keyed on (url, method, header/cookie
                   fingerprint) so repeated scans don't generate redundant traffic.
CanaryScheduler  – Returns an ordered list of payloads, starting with a small "canary
                   set" of high-signal probes; callers escalate to the full list only
                   when canary signals appear.

Confirmation loop
-----------------
``confirm_finding`` re-tests a candidate finding, also sends a benign control
mutation, and returns True only when evidence is consistent across repetitions.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _median(values: List[float]) -> float:
    """Return the median of a non-empty list of floats."""
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    mid = n // 2
    if n % 2 == 0:
        return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0
    return sorted_vals[mid]


def _iqr(values: List[float]) -> float:
    """Return the inter-quartile range (IQR) of a list of floats."""
    if len(values) < 2:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    q1_idx = n // 4
    q3_idx = (3 * n) // 4
    return sorted_vals[q3_idx] - sorted_vals[q1_idx]


# ---------------------------------------------------------------------------
# BaselineResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineResult:
    """Immutable statistical summary of N benign baseline responses.

    Attributes
    ----------
    median_time:  Median response time in seconds across the N samples.
    iqr_time:     Inter-quartile range of response times.
    body_signature: Stable hex fingerprint of the normalised response body
                    (built from the *most common* body across samples).
    sample_count: Number of samples collected.
    """

    median_time: float
    iqr_time: float
    body_signature: str
    sample_count: int


# ---------------------------------------------------------------------------
# BaselineCollector
# ---------------------------------------------------------------------------


class BaselineCollector:
    """Collect *n_samples* benign responses and return a :class:`BaselineResult`.

    Parameters
    ----------
    request_fn:
        Callable ``(url, method, params, data, cookies, headers) -> response``
        that performs a single HTTP request and returns an object with
        ``.elapsed.total_seconds()`` and ``.text`` attributes (compatible with
        ``requests.Response``).  Returns ``None`` on failure.
    normalise_fn:
        Optional callable ``(body: str) -> str`` applied to the response body
        before fingerprinting.  Defaults to the standard pipeline from
        ``engine.normalization``.
    n_samples:
        Number of baseline requests to send (default: 3).
    """

    def __init__(
        self,
        request_fn: Callable,
        normalise_fn: Optional[Callable[[str], str]] = None,
        n_samples: int = 3,
    ) -> None:
        if normalise_fn is None:
            from .normalization import normalize_response_body
            normalise_fn = normalize_response_body
        self._request_fn = request_fn
        self._normalise_fn = normalise_fn
        self._n_samples = max(1, n_samples)

    def collect(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> Optional[BaselineResult]:
        """Send ``n_samples`` requests and return a :class:`BaselineResult`.

        Returns ``None`` if no successful responses were obtained.
        """
        times: List[float] = []
        bodies: List[str] = []

        for i in range(self._n_samples):
            response = self._request_fn(url, method, params, data, cookies, headers)
            if response is None:
                logger.debug("Baseline sample %d/%d: no response", i + 1, self._n_samples)
                continue
            try:
                elapsed = response.elapsed.total_seconds()
            except Exception:
                elapsed = 0.0
            try:
                body = response.text
            except Exception:
                body = ""
            times.append(elapsed)
            bodies.append(self._normalise_fn(body))
            logger.debug(
                "Baseline sample %d/%d: elapsed=%.3fs body_len=%d",
                i + 1,
                self._n_samples,
                elapsed,
                len(body),
            )

        if not times:
            logger.warning("BaselineCollector: no usable samples collected for %s", url)
            return None

        median_t = _median(times)
        iqr_t = _iqr(times)

        # Pick the most common body fingerprint as the stable signature
        from collections import Counter
        body_fp_counter = Counter(
            hashlib.sha256(b.encode("utf-8", errors="replace")).hexdigest()[:16]
            for b in bodies
        )
        body_sig = body_fp_counter.most_common(1)[0][0]

        result = BaselineResult(
            median_time=round(median_t, 4),
            iqr_time=round(iqr_t, 4),
            body_signature=body_sig,
            sample_count=len(times),
        )
        logger.info(
            "Baseline for %s: median=%.3fs iqr=%.3fs sig=%s (n=%d)",
            url,
            result.median_time,
            result.iqr_time,
            result.body_signature,
            result.sample_count,
        )
        return result


# ---------------------------------------------------------------------------
# BaselineCache
# ---------------------------------------------------------------------------


def _cache_key(url: str, method: str, headers: Optional[Dict], cookies: Optional[Dict]) -> str:
    """Build a stable cache key from request parameters."""
    parts = [url.lower(), method.upper()]
    if headers:
        parts.append(
            ",".join(f"{k.lower()}={v}" for k, v in sorted(headers.items()))
        )
    if cookies:
        parts.append(
            ",".join(f"{k}={v}" for k, v in sorted(cookies.items()))
        )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


class BaselineCache:
    """Thread-safe cache for :class:`BaselineResult` objects.

    Entries expire after *ttl_seconds* (default: 300 s / 5 min).

    Parameters
    ----------
    ttl_seconds: How long a cached baseline remains valid.
    max_entries:  Maximum cache size (oldest entries are evicted first).
    """

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 256) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._store: Dict[str, Tuple[BaselineResult, float]] = {}
        self._lock = threading.Lock()

    def get(
        self,
        url: str,
        method: str,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
    ) -> Optional[BaselineResult]:
        """Return the cached baseline, or ``None`` if missing / expired."""
        key = _cache_key(url, method, headers, cookies)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            result, ts = entry
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            return result

    def put(
        self,
        url: str,
        method: str,
        result: BaselineResult,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
    ) -> None:
        """Store a baseline result."""
        key = _cache_key(url, method, headers, cookies)
        with self._lock:
            # Evict oldest entry if at capacity
            if len(self._store) >= self._max and key not in self._store:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
            self._store[key] = (result, time.monotonic())

    def invalidate(
        self,
        url: str,
        method: str,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
    ) -> None:
        """Remove a specific entry from the cache."""
        key = _cache_key(url, method, headers, cookies)
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._store.clear()


# ---------------------------------------------------------------------------
# CanaryScheduler
# ---------------------------------------------------------------------------

# A small set of high-signal "canary" payloads used as the first probe round.
# These are chosen because they are low-noise and broad-spectrum.
_DEFAULT_CANARY_PAYLOADS: List[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
]


class CanaryScheduler:
    """Order payloads so that a small canary set is tried first.

    If any canary payload produces a signal, the caller escalates to the full
    payload list.  This reduces unnecessary requests when targets are not
    vulnerable.

    Parameters
    ----------
    canary_payloads:
        Short list of high-signal probes to run first.  Defaults to
        :data:`_DEFAULT_CANARY_PAYLOADS`.
    """

    def __init__(
        self,
        canary_payloads: Optional[List[str]] = None,
    ) -> None:
        self._canary = list(canary_payloads or _DEFAULT_CANARY_PAYLOADS)

    @property
    def canary_payloads(self) -> List[str]:
        """Return the canary payload list."""
        return list(self._canary)

    def schedule(self, full_payloads: List[str]) -> Tuple[List[str], List[str]]:
        """Return ``(canary_set, remainder)`` where *canary_set* comes first and
        the canary payloads are de-duplicated from *remainder*.

        Args:
            full_payloads: Complete list of payloads for a parameter test.

        Returns:
            Tuple of *(canary_set, remainder)*.  The caller should try the
            canary set first, and only proceed to *remainder* if a signal is
            detected.
        """
        canary_set = list(self._canary)
        remainder = [p for p in full_payloads if p not in set(self._canary)]
        return canary_set, remainder


# ---------------------------------------------------------------------------
# Confirmation loop
# ---------------------------------------------------------------------------


def confirm_finding(
    test_fn: Callable[[], Optional[Any]],
    benign_fn: Callable[[], Optional[Any]],
    detect_fn: Callable[[Any], bool],
    repetitions: int = 2,
) -> Tuple[bool, str]:
    """Re-test a candidate finding and send a benign control mutation.

    A finding is *confirmed* only when:
    - The injection payload triggers the detection signal in at least
      ``ceil(repetitions / 2)`` out of ``repetitions`` retests, **and**
    - The benign control does **not** trigger the detection signal.

    This prevents non-repeatable anomalies and baseline drift from being
    escalated to high-confidence findings.

    Parameters
    ----------
    test_fn:
        Zero-argument callable that sends the injected payload and returns a
        response (or None on failure).
    benign_fn:
        Zero-argument callable that sends a benign variant (e.g. the original
        parameter value) and returns a response (or None on failure).
    detect_fn:
        Callable ``(response) -> bool`` that evaluates whether a response
        indicates injection success.
    repetitions:
        Number of times to repeat the injection probe (default: 2).

    Returns
    -------
    (confirmed: bool, rationale: str)
    """
    import math

    required = math.ceil(repetitions / 2)
    positive_count = 0
    for attempt in range(repetitions):
        response = test_fn()
        if response is not None and detect_fn(response):
            positive_count += 1
        logger.debug(
            "confirm_finding: attempt %d/%d → %s",
            attempt + 1,
            repetitions,
            "positive" if response is not None and detect_fn(response) else "negative",
        )

    # Benign control: must NOT trigger detection
    benign_response = benign_fn()
    benign_triggered = benign_response is not None and detect_fn(benign_response)

    if benign_triggered:
        rationale = (
            f"Benign control also triggered detection — likely a false positive "
            f"({positive_count}/{repetitions} probes positive)."
        )
        logger.info("confirm_finding: %s", rationale)
        return False, rationale

    if positive_count >= required:
        rationale = (
            f"Finding confirmed: {positive_count}/{repetitions} probes positive, "
            "benign control negative."
        )
        logger.info("confirm_finding: %s", rationale)
        return True, rationale

    rationale = (
        f"Finding NOT confirmed: only {positive_count}/{repetitions} probes "
        f"positive (required {required}), benign control negative."
    )
    logger.info("confirm_finding: %s", rationale)
    return False, rationale
