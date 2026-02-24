"""
ScanConfig – Configuration knobs for the SQL injection discovery engine.
=========================================================================

``ScanConfig`` is an immutable-ish dataclass that centralises all tunable
parameters for a discovery scan.  Safe defaults are chosen so that a caller
who does not touch the config still gets a safe, bounded scan.

Usage::

    from sql_attacker.engine.config import ScanConfig

    # Minimal – everything at safe defaults
    cfg = ScanConfig()

    # Custom – increase concurrency and enable header injection
    cfg = ScanConfig(
        max_concurrent_requests=5,
        inject_headers=True,
        time_based_enabled=True,
        time_based_max_delay_seconds=3,
        time_based_max_requests_per_host=10,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    """Configuration for a SQL injection discovery scan.

    Attributes
    ----------
    baseline_samples:
        Number of benign baseline requests to send per injection point
        before probing.  Higher values reduce timing noise at the cost of
        more requests.  Default: 3.
    max_concurrent_requests:
        Maximum number of concurrent HTTP requests.  1 = sequential (safest).
        Default: 1.
    request_timeout_seconds:
        Per-request socket / read timeout in seconds.  Default: 10.
    retry_max_attempts:
        Maximum number of retries on transient network errors.  Default: 2.
    retry_base_delay_seconds:
        Base delay for jittered exponential back-off between retries.
        Default: 0.5.
    retry_max_delay_seconds:
        Upper cap on the back-off delay.  Default: 8.
    per_host_request_budget:
        Maximum total requests allowed to a single host during one scan.
        0 = unlimited (not recommended).  Default: 200.
    inject_query_params:
        Whether to inject into URL query string parameters.  Default: True.
    inject_form_params:
        Whether to inject into form-encoded POST body parameters.
        Default: True.
    inject_json_params:
        Whether to inject into JSON POST body parameters.  Default: True.
    inject_headers:
        Whether to inject into selected HTTP headers.  This is **opt-in** and
        disabled by default because header injection is noisier and has higher
        false-positive risk.  Default: False.
    inject_cookies:
        Whether to inject into HTTP cookies.  This is **opt-in** and disabled
        by default.  Default: False.
    injectable_headers:
        The specific header names to test when ``inject_headers`` is True.
        Default: ``["X-Forwarded-For", "User-Agent", "Referer", "X-Custom-IP-Authorization"]``.
    redact_sensitive_headers:
        Header names whose values will be redacted from logs and reports.
        Default: common auth / session headers.
    redact_payloads_in_logs:
        When True, injection payloads are redacted from debug-level log
        messages.  Default: False (payloads are often needed for debugging).
    time_based_enabled:
        Whether to run time-based confirmation when other signals are
        inconclusive.  Default: False (must be explicitly opted in).
    time_based_max_delay_seconds:
        Maximum SLEEP / WAITFOR delay injected per time-based probe, in
        seconds.  Requests that take longer than this value + network jitter
        are considered suspicious.  Default: 3.
    time_based_max_requests_per_endpoint:
        Maximum number of time-based probes to send to a single injection
        point.  Default: 6.
    time_based_max_requests_per_host:
        Total time-based probe budget per host across all injection points.
        Default: 20.
    boolean_probe_count:
        Number of true/false boolean probe pairs to send per injection point.
        Default: 2.
    length_delta_threshold:
        Minimum response length difference (in characters) that is considered
        significant.  Default: 50.
    similarity_threshold:
        Minimum Jaccard similarity drop that is considered significant.
        Scores below this vs the baseline trigger a content-change signal.
        Default: 0.10.
    error_detection_enabled:
        Whether to check responses for SQL error message signatures.
        Default: True.
    """

    # ------------------------------------------------------------------ #
    # Baseline / general                                                   #
    # ------------------------------------------------------------------ #
    baseline_samples: int = 3
    max_concurrent_requests: int = 1
    request_timeout_seconds: float = 10.0

    # ------------------------------------------------------------------ #
    # Retry / back-off                                                     #
    # ------------------------------------------------------------------ #
    retry_max_attempts: int = 2
    retry_base_delay_seconds: float = 0.5
    retry_max_delay_seconds: float = 8.0

    # ------------------------------------------------------------------ #
    # Request budget (safety guardrail)                                    #
    # ------------------------------------------------------------------ #
    per_host_request_budget: int = 200

    # ------------------------------------------------------------------ #
    # Injection-point locations                                            #
    # ------------------------------------------------------------------ #
    inject_query_params: bool = True
    inject_form_params: bool = True
    inject_json_params: bool = True
    inject_headers: bool = False  # explicit opt-in
    inject_cookies: bool = False  # explicit opt-in
    injectable_headers: List[str] = field(
        default_factory=lambda: [
            "X-Forwarded-For",
            "User-Agent",
            "Referer",
            "X-Custom-IP-Authorization",
        ]
    )

    # ------------------------------------------------------------------ #
    # Redaction                                                            #
    # ------------------------------------------------------------------ #
    redact_sensitive_headers: List[str] = field(
        default_factory=lambda: [
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Auth-Token",
            "X-Api-Key",
            "Proxy-Authorization",
            "WWW-Authenticate",
        ]
    )
    redact_payloads_in_logs: bool = False

    # ------------------------------------------------------------------ #
    # Time-based detection (opt-in)                                        #
    # ------------------------------------------------------------------ #
    time_based_enabled: bool = False  # must be explicitly opted in
    time_based_max_delay_seconds: float = 3.0
    time_based_max_requests_per_endpoint: int = 6
    time_based_max_requests_per_host: int = 20

    # ------------------------------------------------------------------ #
    # Probe tuning                                                         #
    # ------------------------------------------------------------------ #
    boolean_probe_count: int = 2
    length_delta_threshold: int = 50
    similarity_threshold: float = 0.10
    error_detection_enabled: bool = True

    # ------------------------------------------------------------------ #
    # Payload management                                                   #
    # ------------------------------------------------------------------ #
    max_payloads_per_param: Optional[int] = None
    """Cap on the total number of injection payloads sent to a single
    parameter.  Canary probes are always included first; the remainder is
    trimmed to stay within this budget.  ``None`` (default) means no cap."""

    payload_seed: Optional[int] = None
    """Integer seed for deterministic payload selection.  When set, the
    remainder payload list is shuffled with ``random.Random(payload_seed)``
    before capping, so repeated runs with the same seed produce identical
    probe sequences – useful for reproducible CI pipelines."""

    # ------------------------------------------------------------------ #
    # WAF / lockout detection (safety guardrail)                          #
    # ------------------------------------------------------------------ #
    waf_detection_enabled: bool = True
    """Automatically abort scanning for an endpoint when WAF/lockout signals
    are detected (spikes in HTTP 403/429 or captcha-like pages)."""

    waf_abort_threshold: int = 3
    """Number of consecutive 403/429 responses before the scanner aborts
    further probing of the current injection point."""

    def validate(self) -> None:
        """Raise ``ValueError`` if any configuration value is out of range."""
        if self.baseline_samples < 1:
            raise ValueError("baseline_samples must be >= 1")
        if self.max_concurrent_requests < 1:
            raise ValueError("max_concurrent_requests must be >= 1")
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be > 0")
        if self.time_based_max_delay_seconds <= 0:
            raise ValueError("time_based_max_delay_seconds must be > 0")
        if self.time_based_max_delay_seconds > 30:
            raise ValueError(
                "time_based_max_delay_seconds must be <= 30 to avoid excessive delays"
            )
        if self.length_delta_threshold < 0:
            raise ValueError("length_delta_threshold must be >= 0")
        if not 0.0 <= self.similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be in [0, 1]")
        if self.waf_abort_threshold < 1:
            raise ValueError("waf_abort_threshold must be >= 1")
        if self.max_payloads_per_param is not None and self.max_payloads_per_param < 1:
            raise ValueError("max_payloads_per_param must be >= 1 when set")
