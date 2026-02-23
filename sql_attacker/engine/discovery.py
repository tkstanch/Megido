"""
SQLi Discovery – Multi-location Injection-point Scanner
========================================================

Orchestrates discovery-focused SQL injection testing across multiple injection
point locations (query parameters, form-encoded bodies, JSON bodies, and
optionally selected headers).

Key components
--------------
InjectionLocation
    Enum of supported injection point locations.
InjectionPoint
    Metadata for a single testable parameter.
ProbeSet
    A canonical set of probe payloads (boolean-true/false pairs + quote-break
    probes) for differential analysis.
ResponseComparator
    Compares a probe response against a baseline using status code, length
    delta, content similarity, and SQL error signatures.
DiscoveryScanner
    Orchestrates baseline collection, probe injection, and result scoring for
    all discovered injection points.

Usage::

    from sql_attacker.engine.config import ScanConfig
    from sql_attacker.engine.discovery import DiscoveryScanner

    def my_request_fn(url, method, params, data, json_data, headers, cookies):
        import requests
        return requests.request(
            method, url, params=params, data=data, json=json_data,
            headers=headers, cookies=cookies, timeout=10,
        )

    scanner = DiscoveryScanner(request_fn=my_request_fn)
    findings = scanner.scan(
        url="https://example.com/search",
        method="GET",
        params={"q": "test", "page": "1"},
    )
    for finding in findings:
        print(finding.parameter, finding.verdict, finding.confidence)
"""

from __future__ import annotations

import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .adapters import AdapterRegistry, DBType, TECHNIQUE_ERROR, TECHNIQUE_BOOLEAN
from .baseline import BaselineCollector, BaselineResult, CanaryScheduler, confirm_finding
from .config import ScanConfig
from .modes import ModePolicy, OperationMode
from .normalization import normalize_response_body
from .reporting import Evidence, Finding
from .scoring import ScoringResult, compute_confidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum number of evidence items recorded per finding.  Caps report size
#: while preserving the most informative observations.
_MAX_EVIDENCE_ITEMS: int = 10

#: Minimum Jaccard similarity difference between true-probe and false-probe
#: (both vs baseline) required to register a boolean-differential signal.
_BOOLEAN_DIFF_THRESHOLD: float = 0.15

#: Scale factor applied to the similarity difference to produce a ``[0, 1]``
#: score.  A diff of exactly the threshold maps to 0.30; a diff of 2× the
#: threshold maps to 1.0.
_BOOLEAN_DIFF_SCALE_FACTOR: float = 2.0

# ---------------------------------------------------------------------------
# InjectionLocation
# ---------------------------------------------------------------------------


class InjectionLocation(Enum):
    """Possible locations for an injection point."""

    QUERY_PARAM = "query_param"
    FORM_PARAM = "form_param"
    JSON_PARAM = "json_param"
    HEADER = "header"


# ---------------------------------------------------------------------------
# InjectionPoint
# ---------------------------------------------------------------------------


@dataclass
class InjectionPoint:
    """Metadata describing a single testable injection point.

    Attributes
    ----------
    name:     Parameter or header name.
    location: Where the parameter lives in the request.
    original_value: The benign original value for the parameter.
    """

    name: str
    location: InjectionLocation
    original_value: str = ""


# ---------------------------------------------------------------------------
# ProbeSet
# ---------------------------------------------------------------------------

#: Quote-break probes – these should cause a syntax error in a SQL backend.
_QUOTE_BREAK_PROBES: List[str] = [
    "'",
    '"',
    "\\",
    "''",
    "\"\"",
]

#: Boolean true payloads (should return the same/more results than baseline).
_BOOLEAN_TRUE_PROBES: List[str] = [
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1 OR 1=1",
    "' OR 'x'='x",
]

#: Boolean false payloads (should return fewer/no results than baseline).
_BOOLEAN_FALSE_PROBES: List[str] = [
    "' AND '1'='2",
    "' AND 1=2--",
    '" AND "1"="2',
    "1 AND 1=2",
    "' AND 'x'='y",
]


@dataclass
class ProbeSet:
    """Canonical set of probes for a single injection point.

    Attributes
    ----------
    quote_break: Short probes whose purpose is to break SQL syntax.
    boolean_true: Payloads that should evaluate as TRUE in a SQL context.
    boolean_false: Payloads that should evaluate as FALSE in a SQL context.
    """

    quote_break: List[str] = field(default_factory=lambda: list(_QUOTE_BREAK_PROBES))
    boolean_true: List[str] = field(default_factory=lambda: list(_BOOLEAN_TRUE_PROBES))
    boolean_false: List[str] = field(default_factory=lambda: list(_BOOLEAN_FALSE_PROBES))

    @classmethod
    def default(cls, boolean_probe_count: int = 2) -> "ProbeSet":
        """Return a standard probe set with *boolean_probe_count* pairs."""
        n = max(1, boolean_probe_count)
        return cls(
            quote_break=list(_QUOTE_BREAK_PROBES),
            boolean_true=list(_BOOLEAN_TRUE_PROBES[:n]),
            boolean_false=list(_BOOLEAN_FALSE_PROBES[:n]),
        )


# ---------------------------------------------------------------------------
# SQL error signatures (curated set for common DBMS)
# ---------------------------------------------------------------------------

@dataclass
class ErrorSignature:
    """A compiled SQL error pattern and the DBMS it identifies."""

    pattern: re.Pattern
    db_type: str
    description: str


def _build_error_signatures() -> List[ErrorSignature]:
    """Build the curated list of SQL error signatures."""
    raw: List[Tuple[str, str, str]] = [
        # MySQL / MariaDB
        (r"You have an error in your SQL syntax.*MySQL", "mysql", "MySQL syntax error"),
        (r"mysql_fetch|mysql_num_rows|mysql_query", "mysql", "MySQL PHP function"),
        (r"MySQL server version for the right syntax", "mysql", "MySQL version hint"),
        (r"check the manual that corresponds to your MySQL server", "mysql", "MySQL manual reference"),
        (r"com\.mysql\.jdbc", "mysql", "Java MySQL JDBC"),
        (r"Unclosed quotation mark.*MySQL", "mysql", "MySQL unclosed quote"),
        (r"Warning.*mysqli?_", "mysql", "PHP MySQLi warning"),
        # PostgreSQL
        (r"pg_query\(\)|pg_exec\(", "postgresql", "PostgreSQL PHP function"),
        (r"PostgreSQL.*ERROR|ERROR.*PostgreSQL", "postgresql", "PostgreSQL error"),
        (r"ERROR:\s+syntax error at or near", "postgresql", "PostgreSQL syntax error"),
        (r"org\.postgresql|PSQLException", "postgresql", "Java PostgreSQL JDBC"),
        (r"Warning.*\Wpg_", "postgresql", "PHP PostgreSQL warning"),
        # MSSQL / SQL Server
        (r"Microsoft OLE DB Provider for SQL Server", "mssql", "MSSQL OLE DB error"),
        (r"Unclosed quotation mark after the character string", "mssql", "MSSQL unclosed quote"),
        (r"Microsoft SQL Server", "mssql", "MSSQL server string"),
        (r"\[SQL Server\]", "mssql", "MSSQL bracket error"),
        (r"SqlException|com\.microsoft\.sqlserver", "mssql", "Java MSSQL JDBC"),
        (r"Incorrect syntax near", "mssql", "MSSQL syntax error"),
        (r"SQLSTATE\[42", "mssql", "SQLSTATE 42xxx error"),
        # SQLite
        (r"SQLite/JDBCDriver|SQLite\.Exception", "sqlite", "SQLite JDBC"),
        (r"System\.Data\.SQLite", "sqlite", "SQLite .NET"),
        (r"unrecognized token:", "sqlite", "SQLite token error"),
        (r"sqlite3_exec", "sqlite", "SQLite C function"),
        (r"\[SQLITE_ERROR\]", "sqlite", "SQLite error bracket"),
        # Oracle
        (r"ORA-\d{5}", "oracle", "Oracle ORA error code"),
        (r"Oracle error|oracle\.jdbc|OracleException", "oracle", "Oracle error/JDBC"),
        (r"quoted string not properly terminated", "oracle", "Oracle unclosed quote"),
        (r"missing right parenthesis", "oracle", "Oracle parenthesis error"),
        # Generic SQL error keywords (lower confidence)
        (r"SQL syntax.*error|error.*SQL syntax", "unknown", "Generic SQL syntax error"),
        (r"supplied argument is not a valid MySQL", "mysql", "PHP MySQL argument error"),
        (r"Exception.*\bSQL\b", "unknown", "Generic SQL exception"),
    ]
    return [
        ErrorSignature(
            pattern=re.compile(pattern, re.IGNORECASE),
            db_type=db_type,
            description=description,
        )
        for pattern, db_type, description in raw
    ]


_ERROR_SIGNATURES: List[ErrorSignature] = _build_error_signatures()


def detect_sql_errors(body: str) -> List[ErrorSignature]:
    """Return a list of SQL error signatures that match *body*.

    Args:
        body: Raw HTTP response body text.

    Returns:
        List of :class:`ErrorSignature` objects for every pattern that
        matched.  Empty list means no signatures matched.
    """
    return [sig for sig in _ERROR_SIGNATURES if sig.pattern.search(body)]


# ---------------------------------------------------------------------------
# ResponseComparator
# ---------------------------------------------------------------------------


def _jaccard_similarity(text_a: str, text_b: str) -> float:
    """Estimate Jaccard similarity between two texts based on word-level tokens."""
    tokens_a = set(text_a.split())
    tokens_b = set(text_b.split())
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return intersection / union if union else 1.0


@dataclass
class ComparisonResult:
    """Outcome of comparing a probe response against a baseline.

    Attributes
    ----------
    status_changed:    True when the HTTP status code differs from the baseline.
    length_delta:      Absolute character-count difference between the
                       normalised probe body and the normalised baseline body.
    similarity:        Jaccard similarity in ``[0, 1]`` between probe and baseline.
    matched_signatures: SQL error signatures detected in the probe response.
    baseline_status:   HTTP status code of the baseline response.
    probe_status:      HTTP status code of the probe response.
    """

    status_changed: bool
    length_delta: int
    similarity: float
    matched_signatures: List[ErrorSignature]
    baseline_status: int = 200
    probe_status: int = 200

    @property
    def has_sql_errors(self) -> bool:
        """True when at least one SQL error signature was detected."""
        return len(self.matched_signatures) > 0

    @property
    def matched_db_types(self) -> List[str]:
        """Unique DB types from matched signatures."""
        seen = []
        for sig in self.matched_signatures:
            if sig.db_type not in seen:
                seen.append(sig.db_type)
        return seen


class ResponseComparator:
    """Compare a probe response against a normalised baseline.

    Parameters
    ----------
    config:
        :class:`~sql_attacker.engine.config.ScanConfig` with tolerance
        thresholds.
    """

    def __init__(self, config: Optional[ScanConfig] = None) -> None:
        self._cfg = config or ScanConfig()

    def compare(
        self,
        baseline_body: str,
        probe_body: str,
        baseline_status: int = 200,
        probe_status: int = 200,
    ) -> ComparisonResult:
        """Compare *probe_body* against *baseline_body* and return a
        :class:`ComparisonResult`.

        Both bodies should already be normalised (e.g. via
        :func:`~sql_attacker.engine.normalization.normalize_response_body`).
        """
        status_changed = baseline_status != probe_status
        length_delta = abs(len(probe_body) - len(baseline_body))
        similarity = _jaccard_similarity(baseline_body, probe_body)
        matched_sigs = detect_sql_errors(probe_body) if self._cfg.error_detection_enabled else []

        return ComparisonResult(
            status_changed=status_changed,
            length_delta=length_delta,
            similarity=similarity,
            matched_signatures=matched_sigs,
            baseline_status=baseline_status,
            probe_status=probe_status,
        )

    def to_feature_dict(
        self,
        result: ComparisonResult,
    ) -> Dict[str, float]:
        """Convert a :class:`ComparisonResult` to a feature dict for scoring.

        Each feature value is in ``[0, 1]`` and matches the weight names used
        by :func:`~sql_attacker.engine.scoring.compute_confidence`.
        """
        features: Dict[str, float] = {}

        if result.has_sql_errors:
            features["sql_error_pattern"] = 1.0

        if result.status_changed:
            # A 5xx status change is a stronger signal than any other change.
            if result.probe_status >= 500:
                features["http_error_code"] = 1.0
            else:
                features["http_error_code"] = 0.5

        if result.length_delta >= self._cfg.length_delta_threshold:
            # Scale: delta at exactly threshold → 0.5, large delta → 1.0
            ratio = min(1.0, result.length_delta / max(1, self._cfg.length_delta_threshold * 4))
            features["content_change"] = 0.5 + 0.5 * ratio

        similarity_drop = 1.0 - result.similarity
        if similarity_drop >= self._cfg.similarity_threshold:
            features["similarity_delta"] = min(1.0, similarity_drop / max(0.01, self._cfg.similarity_threshold * 2))

        return features


# ---------------------------------------------------------------------------
# DiscoveryScanner
# ---------------------------------------------------------------------------


class DiscoveryScanner:
    """Orchestrate discovery-focused SQL injection testing.

    Parameters
    ----------
    request_fn:
        Callable with the signature::

            def request_fn(url, method, params, data, json_data, headers, cookies) -> response | None

        ``response`` must expose ``.status_code`` and ``.text`` attributes
        compatible with ``requests.Response``.  May return ``None`` on failure.
    config:
        Optional :class:`~sql_attacker.engine.config.ScanConfig`.  Uses safe
        defaults when not provided.
    registry:
        Optional :class:`~sql_attacker.engine.adapters.AdapterRegistry`.  A
        default registry is created if not provided.
    """

    def __init__(
        self,
        request_fn: Callable,
        config: Optional[ScanConfig] = None,
        registry: Optional[AdapterRegistry] = None,
        mode_policy: Optional[ModePolicy] = None,
    ) -> None:
        self._request_fn = request_fn
        self._cfg = config or ScanConfig()
        self._registry = registry or AdapterRegistry()
        self._comparator = ResponseComparator(self._cfg)
        self._mode_policy = mode_policy or ModePolicy(OperationMode.DETECT)
        # Thread-safe request budget tracker
        self._host_request_counts: Dict[str, int] = {}
        self._host_request_lock = threading.Lock()
        # Per-scan baseline deduplication cache: key → (body, status_code)
        self._baseline_dedup: Dict[str, Tuple[str, int]] = {}
        self._baseline_dedup_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        """Scan all injection points in a request for SQL injection.

        Args:
            url:      Target URL.
            method:   HTTP method (``"GET"`` or ``"POST"``).
            params:   URL query parameters.
            data:     Form-encoded POST body parameters.
            json_data: JSON POST body as a dict.
            headers:  Request headers (merged with defaults).
            cookies:  Request cookies.

        Returns:
            List of :class:`~sql_attacker.engine.reporting.Finding` objects,
            one per vulnerable injection point.  Empty list if none found.
        """
        self._cfg.validate()
        self._mode_policy.assert_may_detect()
        method = method.upper()
        injection_points = self._enumerate_injection_points(
            method=method,
            params=params or {},
            data=data or {},
            json_data=json_data or {},
            headers=headers or {},
        )

        if not injection_points:
            logger.info("DiscoveryScanner: no injection points found for %s %s", method, url)
            return []

        findings: List[Finding] = []
        max_workers = max(1, self._cfg.max_concurrent_requests)

        if max_workers == 1:
            # Sequential path – no threading overhead
            for ip in injection_points:
                finding = self._test_injection_point(
                    ip=ip,
                    url=url,
                    method=method,
                    params=params or {},
                    data=data or {},
                    json_data=json_data or {},
                    headers=headers or {},
                    cookies=cookies or {},
                )
                if finding is not None:
                    findings.append(finding)
        else:
            # Concurrent path – bounded by max_concurrent_requests
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        self._test_injection_point,
                        ip=ip,
                        url=url,
                        method=method,
                        params=params or {},
                        data=data or {},
                        json_data=json_data or {},
                        headers=headers or {},
                        cookies=cookies or {},
                    ): ip
                    for ip in injection_points
                }
                for future in as_completed(futures):
                    try:
                        finding = future.result()
                        if finding is not None:
                            findings.append(finding)
                    except Exception as exc:
                        ip = futures[future]
                        logger.debug(
                            "Injection point test raised exception for %s: %s",
                            ip.name, exc,
                        )

        return findings

    # ------------------------------------------------------------------
    # Injection point enumeration
    # ------------------------------------------------------------------

    def _enumerate_injection_points(
        self,
        method: str,
        params: Dict[str, str],
        data: Dict[str, str],
        json_data: Dict[str, Any],
        headers: Dict[str, str],
    ) -> List[InjectionPoint]:
        """Enumerate all injection points based on request and config."""
        points: List[InjectionPoint] = []

        if self._cfg.inject_query_params:
            for name, value in params.items():
                points.append(InjectionPoint(
                    name=name,
                    location=InjectionLocation.QUERY_PARAM,
                    original_value=str(value),
                ))

        if self._cfg.inject_form_params and method == "POST":
            for name, value in data.items():
                points.append(InjectionPoint(
                    name=name,
                    location=InjectionLocation.FORM_PARAM,
                    original_value=str(value),
                ))

        if self._cfg.inject_json_params and method == "POST":
            for name, value in json_data.items():
                if isinstance(value, (str, int, float)):
                    points.append(InjectionPoint(
                        name=name,
                        location=InjectionLocation.JSON_PARAM,
                        original_value=str(value),
                    ))

        if self._cfg.inject_headers:
            for header_name in self._cfg.injectable_headers:
                if header_name in headers:
                    points.append(InjectionPoint(
                        name=header_name,
                        location=InjectionLocation.HEADER,
                        original_value=str(headers[header_name]),
                    ))

        return points

    # ------------------------------------------------------------------
    # Per-injection-point testing
    # ------------------------------------------------------------------

    def _test_injection_point(
        self,
        ip: InjectionPoint,
        url: str,
        method: str,
        params: Dict[str, str],
        data: Dict[str, str],
        json_data: Dict[str, Any],
        headers: Dict[str, str],
        cookies: Dict[str, str],
    ) -> Optional[Finding]:
        """Run the full probe sequence for a single injection point.

        Uses canary scheduling: quote-break probes run first as canaries.
        Boolean probes only run when the canary phase detects a signal.
        If an error signature identifies a specific DB type, DB-specific
        payloads are substituted for the remainder phase.
        In VERIFY mode a benign-control confirmation loop is applied to
        ``"likely"`` findings before reporting them.
        """
        logger.debug(
            "Testing injection point: %s @ %s [%s]",
            ip.name, url, ip.location.value,
        )

        # 1. Collect baseline (dedup: reuse within same scan for same endpoint)
        dedup_key = f"{method}:{url}"
        with self._baseline_dedup_lock:
            cached = self._baseline_dedup.get(dedup_key)
        if cached is not None:
            baseline_body, baseline_status = cached
            logger.debug("Baseline cache hit for %s", dedup_key)
        else:
            baseline_response = self._send_request(
                url=url,
                method=method,
                params=params,
                data=data,
                json_data=json_data,
                headers=headers,
                cookies=cookies,
            )
            if baseline_response is None:
                logger.warning("Could not collect baseline for %s @ %s", ip.name, url)
                return None
            baseline_body = normalize_response_body(getattr(baseline_response, "text", ""))
            baseline_status = getattr(baseline_response, "status_code", 200)
            with self._baseline_dedup_lock:
                self._baseline_dedup[dedup_key] = (baseline_body, baseline_status)

        # 2. Build probe set and apply canary scheduling
        probe_set = ProbeSet.default(boolean_probe_count=self._cfg.boolean_probe_count)

        all_probe_payloads = (
            [(p, "quote_break") for p in probe_set.quote_break]
            + [(p, "boolean_true") for p in probe_set.boolean_true]
            + [(p, "boolean_false") for p in probe_set.boolean_false]
        )

        # CanaryScheduler splits the flat payload list into canary + remainder
        scheduler = CanaryScheduler()
        payload_strings = [p for p, _ in all_probe_payloads]
        payload_type_map: Dict[str, str] = {p: t for p, t in all_probe_payloads}
        canary_strings, remainder_strings = scheduler.schedule(payload_strings)
        # Rebuild with types; canary first then remainder
        canary_phase = [(p, payload_type_map.get(p, "quote_break")) for p in canary_strings]
        remainder_phase = [(p, payload_type_map.get(p, "boolean_true")) for p in remainder_strings]

        feature_union: Dict[str, float] = {}
        evidence_list: List[Evidence] = []
        detected_db_types: List[str] = []
        matched_signature_names: List[str] = []

        def _run_probes(probe_list: List[Tuple[str, str]]) -> bool:
            """Send probes, update shared state; returns True when any signal fires."""
            any_signal = False
            for payload, probe_type in probe_list:
                injected_params, injected_data, injected_json, injected_headers = (
                    self._inject_payload(ip, payload, params, data, json_data, headers)
                )
                probe_response = self._send_request(
                    url=url,
                    method=method,
                    params=injected_params,
                    data=injected_data,
                    json_data=injected_json,
                    headers=injected_headers,
                    cookies=cookies,
                )
                if probe_response is None:
                    continue

                probe_body = normalize_response_body(getattr(probe_response, "text", ""))
                probe_status = getattr(probe_response, "status_code", 200)

                cmp = self._comparator.compare(
                    baseline_body=baseline_body,
                    probe_body=probe_body,
                    baseline_status=baseline_status,
                    probe_status=probe_status,
                )

                new_features = self._comparator.to_feature_dict(cmp)
                for feat, val in new_features.items():
                    if val > feature_union.get(feat, 0.0):
                        feature_union[feat] = val
                        any_signal = True

                for db_t in cmp.matched_db_types:
                    if db_t not in detected_db_types:
                        detected_db_types.append(db_t)
                for sig in cmp.matched_signatures:
                    if sig.description not in matched_signature_names:
                        matched_signature_names.append(sig.description)

                if new_features:
                    log_payload = (
                        "<redacted>" if self._cfg.redact_payloads_in_logs else payload
                    )
                    body_excerpt = getattr(probe_response, "text", "")[:512]
                    evidence_list.append(Evidence(
                        payload=payload,
                        request_summary=self._build_request_summary(
                            url=url,
                            method=method,
                            ip=ip,
                            payload=log_payload,
                            probe_status=probe_status,
                        ),
                        response_length=len(getattr(probe_response, "text", "")),
                        response_body_excerpt=body_excerpt,
                        technique=self._probe_type_to_technique(probe_type),
                    ))
            return any_signal

        # 3. Phase 1 – canary probes
        canary_signal = _run_probes(canary_phase)

        if not canary_signal and not feature_union:
            # No signal from canary set → skip remainder to save requests
            logger.debug(
                "Canary phase: no signal for %s @ %s; skipping remainder probes.",
                ip.name, url,
            )
            return None

        # 4. Phase 2 – escalate: run remainder probes
        # If an error signature already identified the DB type, prefer DB-specific payloads
        if detected_db_types and remainder_phase:
            try:
                db_enum = DBType(detected_db_types[0])
                adapter = self._registry.get_adapter(db_enum)
                db_payloads = adapter.get_payloads(TECHNIQUE_BOOLEAN)
                if db_payloads:
                    # Replace remainder with DB-specific boolean payloads
                    remainder_phase = [(p, "boolean_true") for p in db_payloads]
                    logger.debug(
                        "Switched to %s-specific payloads (%d) for %s @ %s",
                        detected_db_types[0], len(db_payloads), ip.name, url,
                    )
            except (ValueError, KeyError):
                pass  # unknown DB type string; use original remainder

        _run_probes(remainder_phase)

        # 5. Boolean diff signal: compare responses from true vs false pairs
        boolean_diff_score = self._compute_boolean_diff(
            ip=ip,
            url=url,
            method=method,
            params=params,
            data=data,
            json_data=json_data,
            headers=headers,
            cookies=cookies,
            baseline_body=baseline_body,
            probe_set=probe_set,
        )
        if boolean_diff_score > feature_union.get("boolean_diff", 0.0):
            feature_union["boolean_diff"] = boolean_diff_score

        # 6. Score and build Finding if threshold reached
        if not feature_union:
            logger.debug("No signals for %s @ %s", ip.name, url)
            return None

        scoring_result: ScoringResult = compute_confidence(feature_union)
        if scoring_result.verdict == "uncertain" and not evidence_list:
            logger.debug(
                "Signal too weak for %s @ %s (score=%.3f)",
                ip.name, url, scoring_result.score,
            )
            return None

        # 7. VERIFY mode: run confirmation loop for non-confirmed findings
        confirmed_verdict = scoring_result.verdict
        confirm_rationale: Optional[str] = None
        if self._mode_policy.may_verify() and scoring_result.verdict in ("likely", "uncertain"):
            best_payload = evidence_list[0].payload if evidence_list else None
            if best_payload:
                ip_ref = ip

                def _test_fn() -> Optional[Any]:
                    p, d, j, h = self._inject_payload(
                        ip_ref, best_payload, params, data, json_data, headers
                    )
                    return self._send_request(url, method, p, d, j, h, cookies)

                def _benign_fn() -> Optional[Any]:
                    return self._send_request(
                        url, method, params, data, json_data, headers, cookies
                    )

                def _detect_fn(resp: Any) -> bool:
                    body = normalize_response_body(getattr(resp, "text", ""))
                    return bool(detect_sql_errors(body)) or (
                        abs(len(body) - len(baseline_body)) >= self._cfg.length_delta_threshold
                    )

                confirmed, confirm_rationale = confirm_finding(
                    test_fn=_test_fn,
                    benign_fn=_benign_fn,
                    detect_fn=_detect_fn,
                )
                if not confirmed and scoring_result.verdict == "uncertain":
                    logger.debug(
                        "Uncertain finding NOT confirmed for %s @ %s: %s",
                        ip.name, url, confirm_rationale,
                    )
                    return None
                if confirmed and confirmed_verdict != "confirmed":
                    confirmed_verdict = "confirmed"

        db_type_str = detected_db_types[0] if detected_db_types else "unknown"
        technique = self._pick_technique(feature_union)

        # Annotate evidence with matched signature names
        if matched_signature_names and evidence_list:
            first_ev = evidence_list[0]
            if first_ev.response_body_excerpt:
                suffix = " | Signatures: " + "; ".join(matched_signature_names[:3])
                evidence_list[0] = Evidence(
                    payload=first_ev.payload,
                    request_summary=first_ev.request_summary,
                    response_length=first_ev.response_length,
                    response_body_excerpt=(first_ev.response_body_excerpt[:400] + suffix)[:512],
                    timing_samples_ms=first_ev.timing_samples_ms,
                    baseline_median_ms=first_ev.baseline_median_ms,
                    technique=first_ev.technique,
                )

        # Build score rationale including top contributions for reporting
        rationale_parts = [r for r in [scoring_result.rationale, confirm_rationale] if r]
        score_rationale = " | ".join(rationale_parts) if rationale_parts else None

        finding = Finding(
            parameter=ip.name,
            technique=technique,
            db_type=db_type_str,
            confidence=scoring_result.score,
            verdict=confirmed_verdict,
            evidence=evidence_list[:_MAX_EVIDENCE_ITEMS],
            url=url,
            method=method,
            score_rationale=score_rationale,
        )
        logger.info(
            "Finding: %s [%s] param=%s technique=%s confidence=%.3f verdict=%s db=%s",
            url, method, ip.name, technique,
            scoring_result.score, confirmed_verdict, db_type_str,
        )
        return finding

    # ------------------------------------------------------------------
    # Boolean differential
    # ------------------------------------------------------------------

    def _compute_boolean_diff(
        self,
        ip: InjectionPoint,
        url: str,
        method: str,
        params: Dict[str, str],
        data: Dict[str, str],
        json_data: Dict[str, Any],
        headers: Dict[str, str],
        cookies: Dict[str, str],
        baseline_body: str,
        probe_set: ProbeSet,
    ) -> float:
        """Compute a boolean-differential signal score.

        Sends one true/false pair and measures whether the true payload returns
        a response more similar to the baseline than the false payload does.

        Returns a score in ``[0, 1]`` or ``0`` when no significant difference
        was detected.
        """
        if not probe_set.boolean_true or not probe_set.boolean_false:
            return 0.0

        true_payload = probe_set.boolean_true[0]
        false_payload = probe_set.boolean_false[0]

        true_params, true_data, true_json, true_headers = self._inject_payload(
            ip, true_payload, params, data, json_data, headers
        )
        false_params, false_data, false_json, false_headers = self._inject_payload(
            ip, false_payload, params, data, json_data, headers
        )

        true_response = self._send_request(
            url=url, method=method,
            params=true_params, data=true_data, json_data=true_json,
            headers=true_headers, cookies=cookies,
        )
        false_response = self._send_request(
            url=url, method=method,
            params=false_params, data=false_data, json_data=false_json,
            headers=false_headers, cookies=cookies,
        )

        if true_response is None or false_response is None:
            return 0.0

        true_body = normalize_response_body(getattr(true_response, "text", ""))
        false_body = normalize_response_body(getattr(false_response, "text", ""))

        true_sim = _jaccard_similarity(baseline_body, true_body)
        false_sim = _jaccard_similarity(baseline_body, false_body)
        diff = true_sim - false_sim

        # A meaningful boolean diff: true is more similar to baseline than false
        if diff >= _BOOLEAN_DIFF_THRESHOLD:
            return min(1.0, diff * _BOOLEAN_DIFF_SCALE_FACTOR)
        return 0.0

    # ------------------------------------------------------------------
    # Payload injection helpers
    # ------------------------------------------------------------------

    def _inject_payload(
        self,
        ip: InjectionPoint,
        payload: str,
        params: Dict[str, str],
        data: Dict[str, str],
        json_data: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Tuple[Dict, Dict, Dict, Dict]:
        """Return modified (params, data, json_data, headers) with *payload* injected."""
        new_params = dict(params)
        new_data = dict(data)
        new_json = dict(json_data)
        new_headers = dict(headers)

        if ip.location == InjectionLocation.QUERY_PARAM:
            new_params[ip.name] = payload
        elif ip.location == InjectionLocation.FORM_PARAM:
            new_data[ip.name] = payload
        elif ip.location == InjectionLocation.JSON_PARAM:
            new_json[ip.name] = payload
        elif ip.location == InjectionLocation.HEADER:
            new_headers[ip.name] = payload

        return new_params, new_data, new_json, new_headers

    # ------------------------------------------------------------------
    # HTTP request with budget tracking
    # ------------------------------------------------------------------

    def _send_request(
        self,
        url: str,
        method: str,
        params: Dict,
        data: Dict,
        json_data: Dict,
        headers: Dict,
        cookies: Dict,
    ) -> Optional[Any]:
        """Send a single request, honoring the per-host budget.

        Redacts sensitive headers before logging.
        """
        from urllib.parse import urlparse

        host = urlparse(url).hostname or url
        with self._host_request_lock:
            count = self._host_request_counts.get(host, 0)
            budget = self._cfg.per_host_request_budget
            if budget > 0 and count >= budget:
                logger.warning(
                    "Per-host budget exhausted for %s (%d requests). Skipping.", host, count
                )
                return None
            self._host_request_counts[host] = count + 1

        # Build redacted header dict for logging
        if logger.isEnabledFor(logging.DEBUG):
            redacted = {
                k: ("<redacted>" if k in self._cfg.redact_sensitive_headers else v)
                for k, v in headers.items()
            }
            logger.debug(
                "Request: %s %s params=%s headers=%s",
                method, url, params, redacted,
            )

        try:
            return self._request_fn(
                url,
                method,
                params or None,
                data or None,
                json_data or None,
                headers or None,
                cookies or None,
            )
        except Exception as exc:
            logger.debug("Request failed: %s %s → %s", method, url, exc)
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_request_summary(
        url: str,
        method: str,
        ip: InjectionPoint,
        payload: str,
        probe_status: int,
    ) -> str:
        """Build a human-readable, reproducible request summary."""
        location = ip.location.value
        return (
            f"{method} {url} [{location}: {ip.name}={payload!r}] "
            f"→ HTTP {probe_status}"
        )

    @staticmethod
    def _probe_type_to_technique(probe_type: str) -> str:
        """Map a probe type label to a technique name."""
        if probe_type in ("boolean_true", "boolean_false"):
            return "boolean"
        if probe_type == "quote_break":
            return "error"
        return probe_type

    @staticmethod
    def _pick_technique(features: Dict[str, float]) -> str:
        """Choose the primary technique name from the feature dict."""
        if features.get("sql_error_pattern", 0) > 0.5:
            return "error"
        if features.get("boolean_diff", 0) > 0.5:
            return "boolean"
        if features.get("timing_delta_significant", 0) > 0.5:
            return "time"
        # Fall back to the highest-scoring feature
        if not features:
            return "error"
        best = max(features, key=lambda k: features[k])
        if "error" in best:
            return "error"
        if "bool" in best or "content" in best or "similar" in best:
            return "boolean"
        return "error"
