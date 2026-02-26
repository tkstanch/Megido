"""
Standardised Reporting: JSON + SARIF
=====================================
Provides machine-readable output for SQL injection findings.

Classes
-------
Evidence
    A single paired payload/response observation (or timing distribution)
    that supports a finding.
Finding
    A structured vulnerability record with parameter name, technique,
    confidence score, evidence, and remediation guidance.
ReportBuilder
    Accumulates :class:`Finding` objects and emits them as JSON or SARIF.

Emitting reports::

    from sql_attacker.engine.reporting import Finding, Evidence, ReportBuilder

    builder = ReportBuilder(target_url="https://example.com/search")
    builder.add_finding(Finding(
        parameter="q",
        technique="error",
        db_type="mysql",
        confidence=0.92,
        verdict="confirmed",
        evidence=[Evidence(
            payload="' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            request_summary="GET /search?q=%27+AND+... HTTP/1.1",
            response_length=1234,
            response_body_excerpt="XPATH syntax error: '~5.7.38-0ubuntu0.18.04.1'",
        )],
        remediation=(
            "Use parameterised queries / prepared statements. "
            "Never interpolate user input directly into SQL."
        ),
    ))
    json_report = builder.to_json()
    sarif_report = builder.to_sarif()
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote, urlparse, urlencode

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "Megido SQLi Engine"
_TOOL_VERSION = "1.0.0"
_RULE_ID_PREFIX = "MEGIDO-SQLI"

# CWE-89: Improper Neutralisation of Special Elements used in an SQL Command
_CWE_SQL_INJECTION = "CWE-89"

# Default remediation text used when the caller does not supply one.
_DEFAULT_REMEDIATION = (
    "Use parameterised queries (prepared statements) to separate SQL code "
    "from user-supplied data. Validate and allow-list input where possible. "
    "Apply the principle of least privilege to database accounts. "
    "See OWASP SQL Injection Prevention Cheat Sheet for detailed guidance."
)

# Default maximum length for stored response body excerpts.
_DEFAULT_BODY_EXCERPT_MAX_LENGTH: int = 512

# ---------------------------------------------------------------------------
# CVSS v3.1 base score constants
# ---------------------------------------------------------------------------

# CVSS v3.1 base scores by technique and impact level.
# Scores are approximate based on FIRST.org calculator defaults for SQLi.
_CVSS_SCORES: Dict[str, float] = {
    "error": 9.8,       # Error-based: full confidentiality/integrity/availability
    "union": 9.8,       # UNION-based: data extraction
    "boolean": 8.8,     # Boolean blind: slower but same impact
    "time": 7.5,        # Time-based: limited impact, harder to exploit
    "second_order": 8.8,  # Second-order: deferred execution
    "stacked": 9.8,     # Stacked queries: command execution possible
    "oob": 8.1,         # Out-of-band: network-dependent
}

# CVSS v3.1 vector strings by technique.
_CVSS_VECTORS: Dict[str, str] = {
    "error": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "union": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "boolean": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "time": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "second_order": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "stacked": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "oob": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# ---------------------------------------------------------------------------
# Compliance mapping constants
# ---------------------------------------------------------------------------

# Compliance framework references per injection technique.
_COMPLIANCE_REFS: Dict[str, Dict[str, List[str]]] = {
    "owasp_top10": {
        "default": ["A03:2021 – Injection"],
    },
    "cwe": {
        "default": ["CWE-89: SQL Injection"],
        "second_order": ["CWE-89: SQL Injection", "CWE-501: Trust Boundary Violation"],
    },
    "pci_dss": {
        "default": ["PCI-DSS v4.0 Req 6.2.4 – Prevent SQL injection"],
    },
    "nist": {
        "default": ["NIST SP 800-53 SI-10: Information Input Validation"],
    },
}

# Suffix appended to truncated body excerpts.  Fixed length so that the total
# output length never exceeds max_length.
_TRUNCATION_SUFFIX: str = "...[truncated]"

# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

# Compiled patterns for sensitive material that must be redacted from
# stored/logged request and response artifacts.
_REDACT_COMPILED = [
    # JWT tokens: three base64url segments separated by dots
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), '<JWT_REDACTED>'),
    # Authorization header values
    (re.compile(r'(?i)(Authorization\s*[:=]\s*)[^\r\n]+'), r'\1<REDACTED>'),
    # Cookie header line values
    (re.compile(r'(?i)(Cookie\s*[:=]\s*)[^\r\n]+'), r'\1<REDACTED>'),
    # Bearer tokens
    (re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9+/._-]{16,}'), r'\1<REDACTED>'),
    # API keys in common key=value patterns
    (re.compile(r'(?i)((?:api[_-]?key|apikey|api_token|access_token)\s*[=:]\s*)[^\s"&<>]+'), r'\1<REDACTED>'),
]


def redact_response_body(text: str, max_length: int = _DEFAULT_BODY_EXCERPT_MAX_LENGTH) -> str:
    """Redact sensitive patterns and truncate a response body for safe storage.

    Applies redaction of JWT tokens, Authorization values, Cookie header
    values, bearer tokens, and common API key patterns before truncating to
    *max_length* characters.  The total output length (including the
    ``"...[truncated]"`` suffix when applied) never exceeds *max_length*.

    This function is safe to call on any string; it never raises.

    Args:
        text:       Raw response body or excerpt text.
        max_length: Maximum number of characters to return.  Set to 0 for no
                    truncation (useful when storing full bodies explicitly).
                    Default: 512.

    Returns:
        Redacted and optionally truncated string.
    """
    if not text:
        return text
    for pattern, replacement in _REDACT_COMPILED:
        try:
            text = pattern.sub(replacement, text)
        except Exception:  # noqa: BLE001 – never let redaction crash a scan
            pass
    if max_length > 0 and len(text) > max_length:
        cut = max(0, max_length - len(_TRUNCATION_SUFFIX))
        text = text[:cut] + _TRUNCATION_SUFFIX
    return text


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """A single observation that supports a vulnerability finding.

    Attributes
    ----------
    payload:
        The injection string that triggered the signal.
    request_summary:
        A human-readable, reproducible request description, e.g.
        ``"GET /search?q=<payload> HTTP/1.1"`` or a cURL equivalent.
        Must not contain sensitive authentication material.
    response_length:
        Length of the response body in bytes.
    response_body_excerpt:
        Short excerpt from the response that confirms the signal (e.g. the
        matched error string or the differing fragment).  Secrets and
        sensitive patterns are automatically redacted when serialising via
        :meth:`to_dict`.  The default storage limit is
        ``_DEFAULT_BODY_EXCERPT_MAX_LENGTH`` (512 chars); set
        ``include_full_body=True`` on :meth:`to_dict` to override.
    timing_samples_ms:
        For time-based evidence: list of observed response times in
        milliseconds across repeated trials.
    baseline_median_ms:
        Median baseline response time in milliseconds (no payload).
    technique:
        Detection technique used: ``"error"``, ``"boolean"``, or ``"time"``.
    """

    payload: str
    request_summary: str
    response_length: int = 0
    response_body_excerpt: str = ""
    timing_samples_ms: List[float] = field(default_factory=list)
    baseline_median_ms: Optional[float] = None
    technique: str = "error"

    def to_dict(self, *, include_full_body: bool = False) -> Dict[str, Any]:
        """Serialise to a JSON-compatible dictionary.

        Args:
            include_full_body: When True the response body excerpt is stored
                in full (after redaction) rather than being truncated to
                ``_DEFAULT_BODY_EXCERPT_MAX_LENGTH`` characters.  Defaults to
                False.  **Use with caution** – full bodies may be large and
                could contain sensitive data not caught by redaction patterns.
        """
        d: Dict[str, Any] = {
            "payload": self.payload,
            "request_summary": self.request_summary,
            "technique": self.technique,
            "response_length": self.response_length,
        }
        if self.response_body_excerpt:
            max_len = 0 if include_full_body else _DEFAULT_BODY_EXCERPT_MAX_LENGTH
            d["response_body_excerpt"] = redact_response_body(
                self.response_body_excerpt, max_length=max_len
            )
        if self.timing_samples_ms:
            d["timing_samples_ms"] = self.timing_samples_ms
        if self.baseline_median_ms is not None:
            d["baseline_median_ms"] = self.baseline_median_ms
        return d


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A structured vulnerability record.

    Attributes
    ----------
    parameter:
        Name of the vulnerable HTTP parameter (e.g. ``"id"`` or ``"search"``).
    technique:
        Detection technique that revealed the vulnerability.
    db_type:
        Detected or assumed DBMS (e.g. ``"mysql"``).
    confidence:
        Numeric confidence score in ``[0, 1]``.
    verdict:
        Human-readable confidence label: ``"confirmed"``, ``"likely"``,
        or ``"uncertain"``.
    evidence:
        List of :class:`Evidence` objects supporting this finding.
    remediation:
        Remediation guidance for this finding.
    url:
        Target URL (may differ from the ``ReportBuilder`` top-level URL when
        multiple endpoints are tested).
    method:
        HTTP method used (``"GET"`` or ``"POST"``).
    parameter_location:
        Location where the parameter lives: ``"query_param"``, ``"form_param"``,
        ``"json_param"``, ``"header"``, ``"cookie_param"``, or ``"unknown"``.
    cwe:
        CWE identifier (defaults to ``"CWE-89"``).
    severity:
        Severity string: ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.
        Derived automatically from *confidence* when not set explicitly.
    finding_id:
        Unique identifier for this finding (auto-generated UUID4).
    """

    parameter: str
    technique: str
    db_type: str
    confidence: float
    verdict: str
    evidence: List[Evidence] = field(default_factory=list)
    remediation: str = _DEFAULT_REMEDIATION
    url: Optional[str] = None
    method: str = "GET"
    parameter_location: str = "unknown"
    cwe: str = _CWE_SQL_INJECTION
    severity: Optional[str] = None
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    score_rationale: Optional[str] = None
    # Enhanced reporting fields
    cvss: Optional[Dict[str, Any]] = None
    compliance: Optional[Dict[str, List[str]]] = None
    curl_command: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def __post_init__(self) -> None:
        # Clamp confidence to [0, 1]
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        # Derive severity from confidence if not explicitly set
        if self.severity is None:
            self.severity = _confidence_to_severity(self.confidence)
        # Auto-populate CVSS if not provided
        if self.cvss is None:
            self.cvss = compute_cvss_score(self.technique, self.confidence)
        # Auto-populate compliance refs if not provided
        if self.compliance is None:
            self.compliance = get_compliance_refs(self.technique)
        # Auto-generate cURL command from first evidence payload if not provided
        if self.curl_command is None and self.evidence and self.url:
            first_ev = self.evidence[0]
            self.curl_command = build_curl_command(
                url=self.url,
                method=self.method,
                parameter=self.parameter,
                payload=first_ev.payload,
                parameter_location=self.parameter_location,
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-compatible dictionary."""
        d: Dict[str, Any] = {
            "finding_id": self.finding_id,
            "parameter": self.parameter,
            "url": self.url,
            "method": self.method,
            "parameter_location": self.parameter_location,
            "technique": self.technique,
            "db_type": self.db_type,
            "confidence": round(self.confidence, 4),
            "verdict": self.verdict,
            "severity": self.severity,
            "cwe": self.cwe,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }
        if self.score_rationale:
            d["score_rationale"] = self.score_rationale
        if self.cvss:
            d["cvss_v31"] = self.cvss
        if self.compliance:
            d["compliance"] = self.compliance
        if self.curl_command:
            d["curl_command"] = self.curl_command
        return d


def _confidence_to_severity(confidence: float) -> str:
    """Map a confidence score to a severity label."""
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.60:
        return "medium"
    if confidence >= 0.35:
        return "low"
    return "informational"


# ---------------------------------------------------------------------------
# cURL reproduction helpers
# ---------------------------------------------------------------------------


def build_curl_command(
    url: str,
    method: str,
    parameter: str,
    payload: str,
    parameter_location: str = "query_param",
    headers: Optional[Dict[str, str]] = None,
) -> str:
    """Build a cURL command that reproduces the injection request.

    The command is safe to copy-paste into a terminal.  Sensitive header
    values are never included; the caller is responsible for substituting
    authentication material.

    Args:
        url:                The target URL (without the injected parameter).
        method:             HTTP method (``"GET"`` or ``"POST"``).
        parameter:          Name of the injected parameter.
        payload:            The injection payload string.
        parameter_location: Where the parameter lives (``"query_param"``,
                            ``"form_param"``, ``"json_param"``).
        headers:            Optional additional headers to include.

    Returns:
        A multi-line cURL command string.
    """
    method = (method or "GET").upper()
    encoded_payload = quote(payload, safe="")
    parts = [f"curl -v -X {method}"]

    if headers:
        for k, v in headers.items():
            parts.append(f"  -H '{k}: {v}'")

    if parameter_location in ("query_param",):
        sep = "&" if "?" in url else "?"
        full_url = f"{url}{sep}{parameter}={encoded_payload}"
        parts.append(f"  '{full_url}'")
    elif parameter_location in ("form_param",):
        parts.append(f"  -H 'Content-Type: application/x-www-form-urlencoded'")
        parts.append(f"  --data-urlencode '{parameter}={payload}'")
        parts.append(f"  '{url}'")
    elif parameter_location in ("json_param",):
        json_body = json.dumps({parameter: payload})
        parts.append(f"  -H 'Content-Type: application/json'")
        parts.append(f"  -d '{json_body}'")
        parts.append(f"  '{url}'")
    else:
        sep = "&" if "?" in url else "?"
        full_url = f"{url}{sep}{parameter}={encoded_payload}"
        parts.append(f"  '{full_url}'")

    return " \\\n".join(parts)


# ---------------------------------------------------------------------------
# CVSS v3.1 helpers
# ---------------------------------------------------------------------------


def compute_cvss_score(technique: str, confidence: float) -> Dict[str, Any]:
    """Compute a CVSS v3.1 base score for a finding.

    The base score is adjusted downward slightly for lower-confidence findings
    to reflect uncertainty.  The vector string is technique-specific.

    Args:
        technique:  Detection technique (``"error"``, ``"union"``, etc.).
        confidence: Confidence score in ``[0, 1]``.

    Returns:
        Dict with keys ``"score"``, ``"vector"``, ``"severity"``.
    """
    base = _CVSS_SCORES.get(technique, 7.5)
    # Discount score proportionally for confidence < 0.7
    adjusted = base * min(1.0, max(0.3, confidence / 0.7))
    adjusted = round(adjusted, 1)
    vector = _CVSS_VECTORS.get(technique, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")
    if adjusted >= 9.0:
        sev = "critical"
    elif adjusted >= 7.0:
        sev = "high"
    elif adjusted >= 4.0:
        sev = "medium"
    else:
        sev = "low"
    return {"score": adjusted, "vector": vector, "severity": sev}


# ---------------------------------------------------------------------------
# Compliance mapping helpers
# ---------------------------------------------------------------------------


def get_compliance_refs(technique: str) -> Dict[str, List[str]]:
    """Return compliance framework references for a given injection technique.

    Args:
        technique: Detection technique string.

    Returns:
        Dict mapping framework name → list of reference strings.
    """
    result: Dict[str, List[str]] = {}
    for framework, refs in _COMPLIANCE_REFS.items():
        result[framework] = refs.get(technique, refs["default"])
    return result


# ---------------------------------------------------------------------------
# ReportBuilder
# ---------------------------------------------------------------------------


class ReportBuilder:
    """Accumulates findings and emits them as JSON or SARIF.

    Parameters
    ----------
    target_url:
        The primary URL under test.
    scan_id:
        Optional unique identifier for this scan run (auto-generated when
        not provided).
    """

    def __init__(
        self,
        target_url: str = "",
        scan_id: Optional[str] = None,
    ) -> None:
        self._target_url = target_url
        self._scan_id = scan_id or str(uuid.uuid4())
        self._findings: List[Finding] = []
        self._started_at: str = _utcnow_iso()
        self._finished_at: Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        """Append a :class:`Finding` to the report."""
        if finding.url is None:
            finding.url = self._target_url
        self._findings.append(finding)

    def finish(self) -> None:
        """Record the scan completion timestamp."""
        self._finished_at = _utcnow_iso()

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def to_json(self, *, indent: int = 2) -> str:
        """Serialise the report to a JSON string.

        The output schema is::

            {
              "schema_version": "1.0",
              "scan_id": "<uuid>",
              "target_url": "https://...",
              "started_at": "2026-01-01T00:00:00Z",
              "finished_at": "2026-01-01T00:01:00Z",
              "summary": { "total": N, "confirmed": N, "likely": N, ... },
              "findings": [ <Finding.to_dict()>, ... ]
            }
        """
        return json.dumps(self._build_report_dict(), indent=indent, ensure_ascii=False)

    def _build_report_dict(self) -> Dict[str, Any]:
        summary = _summarise(self._findings)
        return {
            "schema_version": "1.0",
            "scan_id": self._scan_id,
            "target_url": self._target_url,
            "started_at": self._started_at,
            "finished_at": self._finished_at or _utcnow_iso(),
            "summary": summary,
            "findings": [f.to_dict() for f in self._findings],
        }

    # ------------------------------------------------------------------
    # SARIF output
    # ------------------------------------------------------------------

    def to_sarif(self) -> str:
        """Serialise the report to a SARIF 2.1.0 JSON string.

        Produces a minimal but valid SARIF document suitable for import into
        GitHub Advanced Security, Azure DevOps, or any SARIF-aware tool.
        """
        return json.dumps(self._build_sarif_dict(), indent=2, ensure_ascii=False)

    def _build_sarif_dict(self) -> Dict[str, Any]:
        rules = _sarif_rules(self._findings)
        results = [_sarif_result(f) for f in self._findings]

        return {
            "version": _SARIF_VERSION,
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": "https://github.com/tkstanch/Megido",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanId": self._scan_id,
                        "targetUrl": self._target_url,
                        "startedAt": self._started_at,
                        "finishedAt": self._finished_at or _utcnow_iso(),
                    },
                }
            ],
        }

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def findings(self) -> List[Finding]:
        """Read-only list of accumulated findings."""
        return list(self._findings)

    @property
    def scan_id(self) -> str:
        """Unique identifier for this scan run."""
        return self._scan_id

    @property
    def target_url(self) -> str:
        """Primary target URL."""
        return self._target_url

    def executive_summary(self) -> str:
        """Generate a plain-text executive summary of the scan findings.

        Returns a human-readable string suitable for including in reports
        or emails to non-technical stakeholders.
        """
        total = len(self._findings)
        if total == 0:
            return (
                f"SQL injection scan of {self._target_url or 'target'} completed. "
                "No SQL injection vulnerabilities were detected."
            )
        high = sum(1 for f in self._findings if (f.severity or "") in ("high", "critical"))
        med = sum(1 for f in self._findings if (f.severity or "") == "medium")
        low = sum(1 for f in self._findings if (f.severity or "") in ("low", "informational"))
        confirmed = sum(1 for f in self._findings if f.verdict == "confirmed")
        top_cvss = max((f.cvss or {}).get("score", 0.0) for f in self._findings)
        techniques = sorted({f.technique for f in self._findings})
        lines = [
            f"EXECUTIVE SUMMARY — SQL Injection Scan",
            f"Target:    {self._target_url or 'N/A'}",
            f"Scan ID:   {self._scan_id}",
            f"Started:   {self._started_at}",
            f"Completed: {self._finished_at or _utcnow_iso()}",
            "",
            f"Total findings:  {total}",
            f"  Confirmed:     {confirmed}",
            f"  High/Critical: {high}",
            f"  Medium:        {med}",
            f"  Low:           {low}",
            f"Highest CVSS v3.1 score: {top_cvss:.1f}",
            f"Techniques detected: {', '.join(techniques) or 'none'}",
            "",
            "RISK RATING: " + _risk_rating(top_cvss, confirmed),
            "",
            "RECOMMENDATION:",
            _DEFAULT_REMEDIATION,
        ]
        return "\n".join(lines)

    def attack_timeline(self) -> List[Dict[str, Any]]:
        """Return an ordered timeline of findings by timestamp.

        Each entry contains the finding ID, timestamp, technique, parameter,
        and verdict.  Useful for understanding the progression of an attack.

        Returns:
            List of dicts ordered by ``timestamp`` ascending.
        """
        events = []
        for f in self._findings:
            events.append({
                "timestamp": f.timestamp,
                "finding_id": f.finding_id,
                "parameter": f.parameter,
                "technique": f.technique,
                "db_type": f.db_type,
                "verdict": f.verdict,
                "severity": f.severity,
            })
        events.sort(key=lambda e: e["timestamp"])
        return events


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarise(findings: List[Finding]) -> Dict[str, Any]:
    """Build a summary dict from a list of findings."""
    by_verdict: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_technique: Dict[str, int] = {}
    for f in findings:
        by_verdict[f.verdict] = by_verdict.get(f.verdict, 0) + 1
        sev = f.severity or "unknown"
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_technique[f.technique] = by_technique.get(f.technique, 0) + 1
    return {
        "total": len(findings),
        "by_verdict": by_verdict,
        "by_severity": by_severity,
        "by_technique": by_technique,
    }


def _rule_id(technique: str, db_type: str) -> str:
    """Build a SARIF rule ID from technique and db_type."""
    clean_tech = re.sub(r"[^a-zA-Z0-9]", "-", technique.upper())
    clean_db = re.sub(r"[^a-zA-Z0-9]", "-", db_type.upper())
    return f"{_RULE_ID_PREFIX}/{clean_tech}/{clean_db}"


def _sarif_rules(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Build SARIF rule descriptors (deduplicated) from findings."""
    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rid = _rule_id(f.technique, f.db_type)
        if rid in seen:
            continue
        seen[rid] = {
            "id": rid,
            "name": f"SqlInjection/{f.technique.capitalize()}/{f.db_type.capitalize()}",
            "shortDescription": {
                "text": (
                    f"SQL injection ({f.technique}-based) detected in "
                    f"{f.db_type.upper()} database"
                )
            },
            "fullDescription": {
                "text": (
                    f"A {f.technique}-based SQL injection vulnerability was identified "
                    f"in a {f.db_type.upper()} database. {_DEFAULT_REMEDIATION}"
                )
            },
            "helpUri": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "properties": {
                "tags": ["security", "sql-injection", "cwe-89"],
                "precision": _verdict_to_sarif_precision(f.verdict),
                "problem.severity": _severity_to_sarif_level(f.severity or "medium"),
            },
        }
    return list(seen.values())


def _sarif_result(f: Finding) -> Dict[str, Any]:
    """Convert a :class:`Finding` to a SARIF result object."""
    message_text = (
        f"SQL injection ({f.technique}) in parameter '{f.parameter}' "
        f"[{f.db_type}, confidence={f.confidence:.0%}, verdict={f.verdict}]. "
        f"{f.remediation}"
    )
    result: Dict[str, Any] = {
        "ruleId": _rule_id(f.technique, f.db_type),
        "kind": "open",
        "level": _severity_to_sarif_level(f.severity or "medium"),
        "message": {"text": message_text},
        "properties": {
            "findingId": f.finding_id,
            "parameter": f.parameter,
            "parameterLocation": f.parameter_location,
            "dbType": f.db_type,
            "technique": f.technique,
            "confidence": round(f.confidence, 4),
            "verdict": f.verdict,
            "cwe": f.cwe,
        },
    }
    if f.url:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                }
            }
        ]
    return result


def _verdict_to_sarif_precision(verdict: str) -> str:
    """Map a verdict string to a SARIF precision label."""
    return {
        "confirmed": "high",
        "likely": "medium",
        "uncertain": "low",
    }.get(verdict, "low")


def _severity_to_sarif_level(severity: str) -> str:
    """Map a severity string to a SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "note",
    }.get(severity, "warning")


def _risk_rating(top_cvss: float, confirmed: int) -> str:
    """Derive an executive risk rating from CVSS score and confirmed findings.

    Args:
        top_cvss:  Highest CVSS v3.1 base score across all findings.
        confirmed: Number of findings with verdict ``"confirmed"``.

    Returns:
        A single-word risk label: ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``,
        ``"LOW"``, or ``"INFORMATIONAL"``.
    """
    if top_cvss >= 9.0 or (confirmed >= 1 and top_cvss >= 7.0):
        return "CRITICAL"
    if top_cvss >= 7.0:
        return "HIGH"
    if top_cvss >= 4.0:
        return "MEDIUM"
    if top_cvss >= 0.1:
        return "LOW"
    return "INFORMATIONAL"
