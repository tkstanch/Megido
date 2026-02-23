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
        Short excerpt (≤ 512 chars) from the response that confirms the
        signal (e.g. the matched error string or the differing fragment).
        Sensitive user data must be redacted by the caller before setting
        this field.
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

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-compatible dictionary."""
        d: Dict[str, Any] = {
            "payload": self.payload,
            "request_summary": self.request_summary,
            "technique": self.technique,
            "response_length": self.response_length,
        }
        if self.response_body_excerpt:
            d["response_body_excerpt"] = self.response_body_excerpt[:512]
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
    cwe: str = _CWE_SQL_INJECTION
    severity: Optional[str] = None
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    score_rationale: Optional[str] = None

    def __post_init__(self) -> None:
        # Clamp confidence to [0, 1]
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        # Derive severity from confidence if not explicitly set
        if self.severity is None:
            self.severity = _confidence_to_severity(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-compatible dictionary."""
        d: Dict[str, Any] = {
            "finding_id": self.finding_id,
            "parameter": self.parameter,
            "url": self.url,
            "method": self.method,
            "technique": self.technique,
            "db_type": self.db_type,
            "confidence": round(self.confidence, 4),
            "verdict": self.verdict,
            "severity": self.severity,
            "cwe": self.cwe,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
        }
        if self.score_rationale:
            d["score_rationale"] = self.score_rationale
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
