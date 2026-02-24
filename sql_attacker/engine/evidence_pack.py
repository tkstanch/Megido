"""
EvidencePack – Client-ready proof-of-concept evidence for SQL injection findings.
==================================================================================

An :class:`EvidencePack` captures everything needed to reproduce a finding:

* The exact HTTP request that triggered the signal (method, URL, params,
  headers, body — with sensitive values redacted).
* Baseline and mutated response signatures (stable SHA-256 fingerprints).
* A structured response diff summary (status, length delta, similarity ratio).
* Timing statistics across multiple trials (median, mean, stddev, raw samples).
* Payload identifiers and the deterministic seed used for payload selection.
* Auto-generated cURL and Python reproduction scripts (with secret redaction).

Persistence
-----------
:meth:`EvidencePack.save` writes the pack to a JSON file.
:meth:`EvidencePack.load` reads it back.

Usage::

    from sql_attacker.engine.evidence_pack import EvidencePack, TimingStats, RequestSpec

    pack = EvidencePack(
        finding_id="abc123",
        url="https://example.com/search",
        request=RequestSpec(
            method="GET",
            url="https://example.com/search",
            params={"q": "' OR 1=1--"},
        ),
        baseline_signature="aabbcc112233",
        mutated_signature="ddeeff445566",
        diff_summary={"changed": True, "ratio": 0.42, "length_delta": 312, "summary": "..."},
        timing_stats=TimingStats(samples_ms=[120.0, 118.5, 122.0]),
        payload_ids=["sqli-bool-001"],
        deterministic_seed=42,
    )
    pack.save("/tmp/evidence/finding_abc123.json")

    # Reproduce later
    print(pack.to_curl())
    print(pack.to_python_repro())
"""

from __future__ import annotations

import json
import math
import os
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Secret redaction helpers
# ---------------------------------------------------------------------------

_REDACT_PATTERNS = [
    # Authorization header value (whole value to end of line)
    (re.compile(r"(?i)(authorization\s*[:=]\s*)[^\r\n]+"), r"\1<REDACTED>"),
    # Cookie header value (whole value to end of line)
    (re.compile(r"(?i)(cookie\s*[:=]\s*)[^\r\n]+"), r"\1<REDACTED>"),
    # Bearer token (standalone, e.g. in JSON or query params)
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9+/_.\-]{16,}"), r"\1<REDACTED>"),
    # API key in key=value / key: value
    (
        re.compile(
            r"(?i)((?:api[_-]?key|apikey|api_token|access_token|secret)\s*[=:]\s*)[^\s\"&<>]+"
        ),
        r"\1<REDACTED>",
    ),
    # JWT tokens (three base64url segments)
    (
        re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
        "<JWT_REDACTED>",
    ),
]


def _redact(text: str) -> str:
    """Apply secret-redaction patterns to *text*."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of *d* with sensitive key values redacted."""
    _SENSITIVE_KEYS = frozenset(
        {
            "authorization",
            "cookie",
            "set-cookie",
            "x-auth-token",
            "x-api-key",
            "proxy-authorization",
            "api_key",
            "apikey",
            "api_token",
            "access_token",
            "secret",
        }
    )
    result: Dict[str, Any] = {}
    for k, v in d.items():
        if k.lower() in _SENSITIVE_KEYS:
            result[k] = "<REDACTED>"
        elif isinstance(v, str):
            result[k] = _redact(v)
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# TimingStats
# ---------------------------------------------------------------------------


@dataclass
class TimingStats:
    """Descriptive statistics for a series of response-time samples.

    Parameters
    ----------
    samples_ms:
        Raw response times in milliseconds (at least one value required).
    """

    samples_ms: List[float] = field(default_factory=list)

    # Computed on first access via __post_init__
    median_ms: float = field(init=False)
    mean_ms: float = field(init=False)
    stddev_ms: float = field(init=False)
    min_ms: float = field(init=False)
    max_ms: float = field(init=False)

    def __post_init__(self) -> None:
        if self.samples_ms:
            self.median_ms = statistics.median(self.samples_ms)
            self.mean_ms = statistics.mean(self.samples_ms)
            self.stddev_ms = (
                statistics.stdev(self.samples_ms) if len(self.samples_ms) > 1 else 0.0
            )
            self.min_ms = min(self.samples_ms)
            self.max_ms = max(self.samples_ms)
        else:
            self.median_ms = 0.0
            self.mean_ms = 0.0
            self.stddev_ms = 0.0
            self.min_ms = 0.0
            self.max_ms = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "samples_ms": self.samples_ms,
            "median_ms": round(self.median_ms, 3),
            "mean_ms": round(self.mean_ms, 3),
            "stddev_ms": round(self.stddev_ms, 3),
            "min_ms": round(self.min_ms, 3),
            "max_ms": round(self.max_ms, 3),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TimingStats":
        return cls(samples_ms=d.get("samples_ms", []))


# ---------------------------------------------------------------------------
# RequestSpec
# ---------------------------------------------------------------------------


@dataclass
class RequestSpec:
    """Serialisable specification of a single HTTP request.

    All sensitive header/cookie values are redacted before serialisation.

    Parameters
    ----------
    method:   HTTP verb (``"GET"``, ``"POST"``, …).
    url:      Full target URL.
    params:   URL query parameters dict.
    headers:  Request headers dict (sensitive values are redacted on save).
    cookies:  Cookies dict (redacted on save).
    body:     Raw request body string (used for form-encoded or JSON bodies).
    json_data: Parsed JSON body dict.
    """

    method: str = "GET"
    url: str = ""
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "method": self.method,
            "url": self.url,
        }
        if self.params:
            d["params"] = _redact_dict(self.params)
        if self.headers:
            d["headers"] = _redact_dict(self.headers)
        if self.cookies:
            d["cookies"] = {k: "<REDACTED>" for k in self.cookies}
        if self.body:
            d["body"] = _redact(self.body)
        if self.json_data is not None:
            d["json_data"] = self.json_data
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RequestSpec":
        return cls(
            method=d.get("method", "GET"),
            url=d.get("url", ""),
            params=d.get("params", {}),
            headers=d.get("headers", {}),
            cookies=d.get("cookies", {}),
            body=d.get("body", ""),
            json_data=d.get("json_data"),
        )


# ---------------------------------------------------------------------------
# EvidencePack
# ---------------------------------------------------------------------------


@dataclass
class EvidencePack:
    """Complete proof-of-concept evidence bundle for a single finding.

    Attributes
    ----------
    finding_id:
        UUID of the parent :class:`~sql_attacker.engine.reporting.Finding`.
    url:
        Target URL (convenience copy; also in *request*).
    request:
        The exact HTTP request that triggered the finding.
    baseline_signature:
        Stable fingerprint (hex) of the normalised baseline response body.
    mutated_signature:
        Stable fingerprint (hex) of the normalised mutated response body.
    diff_summary:
        Structured diff between baseline and mutated response (keys:
        ``changed``, ``ratio``, ``length_delta``, ``summary``).
    timing_stats:
        Response-time statistics across multiple trials (optional; present
        when time-based evidence was collected).
    payload_ids:
        Ordered list of payload identifiers used to trigger the finding.
    deterministic_seed:
        The ``payload_seed`` value from :class:`~sql_attacker.engine.config.ScanConfig`
        used during the scan, enabling exact reproduction.
    captured_at:
        ISO-8601 UTC timestamp when this pack was created.
    parameter:
        Vulnerable parameter name.
    parameter_location:
        Location of the parameter (``"query_param"``, ``"form_param"``, …).
    technique:
        Detection technique (``"error"``, ``"boolean"``, ``"time"``).
    db_type:
        Detected or assumed DBMS.
    """

    finding_id: str
    url: str
    request: RequestSpec
    baseline_signature: str
    mutated_signature: str
    diff_summary: Dict[str, Any]
    timing_stats: Optional[TimingStats] = None
    payload_ids: List[str] = field(default_factory=list)
    deterministic_seed: Optional[int] = None
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )
    parameter: str = ""
    parameter_location: str = "unknown"
    technique: str = "error"
    db_type: str = "unknown"

    # ------------------------------------------------------------------
    # Repro script generation
    # ------------------------------------------------------------------

    def to_curl(self) -> str:
        """Generate a cURL command that reproduces the finding.

        Sensitive header/cookie values are redacted.  The command is
        suitable for inclusion in client reports or issue tickets.
        """
        parts = ["curl -s -o /dev/null -w '%{http_code}'"]
        parts.append(f"  -X {self.request.method}")

        for k, v in _redact_dict(self.request.headers).items():
            parts.append(f"  -H '{k}: {v}'")
        if self.request.cookies:
            cookie_str = "; ".join(
                f"{k}=<REDACTED>" for k in self.request.cookies
            )
            parts.append(f"  -H 'Cookie: {cookie_str}'")

        if self.request.json_data is not None:
            body = json.dumps(self.request.json_data)
            parts.append(f"  -H 'Content-Type: application/json'")
            parts.append(f"  --data '{_redact(body)}'")
        elif self.request.body:
            parts.append(f"  --data '{_redact(self.request.body)}'")

        # Build URL with query params
        url = self.request.url
        safe_params = _redact_dict(self.request.params)
        if safe_params:
            from urllib.parse import urlencode
            url = url + "?" + urlencode(safe_params)

        parts.append(f"  '{url}'")
        return " \\\n".join(parts)

    def to_python_repro(self) -> str:
        """Generate a Python ``requests`` script that reproduces the finding.

        Sensitive values are redacted.  The script is self-contained and
        runnable once the ``<REDACTED>`` placeholders are filled in.
        """
        lines = [
            "#!/usr/bin/env python3",
            '"""Auto-generated reproduction script — fill in <REDACTED> placeholders."""',
            "import requests",
            "",
        ]
        req = self.request
        safe_params = _redact_dict(req.params)
        safe_headers = _redact_dict(req.headers)
        safe_cookies = {k: "<REDACTED>" for k in req.cookies}

        lines.append(f"url = {req.url!r}")
        if safe_params:
            lines.append(f"params = {safe_params!r}")
        else:
            lines.append("params = {}")

        if safe_headers:
            lines.append(f"headers = {safe_headers!r}")
        else:
            lines.append("headers = {}")

        if safe_cookies:
            lines.append(f"cookies = {safe_cookies!r}")
        else:
            lines.append("cookies = {}")

        call_kwargs = ["url", "params=params", "headers=headers", "cookies=cookies"]

        if req.json_data is not None:
            lines.append(f"json_data = {req.json_data!r}")
            call_kwargs.append("json=json_data")
        elif req.body:
            redacted_body = _redact(req.body)
            lines.append(f"data = {redacted_body!r}")
            call_kwargs.append("data=data")

        lines.append("timeout = 30")
        call_kwargs.append("timeout=timeout")

        lines.append("")
        lines.append(
            f"response = requests.{req.method.lower()}({', '.join(call_kwargs)})"
        )
        lines.append("print(f'Status: {response.status_code}')")
        lines.append("print(f'Length: {len(response.text)}')")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary representation."""
        d: Dict[str, Any] = {
            "schema_version": "1.0",
            "finding_id": self.finding_id,
            "url": self.url,
            "parameter": self.parameter,
            "parameter_location": self.parameter_location,
            "technique": self.technique,
            "db_type": self.db_type,
            "captured_at": self.captured_at,
            "request": self.request.to_dict(),
            "baseline_signature": self.baseline_signature,
            "mutated_signature": self.mutated_signature,
            "diff_summary": self.diff_summary,
        }
        if self.timing_stats is not None:
            d["timing_stats"] = self.timing_stats.to_dict()
        if self.payload_ids:
            d["payload_ids"] = self.payload_ids
        if self.deterministic_seed is not None:
            d["deterministic_seed"] = self.deterministic_seed
        d["repro"] = {
            "curl": self.to_curl(),
            "python": self.to_python_repro(),
        }
        return d

    def save(self, path: str, *, indent: int = 2) -> None:
        """Persist the evidence pack to a JSON file at *path*.

        Parent directories are created automatically.  Existing files are
        **overwritten**.

        Args:
            path:   Absolute or relative file path.
            indent: JSON indentation level (default: 2).
        """
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=indent, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> "EvidencePack":
        """Load an :class:`EvidencePack` from a JSON file.

        Args:
            path: Path to a JSON file previously written by :meth:`save`.

        Returns:
            Reconstructed :class:`EvidencePack`.

        Raises:
            FileNotFoundError: If *path* does not exist.
            ValueError: If the file does not contain a valid EvidencePack.
        """
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)

        try:
            timing = (
                TimingStats.from_dict(d["timing_stats"])
                if "timing_stats" in d
                else None
            )
            return cls(
                finding_id=d["finding_id"],
                url=d["url"],
                request=RequestSpec.from_dict(d.get("request", {})),
                baseline_signature=d["baseline_signature"],
                mutated_signature=d["mutated_signature"],
                diff_summary=d.get("diff_summary", {}),
                timing_stats=timing,
                payload_ids=d.get("payload_ids", []),
                deterministic_seed=d.get("deterministic_seed"),
                captured_at=d.get("captured_at", ""),
                parameter=d.get("parameter", ""),
                parameter_location=d.get("parameter_location", "unknown"),
                technique=d.get("technique", "error"),
                db_type=d.get("db_type", "unknown"),
            )
        except KeyError as exc:
            raise ValueError(
                f"EvidencePack JSON is missing required field: {exc}"
            ) from exc
