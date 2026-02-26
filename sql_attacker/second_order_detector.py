"""
Second-Order SQL Injection Detector
=====================================
Detects second-order (stored) SQL injection by injecting a unique canary
value via one endpoint and monitoring separate trigger endpoints for evidence
that the stored payload was later interpreted as SQL.

Workflow
--------
1. Inject a unique canary string (``MEGIDO_2O_<uuid>``) mixed with SQL
   metacharacters into an *injection endpoint* (e.g. a registration form).
2. Request one or more *trigger endpoints* (e.g. profile page, admin panel)
   that are expected to retrieve and process the stored value.
3. Inspect the trigger response for:
   * SQL error patterns (the canary caused a syntax error).
   * The raw canary being echoed back verbatim (unsafe reflection).
4. Correlate the injection point to the trigger point and produce a
   :class:`~sql_attacker.engine.reporting.Finding`.

Integration
-----------
* :class:`~sql_attacker.engine.config.ScanConfig` — configuration knobs.
* :func:`~sql_attacker.engine.scoring.compute_confidence` — confidence score.
* :class:`~sql_attacker.engine.reporting.Finding` /
  :class:`~sql_attacker.engine.reporting.Evidence` — structured results.
* :func:`~sql_attacker.guardrails.check_authorization` — fail-closed
  authorization gate checked before *every* outbound request.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, urljoin

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.reporting import Evidence, Finding
from sql_attacker.engine.scoring import ScoringResult, compute_confidence
from sql_attacker.guardrails import check_authorization

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQL error patterns used to detect triggered injection in responses
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning:\s*mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"pg_query\(\).*error",
        r"supplied argument is not a valid mysql",
        r"ora-\d{5}",
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
        r"jdbc.*exception",
        r"sqlexception",
        r"syntax error.*sql",
        r"sql syntax.*near",
        r"unexpected end of sql command",
        r"invalid query",
        r"division by zero",
        r"column.*does not exist",
        r"relation.*does not exist",
        r"unterminated string",
        r"parse error.*line \d",
        r"sqlite.*error",
        r"no such column",
    ]
]

# Canary prefix injected with every probe
_CANARY_PREFIX = "MEGIDO_2O_"

# SQL metacharacter suffixes appended to the canary to provoke errors
_METACHAR_SUFFIXES: List[str] = [
    "'",
    "\"",
    "'--",
    "'/*",
    "';--",
    "' OR '1'='1",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class EndpointMapping:
    """Describes a single injection→trigger relationship.

    Attributes
    ----------
    injection_url:
        URL that accepts the injection payload (e.g. user registration).
    injection_param:
        Parameter name in the injection request that carries the payload.
    trigger_url:
        URL that is expected to retrieve and process the stored value
        (e.g. user profile page, admin panel).
    trigger_param:
        Optional query-string parameter to append to *trigger_url* for
        trigger-side probing.  ``None`` means the trigger URL is fetched
        as-is.
    method:
        HTTP method to use for the injection request (``"POST"`` or
        ``"GET"``).  Defaults to ``"POST"``.
    """

    injection_url: str
    injection_param: str
    trigger_url: str
    trigger_param: Optional[str] = None
    method: str = "POST"


@dataclass
class SecondOrderResult:
    """Raw result of a single second-order probe.

    Attributes
    ----------
    injection_url:
        URL that received the injected canary.
    injection_param:
        Parameter that carried the canary.
    trigger_url:
        URL that was monitored for evidence.
    triggered:
        ``True`` when at least one evidence signal was observed.
    evidence:
        List of :class:`~sql_attacker.engine.reporting.Evidence` objects
        collected from the trigger response.
    correlation_score:
        Numeric confidence score in ``[0, 1]`` computed from observed
        signals.
    """

    injection_url: str
    injection_param: str
    trigger_url: str
    triggered: bool
    evidence: List[Evidence] = field(default_factory=list)
    correlation_score: float = 0.0


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------


class SecondOrderDetector:
    """Detects second-order (stored) SQL injection.

    Parameters
    ----------
    config:
        Scan configuration controlling timeouts, budgets, and authorization.
    request_fn:
        Callable with the signature
        ``(method: str, url: str, params: dict, data: dict, headers: dict,
        timeout: float) -> (status_code: int, response_body: str)``.
        The caller is responsible for supplying an appropriate HTTP client
        wrapper.
    authorized:
        Must be ``True`` to allow outbound requests.  Mirrors the
        ``authorized`` field on :class:`~sql_attacker.engine.config.ScanConfig`.

    Raises
    ------
    :class:`~sql_attacker.guardrails.AuthorizationError`
        If :py:attr:`authorized` is ``False`` when any request is made.
    """

    def __init__(
        self,
        config: ScanConfig,
        request_fn: Callable[
            [str, str, Dict, Dict, Dict, float],
            Tuple[int, str],
        ],
        authorized: bool = False,
    ) -> None:
        self.config = config
        self._request_fn = request_fn
        self._authorized = authorized
        # Registered injection→trigger mappings
        self._mappings: List[EndpointMapping] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(
        self,
        injection_url: str,
        injection_param: str,
        trigger_url: str,
        trigger_param: Optional[str] = None,
        method: str = "POST",
    ) -> Optional[Finding]:
        """Run a second-order injection probe for a single mapping.

        Parameters
        ----------
        injection_url:
            URL that receives the injected canary payload.
        injection_param:
            Name of the parameter that carries the payload.
        trigger_url:
            URL to monitor after injection.
        trigger_param:
            Optional query-string parameter name for the trigger request.
        method:
            HTTP method for the injection request (``"POST"``/``"GET"``).

        Returns
        -------
        :class:`~sql_attacker.engine.reporting.Finding`
            Populated finding when second-order injection is detected, or
            ``None`` if no evidence was found.
        """
        result = self._probe(
            injection_url=injection_url,
            injection_param=injection_param,
            trigger_url=trigger_url,
            trigger_param=trigger_param,
            method=method,
        )

        if not result.triggered:
            return None

        return self._build_finding(result)

    def add_endpoint_mapping(
        self,
        injection_url: str,
        trigger_url: str,
        injection_param: str = "input",
        trigger_param: Optional[str] = None,
        method: str = "POST",
    ) -> None:
        """Register an injection→trigger endpoint pair for batch scanning.

        Parameters
        ----------
        injection_url:
            URL that receives payloads.
        trigger_url:
            URL monitored after each injection.
        injection_param:
            Parameter name on the injection URL (default: ``"input"``).
        trigger_param:
            Optional query parameter on the trigger URL.
        method:
            HTTP method for injection (default: ``"POST"``).
        """
        mapping = EndpointMapping(
            injection_url=injection_url,
            injection_param=injection_param,
            trigger_url=trigger_url,
            trigger_param=trigger_param,
            method=method,
        )
        self._mappings.append(mapping)
        logger.debug(
            "Registered mapping: %s [%s] → %s",
            injection_url,
            injection_param,
            trigger_url,
        )

    def scan_all_mappings(self) -> List[Finding]:
        """Run :meth:`detect` over all registered mappings.

        Returns
        -------
        list of :class:`~sql_attacker.engine.reporting.Finding`
            All findings produced across every registered mapping.
        """
        findings: List[Finding] = []
        for mapping in self._mappings:
            finding = self.detect(
                injection_url=mapping.injection_url,
                injection_param=mapping.injection_param,
                trigger_url=mapping.trigger_url,
                trigger_param=mapping.trigger_param,
                method=mapping.method,
            )
            if finding is not None:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe(
        self,
        injection_url: str,
        injection_param: str,
        trigger_url: str,
        trigger_param: Optional[str],
        method: str,
    ) -> SecondOrderResult:
        """Inject canary payloads and inspect the trigger response.

        For each metacharacter suffix a fresh canary is generated, injected,
        and the trigger URL is fetched.  All evidence is collected before
        computing the aggregate correlation score.
        """
        all_evidence: List[Evidence] = []

        for suffix in _METACHAR_SUFFIXES:
            canary = _CANARY_PREFIX + str(uuid.uuid4()).replace("-", "")[:12]
            payload = canary + suffix

            # 1. Send injection request
            injected = self._inject(
                url=injection_url,
                param=injection_param,
                payload=payload,
                method=method,
            )
            if not injected:
                continue

            # 2. Fetch trigger URL and look for evidence
            trigger_status, trigger_body = self._fetch_trigger(
                trigger_url=trigger_url,
                trigger_param=trigger_param,
            )
            if trigger_body is None:
                continue

            evidence_items = self._analyse_response(
                payload=payload,
                canary=canary,
                trigger_url=trigger_url,
                trigger_param=trigger_param,
                trigger_status=trigger_status,
                body=trigger_body,
            )
            all_evidence.extend(evidence_items)

            # Stop probing once we have strong evidence
            if len(all_evidence) >= 2:
                break

        triggered = bool(all_evidence)
        score = 0.0
        if triggered:
            score_result = self._score(all_evidence)
            score = score_result.score

        return SecondOrderResult(
            injection_url=injection_url,
            injection_param=injection_param,
            trigger_url=trigger_url,
            triggered=triggered,
            evidence=all_evidence,
            correlation_score=score,
        )

    def _inject(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
    ) -> bool:
        """Send the injection request.  Returns True on success."""
        check_authorization(self._authorized)

        method = method.upper()
        params: Dict[str, str] = {}
        data: Dict[str, str] = {}
        headers: Dict[str, str] = {"User-Agent": "MegidoSecurityScanner/1.0"}

        if method == "GET":
            params[param] = payload
        else:
            data[param] = payload

        try:
            status, _ = self._request_fn(
                method,
                url,
                params,
                data,
                headers,
                float(self.config.request_timeout_seconds),
            )
            logger.debug(
                "Injected canary into %s [param=%s] → HTTP %s",
                url,
                param,
                status,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Injection request to %s failed: %s", url, exc)
            return False

    def _fetch_trigger(
        self,
        trigger_url: str,
        trigger_param: Optional[str],
    ) -> Tuple[int, Optional[str]]:
        """Fetch the trigger URL and return ``(status_code, body)``."""
        check_authorization(self._authorized)

        params: Dict[str, str] = {}
        if trigger_param:
            params[trigger_param] = ""

        headers: Dict[str, str] = {"User-Agent": "MegidoSecurityScanner/1.0"}

        try:
            status, body = self._request_fn(
                "GET",
                trigger_url,
                params,
                {},
                headers,
                float(self.config.request_timeout_seconds),
            )
            logger.debug("Trigger fetch %s → HTTP %s (%d bytes)", trigger_url, status, len(body))
            return status, body
        except Exception as exc:  # noqa: BLE001
            logger.warning("Trigger request to %s failed: %s", trigger_url, exc)
            return 0, None

    def _analyse_response(
        self,
        payload: str,
        canary: str,
        trigger_url: str,
        trigger_param: Optional[str],
        trigger_status: int,
        body: str,
    ) -> List[Evidence]:
        """Return a list of Evidence items found in the trigger response."""
        evidence_items: List[Evidence] = []
        request_summary = self._build_request_summary(
            trigger_url=trigger_url,
            trigger_param=trigger_param,
        )

        # Check for SQL error patterns
        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                excerpt_start = max(0, match.start() - 80)
                excerpt = body[excerpt_start: match.end() + 80]
                evidence_items.append(
                    Evidence(
                        payload=payload,
                        request_summary=request_summary,
                        response_length=len(body),
                        response_body_excerpt=excerpt,
                        technique="error",
                    )
                )
                logger.info(
                    "SQL error pattern '%s' triggered at %s",
                    pattern.pattern,
                    trigger_url,
                )
                break  # One error pattern per payload is sufficient

        # Check for canary reflection (the stored value echoed back verbatim)
        if canary in body:
            excerpt_idx = body.find(canary)
            excerpt = body[max(0, excerpt_idx - 40): excerpt_idx + len(canary) + 40]
            evidence_items.append(
                Evidence(
                    payload=payload,
                    request_summary=request_summary,
                    response_length=len(body),
                    response_body_excerpt=excerpt,
                    technique="error",
                )
            )
            logger.info("Canary '%s' reflected at %s", canary, trigger_url)

        return evidence_items

    @staticmethod
    def _build_request_summary(
        trigger_url: str,
        trigger_param: Optional[str],
    ) -> str:
        """Produce a human-readable request summary for Evidence."""
        if trigger_param:
            return f"GET {trigger_url}?{trigger_param}= HTTP/1.1"
        return f"GET {trigger_url} HTTP/1.1"

    def _score(self, evidence: List[Evidence]) -> ScoringResult:
        """Compute a confidence score from the collected evidence items."""
        has_error = any(e.technique == "error" for e in evidence)
        canary_reflected = any(
            _CANARY_PREFIX in e.response_body_excerpt for e in evidence
        )
        sql_error_in_excerpt = any(
            any(p.search(e.response_body_excerpt) for p in _SQL_ERROR_PATTERNS)
            for e in evidence
        )

        features = {
            "sql_error_pattern": 1.0 if sql_error_in_excerpt else 0.0,
            "response_anomaly": 1.0 if has_error else 0.0,
            "canary_reflected": 1.0 if canary_reflected else 0.0,
            "multi_evidence": min(1.0, len(evidence) / 3.0),
        }
        return compute_confidence(features)

    def _build_finding(self, result: SecondOrderResult) -> Finding:
        """Construct a :class:`~sql_attacker.engine.reporting.Finding`."""
        scoring = self._score(result.evidence)
        return Finding(
            parameter=result.injection_param,
            technique="second_order",
            db_type="unknown",
            confidence=scoring.score,
            verdict=scoring.verdict,
            evidence=result.evidence,
            url=result.injection_url,
            method="POST",
            parameter_location="form_param",
            remediation=(
                "Use parameterised queries / prepared statements when storing "
                "and later retrieving user-supplied data.  Never interpolate "
                "stored values directly into SQL statements.  "
                "See https://cheatsheetseries.owasp.org/cheatsheets/"
                "SQL_Injection_Prevention_Cheat_Sheet.html"
            ),
            score_rationale=(
                f"second_order injection: injection_url={result.injection_url} "
                f"trigger_url={result.trigger_url} | {scoring.rationale}"
            ),
        )
