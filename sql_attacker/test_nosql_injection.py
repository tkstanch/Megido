"""
Unit tests for the NoSQL Injection module.
"""

import unittest
from unittest.mock import Mock, patch
from sql_attacker.nosql_injector import (
    NoSQLInjector,
    NoSQLInjectionContext,
    MONGODB_OPERATOR_PAYLOADS,
    MONGODB_STRING_PAYLOADS,
    REDIS_COMMAND_INJECTION,
    COUCHDB_PAYLOADS,
    COUCHDB_STRING_PAYLOADS,
    NEO4J_CYPHER_PAYLOADS,
    NOSQL_ERROR_PATTERNS,
)
from sql_attacker.injection_contexts import InjectionContextType


class TestNoSQLPayloadLibraries(unittest.TestCase):
    """Ensure all NoSQL payload libraries are non-empty and well-formed."""

    def test_mongodb_operator_payloads(self):
        self.assertGreater(len(MONGODB_OPERATOR_PAYLOADS), 0)
        self.assertTrue(all(isinstance(p, dict) for p in MONGODB_OPERATOR_PAYLOADS))

    def test_mongodb_string_payloads(self):
        self.assertGreater(len(MONGODB_STRING_PAYLOADS), 0)
        self.assertTrue(all(isinstance(p, str) for p in MONGODB_STRING_PAYLOADS))

    def test_redis_payloads(self):
        self.assertGreater(len(REDIS_COMMAND_INJECTION), 0)
        # Should contain CRLF injection
        self.assertTrue(any("\r\n" in p or "%0d%0a" in p for p in REDIS_COMMAND_INJECTION))

    def test_couchdb_operator_payloads(self):
        self.assertGreater(len(COUCHDB_PAYLOADS), 0)

    def test_couchdb_string_payloads(self):
        self.assertGreater(len(COUCHDB_STRING_PAYLOADS), 0)

    def test_neo4j_cypher_payloads(self):
        self.assertGreater(len(NEO4J_CYPHER_PAYLOADS), 0)
        self.assertTrue(any("MATCH" in p or "OR" in p for p in NEO4J_CYPHER_PAYLOADS))

    def test_mongodb_auth_bypass_payload(self):
        # $ne:null auth bypass must exist
        has_ne_bypass = any(
            "$ne" in str(p) for p in MONGODB_OPERATOR_PAYLOADS
        )
        self.assertTrue(has_ne_bypass)

    def test_error_patterns_defined(self):
        self.assertGreater(len(NOSQL_ERROR_PATTERNS), 0)
        for pattern in NOSQL_ERROR_PATTERNS:
            self.assertIn("pattern", pattern)
            self.assertIn("type", pattern)
            self.assertIn("confidence", pattern)


class TestNoSQLInjector(unittest.TestCase):
    """Tests for NoSQLInjector helper class."""

    def setUp(self):
        self.injector = NoSQLInjector()

    # ------------------------------------------------------------------
    # Backend identification
    # ------------------------------------------------------------------

    def test_identify_mongodb(self):
        backend = self.injector.identify_nosql_backend("MongoServerError near line 1", {})
        self.assertEqual(backend, "mongodb")

    def test_identify_redis(self):
        backend = self.injector.identify_nosql_backend("-ERR unknown command", {})
        self.assertEqual(backend, "redis")

    def test_identify_couchdb(self):
        backend = self.injector.identify_nosql_backend(
            "couchdb mango query failed", {}
        )
        self.assertEqual(backend, "couchdb")

    def test_identify_neo4j(self):
        backend = self.injector.identify_nosql_backend(
            "Neo.ClientError.Statement.SyntaxError: Invalid Cypher", {}
        )
        self.assertEqual(backend, "neo4j")

    def test_identify_unknown(self):
        backend = self.injector.identify_nosql_backend("Regular page response", {})
        self.assertEqual(backend, "unknown")

    # ------------------------------------------------------------------
    # Payload retrieval
    # ------------------------------------------------------------------

    def test_get_payloads_mongodb(self):
        payloads = self.injector.get_payloads_for_backend("mongodb")
        self.assertGreater(len(payloads), 0)

    def test_get_payloads_redis(self):
        payloads = self.injector.get_payloads_for_backend("redis")
        self.assertGreater(len(payloads), 0)

    def test_get_payloads_couchdb(self):
        payloads = self.injector.get_payloads_for_backend("couchdb")
        self.assertGreater(len(payloads), 0)

    def test_get_payloads_neo4j(self):
        payloads = self.injector.get_payloads_for_backend("neo4j")
        self.assertGreater(len(payloads), 0)

    def test_get_all_payloads(self):
        all_payloads = self.injector.get_all_payloads()
        self.assertGreater(len(all_payloads), 10)

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def test_detect_mongodb_error(self):
        detected, anomalies = self.injector.detect_anomalies(
            "MongoServerError: unknown field '$hack'", {}, 0.1
        )
        self.assertTrue(detected)
        self.assertTrue(any("mongodb_error" in a for a in anomalies))

    def test_detect_redis_error(self):
        detected, anomalies = self.injector.detect_anomalies(
            "-ERR unknown command 'HACK'", {}, 0.1
        )
        self.assertTrue(detected)

    def test_detect_neo4j_error(self):
        detected, anomalies = self.injector.detect_anomalies(
            "Neo.ClientError.Statement.SyntaxError: Invalid Cypher syntax", {}, 0.1
        )
        self.assertTrue(detected)
        self.assertTrue(any("neo4j_error" in a for a in anomalies))

    def test_no_anomaly_clean_response(self):
        detected, anomalies = self.injector.detect_anomalies(
            "<html><body>Hello</body></html>", {}, 0.1
        )
        self.assertFalse(detected)
        self.assertEqual(len(anomalies), 0)

    def test_timing_anomaly(self):
        baseline = ("", 0.1)
        detected, anomalies = self.injector.detect_anomalies("<html>ok</html>", {}, 6.0, baseline)
        self.assertTrue(detected)
        self.assertTrue(any("time_based" in a for a in anomalies))

    # ------------------------------------------------------------------
    # Evidence extraction
    # ------------------------------------------------------------------

    def test_extract_evidence_mongodb(self):
        anomalies = ["mongodb_error: MongoError"]
        evidence = self.injector.extract_evidence("MongoError", anomalies)
        self.assertGreater(evidence["confidence"], 0.5)
        self.assertEqual(evidence["context_info"].get("db_type"), "mongodb")

    def test_extract_evidence_redis(self):
        anomalies = ["redis_error: -ERR"]
        evidence = self.injector.extract_evidence("-ERR", anomalies)
        self.assertGreater(evidence["confidence"], 0.5)

    def test_extract_evidence_no_anomalies(self):
        evidence = self.injector.extract_evidence("<html>ok</html>", [])
        self.assertEqual(evidence["confidence"], 0.0)


class TestNoSQLInjectionContext(unittest.TestCase):
    """Tests for NoSQLInjectionContext (InjectionAttackModule implementation)."""

    def setUp(self):
        self.ctx = NoSQLInjectionContext()

    def test_context_type(self):
        self.assertEqual(self.ctx.get_context_type(), InjectionContextType.NOSQL)

    def test_payloads_loaded(self):
        self.assertGreater(len(self.ctx.payloads), 0)

    def test_detection_patterns_loaded(self):
        self.assertGreater(len(self.ctx.detection_patterns), 0)

    def test_step1_supply_payloads(self):
        payloads = self.ctx.step1_supply_payloads("test")
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)

    def test_step2_detect_anomalies(self):
        detected, anomalies = self.ctx.step2_detect_anomalies(
            "MongoServerError near '\\$where'", {}, 0.1
        )
        self.assertTrue(detected)

    def test_step3_extract_evidence(self):
        anomalies = ["mongodb_error: MongoError"]
        evidence = self.ctx.step3_extract_evidence("MongoError", anomalies)
        self.assertIn("confidence", evidence)

    def test_step5_build_poc(self):
        poc = self.ctx.step5_build_poc("username", '{"$ne": null}', {})
        self.assertIn("poc_payload", poc)
        self.assertIn("reproduction_steps", poc)

    def test_analyze_response_detects_error(self):
        body = "MongoServerError: bad operator $hack"
        success, confidence, evidence = self.ctx.analyze_response(body, {}, 0.1)
        self.assertTrue(success)
        self.assertGreater(confidence, 0.5)

    def test_analyze_response_clean(self):
        success, confidence, evidence = self.ctx.analyze_response(
            "<html>ok</html>", {}, 0.1
        )
        self.assertFalse(success)
        self.assertEqual(confidence, 0.0)


class TestNoSQLContextTypeInEnum(unittest.TestCase):
    def test_nosql_in_enum(self):
        self.assertIn("NOSQL", [t.name for t in InjectionContextType])

    def test_nosql_value(self):
        self.assertEqual(InjectionContextType.NOSQL.value, "nosql")


if __name__ == "__main__":
    unittest.main()
