"""
Unit tests for the GraphQL SQL Injection Module.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from sql_attacker.graphql_injector import (
    GraphQLInjectionModule,
    GRAPHQL_SQL_INJECTION_PAYLOADS,
    GRAPHQL_VARIABLE_PAYLOADS,
    GRAPHQL_MUTATION_PAYLOADS,
)
from sql_attacker.injection_contexts import InjectionContextType


class TestGraphQLInjectionModule(unittest.TestCase):
    """Tests for GraphQLInjectionModule."""

    def setUp(self):
        self.module = GraphQLInjectionModule()

    # ------------------------------------------------------------------
    # Payload library
    # ------------------------------------------------------------------

    def test_payload_library_size(self):
        """At least 50 GraphQL SQL injection payloads must be defined."""
        self.assertGreaterEqual(len(GRAPHQL_SQL_INJECTION_PAYLOADS), 50)

    def test_context_type(self):
        self.assertEqual(self.module.get_context_type(), InjectionContextType.GRAPHQL)

    def test_payloads_loaded(self):
        self.assertGreater(len(self.module.payloads), 0)

    def test_detection_patterns_loaded(self):
        self.assertGreater(len(self.module.detection_patterns), 0)

    # ------------------------------------------------------------------
    # Step 1
    # ------------------------------------------------------------------

    def test_step1_supply_payloads(self):
        payloads = self.module.step1_supply_payloads("1")
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertIn("' OR 1=1--", payloads)

    # ------------------------------------------------------------------
    # Step 2
    # ------------------------------------------------------------------

    def test_step2_detect_sql_error(self):
        body = "You have an error in your SQL syntax near '1' OR '1'='1'"
        detected, anomalies = self.module.step2_detect_anomalies(body, {}, 0.1)
        self.assertTrue(detected)
        self.assertTrue(any("sql_error" in a for a in anomalies))

    def test_step2_detect_no_anomaly(self):
        body = "<html><body>Normal response</body></html>"
        detected, anomalies = self.module.step2_detect_anomalies(body, {}, 0.1)
        self.assertFalse(detected)
        self.assertEqual(len(anomalies), 0)

    def test_step2_detect_timing(self):
        baseline = ("", 0.1)
        body = "<html>ok</html>"
        detected, anomalies = self.module.step2_detect_anomalies(body, {}, 5.5, baseline)
        self.assertTrue(detected)
        self.assertTrue(any("time_based" in a for a in anomalies))

    def test_step2_detect_graphql_errors_field(self):
        body = '{"errors":[{"message":"SQL error"}]}'
        detected, anomalies = self.module.step2_detect_anomalies(body, {}, 0.1)
        self.assertTrue(detected)

    # ------------------------------------------------------------------
    # Step 3
    # ------------------------------------------------------------------

    def test_step3_extract_sql_error(self):
        body = "You have an error in your SQL syntax"
        anomalies = ["sql_error: you have an error in your sql"]
        evidence = self.module.step3_extract_evidence(body, anomalies)
        self.assertGreater(evidence["confidence"], 0.5)
        self.assertEqual(evidence["error_type"], "graphql_sqli")

    def test_step3_low_confidence_no_anomalies(self):
        evidence = self.module.step3_extract_evidence("<html>ok</html>", [])
        self.assertEqual(evidence["confidence"], 0.0)

    # ------------------------------------------------------------------
    # Step 5
    # ------------------------------------------------------------------

    def test_step5_build_poc(self):
        poc = self.module.step5_build_poc("id", "1' OR '1'='1", {})
        self.assertIn("poc_payload", poc)
        self.assertIn("reproduction_steps", poc)
        self.assertIn("safety_notes", poc)

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------

    def test_build_query_payloads(self):
        payloads = self.module.build_query_payloads("user", "id", "1' OR '1'='1")
        self.assertEqual(len(payloads), 2)
        self.assertTrue(all("user" in p for p in payloads))

    def test_build_variable_query(self):
        query, variables = self.module.build_variable_query("user", "id", "String", "1' OR '1'='1")
        self.assertIn("$val", query)
        self.assertIn("val", variables)

    def test_build_batching_attack(self):
        batch = self.module.build_batching_attack("user", "id", "1' OR '1'='1", count=5)
        self.assertEqual(len(batch), 5)
        self.assertIsInstance(batch[0], dict)

    def test_build_batching_attack_capped_at_50(self):
        batch = self.module.build_batching_attack("user", "id", "x", count=200)
        self.assertLessEqual(len(batch), 50)

    def test_build_mutation_payloads(self):
        payloads = self.module.build_mutation_payloads("admin'--")
        self.assertGreater(len(payloads), 0)
        self.assertTrue(all("mutation" in p for p in payloads))

    # ------------------------------------------------------------------
    # Endpoint detection (mocked)
    # ------------------------------------------------------------------

    def test_detect_graphql_endpoint_by_url(self):
        self.assertTrue(self.module.detect_graphql_endpoint("http://example.com/graphql"))
        self.assertTrue(self.module.detect_graphql_endpoint("http://example.com/api/graphql"))

    @patch("sql_attacker.graphql_injector.requests.post")
    def test_detect_graphql_endpoint_by_probe(self, mock_post):
        mock_response = Mock()
        mock_response.text = '{"data": {"__typename": "Query"}}'
        mock_post.return_value = mock_response
        self.assertTrue(self.module.detect_graphql_endpoint("http://example.com/api/query"))

    # ------------------------------------------------------------------
    # Introspection (mocked)
    # ------------------------------------------------------------------

    @patch("sql_attacker.graphql_injector.requests.post")
    def test_introspect_schema_returns_types(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {
                "__schema": {
                    "types": [
                        {
                            "name": "User",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "id",
                                    "args": [{"name": "where", "type": {"name": "String", "kind": "SCALAR"}}],
                                    "type": {"name": "ID", "kind": "SCALAR"},
                                }
                            ],
                        }
                    ]
                }
            }
        }
        mock_post.return_value = mock_response
        schema = self.module.introspect_schema("http://example.com/graphql")
        self.assertIn("types", schema)
        self.assertEqual(len(schema["types"]), 1)

    # ------------------------------------------------------------------
    # Variable payloads
    # ------------------------------------------------------------------

    def test_variable_payloads_defined(self):
        self.assertGreater(len(GRAPHQL_VARIABLE_PAYLOADS), 0)
        self.assertTrue(all(isinstance(p, dict) for p in GRAPHQL_VARIABLE_PAYLOADS))

    def test_mutation_payloads_defined(self):
        self.assertGreater(len(GRAPHQL_MUTATION_PAYLOADS), 0)

    # ------------------------------------------------------------------
    # analyze_response (compat)
    # ------------------------------------------------------------------

    def test_analyze_response_sql_error(self):
        body = "ORA-01756: quoted string not properly terminated"
        success, confidence, evidence = self.module.analyze_response(body, {}, 0.1)
        self.assertTrue(success)
        self.assertGreater(confidence, 0.5)

    def test_analyze_response_no_error(self):
        body = "<html>Welcome</html>"
        success, confidence, evidence = self.module.analyze_response(body, {}, 0.1)
        self.assertFalse(success)
        self.assertEqual(confidence, 0.0)


class TestGraphQLInjectionContextType(unittest.TestCase):
    """Ensure GRAPHQL is present in InjectionContextType."""

    def test_graphql_context_type_exists(self):
        self.assertIn("GRAPHQL", [t.name for t in InjectionContextType])

    def test_graphql_context_type_value(self):
        self.assertEqual(InjectionContextType.GRAPHQL.value, "graphql")


if __name__ == "__main__":
    unittest.main()
