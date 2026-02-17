"""
Unit tests for multi-context injection framework.

Tests each injection context and the orchestrator.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from sql_attacker.injection_contexts import (
    InjectionContextType,
    InjectionResult,
    AttackVector,
)
from sql_attacker.injection_contexts.sql_context import SQLInjectionContext
from sql_attacker.injection_contexts.ldap_context import LDAPInjectionContext
from sql_attacker.injection_contexts.xpath_context import XPathInjectionContext
from sql_attacker.injection_contexts.message_queue_context import MessageQueueInjectionContext
from sql_attacker.injection_contexts.custom_query_context import CustomQueryInjectionContext
from sql_attacker.multi_context_orchestrator import MultiContextAttackOrchestrator


class TestSQLInjectionContext(unittest.TestCase):
    """Test SQL injection context."""
    
    def setUp(self):
        self.context = SQLInjectionContext()
    
    def test_context_type(self):
        """Test context type is correct."""
        self.assertEqual(self.context.get_context_type(), InjectionContextType.SQL)
    
    def test_payloads_loaded(self):
        """Test that payloads are loaded."""
        self.assertGreater(len(self.context.payloads), 0)
        self.assertIn("' OR '1'='1", self.context.payloads)
    
    def test_detection_patterns_loaded(self):
        """Test that detection patterns are loaded."""
        self.assertGreater(len(self.context.detection_patterns), 0)
    
    def test_analyze_response_sql_error(self):
        """Test SQL error detection in response."""
        response_body = "You have an error in your SQL syntax near '1'"
        success, confidence, evidence = self.context.analyze_response(
            response_body, {}, 0.5
        )
        self.assertTrue(success)
        self.assertGreater(confidence, 0.8)
        self.assertIn("SQL", evidence)
    
    def test_analyze_response_no_error(self):
        """Test no false positive on clean response."""
        response_body = "Welcome to our website"
        success, confidence, evidence = self.context.analyze_response(
            response_body, {}, 0.5
        )
        self.assertFalse(success)
        self.assertEqual(confidence, 0.0)


class TestLDAPInjectionContext(unittest.TestCase):
    """Test LDAP injection context."""
    
    def setUp(self):
        self.context = LDAPInjectionContext()
    
    def test_context_type(self):
        """Test context type is correct."""
        self.assertEqual(self.context.get_context_type(), InjectionContextType.LDAP)
    
    def test_payloads_loaded(self):
        """Test that LDAP payloads are loaded."""
        self.assertGreater(len(self.context.payloads), 0)
        self.assertIn("*", self.context.payloads)
        self.assertIn("*)(&", self.context.payloads)
    
    def test_analyze_response_ldap_error(self):
        """Test LDAP error detection."""
        response_body = "LDAP error: Invalid filter syntax"
        success, confidence, evidence = self.context.analyze_response(
            response_body, {}, 0.5
        )
        self.assertTrue(success)
        self.assertGreater(confidence, 0.8)


class TestXPathInjectionContext(unittest.TestCase):
    """Test XPath injection context."""
    
    def setUp(self):
        self.context = XPathInjectionContext()
    
    def test_context_type(self):
        """Test context type is correct."""
        self.assertEqual(self.context.get_context_type(), InjectionContextType.XPATH)
    
    def test_payloads_loaded(self):
        """Test that XPath payloads are loaded."""
        self.assertGreater(len(self.context.payloads), 0)
        self.assertIn("' or '1'='1", self.context.payloads)
    
    def test_analyze_response_xpath_error(self):
        """Test XPath error detection."""
        response_body = "XPath syntax error at position 5"
        success, confidence, evidence = self.context.analyze_response(
            response_body, {}, 0.5
        )
        self.assertTrue(success)
        self.assertGreater(confidence, 0.8)


class TestMessageQueueInjectionContext(unittest.TestCase):
    """Test Message Queue injection context."""
    
    def setUp(self):
        self.context = MessageQueueInjectionContext()
    
    def test_context_type(self):
        """Test context type is correct."""
        self.assertEqual(self.context.get_context_type(), InjectionContextType.MESSAGE_QUEUE)
    
    def test_payloads_loaded(self):
        """Test that message queue payloads are loaded."""
        self.assertGreater(len(self.context.payloads), 0)
        self.assertIn('{"admin": true}', self.context.payloads)


class TestCustomQueryInjectionContext(unittest.TestCase):
    """Test Custom Query injection context."""
    
    def setUp(self):
        self.context = CustomQueryInjectionContext()
    
    def test_context_type(self):
        """Test context type is correct."""
        self.assertEqual(self.context.get_context_type(), InjectionContextType.CUSTOM_QUERY)
    
    def test_payloads_loaded(self):
        """Test that custom query payloads are loaded."""
        self.assertGreater(len(self.context.payloads), 0)
        # Should have GraphQL payloads
        graphql_payloads = [p for p in self.context.payloads if '__schema' in p]
        self.assertGreater(len(graphql_payloads), 0)


class TestMultiContextOrchestrator(unittest.TestCase):
    """Test multi-context attack orchestrator."""
    
    def setUp(self):
        self.orchestrator = MultiContextAttackOrchestrator({
            'enabled_contexts': [
                InjectionContextType.SQL,
                InjectionContextType.LDAP,
            ],
            'parallel_execution': False,  # Sequential for easier testing
        })
    
    def test_initialization(self):
        """Test orchestrator initializes correctly."""
        self.assertEqual(len(self.orchestrator.contexts), 2)
        self.assertIn(InjectionContextType.SQL, self.orchestrator.contexts)
        self.assertIn(InjectionContextType.LDAP, self.orchestrator.contexts)
    
    def test_get_context_statistics(self):
        """Test context statistics generation."""
        stats = self.orchestrator.get_context_statistics()
        self.assertEqual(stats['enabled_contexts'], 2)
        self.assertGreater(stats['total_payloads'], 0)
        self.assertIn('sql', stats['contexts'])
        self.assertIn('ldap', stats['contexts'])
    
    @patch('requests.get')
    def test_test_all_contexts(self, mock_get):
        """Test testing all contexts (mocked requests)."""
        # Mock successful SQL injection response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "You have an error in your SQL syntax"
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        results = self.orchestrator.test_all_contexts(
            target_url="http://example.com/test",
            parameter_name="id",
            parameter_type="GET",
            parameter_value="1",
        )
        
        # Should find SQL injection
        self.assertGreater(len(results), 0)
        sql_results = [r for r in results if r.context_type == InjectionContextType.SQL]
        self.assertGreater(len(sql_results), 0)
    
    def test_generate_attack_report(self):
        """Test attack report generation."""
        # Create mock results
        attack_vector = AttackVector(
            context_type=InjectionContextType.SQL,
            parameter_name="id",
            parameter_type="GET",
            payload="' OR '1'='1",
            description="SQL injection test"
        )
        
        result = InjectionResult(
            success=True,
            context_type=InjectionContextType.SQL,
            attack_vector=attack_vector,
            evidence="SQL error detected",
            confidence_score=0.95,
            response_time=0.5,
            response_status=200,
            response_body="Error in SQL syntax",
            exploited=True,
        )
        
        report = self.orchestrator.generate_attack_report(
            [result],
            "http://example.com/test",
            "id"
        )
        
        self.assertEqual(report['total_vulnerabilities'], 1)
        self.assertEqual(report['contexts_affected'], 1)
        self.assertIn('sql', report['vulnerabilities_by_context'])
        self.assertEqual(len(report['high_confidence_findings']), 1)
        self.assertEqual(len(report['exploited_vulnerabilities']), 1)


class TestInjectionPayloadInjection(unittest.TestCase):
    """Test payload injection strategies."""
    
    def test_default_injection_strategy(self):
        """Test default payload injection (append)."""
        context = SQLInjectionContext()
        injected = context._inject_payload("test", "' OR '1'='1")
        self.assertEqual(injected, "test' OR '1'='1")
    
    def test_empty_original_value(self):
        """Test injection with empty original value."""
        context = SQLInjectionContext()
        injected = context._inject_payload("", "' OR '1'='1")
        self.assertEqual(injected, "' OR '1'='1")


class TestAttackVector(unittest.TestCase):
    """Test AttackVector data structure."""
    
    def test_attack_vector_creation(self):
        """Test creating an attack vector."""
        vector = AttackVector(
            context_type=InjectionContextType.SQL,
            parameter_name="username",
            parameter_type="POST",
            payload="admin'--",
            description="SQL injection via POST parameter"
        )
        
        self.assertEqual(vector.context_type, InjectionContextType.SQL)
        self.assertEqual(vector.parameter_name, "username")
        self.assertEqual(vector.payload, "admin'--")


class TestInjectionResult(unittest.TestCase):
    """Test InjectionResult data structure."""
    
    def test_result_creation(self):
        """Test creating an injection result."""
        vector = AttackVector(
            context_type=InjectionContextType.LDAP,
            parameter_name="user",
            parameter_type="GET",
            payload="*",
            description="LDAP injection test"
        )
        
        result = InjectionResult(
            success=True,
            context_type=InjectionContextType.LDAP,
            attack_vector=vector,
            evidence="LDAP error message detected",
            confidence_score=0.90,
            response_time=0.3,
            response_status=500,
            response_body="LDAP error: Invalid filter",
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.confidence_score, 0.90)
        self.assertEqual(result.context_type, InjectionContextType.LDAP)
    
    def test_proof_snippet(self):
        """Test proof snippet generation."""
        vector = AttackVector(
            context_type=InjectionContextType.SQL,
            parameter_name="id",
            parameter_type="GET",
            payload="'",
            description="Test"
        )
        
        long_body = "x" * 1000
        result = InjectionResult(
            success=True,
            context_type=InjectionContextType.SQL,
            attack_vector=vector,
            evidence="Test",
            confidence_score=0.8,
            response_time=0.5,
            response_status=200,
            response_body=long_body,
        )
        
        snippet = result.get_proof_snippet(max_length=500)
        self.assertEqual(len(snippet), 503)  # 500 + "..."
        self.assertTrue(snippet.endswith("..."))


if __name__ == '__main__':
    unittest.main()
