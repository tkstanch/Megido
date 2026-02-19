"""
Unit tests for adaptive payload selector and fuzzy logic detector

Tests cover:
- Payload generator creating 1000+ payloads
- Adaptive selector learning from responses
- Fuzzy logic detection and classification
- Integration with SQL injection engine
"""

import unittest
import time
from sql_attacker.payload_generator import ComprehensivePayloadGenerator, generate_comprehensive_payloads
from sql_attacker.adaptive_payload_selector import AdaptivePayloadSelector, ResponseClass
from sql_attacker.fuzzy_logic_detector import FuzzyLogicDetector
from sql_attacker.payload_integration import PayloadIntegration


class TestPayloadGenerator(unittest.TestCase):
    """Test the comprehensive payload generator"""
    
    def setUp(self):
        self.generator = ComprehensivePayloadGenerator()
    
    def test_payload_count(self):
        """Test that generator creates 1000+ unique payloads"""
        payloads = self.generator.generate_all_payloads()
        self.assertGreater(len(payloads), 1000, "Should generate more than 1000 payloads")
        
        # Check uniqueness
        self.assertEqual(len(payloads), len(set(payloads)), "All payloads should be unique")
    
    def test_categorization(self):
        """Test that payloads are properly categorized"""
        self.generator.generate_all_payloads()
        categorized = self.generator.get_categorized_payloads()
        
        # Check that categories exist
        self.assertIn('boolean_based', categorized)
        self.assertIn('union_based', categorized)
        self.assertIn('time_based', categorized)
        self.assertIn('error_based', categorized)
        
        # Check that categories have payloads
        self.assertGreater(len(categorized['boolean_based']), 0)
        self.assertGreater(len(categorized['union_based']), 0)
    
    def test_waf_evasion_techniques(self):
        """Test that WAF evasion payloads are included"""
        payloads = self.generator.generate_all_payloads()
        
        # Check for various evasion techniques
        has_url_encoded = any('%' in p for p in payloads)
        has_comment_injection = any('/**/' in p for p in payloads)
        has_null_byte = any('%00' in p for p in payloads)
        
        self.assertTrue(has_url_encoded, "Should have URL encoded payloads")
        self.assertTrue(has_comment_injection, "Should have comment injection payloads")
        self.assertTrue(has_null_byte, "Should have null byte payloads")
    
    def test_sql_dialect_coverage(self):
        """Test that payloads cover multiple SQL dialects"""
        payloads = self.generator.generate_all_payloads()
        payloads_str = ' '.join(payloads).upper()
        
        # Check for dialect-specific functions
        self.assertIn('SLEEP', payloads_str, "Should have MySQL payloads")
        self.assertIn('PG_SLEEP', payloads_str, "Should have PostgreSQL payloads")
        self.assertIn('WAITFOR', payloads_str, "Should have MSSQL payloads")


class TestAdaptivePayloadSelector(unittest.TestCase):
    """Test the adaptive payload selector"""
    
    def setUp(self):
        self.selector = AdaptivePayloadSelector()
    
    def test_record_attempt(self):
        """Test recording payload attempts"""
        payload = "' OR 1=1--"
        
        self.selector.record_attempt(
            payload=payload,
            response_class=ResponseClass.SUCCESS,
            response_time=0.1,
            status_code=200,
            response_body="test response",
            payload_category="boolean"
        )
        
        # Check that stats were recorded
        self.assertIn(payload, self.selector.payload_stats)
        stats = self.selector.payload_stats[payload]
        self.assertEqual(stats.attempts, 1)
        self.assertEqual(stats.successes, 1)
    
    def test_learning_from_success(self):
        """Test that selector learns from successful payloads"""
        payload1 = "' OR 1=1--"
        payload2 = "' OR 1=2--"
        
        # Record success for payload1
        for _ in range(3):
            self.selector.record_attempt(
                payload=payload1,
                response_class=ResponseClass.SUCCESS,
                response_time=0.1,
                status_code=200,
                response_body="success",
                payload_category="boolean"
            )
        
        # Record blocks for payload2
        for _ in range(3):
            self.selector.record_attempt(
                payload=payload2,
                response_class=ResponseClass.BLOCKED,
                response_time=0.1,
                status_code=403,
                response_body="blocked",
                payload_category="boolean"
            )
        
        # Payload1 should have higher priority
        stats1 = self.selector.payload_stats[payload1]
        stats2 = self.selector.payload_stats[payload2]
        
        self.assertEqual(stats1.success_rate, 1.0)
        self.assertEqual(stats2.success_rate, 0.0)
        self.assertGreater(stats1.success_rate, stats2.success_rate)
    
    def test_mutation_generation(self):
        """Test payload mutation generation"""
        base_payload = "' OR 1=1--"
        mutations = self.selector.generate_mutations(base_payload, count=5)
        
        self.assertEqual(len(mutations), 5)
        # Mutations should be different from base
        for mutation in mutations:
            self.assertNotEqual(mutation, base_payload)
    
    def test_filter_behavior_analysis(self):
        """Test filter behavior analysis"""
        # Simulate blocked payloads with quotes
        for _ in range(3):
            self.selector.record_attempt(
                payload="' OR 1=1--",
                response_class=ResponseClass.BLOCKED,
                response_time=0.1,
                status_code=403,
                response_body="blocked",
                payload_category="boolean"
            )
        
        insights = self.selector.get_filter_insights()
        
        # Should detect that quotes are being blocked
        self.assertTrue(insights['characteristics']['blocks_quotes'])
        self.assertGreater(len(insights['recommendations']), 0)


class TestFuzzyLogicDetector(unittest.TestCase):
    """Test the fuzzy logic detector"""
    
    def setUp(self):
        # Use lower thresholds for testing to allow detection
        self.detector = FuzzyLogicDetector(
            similarity_threshold=0.85,
            confidence_threshold=0.5  # Lower threshold for testing
        )
    
    def test_baseline_setting(self):
        """Test baseline response setting"""
        self.detector.set_baseline(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Normal response",
            response_time=0.1
        )
        
        self.assertEqual(len(self.detector.baseline_signatures), 1)
    
    def test_sql_error_detection(self):
        """Test SQL error pattern detection"""
        self.detector.set_baseline(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Normal response",
            response_time=0.1
        )
        
        # Test with SQL error
        result = self.detector.analyze_response(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Error: You have an error in your SQL syntax near '1'",
            response_time=0.12,
            payload="' OR 1=1--"
        )
        
        # Should detect SQL error patterns
        self.assertGreater(len(result.matched_patterns), 0, "Should match SQL error patterns")
        # Verdict could be vulnerable, suspicious, or uncertain depending on confidence
        self.assertIn(result.verdict, ["vulnerable", "suspicious", "uncertain"])
    
    def test_false_positive_reduction(self):
        """Test that similar responses are not flagged as vulnerable"""
        self.detector.set_baseline(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Normal response with some content",
            response_time=0.1
        )
        
        # Test with very similar response (no SQL error)
        result = self.detector.analyze_response(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Normal response with some content",
            response_time=0.11,
            payload="' OR 1=1--"
        )
        
        # Should not be flagged as vulnerable due to high similarity
        self.assertIn(result.verdict, ["not_vulnerable", "uncertain"])
    
    def test_timing_anomaly_detection(self):
        """Test detection of timing anomalies (time-based SQLi)"""
        self.detector.set_baseline(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Normal response",
            response_time=0.1
        )
        
        # Test with delayed response
        result = self.detector.analyze_response(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Normal response",
            response_time=5.2,  # 5 second delay
            payload="' AND SLEEP(5)--"
        )
        
        # Should have timing anomaly indicator
        self.assertGreater(len(result.anomaly_indicators), 0)
        timing_anomaly = any('Timing anomaly' in ind for ind in result.anomaly_indicators)
        self.assertTrue(timing_anomaly)
    
    def test_fuzzy_confidence_scoring(self):
        """Test fuzzy confidence scoring"""
        self.detector.set_baseline(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Normal response",
            response_time=0.1
        )
        
        # Test with definite SQL error
        result1 = self.detector.analyze_response(
            status_code=500,
            headers={'content-type': 'text/html'},
            body="MySQL error: You have an error in your SQL syntax",
            response_time=0.15,
            payload="' OR 1=1--"
        )
        
        # Test with ambiguous response
        result2 = self.detector.analyze_response(
            status_code=200,
            headers={'content-type': 'text/html'},
            body="Page not found",
            response_time=0.12,
            payload="' OR 1=1--"
        )
        
        # Definite error should have higher confidence
        self.assertGreater(result1.confidence, result2.confidence)


class TestPayloadIntegration(unittest.TestCase):
    """Test payload integration system"""
    
    def setUp(self):
        self.integration = PayloadIntegration(storage_path='/tmp/test_payloads')
    
    def test_comprehensive_payload_generation(self):
        """Test generating comprehensive payload set"""
        count = self.integration.generate_comprehensive_payloads()
        
        self.assertGreater(count, 1000, "Should generate more than 1000 payloads")
        
        stats = self.integration.get_statistics()
        self.assertGreater(stats['total_payloads'], 1000)
    
    def test_payload_categorization(self):
        """Test that payloads are categorized"""
        self.integration.generate_comprehensive_payloads()
        stats = self.integration.get_statistics()
        
        self.assertIn('payloads_by_category', stats)
        self.assertGreater(len(stats['payloads_by_category']), 0)


if __name__ == '__main__':
    unittest.main()
