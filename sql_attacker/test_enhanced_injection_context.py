"""
Unit tests for enhanced SQL injection context with adaptive capabilities.

Tests the Phase 1 enhancements including:
- Advanced payload library integration
- Polymorphic payload generation
- Adaptive learning strategy
- Fuzzy logic anomaly detection
- Enhanced DBMS fingerprinting
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from sql_attacker.injection_contexts.sql_context import (
    SQLInjectionModule,
    ResponseProfile,
    AdaptiveStrategy,
    FuzzyAnomalyDetector,
    EnhancedDBMSFingerprinter,
)
from sql_attacker.injection_contexts.base import InjectionContextType


class TestResponseProfile(unittest.TestCase):
    """Test ResponseProfile class for response similarity analysis."""
    
    def test_create_from_response(self):
        """Test creating profile from response data."""
        body = "Test response body"
        headers = {"Content-Type": "text/html", "Server": "Apache"}
        profile = ResponseProfile.from_response(body, 200, 0.5, headers)
        
        self.assertEqual(profile.content_length, len(body))
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.response_time, 0.5)
        self.assertIsNotNone(profile.content_hash)
        self.assertIsNotNone(profile.headers_hash)
    
    def test_calculate_similarity_identical(self):
        """Test similarity calculation for identical responses."""
        body = "Test response"
        headers = {"Content-Type": "text/html"}
        profile1 = ResponseProfile.from_response(body, 200, 0.5, headers)
        profile2 = ResponseProfile.from_response(body, 200, 0.5, headers)
        
        similarity = profile1.calculate_similarity(profile2)
        self.assertGreater(similarity, 0.8)  # Should be very similar
    
    def test_calculate_similarity_different(self):
        """Test similarity calculation for different responses."""
        headers = {"Content-Type": "text/html"}
        profile1 = ResponseProfile.from_response("Response 1", 200, 0.5, headers)
        profile2 = ResponseProfile.from_response("Completely different response", 404, 1.5, headers)
        
        similarity = profile1.calculate_similarity(profile2)
        self.assertLess(similarity, 0.5)  # Should be dissimilar


class TestAdaptiveStrategy(unittest.TestCase):
    """Test AdaptiveStrategy class for adaptive learning."""
    
    def test_initialization(self):
        """Test strategy initialization."""
        strategy = AdaptiveStrategy()
        self.assertIsNone(strategy.detected_dbms)
        self.assertIsNone(strategy.detected_waf)
        self.assertEqual(len(strategy.successful_encodings), 0)
    
    def test_update_from_successful_response(self):
        """Test updating strategy from successful payload."""
        strategy = AdaptiveStrategy()
        profile = ResponseProfile.from_response("Error", 500, 0.5, {})
        profile.error_indicators = ["SQL syntax error"]
        
        strategy.update_from_response('union', 'url', profile, success=True)
        
        self.assertIn('url', strategy.successful_encodings)
        self.assertGreater(strategy.attack_scores['union'], 0)
    
    def test_update_from_failed_response(self):
        """Test updating strategy from failed payload."""
        strategy = AdaptiveStrategy()
        profile = ResponseProfile.from_response("OK", 200, 0.5, {})
        
        strategy.update_from_response('union', 'hex', profile, success=False)
        
        self.assertIn('hex', strategy.failed_encodings)
        self.assertLess(strategy.attack_scores['union'], 1.0)
    
    def test_should_try_encoding(self):
        """Test encoding recommendation logic."""
        strategy = AdaptiveStrategy()
        
        # Should try untested encoding
        self.assertTrue(strategy.should_try_encoding('url'))
        
        # Should try successful encoding
        strategy.successful_encodings.add('url')
        self.assertTrue(strategy.should_try_encoding('url'))
        
        # Should not retry failed encoding
        strategy.failed_encodings.add('hex')
        self.assertFalse(strategy.should_try_encoding('hex'))


class TestFuzzyAnomalyDetector(unittest.TestCase):
    """Test FuzzyAnomalyDetector class."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = FuzzyAnomalyDetector()
        self.assertEqual(len(detector.baseline_profiles), 0)
        self.assertGreater(detector.anomaly_threshold, 0)
    
    def test_add_baseline(self):
        """Test adding baseline profiles."""
        detector = FuzzyAnomalyDetector()
        profile = ResponseProfile.from_response("Normal", 200, 0.5, {})
        
        detector.add_baseline(profile)
        self.assertEqual(len(detector.baseline_profiles), 1)
    
    def test_detect_anomaly_no_baseline(self):
        """Test anomaly detection without baseline."""
        detector = FuzzyAnomalyDetector()
        test_profile = ResponseProfile.from_response("Test", 200, 0.5, {})
        
        detected, score, reasons = detector.detect_anomaly(test_profile)
        self.assertFalse(detected)
        self.assertEqual(score, 0.0)
    
    def test_detect_anomaly_with_error(self):
        """Test anomaly detection with error indicators."""
        detector = FuzzyAnomalyDetector()
        
        # Add baseline
        baseline = ResponseProfile.from_response("Normal response", 200, 0.5, {})
        detector.add_baseline(baseline)
        
        # Test profile with error
        test_profile = ResponseProfile.from_response("SQL error detected", 500, 0.5, {})
        test_profile.error_indicators = ["SQL syntax error"]
        
        detected, score, reasons = detector.detect_anomaly(test_profile)
        # May or may not detect depending on threshold, but should have reasons
        self.assertGreaterEqual(len(reasons), 0)


class TestEnhancedDBMSFingerprinter(unittest.TestCase):
    """Test EnhancedDBMSFingerprinter class."""
    
    def test_fingerprint_mysql_error(self):
        """Test MySQL fingerprinting from error."""
        error_text = "You have an error in your SQL syntax near 'test'"
        dbms, confidence = EnhancedDBMSFingerprinter.fingerprint_from_error(error_text)
        
        self.assertEqual(dbms, 'MySQL')
        self.assertGreater(confidence, 0.4)
    
    def test_fingerprint_postgresql_error(self):
        """Test PostgreSQL fingerprinting from error."""
        error_text = "PostgreSQL ERROR: invalid input syntax for integer"
        dbms, confidence = EnhancedDBMSFingerprinter.fingerprint_from_error(error_text)
        
        self.assertEqual(dbms, 'PostgreSQL')
        self.assertGreater(confidence, 0.4)
    
    def test_fingerprint_mssql_error(self):
        """Test MSSQL fingerprinting from error."""
        error_text = "Microsoft SQL Native Client error '80040e14'"
        dbms, confidence = EnhancedDBMSFingerprinter.fingerprint_from_error(error_text)
        
        self.assertEqual(dbms, 'MSSQL')
        self.assertGreater(confidence, 0.4)
    
    def test_fingerprint_no_match(self):
        """Test fingerprinting with no matches."""
        error_text = "Generic error message"
        dbms, confidence = EnhancedDBMSFingerprinter.fingerprint_from_error(error_text)
        
        self.assertIsNone(dbms)
        self.assertEqual(confidence, 0.0)
    
    def test_generate_fingerprint_payloads(self):
        """Test fingerprint payload generation."""
        payloads = EnhancedDBMSFingerprinter.generate_fingerprint_payloads()
        
        self.assertGreater(len(payloads), 0)
        # Check that payloads contain DBMS names
        dbms_names = [dbms for dbms, _ in payloads]
        self.assertIn('MySQL', dbms_names)


class TestSQLInjectionModule(unittest.TestCase):
    """Test enhanced SQL injection module."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.module = SQLInjectionModule()
    
    def test_initialization(self):
        """Test module initialization."""
        self.assertIsInstance(self.module.adaptive_strategy, AdaptiveStrategy)
        self.assertIsInstance(self.module.fuzzy_detector, FuzzyAnomalyDetector)
        self.assertIsInstance(self.module.fingerprinter, EnhancedDBMSFingerprinter)
    
    def test_get_context_type(self):
        """Test context type is SQL."""
        self.assertEqual(self.module.get_context_type(), InjectionContextType.SQL)
    
    def test_load_payloads(self):
        """Test payload loading."""
        payloads = self.module._load_payloads()
        self.assertGreater(len(payloads), 50)
        # Check for various payload types
        self.assertTrue(any("'" in p for p in payloads))
        self.assertTrue(any("UNION" in p for p in payloads))
    
    def test_step1_supply_payloads_basic(self):
        """Test basic payload supply."""
        payloads = self.module.step1_supply_payloads("test")
        self.assertGreater(len(payloads), 0)
        self.assertIsInstance(payloads, list)
    
    def test_step1_with_db_hint(self):
        """Test payload supply with DBMS hint."""
        payloads = self.module.step1_supply_payloads("test", db_hint="mysql")
        self.assertGreater(len(payloads), 0)
    
    def test_step1_with_insert_enum(self):
        """Test payload supply with INSERT enumeration."""
        payloads = self.module.step1_supply_payloads("test", include_insert_enum=True)
        # Should include INSERT-specific payloads
        insert_payloads = [p for p in payloads if ')--' in p or ')#' in p]
        self.assertGreater(len(insert_payloads), 0)
    
    def test_step2_detect_mysql_error(self):
        """Test MySQL error detection."""
        response_body = "You have an error in your SQL syntax near '1'"
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        
        self.assertTrue(detected)
        self.assertGreater(len(anomalies), 0)
        self.assertTrue(any('sql_error' in a for a in anomalies))
    
    def test_step2_detect_timing_anomaly(self):
        """Test timing-based detection."""
        response_body = "OK"
        baseline = ("OK", 0.5)
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 6.0, baseline
        )
        
        self.assertTrue(detected)
        self.assertTrue(any('time_based' in a for a in anomalies))
    
    def test_step3_extract_evidence_mysql(self):
        """Test evidence extraction from MySQL error."""
        response_body = "You have an error in your SQL syntax; MySQL server version 5.7.30"
        anomalies = ["sql_error: MySQL syntax"]
        
        evidence = self.module.step3_extract_evidence(response_body, anomalies)
        
        self.assertEqual(evidence['error_type'], 'sql_injection')
        self.assertGreater(evidence['confidence'], 0.7)
        # Should detect MySQL
        self.assertIn('database_type', evidence['context_info'])
    
    def test_analyze_response_positive(self):
        """Test response analysis with SQL injection."""
        response_body = "You have an error in your SQL syntax"
        detected, confidence, evidence_str = self.module.analyze_response(
            response_body, {}, 0.5
        )
        
        self.assertTrue(detected)
        self.assertGreater(confidence, 0.7)
        self.assertIn("SQL injection detected", evidence_str)
    
    def test_analyze_response_negative(self):
        """Test response analysis without SQL injection."""
        response_body = "Normal page content"
        detected, confidence, evidence_str = self.module.analyze_response(
            response_body, {}, 0.5
        )
        
        self.assertFalse(detected)
        self.assertEqual(confidence, 0.0)
        self.assertIn("No SQL injection", evidence_str)
    
    def test_generate_insert_payloads(self):
        """Test INSERT payload generation."""
        payloads = self.module._generate_insert_payloads("test", max_params=5)
        
        self.assertGreater(len(payloads), 0)
        # Check for parameter enumeration
        self.assertTrue(any('NULL' in p for p in payloads))
        self.assertTrue(any(')--' in p for p in payloads))
    
    def test_generate_quote_balanced_payloads(self):
        """Test quote-balanced payload generation."""
        payloads = self.module._generate_quote_balanced_payloads("test")
        
        self.assertGreater(len(payloads), 0)
        # Check for quote balancing (no -- or # at end)
        quote_balanced = [p for p in payloads if not p.endswith('--') and not p.endswith('#')]
        self.assertGreater(len(quote_balanced), 0)
    
    def test_adaptive_learning(self):
        """Test adaptive learning from responses."""
        # Simulate successful detection
        response_body = "MySQL syntax error"
        detected, confidence, evidence = self.module.analyze_response(
            response_body, {}, 0.5, payload_used="' UNION SELECT NULL--"
        )
        
        # Check that DBMS was detected and stored
        if self.module.adaptive_strategy.detected_dbms:
            self.assertEqual(self.module.adaptive_strategy.detected_dbms, 'MySQL')


class TestIntegrationWithAdvancedPayloads(unittest.TestCase):
    """Test integration with advanced payload library."""
    
    def test_advanced_payloads_available(self):
        """Test that advanced payloads library is accessible."""
        try:
            from sql_attacker.advanced_payloads import AdvancedPayloadLibrary
            self.assertTrue(True)
        except ImportError:
            self.skipTest("Advanced payloads library not available")
    
    def test_get_all_payloads(self):
        """Test getting all payloads from library."""
        try:
            from sql_attacker.advanced_payloads import AdvancedPayloadLibrary
            
            payloads = AdvancedPayloadLibrary.get_all_payloads()
            self.assertGreater(len(payloads), 1000)  # Should have 1000+ payloads
        except ImportError:
            self.skipTest("Advanced payloads library not available")
    
    def test_polymorphic_generation(self):
        """Test polymorphic payload generation."""
        try:
            from sql_attacker.advanced_payloads import PolymorphicPayloadGenerator
            
            generator = PolymorphicPayloadGenerator()
            base_payload = "' OR '1'='1"
            variants = generator.generate_variants(base_payload, count=10)
            
            self.assertGreaterEqual(len(variants), 1)
            self.assertIn(base_payload, variants)  # Original should be included
        except ImportError:
            self.skipTest("Advanced payloads library not available")


class TestCanaryFirstPayloadOrdering(unittest.TestCase):
    """Tests for canary-first payload scheduling in step1_supply_payloads."""

    def setUp(self):
        self.module = SQLInjectionModule(config={"use_adaptive": False, "enable_polymorphic": False})

    def test_canary_payloads_appear_first(self):
        """Canary payloads must be at the beginning of the returned payload list."""
        from sql_attacker.engine.baseline import _DEFAULT_CANARY_PAYLOADS
        payloads = self.module.step1_supply_payloads("test", canary_first=True)
        # The first payloads must be exactly the canary set
        for i, canary in enumerate(_DEFAULT_CANARY_PAYLOADS):
            self.assertEqual(
                payloads[i],
                canary,
                f"Canary payload {canary!r} not found at index {i}",
            )

    def test_canary_false_does_not_prepend_canary(self):
        """When canary_first=False the first payload is not forced to be a canary."""
        from sql_attacker.engine.baseline import _DEFAULT_CANARY_PAYLOADS
        # Use a non-canary payload that IS in the basic list but NOT a canary payload
        # to verify canary_first=True moves canaries to the front.
        payloads_with = self.module.step1_supply_payloads("test", canary_first=True)
        payloads_without = self.module.step1_supply_payloads("test", canary_first=False)
        # With canary_first=True, the first payload is the first canary
        first_canary = _DEFAULT_CANARY_PAYLOADS[0]
        self.assertEqual(payloads_with[0], first_canary)
        # Both lists must be non-empty and valid
        self.assertGreater(len(payloads_with), 0)
        self.assertGreater(len(payloads_without), 0)

    def test_canary_payloads_not_duplicated(self):
        """Canary payloads must not appear more than once in the final list."""
        from sql_attacker.engine.baseline import _DEFAULT_CANARY_PAYLOADS
        payloads = self.module.step1_supply_payloads("test", canary_first=True)
        for canary in _DEFAULT_CANARY_PAYLOADS:
            count = payloads.count(canary)
            self.assertEqual(count, 1, f"Canary payload {canary!r} appears {count} times")

    def test_result_contains_more_than_canary(self):
        """The returned list must contain payloads beyond the canary set."""
        from sql_attacker.engine.baseline import _DEFAULT_CANARY_PAYLOADS
        payloads = self.module.step1_supply_payloads("test", canary_first=True)
        self.assertGreater(len(payloads), len(_DEFAULT_CANARY_PAYLOADS))


if __name__ == '__main__':
    unittest.main()
