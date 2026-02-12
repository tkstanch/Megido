"""
Tests for World-Class Enhancements:
- Confidence Engine
- Enhanced False Positive Filter

These tests validate the new modules that reduce false positives
and improve detection accuracy.
"""

import unittest
from unittest.mock import Mock, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.confidence_engine import (
    ConfidenceEngine,
    ConfidenceFactors,
    ConfidenceLevel,
    ResponseAnalyzer,
    calculate_finding_confidence
)

from scanner.enhanced_fp_filter import (
    EnhancedFalsePositiveFilter,
    ResponseCharacteristics,
    create_filter
)


class TestConfidenceEngine(unittest.TestCase):
    """Test the Confidence Engine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = ConfidenceEngine()
    
    def test_initialization(self):
        """Test engine initializes correctly"""
        self.assertIsNotNone(self.engine)
        self.assertEqual(len(self.engine.weights), 8)
        # Weights should sum to 1.0
        self.assertAlmostEqual(sum(self.engine.weights.values()), 1.0)
    
    def test_high_confidence_verified_finding(self):
        """Test that verified findings get very high confidence"""
        factors = ConfidenceFactors(
            payload_effectiveness=0.9,
            response_anomaly=0.8,
            verification_success=1.0,  # Verified
            pattern_specificity=0.8,
            context_relevance=0.9,
            error_signature=0.8,
            timing_analysis=0.7,
            consistency_check=0.9
        )
        
        score = self.engine.calculate_confidence(
            factors,
            vulnerability_type='xss',
            metadata={'verified': True}
        )
        
        # Should be VERY_HIGH or HIGH
        self.assertGreaterEqual(score.normalized_score, 75.0)
        self.assertIn(score.confidence_level, 
                     [ConfidenceLevel.VERY_HIGH, ConfidenceLevel.HIGH])
    
    def test_low_confidence_unverified_finding(self):
        """Test that unverified findings with weak indicators get low confidence"""
        factors = ConfidenceFactors(
            payload_effectiveness=0.3,
            response_anomaly=0.2,
            verification_success=0.0,
            pattern_specificity=0.4,
            context_relevance=0.3,
            error_signature=0.2,
            timing_analysis=0.1,
            consistency_check=0.3
        )
        
        score = self.engine.calculate_confidence(
            factors,
            vulnerability_type='xss',
            metadata={'verified': False}
        )
        
        # Should be LOW or VERY_LOW
        self.assertLess(score.normalized_score, 60.0)
    
    def test_waf_detected_reduces_confidence(self):
        """Test that WAF detection reduces confidence"""
        factors = ConfidenceFactors(
            payload_effectiveness=0.7,
            response_anomaly=0.6,
            verification_success=0.0,
            pattern_specificity=0.7,
            context_relevance=0.6,
            error_signature=0.5,
            timing_analysis=0.5,
            consistency_check=0.6
        )
        
        # Without WAF
        score_no_waf = self.engine.calculate_confidence(
            factors,
            vulnerability_type='xss',
            metadata={'waf_detected': False}
        )
        
        # With WAF
        score_with_waf = self.engine.calculate_confidence(
            factors,
            vulnerability_type='xss',
            metadata={'waf_detected': True}
        )
        
        # WAF detected should reduce confidence
        self.assertLess(score_with_waf.normalized_score, score_no_waf.normalized_score)
        self.assertIn('contextual', score_with_waf.adjustments)
    
    def test_sqli_error_signature_boost(self):
        """Test that SQL injection with error signatures gets boost"""
        factors = ConfidenceFactors(
            payload_effectiveness=0.6,
            response_anomaly=0.5,
            verification_success=0.0,
            pattern_specificity=0.6,
            context_relevance=0.5,
            error_signature=0.9,  # Strong error signature
            timing_analysis=0.3,
            consistency_check=0.5
        )
        
        score = self.engine.calculate_confidence(
            factors,
            vulnerability_type='sqli',
            metadata={}
        )
        
        # Should have type-specific adjustment
        self.assertIn('type_specific', score.adjustments)
        self.assertGreater(score.adjustments['type_specific'], 0)
    
    def test_payload_effectiveness_calculation(self):
        """Test payload effectiveness calculation"""
        mock_response = Mock()
        mock_response.text = "Error: SQL syntax error near '<script>alert(1)</script>'"
        
        payload = "<script>alert(1)</script>"
        expected_indicators = ["error", "syntax", "script"]
        
        effectiveness = self.engine.calculate_payload_effectiveness(
            payload, mock_response, expected_indicators
        )
        
        # Should be > 0 since payload is reflected and indicators present
        self.assertGreater(effectiveness, 0.0)
        self.assertLessEqual(effectiveness, 1.0)
    
    def test_response_anomaly_calculation(self):
        """Test response anomaly calculation"""
        baseline = Mock()
        baseline.text = "Normal page content " * 100
        baseline.status_code = 200
        
        test_response = Mock()
        test_response.text = "Error: Database connection failed"
        test_response.status_code = 500
        
        anomaly = self.engine.calculate_response_anomaly(baseline, test_response)
        
        # Should detect anomaly
        self.assertGreater(anomaly, 0.0)
        self.assertLessEqual(anomaly, 1.0)
    
    def test_pattern_specificity(self):
        """Test pattern specificity calculation"""
        # Generic pattern
        generic = self.engine.calculate_pattern_specificity("error")
        
        # Specific pattern
        specific = self.engine.calculate_pattern_specificity(
            r'\bMySQL.*syntax.*error\b.*near.*[\'"]'
        )
        
        # Specific should score higher
        self.assertGreater(specific, generic)


class TestResponseAnalyzer(unittest.TestCase):
    """Test the Response Analyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = ResponseAnalyzer()
    
    def test_false_positive_detection(self):
        """Test detection of false positive patterns"""
        mock_response = Mock()
        mock_response.text = "404 Not Found - The page you requested does not exist"
        
        is_fp = self.analyzer.is_likely_false_positive(mock_response)
        
        self.assertTrue(is_fp)
    
    def test_waf_detection(self):
        """Test WAF detection"""
        mock_response = Mock()
        mock_response.text = "Request blocked by Cloudflare security"
        mock_response.headers = {'server': 'cloudflare'}
        
        waf_detected = self.analyzer.detect_waf(mock_response)
        
        self.assertTrue(waf_detected)
    
    def test_rate_limiting_detection(self):
        """Test rate limiting detection"""
        mock_response = Mock()
        mock_response.text = "Rate limit exceeded. Please try again later."
        mock_response.status_code = 429
        
        rate_limited = self.analyzer.detect_rate_limiting(mock_response)
        
        self.assertTrue(rate_limited)
    
    def test_normal_response_not_false_positive(self):
        """Test that normal vulnerable responses are not flagged as FP"""
        mock_response = Mock()
        mock_response.text = "Welcome to the application. Your input was: <script>alert(1)</script>"
        
        is_fp = self.analyzer.is_likely_false_positive(mock_response)
        
        self.assertFalse(is_fp)


class TestEnhancedFalsePositiveFilter(unittest.TestCase):
    """Test the Enhanced False Positive Filter"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.filter = create_filter(learning_enabled=False)  # Disable learning for tests
    
    def test_initialization(self):
        """Test filter initializes correctly"""
        self.assertIsNotNone(self.filter)
        self.assertEqual(self.filter.similarity_threshold, 0.95)
    
    def test_baseline_setting(self):
        """Test setting baseline responses"""
        mock_response = Mock()
        mock_response.text = "Normal page content"
        mock_response.status_code = 200
        mock_response.headers = {'content-type': 'text/html'}
        
        self.filter.set_baseline("http://example.com/test", mock_response)
        
        self.assertIn("http://example.com/test", self.filter.baselines)
    
    def test_404_false_positive(self):
        """Test detection of 404 as false positive"""
        mock_response = Mock()
        mock_response.text = "404 Not Found"
        mock_response.status_code = 404
        mock_response.headers = {}
        
        is_fp, reason = self.filter.is_false_positive(
            "http://example.com/test",
            mock_response,
            "test_payload"
        )
        
        self.assertTrue(is_fp)
        self.assertIn("404", reason)
    
    def test_waf_block_false_positive(self):
        """Test detection of WAF blocks as false positive"""
        mock_response = Mock()
        mock_response.text = "Your request was blocked by our security policy (Cloudflare)"
        mock_response.status_code = 403
        mock_response.headers = {'server': 'cloudflare'}
        
        is_fp, reason = self.filter.is_false_positive(
            "http://example.com/test",
            mock_response,
            "' OR '1'='1"
        )
        
        self.assertTrue(is_fp)
        self.assertIn("WAF", reason)
    
    def test_rate_limit_false_positive(self):
        """Test detection of rate limiting as false positive"""
        mock_response = Mock()
        mock_response.text = "Too many requests. Rate limit exceeded."
        mock_response.status_code = 429
        mock_response.headers = {}
        
        is_fp, reason = self.filter.is_false_positive(
            "http://example.com/test",
            mock_response,
            "test_payload"
        )
        
        self.assertTrue(is_fp)
        self.assertIn("rate_limit", reason.lower())
    
    def test_normal_response_not_false_positive(self):
        """Test that normal responses are not flagged as false positive"""
        mock_response = Mock()
        mock_response.text = "Welcome! Your search results for: <script>alert(1)</script>"
        mock_response.status_code = 200
        mock_response.headers = {'content-type': 'text/html'}
        
        is_fp, reason = self.filter.is_false_positive(
            "http://example.com/search",
            mock_response,
            "<script>alert(1)</script>",
            "xss"
        )
        
        self.assertFalse(is_fp)
    
    def test_statistics_tracking(self):
        """Test that statistics are tracked correctly"""
        mock_response = Mock()
        mock_response.text = "404 Not Found"
        mock_response.status_code = 404
        mock_response.headers = {}
        
        # Make multiple checks
        for i in range(5):
            self.filter.is_false_positive(
                f"http://example.com/test{i}",
                mock_response,
                "test_payload"
            )
        
        stats = self.filter.get_statistics()
        
        self.assertEqual(stats['total_checks'], 5)
        self.assertGreater(stats['false_positives_filtered'], 0)


class TestCalculateFindingConfidence(unittest.TestCase):
    """Test the convenience function for calculating finding confidence"""
    
    def test_verified_finding(self):
        """Test confidence calculation for verified finding"""
        finding = {
            'type': 'xss',
            'payload_effectiveness': 0.9,
            'response_anomaly': 0.8,
            'verified': True,
            'successful_payloads': 3,
        }
        
        score = calculate_finding_confidence(finding)
        
        self.assertIsNotNone(score)
        self.assertGreaterEqual(score.normalized_score, 75.0)
    
    def test_unverified_finding(self):
        """Test confidence calculation for unverified finding"""
        finding = {
            'type': 'xss',
            'payload_effectiveness': 0.5,
            'response_anomaly': 0.4,
            'verified': False,
        }
        
        score = calculate_finding_confidence(finding)
        
        self.assertIsNotNone(score)
        self.assertLess(score.normalized_score, 75.0)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestConfidenceEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestResponseAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestEnhancedFalsePositiveFilter))
    suite.addTests(loader.loadTestsFromTestCase(TestCalculateFindingConfidence))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
