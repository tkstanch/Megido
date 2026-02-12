"""
Unit tests for boolean-based blind SQL injection detector
"""

from django.test import TestCase
from sql_attacker.boolean_blind_detector import BooleanBlindDetector, ResponsePattern


class MockResponse:
    """Mock HTTP response for testing"""
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class BooleanBlindDetectorTest(TestCase):
    """Test boolean-based blind SQLi detection"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = BooleanBlindDetector()
    
    def test_initialization(self):
        """Test detector initializes correctly"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.similarity_threshold, 0.95)
        self.assertEqual(self.detector.confidence_threshold, 0.9)
        self.assertEqual(len(self.detector.baseline_responses), 0)
    
    def test_analyze_response(self):
        """Test response analysis"""
        response = MockResponse("Test content with some data", 200)
        pattern = self.detector.analyze_response(response, 0.5)
        
        self.assertIsInstance(pattern, ResponsePattern)
        self.assertEqual(pattern.content, "Test content with some data")
        self.assertEqual(pattern.status_code, 200)
        self.assertEqual(pattern.response_time, 0.5)
        self.assertGreater(len(pattern.content_hash), 0)
    
    def test_calculate_similarity_identical(self):
        """Test similarity calculation for identical responses"""
        response1 = MockResponse("Identical content", 200)
        response2 = MockResponse("Identical content", 200)
        
        pattern1 = self.detector.analyze_response(response1)
        pattern2 = self.detector.analyze_response(response2)
        
        similarity = self.detector.calculate_similarity(pattern1, pattern2)
        self.assertEqual(similarity, 1.0)
    
    def test_calculate_similarity_different(self):
        """Test similarity calculation for different responses"""
        response1 = MockResponse("Content A", 200)
        response2 = MockResponse("Completely different content B", 200)
        
        pattern1 = self.detector.analyze_response(response1)
        pattern2 = self.detector.analyze_response(response2)
        
        similarity = self.detector.calculate_similarity(pattern1, pattern2)
        self.assertLess(similarity, 0.5)
    
    def test_calculate_similarity_similar(self):
        """Test similarity calculation for similar responses"""
        response1 = MockResponse("User ID 123 found in database", 200)
        response2 = MockResponse("User ID 456 found in database", 200)
        
        pattern1 = self.detector.analyze_response(response1)
        pattern2 = self.detector.analyze_response(response2)
        
        similarity = self.detector.calculate_similarity(pattern1, pattern2)
        self.assertGreater(similarity, 0.7)
        self.assertLess(similarity, 1.0)
    
    def test_establish_baseline(self):
        """Test baseline establishment"""
        response = MockResponse("Normal response without injection", 200)
        
        baseline = self.detector.establish_baseline(response, 0.3)
        
        self.assertIsInstance(baseline, ResponsePattern)
        self.assertIn('normal', self.detector.baseline_responses)
        self.assertEqual(self.detector.baseline_responses['normal'], baseline)
    
    def test_boolean_payloads_exist(self):
        """Test that boolean payloads are defined"""
        self.assertIn('numeric', self.detector.BOOLEAN_PAYLOADS)
        self.assertIn('string', self.detector.BOOLEAN_PAYLOADS)
        self.assertIn('advanced', self.detector.BOOLEAN_PAYLOADS)
        
        # Check numeric payloads
        numeric_payloads = self.detector.BOOLEAN_PAYLOADS['numeric']
        self.assertGreater(len(numeric_payloads), 0)
        
        # Check structure
        for payload_info in numeric_payloads:
            self.assertIn('payload', payload_info)
            self.assertIn('expected', payload_info)
            self.assertIn(payload_info['expected'], ['true', 'false'])
    
    def test_extraction_templates_exist(self):
        """Test that extraction templates are defined"""
        self.assertIn('mysql', self.detector.EXTRACTION_TEMPLATES)
        self.assertIn('postgresql', self.detector.EXTRACTION_TEMPLATES)
        self.assertIn('mssql', self.detector.EXTRACTION_TEMPLATES)
        self.assertIn('oracle', self.detector.EXTRACTION_TEMPLATES)
        
        # Check template structure
        mysql_templates = self.detector.EXTRACTION_TEMPLATES['mysql']
        self.assertIn('char_extraction', mysql_templates)
        self.assertIn('length_check', mysql_templates)
        self.assertIn('exists_check', mysql_templates)
    
    def test_group_similarity_identical(self):
        """Test group similarity with identical responses"""
        response1 = MockResponse("Same content", 200)
        response2 = MockResponse("Same content", 200)
        response3 = MockResponse("Same content", 200)
        
        patterns = [
            self.detector.analyze_response(response1),
            self.detector.analyze_response(response2),
            self.detector.analyze_response(response3),
        ]
        
        similarity = self.detector._calculate_group_similarity(patterns)
        self.assertGreaterEqual(similarity, 0.99)
    
    def test_group_similarity_different(self):
        """Test group similarity with different responses"""
        response1 = MockResponse("Content A", 200)
        response2 = MockResponse("Content B different", 200)
        response3 = MockResponse("Content C completely different", 200)
        
        patterns = [
            self.detector.analyze_response(response1),
            self.detector.analyze_response(response2),
            self.detector.analyze_response(response3),
        ]
        
        similarity = self.detector._calculate_group_similarity(patterns)
        self.assertLess(similarity, 0.5)
    
    def test_cross_similarity(self):
        """Test cross-group similarity"""
        true_responses = [
            MockResponse("Valid user found", 200),
            MockResponse("Valid user exists", 200),
        ]
        
        false_responses = [
            MockResponse("Invalid user", 404),
            MockResponse("User not found", 404),
        ]
        
        true_patterns = [self.detector.analyze_response(r) for r in true_responses]
        false_patterns = [self.detector.analyze_response(r) for r in false_responses]
        
        cross_sim = self.detector._calculate_cross_similarity(true_patterns, false_patterns)
        
        # Should be different
        self.assertLess(cross_sim, 0.8)
    
    def test_generate_report_no_data(self):
        """Test report generation without detection data"""
        report = self.detector.generate_report()
        
        self.assertIsInstance(report, str)
        self.assertIn('BOOLEAN-BASED BLIND', report)
        self.assertIn('No Boolean Differentiation', report)
    
    def test_generate_report_with_data(self):
        """Test report generation with detection data"""
        # Set up dummy responses
        self.detector.true_responses = [
            self.detector.analyze_response(MockResponse("True response", 200))
        ]
        self.detector.false_responses = [
            self.detector.analyze_response(MockResponse("False response", 404))
        ]
        
        report = self.detector.generate_report()
        
        self.assertIn('Boolean Differentiation Detected', report)
        self.assertIn('True Responses: 1', report)
        self.assertIn('False Responses: 1', report)


class ResponsePatternTest(TestCase):
    """Test ResponsePattern dataclass"""
    
    def test_response_pattern_creation(self):
        """Test creating a response pattern"""
        pattern = ResponsePattern(
            content="Test content",
            content_length=100,
            content_hash="abc123",
            status_code=200,
            response_time=0.5,
            headers={'Content-Type': 'text/html'}
        )
        
        self.assertEqual(pattern.content, "Test content")
        self.assertEqual(pattern.content_length, 100)
        self.assertEqual(pattern.content_hash, "abc123")
        self.assertEqual(pattern.status_code, 200)
        self.assertEqual(pattern.response_time, 0.5)
        self.assertEqual(pattern.headers['Content-Type'], 'text/html')
