"""
Unit tests for error-based blind SQL injection detector
"""

from django.test import TestCase
from sql_attacker.error_based_blind_detector import ErrorBasedBlindDetector, ErrorPattern


class MockResponse:
    """Mock HTTP response for testing"""
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class ErrorBasedBlindDetectorTest(TestCase):
    """Test error-based blind SQLi detection"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = ErrorBasedBlindDetector()
    
    def test_initialization(self):
        """Test detector initializes correctly"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.confidence_threshold, 0.8)
        self.assertIsNone(self.detector.baseline_pattern)
    
    def test_analyze_response_no_error(self):
        """Test response analysis without errors"""
        response = MockResponse("Normal content without errors", 200)
        pattern = self.detector.analyze_response(response, 0.5)
        
        self.assertIsInstance(pattern, ErrorPattern)
        self.assertFalse(pattern.has_error)
        self.assertEqual(pattern.status_code, 200)
        self.assertEqual(pattern.response_time, 0.5)
        self.assertEqual(len(pattern.error_indicators), 0)
    
    def test_analyze_response_http_500(self):
        """Test response analysis with HTTP 500 error"""
        response = MockResponse("Internal Server Error", 500)
        pattern = self.detector.analyze_response(response)
        
        self.assertTrue(pattern.has_error)
        self.assertEqual(pattern.status_code, 500)
        self.assertIn('HTTP 500', pattern.error_indicators)
    
    def test_analyze_response_mysql_error(self):
        """Test response analysis with MySQL error message"""
        response = MockResponse(
            "You have an error in your SQL syntax near 'LIMIT 1' at line 1",
            200
        )
        pattern = self.detector.analyze_response(response)
        
        self.assertTrue(pattern.has_error)
        self.assertGreater(len(pattern.error_indicators), 0)
    
    def test_analyze_response_division_by_zero(self):
        """Test response analysis with division by zero error"""
        response = MockResponse("Warning: Division by zero in /var/www/html/index.php", 200)
        pattern = self.detector.analyze_response(response)
        
        self.assertTrue(pattern.has_error)
    
    def test_analyze_response_mssql_error(self):
        """Test response analysis with MS-SQL error"""
        response = MockResponse("Microsoft SQL Server error: Divide by zero error encountered", 500)
        pattern = self.detector.analyze_response(response)
        
        self.assertTrue(pattern.has_error)
        self.assertGreater(len(pattern.error_indicators), 0)
    
    def test_analyze_response_oracle_error(self):
        """Test response analysis with Oracle error"""
        response = MockResponse("ORA-01476: divisor is equal to zero", 500)
        pattern = self.detector.analyze_response(response)
        
        self.assertTrue(pattern.has_error)
        self.assertGreater(len(pattern.error_indicators), 0)
    
    def test_analyze_response_postgresql_error(self):
        """Test response analysis with PostgreSQL error"""
        response = MockResponse("ERROR: division by zero", 500)
        pattern = self.detector.analyze_response(response)
        
        self.assertTrue(pattern.has_error)
    
    def test_establish_baseline(self):
        """Test baseline establishment"""
        response = MockResponse("Normal response without errors", 200)
        
        baseline = self.detector.establish_baseline(response, 0.3)
        
        self.assertIsInstance(baseline, ErrorPattern)
        self.assertIsNotNone(self.detector.baseline_pattern)
        self.assertEqual(self.detector.baseline_pattern, baseline)
        self.assertFalse(baseline.has_error)
    
    def test_conditional_error_payloads_exist(self):
        """Test that conditional error payloads are defined"""
        self.assertIn('mysql', self.detector.CONDITIONAL_ERROR_PAYLOADS)
        self.assertIn('mssql', self.detector.CONDITIONAL_ERROR_PAYLOADS)
        self.assertIn('oracle', self.detector.CONDITIONAL_ERROR_PAYLOADS)
        self.assertIn('postgresql', self.detector.CONDITIONAL_ERROR_PAYLOADS)
        
        # Check MySQL payloads
        mysql_payloads = self.detector.CONDITIONAL_ERROR_PAYLOADS['mysql']
        self.assertGreater(len(mysql_payloads), 0)
        
        # Check structure
        for payload_info in mysql_payloads:
            self.assertIn('payload_template', payload_info)
            self.assertIn('description', payload_info)
            self.assertIn('error_expected', payload_info)
            self.assertIn(payload_info['error_expected'], ['true', 'false'])
    
    def test_extraction_templates_exist(self):
        """Test that extraction templates are defined"""
        self.assertIn('mysql', self.detector.EXTRACTION_TEMPLATES)
        self.assertIn('mssql', self.detector.EXTRACTION_TEMPLATES)
        self.assertIn('oracle', self.detector.EXTRACTION_TEMPLATES)
        self.assertIn('postgresql', self.detector.EXTRACTION_TEMPLATES)
        
        # Check template structure
        mysql_templates = self.detector.EXTRACTION_TEMPLATES['mysql']
        self.assertIn('char_at_position', mysql_templates)
        self.assertIn('ascii_at_position', mysql_templates)
        self.assertIn('length_check', mysql_templates)
    
    def test_payload_formatting_mysql(self):
        """Test payload formatting for MySQL"""
        payloads = self.detector.CONDITIONAL_ERROR_PAYLOADS['mysql']
        error_payload = next(p for p in payloads if p['error_expected'] == 'true')
        
        formatted = error_payload['payload_template'].format(condition="1=1")
        
        self.assertIn("1=1", formatted)
        self.assertTrue(formatted.startswith("'"))
    
    def test_payload_formatting_mssql(self):
        """Test payload formatting for MS-SQL"""
        payloads = self.detector.CONDITIONAL_ERROR_PAYLOADS['mssql']
        error_payload = next(p for p in payloads if p['error_expected'] == 'true')
        
        formatted = error_payload['payload_template'].format(condition="1=1")
        
        self.assertIn("1=1", formatted)
        self.assertIn("CASE", formatted)
    
    def test_payload_formatting_oracle(self):
        """Test payload formatting for Oracle"""
        payloads = self.detector.CONDITIONAL_ERROR_PAYLOADS['oracle']
        error_payload = next(p for p in payloads if p['error_expected'] == 'true')
        
        formatted = error_payload['payload_template'].format(condition="1=1")
        
        self.assertIn("1=1", formatted)
        self.assertTrue("dual" in formatted or "CASE" in formatted)
    
    def test_extraction_template_formatting_mysql(self):
        """Test extraction template formatting for MySQL"""
        templates = self.detector.EXTRACTION_TEMPLATES['mysql']
        
        # Test ASCII extraction
        ascii_condition = templates['ascii_at_position'].format(
            data="@@version",
            position=1,
            ascii_code=53
        )
        self.assertIn("@@version", ascii_condition)
        self.assertIn("1", ascii_condition)
        self.assertIn("53", ascii_condition)
        self.assertIn("ASCII", ascii_condition)
        self.assertIn("SUBSTRING", ascii_condition)
    
    def test_extraction_template_formatting_oracle(self):
        """Test extraction template formatting for Oracle"""
        templates = self.detector.EXTRACTION_TEMPLATES['oracle']
        
        # Test character extraction
        char_condition = templates['char_at_position'].format(
            data="SELECT user FROM dual",
            position=1,
            char='S'
        )
        self.assertIn("SELECT user FROM dual", char_condition)
        self.assertIn("1", char_condition)
        self.assertIn("S", char_condition)
        self.assertIn("SUBSTR", char_condition)
    
    def test_generate_report_no_data(self):
        """Test report generation without detection data"""
        report = self.detector.generate_report()
        
        self.assertIsInstance(report, str)
        self.assertIn('ERROR-BASED BLIND', report)
        self.assertIn('No Conditional Error Differentiation', report)
    
    def test_generate_report_with_data(self):
        """Test report generation with detection data"""
        # Set up dummy patterns
        self.detector.true_error_patterns = [
            ErrorPattern(True, 500, ['Division by zero'], 1000, 0.5),
            ErrorPattern(True, 500, ['SQL syntax error'], 1200, 0.6),
        ]
        self.detector.false_no_error_patterns = [
            ErrorPattern(False, 200, [], 800, 0.3),
        ]
        
        report = self.detector.generate_report()
        
        self.assertIn('Conditional Error Differentiation Detected', report)
        self.assertIn('Patterns with errors (true conditions): 2', report)
        self.assertIn('Patterns without errors (false conditions): 1', report)
        self.assertIn('Division by zero', report)
    
    def test_error_indicators_comprehensive(self):
        """Test that error indicators cover major databases"""
        indicators = self.detector.ERROR_INDICATORS
        
        # MySQL indicators
        self.assertTrue(any('mysql' in i.lower() for i in indicators))
        
        # MS-SQL indicators
        self.assertTrue(any('sql server' in i.lower() or 'mssql' in i.lower() for i in indicators))
        
        # Oracle indicators
        self.assertTrue(any('ora-' in i.lower() or 'oracle' in i.lower() for i in indicators))
        
        # PostgreSQL indicators
        self.assertTrue(any('postgresql' in i.lower() or 'pg_' in i.lower() for i in indicators))
        
        # Generic indicators
        self.assertTrue(any('division by zero' in i.lower() for i in indicators))


class ErrorPatternTest(TestCase):
    """Test ErrorPattern dataclass"""
    
    def test_error_pattern_creation(self):
        """Test creating an error pattern"""
        pattern = ErrorPattern(
            has_error=True,
            status_code=500,
            error_indicators=['Division by zero', 'SQL error'],
            content_length=1500,
            response_time=0.8
        )
        
        self.assertTrue(pattern.has_error)
        self.assertEqual(pattern.status_code, 500)
        self.assertEqual(len(pattern.error_indicators), 2)
        self.assertIn('Division by zero', pattern.error_indicators)
        self.assertEqual(pattern.content_length, 1500)
        self.assertEqual(pattern.response_time, 0.8)
    
    def test_error_pattern_no_error(self):
        """Test creating an error pattern without errors"""
        pattern = ErrorPattern(
            has_error=False,
            status_code=200,
            error_indicators=[],
            content_length=500,
            response_time=0.2
        )
        
        self.assertFalse(pattern.has_error)
        self.assertEqual(pattern.status_code, 200)
        self.assertEqual(len(pattern.error_indicators), 0)
