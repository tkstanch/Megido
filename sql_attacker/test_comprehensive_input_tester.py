"""
Tests for Comprehensive Input Vector Testing
"""

from django.test import TestCase
from unittest.mock import Mock, patch, MagicMock
from sql_attacker.comprehensive_input_tester import ComprehensiveInputTester
from sql_attacker.sqli_engine import SQLInjectionEngine
import requests


class ComprehensiveInputTesterTest(TestCase):
    """Test ComprehensiveInputTester class"""
    
    def setUp(self):
        """Set up test fixtures"""
        config = {
            'enable_stealth': False,
            'verify_ssl': False,
        }
        self.engine = SQLInjectionEngine(config)
        self.tester = ComprehensiveInputTester(self.engine)
    
    def test_string_concatenation_payloads(self):
        """Test that string concatenation payloads are defined for all databases"""
        self.assertIn('oracle', self.tester.STRING_CONCAT_PAYLOADS)
        self.assertIn('mssql', self.tester.STRING_CONCAT_PAYLOADS)
        self.assertIn('mysql', self.tester.STRING_CONCAT_PAYLOADS)
        self.assertIn('postgresql', self.tester.STRING_CONCAT_PAYLOADS)
        
        # Check Oracle concatenation operator
        oracle_payloads = self.tester.STRING_CONCAT_PAYLOADS['oracle']
        self.assertTrue(any("||" in p for p in oracle_payloads))
        
        # Check MS-SQL concatenation operator
        mssql_payloads = self.tester.STRING_CONCAT_PAYLOADS['mssql']
        self.assertTrue(any("+" in p for p in mssql_payloads))
        
        # Check MySQL space concatenation
        mysql_payloads = self.tester.STRING_CONCAT_PAYLOADS['mysql']
        self.assertTrue(any("' '" in p for p in mysql_payloads))
    
    def test_wildcard_payloads(self):
        """Test that SQL wildcard payloads are defined"""
        self.assertGreater(len(self.tester.WILDCARD_PAYLOADS), 0)
        self.assertTrue(any('%' in p for p in self.tester.WILDCARD_PAYLOADS))
        self.assertTrue(any("LIKE" in p for p in self.tester.WILDCARD_PAYLOADS))
    
    def test_testable_headers(self):
        """Test that common HTTP headers are defined for testing"""
        self.assertIn('User-Agent', self.tester.TESTABLE_HEADERS)
        self.assertIn('Referer', self.tester.TESTABLE_HEADERS)
        self.assertIn('X-Forwarded-For', self.tester.TESTABLE_HEADERS)
        self.assertIn('Cookie', self.tester.TESTABLE_HEADERS)
        self.assertIn('Accept-Language', self.tester.TESTABLE_HEADERS)
    
    def test_js_error_patterns(self):
        """Test that JavaScript error patterns are defined"""
        self.assertGreater(len(self.tester.JS_ERROR_PATTERNS), 0)
        self.assertTrue(any("SyntaxError" in p for p in self.tester.JS_ERROR_PATTERNS))
        self.assertTrue(any("Uncaught" in p for p in self.tester.JS_ERROR_PATTERNS))
    
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._make_request')
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._check_sql_errors')
    def test_cookie_injection_detection(self, mock_check_errors, mock_request):
        """Test detection of SQL injection in cookies"""
        # Mock response with SQL error
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "MySQL syntax error near '1'' at line 1"
        
        mock_request.return_value = mock_response
        mock_check_errors.return_value = "MySQL syntax error"
        
        # Test cookies
        cookies = {'session_id': 'abc123'}
        findings = self.tester._test_cookies(
            url='http://example.com',
            method='GET',
            params=None,
            data=None,
            cookies=cookies,
            headers=None,
            baseline=None
        )
        
        # Should detect vulnerability
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['vulnerable_parameter'], 'session_id')
        self.assertEqual(findings[0]['parameter_type'], 'COOKIE')
    
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._make_request')
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._check_sql_errors')
    def test_header_injection_detection(self, mock_check_errors, mock_request):
        """Test detection of SQL injection in HTTP headers"""
        # Mock response with SQL error
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "PostgreSQL ERROR: syntax error at or near \"'\""
        
        mock_request.return_value = mock_response
        mock_check_errors.return_value = "PostgreSQL ERROR"
        
        # Test headers
        findings = self.tester._test_http_headers(
            url='http://example.com',
            method='GET',
            params=None,
            data=None,
            cookies=None,
            headers={'User-Agent': 'TestBot/1.0'},
            baseline=None
        )
        
        # Should detect vulnerability
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['parameter_type'], 'HEADER')
    
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._make_request')
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._check_sql_errors')
    def test_parameter_name_injection(self, mock_check_errors, mock_request):
        """Test detection of SQL injection in parameter names"""
        # Mock response with SQL error
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 500
        mock_response.text = "SQLSTATE[42000]: Syntax error or access violation"
        
        mock_request.return_value = mock_response
        mock_check_errors.return_value = "SQLSTATE[42000]"
        
        # Test parameter names
        params = {'user_id': '123'}
        findings = self.tester._test_parameter_names(
            url='http://example.com',
            method='GET',
            params=params,
            data=None,
            cookies=None,
            headers=None,
            param_type='GET',
            baseline=None
        )
        
        # Should detect vulnerability
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['injection_point'], 'parameter_name')
        self.assertEqual(findings[0]['vulnerable_parameter'], 'user_id')
    
    def test_js_error_detection(self):
        """Test JavaScript error detection in responses"""
        # Mock response with JS error
        mock_response = Mock(spec=requests.Response)
        mock_response.text = "Uncaught SyntaxError: Unexpected token ' in JSON at position 0"
        
        js_error = self.tester._detect_js_errors(mock_response)
        self.assertIsNotNone(js_error)
        self.assertIn("Uncaught", js_error)
    
    def test_response_anomaly_detection_status_code(self):
        """Test response anomaly detection based on status code"""
        baseline = Mock(spec=requests.Response)
        baseline.status_code = 200
        baseline.text = "Normal response"
        
        response = Mock(spec=requests.Response)
        response.status_code = 500
        response.text = "Error response"
        
        # Different status code should trigger anomaly
        anomaly = self.tester._detect_response_anomaly(response, baseline)
        self.assertTrue(anomaly)
    
    def test_response_anomaly_detection_content_length(self):
        """Test response anomaly detection based on content length"""
        baseline = Mock(spec=requests.Response)
        baseline.status_code = 200
        baseline.text = "A" * 1000  # 1000 chars
        
        response = Mock(spec=requests.Response)
        response.status_code = 200
        response.text = "B" * 100  # 100 chars - 90% difference
        
        # Significant length difference should trigger anomaly
        anomaly = self.tester._detect_response_anomaly(response, baseline)
        self.assertTrue(anomaly)
    
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._make_request')
    def test_baseline_response_caching(self, mock_request):
        """Test that baseline responses are cached"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "Test response"
        
        mock_request.return_value = mock_response
        
        # First call should make request
        baseline1 = self.tester._get_baseline_response('http://example.com', 'GET')
        self.assertEqual(mock_request.call_count, 1)
        
        # Second call should use cache
        baseline2 = self.tester._get_baseline_response('http://example.com', 'GET')
        self.assertEqual(mock_request.call_count, 1)  # No additional call
        
        self.assertEqual(baseline1, baseline2)
    
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._make_request')
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._check_sql_errors')
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._detect_database_type')
    def test_string_concatenation_detection(self, mock_detect_db, mock_check_errors, mock_request):
        """Test detection of database-specific string concatenation"""
        # Mock Oracle response
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "ORA-00933: SQL command not properly ended"
        
        mock_request.return_value = mock_response
        mock_check_errors.return_value = "ORA-00933"
        mock_detect_db.return_value = "oracle"
        
        # Test string concatenation
        params = {'search': 'test'}
        findings = self.tester._test_string_concatenation(
            url='http://example.com',
            method='GET',
            params=params,
            data=None,
            cookies=None,
            headers=None,
            param_name='search',
            param_value='test',
            param_type='GET',
            baseline=None
        )
        
        # Should detect Oracle-specific vulnerability
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['database_type'], 'oracle')
        self.assertEqual(findings[0]['injection_type'], 'string_concatenation')
    
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._make_request')
    @patch('sql_attacker.sqli_engine.SQLInjectionEngine._check_sql_errors')
    def test_wildcard_injection_detection(self, mock_check_errors, mock_request):
        """Test detection of SQL wildcard injection"""
        # Mock response
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "MySQL error: You have an error in your SQL syntax near '%'"
        
        mock_request.return_value = mock_response
        mock_check_errors.return_value = "MySQL error"
        
        # Test wildcard payloads
        params = {'filter': 'value'}
        findings = self.tester._test_wildcard_payloads(
            url='http://example.com',
            method='GET',
            params=params,
            data=None,
            cookies=None,
            headers=None,
            param_name='filter',
            param_value='value',
            param_type='GET',
            baseline=None
        )
        
        # Should detect vulnerability
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['injection_type'], 'wildcard_injection')
    
    def test_test_all_vectors_integration(self):
        """Test that test_all_vectors calls all sub-testers"""
        with patch.object(self.tester, '_get_baseline_response') as mock_baseline:
            with patch.object(self.tester, '_test_parameter_values') as mock_param_values:
                with patch.object(self.tester, '_test_parameter_names') as mock_param_names:
                    with patch.object(self.tester, '_test_cookies') as mock_cookies:
                        with patch.object(self.tester, '_test_http_headers') as mock_headers:
                            mock_baseline.return_value = None
                            mock_param_values.return_value = []
                            mock_param_names.return_value = []
                            mock_cookies.return_value = []
                            mock_headers.return_value = []
                            
                            # Call test_all_vectors
                            self.tester.test_all_vectors(
                                url='http://example.com',
                                method='GET',
                                params={'id': '1'},
                                data={'field': 'value'},
                                cookies={'session': 'abc'},
                                headers={'User-Agent': 'test'},
                                json_data=None
                            )
                            
                            # Verify all sub-testers were called
                            self.assertTrue(mock_baseline.called)
                            self.assertTrue(mock_param_values.called)
                            self.assertTrue(mock_param_names.called)
                            self.assertTrue(mock_cookies.called)
                            self.assertTrue(mock_headers.called)
