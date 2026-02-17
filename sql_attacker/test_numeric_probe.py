"""
Unit tests for Numeric SQL Injection Prober

Tests for the NumericSqlInjector class, including:
- Payload generation and encoding
- Numeric parameter identification
- HTTP request handling
- Response analysis and vulnerability detection
"""

from django.test import TestCase
from unittest.mock import Mock, patch, MagicMock
import requests
from sql_attacker.numeric_probe import (
    NumericSqlInjector,
    NumericParameter,
    NumericInjectionResult
)


class MockResponse:
    """Mock HTTP response for testing"""
    
    def __init__(self, text: str, status_code: int = 200, headers=None):
        """
        Initialize mock response.
        
        Args:
            text: Response body text
            status_code: HTTP status code
            headers: Response headers
        """
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.content = text.encode('utf-8')


class NumericParameterTest(TestCase):
    """Test NumericParameter class"""
    
    def test_parameter_creation(self):
        """Test creating a numeric parameter"""
        param = NumericParameter(
            name='id',
            value='123',
            method='GET',
            location='query'
        )
        
        self.assertEqual(param.name, 'id')
        self.assertEqual(param.value, '123')
        self.assertEqual(param.method, 'GET')
        self.assertEqual(param.location, 'query')
    
    def test_parameter_repr(self):
        """Test string representation"""
        param = NumericParameter('page', '5', 'GET', 'query')
        repr_str = repr(param)
        
        self.assertIn('page', repr_str)
        self.assertIn('5', repr_str)
        self.assertIn('GET', repr_str)
        self.assertIn('query', repr_str)
    
    def test_parameter_to_dict(self):
        """Test converting parameter to dictionary"""
        param = NumericParameter('count', '10', 'POST', 'body')
        param_dict = param.to_dict()
        
        self.assertEqual(param_dict['name'], 'count')
        self.assertEqual(param_dict['value'], '10')
        self.assertEqual(param_dict['method'], 'POST')
        self.assertEqual(param_dict['location'], 'body')


class NumericInjectionResultTest(TestCase):
    """Test NumericInjectionResult class"""
    
    def test_result_creation(self):
        """Test creating an injection result"""
        param = NumericParameter('id', '5', 'GET', 'query')
        result = NumericInjectionResult(
            parameter=param,
            payload='5+1',
            vulnerable=True,
            confidence=0.9,
            evidence='SQL error detected',
            response_diff=0.8
        )
        
        self.assertEqual(result.parameter.name, 'id')
        self.assertEqual(result.payload, '5+1')
        self.assertTrue(result.vulnerable)
        self.assertEqual(result.confidence, 0.9)
        self.assertEqual(result.evidence, 'SQL error detected')
        self.assertEqual(result.response_diff, 0.8)
    
    def test_result_repr(self):
        """Test string representation"""
        param = NumericParameter('id', '5', 'GET', 'query')
        result = NumericInjectionResult(
            parameter=param,
            payload='5+1',
            vulnerable=True,
            confidence=0.9
        )
        repr_str = repr(result)
        
        self.assertIn('id', repr_str)
        self.assertIn('True', repr_str)
        self.assertIn('0.9', repr_str)
    
    def test_result_to_dict(self):
        """Test converting result to dictionary"""
        param = NumericParameter('user_id', '100', 'POST', 'body')
        result = NumericInjectionResult(
            parameter=param,
            payload='100+0',
            vulnerable=False,
            confidence=0.1
        )
        result_dict = result.to_dict()
        
        self.assertEqual(result_dict['payload'], '100+0')
        self.assertFalse(result_dict['vulnerable'])
        self.assertEqual(result_dict['confidence'], 0.1)
        self.assertIn('parameter', result_dict)


class NumericSqlInjectorTest(TestCase):
    """Test NumericSqlInjector class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.injector = NumericSqlInjector()
    
    def test_initialization(self):
        """Test injector initialization"""
        self.assertIsNotNone(self.injector)
        self.assertEqual(self.injector.timeout, 10)
        self.assertEqual(self.injector.max_retries, 2)
        self.assertEqual(self.injector.similarity_threshold, 0.95)
    
    def test_initialization_custom_params(self):
        """Test injector initialization with custom parameters"""
        injector = NumericSqlInjector(
            timeout=30,
            max_retries=5,
            similarity_threshold=0.90
        )
        
        self.assertEqual(injector.timeout, 30)
        self.assertEqual(injector.max_retries, 5)
        self.assertEqual(injector.similarity_threshold, 0.90)
    
    def test_is_numeric_integer(self):
        """Test numeric detection for integers"""
        self.assertTrue(self.injector._is_numeric('123'))
        self.assertTrue(self.injector._is_numeric('0'))
        self.assertTrue(self.injector._is_numeric('999'))
    
    def test_is_numeric_negative(self):
        """Test numeric detection for negative numbers"""
        self.assertTrue(self.injector._is_numeric('-123'))
        self.assertTrue(self.injector._is_numeric('-1'))
    
    def test_is_numeric_decimal(self):
        """Test numeric detection for decimal numbers"""
        self.assertTrue(self.injector._is_numeric('123.45'))
        self.assertTrue(self.injector._is_numeric('-123.45'))
        self.assertTrue(self.injector._is_numeric('0.5'))
    
    def test_is_numeric_non_numeric(self):
        """Test numeric detection for non-numeric values"""
        self.assertFalse(self.injector._is_numeric('abc'))
        self.assertFalse(self.injector._is_numeric('test123'))
        self.assertFalse(self.injector._is_numeric(''))
        self.assertFalse(self.injector._is_numeric('12.34.56'))
    
    def test_identify_numeric_parameters_from_url(self):
        """Test identifying numeric parameters from URL"""
        params = self.injector.identify_numeric_parameters(
            url='http://example.com/product?id=123&name=test&page=5',
            method='GET'
        )
        
        # Should find 'id' and 'page'
        self.assertEqual(len(params), 2)
        param_names = [p.name for p in params]
        self.assertIn('id', param_names)
        self.assertIn('page', param_names)
    
    def test_identify_numeric_parameters_from_params(self):
        """Test identifying numeric parameters from params dict"""
        params = self.injector.identify_numeric_parameters(
            url='http://example.com/product',
            method='GET',
            params={'id': '100', 'category': 'electronics'}
        )
        
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].name, 'id')
        self.assertEqual(params[0].value, '100')
        self.assertEqual(params[0].location, 'query')
    
    def test_identify_numeric_parameters_from_data(self):
        """Test identifying numeric parameters from POST data"""
        params = self.injector.identify_numeric_parameters(
            url='http://example.com/api',
            method='POST',
            data={'user_id': '456', 'username': 'john', 'age': '30'}
        )
        
        self.assertEqual(len(params), 2)
        param_names = [p.name for p in params]
        self.assertIn('user_id', param_names)
        self.assertIn('age', param_names)
        
        for param in params:
            self.assertEqual(param.location, 'body')
    
    def test_identify_numeric_parameters_from_cookies(self):
        """Test identifying numeric parameters from cookies"""
        params = self.injector.identify_numeric_parameters(
            url='http://example.com',
            method='GET',
            cookies={'session_id': 'abc123', 'user_id': '789'}
        )
        
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0].name, 'user_id')
        self.assertEqual(params[0].value, '789')
        self.assertEqual(params[0].location, 'cookie')
    
    def test_identify_numeric_parameters_from_headers(self):
        """Test identifying numeric parameters from headers"""
        params = self.injector.identify_numeric_parameters(
            url='http://example.com',
            method='GET',
            headers={'X-User-ID': '123', 'X-Request-ID': '456', 'User-Agent': 'Test'}
        )
        
        # Should find numeric headers
        self.assertGreaterEqual(len(params), 1)
        param_names = [p.name for p in params]
        self.assertIn('X-User-ID', param_names)
    
    def test_identify_numeric_parameters_no_numeric(self):
        """Test identifying parameters when none are numeric"""
        params = self.injector.identify_numeric_parameters(
            url='http://example.com?name=test&category=books',
            method='GET'
        )
        
        self.assertEqual(len(params), 0)
    
    def test_generate_payloads(self):
        """Test payload generation"""
        payloads = self.injector.generate_payloads('5')
        
        # Should generate multiple payloads
        self.assertGreater(len(payloads), 0)
        
        # Check for expected payloads
        self.assertIn('5', payloads)
        self.assertIn('5+0', payloads)
        self.assertIn('5-0', payloads)
        self.assertIn('5+1', payloads)
        self.assertIn('5-1', payloads)
        self.assertIn('67-ASCII("A")', payloads)
        self.assertIn("67-ASCII('A')", payloads)
        self.assertIn('51-ASCII(1)', payloads)
    
    def test_generate_payloads_different_value(self):
        """Test payload generation with different value"""
        payloads = self.injector.generate_payloads('100')
        
        # Check value substitution
        self.assertIn('100', payloads)
        self.assertIn('100+0', payloads)
        self.assertIn('100*1', payloads)
        self.assertIn('(100+1)-1', payloads)
    
    def test_url_encode_payload_query(self):
        """Test URL encoding for query parameters"""
        # Test special characters
        encoded = self.injector.url_encode_payload('5+1', 'query')
        self.assertEqual(encoded, '5%2B1')
        
        encoded = self.injector.url_encode_payload('5 + 1', 'query')
        self.assertEqual(encoded, '5%20%2B%201')
        
        encoded = self.injector.url_encode_payload('id=5&name=test', 'query')
        self.assertIn('%3D', encoded)  # = encoded
        self.assertIn('%26', encoded)  # & encoded
    
    def test_url_encode_payload_parentheses(self):
        """Test URL encoding of parentheses and quotes"""
        encoded = self.injector.url_encode_payload('67-ASCII("A")', 'query')
        
        # Check that special characters are encoded
        self.assertIn('%28', encoded)  # ( encoded
        self.assertIn('%29', encoded)  # ) encoded
        self.assertIn('%22', encoded)  # " encoded
    
    def test_url_encode_payload_body(self):
        """Test URL encoding for POST body"""
        encoded = self.injector.url_encode_payload('5+1', 'body')
        
        # For body, + should be encoded differently
        self.assertIn('%2B', encoded)
    
    def test_url_encode_payload_single_quotes(self):
        """Test URL encoding of single quotes"""
        encoded = self.injector.url_encode_payload("67-ASCII('A')", 'query')
        
        # Check that single quote is encoded
        self.assertIn('%27', encoded)  # ' encoded
    
    def test_calculate_similarity_identical(self):
        """Test similarity calculation for identical texts"""
        text1 = "This is a test response"
        text2 = "This is a test response"
        
        similarity = self.injector._calculate_similarity(text1, text2)
        self.assertEqual(similarity, 1.0)
    
    def test_calculate_similarity_completely_different(self):
        """Test similarity calculation for completely different texts"""
        text1 = "Hello world"
        text2 = "Goodbye universe"
        
        similarity = self.injector._calculate_similarity(text1, text2)
        self.assertLess(similarity, 0.5)
    
    def test_calculate_similarity_similar(self):
        """Test similarity calculation for similar texts"""
        text1 = "User ID 123 found in database"
        text2 = "User ID 456 found in database"
        
        similarity = self.injector._calculate_similarity(text1, text2)
        self.assertGreater(similarity, 0.7)
        self.assertLess(similarity, 1.0)
    
    def test_calculate_similarity_empty(self):
        """Test similarity calculation for empty texts"""
        similarity = self.injector._calculate_similarity('', '')
        self.assertEqual(similarity, 1.0)
        
        similarity = self.injector._calculate_similarity('test', '')
        self.assertEqual(similarity, 0.0)
        
        similarity = self.injector._calculate_similarity('', 'test')
        self.assertEqual(similarity, 0.0)
    
    def test_check_sql_errors_mysql(self):
        """Test SQL error detection for MySQL"""
        response_text = "You have an error in your SQL syntax near '1'"
        error = self.injector._check_sql_errors(response_text)
        
        self.assertIsNotNone(error)
        self.assertIn('SQL syntax', error)
    
    def test_check_sql_errors_postgresql(self):
        """Test SQL error detection for PostgreSQL"""
        response_text = "PostgreSQL ERROR: syntax error at or near \"'\""
        error = self.injector._check_sql_errors(response_text)
        
        self.assertIsNotNone(error)
        self.assertIn('PostgreSQL', error)
    
    def test_check_sql_errors_oracle(self):
        """Test SQL error detection for Oracle"""
        response_text = "ORA-00933: SQL command not properly ended"
        error = self.injector._check_sql_errors(response_text)
        
        self.assertIsNotNone(error)
        self.assertIn('ORA-', error)
    
    def test_check_sql_errors_mssql(self):
        """Test SQL error detection for MS SQL Server"""
        response_text = "Incorrect syntax near '1'"
        error = self.injector._check_sql_errors(response_text)
        
        self.assertIsNotNone(error)
        self.assertIn('Incorrect syntax', error)
    
    def test_check_sql_errors_no_error(self):
        """Test SQL error detection when no error present"""
        response_text = "Welcome to our website! Your ID is 123."
        error = self.injector._check_sql_errors(response_text)
        
        self.assertIsNone(error)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_probe_parameter_basic(self, mock_request):
        """Test probing a single parameter"""
        # Create mock responses
        baseline = MockResponse("Product ID: 5, Name: Widget", 200)
        test_response = MockResponse("Product ID: 5, Name: Widget", 200)
        
        mock_request.side_effect = [baseline, test_response]
        
        # Create parameter
        param = NumericParameter('id', '5', 'GET', 'query')
        
        # Probe parameter (will call multiple times, but we'll test with limited payloads)
        with patch.object(self.injector, 'generate_payloads', return_value=['5', '5+0']):
            results = self.injector.probe_parameter(
                url='http://example.com/product',
                parameter=param,
                method='GET',
                params={'id': '5'}
            )
        
        # Should have results
        self.assertGreater(len(results), 0)
        
        # Each result should have the correct parameter
        for result in results:
            self.assertEqual(result.parameter.name, 'id')
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_probe_parameter_sql_error_detection(self, mock_request):
        """Test detection of SQL errors during probing"""
        # Baseline is normal
        baseline = MockResponse("Product ID: 5", 200)
        
        # Test response contains SQL error
        test_response = MockResponse(
            "You have an error in your SQL syntax near '5+1'",
            200
        )
        
        mock_request.side_effect = [baseline, test_response]
        
        param = NumericParameter('id', '5', 'GET', 'query')
        
        with patch.object(self.injector, 'generate_payloads', return_value=['5+1']):
            results = self.injector.probe_parameter(
                url='http://example.com/product',
                parameter=param,
                method='GET',
                params={'id': '5'}
            )
        
        # Should detect vulnerability
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].vulnerable)
        self.assertGreater(results[0].confidence, 0.8)
        self.assertIn('SQL error', results[0].evidence)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_probe_parameter_status_code_change(self, mock_request):
        """Test detection based on status code change"""
        baseline = MockResponse("Product ID: 5", 200)
        test_response = MockResponse("Server Error", 500)
        
        mock_request.side_effect = [baseline, test_response]
        
        param = NumericParameter('id', '5', 'GET', 'query')
        
        with patch.object(self.injector, 'generate_payloads', return_value=['5+1']):
            results = self.injector.probe_parameter(
                url='http://example.com/product',
                parameter=param,
                method='GET',
                params={'id': '5'}
            )
        
        # Should detect vulnerability based on status code change
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].vulnerable)
        self.assertIn('Status code changed', results[0].evidence)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_probe_parameter_content_difference(self, mock_request):
        """Test detection based on significant content difference"""
        baseline = MockResponse("Product ID: 5, Name: Widget, Price: $10", 200)
        test_response = MockResponse("Error: Invalid product", 200)
        
        mock_request.side_effect = [baseline, test_response]
        
        param = NumericParameter('id', '5', 'GET', 'query')
        
        with patch.object(self.injector, 'generate_payloads', return_value=['5+1']):
            results = self.injector.probe_parameter(
                url='http://example.com/product',
                parameter=param,
                method='GET',
                params={'id': '5'}
            )
        
        # Should detect potential vulnerability based on content difference
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].vulnerable)
        self.assertGreater(results[0].response_diff, 0.5)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_probe_parameter_no_vulnerability(self, mock_request):
        """Test when no vulnerability is detected"""
        baseline = MockResponse("Product ID: 5, Name: Widget", 200)
        test_response = MockResponse("Product ID: 5, Name: Widget", 200)
        
        mock_request.side_effect = [baseline, test_response]
        
        param = NumericParameter('id', '5', 'GET', 'query')
        
        with patch.object(self.injector, 'generate_payloads', return_value=['5+0']):
            results = self.injector.probe_parameter(
                url='http://example.com/product',
                parameter=param,
                method='GET',
                params={'id': '5'}
            )
        
        # Should not detect vulnerability
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].vulnerable)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_probe_parameter_baseline_failure(self, mock_request):
        """Test handling when baseline request fails"""
        mock_request.return_value = None
        
        param = NumericParameter('id', '5', 'GET', 'query')
        
        results = self.injector.probe_parameter(
            url='http://example.com/product',
            parameter=param,
            method='GET',
            params={'id': '5'}
        )
        
        # Should return empty results
        self.assertEqual(len(results), 0)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector.probe_parameter')
    @patch('sql_attacker.numeric_probe.NumericSqlInjector.identify_numeric_parameters')
    def test_probe_all_parameters(self, mock_identify, mock_probe):
        """Test probing all parameters"""
        # Mock identified parameters
        param1 = NumericParameter('id', '5', 'GET', 'query')
        param2 = NumericParameter('page', '1', 'GET', 'query')
        mock_identify.return_value = [param1, param2]
        
        # Mock probe results
        result1 = NumericInjectionResult(param1, '5+1', False, 0.1)
        result2 = NumericInjectionResult(param2, '1+1', False, 0.1)
        mock_probe.side_effect = [[result1], [result2]]
        
        # Probe all parameters
        results = self.injector.probe_all_parameters(
            url='http://example.com/product?id=5&page=1',
            method='GET'
        )
        
        # Should have results from both parameters
        self.assertEqual(len(results), 2)
        self.assertEqual(mock_probe.call_count, 2)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector.identify_numeric_parameters')
    def test_probe_all_parameters_no_numeric(self, mock_identify):
        """Test probing when no numeric parameters found"""
        mock_identify.return_value = []
        
        results = self.injector.probe_all_parameters(
            url='http://example.com/page',
            method='GET'
        )
        
        self.assertEqual(len(results), 0)
    
    @patch('requests.Session.get')
    def test_make_request_get(self, mock_get):
        """Test making GET requests"""
        mock_response = MockResponse("Test response", 200)
        mock_get.return_value = mock_response
        
        response = self.injector._make_request(
            url='http://example.com',
            method='GET',
            params={'id': '5'}
        )
        
        self.assertIsNotNone(response)
        self.assertEqual(response.text, "Test response")
        mock_get.assert_called_once()
    
    @patch('requests.Session.post')
    def test_make_request_post(self, mock_post):
        """Test making POST requests"""
        mock_response = MockResponse("Test response", 200)
        mock_post.return_value = mock_response
        
        response = self.injector._make_request(
            url='http://example.com',
            method='POST',
            data={'user_id': '100'}
        )
        
        self.assertIsNotNone(response)
        self.assertEqual(response.text, "Test response")
        mock_post.assert_called_once()
    
    @patch('requests.Session.get')
    def test_make_request_failure_with_retry(self, mock_get):
        """Test request failure and retry logic"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")
        
        response = self.injector._make_request(
            url='http://example.com',
            method='GET'
        )
        
        # Should return None after retries
        self.assertIsNone(response)
        
        # Should have retried max_retries + 1 times
        self.assertEqual(mock_get.call_count, self.injector.max_retries + 1)
    
    @patch('requests.Session.get')
    def test_make_request_with_headers_and_cookies(self, mock_get):
        """Test making request with custom headers and cookies"""
        mock_response = MockResponse("Test response", 200)
        mock_get.return_value = mock_response
        
        response = self.injector._make_request(
            url='http://example.com',
            method='GET',
            headers={'X-Custom': 'value'},
            cookies={'session': 'abc123'}
        )
        
        self.assertIsNotNone(response)
        
        # Verify headers were passed
        call_args = mock_get.call_args
        self.assertIn('X-Custom', call_args.kwargs['headers'])
        self.assertEqual(call_args.kwargs['cookies'], {'session': 'abc123'})
    
    def test_analyze_response_sql_error(self):
        """Test response analysis with SQL error"""
        param = NumericParameter('id', '5', 'GET', 'query')
        baseline = MockResponse("Normal response", 200)
        test = MockResponse("SQL syntax error near '5+1'", 200)
        
        result = self.injector._analyze_response(param, '5+1', baseline, test)
        
        self.assertTrue(result.vulnerable)
        self.assertGreater(result.confidence, 0.8)
        self.assertIn('SQL error', result.evidence)
    
    def test_analyze_response_status_change(self):
        """Test response analysis with status code change"""
        param = NumericParameter('id', '5', 'GET', 'query')
        baseline = MockResponse("Normal response", 200)
        test = MockResponse("Server error", 500)
        
        result = self.injector._analyze_response(param, '5+1', baseline, test)
        
        self.assertTrue(result.vulnerable)
        self.assertIn('Status code changed', result.evidence)
    
    def test_analyze_response_large_content_diff(self):
        """Test response analysis with large content difference"""
        param = NumericParameter('id', '5', 'GET', 'query')
        baseline = MockResponse("Product details: ID=5, Name=Widget, Price=$10", 200)
        test = MockResponse("Error: Invalid product", 200)
        
        result = self.injector._analyze_response(param, '5+1', baseline, test)
        
        self.assertTrue(result.vulnerable)
        self.assertGreater(result.response_diff, 0.5)
    
    def test_analyze_response_no_vulnerability(self):
        """Test response analysis when responses are identical"""
        param = NumericParameter('id', '5', 'GET', 'query')
        baseline = MockResponse("Product ID: 5", 200)
        test = MockResponse("Product ID: 5", 200)
        
        result = self.injector._analyze_response(param, '5+0', baseline, test)
        
        self.assertFalse(result.vulnerable)
        self.assertLess(result.response_diff, 0.1)


class NumericSqlInjectorIntegrationTest(TestCase):
    """Integration tests with mocked HTTP responses"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.injector = NumericSqlInjector()
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_full_probe_workflow_vulnerable(self, mock_request):
        """Test complete probing workflow with vulnerable target"""
        # Setup: baseline is normal, one payload triggers SQL error
        baseline = MockResponse("Product: Widget (ID: 5)", 200)
        normal_response = MockResponse("Product: Widget (ID: 5)", 200)
        vulnerable_response = MockResponse(
            "MySQL error: You have an error in your SQL syntax",
            200
        )
        
        # Return baseline first, then alternate between normal and vulnerable
        mock_request.side_effect = [
            baseline,
            normal_response,  # 5
            normal_response,  # 5+0
            vulnerable_response,  # 5+1
        ]
        
        # Probe all parameters
        with patch.object(self.injector, 'generate_payloads', 
                         return_value=['5', '5+0', '5+1']):
            results = self.injector.probe_all_parameters(
                url='http://example.com/product?id=5',
                method='GET',
                params={'id': '5'}
            )
        
        # Should find at least one vulnerability
        vulnerable_results = [r for r in results if r.vulnerable]
        self.assertGreater(len(vulnerable_results), 0)
        
        # The vulnerable result should be for the 5+1 payload
        vuln = vulnerable_results[0]
        self.assertEqual(vuln.payload, '5+1')
        self.assertGreater(vuln.confidence, 0.8)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_full_probe_workflow_not_vulnerable(self, mock_request):
        """Test complete probing workflow with non-vulnerable target"""
        # All responses are identical (properly sanitized)
        response = MockResponse("Product: Widget (ID: 5)", 200)
        mock_request.return_value = response
        
        # Probe all parameters
        with patch.object(self.injector, 'generate_payloads', 
                         return_value=['5', '5+0', '5+1']):
            results = self.injector.probe_all_parameters(
                url='http://example.com/product?id=5',
                method='GET',
                params={'id': '5'}
            )
        
        # Should not find vulnerabilities
        vulnerable_results = [r for r in results if r.vulnerable]
        self.assertEqual(len(vulnerable_results), 0)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_probe_multiple_parameters(self, mock_request):
        """Test probing multiple numeric parameters"""
        baseline = MockResponse("ID: 5, Page: 1", 200)
        mock_request.return_value = baseline
        
        with patch.object(self.injector, 'generate_payloads', 
                         return_value=['5', '5+1']):
            results = self.injector.probe_all_parameters(
                url='http://example.com/product?id=5&page=1',
                method='GET'
            )
        
        # Should test both parameters
        tested_params = set(r.parameter.name for r in results)
        self.assertIn('id', tested_params)
        self.assertIn('page', tested_params)
    
    @patch('sql_attacker.numeric_probe.NumericSqlInjector._make_request')
    def test_post_request_probing(self, mock_request):
        """Test probing POST request parameters"""
        baseline = MockResponse("User created: 123", 200)
        mock_request.return_value = baseline
        
        with patch.object(self.injector, 'generate_payloads', 
                         return_value=['123', '123+0']):
            results = self.injector.probe_all_parameters(
                url='http://example.com/api/user',
                method='POST',
                data={'user_id': '123', 'name': 'John'}
            )
        
        # Should find and test user_id parameter
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].parameter.location, 'body')
