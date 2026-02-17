"""
Numeric SQL Injection Prober

This module provides functionality to probe numeric parameters for SQL injection
vulnerabilities using numeric-based payloads that are less likely to be detected
by WAFs and input validation filters.

Key Features:
- Identify numeric parameters from HTTP requests
- Generate numeric SQL injection payloads (arithmetic operations)
- URL-encode payloads with proper handling of special characters
- Send tampered requests and analyze responses for vulnerabilities
- Preserve HTTP method (GET/POST) and compare responses to baseline

Author: Megido Security Testing Framework
"""

import logging
import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlencode, parse_qs, urlparse, quote, quote_plus
import requests
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class NumericParameter:
    """
    Represents a numeric parameter discovered in an HTTP request.
    
    Attributes:
        name: Parameter name
        value: Original parameter value
        method: HTTP method (GET, POST, etc.)
        location: Where the parameter was found (query, body, cookie, header)
    """
    
    def __init__(self, name: str, value: str, method: str, location: str):
        """
        Initialize a numeric parameter.
        
        Args:
            name: Parameter name
            value: Original parameter value
            method: HTTP method (GET, POST, etc.)
            location: Parameter location (query, body, cookie, header)
        """
        self.name = name
        self.value = value
        self.method = method
        self.location = location
    
    def __repr__(self):
        return f"NumericParameter(name={self.name}, value={self.value}, method={self.method}, location={self.location})"
    
    def to_dict(self) -> Dict[str, str]:
        """
        Convert parameter to dictionary representation.
        
        Returns:
            Dictionary with parameter details
        """
        return {
            'name': self.name,
            'value': self.value,
            'method': self.method,
            'location': self.location
        }


class NumericInjectionResult:
    """
    Represents the result of a numeric SQL injection probe.
    
    Attributes:
        parameter: The tested parameter
        payload: The payload that was tested
        vulnerable: Whether vulnerability was detected
        confidence: Confidence score (0.0 to 1.0)
        evidence: Evidence of vulnerability
        response_diff: Difference in response compared to baseline
    """
    
    def __init__(self, parameter: NumericParameter, payload: str, 
                 vulnerable: bool = False, confidence: float = 0.0,
                 evidence: str = "", response_diff: float = 0.0):
        """
        Initialize an injection result.
        
        Args:
            parameter: The tested parameter
            payload: The payload that was tested
            vulnerable: Whether vulnerability was detected
            confidence: Confidence score (0.0 to 1.0)
            evidence: Evidence of vulnerability
            response_diff: Difference in response compared to baseline
        """
        self.parameter = parameter
        self.payload = payload
        self.vulnerable = vulnerable
        self.confidence = confidence
        self.evidence = evidence
        self.response_diff = response_diff
    
    def __repr__(self):
        return (f"NumericInjectionResult(parameter={self.parameter.name}, "
                f"vulnerable={self.vulnerable}, confidence={self.confidence:.2f})")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert result to dictionary representation.
        
        Returns:
            Dictionary with result details
        """
        return {
            'parameter': self.parameter.to_dict(),
            'payload': self.payload,
            'vulnerable': self.vulnerable,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'response_diff': self.response_diff
        }


class NumericSqlInjector:
    """
    SQL Injection prober specialized for numeric parameters.
    
    This class identifies numeric parameters and tests them using arithmetic-based
    SQL injection payloads that are less likely to trigger WAFs or input validation.
    
    Example Usage:
        injector = NumericSqlInjector()
        
        # Identify numeric parameters
        params = injector.identify_numeric_parameters(
            url='http://example.com/product?id=5&page=1',
            method='GET'
        )
        
        # Probe parameters for vulnerabilities
        results = injector.probe_all_parameters(
            url='http://example.com/product?id=5',
            method='GET',
            params={'id': '5'}
        )
        
        # Check for vulnerabilities
        for result in results:
            if result.vulnerable:
                print(f"Vulnerable parameter: {result.parameter.name}")
                print(f"Payload: {result.payload}")
                print(f"Confidence: {result.confidence}")
    """
    
    # Numeric SQL injection payloads
    # These payloads use arithmetic operations that may behave differently
    # when interpreted by SQL databases vs. application code
    NUMERIC_PAYLOADS = [
        # Basic arithmetic that should return original value
        '{value}',           # Baseline
        '{value}+0',         # Addition of zero
        '{value}-0',         # Subtraction of zero
        '{value}*1',         # Multiplication by one
        '{value}/1',         # Division by one
        
        # Arithmetic that changes the value
        '{value}+1',         # Addition
        '{value}-1',         # Subtraction
        '1+{value}',         # Reverse addition
        '{value}*2',         # Multiplication
        
        # ASCII/CHAR operations
        '67-ASCII("A")',     # 67-65=2 (ASCII of 'A' is 65)
        '67-ASCII(\'A\')',   # Same with single quotes
        '51-ASCII(1)',       # 51-49=2 (ASCII of '1' is 49)
        'ASCII("B")-64',     # 66-64=2 (ASCII of 'B' is 66)
        
        # Bitwise operations
        '{value}|0',         # Bitwise OR with 0
        '{value}&{value}',   # Bitwise AND with itself
        '{value}^0',         # Bitwise XOR with 0
        
        # Nested arithmetic
        '({value}+1)-1',     # Should equal original
        '({value}*2)/2',     # Should equal original
        '{value}+(2-2)',     # Addition of zero with expression
    ]
    
    # Patterns to identify numeric parameters
    NUMERIC_PATTERNS = [
        r'^\d+$',                    # Pure numeric: 123
        r'^\d+\.\d+$',              # Decimal: 123.45
        r'^-?\d+$',                 # Signed integer: -123
        r'^-?\d+\.\d+$',            # Signed decimal: -123.45
    ]
    
    # HTTP special characters that need encoding
    SPECIAL_CHARS = {
        ' ': '%20',   # Space
        '+': '%2B',   # Plus (already used for space in forms)
        '=': '%3D',   # Equals
        '&': '%26',   # Ampersand
        ';': '%3B',   # Semicolon
        '#': '%23',   # Hash
        '?': '%3F',   # Question mark
        '/': '%2F',   # Forward slash
        '(': '%28',   # Left parenthesis
        ')': '%29',   # Right parenthesis
        '"': '%22',   # Double quote
        "'": '%27',   # Single quote
    }
    
    def __init__(self, timeout: int = 10, max_retries: int = 2,
                 similarity_threshold: float = 0.95):
        """
        Initialize the NumericSqlInjector.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts for failed requests
            similarity_threshold: Threshold for response similarity comparison (0.0 to 1.0)
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.similarity_threshold = similarity_threshold
        self.session = requests.Session()
        
        # User agent for requests
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    def identify_numeric_parameters(self, url: str, method: str = 'GET',
                                   params: Optional[Dict[str, str]] = None,
                                   data: Optional[Dict[str, str]] = None,
                                   cookies: Optional[Dict[str, str]] = None,
                                   headers: Optional[Dict[str, str]] = None
                                   ) -> List[NumericParameter]:
        """
        Identify numeric parameters from an HTTP request.
        
        This method analyzes the URL query string, POST data, cookies, and headers
        to identify parameters that contain numeric values.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            params: Query parameters (GET)
            data: Body data (POST)
            cookies: Cookie values
            headers: HTTP headers
        
        Returns:
            List of NumericParameter objects representing identified numeric parameters
        
        Example:
            >>> injector = NumericSqlInjector()
            >>> params = injector.identify_numeric_parameters(
            ...     url='http://example.com/product?id=123&name=test',
            ...     method='GET'
            ... )
            >>> len(params)
            1
            >>> params[0].name
            'id'
        """
        numeric_params = []
        
        # Parse URL for query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Check query parameters
        for param_name, param_values in query_params.items():
            for param_value in param_values:
                if self._is_numeric(param_value):
                    numeric_params.append(
                        NumericParameter(param_name, param_value, method, 'query')
                    )
                    logger.debug(f"Identified numeric query parameter: {param_name}={param_value}")
        
        # Check GET params if provided separately
        if params:
            for param_name, param_value in params.items():
                if self._is_numeric(str(param_value)):
                    # Avoid duplicates from URL parsing
                    if not any(p.name == param_name and p.location == 'query' 
                             for p in numeric_params):
                        numeric_params.append(
                            NumericParameter(param_name, str(param_value), method, 'query')
                        )
                        logger.debug(f"Identified numeric GET parameter: {param_name}={param_value}")
        
        # Check POST data
        if data:
            for param_name, param_value in data.items():
                if self._is_numeric(str(param_value)):
                    numeric_params.append(
                        NumericParameter(param_name, str(param_value), method, 'body')
                    )
                    logger.debug(f"Identified numeric POST parameter: {param_name}={param_value}")
        
        # Check cookies
        if cookies:
            for cookie_name, cookie_value in cookies.items():
                if self._is_numeric(str(cookie_value)):
                    numeric_params.append(
                        NumericParameter(cookie_name, str(cookie_value), method, 'cookie')
                    )
                    logger.debug(f"Identified numeric cookie: {cookie_name}={cookie_value}")
        
        # Check specific headers that commonly contain numeric values
        numeric_headers = ['X-Request-ID', 'X-Session-ID', 'X-User-ID', 'X-Account-ID']
        if headers:
            for header_name in numeric_headers:
                if header_name in headers:
                    header_value = headers[header_name]
                    if self._is_numeric(str(header_value)):
                        numeric_params.append(
                            NumericParameter(header_name, str(header_value), method, 'header')
                        )
                        logger.debug(f"Identified numeric header: {header_name}={header_value}")
        
        logger.info(f"Identified {len(numeric_params)} numeric parameter(s)")
        return numeric_params
    
    def _is_numeric(self, value: str) -> bool:
        """
        Check if a value is numeric.
        
        Args:
            value: Value to check
        
        Returns:
            True if value matches numeric patterns, False otherwise
        """
        if not value:
            return False
        
        # Check against numeric patterns
        for pattern in self.NUMERIC_PATTERNS:
            if re.match(pattern, value.strip()):
                return True
        
        return False
    
    def generate_payloads(self, original_value: str) -> List[str]:
        """
        Generate numeric SQL injection payloads for a given value.
        
        This method creates a list of SQL injection payloads that use arithmetic
        operations. These payloads are designed to detect SQL injection vulnerabilities
        while being less suspicious to WAFs.
        
        Args:
            original_value: Original numeric parameter value
        
        Returns:
            List of generated payload strings
        
        Example:
            >>> injector = NumericSqlInjector()
            >>> payloads = injector.generate_payloads('5')
            >>> '5+0' in payloads
            True
            >>> '5+1' in payloads
            True
            >>> '67-ASCII("A")' in payloads
            True
        """
        payloads = []
        
        for payload_template in self.NUMERIC_PAYLOADS:
            # Replace {value} placeholder with actual value
            payload = payload_template.replace('{value}', original_value)
            payloads.append(payload)
        
        logger.debug(f"Generated {len(payloads)} payload(s) for value '{original_value}'")
        return payloads
    
    def url_encode_payload(self, payload: str, encode_for: str = 'query') -> str:
        """
        URL-encode a payload with proper handling of HTTP special characters.
        
        This method encodes special characters that have meaning in HTTP requests
        (&, =, +, ;, space) while preserving the SQL injection payload structure.
        Different encoding strategies are used for query strings vs. POST data.
        
        Args:
            payload: Payload to encode
            encode_for: Context for encoding ('query' or 'body')
        
        Returns:
            URL-encoded payload string
        
        Example:
            >>> injector = NumericSqlInjector()
            >>> injector.url_encode_payload('5+1', 'query')
            '5%2B1'
            >>> injector.url_encode_payload('67-ASCII("A")', 'query')
            '67-ASCII%28%22A%22%29'
        """
        if encode_for == 'query':
            # For query strings, encode special characters
            # Use quote_plus which converts spaces to + and encodes other special chars
            # But we need to encode + as %2B to prevent it being interpreted as space
            encoded = quote(payload, safe='')
        elif encode_for == 'body':
            # For POST body with application/x-www-form-urlencoded
            # Use quote_plus which is standard for form encoding
            encoded = quote_plus(payload)
        else:
            # Default to query encoding
            encoded = quote(payload, safe='')
        
        logger.debug(f"Encoded payload '{payload}' to '{encoded}' for {encode_for}")
        return encoded
    
    def probe_parameter(self, url: str, parameter: NumericParameter,
                       method: str = 'GET',
                       params: Optional[Dict[str, str]] = None,
                       data: Optional[Dict[str, str]] = None,
                       cookies: Optional[Dict[str, str]] = None,
                       headers: Optional[Dict[str, str]] = None
                       ) -> List[NumericInjectionResult]:
        """
        Probe a single numeric parameter for SQL injection vulnerabilities.
        
        This method sends multiple requests with different payloads and compares
        the responses to detect potential SQL injection vulnerabilities.
        
        Args:
            url: Target URL
            parameter: NumericParameter to probe
            method: HTTP method (GET, POST, etc.)
            params: Query parameters
            data: POST data
            cookies: Cookies
            headers: HTTP headers
        
        Returns:
            List of NumericInjectionResult objects
        
        Example:
            >>> injector = NumericSqlInjector()
            >>> param = NumericParameter('id', '5', 'GET', 'query')
            >>> results = injector.probe_parameter(
            ...     url='http://example.com/product',
            ...     parameter=param,
            ...     method='GET',
            ...     params={'id': '5'}
            ... )
        """
        results = []
        
        # Get baseline response with original value
        logger.info(f"Getting baseline response for parameter '{parameter.name}'")
        baseline_response = self._make_request(
            url, method, params, data, cookies, headers
        )
        
        if not baseline_response:
            logger.warning(f"Failed to get baseline response for '{parameter.name}'")
            return results
        
        # Generate payloads
        payloads = self.generate_payloads(parameter.value)
        
        # Test each payload
        for payload in payloads:
            logger.debug(f"Testing payload '{payload}' on parameter '{parameter.name}'")
            
            # Create modified request parameters
            test_params = params.copy() if params else {}
            test_data = data.copy() if data else {}
            test_cookies = cookies.copy() if cookies else {}
            test_headers = headers.copy() if headers else {}
            
            # URL-encode the payload based on parameter location
            if parameter.location == 'query':
                encoded_payload = self.url_encode_payload(payload, 'query')
                test_params[parameter.name] = encoded_payload
            elif parameter.location == 'body':
                encoded_payload = self.url_encode_payload(payload, 'body')
                test_data[parameter.name] = encoded_payload
            elif parameter.location == 'cookie':
                # Cookies are typically not URL-encoded by the client
                test_cookies[parameter.name] = payload
            elif parameter.location == 'header':
                # Headers may contain unencoded values
                test_headers[parameter.name] = payload
            
            # Send request with modified payload
            test_response = self._make_request(
                url, method, test_params, test_data, test_cookies, test_headers
            )
            
            if not test_response:
                logger.warning(f"Failed to get response for payload '{payload}'")
                continue
            
            # Analyze response for potential vulnerability
            result = self._analyze_response(
                parameter, payload, baseline_response, test_response
            )
            
            if result.vulnerable:
                logger.warning(
                    f"Potential SQL injection found in '{parameter.name}' "
                    f"with payload '{payload}' (confidence: {result.confidence:.2f})"
                )
            
            results.append(result)
        
        return results
    
    def probe_all_parameters(self, url: str, method: str = 'GET',
                            params: Optional[Dict[str, str]] = None,
                            data: Optional[Dict[str, str]] = None,
                            cookies: Optional[Dict[str, str]] = None,
                            headers: Optional[Dict[str, str]] = None
                            ) -> List[NumericInjectionResult]:
        """
        Probe all numeric parameters in a request for SQL injection vulnerabilities.
        
        This is a convenience method that identifies all numeric parameters and
        probes each one for vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            params: Query parameters
            data: POST data
            cookies: Cookies
            headers: HTTP headers
        
        Returns:
            List of all NumericInjectionResult objects
        
        Example:
            >>> injector = NumericSqlInjector()
            >>> results = injector.probe_all_parameters(
            ...     url='http://example.com/product?id=5&page=1',
            ...     method='GET'
            ... )
            >>> vulnerable = [r for r in results if r.vulnerable]
        """
        # Identify numeric parameters
        numeric_params = self.identify_numeric_parameters(
            url, method, params, data, cookies, headers
        )
        
        if not numeric_params:
            logger.info("No numeric parameters found to probe")
            return []
        
        logger.info(f"Probing {len(numeric_params)} numeric parameter(s)")
        
        # Probe each parameter
        all_results = []
        for param in numeric_params:
            param_results = self.probe_parameter(
                url, param, method, params, data, cookies, headers
            )
            all_results.extend(param_results)
        
        # Log summary
        vulnerable_count = sum(1 for r in all_results if r.vulnerable)
        logger.info(
            f"Probing complete: {vulnerable_count} potential vulnerabilities found "
            f"out of {len(all_results)} tests"
        )
        
        return all_results
    
    def _make_request(self, url: str, method: str,
                     params: Optional[Dict] = None,
                     data: Optional[Dict] = None,
                     cookies: Optional[Dict] = None,
                     headers: Optional[Dict] = None
                     ) -> Optional[requests.Response]:
        """
        Make an HTTP request with retry logic.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Query parameters
            data: POST data
            cookies: Cookies
            headers: HTTP headers
        
        Returns:
            Response object or None if request failed
        """
        # Prepare headers
        request_headers = {'User-Agent': self.user_agent}
        if headers:
            request_headers.update(headers)
        
        # Retry logic
        for attempt in range(self.max_retries + 1):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(
                        url,
                        params=params,
                        cookies=cookies,
                        headers=request_headers,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                elif method.upper() == 'POST':
                    response = self.session.post(
                        url,
                        params=params,
                        data=data,
                        cookies=cookies,
                        headers=request_headers,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                else:
                    # Support other methods
                    response = self.session.request(
                        method,
                        url,
                        params=params,
                        data=data,
                        cookies=cookies,
                        headers=request_headers,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                
                return response
            
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}")
                if attempt == self.max_retries:
                    logger.error(f"Failed to make request after {self.max_retries + 1} attempts")
                    return None
        
        return None
    
    def _analyze_response(self, parameter: NumericParameter, payload: str,
                         baseline_response: requests.Response,
                         test_response: requests.Response
                         ) -> NumericInjectionResult:
        """
        Analyze a response to detect potential SQL injection vulnerability.
        
        This method compares the test response with the baseline response to
        determine if the payload triggered different behavior that could indicate
        SQL injection.
        
        Args:
            parameter: Parameter being tested
            payload: Payload that was sent
            baseline_response: Original response
            test_response: Response with injected payload
        
        Returns:
            NumericInjectionResult with analysis
        """
        # Calculate response similarity
        similarity = self._calculate_similarity(
            baseline_response.text,
            test_response.text
        )
        
        response_diff = 1.0 - similarity
        
        # Check for SQL errors
        sql_errors = self._check_sql_errors(test_response.text)
        
        # Determine vulnerability
        vulnerable = False
        confidence = 0.0
        evidence = []
        
        # High confidence: SQL errors detected
        if sql_errors:
            vulnerable = True
            confidence = 0.9
            evidence.append(f"SQL error detected: {sql_errors}")
        
        # Medium confidence: Significant response difference
        elif response_diff > 0.3:
            # Check if the difference is suspicious
            # Different status codes
            if baseline_response.status_code != test_response.status_code:
                vulnerable = True
                confidence = 0.7
                evidence.append(
                    f"Status code changed: {baseline_response.status_code} -> "
                    f"{test_response.status_code}"
                )
            # Large content difference with arithmetic payload
            elif response_diff > 0.5:
                vulnerable = True
                confidence = 0.6
                evidence.append(
                    f"Large response difference: {response_diff:.2f}"
                )
        
        # Low confidence: Timing differences or minor changes
        elif response_diff > 0.1:
            vulnerable = False  # Not confident enough
            confidence = 0.3
            evidence.append(
                f"Minor response difference: {response_diff:.2f}"
            )
        
        evidence_str = "; ".join(evidence) if evidence else "No significant differences"
        
        return NumericInjectionResult(
            parameter=parameter,
            payload=payload,
            vulnerable=vulnerable,
            confidence=confidence,
            evidence=evidence_str,
            response_diff=response_diff
        )
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two text strings.
        
        Uses SequenceMatcher for similarity calculation.
        
        Args:
            text1: First text string
            text2: Second text string
        
        Returns:
            Similarity ratio between 0.0 and 1.0
        """
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        # Use SequenceMatcher for similarity
        similarity = SequenceMatcher(None, text1, text2).ratio()
        return similarity
    
    def _check_sql_errors(self, response_text: str) -> Optional[str]:
        """
        Check response for SQL error messages.
        
        Args:
            response_text: HTTP response body
        
        Returns:
            Error message if found, None otherwise
        """
        # Common SQL error patterns
        error_patterns = [
            r'SQL\s+syntax.*error',
            r'error.*SQL\s+syntax',
            r'mysql_fetch',
            r'mysqli',
            r'pg_query',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql',
            r'valid\s+MySQL\s+result',
            r'MySqlClient\.',
            r'com\.mysql\.jdbc',
            r'org\.postgresql',
            r'Incorrect\s+syntax\s+near',
            r'Unclosed\s+quotation\s+mark',
            r'SQLSTATE',
            r'SQL\s+Server',
            r'ORA-\d+',
            r'Microsoft\s+OLE\s+DB\s+Provider',
            r'SQLServer\s+JDBC\s+Driver',
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
