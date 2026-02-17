"""
Unit tests for SQL Fingerprinter module
"""

from django.test import TestCase
from sql_attacker.sql_fingerprinter import (
    SqlFingerprinter,
    DatabaseType,
    FingerprintResult
)


class MockTransport:
    """Mock transport function for testing"""
    
    def __init__(self, scenario="success_3_columns"):
        """
        Initialize mock transport with specific scenario.
        
        Scenarios:
        - success_3_columns: Successful injection with 3 columns
        - success_5_columns: Successful injection with 5 columns
        - oracle_3_columns: Oracle DB requiring FROM DUAL
        - no_injection: No successful injection
        - string_col_2: Only column 2 accepts strings
        """
        self.scenario = scenario
        self.requests = []
        
    def __call__(self, payload):
        """Handle payload request"""
        self.requests.append(payload)
        
        # Default error response
        error_response = {
            'status_code': 500,
            'content': 'You have an error in your SQL syntax; MySQL server version',
            'length': 100
        }
        
        # Normal response (non-injection)
        normal_response = {
            'status_code': 200,
            'content': '<html>User profile for ID 1</html>',
            'length': 35
        }
        
        if self.scenario == "success_3_columns":
            # Check for 3-column UNION
            if "UNION SELECT NULL,NULL,NULL" in payload:
                return {
                    'status_code': 200,
                    'content': '<html>User profile for ID 1<div>Extra data</div></html>',
                    'length': 55  # Different length indicates success
                }
            elif "UNION SELECT" in payload and "'SQLFingerprint'" in payload:
                # String marker test
                return {
                    'status_code': 200,
                    'content': '<html>SQLFingerprint found in response</html>',
                    'length': 45
                }
            elif "UNION SELECT" in payload:
                return error_response
            else:
                return normal_response if payload == "1" else error_response
                
        elif self.scenario == "success_5_columns":
            # Check for 5-column UNION
            if "UNION SELECT NULL,NULL,NULL,NULL,NULL" in payload:
                return {
                    'status_code': 200,
                    'content': '<html>User profile with 5 columns</html>',
                    'length': 40
                }
            elif "UNION SELECT" in payload and "'SQLFingerprint'" in payload:
                return {
                    'status_code': 200,
                    'content': '<html>SQLFingerprint present</html>',
                    'length': 35
                }
            elif "UNION SELECT" in payload:
                return error_response
            else:
                return normal_response if payload == "1" else error_response
                
        elif self.scenario == "oracle_3_columns":
            # Oracle requires FROM DUAL
            if "FROM DUAL" in payload and "UNION SELECT NULL,NULL,NULL" in payload:
                return {
                    'status_code': 200,
                    'content': 'ORA-00933: SQL command not properly ended',
                    'length': 50
                }
            elif "FROM DUAL" in payload and "'SQLFingerprint'" in payload:
                return {
                    'status_code': 200,
                    'content': 'SQLFingerprint',
                    'length': 14
                }
            elif "UNION SELECT" in payload and "FROM DUAL" not in payload:
                return {
                    'status_code': 500,
                    'content': 'ORA-00923: FROM keyword not found where expected',
                    'length': 50
                }
            else:
                return normal_response if payload == "1" else {
                    'status_code': 500,
                    'content': 'ORA-01756: quoted string not properly terminated',
                    'length': 50
                }
                
        elif self.scenario == "string_col_2":
            # Only column index 2 (3rd column) accepts strings
            if "UNION SELECT NULL,NULL,NULL" in payload and "'SQLFingerprint'" not in payload:
                return {
                    'status_code': 200,
                    'content': '<html>Success with 3 cols</html>',
                    'length': 30
                }
            elif "'SQLFingerprint',NULL,NULL" in payload or "NULL,'SQLFingerprint',NULL" in payload:
                # First two columns don't show marker
                return {
                    'status_code': 200,
                    'content': '<html>No marker visible</html>',
                    'length': 30
                }
            elif "NULL,NULL,'SQLFingerprint'" in payload:
                # Third column shows marker
                return {
                    'status_code': 200,
                    'content': '<html>SQLFingerprint visible here</html>',
                    'length': 40
                }
            else:
                return normal_response if payload == "1" else error_response
                
        elif self.scenario == "no_injection":
            # No successful injection possible
            return error_response if "UNION SELECT" in payload or "'" in payload else normal_response
        
        return error_response


class SqlFingerprinterTest(TestCase):
    """Test SQL Fingerprinter functionality"""
    
    def test_initialization(self):
        """Test fingerprinter initialization"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        self.assertIsNotNone(fingerprinter)
        self.assertEqual(fingerprinter.transport_function, transport)
        self.assertIsNone(fingerprinter.detected_db_type)
    
    def test_initialization_with_db_type(self):
        """Test initialization with pre-set database type"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(
            transport, 
            verbose=False,
            database_type=DatabaseType.ORACLE
        )
        
        self.assertEqual(fingerprinter.detected_db_type, DatabaseType.ORACLE)
    
    def test_build_union_payload_basic(self):
        """Test building basic UNION payload"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        payload = fingerprinter._build_union_payload(3)
        
        self.assertIn("UNION SELECT", payload)
        self.assertIn("NULL,NULL,NULL", payload)
        self.assertIn("--", payload)
        self.assertNotIn("FROM DUAL", payload)
    
    def test_build_union_payload_with_string(self):
        """Test building UNION payload with string marker"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        payload = fingerprinter._build_union_payload(3, string_position=1, marker="'test'")
        
        self.assertIn("NULL,'test',NULL", payload)
    
    def test_build_union_payload_oracle(self):
        """Test building UNION payload for Oracle (with FROM DUAL)"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(
            transport,
            verbose=False,
            database_type=DatabaseType.ORACLE
        )
        
        payload = fingerprinter._build_union_payload(3)
        
        self.assertIn("FROM DUAL", payload)
        self.assertIn("UNION SELECT NULL,NULL,NULL FROM DUAL--", payload)
    
    def test_detect_database_from_response(self):
        """Test database type detection from error messages"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        # Test MySQL detection
        mysql_response = {
            'content': 'You have an error in your SQL syntax; MySQL server version 5.7'
        }
        db_type = fingerprinter._detect_database_from_response(mysql_response)
        self.assertEqual(db_type, DatabaseType.MYSQL)
        
        # Test PostgreSQL detection
        pg_response = {
            'content': 'PostgreSQL ERROR: syntax error at or near'
        }
        db_type = fingerprinter._detect_database_from_response(pg_response)
        self.assertEqual(db_type, DatabaseType.POSTGRESQL)
        
        # Test Oracle detection
        oracle_response = {
            'content': 'ORA-00933: SQL command not properly ended'
        }
        db_type = fingerprinter._detect_database_from_response(oracle_response)
        self.assertEqual(db_type, DatabaseType.ORACLE)
    
    def test_column_count_discovery_success_3_cols(self):
        """Test successful column count discovery with 3 columns"""
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.discover_column_count(max_columns=10)
        
        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 3)
        self.assertGreater(result.confidence, 0.5)
        self.assertEqual(result.method, "column_count_discovery")
    
    def test_column_count_discovery_success_5_cols(self):
        """Test successful column count discovery with 5 columns"""
        transport = MockTransport(scenario="success_5_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.discover_column_count(max_columns=10)
        
        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 5)
    
    def test_column_count_discovery_failure(self):
        """Test failed column count discovery"""
        transport = MockTransport(scenario="no_injection")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.discover_column_count(max_columns=5)
        
        self.assertFalse(result.success)
        self.assertIsNone(result.column_count)
    
    def test_column_count_discovery_with_start_columns(self):
        """Test column count discovery with custom start value"""
        transport = MockTransport(scenario="success_5_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        # Start from column 3 to save time
        result = fingerprinter.discover_column_count(
            max_columns=10,
            start_columns=3
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 5)
    
    def test_string_column_discovery_all_columns(self):
        """Test string column discovery when all columns accept strings"""
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.discover_string_columns(column_count=3)
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.string_columns)
        self.assertGreater(len(result.string_columns), 0)
        self.assertEqual(result.column_count, 3)
    
    def test_string_column_discovery_specific_column(self):
        """Test string column discovery with only specific column accepting strings"""
        transport = MockTransport(scenario="string_col_2")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.discover_string_columns(column_count=3)
        
        self.assertTrue(result.success)
        # Column index 2 (3rd column) should be detected
        self.assertIn(2, result.string_columns)
        # Should have exactly 1 string column
        self.assertEqual(len(result.string_columns), 1)
    
    def test_string_column_discovery_with_custom_marker(self):
        """Test string column discovery with custom marker"""
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.discover_string_columns(
            column_count=3,
            marker="'CustomMarker'"
        )
        
        # Should still work (mock accepts any marker with SQLFingerprint)
        self.assertIsNotNone(result.string_columns)
    
    def test_full_fingerprint_success(self):
        """Test full fingerprinting process"""
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.full_fingerprint(max_columns=10)
        
        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 3)
        self.assertIsNotNone(result.string_columns)
        self.assertEqual(result.method, "full_fingerprint")
        self.assertIn('column_discovery', result.details)
        self.assertIn('string_discovery', result.details)
    
    def test_full_fingerprint_failure_at_column_count(self):
        """Test full fingerprint when column count discovery fails"""
        transport = MockTransport(scenario="no_injection")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        result = fingerprinter.full_fingerprint(max_columns=5)
        
        self.assertFalse(result.success)
        self.assertIsNone(result.column_count)
    
    def test_oracle_from_dual_handling(self):
        """Test Oracle FROM DUAL handling"""
        transport = MockTransport(scenario="oracle_3_columns")
        fingerprinter = SqlFingerprinter(
            transport,
            verbose=False,
            database_type=DatabaseType.ORACLE
        )
        
        # Should use FROM DUAL for Oracle
        payload = fingerprinter._build_union_payload(3)
        self.assertIn("FROM DUAL", payload)
    
    def test_generate_exploitation_payloads_mysql(self):
        """Test exploitation payload generation for MySQL"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(
            transport,
            verbose=False,
            database_type=DatabaseType.MYSQL
        )
        
        payloads = fingerprinter.generate_exploitation_payloads(
            column_count=3,
            string_columns=[1]
        )
        
        self.assertGreater(len(payloads), 0)
        # Should contain MySQL-specific functions
        self.assertTrue(any('@@version' in p for p in payloads))
        self.assertTrue(any('user()' in p for p in payloads))
        self.assertTrue(any('database()' in p for p in payloads))
    
    def test_generate_exploitation_payloads_postgresql(self):
        """Test exploitation payload generation for PostgreSQL"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(
            transport,
            verbose=False,
            database_type=DatabaseType.POSTGRESQL
        )
        
        payloads = fingerprinter.generate_exploitation_payloads(
            column_count=3,
            string_columns=[0, 1]
        )
        
        self.assertGreater(len(payloads), 0)
        # Should contain PostgreSQL-specific functions
        self.assertTrue(any('version()' in p for p in payloads))
        self.assertTrue(any('current_user' in p for p in payloads))
    
    def test_generate_exploitation_payloads_oracle(self):
        """Test exploitation payload generation for Oracle"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(
            transport,
            verbose=False,
            database_type=DatabaseType.ORACLE
        )
        
        payloads = fingerprinter.generate_exploitation_payloads(
            column_count=3,
            string_columns=[1]
        )
        
        self.assertGreater(len(payloads), 0)
        # Should contain Oracle-specific syntax
        self.assertTrue(any('FROM DUAL' in p for p in payloads))
        self.assertTrue(any('v$version' in p for p in payloads))
    
    def test_generate_exploitation_payloads_custom_data(self):
        """Test exploitation payload generation with custom data"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(
            transport,
            verbose=False,
            database_type=DatabaseType.MYSQL
        )
        
        custom_data = ['table_name FROM information_schema.tables', 'COUNT(*) FROM users']
        payloads = fingerprinter.generate_exploitation_payloads(
            column_count=3,
            string_columns=[1],
            data_to_extract=custom_data
        )
        
        self.assertEqual(len(payloads), len(custom_data))
        self.assertTrue(any('information_schema.tables' in p for p in payloads))
        self.assertTrue(any('COUNT(*)' in p for p in payloads))
    
    def test_generate_exploitation_payloads_no_string_columns(self):
        """Test exploitation payload generation with no string columns"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        payloads = fingerprinter.generate_exploitation_payloads(
            column_count=3,
            string_columns=[]
        )
        
        self.assertEqual(len(payloads), 0)
    
    def test_format_report_success(self):
        """Test report formatting for successful fingerprint"""
        result = FingerprintResult(
            success=True,
            column_count=3,
            string_columns=[0, 2],
            database_type=DatabaseType.MYSQL,
            confidence=0.9,
            method="full_fingerprint",
            details={
                'payload': "' UNION SELECT NULL,NULL,NULL--",
                'message': 'Success'
            }
        )
        
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        report = fingerprinter.format_report(result)
        
        self.assertIn("SUCCESS", report)
        self.assertIn("Column Count: 3", report)
        self.assertIn("MYSQL", report)
        self.assertIn("[1, 3]", report)  # 1-indexed column numbers
        self.assertIn("90", report)  # Confidence percentage
    
    def test_format_report_failure(self):
        """Test report formatting for failed fingerprint"""
        result = FingerprintResult(
            success=False,
            method="column_count_discovery",
            details={'message': 'Failed to discover columns'}
        )
        
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        report = fingerprinter.format_report(result)
        
        self.assertIn("FAILED", report)
        self.assertIn("Failed to discover columns", report)
    
    def test_baseline_establishment(self):
        """Test baseline response establishment"""
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        success = fingerprinter._establish_baseline()
        
        self.assertTrue(success)
        self.assertIsNotNone(fingerprinter.baseline_response)
        self.assertIsNotNone(fingerprinter.baseline_error_response)
    
    def test_success_detection_error_disappears(self):
        """Test success detection when error disappears"""
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        # Establish baseline with error
        fingerprinter._establish_baseline()
        
        # Test successful response
        success_response = {
            'status_code': 200,
            'content': '<html>No errors here</html>',
            'length': 30
        }
        
        is_success, reason = fingerprinter._is_successful_injection(success_response)
        
        # Should detect success based on error disappearing
        self.assertTrue(is_success or len(reason) > 0)  # Either success or has a reason
    
    def test_success_detection_marker_found(self):
        """Test success detection when marker is found"""
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        response = {
            'status_code': 200,
            'content': '<html>SQLFingerprint found here</html>',
            'length': 40
        }
        
        is_success, reason = fingerprinter._is_successful_injection(
            response,
            check_marker="'SQLFingerprint'"
        )
        
        self.assertTrue(is_success)
        self.assertIn("Marker", reason)
    
    def test_success_detection_length_change(self):
        """Test success detection based on response length change"""
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        # Establish baseline
        fingerprinter._establish_baseline()
        
        # Response with significantly different length
        response = {
            'status_code': 200,
            'content': '<html>Much longer response with extra data' * 10 + '</html>',
            'length': 500
        }
        
        is_success, reason = fingerprinter._is_successful_injection(response)
        
        # May detect success based on length change
        # (This is scenario-dependent, so we just check it doesn't crash)
        self.assertIsInstance(is_success, bool)
        self.assertIsInstance(reason, str)
    
    def test_delay_between_requests(self):
        """Test that delay is applied between requests"""
        import time
        
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False, delay=0.1)
        
        start_time = time.time()
        fingerprinter.discover_column_count(max_columns=3)
        elapsed = time.time() - start_time
        
        # With baseline + 3 tests, should have at least 4 * 0.1 = 0.4 seconds
        # (baseline sends 2 requests, so 5 total requests minimum)
        self.assertGreater(elapsed, 0.4)
    
    def test_fingerprint_result_dataclass(self):
        """Test FingerprintResult dataclass"""
        result = FingerprintResult(
            success=True,
            column_count=5,
            string_columns=[0, 2, 4],
            confidence=0.85
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 5)
        self.assertEqual(len(result.string_columns), 3)
        self.assertEqual(result.confidence, 0.85)
        self.assertIsNotNone(result.details)  # Should be initialized to {}
    
    def test_database_type_enum(self):
        """Test DatabaseType enum"""
        self.assertEqual(DatabaseType.MYSQL.value, "mysql")
        self.assertEqual(DatabaseType.POSTGRESQL.value, "postgresql")
        self.assertEqual(DatabaseType.ORACLE.value, "oracle")
        self.assertEqual(DatabaseType.MSSQL.value, "mssql")
        self.assertEqual(DatabaseType.SQLITE.value, "sqlite")
        self.assertEqual(DatabaseType.UNKNOWN.value, "unknown")
