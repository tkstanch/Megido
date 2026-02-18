"""
Unit tests for time-based blind SQL injection detector
"""

import time
from django.test import TestCase
from sql_attacker.time_based_blind_detector import (
    TimeBasedBlindDetector, 
    DBMSType, 
    TimingResult
)


class MockResponse:
    """Mock HTTP response for testing"""
    def __init__(self, text="Mock response", status_code=200):
        self.text = text
        self.status_code = status_code


class TimeBasedBlindDetectorTest(TestCase):
    """Test time-based blind SQL injection detection"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = TimeBasedBlindDetector(
            delay_seconds=5.0,
            threshold_multiplier=0.8,
            baseline_samples=3,
            test_samples=2
        )
    
    def test_initialization(self):
        """Test detector initializes correctly"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.delay_seconds, 5.0)
        self.assertEqual(self.detector.threshold_multiplier, 0.8)
        self.assertEqual(self.detector.baseline_samples, 3)
        self.assertEqual(self.detector.test_samples, 2)
        self.assertEqual(len(self.detector.baseline_times), 0)
        self.assertIsNone(self.detector.detected_dbms)
    
    def test_time_delay_payloads_exist(self):
        """Test that time-delay payloads are defined for all DBMS types"""
        # Check all DBMS types have payloads
        self.assertIn(DBMSType.MYSQL, self.detector.TIME_DELAY_PAYLOADS)
        self.assertIn(DBMSType.MSSQL, self.detector.TIME_DELAY_PAYLOADS)
        self.assertIn(DBMSType.POSTGRESQL, self.detector.TIME_DELAY_PAYLOADS)
        self.assertIn(DBMSType.ORACLE, self.detector.TIME_DELAY_PAYLOADS)
        
        # Check MySQL payloads
        mysql_payloads = self.detector.TIME_DELAY_PAYLOADS[DBMSType.MYSQL]
        self.assertIn('simple_delay', mysql_payloads)
        self.assertIn('conditional_delay', mysql_payloads)
        self.assertIn('extraction_template', mysql_payloads)
        
        # Verify SLEEP is used in MySQL
        simple_delays = mysql_payloads['simple_delay']
        self.assertTrue(any('SLEEP' in p for p in simple_delays))
    
    def test_mssql_waitfor_payloads(self):
        """Test MS-SQL WAITFOR DELAY payloads"""
        mssql_payloads = self.detector.TIME_DELAY_PAYLOADS[DBMSType.MSSQL]
        
        # Check WAITFOR DELAY is present
        simple_delays = mssql_payloads['simple_delay']
        self.assertTrue(any('WAITFOR DELAY' in p for p in simple_delays))
        
        # Check extraction template
        templates = mssql_payloads['extraction_template']
        self.assertIn('char_test', templates)
        self.assertIn('WAITFOR DELAY', templates['char_test'])
    
    def test_postgresql_pg_sleep_payloads(self):
        """Test PostgreSQL pg_sleep payloads"""
        pg_payloads = self.detector.TIME_DELAY_PAYLOADS[DBMSType.POSTGRESQL]
        
        # Check pg_sleep is present
        simple_delays = pg_payloads['simple_delay']
        self.assertTrue(any('pg_sleep' in p for p in simple_delays))
        
        # Check conditional delays use CASE
        conditional_delays = pg_payloads['conditional_delay']
        self.assertTrue(any('CASE WHEN' in p for p in conditional_delays))
    
    def test_oracle_utl_http_payloads(self):
        """Test Oracle UTL_HTTP timeout payloads"""
        oracle_payloads = self.detector.TIME_DELAY_PAYLOADS[DBMSType.ORACLE]
        
        # Check UTL_HTTP is present
        simple_delays = oracle_payloads['simple_delay']
        self.assertTrue(any('UTL_HTTP' in p for p in simple_delays))
        
        # Check alternative DBMS_LOCK
        if 'dbms_lock_delay' in oracle_payloads:
            dbms_lock = oracle_payloads['dbms_lock_delay']
            self.assertTrue(any('DBMS_LOCK.SLEEP' in p for p in dbms_lock))
    
    def test_detection_probes_exist(self):
        """Test that detection probes are defined"""
        self.assertIn(DBMSType.MYSQL, self.detector.DETECTION_PROBES)
        self.assertIn(DBMSType.MSSQL, self.detector.DETECTION_PROBES)
        self.assertIn(DBMSType.POSTGRESQL, self.detector.DETECTION_PROBES)
        
        # Check MySQL detection uses SLEEP
        mysql_probes = self.detector.DETECTION_PROBES[DBMSType.MYSQL]
        self.assertTrue(any('SLEEP' in p for p in mysql_probes))
    
    def test_establish_baseline(self):
        """Test baseline establishment"""
        call_count = [0]
        
        def mock_test_function(payload=None, **kwargs):
            call_count[0] += 1
            time.sleep(0.01)  # Simulate network latency
            return MockResponse()
        
        avg_baseline = self.detector.establish_baseline(
            test_function=mock_test_function,
            url="http://test.com",
            param="id",
            param_type="GET"
        )
        
        # Check baseline was established
        self.assertEqual(len(self.detector.baseline_times), 3)
        self.assertGreater(avg_baseline, 0)
        self.assertEqual(call_count[0], 3)
        
        # All baseline times should be small (no delay)
        for t in self.detector.baseline_times:
            self.assertLess(t, 0.5)
    
    def test_measure_response_time(self):
        """Test response time measurement"""
        def mock_test_function(payload, **kwargs):
            if 'SLEEP' in payload:
                time.sleep(0.1)  # Simulate delay
            else:
                time.sleep(0.01)
            return MockResponse()
        
        # Measure normal payload
        time1 = self.detector.measure_response_time(
            mock_test_function, 
            "1", 
            url="http://test.com"
        )
        self.assertLess(time1, 0.5)
        
        # Measure delayed payload
        time2 = self.detector.measure_response_time(
            mock_test_function,
            "' AND SLEEP(5)--",
            url="http://test.com"
        )
        self.assertGreater(time2, 0.05)
    
    def test_is_delayed_response(self):
        """Test delayed response detection"""
        # Set up baseline
        self.detector.baseline_times = [0.2, 0.21, 0.19]
        
        # Test with delayed response (5 seconds over baseline)
        is_delayed, confidence = self.detector.is_delayed_response(5.2, baseline=0.2)
        self.assertTrue(is_delayed)
        self.assertGreater(confidence, 0.9)
        
        # Test with normal response
        is_delayed, confidence = self.detector.is_delayed_response(0.3, baseline=0.2)
        self.assertFalse(is_delayed)
        self.assertEqual(confidence, 0.0)
        
        # Test with partial delay (3 seconds, below 80% threshold)
        is_delayed, confidence = self.detector.is_delayed_response(3.2, baseline=0.2)
        self.assertFalse(is_delayed)
    
    def test_is_delayed_response_uses_baseline_average(self):
        """Test that is_delayed_response uses average baseline if not provided"""
        self.detector.baseline_times = [0.2, 0.22, 0.18]
        
        # Should use average (0.2) if baseline not provided
        is_delayed, confidence = self.detector.is_delayed_response(5.2)
        self.assertTrue(is_delayed)
        self.assertGreater(confidence, 0.9)
    
    def test_extraction_templates_have_required_fields(self):
        """Test that extraction templates have required fields"""
        for dbms_type, payloads in self.detector.TIME_DELAY_PAYLOADS.items():
            if 'extraction_template' in payloads:
                templates = payloads['extraction_template']
                
                # Should have at least char_test
                self.assertIn('char_test', templates)
                
                # char_test should have placeholders
                char_template = templates['char_test']
                self.assertIn('{query}', char_template)
                self.assertIn('{position}', char_template)
                self.assertIn('{ascii_code}', char_template)
    
    def test_bitwise_templates_exist(self):
        """Test that bitwise extraction templates exist"""
        # Check MySQL bitwise
        mysql_templates = self.detector.TIME_DELAY_PAYLOADS[DBMSType.MYSQL]['extraction_template']
        self.assertIn('bitwise_test', mysql_templates)
        
        bitwise_template = mysql_templates['bitwise_test']
        self.assertIn('{mask}', bitwise_template)
        self.assertIn('{value}', bitwise_template)
    
    def test_test_time_based_injection_mock(self):
        """Test time-based injection detection with mock function"""
        call_count = [0]
        
        def mock_test_function(payload, url, param, param_type, **kwargs):
            call_count[0] += 1
            
            # Simulate delay for conditional delay payloads
            if payload and ('SLEEP' in payload or 'WAITFOR' in payload):
                # Check if it's a true condition (should delay)
                if '1=1' in payload or 'IF(1' in payload or 'CASE WHEN (1=1)' in payload:
                    time.sleep(0.1)  # Simulate delay
                else:
                    time.sleep(0.01)  # No delay for false condition
            else:
                time.sleep(0.01)  # Normal response
            
            return MockResponse()
        
        # Establish baseline first
        self.detector.establish_baseline(
            test_function=mock_test_function,
            url="http://test.com",
            param="id",
            param_type="GET"
        )
        
        # Use a smaller delay for testing
        self.detector.delay_seconds = 0.05
        
        # Test for vulnerability
        results = self.detector.test_time_based_injection(
            test_function=mock_test_function,
            url="http://test.com",
            param="id",
            param_type="GET",
            dbms_type=DBMSType.MYSQL
        )
        
        # Check results structure
        self.assertIn('vulnerable', results)
        self.assertIn('confidence', results)
        self.assertIn('method', results)
        self.assertIn('dbms_type', results)
        self.assertEqual(results['method'], 'time_based_blind')
    
    def test_generate_report(self):
        """Test report generation"""
        self.detector.baseline_times = [0.2, 0.21, 0.19]
        self.detector.detected_dbms = DBMSType.MYSQL
        
        report = self.detector.generate_report()
        
        self.assertIsInstance(report, str)
        self.assertIn("TIME-BASED BLIND SQL INJECTION", report)
        self.assertIn("Baseline Response Time", report)
        self.assertIn("MYSQL", report)
    
    def test_dbms_type_enum(self):
        """Test DBMSType enum values"""
        self.assertEqual(DBMSType.MYSQL.value, "mysql")
        self.assertEqual(DBMSType.MSSQL.value, "mssql")
        self.assertEqual(DBMSType.POSTGRESQL.value, "postgresql")
        self.assertEqual(DBMSType.ORACLE.value, "oracle")
    
    def test_mysql_benchmark_payloads(self):
        """Test MySQL BENCHMARK alternative payloads"""
        mysql_payloads = self.detector.TIME_DELAY_PAYLOADS[DBMSType.MYSQL]
        
        # Check BENCHMARK payloads exist
        self.assertIn('benchmark_delay', mysql_payloads)
        
        benchmark_payloads = mysql_payloads['benchmark_delay']
        self.assertTrue(any('BENCHMARK' in p for p in benchmark_payloads))
        
        # Check extraction template has BENCHMARK variant
        templates = mysql_payloads['extraction_template']
        self.assertIn('benchmark_char_test', templates)
    
    def test_payload_formatting(self):
        """Test that payload templates can be formatted correctly"""
        # Test MySQL payload formatting
        mysql_templates = self.detector.TIME_DELAY_PAYLOADS[DBMSType.MYSQL]['extraction_template']
        char_template = mysql_templates['char_test']
        
        formatted = char_template.format(
            query="database()",
            position=1,
            ascii_code=116,
            delay=5
        )
        
        self.assertIn("database()", formatted)
        self.assertIn("1", formatted)
        self.assertIn("116", formatted)
        self.assertIn("SLEEP(5)", formatted)
    
    def test_mssql_payload_formatting(self):
        """Test MS-SQL payload formatting"""
        mssql_templates = self.detector.TIME_DELAY_PAYLOADS[DBMSType.MSSQL]['extraction_template']
        char_template = mssql_templates['char_test']
        
        formatted = char_template.format(
            query="DB_NAME()",
            position=2,
            ascii_code=97,
            delay=5
        )
        
        self.assertIn("DB_NAME()", formatted)
        self.assertIn("2", formatted)
        self.assertIn("97", formatted)
        self.assertIn("WAITFOR DELAY", formatted)
    
    def test_postgresql_payload_formatting(self):
        """Test PostgreSQL payload formatting"""
        pg_templates = self.detector.TIME_DELAY_PAYLOADS[DBMSType.POSTGRESQL]['extraction_template']
        char_template = pg_templates['char_test']
        
        formatted = char_template.format(
            query="current_database()",
            position=3,
            ascii_code=115,
            delay=5
        )
        
        self.assertIn("current_database()", formatted)
        self.assertIn("3", formatted)
        self.assertIn("115", formatted)
        self.assertIn("pg_sleep", formatted)
    
    def test_oracle_payload_formatting(self):
        """Test Oracle payload formatting"""
        oracle_templates = self.detector.TIME_DELAY_PAYLOADS[DBMSType.ORACLE]['extraction_template']
        char_template = oracle_templates['char_test']
        
        formatted = char_template.format(
            query="SELECT user FROM dual",
            position=1,
            ascii_code=83,
            delay=5
        )
        
        self.assertIn("SELECT user FROM dual", formatted)
        self.assertIn("1", formatted)
        self.assertIn("83", formatted)
    
    def test_bitwise_payload_formatting(self):
        """Test bitwise payload formatting"""
        mysql_templates = self.detector.TIME_DELAY_PAYLOADS[DBMSType.MYSQL]['extraction_template']
        bitwise_template = mysql_templates['bitwise_test']
        
        # Test bit 7 (mask=128)
        formatted = bitwise_template.format(
            query="database()",
            position=1,
            mask=128,
            value=128,
            delay=5
        )
        
        self.assertIn("database()", formatted)
        self.assertIn("128", formatted)
        self.assertIn("&", formatted)
    
    def test_empty_baseline_handling(self):
        """Test handling of empty baseline"""
        # No baseline established
        self.assertEqual(len(self.detector.baseline_times), 0)
        
        # is_delayed_response should handle gracefully
        is_delayed, confidence = self.detector.is_delayed_response(5.0)
        self.assertFalse(is_delayed)
        self.assertEqual(confidence, 0.0)
    
    def test_confidence_calculation(self):
        """Test confidence calculation logic"""
        self.detector.baseline_times = [0.2]
        
        # Test exact expected delay (5 seconds)
        is_delayed, confidence = self.detector.is_delayed_response(5.2, baseline=0.2)
        self.assertTrue(is_delayed)
        self.assertAlmostEqual(confidence, 1.0, places=1)
        
        # Test 50% over expected delay
        is_delayed, confidence = self.detector.is_delayed_response(7.7, baseline=0.2)
        self.assertTrue(is_delayed)
        self.assertEqual(confidence, 1.0)  # Capped at 1.0
    
    def test_threshold_multiplier_effect(self):
        """Test that threshold multiplier affects detection"""
        self.detector.baseline_times = [0.2]
        
        # With 0.8 multiplier, threshold is 0.2 + (5 * 0.8) = 4.2 seconds
        # Response of 4.5 seconds should be detected
        is_delayed, confidence = self.detector.is_delayed_response(4.5, baseline=0.2)
        self.assertTrue(is_delayed)
        
        # Response of 3.5 seconds should NOT be detected
        is_delayed, confidence = self.detector.is_delayed_response(3.5, baseline=0.2)
        self.assertFalse(is_delayed)
