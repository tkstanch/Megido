#!/usr/bin/env python3
"""
Standalone test runner for time_based_blind_detector
Runs tests without requiring full Django setup or database
"""

import sys
import os
import time
import unittest
from typing import Optional

# Add project root to path (portable across environments)
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

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


class TimeBasedBlindDetectorTest(unittest.TestCase):
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
    
    def test_generate_report(self):
        """Test report generation"""
        self.detector.baseline_times = [0.2, 0.21, 0.19]
        self.detector.detected_dbms = DBMSType.MYSQL
        
        report = self.detector.generate_report()
        
        self.assertIsInstance(report, str)
        self.assertIn("TIME-BASED BLIND SQL INJECTION", report)
        self.assertIn("Baseline Response Time", report)
        self.assertIn("MYSQL", report)


if __name__ == '__main__':
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TimeBasedBlindDetectorTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print(f"✓ All {result.testsRun} tests PASSED")
    else:
        print(f"✗ {len(result.failures)} test(s) FAILED")
        print(f"✗ {len(result.errors)} test(s) had ERRORS")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
