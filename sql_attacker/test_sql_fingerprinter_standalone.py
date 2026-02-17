#!/usr/bin/env python3
"""
Standalone test runner for SQL Fingerprinter module
(Does not require Django or database)
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.sql_fingerprinter import (
    SqlFingerprinter,
    DatabaseType,
    FingerprintResult
)


class MockTransport:
    """Mock transport function for testing"""
    
    def __init__(self, scenario="success_3_columns"):
        self.scenario = scenario
        self.requests = []
        
    def __call__(self, payload):
        """Handle payload request"""
        self.requests.append(payload)
        
        error_response = {
            'status_code': 500,
            'content': 'You have an error in your SQL syntax; MySQL server version',
            'length': 100
        }
        
        normal_response = {
            'status_code': 200,
            'content': '<html>User profile for ID 1</html>',
            'length': 35
        }
        
        if self.scenario == "success_3_columns":
            if "UNION SELECT NULL,NULL,NULL" in payload:
                return {
                    'status_code': 200,
                    'content': '<html>User profile for ID 1<div>Extra data</div></html>',
                    'length': 55
                }
            elif "UNION SELECT" in payload and "'SQLFingerprint'" in payload:
                return {
                    'status_code': 200,
                    'content': '<html>SQLFingerprint found in response</html>',
                    'length': 45
                }
            elif "UNION SELECT" in payload:
                return error_response
            else:
                return normal_response if payload == "1" else error_response
        
        return error_response


def run_tests():
    """Run all tests"""
    print("=" * 70)
    print("SQL FINGERPRINTER TEST SUITE")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    # Test 1: Basic initialization
    print("\n[TEST 1] Basic initialization...")
    try:
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        assert fingerprinter is not None
        assert fingerprinter.transport_function == transport
        print("✓ PASS: Initialization works correctly")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 2: Build UNION payload
    print("\n[TEST 2] Build UNION payload...")
    try:
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        payload = fingerprinter._build_union_payload(3)
        assert "UNION SELECT" in payload
        assert "NULL,NULL,NULL" in payload
        assert "--" in payload
        print(f"✓ PASS: Payload built correctly: {payload}")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 3: Build UNION payload with Oracle FROM DUAL
    print("\n[TEST 3] Build UNION payload for Oracle...")
    try:
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(
            transport,
            verbose=False,
            database_type=DatabaseType.ORACLE
        )
        payload = fingerprinter._build_union_payload(3)
        assert "FROM DUAL" in payload
        print(f"✓ PASS: Oracle payload built correctly: {payload}")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 4: Column count discovery
    print("\n[TEST 4] Column count discovery (3 columns)...")
    try:
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        result = fingerprinter.discover_column_count(max_columns=10)
        assert result.success is True
        assert result.column_count == 3
        print(f"✓ PASS: Discovered {result.column_count} columns")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 5: String column discovery
    print("\n[TEST 5] String column discovery...")
    try:
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        result = fingerprinter.discover_string_columns(column_count=3)
        assert result.success is True
        assert result.string_columns is not None
        assert len(result.string_columns) > 0
        print(f"✓ PASS: Discovered {len(result.string_columns)} string columns: {result.string_columns}")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 6: Full fingerprint
    print("\n[TEST 6] Full fingerprint process...")
    try:
        transport = MockTransport(scenario="success_3_columns")
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        result = fingerprinter.full_fingerprint(max_columns=10)
        assert result.success is True
        assert result.column_count == 3
        assert result.string_columns is not None
        assert result.method == "full_fingerprint"
        print(f"✓ PASS: Full fingerprint successful")
        print(f"  - Column count: {result.column_count}")
        print(f"  - String columns: {result.string_columns}")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 7: Generate exploitation payloads for MySQL
    print("\n[TEST 7] Generate exploitation payloads...")
    try:
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
        assert len(payloads) > 0
        assert any('@@version' in p for p in payloads)
        print(f"✓ PASS: Generated {len(payloads)} exploitation payloads")
        for i, p in enumerate(payloads[:3], 1):
            print(f"  {i}. {p}")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 8: Database type detection
    print("\n[TEST 8] Database type detection...")
    try:
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        
        # Test MySQL detection
        mysql_response = {
            'content': 'You have an error in your SQL syntax; MySQL server version 5.7'
        }
        db_type = fingerprinter._detect_database_from_response(mysql_response)
        assert db_type == DatabaseType.MYSQL
        
        # Test Oracle detection
        oracle_response = {
            'content': 'ORA-00933: SQL command not properly ended'
        }
        db_type = fingerprinter._detect_database_from_response(oracle_response)
        assert db_type == DatabaseType.ORACLE
        
        print("✓ PASS: Database type detection works")
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Test 9: Format report
    print("\n[TEST 9] Format report...")
    try:
        result = FingerprintResult(
            success=True,
            column_count=3,
            string_columns=[0, 2],
            database_type=DatabaseType.MYSQL,
            confidence=0.9,
            method="full_fingerprint"
        )
        
        transport = MockTransport()
        fingerprinter = SqlFingerprinter(transport, verbose=False)
        report = fingerprinter.format_report(result)
        
        assert "SUCCESS" in report
        assert "Column Count: 3" in report
        assert "MYSQL" in report
        print("✓ PASS: Report formatting works")
        print("\nSample report:")
        print(report)
        passed += 1
    except Exception as e:
        print(f"✗ FAIL: {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {passed + failed}")
    
    if failed == 0:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
