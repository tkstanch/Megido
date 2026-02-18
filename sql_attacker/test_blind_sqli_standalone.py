#!/usr/bin/env python3
"""
Standalone tests for blind SQL injection detectors
"""

import sys
import os

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from sql_attacker.error_based_blind_detector import ErrorBasedBlindDetector, ErrorPattern
from sql_attacker.boolean_blind_detector import BooleanBlindDetector, ResponsePattern


class MockResponse:
    """Mock HTTP response for testing"""
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def test_error_based_detector():
    """Test error-based blind detector"""
    print("\n" + "=" * 70)
    print("Testing Error-Based Blind SQL Injection Detector")
    print("=" * 70)
    
    detector = ErrorBasedBlindDetector()
    
    # Test 1: Initialization
    print("\n[Test 1] Initialization...")
    assert detector is not None
    assert detector.confidence_threshold == 0.8
    print("✓ Passed")
    
    # Test 2: Analyze response with no error
    print("\n[Test 2] Analyze response without error...")
    response = MockResponse("Normal content", 200)
    pattern = detector.analyze_response(response)
    assert isinstance(pattern, ErrorPattern)
    assert not pattern.has_error
    assert pattern.status_code == 200
    print("✓ Passed")
    
    # Test 3: Analyze response with HTTP 500
    print("\n[Test 3] Analyze response with HTTP 500...")
    response = MockResponse("Internal Server Error", 500)
    pattern = detector.analyze_response(response)
    assert pattern.has_error
    assert pattern.status_code == 500
    assert 'HTTP 500' in pattern.error_indicators
    print("✓ Passed")
    
    # Test 4: Analyze response with MySQL error
    print("\n[Test 4] Analyze response with MySQL error...")
    response = MockResponse("You have an error in your SQL syntax", 200)
    pattern = detector.analyze_response(response)
    assert pattern.has_error
    assert len(pattern.error_indicators) > 0
    print("✓ Passed")
    
    # Test 5: Analyze response with division by zero
    print("\n[Test 5] Analyze response with division by zero...")
    response = MockResponse("Warning: Division by zero", 200)
    pattern = detector.analyze_response(response)
    assert pattern.has_error
    print("✓ Passed")
    
    # Test 6: Conditional error payloads exist
    print("\n[Test 6] Check conditional error payloads...")
    assert 'mysql' in detector.CONDITIONAL_ERROR_PAYLOADS
    assert 'mssql' in detector.CONDITIONAL_ERROR_PAYLOADS
    assert 'oracle' in detector.CONDITIONAL_ERROR_PAYLOADS
    assert 'postgresql' in detector.CONDITIONAL_ERROR_PAYLOADS
    print("✓ Passed")
    
    # Test 7: Extraction templates exist
    print("\n[Test 7] Check extraction templates...")
    assert 'mysql' in detector.EXTRACTION_TEMPLATES
    assert 'mssql' in detector.EXTRACTION_TEMPLATES
    assert 'oracle' in detector.EXTRACTION_TEMPLATES
    assert 'postgresql' in detector.EXTRACTION_TEMPLATES
    print("✓ Passed")
    
    # Test 8: Payload formatting
    print("\n[Test 8] Test payload formatting...")
    mysql_payloads = detector.CONDITIONAL_ERROR_PAYLOADS['mysql']
    error_payload = next(p for p in mysql_payloads if p['error_expected'] == 'true' and '{data}' not in p['payload_template'])
    formatted = error_payload['payload_template'].format(condition="1=1")
    assert "1=1" in formatted
    print("✓ Passed")
    
    # Test 9: Establish baseline
    print("\n[Test 9] Establish baseline...")
    response = MockResponse("Normal response", 200)
    baseline = detector.establish_baseline(response)
    assert isinstance(baseline, ErrorPattern)
    assert detector.baseline_pattern is not None
    print("✓ Passed")
    
    # Test 10: Generate report
    print("\n[Test 10] Generate report...")
    report = detector.generate_report()
    assert isinstance(report, str)
    assert 'ERROR-BASED BLIND' in report
    print("✓ Passed")
    
    print("\n" + "=" * 70)
    print("All Error-Based Detector Tests Passed! ✓")
    print("=" * 70)


def test_boolean_blind_detector():
    """Test boolean-based blind detector"""
    print("\n" + "=" * 70)
    print("Testing Boolean-Based Blind SQL Injection Detector")
    print("=" * 70)
    
    detector = BooleanBlindDetector()
    
    # Test 1: Initialization
    print("\n[Test 1] Initialization...")
    assert detector is not None
    assert detector.similarity_threshold == 0.95
    print("✓ Passed")
    
    # Test 2: Analyze response
    print("\n[Test 2] Analyze response...")
    response = MockResponse("Test content", 200)
    pattern = detector.analyze_response(response)
    assert isinstance(pattern, ResponsePattern)
    assert pattern.content == "Test content"
    assert pattern.status_code == 200
    print("✓ Passed")
    
    # Test 3: Calculate similarity for identical responses
    print("\n[Test 3] Calculate similarity - identical...")
    response1 = MockResponse("Same content", 200)
    response2 = MockResponse("Same content", 200)
    pattern1 = detector.analyze_response(response1)
    pattern2 = detector.analyze_response(response2)
    similarity = detector.calculate_similarity(pattern1, pattern2)
    assert similarity == 1.0
    print("✓ Passed")
    
    # Test 4: Calculate similarity for different responses
    print("\n[Test 4] Calculate similarity - different...")
    response1 = MockResponse("Content A", 200)
    response2 = MockResponse("Completely different content B with much more text", 200)
    pattern1 = detector.analyze_response(response1)
    pattern2 = detector.analyze_response(response2)
    similarity = detector.calculate_similarity(pattern1, pattern2)
    assert similarity < 0.8  # Should be noticeably different
    print("✓ Passed")
    
    # Test 5: Establish baseline
    print("\n[Test 5] Establish baseline...")
    response = MockResponse("Normal response", 200)
    baseline = detector.establish_baseline(response)
    assert isinstance(baseline, ResponsePattern)
    assert 'normal' in detector.baseline_responses
    print("✓ Passed")
    
    # Test 6: Boolean payloads exist
    print("\n[Test 6] Check boolean payloads...")
    assert 'numeric' in detector.BOOLEAN_PAYLOADS
    assert 'string' in detector.BOOLEAN_PAYLOADS
    assert 'advanced' in detector.BOOLEAN_PAYLOADS
    print("✓ Passed")
    
    # Test 7: Extraction templates with ASCII support
    print("\n[Test 7] Check extraction templates with ASCII...")
    assert 'mysql' in detector.EXTRACTION_TEMPLATES
    mysql_templates = detector.EXTRACTION_TEMPLATES['mysql']
    assert 'ascii_extraction' in mysql_templates
    assert 'char_extraction' in mysql_templates
    print("✓ Passed")
    
    # Test 8: ASCII extraction template formatting
    print("\n[Test 8] Test ASCII extraction template...")
    templates = detector.EXTRACTION_TEMPLATES['mysql']
    ascii_condition = templates['ascii_extraction'].format(
        column="(@@version)",
        position=1,
        ascii_code=53
    )
    assert "@@version" in ascii_condition
    assert "ASCII" in ascii_condition
    assert "53" in ascii_condition
    print("✓ Passed")
    
    # Test 9: Generate report
    print("\n[Test 9] Generate report...")
    report = detector.generate_report()
    assert isinstance(report, str)
    assert 'BOOLEAN-BASED BLIND' in report
    print("✓ Passed")
    
    print("\n" + "=" * 70)
    print("All Boolean-Based Detector Tests Passed! ✓")
    print("=" * 70)


def test_payload_examples():
    """Test that example payloads from problem statement are supported"""
    print("\n" + "=" * 70)
    print("Testing Payload Examples from Problem Statement")
    print("=" * 70)
    
    # Boolean-based examples
    print("\n[Boolean-Based Payloads]")
    
    detector = BooleanBlindDetector()
    templates = detector.EXTRACTION_TEMPLATES
    
    # MySQL example
    print("\nMySQL: ' AND ASCII(SUBSTRING((SELECT database()),1,1))=68--")
    mysql_template = templates['mysql']['ascii_extraction']
    payload = mysql_template.format(column="(SELECT database())", position=1, ascii_code=68)
    assert "ASCII" in payload
    assert "SUBSTRING" in payload
    assert "68" in payload
    print("✓ Template supports this pattern")
    
    # MS-SQL example
    print("\nMS-SQL: ' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))=68--")
    mssql_template = templates['mssql']['ascii_extraction']
    payload = mssql_template.format(column="(SELECT DB_NAME())", position=1, ascii_code=68)
    assert "ASCII" in payload
    assert "SUBSTRING" in payload
    assert "68" in payload
    print("✓ Template supports this pattern")
    
    # Oracle example
    print("\nOracle: ' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))=68--")
    oracle_template = templates['oracle']['ascii_extraction']
    payload = oracle_template.format(column="(SELECT user FROM dual)", position=1, ascii_code=68)
    assert "ASCII" in payload
    assert "SUBSTR" in payload
    assert "68" in payload
    print("✓ Template supports this pattern")
    
    # Error-based examples
    print("\n\n[Error-Based Payloads]")
    
    error_detector = ErrorBasedBlindDetector()
    
    # Oracle example
    print("\nOracle: (SELECT 1/0 FROM dual WHERE ...)")
    oracle_payloads = error_detector.CONDITIONAL_ERROR_PAYLOADS['oracle']
    has_divide_zero = any('1/0' in p['payload_template'] and 'dual' in p['payload_template'] for p in oracle_payloads)
    assert has_divide_zero
    print("✓ Payload library includes this pattern")
    
    # MySQL example
    print("\nMySQL: AND IF((SELECT SUBSTRING(@@version,1,1))='5', (SELECT 1/0), 1)")
    mysql_payloads = error_detector.CONDITIONAL_ERROR_PAYLOADS['mysql']
    has_if_divide = any('IF' in p['payload_template'] and '1/0' in p['payload_template'] for p in mysql_payloads)
    assert has_if_divide
    print("✓ Payload library includes this pattern")
    
    # MS-SQL example
    print("\nMS-SQL: AND 1=CASE WHEN ... THEN 1/0 ELSE 1 END")
    mssql_payloads = error_detector.CONDITIONAL_ERROR_PAYLOADS['mssql']
    has_case_divide = any('CASE' in p['payload_template'] and '1/0' in p['payload_template'] for p in mssql_payloads)
    assert has_case_divide
    print("✓ Payload library includes this pattern")
    
    print("\n" + "=" * 70)
    print("All Payload Examples Verified! ✓")
    print("=" * 70)


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("   BLIND SQL INJECTION DETECTOR - STANDALONE TEST SUITE")
    print("=" * 70)
    
    try:
        test_error_based_detector()
        test_boolean_blind_detector()
        test_payload_examples()
        
        print("\n" + "=" * 70)
        print("                ALL TESTS PASSED! ✓✓✓")
        print("=" * 70)
        print("\nSummary:")
        print("  ✓ Error-based blind detector: All tests passed")
        print("  ✓ Boolean-based blind detector: All tests passed")
        print("  ✓ Payload examples: All verified")
        print("\nModules tested:")
        print("  - sql_attacker/error_based_blind_detector.py")
        print("  - sql_attacker/boolean_blind_detector.py")
        print()
        return 0
    
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
