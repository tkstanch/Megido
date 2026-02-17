#!/usr/bin/env python3
"""
Demonstration script for NumericSqlInjector

This script demonstrates the functionality of the NumericSqlInjector class
for testing numeric parameters for SQL injection vulnerabilities.
"""

import sys
from sql_attacker.numeric_probe import NumericSqlInjector, NumericParameter


def demo_basic_usage():
    """Demonstrate basic usage of NumericSqlInjector"""
    print("=" * 70)
    print("NumericSqlInjector - Basic Usage Demo")
    print("=" * 70)
    print()
    
    # Initialize the injector
    injector = NumericSqlInjector(timeout=10, similarity_threshold=0.95)
    print(f"✓ Initialized NumericSqlInjector")
    print(f"  - Timeout: {injector.timeout}s")
    print(f"  - Similarity threshold: {injector.similarity_threshold}")
    print()


def demo_parameter_identification():
    """Demonstrate parameter identification"""
    print("=" * 70)
    print("Demo 1: Identifying Numeric Parameters")
    print("=" * 70)
    print()
    
    injector = NumericSqlInjector()
    
    # Example 1: URL with multiple parameters
    url1 = 'http://example.com/product?id=123&name=widget&page=5&category=electronics'
    print(f"URL: {url1}")
    params = injector.identify_numeric_parameters(url=url1, method='GET')
    
    print(f"Found {len(params)} numeric parameter(s):")
    for param in params:
        print(f"  - {param.name} = {param.value} (location: {param.location})")
    print()
    
    # Example 2: POST data
    print("POST data: {'user_id': '456', 'username': 'john', 'age': '30'}")
    params = injector.identify_numeric_parameters(
        url='http://example.com/api/user',
        method='POST',
        data={'user_id': '456', 'username': 'john', 'age': '30'}
    )
    
    print(f"Found {len(params)} numeric parameter(s):")
    for param in params:
        print(f"  - {param.name} = {param.value} (location: {param.location})")
    print()
    
    # Example 3: Cookies
    print("Cookies: {'session_id': 'abc123', 'user_id': '789'}")
    params = injector.identify_numeric_parameters(
        url='http://example.com',
        method='GET',
        cookies={'session_id': 'abc123', 'user_id': '789'}
    )
    
    print(f"Found {len(params)} numeric parameter(s):")
    for param in params:
        print(f"  - {param.name} = {param.value} (location: {param.location})")
    print()


def demo_payload_generation():
    """Demonstrate payload generation"""
    print("=" * 70)
    print("Demo 2: Generating Numeric SQL Injection Payloads")
    print("=" * 70)
    print()
    
    injector = NumericSqlInjector()
    
    # Generate payloads for value '5'
    value = '5'
    payloads = injector.generate_payloads(value)
    
    print(f"Generated {len(payloads)} payloads for value '{value}':")
    print()
    
    # Show some interesting payloads
    interesting_payloads = [
        '5',
        '5+0',
        '5-0',
        '5+1',
        '5-1',
        '67-ASCII("A")',
        "67-ASCII('A')",
        '51-ASCII(1)',
        '5|0',
        '(5+1)-1',
    ]
    
    for payload in interesting_payloads:
        if payload in payloads:
            print(f"  ✓ {payload}")
    
    print()
    print("These payloads use arithmetic operations that may behave")
    print("differently when interpreted by SQL databases vs. application code.")
    print()


def demo_url_encoding():
    """Demonstrate URL encoding"""
    print("=" * 70)
    print("Demo 3: URL Encoding of Payloads")
    print("=" * 70)
    print()
    
    injector = NumericSqlInjector()
    
    test_payloads = [
        '5+1',
        '5 + 1',
        '67-ASCII("A")',
        "67-ASCII('A')",
        'id=5&name=test',
    ]
    
    print("Query String Encoding:")
    for payload in test_payloads:
        encoded = injector.url_encode_payload(payload, 'query')
        print(f"  '{payload}' -> '{encoded}'")
    
    print()
    print("POST Body Encoding:")
    for payload in test_payloads[:2]:
        encoded = injector.url_encode_payload(payload, 'body')
        print(f"  '{payload}' -> '{encoded}'")
    
    print()
    print("Note: Special characters (&, =, +, ;, space) are properly encoded")
    print("to preserve the SQL injection payload while maintaining HTTP compliance.")
    print()


def demo_response_analysis():
    """Demonstrate response analysis concepts"""
    print("=" * 70)
    print("Demo 4: Response Analysis Concepts")
    print("=" * 70)
    print()
    
    injector = NumericSqlInjector()
    
    print("The injector analyzes responses by:")
    print()
    print("1. Similarity Comparison:")
    print("   - Compares test response with baseline")
    print("   - Uses SequenceMatcher for text similarity")
    
    # Example similarity calculations
    text1 = "Product ID: 5, Name: Widget, Price: $10"
    text2 = "Product ID: 5, Name: Widget, Price: $10"
    sim = injector._calculate_similarity(text1, text2)
    print(f"   - Identical responses: similarity = {sim:.2f}")
    
    text3 = "Error: Invalid product"
    sim = injector._calculate_similarity(text1, text3)
    print(f"   - Different responses: similarity = {sim:.2f}")
    print()
    
    print("2. SQL Error Detection:")
    print("   - Scans responses for database error messages")
    
    error_examples = [
        "You have an error in your SQL syntax",
        "PostgreSQL ERROR: syntax error",
        "ORA-00933: SQL command not properly ended",
        "Incorrect syntax near '1'",
    ]
    
    for error_text in error_examples:
        detected = injector._check_sql_errors(error_text)
        if detected:
            print(f"   ✓ Detects: '{detected}'")
    print()
    
    print("3. Status Code Changes:")
    print("   - Monitors HTTP status code differences")
    print("   - 200 -> 500 indicates potential vulnerability")
    print()
    
    print("4. Content Differences:")
    print("   - Large response differences suggest SQL interpretation")
    print("   - Threshold-based confidence scoring")
    print()


def demo_integration_example():
    """Show integration example"""
    print("=" * 70)
    print("Demo 5: Integration Example")
    print("=" * 70)
    print()
    
    print("Example code for integrating with Megido attack pipelines:")
    print()
    print("```python")
    print("from sql_attacker.numeric_probe import NumericSqlInjector")
    print()
    print("# Initialize injector")
    print("injector = NumericSqlInjector(")
    print("    timeout=15,")
    print("    max_retries=3,")
    print("    similarity_threshold=0.95")
    print(")")
    print()
    print("# Probe all parameters in a request")
    print("results = injector.probe_all_parameters(")
    print("    url='http://target.com/product?id=5&page=1',")
    print("    method='GET'")
    print(")")
    print()
    print("# Check for vulnerabilities")
    print("for result in results:")
    print("    if result.vulnerable:")
    print("        print(f'Vulnerable: {result.parameter.name}')")
    print("        print(f'Payload: {result.payload}')")
    print("        print(f'Confidence: {result.confidence:.2f}')")
    print("        print(f'Evidence: {result.evidence}')")
    print("```")
    print()


def demo_numeric_parameter_class():
    """Demonstrate NumericParameter class"""
    print("=" * 70)
    print("Demo 6: NumericParameter Class")
    print("=" * 70)
    print()
    
    # Create a parameter
    param = NumericParameter(
        name='product_id',
        value='12345',
        method='GET',
        location='query'
    )
    
    print(f"Created parameter: {param}")
    print()
    print(f"Attributes:")
    print(f"  - name: {param.name}")
    print(f"  - value: {param.value}")
    print(f"  - method: {param.method}")
    print(f"  - location: {param.location}")
    print()
    
    print(f"Dictionary representation:")
    print(f"  {param.to_dict()}")
    print()


def demo_order_by_injection():
    """Demonstrate ORDER BY injection detection"""
    print("=" * 70)
    print("Demo 7: ORDER BY-Based SQL Injection Detection")
    print("=" * 70)
    print()
    
    injector = NumericSqlInjector()
    
    print("ORDER BY injection detection analyzes parameters that may be used")
    print("in ORDER BY clauses or column selection by:")
    print()
    print("1. Testing sequential numeric values (1, 2, 3, ...)")
    print("2. Detecting ordering changes in responses")
    print("3. Detecting field/column changes in responses")
    print("4. Identifying column-with-1s pattern (column number usage)")
    print("5. Testing ORDER BY payloads (ASC --, DESC --)")
    print("6. Testing advanced payloads (subqueries, CASE expressions)")
    print()
    
    print("Example: ORDER BY payloads")
    print()
    for payload in injector.ORDER_BY_PAYLOADS[:8]:
        print(f"  • {payload}")
    print(f"  ... and {len(injector.ORDER_BY_PAYLOADS) - 8} more")
    print()
    
    print("Usage example:")
    print()
    print("```python")
    print("# Create a parameter suspected to be used in ORDER BY")
    print("param = NumericParameter('sort', '1', 'GET', 'query')")
    print()
    print("# Analyze for ORDER BY injection")
    print("results = injector.analyze_order_by_injection(")
    print("    url='http://example.com/products?sort=1',")
    print("    parameter=param,")
    print("    method='GET',")
    print("    params={'sort': '1'},")
    print("    max_sequential=10")
    print(")")
    print()
    print("# Check for ORDER BY vulnerabilities")
    print("for result in results:")
    print("    if result.vulnerable:")
    print("        print(f'Type: {result.injection_type}')")
    print("        print(f'Ordering changed: {result.ordering_changed}')")
    print("        print(f'Fields changed: {result.field_changed}')")
    print("```")
    print()
    
    print("Detection Features:")
    print()
    print("✓ Ordering Change Detection")
    print("  - Identifies when item ordering changes (ascending/descending)")
    print("  - Detects reversed sequences and reordered items")
    print()
    print("✓ Field Change Detection")
    print("  - Identifies when response fields/columns change")
    print("  - Indicates parameter controls column selection")
    print()
    print("✓ Column-with-1s Pattern")
    print("  - Detects when a column contains all '1' values")
    print("  - Suggests parameter used as column number")
    print("  - Pattern: SELECT * FROM table ORDER BY <param>")
    print()
    print("✓ Advanced Payload Testing")
    print("  - Subqueries: (SELECT 1), (SELECT 1 WHERE 1=1)")
    print("  - CASE expressions: (CASE WHEN 1=1 THEN 1 ELSE 2 END)")
    print("  - MS-SQL specific: batched queries, WAITFOR DELAY")
    print()


def main():
    """Run all demos"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "NumericSqlInjector Demonstration" + " " * 21 + "║")
    print("║" + " " * 15 + "SQL Injection Probing for Numeric Parameters" + " " * 9 + "║")
    print("║" + " " * 12 + "Now with ORDER BY Injection Detection!" + " " * 17 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    try:
        demo_basic_usage()
        input("Press Enter to continue...")
        print()
        
        demo_parameter_identification()
        input("Press Enter to continue...")
        print()
        
        demo_payload_generation()
        input("Press Enter to continue...")
        print()
        
        demo_url_encoding()
        input("Press Enter to continue...")
        print()
        
        demo_response_analysis()
        input("Press Enter to continue...")
        print()
        
        demo_numeric_parameter_class()
        input("Press Enter to continue...")
        print()
        
        demo_order_by_injection()
        input("Press Enter to continue...")
        print()
        
        demo_integration_example()
        
        print()
        print("=" * 70)
        print("✅ Demo Complete!")
        print("=" * 70)
        print()
        print("For more information, see:")
        print("  - sql_attacker/numeric_probe.py (implementation)")
        print("  - sql_attacker/test_numeric_probe.py (tests)")
        print("  - sql_attacker/NUMERIC_PROBE_README.md (documentation)")
        print()
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)


if __name__ == '__main__':
    main()
