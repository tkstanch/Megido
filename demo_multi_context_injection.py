#!/usr/bin/env python3
"""
Multi-Context Injection Attack Demo

Demonstrates the usage of the new multi-context injection attack framework.
This script shows how to test a target across multiple injection contexts.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.multi_context_orchestrator import MultiContextAttackOrchestrator
from sql_attacker.injection_contexts import InjectionContextType


def print_banner():
    """Print banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     Multi-Context Injection Attack Framework Demo               ║
║     SQL Attacker Module - Megido Security Platform              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def demo_context_statistics():
    """Demonstrate context statistics."""
    print("\n[*] Initializing Multi-Context Orchestrator...")
    
    orchestrator = MultiContextAttackOrchestrator({
        'enabled_contexts': [
            InjectionContextType.SQL,
            InjectionContextType.LDAP,
            InjectionContextType.XPATH,
            InjectionContextType.MESSAGE_QUEUE,
            InjectionContextType.CUSTOM_QUERY,
        ],
        'parallel_execution': True,
        'max_workers': 5,
    })
    
    print("[+] Orchestrator initialized successfully!")
    
    stats = orchestrator.get_context_statistics()
    
    print(f"\n[*] Context Statistics:")
    print(f"    - Enabled Contexts: {stats['enabled_contexts']}")
    print(f"    - Total Payloads: {stats['total_payloads']}")
    print(f"\n[*] Context Details:")
    
    for context_name, info in stats['contexts'].items():
        print(f"\n    📍 {context_name.upper()}")
        print(f"       Description: {info['description']}")
        print(f"       Payloads: {info['payload_count']}")


def demo_sql_context():
    """Demonstrate SQL context testing."""
    print("\n" + "="*70)
    print("[*] SQL Injection Context Demo")
    print("="*70)
    
    from sql_attacker.injection_contexts.sql_context import SQLInjectionContext
    
    context = SQLInjectionContext()
    
    print(f"\n[+] Loaded {context.get_payload_count()} SQL injection payloads")
    print(f"[+] Context: {context.get_description()}")
    
    # Example payloads
    print("\n[*] Example SQL Injection Payloads:")
    for i, payload in enumerate(context.payloads[:5], 1):
        print(f"    {i}. {payload}")
    
    # Simulate response analysis
    print("\n[*] Testing Response Analysis:")
    
    test_cases = [
        ("You have an error in your SQL syntax near '1'", True, "SQL Error"),
        ("Welcome to our website", False, "Clean Response"),
        ("MySQL server version 5.7.32", True, "Version Leak"),
    ]
    
    for response_body, expected_success, description in test_cases:
        success, confidence, evidence = context.analyze_response(
            response_body, {}, 0.5
        )
        status = "✓" if success == expected_success else "✗"
        print(f"    {status} {description}: {success} (confidence: {confidence:.2f})")
        if success:
            print(f"       Evidence: {evidence[:60]}...")


def demo_ldap_context():
    """Demonstrate LDAP context testing."""
    print("\n" + "="*70)
    print("[*] LDAP Injection Context Demo")
    print("="*70)
    
    from sql_attacker.injection_contexts.ldap_context import LDAPInjectionContext
    
    context = LDAPInjectionContext()
    
    print(f"\n[+] Loaded {context.get_payload_count()} LDAP injection payloads")
    print(f"[+] Context: {context.get_description()}")
    
    print("\n[*] Example LDAP Injection Payloads:")
    for i, payload in enumerate(context.payloads[:5], 1):
        print(f"    {i}. {payload}")


def demo_xpath_context():
    """Demonstrate XPath context testing."""
    print("\n" + "="*70)
    print("[*] XPath Injection Context Demo")
    print("="*70)
    
    from sql_attacker.injection_contexts.xpath_context import XPathInjectionContext
    
    context = XPathInjectionContext()
    
    print(f"\n[+] Loaded {context.get_payload_count()} XPath injection payloads")
    print(f"[+] Context: {context.get_description()}")
    
    print("\n[*] Example XPath Injection Payloads:")
    for i, payload in enumerate(context.payloads[:5], 1):
        print(f"    {i}. {payload}")


def demo_message_queue_context():
    """Demonstrate Message Queue context testing."""
    print("\n" + "="*70)
    print("[*] Message Queue Injection Context Demo")
    print("="*70)
    
    from sql_attacker.injection_contexts.message_queue_context import MessageQueueInjectionContext
    
    context = MessageQueueInjectionContext()
    
    print(f"\n[+] Loaded {context.get_payload_count()} message queue injection payloads")
    print(f"[+] Context: {context.get_description()}")
    
    print("\n[*] Example Message Queue Injection Payloads:")
    for i, payload in enumerate(context.payloads[:5], 1):
        print(f"    {i}. {payload}")


def demo_custom_query_context():
    """Demonstrate Custom Query context testing."""
    print("\n" + "="*70)
    print("[*] Custom Query Language Injection Context Demo")
    print("="*70)
    
    from sql_attacker.injection_contexts.custom_query_context import CustomQueryInjectionContext
    
    context = CustomQueryInjectionContext()
    
    print(f"\n[+] Loaded {context.get_payload_count()} custom query injection payloads")
    print(f"[+] Context: {context.get_description()}")
    
    print("\n[*] Example Custom Query Injection Payloads:")
    print("    (GraphQL, JSONPath, OData, etc.)")
    for i, payload in enumerate(context.payloads[:5], 1):
        print(f"    {i}. {payload}")


def demo_attack_report():
    """Demonstrate attack report generation."""
    print("\n" + "="*70)
    print("[*] Attack Report Generation Demo")
    print("="*70)
    
    from sql_attacker.injection_contexts import AttackVector, InjectionResult
    
    # Create mock results for demonstration
    results = []
    
    # SQL injection result
    sql_vector = AttackVector(
        context_type=InjectionContextType.SQL,
        parameter_name="id",
        parameter_type="GET",
        payload="' OR '1'='1",
        description="SQL injection via GET parameter"
    )
    
    sql_result = InjectionResult(
        success=True,
        context_type=InjectionContextType.SQL,
        attack_vector=sql_vector,
        evidence="MySQL error: You have an error in your SQL syntax",
        confidence_score=0.95,
        response_time=0.5,
        response_status=500,
        response_body="Error in SQL syntax...",
        exploited=True,
        extracted_data={'database_version': 'MySQL 5.7.32', 'current_user': 'root@localhost'}
    )
    results.append(sql_result)
    
    # LDAP injection result
    ldap_vector = AttackVector(
        context_type=InjectionContextType.LDAP,
        parameter_name="username",
        parameter_type="POST",
        payload="*)(uid=*",
        description="LDAP injection via POST parameter"
    )
    
    ldap_result = InjectionResult(
        success=True,
        context_type=InjectionContextType.LDAP,
        attack_vector=ldap_vector,
        evidence="LDAP error: Invalid filter syntax",
        confidence_score=0.90,
        response_time=0.3,
        response_status=500,
        response_body="LDAP Exception...",
        exploited=False,
    )
    results.append(ldap_result)
    
    # Generate report
    orchestrator = MultiContextAttackOrchestrator()
    report = orchestrator.generate_attack_report(
        results,
        "http://example.com/test",
        "id"
    )
    
    print(f"\n[*] Attack Report:")
    print(f"    Target URL: {report['target_url']}")
    print(f"    Parameter: {report['parameter_name']}")
    print(f"    Total Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"    Contexts Affected: {report['contexts_affected']}")
    
    print(f"\n[*] Vulnerabilities by Context:")
    for context, vulns in report['vulnerabilities_by_context'].items():
        print(f"\n    📍 {context.upper()}: {len(vulns)} vulnerabilities")
        for vuln in vulns:
            print(f"       - Payload: {vuln['payload'][:50]}...")
            print(f"         Confidence: {vuln['confidence']:.2%}")
            print(f"         Exploited: {vuln['exploited']}")
    
    print(f"\n[*] High Confidence Findings: {len(report['high_confidence_findings'])}")
    print(f"[*] Exploited Vulnerabilities: {len(report['exploited_vulnerabilities'])}")


def main():
    """Main demo function."""
    print_banner()
    
    print("\nThis demo showcases the Multi-Context Injection Attack Framework.")
    print("The framework supports 5 different injection contexts:")
    print("  1. SQL Injection")
    print("  2. LDAP Injection")
    print("  3. XPath Injection")
    print("  4. Message Queue Injection")
    print("  5. Custom Query Language Injection")
    
    try:
        # Demonstrate context statistics
        demo_context_statistics()
        
        # Demonstrate individual contexts
        demo_sql_context()
        demo_ldap_context()
        demo_xpath_context()
        demo_message_queue_context()
        demo_custom_query_context()
        
        # Demonstrate attack reporting
        demo_attack_report()
        
        print("\n" + "="*70)
        print("[✓] Demo completed successfully!")
        print("="*70)
        
        print("\n[*] Next Steps:")
        print("    1. Review the MULTI_CONTEXT_INJECTION_GUIDE.md for detailed documentation")
        print("    2. Use the dashboard UI to run multi-context attacks")
        print("    3. Customize contexts for your specific testing needs")
        print("    4. Extend the framework with new injection contexts")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
