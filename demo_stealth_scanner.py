#!/usr/bin/env python3
"""
Stealth Scanner Demo

This script demonstrates the advanced stealth and exploitation features
of Megido's vulnerability scanner.

Features demonstrated:
- Stealth engine with randomized headers and timing
- Adaptive payload generation
- Context detection and reflection analysis
- WAF detection
- Filter bypass suggestions

Usage:
    python demo_stealth_scanner.py --url https://target.com
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.stealth_engine import get_stealth_engine
from scanner.adaptive_payload_engine import get_adaptive_payload_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print demo banner."""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                 Megido Stealth Scanner Demo                   ║
║                                                               ║
║  Advanced Stealth & Exploitation Capabilities                ║
╚═══════════════════════════════════════════════════════════════╝
    """)


def demo_stealth_engine():
    """Demonstrate stealth engine capabilities."""
    print("\n[*] Stealth Engine Demo")
    print("=" * 60)
    
    # Initialize stealth engine
    stealth = get_stealth_engine({
        'min_delay': 0.5,
        'max_delay': 2.0,
        'jitter_range': 0.3,
        'enable_session_rotation': True,
    })
    
    # Generate randomized headers
    print("\n[1] Randomized HTTP Headers:")
    headers = stealth.get_randomized_headers()
    
    print(f"  User-Agent: {headers['User-Agent'][:70]}...")
    print(f"  Accept: {headers['Accept'][:60]}...")
    print(f"  Accept-Language: {headers['Accept-Language']}")
    print(f"  Accept-Encoding: {headers['Accept-Encoding']}")
    
    if 'Sec-Fetch-Dest' in headers:
        print(f"  Sec-Fetch-Dest: {headers['Sec-Fetch-Dest']}")
        print(f"  Sec-Fetch-Mode: {headers['Sec-Fetch-Mode']}")
    
    # Request delay
    print("\n[2] Request Timing with Jitter:")
    for i in range(3):
        delay = stealth.get_request_delay()
        print(f"  Request {i+1} delay: {delay:.3f}s")
    
    # Session management
    print("\n[3] Session Management:")
    print(f"  Current session ID: {stealth.current_session_id[:16]}...")
    
    cookies = stealth.get_session_cookies('example.com')
    print(f"  Generated {len(cookies)} cookies:")
    for name, value in list(cookies.items())[:3]:
        print(f"    {name}: {value[:32]}...")
    
    # URL parameter randomization
    print("\n[4] URL Parameter Randomization:")
    original_url = "https://example.com/search?query=test&page=1&sort=date&filter=all"
    print(f"  Original: {original_url}")
    
    randomized_url = stealth.randomize_url_parameters(original_url)
    print(f"  Randomized: {randomized_url}")
    
    # Payload encoding
    print("\n[5] Payload Encoding Variations:")
    payload = '<script>alert(1)</script>'
    print(f"  Original: {payload}")
    
    encodings = ['url', 'html', 'unicode', 'mixed']
    for enc in encodings:
        encoded = stealth.encode_payload(payload, enc)
        print(f"  {enc.capitalize()}: {encoded[:60]}...")


def demo_adaptive_payloads():
    """Demonstrate adaptive payload engine capabilities."""
    print("\n\n[*] Adaptive Payload Engine Demo")
    print("=" * 60)
    
    engine = get_adaptive_payload_engine()
    
    # Context-aware XSS payloads
    print("\n[1] Context-Aware XSS Payloads:")
    
    contexts = ['html', 'attribute', 'javascript', 'json']
    for context in contexts:
        payloads = engine.generate_adaptive_payloads('xss', context=context)
        print(f"\n  {context.upper()} Context ({len(payloads)} payloads):")
        for payload in payloads[:2]:
            print(f"    - {payload}")
    
    # SQL injection payloads
    print("\n\n[2] Database-Specific SQL Injection Payloads:")
    
    databases = ['mysql', 'postgresql', 'mssql']
    for db in databases:
        payloads = engine.generate_adaptive_payloads('sqli', context=db)
        print(f"\n  {db.upper()} ({len(payloads)} payloads):")
        for payload in payloads[:2]:
            print(f"    - {payload}")
    
    # Payload encoding variations
    print("\n\n[3] Multi-Encoded Payloads:")
    base_payload = '<script>alert(1)</script>'
    variants = engine.generate_multi_encoded_payloads(base_payload)
    
    print(f"  Generated {len(variants)} variants from: {base_payload}")
    for variant in variants[:4]:
        print(f"    - {variant[:60]}...")


def demo_reflection_analysis():
    """Demonstrate reflection analysis capabilities."""
    print("\n\n[*] Reflection Analysis Demo")
    print("=" * 60)
    
    engine = get_adaptive_payload_engine()
    
    # Test payload
    test_payload = '<script>TEST123</script>'
    
    # Scenario 1: Direct reflection
    print("\n[1] Direct Reflection (No Filtering):")
    response1 = f'<div>You searched for: {test_payload}</div>'
    analysis1 = engine.analyze_reflection(response1, test_payload)
    
    print(f"  Reflected: {analysis1['reflected']}")
    print(f"  Context: {analysis1['context']}")
    print(f"  Encoded: {analysis1['encoded']}")
    print(f"  Filtered: {analysis1['filtered']}")
    
    # Scenario 2: Encoded reflection
    print("\n[2] Encoded Reflection (HTML Entities):")
    response2 = '<div>You searched for: &lt;script&gt;TEST123&lt;/script&gt;</div>'
    analysis2 = engine.analyze_reflection(response2, test_payload)
    
    print(f"  Reflected: {analysis2['reflected']}")
    print(f"  Context: {analysis2['context']}")
    print(f"  Encoded: {analysis2['encoded']}")
    
    # Scenario 3: Filtered reflection
    print("\n[3] Filtered Reflection (Tag Stripped):")
    response3 = '<div>You searched for: alert(1)</div>'
    analysis3 = engine.analyze_reflection(response3, test_payload)
    
    print(f"  Reflected: {analysis3['reflected']}")
    print(f"  Filtered: {analysis3['filtered']}")
    
    if analysis3['filter_bypasses']:
        print(f"  Bypass Suggestions:")
        for bypass in analysis3['filter_bypasses']:
            print(f"    - {bypass}")


def demo_waf_detection():
    """Demonstrate WAF detection capabilities."""
    print("\n\n[*] WAF Detection Demo")
    print("=" * 60)
    
    engine = get_adaptive_payload_engine()
    
    # Test various WAF signatures
    waf_tests = [
        {
            'name': 'Cloudflare',
            'headers': {'cf-ray': '12345-LAX', 'server': 'cloudflare'},
            'status': 403,
            'body': 'Access denied'
        },
        {
            'name': 'AWS WAF',
            'headers': {'x-amzn-requestid': '12345', 'server': 'awselb'},
            'status': 403,
            'body': 'Forbidden'
        },
        {
            'name': 'No WAF',
            'headers': {'server': 'nginx/1.18.0'},
            'status': 200,
            'body': 'Welcome'
        }
    ]
    
    for test in waf_tests:
        waf = engine.detect_waf_signature(
            test['body'],
            test['status'],
            test['headers']
        )
        
        result = waf if waf else "Not detected"
        print(f"\n  {test['name']}: {result}")


def demo_best_payload_selection():
    """Demonstrate intelligent payload selection."""
    print("\n\n[*] Intelligent Payload Selection Demo")
    print("=" * 60)
    
    engine = get_adaptive_payload_engine()
    
    # Scenario: Filter detected, need bypasses
    print("\n[1] Payload Selection with Filter Detection:")
    
    reflection_analysis = {
        'reflected': True,
        'filtered': True,
        'filter_bypasses': [
            'Use alternative tags: <img>, <svg>, <iframe>',
            'Try event handlers: onerror, onload'
        ]
    }
    
    payloads = engine.select_best_payloads(
        'xss',
        'html',
        reflection_analysis=reflection_analysis,
        max_payloads=5
    )
    
    print(f"  Selected {len(payloads)} optimized payloads:")
    for i, payload in enumerate(payloads, 1):
        print(f"    {i}. {payload}")


def demo_full_workflow():
    """Demonstrate a complete stealth scanning workflow."""
    print("\n\n[*] Complete Stealth Workflow Demo")
    print("=" * 60)
    
    stealth = get_stealth_engine()
    payload_engine = get_adaptive_payload_engine()
    
    print("\n[1] Initialize stealth session")
    session_id = stealth.current_session_id
    print(f"  Session ID: {session_id[:16]}...")
    
    print("\n[2] Generate stealth headers")
    headers = stealth.get_randomized_headers()
    print(f"  User-Agent: {headers['User-Agent'][:50]}...")
    
    print("\n[3] Generate adaptive payloads")
    payloads = payload_engine.generate_adaptive_payloads('xss', context='html')
    print(f"  Generated {len(payloads)} XSS payloads")
    
    print("\n[4] Apply timing delay")
    delay = stealth.get_request_delay()
    print(f"  Waiting {delay:.2f}s before request...")
    
    print("\n[5] Encode payload for evasion")
    payload = payloads[0]
    encoded = stealth.encode_payload(payload, 'mixed')
    print(f"  Original: {payload}")
    print(f"  Encoded: {encoded[:60]}...")
    
    print("\n[6] Ready to send stealthy request!")
    print("  (In real scenario, would use make_stealth_request())")


def main():
    """Main demo function."""
    parser = argparse.ArgumentParser(
        description='Megido Stealth Scanner Feature Demo'
    )
    parser.add_argument(
        '--demo',
        choices=['all', 'stealth', 'payloads', 'reflection', 'waf', 'workflow'],
        default='all',
        help='Demo to run (default: all)'
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo in ['all', 'stealth']:
        demo_stealth_engine()
    
    if args.demo in ['all', 'payloads']:
        demo_adaptive_payloads()
    
    if args.demo in ['all', 'reflection']:
        demo_reflection_analysis()
    
    if args.demo in ['all', 'waf']:
        demo_waf_detection()
    
    if args.demo in ['all', 'workflow']:
        demo_full_workflow()
    
    print("\n\n[*] Demo Complete!")
    print("\nFor full documentation, see: STEALTH_FEATURES_GUIDE.md")
    print("\nUsage in real scans:")
    print("  from scanner.scan_engine import ScanEngine")
    print("  engine = ScanEngine()")
    print("  findings = engine.scan(url, {'enable_stealth': True})")
    print()


if __name__ == '__main__':
    main()
