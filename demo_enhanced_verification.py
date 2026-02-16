#!/usr/bin/env python3
"""
Demo script for Enhanced Vulnerability Verification & Repeater Integration

This script demonstrates the new features:
1. VulnerabilityFinding with payload tracking and repeater data
2. Enhanced exploit plugins that return successful payloads
3. Repeater-ready request/response data for manual testing
4. Verified flag based on real exploitation evidence
"""

import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.scan_plugins import VulnerabilityFinding, create_repeater_request


def demo_vulnerability_finding_with_verification():
    """Demonstrate VulnerabilityFinding with enhanced verification features."""
    print("=" * 80)
    print("DEMO: VulnerabilityFinding with Verification & Repeater Data")
    print("=" * 80)
    print()
    
    # Create a sample finding with verification data
    finding = VulnerabilityFinding(
        vulnerability_type='info_disclosure',
        severity='high',
        url='https://example.com/admin/config.php',
        description='Sensitive configuration file exposed',
        evidence='Found AWS credentials and database password in exposed .env file',
        remediation='Remove sensitive files from web root, implement proper access controls',
        parameter=None,
        confidence=0.95,
        cwe_id='CWE-200',
        verified=True,  # Marked as verified because we extracted real credentials
        successful_payloads=['/.env', '/config/.env', '../.env'],
        repeater_requests=[
            create_repeater_request(
                url='https://example.com/.env',
                method='GET',
                headers={'User-Agent': 'Megido Scanner', 'Accept': '*/*'},
                description='Request that disclosed .env file with AWS credentials'
            )
        ]
    )
    
    # Convert to dict for JSON output
    finding_dict = finding.to_dict()
    
    print("Vulnerability Finding:")
    print(json.dumps(finding_dict, indent=2))
    print()
    
    # Highlight key features
    print("Key Features:")
    print(f"  • Verified: {finding_dict['verified']} (✓ Real exploitation confirmed)")
    print(f"  • Successful Payloads: {len(finding_dict.get('successful_payloads', []))} payloads worked")
    print(f"  • Repeater Requests: {len(finding_dict.get('repeater_requests', []))} copy-paste ready requests")
    print()


def demo_repeater_request_format():
    """Demonstrate the repeater request format."""
    print("=" * 80)
    print("DEMO: Repeater App Request Format")
    print("=" * 80)
    print()
    
    # Example POST request with response data
    repeater_req = create_repeater_request(
        url='https://sb-console-api.fireblocks.io/v1/users',
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Megido Scanner',
            'Authorization': 'Bearer test_token'
        },
        body='{"username": "admin\' OR \'1\'=\'1", "password": "test"}',
        description='SQL Injection via username parameter (error-based)'
    )
    
    # Add mock response data
    repeater_req['response'] = {
        'status_code': 500,
        'headers': {'Content-Type': 'application/json'},
        'body': 'SQL error: You have an error in your SQL syntax near \'admin\' OR \'1\'=\'1\'',
        'evidence': 'Database error reveals SQL injection vulnerability'
    }
    
    print("Repeater Request (Copy-Paste Ready):")
    print(json.dumps(repeater_req, indent=2))
    print()
    
    print("Usage in Repeater App:")
    print("  1. Copy the entire JSON object")
    print("  2. Paste into Megido Repeater App")
    print("  3. Click 'Send' to replay the request")
    print("  4. Compare response with original to verify")
    print()


def demo_exploit_result_format():
    """Demonstrate the exploit plugin result format."""
    print("=" * 80)
    print("DEMO: Exploit Plugin Result Format")
    print("=" * 80)
    print()
    
    # Mock exploit result from info_disclosure_plugin
    exploit_result = {
        'success': True,
        'vulnerability_type': 'info_disclosure',
        'disclosed_info': {
            '/.env': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtn...',
            '/config/database.yml': 'production:\n  adapter: postgresql\n  password: super_secret_pass...',
        },
        'evidence': 'Found 2 exposed file(s) containing sensitive credentials',
        'successful_payloads': ['/.env', '/config/database.yml'],
        'repeater_requests': [
            {
                'url': 'https://example.com/.env',
                'method': 'GET',
                'headers': {'User-Agent': 'Megido Scanner'},
                'body': '',
                'description': 'Request that disclosed /.env',
                'response': {
                    'status_code': 200,
                    'headers': {'Content-Type': 'text/plain'},
                    'body': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n...',
                    'size': 486
                }
            }
        ]
    }
    
    print("Exploit Plugin Result:")
    print(json.dumps(exploit_result, indent=2))
    print()
    
    print("Key Enhancements:")
    print("  • successful_payloads: List of payloads that led to exploitation")
    print("  • repeater_requests: Real request/response pairs for manual verification")
    print("  • Response includes actual data returned from target")
    print("  • Copy-paste ready for Megido Repeater App")
    print()


def demo_verified_vs_unverified():
    """Show the difference between verified and unverified findings."""
    print("=" * 80)
    print("DEMO: Verified vs Unverified Findings")
    print("=" * 80)
    print()
    
    # Unverified finding (detection only)
    unverified = VulnerabilityFinding(
        vulnerability_type='xss',
        severity='medium',
        url='https://example.com/search?q=test',
        description='Potential XSS vulnerability detected in search parameter',
        evidence='Reflected input without encoding detected',
        remediation='Implement proper output encoding',
        parameter='q',
        confidence=0.6,
        verified=False  # Not verified - just detected pattern
    )
    
    # Verified finding (actual exploitation)
    verified = VulnerabilityFinding(
        vulnerability_type='xss',
        severity='high',
        url='https://example.com/search?q=test',
        description='XSS vulnerability confirmed via JavaScript execution',
        evidence='Alert dialog triggered, screenshot captured, callback received',
        remediation='Implement proper output encoding and CSP headers',
        parameter='q',
        confidence=0.95,
        verified=True,  # Verified - JavaScript actually executed
        successful_payloads=[
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>'
        ],
        repeater_requests=[
            create_repeater_request(
                url='https://example.com/search?q=<script>alert(1)</script>',
                method='GET',
                headers={'User-Agent': 'Megido Scanner'},
                description='XSS payload that triggered alert dialog'
            )
        ]
    )
    
    print("UNVERIFIED Finding (Detection Only):")
    print(json.dumps(unverified.to_dict(), indent=2))
    print()
    
    print("VERIFIED Finding (Actual Exploitation):")
    print(json.dumps(verified.to_dict(), indent=2))
    print()
    
    print("Difference:")
    print("  Unverified: confidence=0.6, no payloads, no repeater data")
    print("  Verified:   confidence=0.95, 2 payloads, 1 repeater request")
    print("  → Verified findings have concrete proof of exploitation")
    print()


def main():
    """Run all demos."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 15 + "MEGIDO ENHANCED VERIFICATION DEMO" + " " * 30 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    demo_vulnerability_finding_with_verification()
    demo_repeater_request_format()
    demo_exploit_result_format()
    demo_verified_vs_unverified()
    
    print("=" * 80)
    print("Summary:")
    print("=" * 80)
    print()
    print("The enhanced scanner now provides:")
    print("  ✓ Verified flag based on real exploitation evidence")
    print("  ✓ Successful payloads that led to exploitation")
    print("  ✓ Copy-paste ready repeater requests for manual testing")
    print("  ✓ Real request/response data from actual exploitation")
    print("  ✓ Actionable evidence for security teams")
    print()
    print("This makes vulnerability reports:")
    print("  • More actionable (clear exploitation steps)")
    print("  • More trustworthy (verified = real impact)")
    print("  • Easier to reproduce (repeater-ready requests)")
    print("  • Better integrated with manual testing workflows")
    print()


if __name__ == '__main__':
    main()
