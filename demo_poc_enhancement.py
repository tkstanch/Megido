#!/usr/bin/env python3
"""
Demo script for PoC Enhancement Feature

This script demonstrates the enhanced vulnerability scanner that always populates
the proof_of_impact field with actionable evidence, including both:
1. Verified findings (with credentials/secrets) - marked with green "VERIFIED" badge
2. Unverified findings with generic evidence (stack traces, errors) - marked with yellow "EVIDENCE FOUND" badge

Usage:
    python demo_poc_enhancement.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.plugins.exploits.info_disclosure_plugin import InfoDisclosurePlugin


def print_separator(title=""):
    """Print a visual separator"""
    if title:
        print(f"\n{'=' * 80}")
        print(f" {title}")
        print(f"{'=' * 80}\n")
    else:
        print(f"{'=' * 80}\n")


def demo_verified_with_credentials():
    """Demo 1: Verified finding with credentials"""
    print_separator("DEMO 1: Verified Finding - Credentials Exposed")
    
    plugin = InfoDisclosurePlugin()
    
    # Simulate result with credentials
    result = {
        'success': True,
        'disclosed_info': {
            '/.env': 'API_KEY=example_abc123def456ghi789jkl012mno345\nDB_PASSWORD=MyS3cr3tP@ss!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
            '/config/database.yml': 'production:\n  password: admin123\n  host: db.internal.com'
        },
        'evidence': 'Found 2 exposed file(s) with credentials',
        'vulnerability_type': 'info_disclosure'
    }
    
    is_verified, proof = plugin.verify(
        result=result,
        target_url='https://example.com',
        vulnerability_data={}
    )
    
    print(f"✓ Verified: {is_verified}")
    print(f"✓ PoC Generated: {'Yes' if proof else 'No'}\n")
    print("PROOF OF IMPACT:")
    print("-" * 80)
    print(proof)
    print("-" * 80)
    print("\n✅ Dashboard will show this with a GREEN badge: '✓ Proof of Impact (VERIFIED)'")


def demo_unverified_with_stack_trace():
    """Demo 2: Unverified finding with stack trace"""
    print_separator("DEMO 2: Unverified Finding - Stack Trace Exposed")
    
    plugin = InfoDisclosurePlugin()
    
    # Simulate result with stack trace but no credentials
    result = {
        'success': True,
        'disclosed_info': {
            '/error.log': 'Application error log - no credentials here'
        },
        'advanced_exploitation': {
            'exploited': True,
            'findings': [
                {
                    'category': 'stack_trace',
                    'severity': 'high',
                    'matched_text': 'Traceback (most recent call last): File "/app/main.py", line 42, in process_request',
                    'context': '''Traceback (most recent call last):
  File "/app/main.py", line 42, in process_request
    return handler.handle(request)
  File "/app/handlers/api.py", line 156, in handle
    data = self.parse_json(request.body)
ValueError: Invalid JSON format'''
                },
                {
                    'category': 'debug_output',
                    'severity': 'high',
                    'matched_text': 'DEBUG = True',
                    'context': 'Django settings.py loaded with DEBUG = True in production environment'
                },
                {
                    'category': 'internal_paths',
                    'severity': 'medium',
                    'matched_text': '/var/www/myapp/src',
                    'context': 'Internal application paths disclosed: /var/www/myapp/src/config'
                }
            ],
            'extracted_data': {
                'stack_trace': ['Python traceback with file paths and line numbers'],
                'debug_output': ['DEBUG mode enabled'],
                'internal_paths': ['/var/www/myapp']
            },
            'severity': 'high'
        },
        'evidence': 'Found stack traces and debug information',
        'vulnerability_type': 'info_disclosure'
    }
    
    is_verified, proof = plugin.verify(
        result=result,
        target_url='https://example.com/api/endpoint',
        vulnerability_data={}
    )
    
    print(f"✓ Verified: {is_verified}")
    print(f"✓ PoC Generated: {'Yes' if proof else 'No'}\n")
    print("PROOF OF IMPACT:")
    print("-" * 80)
    print(proof)
    print("-" * 80)
    print("\n⚠️  Dashboard will show this with a YELLOW badge: 'ℹ Proof of Impact (EVIDENCE FOUND)'")


def demo_partial_evidence_errors():
    """Demo 3: Partial evidence from error responses"""
    print_separator("DEMO 3: Partial Evidence - Error Messages")
    
    plugin = InfoDisclosurePlugin()
    
    # Simulate result with partial evidence (error responses only)
    result = {
        'success': False,  # Not fully successful, just partial evidence
        'partial_evidence': [
            {
                'path': '/api/debug',
                'status_code': 500,
                'evidence': 'Error evidence detected (status 500): Fatal error: Call to undefined function mysql_connect() in /var/www/html/db.php on line 23'
            },
            {
                'path': '/api/admin',
                'status_code': 500,
                'evidence': 'Error evidence detected (status 500): Warning: mysqli::query(): MySQL server has gone away in /app/database.php on line 45'
            },
            {
                'path': '/test.php',
                'status_code': 500,
                'evidence': 'Server error detected (status 500), potential info leakage'
            }
        ],
        'confidence': 'partial',
        'message': 'No full disclosure, but found 3 potential indicators',
        'vulnerability_type': 'info_disclosure'
    }
    
    is_verified, proof = plugin.verify(
        result=result,
        target_url='https://example.com',
        vulnerability_data={}
    )
    
    print(f"✓ Verified: {is_verified}")
    print(f"✓ PoC Generated: {'Yes' if proof else 'No'}\n")
    print("PROOF OF IMPACT:")
    print("-" * 80)
    print(proof)
    print("-" * 80)
    print("\n⚠️  Dashboard will show this with a YELLOW badge: 'ℹ Proof of Impact (EVIDENCE FOUND)'")


def demo_database_errors():
    """Demo 4: Database error exposure"""
    print_separator("DEMO 4: Database Error Exposure")
    
    plugin = InfoDisclosurePlugin()
    
    # Simulate result with database errors
    result = {
        'success': True,
        'disclosed_info': {},
        'advanced_exploitation': {
            'exploited': True,
            'findings': [
                {
                    'category': 'database_error',
                    'severity': 'critical',
                    'matched_text': 'You have an error in your SQL syntax',
                    'context': '''MySQL Error: You have an error in your SQL syntax; check the manual that corresponds 
to your MySQL server version for the right syntax to use near 'admin' at line 1
Query: SELECT * FROM users WHERE username = 'admin' AND password = 'test'''
                },
                {
                    'category': 'database_error',
                    'severity': 'critical',
                    'matched_text': 'SQLSTATE[42000]',
                    'context': 'PDO::query(): SQLSTATE[42000]: Syntax error or access violation'
                }
            ],
            'extracted_data': {
                'database_error': ['SQL syntax errors revealing query structure']
            },
            'severity': 'critical'
        },
        'evidence': 'Found database error exposure revealing internal queries',
        'vulnerability_type': 'info_disclosure'
    }
    
    is_verified, proof = plugin.verify(
        result=result,
        target_url='https://example.com/login',
        vulnerability_data={}
    )
    
    print(f"✓ Verified: {is_verified}")
    print(f"✓ PoC Generated: {'Yes' if proof else 'No'}\n")
    print("PROOF OF IMPACT:")
    print("-" * 80)
    print(proof)
    print("-" * 80)
    print("\n⚠️  Dashboard will show this with a YELLOW badge: 'ℹ Proof of Impact (EVIDENCE FOUND)'")
    print("💡 Note: Even though severity is CRITICAL, without actual credentials, it's marked as unverified")


def demo_mixed_evidence():
    """Demo 5: Mixed evidence - both credentials and generic info"""
    print_separator("DEMO 5: Mixed Evidence - Credentials + Stack Traces")
    
    plugin = InfoDisclosurePlugin()
    
    # Simulate result with both credentials and generic evidence
    result = {
        'success': True,
        'disclosed_info': {
            '/.env': 'SECRET_KEY=django-insecure-abc123def456\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
        },
        'advanced_exploitation': {
            'exploited': True,
            'findings': [
                {
                    'category': 'api_keys',
                    'severity': 'critical',
                    'matched_text': 'SECRET_KEY=django-insecure-abc123def456',
                    'context': 'Django secret key exposed in .env file'
                },
                {
                    'category': 'aws_credentials',
                    'severity': 'critical',
                    'matched_text': 'AKIAIOSFODNN7EXAMPLE',
                    'context': 'AWS access key ID found'
                },
                {
                    'category': 'stack_trace',
                    'severity': 'high',
                    'matched_text': 'Traceback (most recent call last)',
                    'context': 'Python stack trace also present in error logs'
                },
                {
                    'category': 'debug_output',
                    'severity': 'high',
                    'matched_text': 'FLASK_DEBUG=1',
                    'context': 'Debug mode enabled'
                }
            ],
            'extracted_data': {
                'api_keys': ['SECRET_KEY'],
                'aws_credentials': ['AKIA...'],
                'stack_trace': ['Python traceback'],
                'debug_output': ['FLASK_DEBUG']
            },
            'severity': 'critical'
        },
        'evidence': 'Found both credentials and debug information',
        'vulnerability_type': 'info_disclosure'
    }
    
    is_verified, proof = plugin.verify(
        result=result,
        target_url='https://example.com',
        vulnerability_data={}
    )
    
    print(f"✓ Verified: {is_verified}")
    print(f"✓ PoC Generated: {'Yes' if proof else 'No'}\n")
    print("PROOF OF IMPACT:")
    print("-" * 80)
    print(proof)
    print("-" * 80)
    print("\n✅ Dashboard will show this with a GREEN badge: '✓ Proof of Impact (VERIFIED)'")
    print("💡 Note: Credentials take priority, so it's VERIFIED. Generic evidence is shown as 'Additional'")


def demo_comparison():
    """Demo 6: Before vs After comparison"""
    print_separator("DEMO 6: Before vs After Enhancement")
    
    print("BEFORE Enhancement:")
    print("-" * 80)
    print("Scenario: Stack trace found but no credentials")
    print("Result: verified=False, proof_of_impact=None")
    print("Dashboard: No PoC shown, security team has no context")
    print("Issue: ❌ Security teams don't know WHY it's flagged as info disclosure\n")
    
    print("AFTER Enhancement:")
    print("-" * 80)
    print("Scenario: Stack trace found but no credentials")
    print("Result: verified=False, proof_of_impact='ℹ EVIDENCE FOUND - Sensitive Output Detected...'")
    print("Dashboard: Yellow badge with full stack trace details shown")
    print("Benefit: ✅ Security teams see exactly what was exposed and can assess risk\n")
    
    print("=" * 80)
    print("\nKEY IMPROVEMENTS:")
    print("1. ✅ PoC field is ALWAYS populated when there's any evidence")
    print("2. ✅ Clear visual distinction: GREEN (verified) vs YELLOW (evidence found)")
    print("3. ✅ Generic sensitive output (stack traces, errors) now captured as proof")
    print("4. ✅ Security teams never see 'verified finding' without accompanying PoC")
    print("5. ✅ Better context for triaging and prioritizing findings")


def main():
    """Run all demos"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                    PoC ENHANCEMENT FEATURE DEMONSTRATION                      ║
║                                                                               ║
║  Enhanced vulnerability scanner that ALWAYS populates proof_of_impact with   ║
║  actionable evidence - even for generic sensitive output like stack traces   ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
""")
    
    try:
        # Run all demos
        demo_verified_with_credentials()
        input("\nPress Enter to continue to next demo...")
        
        demo_unverified_with_stack_trace()
        input("\nPress Enter to continue to next demo...")
        
        demo_partial_evidence_errors()
        input("\nPress Enter to continue to next demo...")
        
        demo_database_errors()
        input("\nPress Enter to continue to next demo...")
        
        demo_mixed_evidence()
        input("\nPress Enter to see summary...")
        
        demo_comparison()
        
        print_separator("DEMONSTRATION COMPLETE")
        print("✅ All 5 demo scenarios completed successfully!")
        print("\nNext steps:")
        print("1. Run the scanner against a test application")
        print("2. View the dashboard to see the new PoC displays")
        print("3. Notice how VERIFIED findings have green badges")
        print("4. Notice how EVIDENCE FOUND findings have yellow badges")
        print("5. Both types now show actionable proof in the dashboard!")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)


if __name__ == '__main__':
    main()
