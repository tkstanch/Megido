#!/usr/bin/env python3
"""
Visual Demo Generator - Creates sample vulnerability data to showcase PoC enhancement

This script creates mock vulnerability data that demonstrates how the enhanced
PoC field is displayed in different scenarios.
"""

import json


def create_sample_verified_vuln():
    """Create a sample verified vulnerability with credentials"""
    return {
        'id': 1,
        'vulnerability_type': 'info_disclosure',
        'severity': 'critical',
        'url': 'https://example.com/.env',
        'description': 'Sensitive configuration file exposed containing credentials',
        'evidence': 'Found exposed .env file with 3 sensitive patterns',
        'verified': True,
        'proof_of_impact': '''✓ VERIFIED - Sensitive Information Disclosed

Disclosed 2 file(s) containing sensitive data:

  - /.env
  - /config/database.yml

Sensitive Data Found (3 instances):
  - credential in /.env
  - credential in /config/database.yml
  - api_keys in /.env''',
        'confidence_score': 0.95,
        'exploited': True,
        'risk_score': 95.0
    }


def create_sample_unverified_stack_trace():
    """Create a sample unverified vulnerability with stack trace"""
    return {
        'id': 2,
        'vulnerability_type': 'info_disclosure',
        'severity': 'high',
        'url': 'https://example.com/api/process',
        'description': 'Stack trace disclosure revealing internal application structure',
        'evidence': 'Found Python stack trace with file paths and line numbers',
        'verified': False,
        'proof_of_impact': '''ℹ EVIDENCE FOUND - Sensitive Output Detected

No credentials/secrets found, but the following sensitive information was exposed:

Disclosed Files (1):
  - /error.log

Generic Sensitive Evidence (3 instances):
  • Stack Trace detected
    Sample: Traceback (most recent call last): File "/app/main.py", line 42, in process_request

  • Debug Output detected
    Sample: DEBUG = True

  • Internal Paths detected
    Sample: /var/www/myapp/src''',
        'confidence_score': 0.75,
        'exploited': True,
        'risk_score': 72.0
    }


def create_sample_unverified_db_error():
    """Create a sample unverified vulnerability with database errors"""
    return {
        'id': 3,
        'vulnerability_type': 'info_disclosure',
        'severity': 'high',
        'url': 'https://example.com/login',
        'description': 'Database error messages revealing query structure',
        'evidence': 'Found MySQL error messages exposing SQL syntax',
        'verified': False,
        'proof_of_impact': '''ℹ EVIDENCE FOUND - Sensitive Output Detected

No credentials/secrets found, but the following sensitive information was exposed:

Generic Sensitive Evidence (2 instances):
  • Database Error detected
    Sample: You have an error in your SQL syntax

  • Database Error detected
    Sample: SQLSTATE[42000]: Syntax error or access violation''',
        'confidence_score': 0.80,
        'exploited': True,
        'risk_score': 78.0
    }


def create_sample_partial_evidence():
    """Create a sample with partial evidence"""
    return {
        'id': 4,
        'vulnerability_type': 'info_disclosure',
        'severity': 'medium',
        'url': 'https://example.com/api/debug',
        'description': 'Error responses revealing internal information',
        'evidence': 'Found 3 error responses with potential information leakage',
        'verified': False,
        'proof_of_impact': '''ℹ EVIDENCE FOUND - Sensitive Output Detected

Found 3 potential information disclosure indicator(s):

  • Path: /api/debug (HTTP 500)
    Evidence: Fatal error: Call to undefined function mysql_connect() in /var/www/html/db.php on line 23

  • Path: /api/admin (HTTP 500)
    Evidence: Warning: mysqli::query(): MySQL server has gone away in /app/database.php on line 45

  • Path: /test.php (HTTP 500)
    Evidence: Server error detected (status 500), potential info leakage''',
        'confidence_score': 0.65,
        'exploited': False,
        'risk_score': 55.0
    }


def create_sample_mixed_evidence():
    """Create a sample with mixed evidence (credentials + generic)"""
    return {
        'id': 5,
        'vulnerability_type': 'info_disclosure',
        'severity': 'critical',
        'url': 'https://example.com/.env',
        'description': 'Environment file with credentials and debug information',
        'evidence': 'Found credentials, AWS keys, and debug output',
        'verified': True,
        'proof_of_impact': '''✓ VERIFIED - Sensitive Information Disclosed

Disclosed 1 file(s) containing sensitive data:

  - /.env

Sensitive Data Found (3 instances):
  - credential in /.env
  - api_keys: SECRET_KEY=django-insecure-abc123def456
  - aws_credentials: AKIAIOSFODNN7EXAMPLE

Additional Generic Evidence (2 instances):
  - stack_trace: Traceback (most recent call last)
  - debug_output: FLASK_DEBUG=1''',
        'confidence_score': 0.98,
        'exploited': True,
        'risk_score': 98.0
    }


def main():
    """Generate sample data"""
    print("=" * 80)
    print("VISUAL DEMO - Sample Vulnerability Data with Enhanced PoC")
    print("=" * 80)
    print()
    
    samples = [
        ("Verified - Credentials Found", create_sample_verified_vuln()),
        ("Unverified - Stack Trace", create_sample_unverified_stack_trace()),
        ("Unverified - Database Errors", create_sample_unverified_db_error()),
        ("Unverified - Partial Evidence", create_sample_partial_evidence()),
        ("Verified - Mixed Evidence", create_sample_mixed_evidence()),
    ]
    
    for title, vuln in samples:
        print(f"\n{'=' * 80}")
        print(f"Sample: {title}")
        print(f"{'=' * 80}")
        print(f"ID: {vuln['id']}")
        print(f"Type: {vuln['vulnerability_type']}")
        print(f"Severity: {vuln['severity'].upper()}")
        print(f"URL: {vuln['url']}")
        print(f"Verified: {'✓ YES' if vuln['verified'] else '✗ NO'}")
        print(f"Exploited: {'✓ YES' if vuln['exploited'] else '✗ NO'}")
        print(f"Confidence: {vuln['confidence_score']*100:.0f}%")
        print(f"Risk Score: {vuln['risk_score']:.1f}/100")
        print()
        print("Description:")
        print(f"  {vuln['description']}")
        print()
        print("Evidence:")
        print(f"  {vuln['evidence']}")
        print()
        print("Proof of Impact:")
        print("-" * 80)
        for line in vuln['proof_of_impact'].split('\n'):
            print(f"  {line}")
        print("-" * 80)
        
        # Dashboard display hint
        if vuln['verified']:
            print("\n🟢 Dashboard Display: GREEN badge - '✓ Proof of Impact (VERIFIED)'")
        else:
            print("\n🟡 Dashboard Display: YELLOW badge - 'ℹ Proof of Impact (EVIDENCE FOUND)'")
        print()
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY - Key Improvements")
    print("=" * 80)
    print()
    print("✅ BEFORE Enhancement:")
    print("   - PoC only shown for verified findings (with credentials)")
    print("   - Unverified findings had no proof_of_impact field")
    print("   - Security teams couldn't see what triggered the finding")
    print()
    print("✅ AFTER Enhancement:")
    print("   - PoC ALWAYS populated when there's evidence")
    print("   - Verified findings (credentials): GREEN badge")
    print("   - Unverified findings (stack traces, errors): YELLOW badge")
    print("   - Security teams see exactly what was exposed")
    print("   - Better context for risk assessment and prioritization")
    print()
    print("=" * 80)
    
    # Save to JSON using tempfile for safety
    import tempfile
    all_vulns = [create_sample_verified_vuln(), 
                 create_sample_unverified_stack_trace(),
                 create_sample_unverified_db_error(),
                 create_sample_partial_evidence(),
                 create_sample_mixed_evidence()]
    
    # Use tempfile to avoid permission issues and overwriting
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sample_vulnerabilities.json', 
                                        delete=False, dir='/tmp') as f:
            json.dump(all_vulns, f, indent=2)
            output_path = f.name
        
        print(f"\n✅ Sample data saved to: {output_path}")
    except Exception as e:
        print(f"\n⚠️  Could not save sample data: {e}")


if __name__ == '__main__':
    main()
