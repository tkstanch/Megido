#!/usr/bin/env python3
"""
Demo Script: Proof Reporting System

This script demonstrates the unified proof reporting system for Megido
vulnerability scanner. It shows how proof evidence is collected, formatted,
and saved across different vulnerability types.

Usage:
    python demo_proof_reporting.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.proof_reporter import ProofReporter, ProofData, get_proof_reporter
import json
from pathlib import Path


def demo_xss_proof():
    """Demonstrate XSS proof reporting."""
    print("\n" + "="*70)
    print("XSS Exploitation Proof Reporting Demo")
    print("="*70 + "\n")
    
    # Initialize proof reporter
    reporter = get_proof_reporter(enable_visual_proof=False)
    
    # Create proof data container
    proof_data = reporter.create_proof_data('xss', vulnerability_id=101)
    
    # Simulate successful XSS exploitation
    proof_data.set_success(success=True, verified=True, confidence=0.92)
    
    # Add HTTP request
    proof_data.add_http_request(
        method='GET',
        url='http://victim.com/search?q=<script>alert(document.cookie)</script>',
        headers={'User-Agent': 'Megido Scanner', 'Accept': 'text/html'},
        body=''
    )
    
    # Add HTTP response
    proof_data.add_http_response(
        status_code=200,
        headers={'Content-Type': 'text/html', 'Server': 'nginx/1.18.0'},
        body='<html><body><h1>Search Results</h1><script>alert(document.cookie)</script></body></html>'
    )
    
    # Add exploitation logs
    proof_data.add_log('XSS exploitation attempt initiated', 'info')
    proof_data.add_log('Payload injected in search parameter', 'info')
    proof_data.add_log('Payload reflected in HTML response', 'success')
    proof_data.add_log('XSS callback received - exploitation confirmed', 'success')
    
    # Add callback evidence
    proof_data.add_callback_evidence({
        'callback_id': 'xss_abc123456',
        'callback_url': 'http://callback.megido.io/xss/abc123',
        'callback_received': True,
        'cookies_exfiltrated': True,
        'timestamp': '2024-01-15T10:30:45Z'
    })
    
    # Add metadata
    proof_data.add_metadata('payload', '<script>alert(document.cookie)</script>')
    proof_data.add_metadata('context', 'HTML body')
    proof_data.add_metadata('browser_executed', True)
    
    # Generate and save proof reports
    results = reporter.report_proof(
        proof_data,
        save_json=True,
        save_html=True,
        store_db=False  # Skip DB for demo
    )
    
    print("✓ XSS Proof Generated:")
    print(f"  - JSON Report: {results.get('json_path')}")
    print(f"  - HTML Report: {results.get('html_path')}")
    print(f"  - Verified: {proof_data.verified}")
    print(f"  - Confidence: {proof_data.confidence_score:.0%}")
    
    return results


def demo_rce_proof():
    """Demonstrate RCE proof reporting."""
    print("\n" + "="*70)
    print("RCE Exploitation Proof Reporting Demo")
    print("="*70 + "\n")
    
    # Initialize proof reporter (no visual proof for RCE)
    reporter = get_proof_reporter(enable_visual_proof=False)
    
    # Create proof data container
    proof_data = reporter.create_proof_data('rce', vulnerability_id=202)
    
    # Simulate successful RCE exploitation
    proof_data.set_success(success=True, verified=True, confidence=0.98)
    
    # Add HTTP request
    proof_data.add_http_request(
        method='POST',
        url='http://victim.com/api/exec',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        body='cmd=whoami;id;uname -a'
    )
    
    # Add HTTP response
    command_output = """root
uid=0(root) gid=0(root) groups=0(root)
Linux webserver 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux"""
    
    proof_data.add_http_response(
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body=command_output
    )
    
    # Set command output as primary evidence
    proof_data.set_command_output(command_output)
    
    # Add exploitation logs
    proof_data.add_log('RCE exploitation attempt initiated', 'info')
    proof_data.add_log('Command injection payload: whoami;id;uname -a', 'info')
    proof_data.add_log('Command executed successfully as root', 'critical')
    proof_data.add_log('System information extracted', 'success')
    
    # Add metadata
    proof_data.add_metadata('command', 'whoami;id;uname -a')
    proof_data.add_metadata('injection_vector', '; command')
    proof_data.add_metadata('os_detected', 'linux')
    proof_data.add_metadata('privilege_level', 'root')
    proof_data.add_metadata('system_info', 'Debian 5.10.162-1')
    
    # Generate and save proof reports
    results = reporter.report_proof(
        proof_data,
        save_json=True,
        save_html=True,
        store_db=False
    )
    
    print("✓ RCE Proof Generated:")
    print(f"  - JSON Report: {results.get('json_path')}")
    print(f"  - HTML Report: {results.get('html_path')}")
    print(f"  - Command Output: {len(command_output)} bytes")
    print(f"  - Privilege Level: ROOT")
    print(f"  - Confidence: {proof_data.confidence_score:.0%}")
    
    return results


def demo_ssrf_proof():
    """Demonstrate SSRF proof reporting."""
    print("\n" + "="*70)
    print("SSRF Exploitation Proof Reporting Demo")
    print("="*70 + "\n")
    
    # Initialize proof reporter
    reporter = get_proof_reporter(enable_visual_proof=False)
    
    # Create proof data container
    proof_data = reporter.create_proof_data('ssrf', vulnerability_id=303)
    
    # Simulate successful SSRF exploitation
    proof_data.set_success(success=True, verified=True, confidence=0.89)
    
    # Add HTTP request
    proof_data.add_http_request(
        method='GET',
        url='http://victim.com/fetch?url=http://169.254.169.254/latest/meta-data/',
        headers={'User-Agent': 'Megido Scanner'},
        body=''
    )
    
    # Add HTTP response with cloud metadata
    metadata_response = """ami-id
ami-launch-index
ami-manifest-path
instance-id
instance-type
local-hostname
local-ipv4
mac
placement/
public-hostname
public-ipv4
security-groups"""
    
    proof_data.add_http_response(
        status_code=200,
        headers={'Content-Type': 'text/plain'},
        body=metadata_response
    )
    
    # Set extracted cloud metadata
    extracted_data = {
        'cloud_provider': 'AWS',
        'instance_id': 'i-0abcd1234efgh5678',
        'instance_type': 't2.micro',
        'ami_id': 'ami-0c55b159cbfafe1f0',
        'region': 'us-east-1',
        'availability_zone': 'us-east-1a',
        'private_ip': '172.31.45.67',
        'public_ip': '54.123.45.67'
    }
    proof_data.set_extracted_data(extracted_data)
    
    # Add exploitation logs
    proof_data.add_log('SSRF exploitation attempt initiated', 'info')
    proof_data.add_log('Target: AWS metadata endpoint', 'info')
    proof_data.add_log('Metadata endpoint accessible via SSRF', 'success')
    proof_data.add_log('Cloud credentials potentially accessible', 'critical')
    
    # Add OOB interaction evidence
    proof_data.add_oob_interaction({
        'type': 'http',
        'protocol': 'http',
        'url': 'http://callback.megido.io/ssrf/xyz789',
        'source_ip': '54.123.45.67',
        'timestamp': '2024-01-15T10:45:12Z'
    })
    
    # Add metadata
    proof_data.add_metadata('ssrf_type', 'cloud_metadata')
    proof_data.add_metadata('cloud_provider', 'AWS')
    proof_data.add_metadata('accessible_hosts', ['169.254.169.254', 'localhost'])
    proof_data.add_metadata('potential_impact', 'credential_theft')
    
    # Generate and save proof reports
    results = reporter.report_proof(
        proof_data,
        save_json=True,
        save_html=True,
        store_db=False
    )
    
    print("✓ SSRF Proof Generated:")
    print(f"  - JSON Report: {results.get('json_path')}")
    print(f"  - HTML Report: {results.get('html_path')}")
    print(f"  - Cloud Provider: AWS")
    print(f"  - Metadata Extracted: {len(extracted_data)} items")
    print(f"  - Confidence: {proof_data.confidence_score:.0%}")
    
    return results


def demo_sqli_proof():
    """Demonstrate SQL Injection proof reporting."""
    print("\n" + "="*70)
    print("SQL Injection Exploitation Proof Reporting Demo")
    print("="*70 + "\n")
    
    # Initialize proof reporter
    reporter = get_proof_reporter(enable_visual_proof=False)
    
    # Create proof data container
    proof_data = reporter.create_proof_data('sqli', vulnerability_id=404)
    
    # Simulate successful SQLi exploitation
    proof_data.set_success(success=True, verified=True, confidence=0.94)
    
    # Add HTTP request
    proof_data.add_http_request(
        method='GET',
        url="http://victim.com/product?id=1' UNION SELECT username,password,email FROM users--",
        headers={'User-Agent': 'Megido Scanner'},
        body=''
    )
    
    # Add HTTP response
    proof_data.add_http_response(
        status_code=200,
        headers={'Content-Type': 'text/html'},
        body='<html><body>admin:$2y$10$...:admin@victim.com...</body></html>'
    )
    
    # Set extracted database data
    extracted_data = {
        'database': 'production_db',
        'table': 'users',
        'columns': ['username', 'password', 'email'],
        'records_extracted': 5,
        'users': [
            {'username': 'admin', 'email': 'admin@victim.com'},
            {'username': 'user1', 'email': 'user1@victim.com'},
            {'username': 'user2', 'email': 'user2@victim.com'}
        ]
    }
    proof_data.set_extracted_data(extracted_data)
    
    # Add exploitation logs
    proof_data.add_log('SQL injection exploitation initiated', 'info')
    proof_data.add_log('Payload: UNION-based injection', 'info')
    proof_data.add_log('Database enumeration successful', 'success')
    proof_data.add_log('User credentials extracted', 'critical')
    
    # Add metadata
    proof_data.add_metadata('sqli_type', 'union_based')
    proof_data.add_metadata('database_type', 'MySQL')
    proof_data.add_metadata('database_version', '8.0.32')
    proof_data.add_metadata('records_extracted', 5)
    
    # Generate and save proof reports
    results = reporter.report_proof(
        proof_data,
        save_json=True,
        save_html=True,
        store_db=False
    )
    
    print("✓ SQLi Proof Generated:")
    print(f"  - JSON Report: {results.get('json_path')}")
    print(f"  - HTML Report: {results.get('html_path')}")
    print(f"  - Records Extracted: {extracted_data['records_extracted']}")
    print(f"  - Database: {extracted_data['database']}")
    print(f"  - Confidence: {proof_data.confidence_score:.0%}")
    
    return results


def display_summary(all_results):
    """Display summary of all generated proofs."""
    print("\n" + "="*70)
    print("Proof Reporting Summary")
    print("="*70 + "\n")
    
    print("All proof reports have been generated and saved.\n")
    
    print("Output Files:")
    for vuln_type, results in all_results.items():
        print(f"\n{vuln_type.upper()}:")
        if results.get('json_path'):
            print(f"  JSON: {results['json_path']}")
        if results.get('html_path'):
            print(f"  HTML: {results['html_path']}")
    
    print("\n" + "="*70)
    print("View HTML reports in your browser to see formatted proof evidence.")
    print("="*70)


def main():
    """Run all proof reporting demos."""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + "  Megido Proof Reporting System - Demonstration".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    
    all_results = {}
    
    try:
        # Demo XSS proof
        all_results['xss'] = demo_xss_proof()
        
        # Demo RCE proof
        all_results['rce'] = demo_rce_proof()
        
        # Demo SSRF proof
        all_results['ssrf'] = demo_ssrf_proof()
        
        # Demo SQLi proof
        all_results['sqli'] = demo_sqli_proof()
        
        # Display summary
        display_summary(all_results)
        
        print("\n✓ All demos completed successfully!\n")
        
    except Exception as e:
        print(f"\n✗ Error during demo: {e}\n")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
