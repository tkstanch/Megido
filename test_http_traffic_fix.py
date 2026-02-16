#!/usr/bin/env python
"""
Test to verify http_traffic field handling in Vulnerability creation.
This test ensures that the fix for NOT NULL violation is working correctly.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from scanner.models import Scan, ScanTarget, Vulnerability
from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
from scanner.scan_engine import ScanEngine


def test_http_traffic_with_none():
    """Test that http_traffic=None is handled correctly"""
    print("Test 1: Creating VulnerabilityFinding with http_traffic=None...")
    
    # Create test data
    target = ScanTarget.objects.create(url="http://test.example.com", name="Test Target")
    scan = Scan.objects.create(target=target, status='running')
    
    # Create a finding with http_traffic=None (default)
    finding = VulnerabilityFinding(
        vulnerability_type='xss',
        severity='high',
        url='http://test.example.com',
        description='Test XSS vulnerability',
        evidence='<script>alert(1)</script>',
        remediation='Sanitize input',
        http_traffic=None  # Explicitly set to None
    )
    
    # Save to database
    engine = ScanEngine()
    vulns = engine.save_findings_to_db(scan, [finding])
    
    # Verify
    assert len(vulns) == 1
    assert vulns[0].http_traffic == {}
    print("✓ Test 1 passed: http_traffic=None was converted to {}")
    
    # Cleanup
    vulns[0].delete()
    scan.delete()
    target.delete()


def test_http_traffic_with_data():
    """Test that http_traffic with data is preserved"""
    print("\nTest 2: Creating VulnerabilityFinding with http_traffic data...")
    
    # Create test data
    target = ScanTarget.objects.create(url="http://test2.example.com", name="Test Target 2")
    scan = Scan.objects.create(target=target, status='running')
    
    # Create a finding with http_traffic data
    traffic_data = {
        'request': {'method': 'GET', 'url': 'http://test2.example.com'},
        'response': {'status': 200, 'body': 'response data'}
    }
    finding = VulnerabilityFinding(
        vulnerability_type='sqli',
        severity='critical',
        url='http://test2.example.com',
        description='Test SQL injection',
        evidence='SQL error',
        remediation='Use parameterized queries',
        http_traffic=traffic_data
    )
    
    # Save to database
    engine = ScanEngine()
    vulns = engine.save_findings_to_db(scan, [finding])
    
    # Verify
    assert len(vulns) == 1
    assert vulns[0].http_traffic == traffic_data
    print("✓ Test 2 passed: http_traffic data was preserved correctly")
    
    # Cleanup
    vulns[0].delete()
    scan.delete()
    target.delete()


def test_http_traffic_default():
    """Test that http_traffic with default value (not specified) works"""
    print("\nTest 3: Creating VulnerabilityFinding without http_traffic field...")
    
    # Create test data
    target = ScanTarget.objects.create(url="http://test3.example.com", name="Test Target 3")
    scan = Scan.objects.create(target=target, status='running')
    
    # Create a finding without specifying http_traffic (will default to None)
    finding = VulnerabilityFinding(
        vulnerability_type='info_disclosure',
        severity='low',
        url='http://test3.example.com',
        description='Missing security header',
        evidence='X-Frame-Options not set',
        remediation='Add security headers'
    )
    
    # Save to database
    engine = ScanEngine()
    vulns = engine.save_findings_to_db(scan, [finding])
    
    # Verify
    assert len(vulns) == 1
    assert vulns[0].http_traffic == {}
    print("✓ Test 3 passed: Default http_traffic was converted to {}")
    
    # Cleanup
    vulns[0].delete()
    scan.delete()
    target.delete()


if __name__ == '__main__':
    try:
        print("=" * 60)
        print("Testing http_traffic Field Handling")
        print("=" * 60)
        
        test_http_traffic_with_none()
        test_http_traffic_with_data()
        test_http_traffic_default()
        
        print("\n" + "=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
