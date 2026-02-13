#!/usr/bin/env python3
"""
Demo Script: XSS Callback Verification System

This script demonstrates the new callback-based XSS verification feature
in the Megido scanner.

Usage:
    python demo_xss_callback_verification.py

Requirements:
    - Django server running
    - Callback endpoint configured (or use internal collaborator)
    - Target URL to test (defaults to example.com)
"""

import sys
import os
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
try:
    import django
    django.setup()
    HAS_DJANGO = True
except ImportError:
    HAS_DJANGO = False
    print("Note: Django not available, using standalone mode")

from scanner.plugins.xss_callback_verifier import XSSCallbackVerifier, get_default_callback_payloads
try:
    from scanner.plugins import get_registry
    HAS_PLUGIN_REGISTRY = True
except ImportError:
    HAS_PLUGIN_REGISTRY = False


def demo_callback_verifier():
    """Demonstrate the XSSCallbackVerifier class."""
    print("=" * 70)
    print("XSS Callback Verification System Demo")
    print("=" * 70)
    print()
    
    # Initialize verifier
    print("1. Initializing Callback Verifier...")
    print("-" * 70)
    
    verifier = XSSCallbackVerifier(
        callback_endpoint='https://test-callback.example.com',
        timeout=30,
        poll_interval=2,
        use_internal_collaborator=False
    )
    
    print(f"✓ Verifier initialized")
    print(f"  Callback Endpoint: {verifier.callback_endpoint}")
    print(f"  Timeout: {verifier.timeout}s")
    print(f"  Poll Interval: {verifier.poll_interval}s")
    print()
    
    # Generate callback payload
    print("2. Generating Callback Payload...")
    print("-" * 70)
    
    base_payload = '<script>CALLBACK</script>'
    payload, payload_id = verifier.generate_callback_payload(
        base_payload=base_payload,
        context='html'
    )
    
    print(f"✓ Payload generated")
    print(f"  Payload ID: {payload_id}")
    print(f"  Base Template: {base_payload}")
    print()
    print(f"  Generated Payload (truncated):")
    print(f"  {payload[:200]}...")
    print()
    
    # Show verification status
    print("3. Checking Verification Status...")
    print("-" * 70)
    
    status = verifier.get_verification_status(payload_id)
    print(f"✓ Status retrieved")
    print(f"  Payload ID: {payload_id}")
    print(f"  Verified: {status['verified']}")
    print(f"  Context: {status['context']}")
    print(f"  Created: {status['created_at']}")
    print()
    
    # Generate multiple payloads
    print("4. Generating Multiple Payloads...")
    print("-" * 70)
    
    templates = [
        '<script>CALLBACK</script>',
        '<img src=x onerror="CALLBACK">',
        '<svg/onload="CALLBACK">'
    ]
    
    results = verifier.generate_multiple_payloads(templates, context='html')
    
    print(f"✓ Generated {len(results)} payloads")
    for i, (payload, pid) in enumerate(results, 1):
        print(f"  {i}. Payload ID: {pid}")
        print(f"     Template: {templates[i-1]}")
    print()
    
    # Show all verifications
    print("5. Listing All Pending Verifications...")
    print("-" * 70)
    
    all_verifications = verifier.get_all_verifications()
    print(f"✓ Total pending verifications: {len(all_verifications)}")
    print()
    
    # Generate report
    print("6. Generating Verification Report...")
    print("-" * 70)
    
    report = verifier.generate_report(payload_id)
    print(report)
    print()
    
    # Show default payloads
    print("7. Default Callback Payloads...")
    print("-" * 70)
    
    default_payloads = get_default_callback_payloads()
    print(f"✓ {len(default_payloads)} default payload templates available")
    print()
    print("  Sample templates:")
    for i, template in enumerate(default_payloads[:5], 1):
        print(f"  {i}. {template}")
    print(f"  ... and {len(default_payloads) - 5} more")
    print()
    
    # Cleanup
    print("8. Cleaning Up...")
    print("-" * 70)
    
    verifier.clear_all_verifications()
    print(f"✓ All verifications cleared")
    print()


def demo_xss_plugin_with_callback():
    """Demonstrate XSS plugin with callback verification."""
    print("=" * 70)
    print("XSS Plugin with Callback Verification Demo")
    print("=" * 70)
    print()
    
    if not HAS_PLUGIN_REGISTRY:
        print("✗ Plugin registry not available (Django not loaded)")
        print("  This demo requires Django to be running")
        print()
        return
    
    # Get the XSS plugin
    print("1. Loading XSS Plugin...")
    print("-" * 70)
    
    try:
        registry = get_registry()
        plugin = registry.get_plugin('xss')
        
        print(f"✓ Plugin loaded: {plugin.name}")
        print(f"  Version: {plugin.version}")
        print(f"  Type: {plugin.vulnerability_type}")
        print()
    except Exception as e:
        print(f"✗ Could not load XSS plugin: {e}")
        return
    
    # Show configuration options
    print("2. Configuration Options...")
    print("-" * 70)
    
    config_example = {
        # Callback verification settings
        'callback_verification_enabled': True,
        'callback_endpoint': 'https://your-callback.example.com',
        'callback_timeout': 30,
        'use_internal_collaborator': False,
        
        # Scanning settings
        'enable_dom_testing': True,
        'enable_crawler': False,
        'crawl_depth': 2,
        'max_pages': 50,
        
        # Browser settings
        'browser_type': 'chrome',
        'headless': True,
        'randomize_fingerprint': True,
        
        # Evidence collection
        'collect_evidence': True,
        
        # Output
        'output_format': 'markdown',
        'output_dir': './xss_reports'
    }
    
    print("Example configuration for callback verification:")
    print()
    for key, value in config_example.items():
        if 'callback' in key.lower() or 'collaborator' in key.lower():
            print(f"  {key}: {value}  ← Callback-related")
        else:
            print(f"  {key}: {value}")
    print()
    
    # Show execution example
    print("3. Execution Example...")
    print("-" * 70)
    
    print("To scan a target with callback verification:")
    print()
    print("  result = plugin.execute_attack(")
    print("      target_url='http://target.com/search',")
    print("      vulnerability_data={'parameter': 'q', 'method': 'GET'},")
    print("      config={")
    print("          'callback_verification_enabled': True,")
    print("          'callback_endpoint': 'https://your-callback.com',")
    print("          'enable_dom_testing': True,")
    print("      }")
    print("  )")
    print()
    print("  if result['success']:")
    print("      for finding in result['findings']:")
    print("          print(f\"✓ VERIFIED XSS: {finding['url']}\")")
    print("          print(f\"  Payload ID: {finding['payload_id']}\")")
    print("          print(f\"  Callbacks: {len(finding['callback_interactions'])}\")")
    print()
    
    # Show traditional vs callback verification
    print("4. Traditional vs Callback Verification...")
    print("-" * 70)
    
    print("Traditional Detection (Legacy):")
    print("  ✓ Inject alert() payload")
    print("  ✓ Check for alert dialog")
    print("  ✓ Check console errors")
    print("  Problem: May have false positives")
    print()
    
    print("Callback Verification (New):")
    print("  ✓ Inject callback payload")
    print("  ✓ Payload makes HTTP request if executed")
    print("  ✓ Verify callback received at endpoint")
    print("  ✓ Only report if callback confirmed")
    print("  Benefit: Proof of actual exploitation")
    print()


def main():
    """Main demo function."""
    print()
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║       Megido XSS Callback Verification System - Demo              ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()
    
    # Demo 1: Callback Verifier
    try:
        demo_callback_verifier()
    except Exception as e:
        print(f"Error in callback verifier demo: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print()
    
    # Demo 2: XSS Plugin Integration
    try:
        demo_xss_plugin_with_callback()
    except Exception as e:
        print(f"Error in XSS plugin demo: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 70)
    print("Demo Complete!")
    print("=" * 70)
    print()
    print("Next Steps:")
    print("  1. Configure callback endpoint in .env or settings.py")
    print("  2. Start Django server: python manage.py runserver")
    print("  3. Run XSS scans with callback verification enabled")
    print("  4. Review XSS_CALLBACK_VERIFICATION_GUIDE.md for details")
    print()


if __name__ == '__main__':
    main()
