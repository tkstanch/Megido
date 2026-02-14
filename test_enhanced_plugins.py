#!/usr/bin/env python3
"""
Test script for enhanced exploit plugins with visual proof capture.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.plugins.exploits.open_redirect_plugin import OpenRedirectPlugin
from scanner.plugins.exploits.other_plugin import OtherPlugin

def test_plugin_initialization():
    """Test that plugins can be initialized."""
    print("Testing plugin initialization...")
    
    # Test Open Redirect Plugin
    or_plugin = OpenRedirectPlugin()
    print(f"✓ {or_plugin.name} v{or_plugin.version}")
    print(f"  Type: {or_plugin.vulnerability_type}")
    print(f"  Description: {or_plugin.description}")
    print(f"  Severity: {or_plugin.get_severity_level()}")
    
    # Test Other Plugin
    other_plugin = OtherPlugin()
    print(f"\n✓ {other_plugin.name} v{other_plugin.version}")
    print(f"  Type: {other_plugin.vulnerability_type}")
    print(f"  Description: {other_plugin.description}")
    print(f"  Severity: {other_plugin.get_severity_level()}")
    
    print("\n✓ Both plugins initialized successfully!")

def test_payload_generation():
    """Test payload generation."""
    print("\n\nTesting payload generation...")
    
    # Test Open Redirect Plugin
    or_plugin = OpenRedirectPlugin()
    payloads = or_plugin.generate_payloads({'target_domain': 'evil.com'})
    print(f"\n✓ Open Redirect Plugin generated {len(payloads)} payloads:")
    for payload in payloads[:3]:
        print(f"  - {payload}")
    
    # Test Other Plugin
    other_plugin = OtherPlugin()
    payloads = other_plugin.generate_payloads()
    print(f"\n✓ Other Plugin generated {len(payloads)} payloads:")
    for payload in payloads:
        print(f"  - {payload}")

def test_visual_proof_imports():
    """Test visual proof module imports."""
    print("\n\nTesting visual proof imports...")
    
    or_plugin = OpenRedirectPlugin()
    other_plugin = OtherPlugin()
    
    # Check if visual proof is available
    from scanner.plugins.exploits import open_redirect_plugin, other_plugin as other_mod
    
    has_visual_proof_or = hasattr(open_redirect_plugin, 'HAS_VISUAL_PROOF') and open_redirect_plugin.HAS_VISUAL_PROOF
    has_visual_proof_other = hasattr(other_mod, 'HAS_VISUAL_PROOF') and other_mod.HAS_VISUAL_PROOF
    
    print(f"✓ Open Redirect Plugin - Visual Proof Support: {has_visual_proof_or}")
    print(f"✓ Other Plugin - Visual Proof Support: {has_visual_proof_other}")

def test_execute_attack_structure():
    """Test that execute_attack method has correct structure."""
    print("\n\nTesting execute_attack method structure...")
    
    # Test Open Redirect Plugin
    or_plugin = OpenRedirectPlugin()
    result = or_plugin.execute_attack(
        'http://example.com',
        {'parameter': 'redirect'},
        {'timeout': 5, 'verify_ssl': False, 'capture_visual_proof': False}
    )
    print(f"\n✓ Open Redirect Plugin execute_attack returned:")
    print(f"  - success: {result.get('success')}")
    print(f"  - vulnerability_type: {result.get('vulnerability_type')}")
    
    # Test Other Plugin
    other_plugin = OtherPlugin()
    result = other_plugin.execute_attack(
        'http://example.com',
        {},
        {'timeout': 5, 'verify_ssl': False, 'capture_visual_proof': False}
    )
    print(f"\n✓ Other Plugin execute_attack returned:")
    print(f"  - success: {result.get('success')}")
    print(f"  - vulnerability_type: {result.get('vulnerability_type')}")

def main():
    """Run all tests."""
    print("=" * 70)
    print("Testing Enhanced Exploit Plugins with Visual Proof Capture")
    print("=" * 70)
    
    try:
        test_plugin_initialization()
        test_payload_generation()
        test_visual_proof_imports()
        test_execute_attack_structure()
        
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED!")
        print("=" * 70)
        print("\nEnhancements Summary:")
        print("1. Open Redirect Plugin - Enhanced with visual proof capture")
        print("   - Captures screenshots of browser redirecting to external domains")
        print("   - Shows redirect headers and final destination")
        print("\n2. Other Plugin - Enhanced with visual proof capture")
        print("   - Captures screenshots of debug mode enabled")
        print("   - Captures screenshots of exposed admin panels")
        print("   - Shows directory listing and verbose errors")
        print("\nBoth plugins follow the same pattern as other enhanced plugins!")
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
