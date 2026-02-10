#!/usr/bin/env python3
"""
Clickjacking Plugin Demo Script

This script demonstrates the capabilities of the Advanced Clickjacking Exploit Plugin
for Megido's vulnerability scanning system.

Usage:
    python3 demo_clickjacking_plugin.py [target_url]

If no target URL is provided, the demo uses example.com for demonstration.
"""

import sys
import os
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.plugins import get_registry, get_payload_generator


def print_banner():
    """Print demo banner."""
    print("=" * 70)
    print("    Megido Clickjacking Exploit Plugin - Interactive Demo")
    print("=" * 70)
    print()


def print_section(title):
    """Print section header."""
    print()
    print("-" * 70)
    print(f"  {title}")
    print("-" * 70)
    print()


def demo_plugin_info():
    """Demonstrate plugin information."""
    print_section("1. Plugin Information")
    
    registry = get_registry()
    plugin = registry.get_plugin('clickjacking')
    
    if not plugin:
        print("❌ Clickjacking plugin not found!")
        print("Make sure the plugin is in scanner/plugins/exploits/")
        return None
    
    print(f"✓ Plugin Name: {plugin.name}")
    print(f"✓ Vulnerability Type: {plugin.vulnerability_type}")
    print(f"✓ Version: {plugin.version}")
    print(f"✓ Severity Level: {plugin.get_severity_level()}")
    print(f"✓ Description: {plugin.description}")
    
    return plugin


def demo_payload_generation(plugin, target_url):
    """Demonstrate payload generation."""
    print_section("2. HTML Proof-of-Concept Generation")
    
    print("Generating three types of HTML PoC payloads...\n")
    
    # Generate transparent overlay
    print("📄 Transparent Overlay PoC:")
    transparent_payload = plugin._generate_transparent_overlay_poc(
        target_url=target_url,
        overlay_text='Click here to continue',
        opacity=0.3,
        action_description='sensitive action'
    )
    print(f"   Length: {len(transparent_payload)} characters")
    print("   This PoC shows a semi-transparent iframe with visible decoy button")
    
    # Generate opaque overlay
    print("\n📄 Opaque Overlay PoC:")
    opaque_payload = plugin._generate_opaque_overlay_poc(
        target_url=target_url,
        overlay_text='Claim Prize',
        action_description='money transfer'
    )
    print(f"   Length: {len(opaque_payload)} characters")
    print("   This PoC hides the iframe with a convincing decoy page")
    
    # Generate partial overlay
    print("\n📄 Partial Overlay PoC:")
    partial_payload = plugin._generate_partial_overlay_poc(
        target_url=target_url,
        overlay_text='Continue',
        opacity=0.5,
        action_description='form submission'
    )
    print(f"   Length: {len(partial_payload)} characters")
    print("   This PoC uses gradient overlay for button hijacking")
    
    # Generate all payloads using the main method
    print("\n📦 Using generate_payloads() method:")
    payloads = plugin.generate_payloads({
        'target_url': target_url,
        'overlay_style': 'transparent',
        'overlay_text': 'Test Button',
    })
    print(f"   Generated {len(payloads)} total payloads")
    
    return payloads


def demo_header_analysis(plugin, target_url):
    """Demonstrate security header analysis."""
    print_section("3. Security Header Analysis")
    
    print(f"Analyzing security headers for: {target_url}\n")
    
    config = {'timeout': 30, 'verify_ssl': False}
    
    try:
        analysis = plugin._analyze_security_headers(target_url, config)
        
        print("📊 Header Analysis Results:")
        print(f"   X-Frame-Options: {analysis.get('x_frame_options', 'Not present')}")
        print(f"   CSP frame-ancestors: {analysis.get('csp_frame_ancestors', 'Not present')}")
        print(f"   Protection Level: {analysis.get('protection_level', 'unknown')}")
        print(f"   Allows Framing: {'Yes ⚠️' if analysis.get('allows_framing') else 'No ✓'}")
        
        return analysis
    except Exception as e:
        print(f"⚠️  Could not analyze headers: {e}")
        return None


def demo_vulnerability_test(plugin, target_url):
    """Demonstrate vulnerability testing."""
    print_section("4. Clickjacking Vulnerability Test")
    
    print(f"Testing target: {target_url}\n")
    print("Using test mode (header analysis only) for quick assessment...\n")
    
    config = {
        'test_mode': True,  # Quick test without browser
        'collect_evidence': False,
        'verify_ssl': False,
    }
    
    result = plugin.execute_attack(
        target_url=target_url,
        vulnerability_data={'action_description': 'demo test'},
        config=config
    )
    
    print("🔍 Test Results:")
    print(f"   Success: {'Yes ✓' if result['success'] else 'No ❌'}")
    print(f"   Vulnerable: {'Yes ⚠️' if result['vulnerable'] else 'No ✓'}")
    print(f"   Severity: {result['severity']}")
    
    if result['error']:
        print(f"   Error: {result['error']}")
    
    if result['vulnerable']:
        print(f"\n⚠️  VULNERABILITY FOUND")
        print(f"   Evidence: {result['evidence']}")
        
        if result['findings']:
            finding = result['findings'][0]
            print(f"   Type: {finding['type']}")
            print(f"   Description: {finding['description']}")
    else:
        print(f"\n✓ No vulnerability detected")
        print(f"   The target has adequate clickjacking protection")
    
    return result


def demo_severity_classification(plugin):
    """Demonstrate severity classification."""
    print_section("5. Severity Classification")
    
    print("The plugin classifies severity based on action context:\n")
    
    test_cases = [
        ('view page', 'medium'),
        ('login form', 'medium'),
        ('payment processing', 'high'),
        ('money transfer', 'high'),
        ('delete account', 'high'),
        ('admin panel', 'high'),
    ]
    
    header_analysis = {'protection_level': 'none'}
    
    for action, expected in test_cases:
        vuln_data = {'action_description': action}
        severity = plugin._determine_severity(header_analysis, vuln_data)
        status = '✓' if severity == expected else '?'
        print(f"   {status} '{action}' → {severity.upper()}")


def demo_remediation_advice(plugin):
    """Demonstrate remediation advice."""
    print_section("6. Remediation Advice")
    
    print("The plugin provides comprehensive remediation guidance:\n")
    
    advice = plugin.get_remediation_advice()
    
    # Print first few lines
    lines = advice.strip().split('\n')
    for line in lines[:20]:  # Print first 20 lines
        print(line)
    
    print("\n... (see full advice in plugin documentation)")


def demo_configuration_options(plugin):
    """Demonstrate configuration options."""
    print_section("7. Configuration Options")
    
    print("Available configuration options:\n")
    
    print("📋 Overlay Appearance:")
    print("   - overlay_style: 'transparent', 'opaque', 'partial'")
    print("   - overlay_text: Custom button text")
    print("   - overlay_opacity: 0.0 to 1.0")
    
    print("\n📋 Testing Options:")
    print("   - test_mode: True/False (skip browser test)")
    print("   - browser_type: 'chrome', 'firefox'")
    print("   - headless: True/False")
    print("   - timeout: seconds")
    
    print("\n📋 Evidence Collection:")
    print("   - collect_evidence: True/False")
    print("   - output_dir: './clickjacking_reports'")
    print("   - enable_annotations: True/False")
    
    print("\n✓ Configuration Validation:")
    
    # Test valid config
    valid_config = {
        'overlay_opacity': 0.5,
        'browser_type': 'chrome',
        'timeout': 30,
    }
    is_valid = plugin.validate_config(valid_config)
    print(f"   Valid config: {is_valid} ✓")
    
    # Test invalid config
    invalid_config = {
        'overlay_opacity': 1.5,  # Out of range
    }
    is_valid = plugin.validate_config(invalid_config)
    print(f"   Invalid config (opacity 1.5): {is_valid} ✓")


def demo_integration_example():
    """Show integration example."""
    print_section("8. Integration Example")
    
    print("Example: Scanning multiple targets\n")
    
    code = '''
from scanner.plugins import get_registry

# Get plugin
registry = get_registry()
plugin = registry.get_plugin('clickjacking')

# Test multiple targets
targets = [
    'http://example.com/login',
    'http://example.com/admin',
    'http://example.com/payment',
]

vulnerable = []
for target in targets:
    result = plugin.execute_attack(
        target_url=target,
        vulnerability_data={},
        config={'test_mode': True}
    )
    if result['vulnerable']:
        vulnerable.append(target)

print(f"Found {len(vulnerable)} vulnerable targets")
'''
    
    print(code)


def save_demo_report(plugin, target_url, result, payloads):
    """Save demo report to file."""
    print_section("9. Saving Demo Report")
    
    report = {
        'plugin': {
            'name': plugin.name,
            'version': plugin.version,
            'type': plugin.vulnerability_type,
        },
        'target': target_url,
        'test_result': {
            'success': result['success'],
            'vulnerable': result['vulnerable'],
            'severity': result['severity'],
            'evidence': result['evidence'],
        },
        'payloads_generated': len(payloads),
    }
    
    report_file = 'clickjacking_demo_report.json'
    
    try:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Demo report saved to: {report_file}")
        print(f"  File size: {os.path.getsize(report_file)} bytes")
    except Exception as e:
        print(f"⚠️  Could not save report: {e}")


def main():
    """Main demo function."""
    print_banner()
    
    # Get target URL from command line or use default
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        print(f"📍 Target URL: {target_url}")
    else:
        target_url = 'http://example.com'
        print(f"📍 Using default target: {target_url}")
        print("   (Provide a URL as argument to test a specific target)")
    
    print()
    
    try:
        # 1. Plugin Information
        plugin = demo_plugin_info()
        if not plugin:
            return 1
        
        # 2. Payload Generation
        payloads = demo_payload_generation(plugin, target_url)
        
        # 3. Header Analysis
        header_analysis = demo_header_analysis(plugin, target_url)
        
        # 4. Vulnerability Test
        result = demo_vulnerability_test(plugin, target_url)
        
        # 5. Severity Classification
        demo_severity_classification(plugin)
        
        # 6. Remediation Advice
        demo_remediation_advice(plugin)
        
        # 7. Configuration Options
        demo_configuration_options(plugin)
        
        # 8. Integration Example
        demo_integration_example()
        
        # 9. Save Report
        save_demo_report(plugin, target_url, result, payloads)
        
        # Final message
        print()
        print("=" * 70)
        print("  Demo Complete!")
        print("=" * 70)
        print()
        print("For more information, see:")
        print("  - CLICKJACKING_PLUGIN_GUIDE.md")
        print("  - EXPLOIT_PLUGINS_GUIDE.md")
        print("  - scanner/tests_clickjacking.py")
        print()
        print("⚠️  Remember: Always obtain proper authorization before testing!")
        print()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n❌ Demo interrupted by user")
        return 130
    except Exception as e:
        print(f"\n\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
