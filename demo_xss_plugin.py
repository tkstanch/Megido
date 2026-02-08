#!/usr/bin/env python3
"""
Advanced XSS Exploit Plugin Demo

This script demonstrates the capabilities of the Advanced XSS Exploit Plugin.
"""

import sys
import os
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from scanner.plugins import get_registry, get_payload_generator


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def demo_xss_plugin_info():
    """Demonstrate XSS plugin information."""
    print_section("XSS Plugin Information")
    
    registry = get_registry()
    
    if not registry.has_plugin('xss'):
        print("\n✗ XSS Plugin not available.")
        return False
    
    xss_plugin = registry.get_plugin('xss')
    
    print(f"\n✓ Plugin Name: {xss_plugin.name}")
    print(f"  Type: {xss_plugin.vulnerability_type}")
    print(f"  Version: {xss_plugin.version}")
    print(f"  Severity: {xss_plugin.get_severity_level()}")
    print(f"\n  Description:")
    print(f"  {xss_plugin.description}")
    
    return True


def demo_payload_generation():
    """Demonstrate payload generation."""
    print_section("Payload Generation")
    
    registry = get_registry()
    xss_plugin = registry.get_plugin('xss')
    
    # 1. Basic payloads
    print("\n1. Basic XSS Payloads:")
    basic_payloads = xss_plugin.generate_payloads({'payload_type': 'basic'})
    print(f"   Generated {len(basic_payloads)} payloads")
    print("   Examples:")
    for i, payload in enumerate(basic_payloads[:5], 1):
        print(f"     {i}. {payload}")
    
    # 2. Attribute-based payloads
    print("\n2. Attribute-based XSS Payloads:")
    attr_payloads = xss_plugin.generate_payloads({'payload_type': 'attribute'})
    print(f"   Generated {len(attr_payloads)} payloads")
    print("   Examples:")
    for i, payload in enumerate(attr_payloads[:5], 1):
        print(f"     {i}. {payload}")
    
    # 3. JavaScript context payloads
    print("\n3. JavaScript Context Payloads:")
    js_payloads = xss_plugin.generate_payloads({'payload_type': 'javascript'})
    print(f"   Generated {len(js_payloads)} payloads")
    print("   Examples:")
    for i, payload in enumerate(js_payloads[:5], 1):
        print(f"     {i}. {payload}")
    
    # 4. DOM-based payloads
    print("\n4. DOM-based XSS Payloads:")
    dom_payloads = xss_plugin.generate_payloads({'payload_type': 'dom'})
    print(f"   Generated {len(dom_payloads)} payloads")
    print("   Examples:")
    for i, payload in enumerate(dom_payloads[:5], 1):
        print(f"     {i}. {payload}")
    
    # 5. Advanced payloads
    print("\n5. Advanced XSS Payloads:")
    advanced_payloads = xss_plugin.generate_payloads({'payload_type': 'advanced'})
    print(f"   Generated {len(advanced_payloads)} payloads")
    print("   Examples:")
    for i, payload in enumerate(advanced_payloads[:5], 1):
        print(f"     {i}. {payload}")
    
    # 6. All payloads
    print("\n6. All Payload Types Combined:")
    all_payloads = xss_plugin.generate_payloads({'payload_type': 'all'})
    print(f"   Generated {len(all_payloads)} total payloads")
    
    # 7. Encoded payloads
    print("\n7. Encoded Payloads (URL encoding):")
    encoded_payloads = xss_plugin.generate_payloads({
        'payload_type': 'basic',
        'encoding': 'url'
    })
    print("   Examples:")
    for i, payload in enumerate(encoded_payloads[:3], 1):
        print(f"     {i}. {payload}")
    
    # 8. Custom payloads
    print("\n8. Custom Payloads:")
    custom = ['<custom>alert(1)</custom>', 'javascript:customAlert()']
    custom_payloads = xss_plugin.generate_payloads({
        'payload_type': 'basic',
        'custom_payloads': custom
    })
    print(f"   Added {len(custom)} custom payloads")
    print("   Custom payloads included in result")


def demo_configuration():
    """Demonstrate configuration options."""
    print_section("Configuration Options")
    
    registry = get_registry()
    xss_plugin = registry.get_plugin('xss')
    
    print("\n1. Basic Configuration:")
    basic_config = {
        'crawl_depth': 2,
        'max_pages': 50,
        'enable_crawler': True,
        'enable_dom_testing': True,
    }
    print(f"   Config: {basic_config}")
    print(f"   Valid: {xss_plugin.validate_config(basic_config)}")
    
    print("\n2. Advanced Configuration:")
    advanced_config = {
        'crawl_depth': 3,
        'max_pages': 100,
        'network_throttle': 1.0,
        'timeout': 60,
        'verify_ssl': False,
        'browser_type': 'chrome',
        'headless': True,
        'randomize_fingerprint': True,
        'collect_evidence': True,
        'output_format': 'both',
    }
    print(f"   Config keys: {', '.join(advanced_config.keys())}")
    print(f"   Valid: {xss_plugin.validate_config(advanced_config)}")
    
    print("\n3. Invalid Configurations:")
    invalid_configs = [
        {'crawl_depth': -1},
        {'max_pages': 0},
        {'timeout': -10},
        {'browser_type': 'safari'},
        {'output_format': 'xml'},
    ]
    for i, config in enumerate(invalid_configs, 1):
        is_valid = xss_plugin.validate_config(config)
        print(f"   {i}. {config} → Valid: {is_valid}")
    
    print("\n4. Required Configuration Keys:")
    required_keys = xss_plugin.get_required_config_keys()
    if required_keys:
        print(f"   Required keys: {', '.join(required_keys)}")
    else:
        print("   No required keys (all optional with defaults)")


def demo_features():
    """Demonstrate plugin features."""
    print_section("Plugin Features")
    
    print("\n✓ Smart Crawling")
    print("  - Configurable depth (default: 2 levels)")
    print("  - Automatic form discovery")
    print("  - Link discovery within same domain")
    print("  - Maximum page limit (default: 50 pages)")
    
    print("\n✓ Network Throttling")
    print("  - Configurable delays between requests")
    print("  - Rate limiting to avoid detection")
    print("  - Stealth operation mode")
    
    print("\n✓ Session Management")
    print("  - Custom cookies support")
    print("  - Custom HTTP headers")
    print("  - Proxy configuration")
    print("  - SSL verification control")
    
    print("\n✓ Selenium-Powered DOM Simulation")
    print("  - Chrome and Firefox support")
    print("  - Headless mode available")
    print("  - Alert detection")
    print("  - Console log collection")
    
    print("\n✓ Browser Fingerprint Randomization")
    print("  - User agent rotation")
    print("  - Automation detection bypass")
    print("  - Anti-fingerprinting features")
    
    print("\n✓ Evidence Collection")
    print("  - Screenshot capture")
    print("  - DOM context preservation")
    print("  - Console log recording")
    print("  - HTML sample collection")
    
    print("\n✓ JavaScript Injection Context Analysis")
    print("  - HTML context detection")
    print("  - Attribute context detection")
    print("  - JavaScript context detection")
    print("  - CSS context detection")
    print("  - URL context detection")
    
    print("\n✓ Report Generation")
    print("  - JSON format (machine-readable)")
    print("  - HTML format (human-readable)")
    print("  - Both formats simultaneously")
    print("  - Detailed findings with evidence")
    print("  - Severity classification")


def demo_remediation():
    """Demonstrate remediation advice."""
    print_section("Remediation Advice")
    
    registry = get_registry()
    xss_plugin = registry.get_plugin('xss')
    
    advice = xss_plugin.get_remediation_advice()
    
    print("\nThe plugin provides comprehensive remediation advice including:")
    print("  1. Input Validation")
    print("  2. Output Encoding")
    print("  3. Content Security Policy (CSP)")
    print("  4. HTTPOnly and Secure Cookies")
    print("  5. Framework Security Features")
    print("  6. DOM Security")
    print("  7. Web Application Firewall (WAF)")
    print("  8. Security Headers")
    print("  9. Regular Security Testing")
    
    print(f"\nTotal advice length: {len(advice)} characters")
    print("\nFirst 500 characters:")
    print(advice[:500] + "...")


def demo_usage_examples():
    """Demonstrate usage examples."""
    print_section("Usage Examples")
    
    print("\n1. Basic Attack (No actual execution in demo):")
    print("""
    result = xss_plugin.execute_attack(
        target_url='http://example.com/search',
        vulnerability_data={
            'parameter': 'q',
            'method': 'GET',
        }
    )
    """)
    
    print("\n2. Advanced Attack with Full Configuration:")
    print("""
    result = xss_plugin.execute_attack(
        target_url='http://example.com',
        vulnerability_data={},
        config={
            'crawl_depth': 3,
            'max_pages': 100,
            'network_throttle': 1.0,
            'enable_dom_testing': True,
            'browser_type': 'chrome',
            'collect_evidence': True,
            'output_format': 'both',
        }
    )
    """)
    
    print("\n3. Authenticated Testing:")
    print("""
    result = xss_plugin.execute_attack(
        target_url='http://example.com',
        vulnerability_data={},
        config={
            'custom_cookies': {
                'session': 'abc123',
                'auth_token': 'xyz789',
            },
            'custom_headers': {
                'Authorization': 'Bearer token123',
            }
        }
    )
    """)
    
    print("\n4. Testing Through Proxy:")
    print("""
    result = xss_plugin.execute_attack(
        target_url='http://example.com',
        vulnerability_data={},
        config={
            'proxy': {
                'http': 'http://proxy.example.com:8080',
                'https': 'https://proxy.example.com:8080',
            }
        }
    )
    """)


def main():
    """Main demo function."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              Advanced XSS Exploit Plugin Demo                                ║
║                                                                              ║
║  This demo showcases the professional-grade XSS exploit plugin with         ║
║  advanced features for security testing, SaaS platforms, and red teams.     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Demo 1: Plugin Information
        if not demo_xss_plugin_info():
            print("\n✗ XSS Plugin not available. Please check installation.")
            return 1
        
        # Demo 2: Payload Generation
        demo_payload_generation()
        
        # Demo 3: Configuration
        demo_configuration()
        
        # Demo 4: Features
        demo_features()
        
        # Demo 5: Remediation
        demo_remediation()
        
        # Demo 6: Usage Examples
        demo_usage_examples()
        
        print("\n" + "=" * 80)
        print("  Demo Complete!")
        print("=" * 80)
        print("\nFor more information, see XSS_PLUGIN_GUIDE.md")
        print("\nIMPORTANT: Always obtain explicit written permission before")
        print("testing any system you don't own. Unauthorized testing is illegal.")
        print()
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
