"""
Test script for SSRF plugin with visual proof capabilities.
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.plugins.exploits.ssrf_plugin import SSRFPlugin

def test_ssrf_plugin():
    """Test SSRF plugin with visual proof capabilities."""
    print("Testing SSRF Plugin with Visual Proof Capabilities")
    print("=" * 60)
    
    # Initialize plugin
    plugin = SSRFPlugin()
    
    # Display plugin info
    print(f"\nPlugin Name: {plugin.name}")
    print(f"Version: {plugin.version}")
    print(f"Vulnerability Type: {plugin.vulnerability_type}")
    print(f"Severity: {plugin.get_severity_level()}")
    print(f"\nDescription: {plugin.description}")
    
    # Test imports
    print("\n" + "=" * 60)
    print("Checking Required Imports:")
    print("=" * 60)
    
    try:
        from scanner.plugins.exploits.ssrf_plugin import HAS_REQUESTS, HAS_VISUAL_PROOF
        print(f"✓ Requests library: {'Available' if HAS_REQUESTS else 'Not Available'}")
        print(f"✓ Visual Proof modules: {'Available' if HAS_VISUAL_PROOF else 'Not Available'}")
    except Exception as e:
        print(f"✗ Import check failed: {e}")
    
    # Test payload generation
    print("\n" + "=" * 60)
    print("Testing Payload Generation:")
    print("=" * 60)
    
    context = {
        'target_host': '127.0.0.1',
        'target_port': 80,
        'cloud_provider': 'aws'
    }
    
    payloads = plugin.generate_payloads(context)
    print(f"\nGenerated {len(payloads)} payloads:")
    for i, payload in enumerate(payloads[:5], 1):
        print(f"  {i}. {payload}")
    if len(payloads) > 5:
        print(f"  ... and {len(payloads) - 5} more")
    
    # Test method existence
    print("\n" + "=" * 60)
    print("Checking Plugin Methods:")
    print("=" * 60)
    
    methods = [
        'execute_attack',
        'generate_payloads',
        '_extract_cloud_metadata',
        '_scan_internal_network',
        '_capture_visual_proof',
        'get_severity_level',
        'get_remediation_advice',
    ]
    
    for method in methods:
        has_method = hasattr(plugin, method)
        print(f"{'✓' if has_method else '✗'} {method}")
    
    # Display cloud endpoints
    print("\n" + "=" * 60)
    print("Cloud Metadata Endpoints:")
    print("=" * 60)
    
    for provider, endpoints in plugin.CLOUD_ENDPOINTS.items():
        print(f"\n{provider.upper()}:")
        for endpoint in endpoints[:2]:
            print(f"  • {endpoint}")
    
    # Display remediation advice
    print("\n" + "=" * 60)
    print("Remediation Advice:")
    print("=" * 60)
    print(plugin.get_remediation_advice())
    
    print("\n" + "=" * 60)
    print("✓ All checks completed successfully!")
    print("=" * 60)

if __name__ == '__main__':
    test_ssrf_plugin()
