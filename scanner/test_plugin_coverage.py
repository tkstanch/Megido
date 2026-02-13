"""
Test to verify that all vulnerability types have corresponding plugins.

This test ensures that every vulnerability type defined in VULNERABILITY_TYPES
has at least one detector plugin and one exploit plugin.
"""

import sys
from pathlib import Path

# Add parent directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent))

from scanner.plugins.plugin_registry import PluginRegistry
from scanner.scan_plugins.scan_plugin_registry import ScanPluginRegistry


def test_all_vulnerability_types_have_plugins():
    """Test that all vulnerability types have both detector and exploit plugins."""
    
    # Vulnerability types from scanner/models.py::VULNERABILITY_TYPES
    vulnerability_types = [
        'xss',
        'sqli', 
        'csrf',
        'xxe',
        'rce',
        'lfi',
        'rfi',
        'open_redirect',
        'ssrf',
        'info_disclosure',
        'other',
    ]
    
    print(f"\nTesting plugin coverage for {len(vulnerability_types)} vulnerability types...")
    print("=" * 70)
    
    # Test exploit plugins
    print("\n1. Testing Exploit Plugin Coverage:")
    print("-" * 70)
    exploit_registry = PluginRegistry()
    exploit_registry.discover_plugins()
    
    missing_exploits = []
    for vuln_type in vulnerability_types:
        if exploit_registry.has_plugin(vuln_type):
            plugin = exploit_registry.get_plugin(vuln_type)
            print(f"  ✓ {vuln_type:20s} : {plugin.name}")
        else:
            print(f"  ✗ {vuln_type:20s} : MISSING EXPLOIT PLUGIN")
            missing_exploits.append(vuln_type)
    
    # Test scan/detector plugins
    print("\n2. Testing Detector Plugin Coverage:")
    print("-" * 70)
    scan_registry = ScanPluginRegistry()
    scan_registry.discover_plugins()
    
    missing_detectors = []
    for vuln_type in vulnerability_types:
        # Check if any plugin handles this vulnerability type
        found = False
        detector_name = None
        for plugin in scan_registry.get_all_plugins():
            if vuln_type in plugin.vulnerability_types:
                found = True
                detector_name = plugin.name
                break
        
        if found:
            print(f"  ✓ {vuln_type:20s} : {detector_name}")
        else:
            print(f"  ✗ {vuln_type:20s} : MISSING DETECTOR PLUGIN")
            missing_detectors.append(vuln_type)
    
    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY:")
    print("=" * 70)
    print(f"Total vulnerability types: {len(vulnerability_types)}")
    print(f"Exploit plugins found: {len(vulnerability_types) - len(missing_exploits)}")
    print(f"Detector plugins found: {len(vulnerability_types) - len(missing_detectors)}")
    
    if missing_exploits:
        print(f"\n❌ Missing exploit plugins: {missing_exploits}")
    else:
        print(f"\n✅ All vulnerability types have exploit plugins!")
    
    if missing_detectors:
        print(f"❌ Missing detector plugins: {missing_detectors}")
    else:
        print(f"✅ All vulnerability types have detector plugins!")
    
    # Assert that all plugins exist
    assert not missing_exploits, f"Missing exploit plugins for: {missing_exploits}"
    assert not missing_detectors, f"Missing detector plugins for: {missing_detectors}"
    
    print("\n✅✅✅ ALL TESTS PASSED! ✅✅✅")
    print("=" * 70)


if __name__ == '__main__':
    test_all_vulnerability_types_have_plugins()
