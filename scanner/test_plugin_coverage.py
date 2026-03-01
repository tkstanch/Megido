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

# Minimum number of payloads each exploit plugin must provide
MIN_PAYLOAD_COUNT = 1000


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
        'clickjacking',
        'js_hijacking',
        'idor',
        'jwt',
        'crlf',
        'host_header',
        'smuggling',
        'deserialization',
        'graphql',
        'websocket',
        'cache_poisoning',
        'cors',
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

    # Test payload counts
    print(f"\n3. Testing Exploit Plugin Payload Counts (minimum {MIN_PAYLOAD_COUNT}):")
    print("-" * 70)
    insufficient_payloads = []
    for vuln_type in vulnerability_types:
        if exploit_registry.has_plugin(vuln_type):
            plugin = exploit_registry.get_plugin(vuln_type)
            try:
                payloads = plugin.generate_payloads()
            except Exception:
                payloads = []
            count = len(payloads)
            if count >= MIN_PAYLOAD_COUNT:
                print(f"  ✓ {vuln_type:20s} : {count} payloads")
            else:
                print(f"  ✗ {vuln_type:20s} : {count} payloads (need {MIN_PAYLOAD_COUNT})")
                insufficient_payloads.append((vuln_type, count))

    # Test plugin metadata
    print("\n4. Testing Exploit Plugin Metadata:")
    print("-" * 70)
    bad_metadata = []
    for vuln_type in vulnerability_types:
        if exploit_registry.has_plugin(vuln_type):
            plugin = exploit_registry.get_plugin(vuln_type)
            issues = []
            if not plugin.name:
                issues.append("missing name")
            if not plugin.description:
                issues.append("missing description")
            if not plugin.version:
                issues.append("missing version")
            if not plugin.vulnerability_type:
                issues.append("missing vulnerability_type")
            if issues:
                print(f"  ✗ {vuln_type:20s} : {', '.join(issues)}")
                bad_metadata.append(vuln_type)
            else:
                print(f"  ✓ {vuln_type:20s} : name={plugin.name!r}, version={plugin.version}")

    # Test execute_attack result structure
    print("\n5. Testing execute_attack() Result Structure:")
    print("-" * 70)
    bad_structure = []
    try:
        from unittest.mock import patch, MagicMock

        # Create a mock response that simulates a 404 not found (prevents false positives)
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ''
        mock_resp.content = b''
        mock_resp.headers = {}
        mock_resp.json.return_value = {}

        mock_oob = MagicMock()
        mock_oob.__enter__ = MagicMock(return_value=mock_oob)
        mock_oob.__exit__ = MagicMock(return_value=False)
        mock_oob.generate_multiple_payloads.return_value = []
        mock_oob.verify_multiple_callbacks.return_value = {}

        with patch('requests.get', return_value=mock_resp), \
             patch('requests.post', return_value=mock_resp), \
             patch('time.sleep', return_value=None), \
             patch('scanner.plugins.exploits.ssrf_plugin.get_oob_exploitation_framework',
                   return_value=mock_oob, create=True):
            for vuln_type in vulnerability_types:
                if exploit_registry.has_plugin(vuln_type):
                    plugin = exploit_registry.get_plugin(vuln_type)
                    try:
                        result = plugin.execute_attack(
                            'http://test.example.com/',
                            {'parameter': 'test'},
                            {'timeout': 1, 'verify_ssl': False,
                             'enable_oob_verification': False},
                        )
                        if not isinstance(result, dict):
                            print(f"  ✗ {vuln_type:20s} : result is not a dict")
                            bad_structure.append(vuln_type)
                        elif 'success' not in result:
                            print(f"  ✗ {vuln_type:20s} : result missing 'success' key")
                            bad_structure.append(vuln_type)
                        else:
                            print(f"  ✓ {vuln_type:20s} : success={result.get('success')}")
                    except Exception as e:
                        print(f"  ✗ {vuln_type:20s} : execute_attack raised {type(e).__name__}: {e}")
                        bad_structure.append(vuln_type)
    except ImportError:
        print("  ⚠ unittest.mock not available, skipping execute_attack structure test")
        bad_structure = []

    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY:")
    print("=" * 70)
    print(f"Total vulnerability types: {len(vulnerability_types)}")
    print(f"Exploit plugins found: {len(vulnerability_types) - len(missing_exploits)}")
    print(f"Detector plugins found: {len(vulnerability_types) - len(missing_detectors)}")
    print(f"Plugins with sufficient payloads: {len(vulnerability_types) - len(insufficient_payloads)}")
    print(f"Plugins with valid metadata: {len(vulnerability_types) - len(bad_metadata)}")
    print(f"Plugins with valid execute_attack: {len(vulnerability_types) - len(bad_structure)}")
    
    if missing_exploits:
        print(f"\n❌ Missing exploit plugins: {missing_exploits}")
    else:
        print(f"\n✅ All vulnerability types have exploit plugins!")
    
    if missing_detectors:
        print(f"❌ Missing detector plugins: {missing_detectors}")
    else:
        print(f"✅ All vulnerability types have detector plugins!")

    if insufficient_payloads:
        print(f"❌ Insufficient payloads: {insufficient_payloads}")
    else:
        print(f"✅ All exploit plugins have {MIN_PAYLOAD_COUNT}+ payloads!")

    if bad_metadata:
        print(f"❌ Bad metadata: {bad_metadata}")
    else:
        print(f"✅ All exploit plugins have valid metadata!")

    if bad_structure:
        print(f"❌ Bad execute_attack structure: {bad_structure}")
    else:
        print(f"✅ All exploit plugins return properly structured results!")
    
    # Assert that all plugins exist
    assert not missing_exploits, f"Missing exploit plugins for: {missing_exploits}"
    assert not missing_detectors, f"Missing detector plugins for: {missing_detectors}"
    assert not insufficient_payloads, (
        f"Plugins with fewer than {MIN_PAYLOAD_COUNT} payloads: {insufficient_payloads}"
    )
    assert not bad_metadata, f"Plugins with invalid metadata: {bad_metadata}"
    assert not bad_structure, f"Plugins with invalid execute_attack structure: {bad_structure}"
    
    print("\n✅✅✅ ALL TESTS PASSED! ✅✅✅")
    print("=" * 70)


if __name__ == '__main__':
    test_all_vulnerability_types_have_plugins()
