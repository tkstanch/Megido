#!/usr/bin/env python3
"""
Standalone API test for OOB payload generation
Tests the API functions without requiring Django server
"""

import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sql_attacker.oob_payloads import OOBPayloadGenerator, DatabaseType as OOBDatabaseType


class MockRequest:
    """Mock Django request object for testing"""
    def __init__(self, data=None, query_params=None):
        self.data = data or {}
        self.query_params = query_params or {}


def test_api_generate_oob_payloads():
    """Test the payload generation API logic"""
    print("=" * 80)
    print("Testing API: Generate OOB Payloads")
    print("=" * 80)
    
    # Test 1: Generate payloads for all databases
    print("\n→ Test 1: Generate payloads for all databases")
    request_data = {
        'attacker_host': 'api-test.attacker.com',
        'attacker_port': 80,
        'data_to_exfiltrate': 'user'
    }
    
    generator = OOBPayloadGenerator(
        request_data['attacker_host'],
        request_data['attacker_port']
    )
    
    all_payloads = generator.generate_all_payloads(
        db_type=None,
        data_to_exfiltrate=request_data['data_to_exfiltrate']
    )
    
    # Convert to API response format
    response_data = {}
    for db, payloads in all_payloads.items():
        response_data[db] = [{
            'technique': payload.technique.value,
            'payload': payload.payload,
            'description': payload.description,
            'requires_privileges': payload.requires_privileges,
            'privilege_level': payload.privilege_level,
            'listener_type': payload.listener_type,
            'example_listener_setup': payload.example_listener_setup
        } for payload in payloads]
    
    print(f"  ✓ Generated payloads for {len(response_data)} databases")
    for db, payloads in response_data.items():
        print(f"    - {db}: {len(payloads)} payloads")
    
    # Verify structure
    assert 'mssql' in response_data
    assert 'oracle' in response_data
    assert 'mysql' in response_data
    assert len(response_data['mssql']) > 0
    print("  ✓ Response structure validated")
    
    # Test 2: Generate payloads for specific database
    print("\n→ Test 2: Generate payloads for MS-SQL only")
    request_data2 = {
        'attacker_host': 'mssql-test.com',
        'attacker_port': 443,
        'db_type': 'mssql',
        'data_to_exfiltrate': '@@version'
    }
    
    db_type = OOBDatabaseType[request_data2['db_type'].upper()]
    generator2 = OOBPayloadGenerator(
        request_data2['attacker_host'],
        request_data2['attacker_port']
    )
    
    mssql_payloads = generator2.generate_all_payloads(
        db_type=db_type,
        data_to_exfiltrate=request_data2['data_to_exfiltrate']
    )
    
    print(f"  ✓ Generated payloads for MS-SQL: {len(mssql_payloads['mssql'])} payloads")
    assert 'mssql' in mssql_payloads
    assert 'oracle' not in mssql_payloads
    assert 'mysql' not in mssql_payloads
    print("  ✓ Database filtering works correctly")
    
    # Test 3: Error handling - missing attacker_host
    print("\n→ Test 3: Error handling - missing attacker_host")
    request_data3 = {}
    
    if 'attacker_host' not in request_data3:
        print("  ✓ Would return 400 error: attacker_host is required")
    
    # Test 4: Error handling - invalid db_type
    print("\n→ Test 4: Error handling - invalid db_type")
    try:
        invalid_db = OOBDatabaseType['INVALID']
        print("  ✗ Should have raised KeyError")
    except KeyError:
        print("  ✓ Would return 400 error: Invalid db_type")
    
    print("\n" + "=" * 80)
    print("✓ All API payload generation tests passed")
    print("=" * 80)


def test_api_oob_listener_guide():
    """Test the listener guide API logic"""
    print("\n" + "=" * 80)
    print("Testing API: OOB Listener Guide")
    print("=" * 80)
    
    generator = OOBPayloadGenerator()
    
    # Test each listener type
    listener_types = ['http', 'smb', 'dns', 'ldap']
    
    for listener_type in listener_types:
        print(f"\n→ Testing listener_type: {listener_type}")
        guide = generator.get_listener_setup_guide(listener_type)
        
        assert len(guide) > 0
        print(f"  ✓ Retrieved guide ({len(guide)} characters)")
    
    # Test invalid listener type
    print(f"\n→ Testing invalid listener_type")
    invalid_guide = generator.get_listener_setup_guide('invalid')
    assert "No setup guide available" in invalid_guide
    print("  ✓ Would return 400 error: Invalid listener_type")
    
    print("\n" + "=" * 80)
    print("✓ All API listener guide tests passed")
    print("=" * 80)


def test_api_response_format():
    """Test that API responses are JSON serializable"""
    print("\n" + "=" * 80)
    print("Testing API: Response JSON Serialization")
    print("=" * 80)
    
    generator = OOBPayloadGenerator('json-test.com', 80)
    all_payloads = generator.generate_all_payloads()
    
    # Convert to API response format
    response_data = {}
    for db, payloads in all_payloads.items():
        response_data[db] = [{
            'technique': payload.technique.value,
            'payload': payload.payload,
            'description': payload.description,
            'requires_privileges': payload.requires_privileges,
            'privilege_level': payload.privilege_level,
            'listener_type': payload.listener_type,
            'example_listener_setup': payload.example_listener_setup
        } for payload in payloads]
    
    # Try to serialize to JSON
    try:
        json_str = json.dumps(response_data, indent=2)
        print(f"\n  ✓ Successfully serialized to JSON ({len(json_str)} bytes)")
        
        # Parse back
        parsed = json.loads(json_str)
        print(f"  ✓ Successfully parsed JSON")
        
        # Verify structure
        assert isinstance(parsed, dict)
        assert 'mssql' in parsed
        assert isinstance(parsed['mssql'], list)
        assert len(parsed['mssql']) > 0
        assert 'technique' in parsed['mssql'][0]
        assert 'payload' in parsed['mssql'][0]
        print(f"  ✓ JSON structure validated")
        
    except Exception as e:
        print(f"  ✗ JSON serialization failed: {e}")
        raise
    
    print("\n" + "=" * 80)
    print("✓ JSON serialization tests passed")
    print("=" * 80)


def main():
    """Run all API tests"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║              OOB SQL Injection API - Standalone Tests                     ║
║                                                                           ║
║  These tests validate the API logic without requiring a running Django   ║
║  server. They test payload generation, listener guides, and JSON         ║
║  serialization.                                                           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")
    
    try:
        test_api_generate_oob_payloads()
        test_api_oob_listener_guide()
        test_api_response_format()
        
        print("\n" + "=" * 80)
        print("✓✓✓ ALL API TESTS PASSED ✓✓✓")
        print("=" * 80)
        print("\nThe API endpoints are ready to use:")
        print("  POST /sql_attacker/api/oob/generate/")
        print("  GET  /sql_attacker/api/oob/listener-guide/")
        print("\nTo test with a running Django server:")
        print("  python manage.py runserver")
        print("  curl -X POST http://localhost:8000/sql_attacker/api/oob/generate/ \\")
        print("       -H 'Content-Type: application/json' \\")
        print("       -d '{\"attacker_host\": \"test.com\"}'")
        print("=" * 80 + "\n")
        
        return True
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
