#!/usr/bin/env python3
"""
Comprehensive test script for SQL Injection Payload Generator
"""
import sys

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    try:
        from sql_syntax_and_errors import SQL_CHEAT_SHEET, get_dbms_list
        from generate_sql_payloads import SQLPayloadGenerator, generate_payloads
        print("✓ All imports successful")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_cheat_sheet():
    """Test the cheat sheet data structure"""
    print("\nTesting cheat sheet...")
    from sql_syntax_and_errors import SQL_CHEAT_SHEET, get_dbms_list
    
    dbms_list = get_dbms_list()
    if not dbms_list or len(dbms_list) < 3:
        print(f"✗ Expected at least 3 DBMS types, got {len(dbms_list)}")
        return False
    
    print(f"✓ Found {len(dbms_list)} DBMS types: {', '.join(dbms_list)}")
    
    # Check each DBMS has required injection types
    for dbms in dbms_list:
        if dbms not in SQL_CHEAT_SHEET:
            print(f"✗ DBMS {dbms} not in cheat sheet")
            return False
        
        dbms_data = SQL_CHEAT_SHEET[dbms]
        if 'name' not in dbms_data:
            print(f"✗ DBMS {dbms} missing 'name' field")
            return False
    
    print("✓ All DBMS types have valid structure")
    return True

def test_payload_generation():
    """Test payload generation for all contexts"""
    print("\nTesting payload generation...")
    from generate_sql_payloads import SQLPayloadGenerator
    
    test_cases = [
        ('mysql', 'version_detection', 'string'),
        ('oracle', 'union_injection', 'numeric'),
        ('mssql', 'time_delay', 'parenthesis'),
    ]
    
    for dbms, injection_type, context in test_cases:
        try:
            generator = SQLPayloadGenerator(dbms)
            payload = generator.get_payload(injection_type, context)
            
            if not payload or 'payload' not in payload:
                print(f"✗ Failed to generate payload for {dbms}/{injection_type}/{context}")
                return False
            
            print(f"✓ Generated {dbms}/{injection_type}/{context}: {payload['payload'][:50]}...")
        except Exception as e:
            print(f"✗ Error generating payload for {dbms}/{injection_type}/{context}: {e}")
            return False
    
    return True

def test_api_structure():
    """Test Flask app structure"""
    print("\nTesting Flask app structure...")
    try:
        from app import app
        
        # Check routes exist
        routes = [rule.rule for rule in app.url_map.iter_rules()]
        required_routes = ['/', '/api/injection-types/<dbms>', '/api/generate-payload', '/health']
        
        for route in required_routes:
            # Check if any route matches the pattern
            found = any(r in routes for r in [route, route.replace('<dbms>', '<string:dbms>')])
            if not found and route not in routes:
                # More lenient check
                route_base = route.split('<')[0]
                found = any(route_base in r for r in routes)
            
            if found or route in routes:
                print(f"✓ Route exists: {route}")
            else:
                print(f"✗ Missing route: {route}")
                return False
        
        print("✓ All required routes exist")
        return True
    except Exception as e:
        print(f"✗ Error checking Flask app: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("SQL Injection Payload Generator - Test Suite")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_cheat_sheet,
        test_payload_generation,
        test_api_structure,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        if test():
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return 0 if failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
