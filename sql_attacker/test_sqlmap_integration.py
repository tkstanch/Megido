#!/usr/bin/env python3
"""
Standalone test script for SQLMap integration (no Django required).
Tests core functionality with mocked sqlmap execution.
"""

import sys
import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.sqlmap_integration import (
    SQLMapAttacker,
    SQLMapConfig,
    SQLMapRiskLevel,
    SQLMapLevel,
    HTTPRequest,
    EnumerationTarget,
    SQLMapResult,
    create_attacker,
)


class TestSQLMapConfig(unittest.TestCase):
    """Test SQLMap configuration"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = SQLMapConfig()
        
        self.assertEqual(config.risk, SQLMapRiskLevel.LOW)
        self.assertEqual(config.level, SQLMapLevel.MINIMAL)
        self.assertEqual(config.verbosity, 1)
        self.assertEqual(config.threads, 1)
        self.assertEqual(config.timeout, 30)
        self.assertTrue(config.batch)
        self.assertFalse(config.flush_session)
        self.assertIsNone(config.proxy)
    
    def test_custom_config(self):
        """Test custom configuration"""
        config = SQLMapConfig(
            risk=SQLMapRiskLevel.HIGH,
            level=SQLMapLevel.COMPREHENSIVE,
            verbosity=3,
            threads=4,
            proxy="http://127.0.0.1:8080",
            tamper=["space2comment", "between"]
        )
        
        self.assertEqual(config.risk, SQLMapRiskLevel.HIGH)
        self.assertEqual(config.level, SQLMapLevel.COMPREHENSIVE)
        self.assertEqual(config.verbosity, 3)
        self.assertEqual(config.threads, 4)
        self.assertEqual(config.proxy, "http://127.0.0.1:8080")
        self.assertEqual(config.tamper, ["space2comment", "between"])


class TestHTTPRequest(unittest.TestCase):
    """Test HTTP request representation"""
    
    def test_get_request(self):
        """Test GET request creation"""
        request = HTTPRequest(
            url="http://example.com/page?id=1",
            method="GET"
        )
        
        self.assertEqual(request.url, "http://example.com/page?id=1")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.headers, {})
        self.assertEqual(request.cookies, {})
        self.assertIsNone(request.data)
    
    def test_post_request(self):
        """Test POST request creation"""
        request = HTTPRequest(
            url="http://example.com/login",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            cookies={"sessionid": "abc123"},
            data={"username": "admin", "password": "pass"}
        )
        
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.headers["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(request.cookies["sessionid"], "abc123")
        self.assertEqual(request.data["username"], "admin")
    
    def test_raw_request(self):
        """Test raw HTTP request"""
        raw = "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin"
        request = HTTPRequest(
            url="http://example.com/login",
            raw_request=raw
        )
        
        self.assertEqual(request.raw_request, raw)


class TestSQLMapAttacker(unittest.TestCase):
    """Test SQLMap attacker functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = SQLMapConfig(
            batch=True,
            verbosity=0,
            authorized=True,
            allowed_domains=["example.com"],
        )
        self.attacker = SQLMapAttacker(config=self.config)
    
    def tearDown(self):
        """Clean up after tests"""
        self.attacker._cleanup_temp_files()
    
    def test_initialization(self):
        """Test attacker initialization"""
        self.assertIsNotNone(self.attacker)
        self.assertEqual(self.attacker.config, self.config)
        self.assertEqual(self.attacker.sqlmap_path, "sqlmap")
        self.assertEqual(self.attacker.temp_files, [])
    
    def test_save_get_request_to_file(self):
        """Test saving GET request to file"""
        request = HTTPRequest(
            url="http://example.com/page?id=1",
            method="GET",
            headers={"User-Agent": "TestAgent"}
        )
        
        temp_file = self.attacker._save_request_to_file(request)
        
        self.assertTrue(os.path.exists(temp_file))
        self.assertIn(temp_file, self.attacker.temp_files)
        
        with open(temp_file, 'r') as f:
            content = f.read()
        
        self.assertIn("GET", content)
        self.assertIn("page?id=1", content)
        self.assertIn("Host: example.com", content)
        self.assertIn("User-Agent: TestAgent", content)
    
    def test_save_post_request_to_file(self):
        """Test saving POST request to file"""
        request = HTTPRequest(
            url="http://example.com/login",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            cookies={"sessionid": "xyz"},
            data={"user": "admin", "pass": "secret"}
        )
        
        temp_file = self.attacker._save_request_to_file(request)
        
        self.assertTrue(os.path.exists(temp_file))
        
        with open(temp_file, 'r') as f:
            content = f.read()
        
        self.assertIn("POST", content)
        self.assertIn("Host: example.com", content)
        self.assertIn("Cookie: sessionid=xyz", content)
        self.assertIn("user=admin", content)
        self.assertIn("pass=secret", content)
    
    def test_save_raw_request_to_file(self):
        """Test saving raw HTTP request to file"""
        raw_request = """POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"user":"admin"}"""
        
        request = HTTPRequest(
            url="http://example.com/api/login",
            raw_request=raw_request
        )
        
        temp_file = self.attacker._save_request_to_file(request)
        
        with open(temp_file, 'r') as f:
            content = f.read()
        
        self.assertEqual(content, raw_request)
    
    def test_cleanup_temp_files(self):
        """Test temporary file cleanup"""
        request = HTTPRequest(url="http://example.com/test?id=1")
        temp_file = self.attacker._save_request_to_file(request)
        
        self.assertTrue(os.path.exists(temp_file))
        
        self.attacker._cleanup_temp_files()
        
        self.assertFalse(os.path.exists(temp_file))
        self.assertEqual(self.attacker.temp_files, [])
    
    def test_build_basic_command(self):
        """Test building basic sqlmap command"""
        request = HTTPRequest(url="http://example.com/test?id=1")
        
        cmd = self.attacker._build_command(request)
        
        self.assertIn("sqlmap", cmd[0])
        self.assertIn("-r", cmd)
        self.assertIn("--risk", cmd)
        self.assertIn("--level", cmd)
        self.assertIn("-v", cmd)
        self.assertIn("--batch", cmd)
    
    def test_build_command_with_enumeration(self):
        """Test building command with enumeration options"""
        request = HTTPRequest(url="http://example.com/test?id=1")
        
        # Test database enumeration
        cmd = self.attacker._build_command(request, enumeration=EnumerationTarget.DATABASES)
        self.assertIn("--dbs", cmd)
        
        # Test table enumeration
        cmd = self.attacker._build_command(request, enumeration=EnumerationTarget.TABLES, database="testdb")
        self.assertIn("--tables", cmd)
        self.assertIn("-D", cmd)
        self.assertIn("testdb", cmd)
        
        # Test column enumeration
        cmd = self.attacker._build_command(request, enumeration=EnumerationTarget.COLUMNS, 
                                          database="testdb", table="users")
        self.assertIn("--columns", cmd)
        self.assertIn("-D", cmd)
        self.assertIn("testdb", cmd)
        self.assertIn("-T", cmd)
        self.assertIn("users", cmd)
        
        # Test data dump
        cmd = self.attacker._build_command(request, enumeration=EnumerationTarget.DUMP,
                                          database="testdb", table="users")
        self.assertIn("--dump", cmd)
    
    def test_build_command_with_proxy(self):
        """Test building command with proxy"""
        config = SQLMapConfig(
            proxy="http://127.0.0.1:8080",
            proxy_cred="user:pass"
        )
        attacker = SQLMapAttacker(config=config)
        
        request = HTTPRequest(url="http://example.com/test?id=1")
        cmd = attacker._build_command(request)
        
        self.assertIn("--proxy", cmd)
        self.assertIn("http://127.0.0.1:8080", cmd)
        self.assertIn("--proxy-cred", cmd)
        self.assertIn("user:pass", cmd)
    
    def test_build_command_with_tamper(self):
        """Test building command with tamper scripts"""
        config = SQLMapConfig(
            tamper=["space2comment", "between", "charencode"]
        )
        attacker = SQLMapAttacker(config=config)
        
        request = HTTPRequest(url="http://example.com/test?id=1")
        cmd = attacker._build_command(request)
        
        self.assertIn("--tamper", cmd)
        tamper_idx = cmd.index("--tamper")
        self.assertEqual(cmd[tamper_idx + 1], "space2comment,between,charencode")
    
    def test_build_command_with_extra_options(self):
        """Test building command with extra options"""
        request = HTTPRequest(url="http://example.com/test?id=1")
        extra_options = ["--os-shell", "--sql-shell", "--no-cast"]
        
        cmd = self.attacker._build_command(request, extra_options=extra_options)
        
        self.assertIn("--os-shell", cmd)
        self.assertIn("--sql-shell", cmd)
        self.assertIn("--no-cast", cmd)
    
    def test_parse_vulnerable_output(self):
        """Test parsing vulnerable sqlmap output"""
        output = """
[INFO] testing connection
[INFO] testing if the target URL is stable
[INFO] target URL is stable
[INFO] testing if GET parameter 'id' is vulnerable to SQL injection
[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing?
[INFO] sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
back-end DBMS: MySQL >= 5.0
[INFO] fetching database names
available databases [3]:
[*] information_schema
[*] mysql
[*] testdb
"""
        
        parsed = self.attacker._parse_output(output)
        
        self.assertTrue(parsed['vulnerable'])
        self.assertIn('testdb', parsed['databases'])
        self.assertIn('mysql', parsed['databases'])
        self.assertEqual(len(parsed['databases']), 3)
        self.assertIn('MySQL', parsed['dbms'])
    
    def test_parse_not_vulnerable_output(self):
        """Test parsing non-vulnerable output"""
        output = """
[INFO] testing connection
[INFO] testing if the target URL is stable
[INFO] target URL is stable
[WARNING] GET parameter 'id' does not appear to be vulnerable
[WARNING] GET parameter 'name' does not appear to be vulnerable
"""
        
        parsed = self.attacker._parse_output(output)
        
        self.assertFalse(parsed['vulnerable'])
    
    @patch('subprocess.Popen')
    def test_execute_sqlmap_success(self, mock_popen):
        """Test successful sqlmap execution"""
        # Mock subprocess
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("sqlmap output", "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        cmd = ["sqlmap", "--version"]
        return_code, stdout, stderr = self.attacker._execute_sqlmap(cmd)
        
        self.assertEqual(return_code, 0)
        self.assertEqual(stdout, "sqlmap output")
        self.assertEqual(stderr, "")
    
    @patch('subprocess.Popen')
    def test_execute_sqlmap_error(self, mock_popen):
        """Test sqlmap execution with error"""
        # Mock subprocess with error
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("", "Error: something went wrong")
        mock_process.returncode = 1
        mock_popen.return_value = mock_process
        
        cmd = ["sqlmap", "--invalid-option"]
        return_code, stdout, stderr = self.attacker._execute_sqlmap(cmd)
        
        self.assertEqual(return_code, 1)
        self.assertIn("Error", stderr)
    
    @patch('subprocess.Popen')
    def test_test_injection(self, mock_popen):
        """Test injection testing method"""
        # Mock vulnerable response
        mock_process = MagicMock()
        mock_process.communicate.return_value = (
            "GET parameter 'id' is vulnerable to SQL injection",
            ""
        )
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        request = HTTPRequest(url="http://example.com/test?id=1")
        result = self.attacker.test_injection(request)
        
        self.assertIsInstance(result, SQLMapResult)
        self.assertTrue(result.success)
        self.assertTrue(result.vulnerable)
        self.assertIn("vulnerable", result.output)
    
    @patch('subprocess.Popen')
    def test_enumerate_databases(self, mock_popen):
        """Test database enumeration method"""
        # Mock database enumeration response
        mock_process = MagicMock()
        mock_process.communicate.return_value = (
            """available databases [2]:
[*] testdb
[*] mysql""",
            ""
        )
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        request = HTTPRequest(url="http://example.com/test?id=1")
        result = self.attacker.enumerate_databases(request)
        
        self.assertTrue(result.success)
        self.assertIn("testdb", result.databases)
        self.assertIn("mysql", result.databases)
    
    @patch('subprocess.Popen')
    def test_enumerate_tables(self, mock_popen):
        """Test table enumeration method"""
        # Mock table enumeration response
        mock_process = MagicMock()
        mock_process.communicate.return_value = (
            """Database: testdb
[3 tables]
[*] users
[*] products
[*] orders""",
            ""
        )
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        request = HTTPRequest(url="http://example.com/test?id=1")
        result = self.attacker.enumerate_tables(request, "testdb")
        
        self.assertTrue(result.success)
        self.assertIn("testdb", result.tables)
        # Verify table parsing
        tables = result.tables.get("testdb", [])
        self.assertGreater(len(tables), 0, "Should parse at least one table")
        self.assertIn("users", tables, "Should parse 'users' table from output")
    
    @patch('subprocess.Popen')
    def test_orchestrate_attack_not_vulnerable(self, mock_popen):
        """Test orchestrated attack when not vulnerable"""
        # Mock non-vulnerable response
        mock_process = MagicMock()
        mock_process.communicate.return_value = (
            "does not appear to be vulnerable",
            ""
        )
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        request = HTTPRequest(url="http://example.com/test?id=1")
        results = self.attacker.orchestrate_attack(request)
        
        self.assertFalse(results['success'])
        self.assertIn('vulnerability_test', results['stages_completed'])
        self.assertEqual(len(results['databases']), 0)
    
    @patch('subprocess.Popen')
    def test_orchestrate_attack_success(self, mock_popen):
        """Test successful orchestrated attack"""
        # Mock multiple responses for different stages
        responses = [
            ("GET parameter 'id' is vulnerable", ""),  # Vulnerability test
            ("available databases [1]:\n[*] testdb", ""),  # Database enumeration
            ("Database: testdb\n[1 tables]\n[*] users", ""),  # Table enumeration
        ]
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate.side_effect = responses
        mock_popen.return_value = mock_process
        
        request = HTTPRequest(url="http://example.com/test?id=1")
        results = self.attacker.orchestrate_attack(request)
        
        self.assertTrue(results['success'])
        self.assertGreaterEqual(len(results['stages_completed']), 2)


class TestConvenienceFunction(unittest.TestCase):
    """Test convenience functions"""
    
    def test_create_attacker(self):
        """Test create_attacker convenience function"""
        attacker = create_attacker(risk=2, level=3, verbosity=2)
        
        self.assertIsInstance(attacker, SQLMapAttacker)
        self.assertEqual(attacker.config.risk, SQLMapRiskLevel.MEDIUM)
        self.assertEqual(attacker.config.level, SQLMapLevel.INTERMEDIATE)
        self.assertEqual(attacker.config.verbosity, 2)
    
    def test_create_attacker_with_proxy(self):
        """Test create_attacker with proxy"""
        attacker = create_attacker(proxy="http://127.0.0.1:8080")
        
        self.assertEqual(attacker.config.proxy, "http://127.0.0.1:8080")


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestSQLMapConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestHTTPRequest))
    suite.addTests(loader.loadTestsFromTestCase(TestSQLMapAttacker))
    suite.addTests(loader.loadTestsFromTestCase(TestConvenienceFunction))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("="*80)
    print("SQLMap Integration - Standalone Test Suite")
    print("="*80)
    print()
    
    success = run_tests()
    
    print()
    print("="*80)
    if success:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed")
    print("="*80)
    
    sys.exit(0 if success else 1)
