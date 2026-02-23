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
    AttackMode,
    OrchestrateReport,
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


class TestAttackMode(unittest.TestCase):
    """Test AttackMode enum and parsing."""

    def test_enum_values(self):
        self.assertEqual(AttackMode.DETECT_ONLY.value, "detect_only")
        self.assertEqual(AttackMode.ENUMERATE_SAFE.value, "enumerate_safe")
        self.assertEqual(AttackMode.FULL.value, "full")

    def test_from_string_valid(self):
        self.assertEqual(AttackMode.from_string("detect_only"), AttackMode.DETECT_ONLY)
        self.assertEqual(AttackMode.from_string("ENUMERATE_SAFE"), AttackMode.ENUMERATE_SAFE)
        self.assertEqual(AttackMode.from_string("  Full  "), AttackMode.FULL)

    def test_from_string_invalid(self):
        with self.assertRaises(ValueError):
            AttackMode.from_string("unknown_mode")


class TestOrchestrateReport(unittest.TestCase):
    """Test OrchestrateReport serialisation, redaction, and dict-like access."""

    def _make_report(self, **overrides):
        """Helper: build a minimal OrchestrateReport for testing."""
        defaults = dict(
            mode=AttackMode.FULL,
            success=True,
            stages_attempted=["vulnerability_test", "enumerate_databases", "dump_data"],
            stages_completed=["vulnerability_test", "enumerate_databases"],
            per_stage_outputs={"vulnerability_test": {"vulnerable": True}},
            databases=["testdb"],
            tables={"testdb": ["users"]},
            columns={"testdb": {"users": ["id", "email"]}},
            dumps={"testdb.users": "secret_data"},
            vulnerability_test=None,
            errors=[],
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            duration_seconds=1.0,
        )
        defaults.update(overrides)
        return OrchestrateReport(**defaults)

    def test_to_dict_contains_expected_keys(self):
        report = self._make_report()
        d = report.to_dict()
        for key in ("mode", "success", "stages_attempted", "stages_completed",
                    "databases", "tables", "columns", "dumps", "errors",
                    "started_at", "finished_at", "duration_seconds"):
            self.assertIn(key, d)

    def test_to_dict_mode_is_string(self):
        report = self._make_report(mode=AttackMode.DETECT_ONLY)
        self.assertEqual(report.to_dict()["mode"], "detect_only")

    def test_to_dict_redacts_dumps_by_default(self):
        report = self._make_report()
        d = report.to_dict()
        # dumps value should be redacted
        self.assertNotEqual(d["dumps"], {"testdb.users": {"testdb.users": "secret_data"}})
        self.assertEqual(d["dumps"]["testdb.users"], "[REDACTED]")

    def test_to_dict_no_redaction_when_disabled(self):
        report = self._make_report()
        d = report.to_dict(redact_dumps=False)
        self.assertEqual(d["dumps"], {"testdb.users": "secret_data"})

    def test_to_json_is_valid_json(self):
        import json as _json
        report = self._make_report()
        raw = report.to_json()
        parsed = _json.loads(raw)
        self.assertEqual(parsed["mode"], "full")
        self.assertTrue(parsed["success"])

    def test_to_json_redacts_dumps_by_default(self):
        import json as _json
        report = self._make_report()
        parsed = _json.loads(report.to_json())
        self.assertEqual(parsed["dumps"]["testdb.users"], "[REDACTED]")

    def test_to_json_no_redaction(self):
        import json as _json
        report = self._make_report()
        parsed = _json.loads(report.to_json(redact_dumps=False))
        self.assertNotEqual(parsed["dumps"]["testdb.users"], "[REDACTED]")
        self.assertEqual(parsed["dumps"]["testdb.users"], "secret_data")

    def test_to_text_returns_markdown(self):
        report = self._make_report()
        text = report.to_text()
        self.assertIn("# SQL Attacker Orchestration Report", text)
        self.assertIn("full", text)
        self.assertIn("testdb", text)
        self.assertIn("redacted", text.lower())

    def test_dict_like_access(self):
        report = self._make_report()
        self.assertTrue(report["success"])
        self.assertIn("testdb", report["databases"])

    def test_dict_contains(self):
        report = self._make_report()
        self.assertIn("success", report)
        self.assertIn("stages_completed", report)
        self.assertNotIn("nonexistent_key", report)


class TestOrchestrateAttackModeGating(unittest.TestCase):
    """Test that operation modes correctly gate which stages execute."""

    def setUp(self):
        self.config = SQLMapConfig(
            batch=True,
            verbosity=0,
            authorized=True,
            allowed_domains=["example.com"],
        )
        self.attacker = SQLMapAttacker(config=self.config)
        self.request = HTTPRequest(url="http://example.com/test?id=1")

    def tearDown(self):
        self.attacker._cleanup_temp_files()

    def _mock_popen_side_effects(self, mock_popen, responses):
        """Configure mock_popen to return successive responses."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate.side_effect = responses
        mock_popen.return_value = mock_process

    @patch('subprocess.Popen')
    def test_detect_only_stops_after_vulnerability_test(self, mock_popen):
        """detect_only mode must not call enumeration or dump stages."""
        self._mock_popen_side_effects(mock_popen, [
            ("GET parameter 'id' is vulnerable", ""),
        ])
        report = self.attacker.orchestrate_attack(
            self.request, mode=AttackMode.DETECT_ONLY
        )
        self.assertIsInstance(report, OrchestrateReport)
        self.assertIn("vulnerability_test", report.stages_completed)
        self.assertNotIn("enumerate_databases", report.stages_completed)
        self.assertNotIn("enumerate_columns", report.stages_completed)
        self.assertNotIn("dump_data", report.stages_completed)
        # subprocess should have been called exactly once (vulnerability test)
        self.assertEqual(mock_popen.call_count, 1)

    @patch('subprocess.Popen')
    def test_enumerate_safe_stops_before_dump(self, mock_popen):
        """enumerate_safe mode must enumerate but must not dump."""
        self._mock_popen_side_effects(mock_popen, [
            ("GET parameter 'id' is vulnerable", ""),              # Stage 1
            ("available databases [1]:\n[*] testdb", ""),          # Stage 2
            ("Database: testdb\n[1 tables]\n[*] users", ""),       # Stage 3
            ("Table: users\n[2 columns]\nid\nemail", ""),          # Stage 4
        ])
        report = self.attacker.orchestrate_attack(
            self.request, mode=AttackMode.ENUMERATE_SAFE
        )
        self.assertIsInstance(report, OrchestrateReport)
        self.assertIn("vulnerability_test", report.stages_completed)
        self.assertIn("enumerate_databases", report.stages_completed)
        self.assertNotIn("dump_data", report.stages_completed)
        # dump_table should NOT have been called
        for call_args in mock_popen.call_args_list:
            cmd = call_args[0][0] if call_args[0] else call_args[1].get("args", [])
            self.assertNotIn("--dump", cmd)

    @patch('subprocess.Popen')
    def test_full_mode_includes_dump(self, mock_popen):
        """full mode must attempt the dump stage."""
        self._mock_popen_side_effects(mock_popen, [
            ("GET parameter 'id' is vulnerable", ""),              # Stage 1
            ("available databases [1]:\n[*] testdb", ""),          # Stage 2
            ("Database: testdb\n[1 tables]\n[*] users", ""),       # Stage 3
            ("Table: users\n[2 columns]\nid\nemail", ""),          # Stage 4
            ("Table: testdb.users\n| id | email |\n| 1 | a@b.com |", ""),  # Stage 5
        ])
        report = self.attacker.orchestrate_attack(
            self.request, mode=AttackMode.FULL
        )
        self.assertIsInstance(report, OrchestrateReport)
        self.assertIn("dump_data", report.stages_attempted)

    @patch('subprocess.Popen')
    def test_detect_only_not_vulnerable(self, mock_popen):
        """detect_only mode: not-vulnerable result should set success=False."""
        self._mock_popen_side_effects(mock_popen, [
            ("does not appear to be vulnerable", ""),
        ])
        report = self.attacker.orchestrate_attack(
            self.request, mode=AttackMode.DETECT_ONLY
        )
        self.assertFalse(report.success)
        self.assertFalse(report["success"])  # dict-like access
        self.assertIn("vulnerability_test", report.stages_completed)
        self.assertNotIn("enumerate_databases", report.stages_completed)

    @patch('subprocess.Popen')
    def test_report_has_timestamps(self, mock_popen):
        """OrchestrateReport should have started_at and finished_at."""
        self._mock_popen_side_effects(mock_popen, [
            ("does not appear to be vulnerable", ""),
        ])
        report = self.attacker.orchestrate_attack(
            self.request, mode=AttackMode.DETECT_ONLY
        )
        self.assertRegex(report.started_at, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
        self.assertRegex(report.finished_at, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
        self.assertGreaterEqual(report.duration_seconds, 0.0)

    @patch('subprocess.Popen')
    def test_backward_compat_not_vulnerable(self, mock_popen):
        """Existing dict-style tests still pass with new OrchestrateReport return."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("does not appear to be vulnerable", "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        results = self.attacker.orchestrate_attack(self.request)
        self.assertFalse(results['success'])
        self.assertIn('vulnerability_test', results['stages_completed'])
        self.assertEqual(len(results['databases']), 0)


class TestRequestSerialisation(unittest.TestCase):
    """Tests for enhanced _save_request_to_file serialisation behaviour."""

    def setUp(self):
        config = SQLMapConfig(authorized=True, allowed_domains=["example.com"])
        self.attacker = SQLMapAttacker(config=config)

    def tearDown(self):
        self.attacker._cleanup_temp_files()

    def _read_file(self, request: HTTPRequest) -> str:
        path = self.attacker._save_request_to_file(request)
        # Open with newline='' to avoid Python's universal-newlines translation
        # so that CRLF bytes in the file are visible as \r\n in the returned string.
        with open(path, 'r', newline='') as fh:
            return fh.read()

    # ------------------------------------------------------------------
    # CRLF line endings
    # ------------------------------------------------------------------

    def test_get_request_uses_crlf(self):
        """Non-body requests must use CRLF line endings."""
        request = HTTPRequest(url="http://example.com/page?id=1", method="GET")
        content = self._read_file(request)
        # Split on CRLF – every logical line should be separated by \r\n
        self.assertIn("\r\n", content)

    def test_post_request_uses_crlf(self):
        """POST requests must use CRLF line endings."""
        request = HTTPRequest(
            url="http://example.com/login",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"user": "admin"},
        )
        content = self._read_file(request)
        self.assertIn("\r\n", content)

    # ------------------------------------------------------------------
    # PUT / PATCH body support
    # ------------------------------------------------------------------

    def test_put_request_includes_body(self):
        """PUT requests with data must have a body in the serialised file."""
        request = HTTPRequest(
            url="http://example.com/api/item/1",
            method="PUT",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"name": "updated"},
        )
        content = self._read_file(request)
        self.assertIn("PUT", content)
        self.assertIn("name=updated", content)

    def test_patch_request_includes_body(self):
        """PATCH requests with data must have a body in the serialised file."""
        request = HTTPRequest(
            url="http://example.com/api/item/1",
            method="PATCH",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"status": "active"},
        )
        content = self._read_file(request)
        self.assertIn("PATCH", content)
        self.assertIn("status=active", content)

    def test_delete_request_without_body(self):
        """DELETE requests must not include a body even if ``data`` is provided.

        Only POST, PUT, and PATCH are expected to carry a request body.
        """
        request = HTTPRequest(
            url="http://example.com/api/item/1",
            method="DELETE",
            data={"confirm": "yes"},  # data provided but DELETE is not in the body-methods list
        )
        content = self._read_file(request)
        self.assertNotIn("confirm=yes", content)

    # ------------------------------------------------------------------
    # JSON body serialisation
    # ------------------------------------------------------------------

    def test_json_body_serialised_as_json(self):
        """When Content-Type is application/json the body must be JSON."""
        import json as _json
        request = HTTPRequest(
            url="http://example.com/api/login",
            method="POST",
            headers={"Content-Type": "application/json"},
            data={"username": "admin", "password": "secret"},
        )
        content = self._read_file(request)
        # Find the body after the header/body separator (\r\n\r\n)
        separator = "\r\n\r\n"
        self.assertIn(separator, content)
        body_part = content.split(separator, 1)[1]
        parsed = _json.loads(body_part)
        self.assertEqual(parsed["username"], "admin")

    def test_form_body_serialised_as_urlencoded(self):
        """When Content-Type is form-encoded the body must be URL-encoded."""
        request = HTTPRequest(
            url="http://example.com/login",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"user": "admin", "pass": "secret"},
        )
        content = self._read_file(request)
        separator = "\r\n\r\n"
        body_part = content.split(separator, 1)[1]
        self.assertIn("user=admin", body_part)

    # ------------------------------------------------------------------
    # Content-Length header
    # ------------------------------------------------------------------

    def test_content_length_added_for_post(self):
        """A Content-Length header must be present when there is a body."""
        request = HTTPRequest(
            url="http://example.com/login",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"user": "admin"},
        )
        content = self._read_file(request)
        self.assertIn("Content-Length:", content)

    def test_content_length_not_duplicated(self):
        """Caller-supplied Content-Length must be replaced by the computed value.

        Any ``Content-Length`` header passed by the caller is stripped and
        replaced with a freshly computed value so that the header appears
        exactly once, regardless of what the caller supplied.
        """
        request = HTTPRequest(
            url="http://example.com/login",
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": "9999",  # caller-supplied; will be ignored and recomputed
            },
            data={"user": "admin"},
        )
        content = self._read_file(request)
        # The re-computed Content-Length should appear exactly once
        self.assertEqual(content.count("Content-Length:"), 1)

    def test_no_content_length_for_get(self):
        """GET requests without a body must not have a Content-Length header."""
        request = HTTPRequest(url="http://example.com/page?id=1", method="GET")
        content = self._read_file(request)
        self.assertNotIn("Content-Length:", content)

    # ------------------------------------------------------------------
    # Host header correctness
    # ------------------------------------------------------------------

    def test_host_header_present(self):
        """Host header must be present and correct."""
        request = HTTPRequest(url="http://example.com:8080/path", method="GET")
        content = self._read_file(request)
        self.assertIn("Host: example.com:8080", content)


class TestParseOutputInjectionPoints(unittest.TestCase):
    """Tests for enhanced _parse_output injection-point extraction."""

    def setUp(self):
        config = SQLMapConfig(authorized=True, allowed_domains=["example.com"])
        self.attacker = SQLMapAttacker(config=config)

    def test_parse_injection_point_get(self):
        """Injection points for GET parameters must be extracted correctly."""
        output = (
            "[INFO] sqlmap identified the following injection point(s):\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind\n"
        )
        parsed = self.attacker._parse_output(output)
        self.assertTrue(parsed["vulnerable"])
        self.assertEqual(len(parsed["injection_points"]), 1)
        ip = parsed["injection_points"][0]
        self.assertEqual(ip["parameter"], "id")
        self.assertEqual(ip["method"], "GET")
        self.assertEqual(ip["type"], "boolean-based blind")

    def test_parse_injection_point_post(self):
        """Injection points for POST parameters must be extracted correctly."""
        output = (
            "Parameter: username (POST)\n"
            "    Type: error-based\n"
            "    Title: MySQL error-based\n"
        )
        parsed = self.attacker._parse_output(output)
        self.assertEqual(len(parsed["injection_points"]), 1)
        ip = parsed["injection_points"][0]
        self.assertEqual(ip["parameter"], "username")
        self.assertEqual(ip["method"], "POST")
        self.assertEqual(ip["type"], "error-based")

    def test_parse_multiple_injection_points(self):
        """Multiple injection points must all be captured."""
        output = (
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "Parameter: name (GET)\n"
            "    Type: time-based blind\n"
        )
        parsed = self.attacker._parse_output(output)
        self.assertEqual(len(parsed["injection_points"]), 2)
        names = [ip["parameter"] for ip in parsed["injection_points"]]
        self.assertIn("id", names)
        self.assertIn("name", names)

    def test_parse_dbms_version(self):
        """DBMS version string should be extracted from back-end DBMS line."""
        output = "back-end DBMS: MySQL >= 5.0.12\n"
        parsed = self.attacker._parse_output(output)
        self.assertIsNotNone(parsed["dbms"])
        self.assertIn("MySQL", parsed["dbms"])
        self.assertIsNotNone(parsed["dbms_version"])

    def test_parse_no_injection_points(self):
        """Output with no injection points must return an empty list."""
        output = "[WARNING] GET parameter 'x' does not appear to be vulnerable\n"
        parsed = self.attacker._parse_output(output)
        self.assertFalse(parsed["vulnerable"])
        self.assertEqual(parsed["injection_points"], [])


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
    suite.addTests(loader.loadTestsFromTestCase(TestAttackMode))
    suite.addTests(loader.loadTestsFromTestCase(TestOrchestrateReport))
    suite.addTests(loader.loadTestsFromTestCase(TestOrchestrateAttackModeGating))
    suite.addTests(loader.loadTestsFromTestCase(TestRequestSerialisation))
    suite.addTests(loader.loadTestsFromTestCase(TestParseOutputInjectionPoints))
    
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
