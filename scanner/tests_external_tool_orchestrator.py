"""
Tests for ExternalToolOrchestrator

Covers:
- Tool availability checks
- NucleiScanner – output parsing
- ContentDiscoveryScanner – ffuf/gobuster/feroxbuster output parsing
- PortScanOrchestrator – nmap XML parsing
- ApplicationAnalyzer – nikto/whatweb output parsing
- ParameterAnalyzer – arjun/paramspider output parsing
- ExternalToolOrchestrator.run_all – integration tests with mocked tools
- ExternalToolOrchestrator.available_tools
"""

import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch, call
import subprocess

from scanner.external_tool_orchestrator import (
    ExternalToolOrchestrator,
    ExternalToolScanConfig,
    NucleiScanner,
    ContentDiscoveryScanner,
    PortScanOrchestrator,
    ApplicationAnalyzer,
    ParameterAnalyzer,
    _is_available,
    _run,
)
from scanner.engine_plugins.base_engine import EngineResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_tmp(content: str, suffix: str = ".tmp") -> str:
    """Write *content* to a temp file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as fh:
        fh.write(content)
        return fh.name


# ---------------------------------------------------------------------------
# _is_available
# ---------------------------------------------------------------------------

class TestIsAvailable(unittest.TestCase):
    def test_existing_binary(self):
        # 'python3' or 'python' should be available
        self.assertTrue(_is_available("python3") or _is_available("python"))

    def test_nonexistent_binary(self):
        self.assertFalse(_is_available("__non_existent_binary_xyzzy__"))


# ---------------------------------------------------------------------------
# NucleiScanner
# ---------------------------------------------------------------------------

class TestNucleiScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = NucleiScanner()

    # ---- availability -------------------------------------------------------

    @patch("scanner.external_tool_orchestrator.shutil.which", return_value=None)
    def test_not_available_when_missing(self, _mock):
        self.assertFalse(self.scanner.is_available())

    @patch("scanner.external_tool_orchestrator.shutil.which", return_value="/usr/bin/nuclei")
    def test_available_when_on_path(self, _mock):
        self.assertTrue(self.scanner.is_available())

    # ---- scan raises when missing -------------------------------------------

    @patch("scanner.external_tool_orchestrator.shutil.which", return_value=None)
    def test_scan_raises_if_not_installed(self, _mock):
        with self.assertRaises(RuntimeError):
            self.scanner.scan(target_url="https://example.com")

    def test_scan_raises_without_target(self):
        with patch.object(self.scanner, "is_available", return_value=True):
            with self.assertRaises(ValueError):
                self.scanner.scan()

    # ---- output parsing -----------------------------------------------------

    def test_parse_output_empty_file(self):
        path = _write_tmp("", ".jsonl")
        try:
            findings = self.scanner._parse_output(path)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_parse_output_valid_jsonl(self):
        record = {
            "template-id": "cve-2021-44228",
            "info": {
                "name": "Log4Shell RCE",
                "severity": "critical",
                "description": "Log4j JNDI injection",
                "tags": ["cve", "CVE-2021-44228", "rce"],
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            },
            "matched-at": "https://example.com/app",
            "extracted-results": ["jndi:ldap://attacker.com/a"],
        }
        path = _write_tmp(json.dumps(record) + "\n", ".jsonl")
        try:
            findings = self.scanner._parse_output(path)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertIsInstance(f, EngineResult)
            self.assertEqual(f.severity, "critical")
            self.assertEqual(f.engine_id, NucleiScanner.ENGINE_ID)
            self.assertEqual(f.title, "Log4Shell RCE")
            self.assertEqual(f.cve_id, "CVE-2021-44228")
            self.assertIn("cve-2021-44228", f.evidence)
        finally:
            os.unlink(path)

    def test_parse_output_skips_non_json_lines(self):
        content = "not json\n" + json.dumps({"template-id": "t1", "info": {"name": "T1", "severity": "low"}}) + "\n"
        path = _write_tmp(content, ".jsonl")
        try:
            findings = self.scanner._parse_output(path)
            self.assertEqual(len(findings), 1)
        finally:
            os.unlink(path)

    def test_item_to_result_info_severity(self):
        item = {
            "template-id": "generic-info",
            "info": {"name": "Info finding", "severity": "info"},
            "matched-at": "https://example.com",
        }
        result = self.scanner._item_to_result(item)
        self.assertEqual(result.severity, "info")
        self.assertAlmostEqual(result.confidence, 0.40, places=2)

    def test_item_to_result_unknown_severity_defaults_to_low(self):
        item = {
            "template-id": "weird",
            "info": {"name": "Weird", "severity": "unknown"},
            "matched-at": "https://x.com",
        }
        result = self.scanner._item_to_result(item)
        # "unknown" is mapped to "low" in the severity map
        self.assertEqual(result.severity, "low")

    def test_item_to_result_classification_cve(self):
        item = {
            "template-id": "test-cve",
            "info": {
                "name": "Test",
                "severity": "high",
                "classification": {"cve-id": ["CVE-2023-1234"], "cwe-id": ["CWE-79"]},
            },
            "matched-at": "https://x.com",
        }
        result = self.scanner._item_to_result(item)
        self.assertEqual(result.cve_id, "CVE-2023-1234")
        self.assertEqual(result.cwe_id, "CWE-79")

    # ---- scan with mocked subprocess ----------------------------------------

    def test_scan_creates_output_file_and_parses(self):
        record = {
            "template-id": "xss-reflected",
            "info": {"name": "Reflected XSS", "severity": "high"},
            "matched-at": "https://example.com/search?q=<xss>",
        }

        def fake_run(cmd, **kwargs):
            # Write JSONL to the output path argument (-o <path>)
            o_idx = cmd.index("-o")
            out_path = cmd[o_idx + 1]
            with open(out_path, "w") as fh:
                fh.write(json.dumps(record) + "\n")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        with patch.object(self.scanner, "is_available", return_value=True), \
             patch("scanner.external_tool_orchestrator._run", side_effect=fake_run):
            findings = self.scanner.scan(target_url="https://example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")


# ---------------------------------------------------------------------------
# ContentDiscoveryScanner
# ---------------------------------------------------------------------------

class TestContentDiscoveryScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = ContentDiscoveryScanner()

    @patch("scanner.external_tool_orchestrator.shutil.which", return_value=None)
    def test_not_available_when_no_tools(self, _mock):
        self.assertFalse(self.scanner.is_available())

    def test_pick_tool_returns_first_available(self):
        with patch("scanner.external_tool_orchestrator.shutil.which") as mock_which:
            def which_side(binary):
                if binary == "ffuf":
                    return None
                if binary == "feroxbuster":
                    return "/usr/bin/feroxbuster"
                return None
            mock_which.side_effect = which_side
            tool = self.scanner._pick_tool()
            self.assertEqual(tool, "feroxbuster")

    # ---- ffuf parser --------------------------------------------------------

    def test_parse_ffuf_empty(self):
        path = _write_tmp('{"results": []}', ".json")
        try:
            findings = self.scanner._parse_ffuf(path, "https://example.com")
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_parse_ffuf_with_results(self):
        data = {
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "url": "https://example.com/admin",
                    "status": 200,
                    "length": 1024,
                }
            ]
        }
        path = _write_tmp(json.dumps(data), ".json")
        try:
            findings = self.scanner._parse_ffuf(path, "https://example.com")
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.severity, "info")
            self.assertIn("admin", f.title)
            self.assertEqual(f.url, "https://example.com/admin")
        finally:
            os.unlink(path)

    # ---- feroxbuster parser -------------------------------------------------

    def test_parse_feroxbuster_with_results(self):
        lines = [
            json.dumps({"type": "response", "url": "https://example.com/secret", "status": 200}),
            json.dumps({"type": "summary", "total": 1}),
            "not json",
        ]
        path = _write_tmp("\n".join(lines), ".jsonl")
        try:
            findings = self.scanner._parse_feroxbuster(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].url, "https://example.com/secret")
        finally:
            os.unlink(path)

    # ---- gobuster parser ----------------------------------------------------

    def test_parse_gobuster(self):
        output = (
            "/admin                (Status: 301) [Size: 123] [--> /admin/]\n"
            "/login                (Status: 200) [Size: 456]\n"
            "Progress: done\n"
        )
        findings = self.scanner._parse_gobuster(output, "https://example.com")
        self.assertEqual(len(findings), 2)
        paths = [f.raw_output["path"] for f in findings]
        self.assertIn("/admin", paths)
        self.assertIn("/login", paths)

    def test_scan_raises_when_no_tools(self):
        with patch.object(self.scanner, "_pick_tool", return_value=None):
            with self.assertRaises(RuntimeError):
                self.scanner.scan("https://example.com", wordlist="/tmp/w.txt")

    def test_scan_raises_when_wordlist_missing(self):
        with patch.object(self.scanner, "_pick_tool", return_value="ffuf"):
            with self.assertRaises(FileNotFoundError):
                self.scanner.scan("https://example.com", wordlist="/nonexistent/wordlist.txt")


# ---------------------------------------------------------------------------
# PortScanOrchestrator
# ---------------------------------------------------------------------------

class TestPortScanOrchestrator(unittest.TestCase):

    NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    def setUp(self):
        self.scanner = PortScanOrchestrator()

    @patch("scanner.external_tool_orchestrator.shutil.which", return_value=None)
    def test_not_available(self, _mock):
        self.assertFalse(self.scanner.is_available())

    def test_parse_xml_open_ports(self):
        path = _write_tmp(self.NMAP_XML, ".xml")
        try:
            findings = self.scanner._parse_xml(path, "192.168.1.1")
            # Only open ports should be returned
            self.assertEqual(len(findings), 2)
            ports = [f.raw_output["port"] for f in findings]
            self.assertIn("22", ports)
            self.assertIn("80", ports)
            self.assertNotIn("443", ports)
        finally:
            os.unlink(path)

    def test_parse_xml_severity_ssh_is_high(self):
        path = _write_tmp(self.NMAP_XML, ".xml")
        try:
            findings = self.scanner._parse_xml(path, "192.168.1.1")
            ssh_finding = next(f for f in findings if f.raw_output["port"] == "22")
            self.assertEqual(ssh_finding.severity, "high")
        finally:
            os.unlink(path)

    def test_parse_xml_severity_http_is_medium(self):
        path = _write_tmp(self.NMAP_XML, ".xml")
        try:
            findings = self.scanner._parse_xml(path, "192.168.1.1")
            http_finding = next(f for f in findings if f.raw_output["port"] == "80")
            self.assertEqual(http_finding.severity, "medium")
        finally:
            os.unlink(path)

    def test_port_severity_redis_is_high(self):
        self.assertEqual(self.scanner._port_severity(6379, "redis"), "high")

    def test_port_severity_unknown_is_info(self):
        self.assertEqual(self.scanner._port_severity(12345, "unknown"), "info")

    def test_scan_raises_if_not_installed(self):
        with patch.object(self.scanner, "is_available", return_value=False):
            with self.assertRaises(RuntimeError):
                self.scanner.scan("192.168.1.1")

    def test_parse_xml_missing_file(self):
        findings = self.scanner._parse_xml("/nonexistent/file.xml", "192.168.1.1")
        self.assertEqual(findings, [])

    def test_scan_with_mocked_nmap(self):
        def fake_run(cmd, **kwargs):
            xml_idx = cmd.index("-oX")
            xml_path = cmd[xml_idx + 1]
            with open(xml_path, "w") as fh:
                fh.write(self.NMAP_XML)
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        with patch.object(self.scanner, "is_available", return_value=True), \
             patch("scanner.external_tool_orchestrator._run", side_effect=fake_run):
            findings = self.scanner.scan("192.168.1.1")

        self.assertEqual(len(findings), 2)


# ---------------------------------------------------------------------------
# ApplicationAnalyzer
# ---------------------------------------------------------------------------

class TestApplicationAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ApplicationAnalyzer()

    def test_is_available_requires_at_least_one_tool(self):
        with patch("scanner.external_tool_orchestrator.shutil.which", return_value=None):
            self.assertFalse(self.analyzer.is_available())

    # ---- nikto parser -------------------------------------------------------

    def test_parse_nikto_empty(self):
        path = _write_tmp('{"vulnerabilities": []}', ".json")
        try:
            findings = self.analyzer._parse_nikto(path)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_parse_nikto_with_findings(self):
        data = {
            "vulnerabilities": [
                {
                    "msg": "X-Frame-Options header not set",
                    "url": "https://example.com/",
                    "OSVDB": "0",
                }
            ]
        }
        path = _write_tmp(json.dumps(data), ".json")
        try:
            findings = self.analyzer._parse_nikto(path)
            self.assertEqual(len(findings), 1)
            self.assertIn("X-Frame-Options", findings[0].title)
        finally:
            os.unlink(path)

    def test_parse_nikto_invalid_json(self):
        path = _write_tmp("not json", ".json")
        try:
            findings = self.analyzer._parse_nikto(path)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    # ---- whatweb parser -----------------------------------------------------

    def test_parse_whatweb_with_plugins(self):
        record = {
            "target": "https://example.com",
            "plugins": {
                "Nginx": {"version": ["1.18.0"]},
                "Django": {},
            },
        }
        output = json.dumps(record)
        findings = self.analyzer._parse_whatweb(output, "https://example.com")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "info")
        self.assertIn("Nginx", f.evidence)

    def test_parse_whatweb_empty_plugins(self):
        record = {"target": "https://example.com", "plugins": {}}
        output = json.dumps(record)
        findings = self.analyzer._parse_whatweb(output, "https://example.com")
        self.assertEqual(findings, [])

    def test_parse_whatweb_non_json_lines_skipped(self):
        output = "not json\n" + json.dumps({"target": "x", "plugins": {}})
        findings = self.analyzer._parse_whatweb(output, "https://x.com")
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# ParameterAnalyzer
# ---------------------------------------------------------------------------

class TestParameterAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = ParameterAnalyzer()

    # ---- arjun parser -------------------------------------------------------

    def test_parse_arjun_with_params(self):
        data = {"https://example.com/search": ["q", "lang", "debug"]}
        path = _write_tmp(json.dumps(data), ".json")
        try:
            findings = self.analyzer._parse_arjun(path, "https://example.com/search")
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.severity, "medium")
            self.assertIn("3 hidden parameter", f.description)
        finally:
            os.unlink(path)

    def test_parse_arjun_no_params(self):
        data = {"https://example.com/": []}
        path = _write_tmp(json.dumps(data), ".json")
        try:
            findings = self.analyzer._parse_arjun(path, "https://example.com/")
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_parse_arjun_invalid_json(self):
        path = _write_tmp("invalid", ".json")
        try:
            findings = self.analyzer._parse_arjun(path, "https://example.com/")
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    # ---- paramspider parser -------------------------------------------------

    def test_parse_paramspider_with_urls(self):
        content = (
            "https://example.com/page?id=FUZZ\n"
            "https://example.com/search?q=FUZZ&lang=FUZZ\n"
        )
        path = _write_tmp(content, ".txt")
        try:
            findings = self.analyzer._parse_paramspider(path, "https://example.com")
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertIn("2", f.description)
        finally:
            os.unlink(path)

    def test_parse_paramspider_empty_file(self):
        path = _write_tmp("", ".txt")
        try:
            findings = self.analyzer._parse_paramspider(path, "https://example.com")
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_parse_paramspider_missing_file(self):
        findings = self.analyzer._parse_paramspider("/nonexistent.txt", "https://example.com")
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# ExternalToolOrchestrator
# ---------------------------------------------------------------------------

class TestExternalToolOrchestrator(unittest.TestCase):

    def setUp(self):
        self.orc = ExternalToolOrchestrator()

    # ---- available_tools ----------------------------------------------------

    def test_available_tools_returns_dict(self):
        tools = self.orc.available_tools()
        expected_keys = {"nuclei", "content_discovery", "nmap", "application_analysis", "parameter_analysis"}
        self.assertEqual(set(tools.keys()), expected_keys)
        for v in tools.values():
            self.assertIsInstance(v, bool)

    # ---- run_all skips unavailable tools ------------------------------------

    def test_run_all_skips_nuclei_when_unavailable(self):
        cfg = ExternalToolScanConfig(
            run_nuclei=True,
            run_content_discovery=False,
            run_port_scan=False,
            run_application_analysis=False,
            run_parameter_analysis=False,
        )
        with patch.object(self.orc._nuclei, "is_available", return_value=False):
            results = self.orc.run_all("https://example.com", config=cfg)
        self.assertEqual(results, [])

    def test_run_all_skips_content_when_wordlist_missing(self):
        cfg = ExternalToolScanConfig(
            run_nuclei=False,
            run_content_discovery=True,
            run_port_scan=False,
            run_application_analysis=False,
            run_parameter_analysis=False,
            wordlist="/nonexistent/wordlist.txt",
        )
        with patch.object(self.orc._content, "is_available", return_value=True):
            results = self.orc.run_all("https://example.com", config=cfg)
        self.assertEqual(results, [])

    def test_run_all_returns_combined_results(self):
        dummy_finding = EngineResult(
            engine_id="test",
            engine_name="Test",
            title="Test finding",
            description="desc",
            severity="high",
        )

        cfg = ExternalToolScanConfig(
            run_nuclei=True,
            run_content_discovery=False,
            run_port_scan=False,
            run_application_analysis=False,
            run_parameter_analysis=False,
        )

        with patch.object(self.orc._nuclei, "is_available", return_value=True), \
             patch.object(self.orc._nuclei, "scan", return_value=[dummy_finding]):
            results = self.orc.run_all("https://example.com", config=cfg)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "Test finding")

    def test_run_all_handles_tool_exception_gracefully(self):
        cfg = ExternalToolScanConfig(
            run_nuclei=True,
            run_content_discovery=False,
            run_port_scan=False,
            run_application_analysis=False,
            run_parameter_analysis=False,
        )
        with patch.object(self.orc._nuclei, "is_available", return_value=True), \
             patch.object(self.orc._nuclei, "scan", side_effect=RuntimeError("boom")):
            # Should NOT raise; error is logged and scan continues
            results = self.orc.run_all("https://example.com", config=cfg)
        self.assertEqual(results, [])

    def test_run_all_port_scan_extracts_hostname(self):
        dummy = EngineResult(
            engine_id="nmap_port_scan",
            engine_name="Nmap Port Scanner",
            title="Port 80 open",
            description="HTTP",
            severity="medium",
        )
        cfg = ExternalToolScanConfig(
            run_nuclei=False,
            run_content_discovery=False,
            run_port_scan=True,
            run_application_analysis=False,
            run_parameter_analysis=False,
        )
        with patch.object(self.orc._ports, "is_available", return_value=True), \
             patch.object(self.orc._ports, "scan", return_value=[dummy]) as mock_scan:
            self.orc.run_all("https://example.com/path?foo=bar", config=cfg)
        # Verify nmap was called with the hostname only
        args, kwargs = mock_scan.call_args
        self.assertEqual(kwargs.get("target") or args[0], "example.com")

    # ---- default config -----------------------------------------------------

    def test_run_all_uses_default_config_when_none_given(self):
        """run_all should not raise when config=None."""
        with patch.object(self.orc._nuclei, "is_available", return_value=False), \
             patch.object(self.orc._content, "is_available", return_value=False), \
             patch.object(self.orc._ports, "is_available", return_value=False), \
             patch.object(self.orc._app, "is_available", return_value=False), \
             patch.object(self.orc._params, "is_available", return_value=False):
            results = self.orc.run_all("https://example.com")
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# ExternalToolScanConfig
# ---------------------------------------------------------------------------

class TestExternalToolScanConfig(unittest.TestCase):

    def test_defaults(self):
        cfg = ExternalToolScanConfig()
        self.assertTrue(cfg.run_nuclei)
        self.assertTrue(cfg.run_content_discovery)
        self.assertTrue(cfg.run_port_scan)
        self.assertTrue(cfg.run_application_analysis)
        self.assertTrue(cfg.run_parameter_analysis)
        self.assertIsNone(cfg.nuclei_tags)
        self.assertIsNone(cfg.target_file)

    def test_custom_values(self):
        cfg = ExternalToolScanConfig(
            run_nuclei=False,
            nuclei_tags=["cve", "sqli"],
            port_range="80,443",
        )
        self.assertFalse(cfg.run_nuclei)
        self.assertEqual(cfg.nuclei_tags, ["cve", "sqli"])
        self.assertEqual(cfg.port_range, "80,443")


if __name__ == "__main__":
    unittest.main()
