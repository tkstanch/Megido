"""
Unit tests for the Clickjacking / UI Redress Detector scan plugin.

Covers:
  - Missing both headers           → vulnerable (medium)
  - XFO DENY present               → protected (no finding)
  - XFO SAMEORIGIN present         → protected (no finding)
  - CSP frame-ancestors 'none'     → protected (no finding)
  - CSP frame-ancestors 'self'     → protected (no finding)
  - CSP frame-ancestors *          → vulnerable (medium)
  - XFO ALLOW-FROM present (weak)  → finding with low severity
  - Plugin auto-discovery via registry
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is on the path
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanner.scan_plugins.detectors.clickjacking_detector import ClickjackingDetectorPlugin
from scanner.scan_plugins.scan_plugin_registry import ScanPluginRegistry, reset_scan_registry


def _make_response(headers: dict):
    """Return a mock requests.Response with the given headers dict."""
    mock_resp = MagicMock()
    mock_resp.headers = headers
    return mock_resp


class TestClickjackingDetectorProperties(unittest.TestCase):
    """Plugin property smoke-tests."""

    def setUp(self):
        self.plugin = ClickjackingDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'clickjacking_detector')

    def test_name(self):
        self.assertIn('Clickjacking', self.plugin.name)

    def test_description(self):
        desc = self.plugin.description.lower()
        self.assertIn('clickjacking', desc)
        self.assertIn('frame', desc)

    def test_vulnerability_types(self):
        self.assertIn('clickjacking', self.plugin.vulnerability_types)

    def test_version(self):
        self.assertIsInstance(self.plugin.version, str)
        self.assertTrue(len(self.plugin.version) > 0)


class TestHeaderParsing(unittest.TestCase):
    """Unit-test the static helper methods."""

    def test_extract_csp_frame_ancestors_present(self):
        csp = "default-src 'self'; frame-ancestors 'none'; script-src 'self'"
        result = ClickjackingDetectorPlugin._extract_csp_frame_ancestors(csp)
        self.assertEqual(result, "'none'")

    def test_extract_csp_frame_ancestors_absent(self):
        csp = "default-src 'self'; script-src 'self'"
        result = ClickjackingDetectorPlugin._extract_csp_frame_ancestors(csp)
        self.assertIsNone(result)

    def test_extract_csp_frame_ancestors_empty_string(self):
        result = ClickjackingDetectorPlugin._extract_csp_frame_ancestors('')
        self.assertIsNone(result)

    def test_extract_csp_frame_ancestors_wildcard(self):
        csp = "frame-ancestors *"
        result = ClickjackingDetectorPlugin._extract_csp_frame_ancestors(csp)
        self.assertEqual(result, '*')

    def test_evaluate_csp_none_protected(self):
        status = ClickjackingDetectorPlugin._evaluate_csp_frame_ancestors("'none'")
        self.assertEqual(status, 'protected')

    def test_evaluate_csp_self_protected(self):
        status = ClickjackingDetectorPlugin._evaluate_csp_frame_ancestors("'self'")
        self.assertEqual(status, 'protected')

    def test_evaluate_csp_host_list_protected(self):
        status = ClickjackingDetectorPlugin._evaluate_csp_frame_ancestors(
            "'self' https://trusted.example.com"
        )
        self.assertEqual(status, 'protected')

    def test_evaluate_csp_wildcard_vulnerable(self):
        status = ClickjackingDetectorPlugin._evaluate_csp_frame_ancestors('*')
        self.assertEqual(status, 'vulnerable')

    def test_evaluate_csp_absent(self):
        status = ClickjackingDetectorPlugin._evaluate_csp_frame_ancestors(None)
        self.assertEqual(status, 'absent')

    def test_evaluate_xfo_deny(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._evaluate_xfo('DENY'), 'protected'
        )

    def test_evaluate_xfo_sameorigin(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._evaluate_xfo('SAMEORIGIN'), 'protected'
        )

    def test_evaluate_xfo_allow_from(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._evaluate_xfo('ALLOW-FROM https://trusted.com'),
            'weak',
        )

    def test_evaluate_xfo_absent(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._evaluate_xfo(None), 'absent'
        )

    def test_evaluate_xfo_unknown(self):
        # Malformed / unrecognised value should be treated as absent
        self.assertEqual(
            ClickjackingDetectorPlugin._evaluate_xfo('INVALID'), 'absent'
        )


class TestScanScenarios(unittest.TestCase):
    """End-to-end scan() tests with mocked HTTP responses."""

    TARGET = 'http://example.com/page'

    def setUp(self):
        self.plugin = ClickjackingDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_missing_both_headers_is_vulnerable(self, mock_get):
        """No XFO and no CSP → medium-severity clickjacking finding."""
        mock_get.return_value = _make_response({})

        findings = self.plugin.scan(self.TARGET)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, 'clickjacking')
        self.assertEqual(finding.severity, 'medium')
        self.assertIn('X-Frame-Options: missing', finding.evidence)
        self.assertIn('frame-ancestors: missing', finding.evidence)
        self.assertIn('frame-ancestors', finding.remediation)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_xfo_deny_is_protected(self, mock_get):
        """X-Frame-Options: DENY → no finding."""
        mock_get.return_value = _make_response({'X-Frame-Options': 'DENY'})
        self.assertEqual(self.plugin.scan(self.TARGET), [])

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_xfo_sameorigin_is_protected(self, mock_get):
        """X-Frame-Options: SAMEORIGIN → no finding."""
        mock_get.return_value = _make_response({'X-Frame-Options': 'SAMEORIGIN'})
        self.assertEqual(self.plugin.scan(self.TARGET), [])

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_csp_frame_ancestors_none_is_protected(self, mock_get):
        """CSP frame-ancestors 'none' → no finding."""
        mock_get.return_value = _make_response({
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"
        })
        self.assertEqual(self.plugin.scan(self.TARGET), [])

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_csp_frame_ancestors_self_is_protected(self, mock_get):
        """CSP frame-ancestors 'self' → no finding."""
        mock_get.return_value = _make_response({
            'Content-Security-Policy': "frame-ancestors 'self'"
        })
        self.assertEqual(self.plugin.scan(self.TARGET), [])

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_csp_frame_ancestors_wildcard_is_vulnerable(self, mock_get):
        """CSP frame-ancestors * → medium-severity finding."""
        mock_get.return_value = _make_response({
            'Content-Security-Policy': 'frame-ancestors *'
        })

        findings = self.plugin.scan(self.TARGET)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, 'clickjacking')
        self.assertEqual(finding.severity, 'medium')
        self.assertIn('broad', finding.description.lower())

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_xfo_allow_from_is_weak(self, mock_get):
        """X-Frame-Options ALLOW-FROM → low-severity finding."""
        mock_get.return_value = _make_response({
            'X-Frame-Options': 'ALLOW-FROM https://trusted.example.com'
        })

        findings = self.plugin.scan(self.TARGET)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, 'clickjacking')
        self.assertEqual(finding.severity, 'low')
        self.assertIn('ALLOW-FROM', finding.description)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_csp_takes_priority_over_xfo(self, mock_get):
        """CSP frame-ancestors 'none' protects even when XFO is absent."""
        mock_get.return_value = _make_response({
            'Content-Security-Policy': "frame-ancestors 'none'"
            # No X-Frame-Options header
        })
        self.assertEqual(self.plugin.scan(self.TARGET), [])

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_evidence_contains_header_values(self, mock_get):
        """Evidence should include the observed header values."""
        mock_get.return_value = _make_response({
            'X-Frame-Options': 'ALLOW-FROM https://a.example.com',
        })

        findings = self.plugin.scan(self.TARGET)
        self.assertTrue(findings)
        evidence = findings[0].evidence
        self.assertIn('ALLOW-FROM', evidence)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_request_exception_returns_empty(self, mock_get):
        """A network error should produce an empty list, not an exception."""
        import requests as req
        mock_get.side_effect = req.RequestException("connection refused")
        findings = self.plugin.scan(self.TARGET)
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_finding_has_cwe_id(self, mock_get):
        mock_get.return_value = _make_response({})
        findings = self.plugin.scan(self.TARGET)
        self.assertTrue(findings)
        self.assertEqual(findings[0].cwe_id, 'CWE-1021')

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_finding_has_remediation(self, mock_get):
        mock_get.return_value = _make_response({})
        findings = self.plugin.scan(self.TARGET)
        self.assertTrue(findings)
        remediation = findings[0].remediation
        self.assertIn('frame-ancestors', remediation)
        self.assertIn('X-Frame-Options', remediation)


class TestRegistryDiscovery(unittest.TestCase):
    """Verify auto-discovery via ScanPluginRegistry."""

    def setUp(self):
        reset_scan_registry()

    def tearDown(self):
        reset_scan_registry()

    def test_plugin_is_discovered(self):
        registry = ScanPluginRegistry()
        registry.discover_plugins()
        self.assertTrue(
            registry.has_plugin('clickjacking_detector'),
            "clickjacking_detector was not discovered by the registry",
        )

    def test_plugin_metadata(self):
        registry = ScanPluginRegistry()
        registry.discover_plugins()
        plugin = registry.get_plugin('clickjacking_detector')
        self.assertIsNotNone(plugin)
        self.assertIn('clickjacking', plugin.vulnerability_types)


if __name__ == '__main__':
    unittest.main()
