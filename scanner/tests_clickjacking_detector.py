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
  - HTML page with no headers      → high severity
  - Non-HTML page with no headers  → medium severity (unchanged)
  - JS-only framebusting           → medium severity + bypassable note
  - _scan_js_framebusting patterns
  - _protection_rating helper
  - Alternate paths scanning
  - Evidence includes protection rating and JS defense info
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


def _make_response(headers: dict, text: str = '', content_type: str = ''):
    """Return a mock requests.Response with the given headers dict and optional body."""
    mock_resp = MagicMock()
    full_headers = dict(headers)
    if content_type:
        full_headers.setdefault('Content-Type', content_type)
    mock_resp.headers = full_headers
    mock_resp.text = text
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


class TestJsFramebusting(unittest.TestCase):
    """Unit-test the _scan_js_framebusting static method."""

    def _scan(self, html):
        return ClickjackingDetectorPlugin._scan_js_framebusting(html)

    def test_top_location_ne_self_location(self):
        html = '<script>if(top.location != self.location){top.location=self.location;}</script>'
        found = self._scan(html)
        self.assertIn('top.location != self.location', found)

    def test_window_top_ne_window_self(self):
        html = '<script>if(window.top !== window.self){window.top.location=window.self.location;}</script>'
        found = self._scan(html)
        self.assertIn('window.top !== window.self', found)

    def test_top_ne_self(self):
        html = '<script>if(top != self){ top.location.href = self.location.href; }</script>'
        found = self._scan(html)
        self.assertTrue(any('top != self' in f for f in found))

    def test_window_frame_element(self):
        html = '<script>if(window.frameElement) window.frameElement.style.display="none";</script>'
        found = self._scan(html)
        self.assertTrue(any('window.frameElement' in f for f in found))

    def test_top_location_href_assignment(self):
        html = '<script>top.location.href = self.location.href;</script>'
        found = self._scan(html)
        self.assertTrue(any('top.location assignment' in f for f in found))

    def test_window_top_location_assignment(self):
        html = '<script>window.top.location = window.self.location;</script>'
        found = self._scan(html)
        self.assertTrue(any('window.top.location assignment' in f for f in found))

    def test_no_patterns_returns_empty(self):
        html = '<html><body><p>Hello, world!</p></body></html>'
        self.assertEqual(self._scan(html), [])

    def test_empty_string_returns_empty(self):
        self.assertEqual(self._scan(''), [])

    def test_multiple_patterns_found(self):
        html = (
            '<script>'
            'if(top != self){ top.location = self.location; }'
            'if(window.frameElement) window.frameElement.style.display="none";'
            '</script>'
        )
        found = self._scan(html)
        self.assertGreater(len(found), 1)


class TestProtectionRating(unittest.TestCase):
    """Unit-test the _protection_rating static method."""

    def test_strong_when_csp_protected(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._protection_rating('protected', 'absent'), 'strong'
        )

    def test_strong_even_with_xfo_protected(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._protection_rating('protected', 'protected'), 'strong'
        )

    def test_partial_when_xfo_protected(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._protection_rating('absent', 'protected'), 'partial'
        )

    def test_partial_when_xfo_weak(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._protection_rating('absent', 'weak'), 'partial'
        )

    def test_none_when_no_headers(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._protection_rating('absent', 'absent'), 'none'
        )

    def test_none_when_csp_vulnerable(self):
        self.assertEqual(
            ClickjackingDetectorPlugin._protection_rating('vulnerable', 'absent'), 'none'
        )


class TestHtmlAwareSeverity(unittest.TestCase):
    """Tests for severity escalation when response is HTML."""

    TARGET = 'http://example.com/page'

    def setUp(self):
        self.plugin = ClickjackingDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_html_page_no_headers_is_high(self, mock_get):
        """HTML page with no CSP/XFO and no JS → high severity."""
        mock_get.return_value = _make_response(
            {}, text='<html><body>Hello</body></html>', content_type='text/html'
        )
        findings = self.plugin.scan(self.TARGET)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, 'high')

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_non_html_page_no_headers_is_medium(self, mock_get):
        """Non-HTML response with no CSP/XFO → medium severity (not upgraded to high)."""
        mock_get.return_value = _make_response({}, text='{}', content_type='application/json')
        findings = self.plugin.scan(self.TARGET)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, 'medium')

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_html_js_only_defense_is_medium(self, mock_get):
        """HTML page with JS framebusting only → medium severity + bypassable note."""
        js_html = (
            '<html><head></head><body>'
            '<script>if(top != self){ top.location = self.location; }</script>'
            '</body></html>'
        )
        mock_get.return_value = _make_response({}, text=js_html, content_type='text/html')
        findings = self.plugin.scan(self.TARGET)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity, 'medium')
        self.assertIn('bypassable', finding.description.lower())
        self.assertIn('JS framebusting patterns', finding.evidence)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_html_with_csp_none_is_protected(self, mock_get):
        """HTML page with CSP frame-ancestors 'none' → no finding (even with JS)."""
        js_html = '<html><script>if(top!=self){top.location=self.location;}</script></html>'
        mock_get.return_value = _make_response(
            {'Content-Security-Policy': "frame-ancestors 'none'"},
            text=js_html,
            content_type='text/html',
        )
        self.assertEqual(self.plugin.scan(self.TARGET), [])

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_evidence_includes_protection_rating(self, mock_get):
        """Evidence string should contain the protection rating."""
        mock_get.return_value = _make_response({}, content_type='text/html')
        findings = self.plugin.scan(self.TARGET)
        self.assertTrue(findings)
        self.assertIn('protection:', findings[0].evidence)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_evidence_includes_js_defense_patterns(self, mock_get):
        """Evidence string should list any JS framebusting patterns found."""
        js_html = '<script>if(window.top !== window.self) window.top.location = window.location;</script>'
        mock_get.return_value = _make_response({}, text=js_html, content_type='text/html')
        findings = self.plugin.scan(self.TARGET)
        self.assertTrue(findings)
        self.assertIn('JS framebusting patterns', findings[0].evidence)


class TestAlternatePaths(unittest.TestCase):
    """Tests for alternate path scanning."""

    TARGET = 'http://example.com/page'

    def setUp(self):
        self.plugin = ClickjackingDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_alternate_paths_disabled_by_default(self, mock_get):
        """Without scan_alternate_paths=True only the primary URL is requested."""
        mock_get.return_value = _make_response({'X-Frame-Options': 'DENY'})
        self.plugin.scan(self.TARGET)
        self.assertEqual(mock_get.call_count, 1)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_alternate_paths_enabled(self, mock_get):
        """With scan_alternate_paths=True the primary URL plus 4 alternates are requested."""
        mock_get.return_value = _make_response({'X-Frame-Options': 'DENY'})
        self.plugin.scan(self.TARGET, config={'scan_alternate_paths': True})
        # primary + /mobile + /m + /app + /lite = 5
        self.assertEqual(mock_get.call_count, 5)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_alternate_paths_use_base_origin(self, mock_get):
        """Alternate paths are appended to the scheme+netloc of the target URL."""
        mock_get.return_value = _make_response({'X-Frame-Options': 'DENY'})
        self.plugin.scan('http://mysite.com/login', config={'scan_alternate_paths': True})
        called_urls = [call.args[0] for call in mock_get.call_args_list]
        self.assertIn('http://mysite.com/mobile', called_urls)
        self.assertIn('http://mysite.com/m', called_urls)
        self.assertIn('http://mysite.com/app', called_urls)
        self.assertIn('http://mysite.com/lite', called_urls)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_alternate_paths_findings_aggregated(self, mock_get):
        """Findings from alternate paths are included in the returned list."""
        # Primary URL returns DENY (protected); alternate paths return no headers
        def side_effect(url, **kwargs):
            if url == 'http://example.com/page':
                return _make_response({'X-Frame-Options': 'DENY'})
            return _make_response({})

        mock_get.side_effect = side_effect
        findings = self.plugin.scan(
            self.TARGET, config={'scan_alternate_paths': True}
        )
        # 4 alternate paths each produce a finding
        self.assertEqual(len(findings), 4)

    @patch('scanner.scan_plugins.detectors.clickjacking_detector.requests.get')
    def test_alternate_path_request_error_skipped(self, mock_get):
        """A network error on an alternate path is skipped; other paths still scanned."""
        import requests as req

        def side_effect(url, **kwargs):
            if '/mobile' in url:
                raise req.RequestException('timeout')
            return _make_response({'X-Frame-Options': 'DENY'})

        mock_get.side_effect = side_effect
        # Should not raise; returns findings from non-erroring URLs
        findings = self.plugin.scan(
            self.TARGET, config={'scan_alternate_paths': True}
        )
        self.assertIsInstance(findings, list)


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
