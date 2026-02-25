"""
Unit tests for the JavaScript Hijacking / JSONP Data Exposure Detector plugin.

Covers:
  - JSONP response with sensitive keys   → high severity finding
  - JSONP response without sensitive keys → medium severity finding
  - JS MIME + sensitive variable assignment → finding
  - JS MIME + plain JSON (no XSSI guard) → finding
  - Benign JS file                        → no finding
  - HTML discovery mode: candidate extraction
  - Heuristic JSONP probe URL generation
  - Plugin auto-discovery via ScanPluginRegistry
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is on the path so imports work without Django setup.
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanner.scan_plugins.detectors.javascript_hijacking_detector import (
    JavaScriptHijackingDetectorPlugin,
)
from scanner.scan_plugins.scan_plugin_registry import ScanPluginRegistry, reset_scan_registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(body: str, content_type: str = 'application/javascript', status: int = 200):
    """Return a minimal mock requests.Response."""
    mock_resp = MagicMock()
    mock_resp.headers = {'Content-Type': content_type}
    mock_resp.status_code = status
    # Simulate stream=True raw.read behaviour.
    mock_resp.raw.read.return_value = body.encode('utf-8')
    return mock_resp


# ---------------------------------------------------------------------------
# Property smoke-tests
# ---------------------------------------------------------------------------

class TestPluginProperties(unittest.TestCase):
    def setUp(self):
        self.plugin = JavaScriptHijackingDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'javascript_hijacking_detector')

    def test_name_contains_hijacking(self):
        self.assertIn('Hijacking', self.plugin.name)

    def test_vulnerability_types(self):
        self.assertIn('js_hijacking', self.plugin.vulnerability_types)

    def test_version_is_string(self):
        self.assertIsInstance(self.plugin.version, str)
        self.assertTrue(len(self.plugin.version) > 0)

    def test_description_is_nonempty(self):
        self.assertGreater(len(self.plugin.description), 10)


# ---------------------------------------------------------------------------
# _analyse_response unit tests
# ---------------------------------------------------------------------------

class TestAnalyseResponse(unittest.TestCase):
    """Unit-test the static _analyse_response helper directly."""

    TARGET = 'https://example.com/api/user'

    def _headers(self, content_type='application/javascript'):
        return {'Content-Type': content_type}

    # --- JSONP with sensitive keys → high ---
    def test_jsonp_with_sensitive_keys_is_high(self):
        body = 'showUserInfo({"csrfToken":"abc123","email":"user@example.com"})'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(), body
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.vulnerability_type, 'js_hijacking')
        self.assertEqual(finding.severity, 'high')
        self.assertGreaterEqual(finding.confidence, 0.80)

    # --- JSONP without obvious sensitive keys → medium ---
    def test_jsonp_without_sensitive_keys_is_medium(self):
        body = '_cb({"title":"Hello","count":42})'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(), body
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, 'medium')

    # --- JS MIME + sensitive assignment → high ---
    def test_js_assignment_sensitive_key_high(self):
        body = 'var csrfToken = "abc-123-def";'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(), body
        )
        self.assertIsNotNone(finding)
        self.assertIn(finding.severity, ('high', 'critical'))

    # --- JS MIME + plain JSON array (no XSSI) → finding ---
    def test_plain_json_array_js_mime_returns_finding(self):
        body = '[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(), body
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.vulnerability_type, 'js_hijacking')

    # --- Benign JS file → no finding ---
    def test_benign_js_file_no_finding(self):
        body = '(function(){"use strict";console.log("hello");})();'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(), body
        )
        self.assertIsNone(finding)

    # --- JSON MIME type does not trigger Check 2 or 3 ---
    def test_json_mime_no_js_assignment_check(self):
        body = '{"csrfToken":"abc123"}'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(content_type='application/json'), body
        )
        # Not a JS MIME type and not a JSONP wrapper → no finding expected
        self.assertIsNone(finding)

    # --- Finding has cwe_id and remediation ---
    def test_finding_has_cwe_and_remediation(self):
        body = 'cb({"session":"xyz","token":"tok"})'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(), body
        )
        self.assertIsNotNone(finding)
        self.assertIsNotNone(finding.cwe_id)
        self.assertIn('JSONP', finding.remediation)

    # --- JSONP check precedes assignment check ---
    def test_jsonp_takes_precedence_over_assignment(self):
        body = 'apiCallback({"csrfToken":"tok123"})'
        finding = JavaScriptHijackingDetectorPlugin._analyse_response(
            self.TARGET, self._headers(), body
        )
        self.assertIsNotNone(finding)
        self.assertIn('JSONP', finding.description)


# ---------------------------------------------------------------------------
# Candidate extraction helpers
# ---------------------------------------------------------------------------

class TestExtractScriptCandidates(unittest.TestCase):
    BASE = 'https://example.com/page'

    def _extract(self, html):
        return JavaScriptHijackingDetectorPlugin._extract_script_candidates(self.BASE, html)

    def test_script_src_same_origin(self):
        html = '<script src="/api/data.json"></script>'
        candidates = self._extract(html)
        self.assertIn('https://example.com/api/data.json', candidates)

    def test_script_src_cross_origin_excluded(self):
        html = '<script src="https://cdn.other.com/lib.js"></script>'
        candidates = self._extract(html)
        self.assertEqual(candidates, [])

    def test_fetch_url_extracted(self):
        html = "<script>fetch('/api/user').then(r=>r.json())</script>"
        candidates = self._extract(html)
        self.assertIn('https://example.com/api/user', candidates)

    def test_getjson_url_extracted(self):
        html = "<script>$.getJSON('/api/items', cb)</script>"
        candidates = self._extract(html)
        self.assertIn('https://example.com/api/items', candidates)

    def test_data_uri_excluded(self):
        html = '<script src="data:text/javascript,alert(1)"></script>'
        candidates = self._extract(html)
        self.assertEqual(candidates, [])


# ---------------------------------------------------------------------------
# JSONP probe URL generation
# ---------------------------------------------------------------------------

class TestJsonpProbeUrls(unittest.TestCase):
    def test_probes_contain_callback_and_jsonp(self):
        url = 'https://example.com/api/data?lang=en'
        probes = JavaScriptHijackingDetectorPlugin._jsonp_probe_urls(url)
        param_names = set()
        for p in probes:
            parsed = __import__('urllib').parse.urlparse(p)
            qs = __import__('urllib').parse.parse_qs(parsed.query)
            param_names.update(qs.keys())
        self.assertIn('callback', param_names)
        self.assertIn('jsonp', param_names)

    def test_probe_uses_sentinel_callback_value(self):
        url = 'https://example.com/api/data?q=1'
        probes = JavaScriptHijackingDetectorPlugin._jsonp_probe_urls(url)
        for p in probes:
            self.assertIn('megidoCb', p)


# ---------------------------------------------------------------------------
# Full scan with mocked requests
# ---------------------------------------------------------------------------

class TestScanMethod(unittest.TestCase):
    TARGET = 'https://example.com/api/user?id=1'
    PLUGIN = JavaScriptHijackingDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.javascript_hijacking_detector.requests.get')
    def test_jsonp_response_returns_finding(self, mock_get):
        """Simulates a JSONP response with sensitive data → expects a high/critical finding."""
        jsonp_body = 'userDataCb({"csrfToken":"secret","session":"abc"})'
        mock_get.return_value = _make_response(jsonp_body, 'application/javascript')
        findings = self.PLUGIN.scan(self.TARGET)
        self.assertTrue(findings, 'Expected at least one finding for JSONP response')
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, 'js_hijacking')
        self.assertIn(finding.severity, ('high', 'critical'))

    @patch('scanner.scan_plugins.detectors.javascript_hijacking_detector.requests.get')
    def test_benign_js_no_finding(self, mock_get):
        """A normal JS bundle should produce no findings."""
        js_body = '!function(e){"use strict";e.exports=function(){return 42};}(module);'
        mock_get.return_value = _make_response(js_body, 'application/javascript')
        findings = self.PLUGIN.scan(self.TARGET)
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.javascript_hijacking_detector.requests.get')
    def test_html_discovery_finds_candidates(self, mock_get):
        """HTML page with a same-origin API script src → candidate is probed."""
        html_body = (
            '<html><body>'
            '<script src="/api/bootstrap.js?v=1"></script>'
            '</body></html>'
        )
        # First call: HTML page.  Subsequent calls: candidate endpoint.
        html_resp = _make_response(html_body, 'text/html')
        api_resp = _make_response(
            'window.csrfToken = "tok-xyz";', 'application/javascript'
        )
        mock_get.side_effect = [html_resp, api_resp] + [
            _make_response('', 'application/javascript')
        ] * 5
        findings = self.PLUGIN.scan('https://example.com/page')
        # Should find something from the discovered /api/bootstrap.js endpoint.
        self.assertTrue(any(f.vulnerability_type == 'js_hijacking' for f in findings))

    @patch('scanner.scan_plugins.detectors.javascript_hijacking_detector.requests.get')
    def test_request_exception_returns_empty(self, mock_get):
        """Network error during initial fetch → empty findings, no crash."""
        import requests as req_lib
        mock_get.side_effect = req_lib.RequestException('connection refused')
        findings = self.PLUGIN.scan(self.TARGET)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Registry auto-discovery
# ---------------------------------------------------------------------------

class TestRegistryDiscovery(unittest.TestCase):
    def setUp(self):
        reset_scan_registry()

    def tearDown(self):
        reset_scan_registry()

    def test_plugin_is_discovered(self):
        registry = ScanPluginRegistry()
        registry.discover_plugins()
        self.assertTrue(
            registry.has_plugin('javascript_hijacking_detector'),
            'javascript_hijacking_detector was not discovered by the registry',
        )

    def test_plugin_metadata(self):
        registry = ScanPluginRegistry()
        registry.discover_plugins()
        plugin = registry.get_plugin('javascript_hijacking_detector')
        self.assertIsNotNone(plugin)
        self.assertIn('js_hijacking', plugin.vulnerability_types)


if __name__ == '__main__':
    unittest.main()
