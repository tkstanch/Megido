"""
Unit tests for the 403 Forbidden Bypass Detector scan plugin and exploit plugin.

Covers:
  - Plugin metadata properties (plugin_id, name, version, description, vulnerability_types)
  - Baseline: non-403 response → no findings
  - Method tampering: 403 on GET, 200 on POST → finding produced
  - Path manipulation: 403 on base URL, 200 on mangled path → finding produced
  - Header bypass: 403 without headers, 200 with X-Original-URL → finding produced
  - No bypass found: all attempts return 403 → empty list
  - Network errors handled gracefully → no crash, empty list
  - Config option toggles (disable individual categories)
  - Correct CWE and severity in findings
  - Exploit plugin: execute_attack success path
  - Exploit plugin: execute_attack no-requests fallback
  - Exploit plugin: verify() logic
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# Ensure project root is on path
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanner.scan_plugins.detectors.forbidden_bypass_detector import ForbiddenBypassDetectorPlugin
from scanner.plugins.exploits.forbidden_bypass_plugin import ForbiddenBypassPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_resp(status_code: int, text: str = '', headers: dict = None):
    """Return a minimal mock requests.Response."""
    m = MagicMock()
    m.status_code = status_code
    m.text = text
    m.headers = headers or {}
    return m


_TARGET = 'http://example.com/admin'
_TARGET_GENERIC = 'http://example.com/secret'


# ---------------------------------------------------------------------------
# Detector: property tests
# ---------------------------------------------------------------------------


class TestForbiddenBypassDetectorProperties(unittest.TestCase):
    """Smoke-tests for plugin metadata."""

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'forbidden_bypass_detector')

    def test_name_contains_403(self):
        self.assertIn('403', self.plugin.name)

    def test_description_contains_bypass(self):
        self.assertIn('bypass', self.plugin.description.lower())

    def test_version_is_string(self):
        self.assertIsInstance(self.plugin.version, str)
        self.assertTrue(self.plugin.version)

    def test_vulnerability_types(self):
        vt = self.plugin.vulnerability_types
        self.assertIn('forbidden_bypass', vt)

    def test_default_config_has_timeout(self):
        cfg = self.plugin.get_default_config()
        self.assertIn('timeout', cfg)

    def test_default_config_categories_enabled(self):
        cfg = self.plugin.get_default_config()
        self.assertTrue(cfg.get('check_method_tampering'))
        self.assertTrue(cfg.get('check_header_bypass'))
        self.assertTrue(cfg.get('check_path_manipulation'))


# ---------------------------------------------------------------------------
# Detector: baseline behaviour (non-403 → skip)
# ---------------------------------------------------------------------------


class TestForbiddenBypassDetectorBaseline(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_200_response_produces_no_findings(self, mock_get):
        """A 200 response means the URL is accessible – nothing to bypass."""
        mock_get.return_value = _mock_resp(200)
        findings = self.plugin.scan(_TARGET)
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_404_response_produces_no_findings(self, mock_get):
        mock_get.return_value = _mock_resp(404)
        findings = self.plugin.scan(_TARGET)
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_baseline_network_error_returns_empty(self, mock_get):
        """Network failure on baseline request → graceful empty list."""
        import requests as req
        mock_get.side_effect = req.RequestException("connection refused")
        findings = self.plugin.scan(_TARGET)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Detector: method tampering category
# ---------------------------------------------------------------------------


class TestMethodTampering(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_post_bypass_produces_finding(self, mock_get, mock_request):
        """GET → 403, POST → 200 should produce a finding."""
        # Baseline GET returns 403
        mock_get.return_value = _mock_resp(403)
        # POST returns 200; all other requests return 403
        def request_side_effect(method, url, **kwargs):
            if method == 'POST':
                return _mock_resp(200, text='admin panel')
            return _mock_resp(403)
        mock_request.side_effect = request_side_effect

        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': True,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )

        self.assertTrue(len(findings) >= 1)
        techniques = [f.description for f in findings]
        self.assertTrue(any('POST' in t for t in techniques))

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_method_tampering_finding_has_correct_cwe(self, mock_get, mock_request):
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = lambda method, url, **kw: (
            _mock_resp(200) if method == 'POST' else _mock_resp(403)
        )
        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': True,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertTrue(findings)
        self.assertEqual(findings[0].cwe_id, 'CWE-284')


# ---------------------------------------------------------------------------
# Detector: path manipulation category
# ---------------------------------------------------------------------------


class TestPathManipulation(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_double_dot_semicolon_bypass_produces_finding(self, mock_get):
        """GET /admin → 403, GET /admin..;/ → 200 should produce a finding."""
        def get_side_effect(url, **kwargs):
            if url.endswith('..;/') or 'admin..;' in url:
                return _mock_resp(200, text='admin home')
            return _mock_resp(403)

        mock_get.side_effect = get_side_effect

        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': False,
                'check_path_manipulation': True,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )

        self.assertTrue(len(findings) >= 1)
        self.assertTrue(any('Path manipulation' in f.description for f in findings))

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_path_finding_severity_for_admin_path(self, mock_get):
        """Findings on /admin should have critical severity."""
        def get_side_effect(url, **kwargs):
            if url != _TARGET:
                return _mock_resp(200)
            return _mock_resp(403)

        mock_get.side_effect = get_side_effect

        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': False,
                'check_path_manipulation': True,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )

        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, 'critical')

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_path_finding_severity_for_sensitive_path(self, mock_get):
        """Findings on /api path → high severity."""
        api_target = 'http://example.com/api/v1'

        def get_side_effect(url, **kwargs):
            if url == api_target:
                return _mock_resp(403)
            return _mock_resp(200)

        mock_get.side_effect = get_side_effect

        findings = self.plugin.scan(
            api_target,
            config={
                'check_method_tampering': False,
                'check_path_manipulation': True,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )

        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, 'high')


# ---------------------------------------------------------------------------
# Detector: header bypass category
# ---------------------------------------------------------------------------


class TestHeaderBypass(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_x_original_url_bypass_produces_finding(self, mock_get, mock_request):
        """GET without headers → 403, GET with X-Original-URL → 200 = finding."""
        mock_get.return_value = _mock_resp(403)

        def request_side_effect(method, url, headers=None, **kwargs):
            if headers and 'X-Original-URL' in headers:
                return _mock_resp(200, text='bypassed')
            return _mock_resp(403)

        mock_request.side_effect = request_side_effect

        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': False,
                'check_path_manipulation': False,
                'check_header_bypass': True,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )

        self.assertTrue(len(findings) >= 1)
        self.assertTrue(any('X-Original-URL' in f.description for f in findings))

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_header_finding_has_remediation(self, mock_get, mock_request):
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = lambda method, url, headers=None, **kw: (
            _mock_resp(200) if (headers and 'X-Forwarded-For' in headers) else _mock_resp(403)
        )
        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': False,
                'check_path_manipulation': False,
                'check_header_bypass': True,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertTrue(findings)
        self.assertIn('access control', findings[0].remediation.lower())


# ---------------------------------------------------------------------------
# Detector: no bypass found
# ---------------------------------------------------------------------------


class TestNoBypassFound(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_all_403_returns_empty_findings(self, mock_get, mock_request):
        """When every attempt returns 403, findings list must be empty."""
        mock_get.return_value = _mock_resp(403)
        mock_request.return_value = _mock_resp(403)

        findings = self.plugin.scan(_TARGET)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Detector: network errors
# ---------------------------------------------------------------------------


class TestNetworkErrors(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_network_errors_in_category_do_not_crash(self, mock_get, mock_request):
        """Connection errors during bypass attempts should be swallowed."""
        import requests as req
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = req.RequestException("timeout")

        findings = self.plugin.scan(_TARGET)
        self.assertEqual(findings, [])  # no crash, just no findings

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_mixed_network_errors_and_success(self, mock_get, mock_request):
        """Partial network errors should not prevent recording successful bypasses."""
        import requests as req

        # Baseline returns 403
        mock_get.return_value = _mock_resp(403)

        call_count = [0]

        def request_side_effect(method, url, **kwargs):
            call_count[0] += 1
            # First call raises; second call succeeds
            if call_count[0] == 1:
                raise req.RequestException("timeout")
            if method == 'PUT':
                return _mock_resp(200)
            return _mock_resp(403)

        mock_request.side_effect = request_side_effect

        # Only enable method tampering to keep the test focused
        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': True,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        # Should have found PUT bypass, error on first call should be swallowed
        self.assertTrue(len(findings) >= 1)


# ---------------------------------------------------------------------------
# Detector: config options
# ---------------------------------------------------------------------------


class TestConfigOptions(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_disable_method_tampering_skips_category(self, mock_get, mock_request):
        """Disabling method tampering should produce no method-tampering findings."""
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = lambda method, url, **kw: _mock_resp(200)

        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': False,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertEqual(findings, [])
        mock_request.assert_not_called()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_disable_header_bypass_skips_header_checks(self, mock_get, mock_request):
        """Disabling header bypass should not produce header-bypass findings."""
        mock_get.return_value = _mock_resp(403)
        # All requests succeed – if headers are tried, findings would appear
        mock_request.return_value = _mock_resp(200)

        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': False,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Detector: finding quality
# ---------------------------------------------------------------------------


class TestFindingQuality(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_finding_evidence_contains_technique(self, mock_get, mock_request):
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = lambda method, url, **kw: (
            _mock_resp(200) if method == 'DELETE' else _mock_resp(403)
        )
        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': True,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertTrue(findings)
        self.assertIn('DELETE', findings[0].evidence)

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_medium_severity_for_generic_path(self, mock_get, mock_request):
        """Paths without admin/sensitive keywords → medium severity."""
        generic_url = 'http://example.com/data'
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = lambda method, url, **kw: (
            _mock_resp(200) if method == 'POST' else _mock_resp(403)
        )
        findings = self.plugin.scan(
            generic_url,
            config={
                'check_method_tampering': True,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, 'medium')

    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.request')
    @patch('scanner.scan_plugins.detectors.forbidden_bypass_detector.requests.get')
    def test_finding_confidence_is_high(self, mock_get, mock_request):
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = lambda method, url, **kw: (
            _mock_resp(200) if method == 'POST' else _mock_resp(403)
        )
        findings = self.plugin.scan(
            _TARGET,
            config={
                'check_method_tampering': True,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertTrue(findings)
        self.assertGreaterEqual(findings[0].confidence, 0.8)


# ---------------------------------------------------------------------------
# Exploit plugin: metadata
# ---------------------------------------------------------------------------


class TestForbiddenBypassPluginProperties(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassPlugin()

    def test_vulnerability_type(self):
        self.assertEqual(self.plugin.vulnerability_type, 'forbidden_bypass')

    def test_name_contains_bypass(self):
        self.assertIn('Bypass', self.plugin.name)

    def test_description(self):
        self.assertIn('bypass', self.plugin.description.lower())

    def test_version(self):
        self.assertIsInstance(self.plugin.version, str)

    def test_generate_payloads(self):
        payloads = self.plugin.generate_payloads()
        self.assertIsInstance(payloads, list)
        self.assertTrue(len(payloads) > 0)


# ---------------------------------------------------------------------------
# Exploit plugin: execute_attack
# ---------------------------------------------------------------------------


class TestForbiddenBypassPluginExecuteAttack(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassPlugin()

    @patch('scanner.plugins.exploits.forbidden_bypass_plugin.requests.request')
    @patch('scanner.plugins.exploits.forbidden_bypass_plugin.requests.get')
    def test_success_when_post_bypasses(self, mock_get, mock_request):
        """POST returning 200 after GET 403 → success=True with finding."""
        mock_get.return_value = _mock_resp(403)
        mock_request.side_effect = lambda method, url, **kw: (
            _mock_resp(200, text='admin') if method == 'POST' else _mock_resp(403)
        )
        result = self.plugin.execute_attack(
            _TARGET,
            {'confirmed_403': True},
            config={
                'check_method_tampering': True,
                'check_path_manipulation': False,
                'check_header_bypass': False,
                'check_protocol_tricks': False,
                'check_proxy_chain': False,
                'check_service_mesh': False,
            },
        )
        self.assertTrue(result['success'])
        self.assertIn('findings', result)
        self.assertTrue(len(result['findings']) >= 1)

    @patch('scanner.plugins.exploits.forbidden_bypass_plugin.requests.request')
    @patch('scanner.plugins.exploits.forbidden_bypass_plugin.requests.get')
    def test_failure_when_all_return_403(self, mock_get, mock_request):
        mock_get.return_value = _mock_resp(403)
        mock_request.return_value = _mock_resp(403)
        result = self.plugin.execute_attack(
            _TARGET,
            {'confirmed_403': True},
        )
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_no_requests_library_returns_error(self):
        import scanner.plugins.exploits.forbidden_bypass_plugin as mod
        original = mod.HAS_REQUESTS
        try:
            mod.HAS_REQUESTS = False
            result = self.plugin.execute_attack(_TARGET, {})
            self.assertFalse(result['success'])
            self.assertIn('error', result)
        finally:
            mod.HAS_REQUESTS = original

    @patch('scanner.plugins.exploits.forbidden_bypass_plugin.requests.get')
    def test_baseline_403_check_when_not_confirmed(self, mock_get):
        """When confirmed_403=False, plugin should verify 403 first."""
        mock_get.return_value = _mock_resp(200)  # returns 200, not 403
        result = self.plugin.execute_attack(_TARGET, {'confirmed_403': False})
        self.assertFalse(result['success'])
        self.assertIn('200', result.get('error', ''))


# ---------------------------------------------------------------------------
# Exploit plugin: verify
# ---------------------------------------------------------------------------


class TestForbiddenBypassPluginVerify(unittest.TestCase):

    def setUp(self):
        self.plugin = ForbiddenBypassPlugin()

    def test_verify_success_with_findings(self):
        result = {
            'success': True,
            'findings': [{'technique': 'POST method', 'status_code': 200}],
            'evidence': 'bypass confirmed',
        }
        verified, proof = self.plugin.verify(result, _TARGET, {})
        self.assertTrue(verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)

    def test_verify_failure_when_success_false(self):
        result = {'success': False}
        verified, proof = self.plugin.verify(result, _TARGET, {})
        self.assertFalse(verified)
        self.assertIsNone(proof)

    def test_verify_failure_when_no_findings(self):
        result = {'success': True, 'findings': [], 'evidence': ''}
        verified, proof = self.plugin.verify(result, _TARGET, {})
        self.assertFalse(verified)


if __name__ == '__main__':
    unittest.main()
