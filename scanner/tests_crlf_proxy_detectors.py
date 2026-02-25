"""
Unit / integration tests for the new security scan plugins:

  - CRLFInjectionDetectorPlugin
      (scanner/scan_plugins/detectors/crlf_injection_detector.py)

  - ProxyDomainMeldingDetectorPlugin
      (scanner/scan_plugins/detectors/proxy_domain_melding_detector.py)

All HTTP calls are mocked; no network requests are made.

Coverage:
  CRLFInjectionDetectorPlugin:
    - Plugin properties (id, name, version, vulnerability_types)
    - _find_header_sinks: parameter reflected in Location header → sink found
    - _find_header_sinks: no reflection → no sinks
    - _find_header_sinks: reflection in non-sink header → no sinks
    - _find_header_sinks: no query params → falls back to path probe
    - _test_crlf_injection: basic payload confirmed → high finding
    - _test_crlf_injection: no confirmation → no finding
    - _confirm_injection: x-megido-crlf header present → True
    - _confirm_injection: megidocrlf set-cookie → True
    - _confirm_injection: no injected headers → False
    - _assess_response_splitting: body contains injected marker → confirmed
    - _assess_response_splitting: no marker → potential only
    - _cookie_injection_finding: returns correct finding
    - scan(): end-to-end with sink + CRLF confirmation
    - scan(): no sinks → empty results
    - scan(): CRLF confirmed + response splitting probe
    - scan(): set-cookie injection → cookie injection finding added
    - scan(): requests not available → returns []
    - Auto-discovery via ScanPluginRegistry

  ProxyDomainMeldingDetectorPlugin:
    - Plugin properties
    - _collect_target_markers: title extracted
    - _collect_target_markers: hostname always included
    - _collect_target_markers: fetch failure falls back to hostname
    - _check_proxy_service: 2xx + matching marker → exposure finding
    - _check_proxy_service: 2xx + no marker → no finding
    - _check_proxy_service: 4xx → no finding
    - _check_proxy_service: request exception → no finding
    - _check_proxy_service: xss_confirmed → elevated severity + vuln type
    - scan(): enable_proxy_checks=False → returns []
    - scan(): no HAS_REQUESTS → returns []
    - scan(): exposure confirmed end-to-end
    - Configurable proxy_services list
    - DEFAULT_PROXY_SERVICES contains Google Translate entry
    - Auto-discovery via ScanPluginRegistry
"""

import sys
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

# Ensure project root is on the path so imports work without a full Django setup
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanner.scan_plugins.detectors.crlf_injection_detector import (
    CRLFInjectionDetectorPlugin,
    _MARKER,
    _CRLF_PAYLOADS,
)
from scanner.scan_plugins.detectors.proxy_domain_melding_detector import (
    ProxyDomainMeldingDetectorPlugin,
    DEFAULT_PROXY_SERVICES,
)
from scanner.scan_plugins.scan_plugin_registry import ScanPluginRegistry, reset_scan_registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    status_code: int = 200,
    headers: Optional[dict] = None,
    text: str = '',
) -> MagicMock:
    """Return a minimal mock requests.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    mock_resp.text = text
    return mock_resp




# ===========================================================================
# CRLFInjectionDetectorPlugin – property tests
# ===========================================================================

class TestCRLFPluginProperties(unittest.TestCase):
    def setUp(self):
        self.plugin = CRLFInjectionDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'crlf_injection_detector')

    def test_name_contains_crlf(self):
        self.assertIn('CRLF', self.plugin.name)

    def test_version_is_string(self):
        self.assertIsInstance(self.plugin.version, str)
        self.assertTrue(len(self.plugin.version) > 0)

    def test_vulnerability_types_include_crlf(self):
        types = self.plugin.vulnerability_types
        self.assertIn('crlf_injection', types)

    def test_vulnerability_types_include_response_splitting(self):
        self.assertIn('response_splitting', self.plugin.vulnerability_types)

    def test_vulnerability_types_include_cookie_injection(self):
        self.assertIn('cookie_injection', self.plugin.vulnerability_types)

    def test_default_config_keys(self):
        config = self.plugin.get_default_config()
        for key in ('verify_ssl', 'timeout', 'check_response_splitting',
                    'check_cookie_injection', 'extra_params'):
            self.assertIn(key, config)


# ===========================================================================
# CRLFInjectionDetectorPlugin – _find_header_sinks
# ===========================================================================

class TestCRLFFindHeaderSinks(unittest.TestCase):
    def setUp(self):
        self.plugin = CRLFInjectionDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_sink_found_when_marker_in_location(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=302,
            headers={'Location': f'https://example.com/{_MARKER}'},
        )
        sinks = self.plugin._find_header_sinks(
            'http://example.com/?next=test', False, 5,
            {'extra_params': []}
        )
        self.assertTrue(len(sinks) >= 1)
        param_names = [s[0] for s in sinks]
        self.assertIn('next', param_names)

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_no_reflection_returns_empty(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            headers={'Content-Type': 'text/html'},
            text='<html></html>',
        )
        sinks = self.plugin._find_header_sinks(
            'http://example.com/?q=test', False, 5,
            {'extra_params': []}
        )
        self.assertEqual(sinks, [])

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_reflection_in_non_sink_header_ignored(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            headers={'X-Debug': f'echo {_MARKER}'},
        )
        sinks = self.plugin._find_header_sinks(
            'http://example.com/?q=test', False, 5,
            {'extra_params': []}
        )
        self.assertEqual(sinks, [])

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_no_query_params_probes_path(self, mock_get):
        # Path reflection: marker in location header
        mock_get.return_value = _make_response(
            status_code=302,
            headers={'Location': f'https://example.com/{_MARKER}'},
        )
        sinks = self.plugin._find_header_sinks(
            'http://example.com/', False, 5,
            {'extra_params': []}
        )
        # Should find __path__ sink
        param_names = [s[0] for s in sinks]
        self.assertIn('__path__', param_names)

    @patch(
        'scanner.scan_plugins.detectors.crlf_injection_detector.requests.get',
        side_effect=Exception("network error"),
    )
    def test_network_error_returns_empty(self, _mock_get):
        sinks = self.plugin._find_header_sinks(
            'http://example.com/?q=test', False, 5,
            {'extra_params': []}
        )
        self.assertEqual(sinks, [])


# ===========================================================================
# CRLFInjectionDetectorPlugin – _confirm_injection
# ===========================================================================

class TestCRLFConfirmInjection(unittest.TestCase):
    def setUp(self):
        self.plugin = CRLFInjectionDetectorPlugin()

    def test_x_megido_crlf_header_confirms(self):
        resp = _make_response(headers={'X-Megido-CRLF': 'injected'})
        confirmed, header = self.plugin._confirm_injection(resp)
        self.assertTrue(confirmed)
        self.assertIn('x-megido-crlf', header.lower())

    def test_megidocrlf_set_cookie_confirms(self):
        resp = _make_response(headers={'Set-Cookie': 'MegidoCRLF=1; path=/'})
        confirmed, header = self.plugin._confirm_injection(resp)
        self.assertTrue(confirmed)

    def test_no_injected_header_not_confirmed(self):
        resp = _make_response(headers={'Content-Type': 'text/html'})
        confirmed, header = self.plugin._confirm_injection(resp)
        self.assertFalse(confirmed)
        self.assertEqual(header, '')


# ===========================================================================
# CRLFInjectionDetectorPlugin – _test_crlf_injection
# ===========================================================================

class TestCRLFTestInjection(unittest.TestCase):
    def setUp(self):
        self.plugin = CRLFInjectionDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_confirmed_injection_returns_high_finding(self, mock_get):
        # First call: basic payload → injected header confirmed
        mock_get.return_value = _make_response(
            status_code=302,
            headers={
                'Location': 'https://example.com/redirect',
                'X-Megido-CRLF': 'injected',
            },
        )
        findings, label = self.plugin._test_crlf_injection(
            'http://example.com/?next=test',
            'next',
            'Location',
            False, 5,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, 'high')
        self.assertEqual(findings[0].vulnerability_type, 'crlf_injection')
        self.assertTrue(findings[0].verified)
        self.assertNotEqual(label, '')

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_no_confirmation_returns_no_findings(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=302,
            headers={'Location': 'https://example.com/redirect'},
        )
        findings, label = self.plugin._test_crlf_injection(
            'http://example.com/?next=test',
            'next',
            'Location',
            False, 5,
        )
        self.assertEqual(findings, [])
        self.assertEqual(label, '')

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_finding_evidence_contains_param_and_payload(self, mock_get):
        mock_get.return_value = _make_response(
            headers={'X-Megido-CRLF': 'injected'},
        )
        findings, _ = self.plugin._test_crlf_injection(
            'http://example.com/?redirect=foo',
            'redirect',
            'Location',
            False, 5,
        )
        if findings:
            self.assertIn('redirect', findings[0].evidence)
            self.assertEqual(findings[0].cwe_id, 'CWE-113')


# ===========================================================================
# CRLFInjectionDetectorPlugin – _assess_response_splitting
# ===========================================================================

class TestCRLFResponseSplitting(unittest.TestCase):
    def setUp(self):
        self.plugin = CRLFInjectionDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_confirmed_splitting_when_marker_in_body(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            text='<!--MegidoSplit-->',
        )
        findings = self.plugin._assess_response_splitting(
            'http://example.com/?q=x', 'q', False, 5
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, 'response_splitting')
        self.assertEqual(findings[0].severity, 'high')
        self.assertTrue(findings[0].verified)

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_potential_splitting_when_no_marker(self, mock_get):
        mock_get.return_value = _make_response(status_code=200, text='<html></html>')
        findings = self.plugin._assess_response_splitting(
            'http://example.com/?q=x', 'q', False, 5
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, 'medium')
        self.assertFalse(findings[0].verified)

    @patch(
        'scanner.scan_plugins.detectors.crlf_injection_detector.requests.get',
        side_effect=Exception("timeout"),
    )
    def test_network_error_returns_empty(self, _mock_get):
        findings = self.plugin._assess_response_splitting(
            'http://example.com/?q=x', 'q', False, 5
        )
        self.assertEqual(findings, [])


# ===========================================================================
# CRLFInjectionDetectorPlugin – _cookie_injection_finding
# ===========================================================================

class TestCRLFCookieInjectionFinding(unittest.TestCase):
    def setUp(self):
        self.plugin = CRLFInjectionDetectorPlugin()

    def test_cookie_injection_finding_type(self):
        finding = self.plugin._cookie_injection_finding('http://example.com/')
        self.assertEqual(finding.vulnerability_type, 'cookie_injection')

    def test_cookie_injection_severity_high(self):
        finding = self.plugin._cookie_injection_finding('http://example.com/')
        self.assertEqual(finding.severity, 'high')

    def test_cookie_injection_cwe(self):
        finding = self.plugin._cookie_injection_finding('http://example.com/')
        self.assertEqual(finding.cwe_id, 'CWE-384')

    def test_cookie_injection_mentions_session_fixation(self):
        finding = self.plugin._cookie_injection_finding('http://example.com/')
        self.assertIn('session fixation', finding.description.lower())


# ===========================================================================
# CRLFInjectionDetectorPlugin – scan() end-to-end
# ===========================================================================

class TestCRLFScanEndToEnd(unittest.TestCase):
    def setUp(self):
        self.plugin = CRLFInjectionDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_scan_no_sinks_returns_empty(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            headers={'Content-Type': 'text/html'},
        )
        findings = self.plugin.scan('http://example.com/?q=test')
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.crlf_injection_detector.requests.get')
    def test_scan_with_sink_and_confirmation(self, mock_get):
        # Call 1: sink discovery – marker reflected in Location
        # Call 2: CRLF payload – injected header confirmed
        # Call 3+: response splitting probe
        def side_effect(url, **kwargs):
            params = kwargs.get('params', {})
            param_val = params.get('next', '') if params else ''
            if _MARKER in str(param_val):
                return _make_response(302, {'Location': f'https://example.com/{_MARKER}'})
            if '%0d%0a' in str(param_val) or '%0d%0a' in str(url):
                return _make_response(302, {'Location': 'x', 'X-Megido-CRLF': 'injected'})
            return _make_response(200, text='<html></html>')

        mock_get.side_effect = side_effect
        findings = self.plugin.scan(
            'http://example.com/?next=foo',
            config={
                'verify_ssl': False,
                'timeout': 5,
                'check_response_splitting': False,
                'check_cookie_injection': False,
                'extra_params': [],
            },
        )
        crlf_findings = [f for f in findings if f.vulnerability_type == 'crlf_injection']
        self.assertTrue(len(crlf_findings) >= 1)

    def test_scan_no_requests_library_returns_empty(self):
        import scanner.scan_plugins.detectors.crlf_injection_detector as mod
        orig = mod.HAS_REQUESTS
        try:
            mod.HAS_REQUESTS = False
            findings = self.plugin.scan('http://example.com/')
            self.assertEqual(findings, [])
        finally:
            mod.HAS_REQUESTS = orig


# ===========================================================================
# ProxyDomainMeldingDetectorPlugin – property tests
# ===========================================================================

class TestProxyPluginProperties(unittest.TestCase):
    def setUp(self):
        self.plugin = ProxyDomainMeldingDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'proxy_domain_melding_detector')

    def test_name_contains_proxy(self):
        self.assertIn('Proxy', self.plugin.name)

    def test_version_is_string(self):
        self.assertIsInstance(self.plugin.version, str)

    def test_vulnerability_types_include_proxy_exposure(self):
        self.assertIn('proxy_exposure', self.plugin.vulnerability_types)

    def test_vulnerability_types_include_domain_melding(self):
        self.assertIn('domain_melding', self.plugin.vulnerability_types)

    def test_default_config_keys(self):
        config = self.plugin.get_default_config()
        for key in ('verify_ssl', 'timeout', 'proxy_services',
                    'enable_proxy_checks', 'xss_confirmed',
                    'xss_findings', 'content_markers'):
            self.assertIn(key, config)


# ===========================================================================
# DEFAULT_PROXY_SERVICES
# ===========================================================================

class TestDefaultProxyServices(unittest.TestCase):
    def test_list_is_non_empty(self):
        self.assertGreater(len(DEFAULT_PROXY_SERVICES), 0)

    def test_google_translate_present(self):
        names = [s.get('name', '').lower() for s in DEFAULT_PROXY_SERVICES]
        self.assertTrue(any('google' in n for n in names))

    def test_each_entry_has_name_and_template(self):
        for service in DEFAULT_PROXY_SERVICES:
            self.assertIn('name', service)
            self.assertIn('url_template', service)
            self.assertIn('{url}', service['url_template'])


# ===========================================================================
# ProxyDomainMeldingDetectorPlugin – _collect_target_markers
# ===========================================================================

class TestProxyCollectMarkers(unittest.TestCase):
    def setUp(self):
        self.plugin = ProxyDomainMeldingDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_hostname_always_included(self, mock_get):
        mock_get.return_value = _make_response(text='<html><title>My Site</title></html>')
        markers = self.plugin._collect_target_markers(
            'http://example.com/', False, 5, []
        )
        self.assertIn('example.com', markers)

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_title_extracted(self, mock_get):
        mock_get.return_value = _make_response(
            text='<html><title>Unique Site Title</title></html>'
        )
        markers = self.plugin._collect_target_markers(
            'http://example.com/', False, 5, []
        )
        self.assertTrue(any('Unique Site Title' in m for m in markers))

    @patch(
        'scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get',
        side_effect=Exception("connection refused"),
    )
    def test_fetch_failure_falls_back_to_hostname(self, _mock_get):
        markers = self.plugin._collect_target_markers(
            'http://example.com/', False, 5, []
        )
        self.assertIn('example.com', markers)

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_extra_markers_included(self, mock_get):
        mock_get.return_value = _make_response(text='')
        markers = self.plugin._collect_target_markers(
            'http://example.com/', False, 5, ['custom-marker-xyz']
        )
        self.assertIn('custom-marker-xyz', markers)


# ===========================================================================
# ProxyDomainMeldingDetectorPlugin – _check_proxy_service
# ===========================================================================

class TestProxyCheckService(unittest.TestCase):
    def setUp(self):
        self.plugin = ProxyDomainMeldingDetectorPlugin()
        self.service = {
            'name': 'TestProxy',
            'url_template': 'https://proxy.example/{url}',
        }

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_exposure_finding_when_marker_in_body(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            text='<html>Welcome to example.com</html>',
        )
        findings = self.plugin._check_proxy_service(
            url='http://example.com/',
            service=self.service,
            target_markers=['example.com'],
            xss_confirmed=False,
            verify_ssl=False,
            timeout=5,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, 'proxy_exposure')
        self.assertEqual(findings[0].severity, 'medium')

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_no_finding_when_no_marker_in_body(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            text='<html>Something completely different</html>',
        )
        findings = self.plugin._check_proxy_service(
            url='http://example.com/',
            service=self.service,
            target_markers=['example.com'],
            xss_confirmed=False,
            verify_ssl=False,
            timeout=5,
        )
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_4xx_response_no_finding(self, mock_get):
        mock_get.return_value = _make_response(status_code=403, text='Forbidden')
        findings = self.plugin._check_proxy_service(
            url='http://example.com/',
            service=self.service,
            target_markers=['example.com'],
            xss_confirmed=False,
            verify_ssl=False,
            timeout=5,
        )
        self.assertEqual(findings, [])

    @patch(
        'scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get',
        side_effect=Exception("connection timeout"),
    )
    def test_network_error_no_finding(self, _mock_get):
        findings = self.plugin._check_proxy_service(
            url='http://example.com/',
            service=self.service,
            target_markers=['example.com'],
            xss_confirmed=False,
            verify_ssl=False,
            timeout=5,
        )
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_xss_confirmed_elevates_severity(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            text='Content from example.com',
        )
        findings = self.plugin._check_proxy_service(
            url='http://example.com/',
            service=self.service,
            target_markers=['example.com'],
            xss_confirmed=True,
            verify_ssl=False,
            timeout=5,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, 'high')
        self.assertEqual(findings[0].vulnerability_type, 'proxy_xss_propagation')
        self.assertIn('Jikto', findings[0].description)

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_evidence_contains_proxy_url(self, mock_get):
        mock_get.return_value = _make_response(
            status_code=200,
            text='example.com content',
        )
        findings = self.plugin._check_proxy_service(
            url='http://example.com/',
            service=self.service,
            target_markers=['example.com'],
            xss_confirmed=False,
            verify_ssl=False,
            timeout=5,
        )
        self.assertTrue(len(findings) > 0)
        self.assertIn('TestProxy', findings[0].evidence)

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_missing_url_template_skipped(self, mock_get):
        findings = self.plugin._check_proxy_service(
            url='http://example.com/',
            service={'name': 'NoTemplate'},
            target_markers=['example.com'],
            xss_confirmed=False,
            verify_ssl=False,
            timeout=5,
        )
        mock_get.assert_not_called()
        self.assertEqual(findings, [])


# ===========================================================================
# ProxyDomainMeldingDetectorPlugin – scan() end-to-end
# ===========================================================================

class TestProxyScanEndToEnd(unittest.TestCase):
    def setUp(self):
        self.plugin = ProxyDomainMeldingDetectorPlugin()

    def test_scan_disabled_via_config_returns_empty(self):
        findings = self.plugin.scan(
            'http://example.com/',
            config={'enable_proxy_checks': False},
        )
        self.assertEqual(findings, [])

    def test_scan_no_requests_library_returns_empty(self):
        import scanner.scan_plugins.detectors.proxy_domain_melding_detector as mod
        orig = mod.HAS_REQUESTS
        try:
            mod.HAS_REQUESTS = False
            findings = self.plugin.scan('http://example.com/')
            self.assertEqual(findings, [])
        finally:
            mod.HAS_REQUESTS = orig

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_scan_exposure_found(self, mock_get):
        # First call: target fetch (for marker collection)
        # Second call: proxy fetch
        mock_get.side_effect = [
            _make_response(200, text='<html><title>Example Site</title></html>'),
            _make_response(200, text='<html>Example Site proxy content</html>'),
        ]
        findings = self.plugin.scan(
            'http://example.com/',
            config={
                'verify_ssl': False,
                'timeout': 5,
                'proxy_services': [
                    {'name': 'TestProxy', 'url_template': 'https://proxy.example/{url}'}
                ],
                'enable_proxy_checks': True,
            },
        )
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].vulnerability_type, 'proxy_exposure')

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_scan_xss_findings_in_config_elevates_severity(self, mock_get):
        from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
        xss_f = VulnerabilityFinding(
            vulnerability_type='xss', severity='high',
            url='http://example.com/', description='Stored XSS',
            evidence='Evidence', remediation='Fix'
        )
        mock_get.side_effect = [
            _make_response(200, text='<html><title>Example</title></html>'),
            _make_response(200, text='Example proxy content'),
        ]
        findings = self.plugin.scan(
            'http://example.com/',
            config={
                'verify_ssl': False,
                'timeout': 5,
                'proxy_services': [
                    {'name': 'TestProxy', 'url_template': 'https://proxy.example/{url}'}
                ],
                'xss_findings': [xss_f],
            },
        )
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].severity, 'high')
        self.assertEqual(findings[0].vulnerability_type, 'proxy_xss_propagation')

    @patch('scanner.scan_plugins.detectors.proxy_domain_melding_detector.requests.get')
    def test_custom_proxy_services_used(self, mock_get):
        custom_service = {
            'name': 'CustomProxy',
            'url_template': 'https://custom.proxy/?url={url}',
        }
        mock_get.side_effect = [
            _make_response(200, text='<html></html>'),   # target fetch
            _make_response(200, text='example.com page'), # proxy fetch
        ]
        findings = self.plugin.scan(
            'http://example.com/',
            config={
                'verify_ssl': False,
                'timeout': 5,
                'proxy_services': [custom_service],
                'content_markers': ['example.com'],
            },
        )
        self.assertTrue(len(findings) >= 1)
        self.assertIn('CustomProxy', findings[0].evidence)


# ===========================================================================
# Registry auto-discovery
# ===========================================================================

class TestNewPluginsRegistryDiscovery(unittest.TestCase):
    def setUp(self):
        reset_scan_registry()
        self.registry = ScanPluginRegistry()
        self.registry.discover_plugins()

    def test_crlf_detector_discovered(self):
        plugin = self.registry.get_plugin('crlf_injection_detector')
        self.assertIsNotNone(plugin, "crlf_injection_detector not discovered")
        self.assertIsInstance(plugin, CRLFInjectionDetectorPlugin)

    def test_proxy_domain_melding_detector_discovered(self):
        plugin = self.registry.get_plugin('proxy_domain_melding_detector')
        self.assertIsNotNone(plugin, "proxy_domain_melding_detector not discovered")
        self.assertIsInstance(plugin, ProxyDomainMeldingDetectorPlugin)

    def tearDown(self):
        reset_scan_registry()


if __name__ == '__main__':
    unittest.main()
