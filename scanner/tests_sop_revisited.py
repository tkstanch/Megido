"""
Unit tests for the Same-Origin Policy Revisited scan plugins:

  - FlashCrossdomainDetectorPlugin    (scanner/scan_plugins/detectors/flash_crossdomain_detector.py)
  - SilverlightClientAccessDetectorPlugin (scanner/scan_plugins/detectors/silverlight_clientaccess_detector.py)
  - CORSScannerPlugin (enhanced)      (scanner/scan_plugins/detectors/cors_scanner.py)

Covers:
  Flash crossdomain.xml:
    - Wildcard domain="*"             → critical finding
    - Wildcard subdomain *.example.com → high finding
    - Benign explicit domain          → no finding
    - site-control with "all"         → medium finding
    - site-control with "master-only" → no finding
    - Internal IP in domain           → informational finding
    - Broad allowlist (many entries)  → informational finding
    - Missing / non-200 response      → no finding
    - Malformed XML                   → no finding (graceful)
    - Plugin auto-discovery via registry

  Silverlight clientaccesspolicy.xml:
    - Wildcard domain uri="*"         → critical finding
    - Wildcard subdomain *.example.com → high finding
    - http-request-headers="*"        → medium finding
    - Benign policy                   → no finding
    - Missing policy (404)            → informational fallback note
    - Malformed XML                   → no finding (graceful)
    - Plugin auto-discovery via registry

  CORS scanner (enhanced CORSScannerPlugin):
    - ACAO: * without credentials     → medium finding
    - ACAO: * with ACAC: true         → high finding
    - Origin reflection without creds → high finding
    - Origin reflection with ACAC     → critical finding
    - Origin reflection missing Vary  → additional low finding
    - No CORS headers                 → no finding
    - _lookalike_origin helper
    - Preflight: risky methods        → medium finding
    - Preflight: wildcard headers     → medium finding
    - Preflight: no CORS headers      → no finding
    - Plugin auto-discovery via registry
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# Ensure project root is on the path so imports work without a full Django setup.
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanner.scan_plugins.detectors.flash_crossdomain_detector import (
    FlashCrossdomainDetectorPlugin,
    _PRIVATE_IP_RE,
)
from scanner.scan_plugins.detectors.silverlight_clientaccess_detector import (
    SilverlightClientAccessDetectorPlugin,
)
from scanner.scan_plugins.detectors.cors_scanner import CORSScannerPlugin
from scanner.scan_plugins.scan_plugin_registry import ScanPluginRegistry, reset_scan_registry

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / 'tests' / 'fixtures'


def _load_fixture(name: str) -> str:
    return (_FIXTURES_DIR / name).read_text(encoding='utf-8')


def _make_response(body: str, status_code: int = 200, content_type: str = 'text/xml'):
    """Return a minimal mock requests.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = {'Content-Type': content_type}
    mock_resp.text = body
    return mock_resp


def _make_get_response(headers: dict, status_code: int = 200):
    """Return a mock requests.Response with arbitrary response headers."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers
    mock_resp.text = ''
    return mock_resp


# ===========================================================================
# Flash crossdomain.xml tests
# ===========================================================================

class TestFlashCrossdomainDetectorProperties(unittest.TestCase):
    def setUp(self):
        self.plugin = FlashCrossdomainDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'flash_crossdomain_detector')

    def test_name_contains_flash(self):
        self.assertIn('Flash', self.plugin.name)

    def test_description_mentions_crossdomain(self):
        self.assertIn('crossdomain', self.plugin.description.lower())

    def test_vulnerability_types(self):
        self.assertIn('cors', self.plugin.vulnerability_types)

    def test_version_string(self):
        self.assertIsInstance(self.plugin.version, str)
        self.assertTrue(len(self.plugin.version) > 0)


class TestFlashPolicyAnalysis(unittest.TestCase):
    """Unit-test _analyse_policy directly (no HTTP calls)."""

    def setUp(self):
        self.plugin = FlashCrossdomainDetectorPlugin()

    def _analyse(self, xml_body: str):
        return self.plugin._analyse_policy(
            'http://example.com/crossdomain.xml', 200, 'text/xml', xml_body
        )

    def test_wildcard_domain_is_critical(self):
        xml = '<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>'
        findings = self._analyse(xml)
        severities = {f.severity for f in findings}
        self.assertIn('critical', severities)
        # Evidence must include the URL and the matched snippet
        critical = [f for f in findings if f.severity == 'critical'][0]
        self.assertIn('*', critical.evidence)
        self.assertIn('allow-access-from', critical.evidence)
        self.assertEqual(critical.cwe_id, 'CWE-942')

    def test_wildcard_subdomain_is_high(self):
        xml = '<cross-domain-policy><allow-access-from domain="*.safe.com"/></cross-domain-policy>'
        findings = self._analyse(xml)
        severities = {f.severity for f in findings}
        self.assertIn('high', severities)
        high_f = [f for f in findings if f.severity == 'high'][0]
        self.assertIn('*.safe.com', high_f.evidence)

    def test_explicit_domain_no_finding(self):
        xml = '<cross-domain-policy><allow-access-from domain="trusted.com"/></cross-domain-policy>'
        findings = self._analyse(xml)
        # No critical / high findings for a plain explicit domain
        self.assertFalse(
            any(f.severity in ('critical', 'high') for f in findings)
        )

    def test_site_control_all_is_medium(self):
        xml = (
            '<cross-domain-policy>'
            '<site-control permitted-cross-domain-policies="all"/>'
            '</cross-domain-policy>'
        )
        findings = self._analyse(xml)
        self.assertTrue(any(f.severity == 'medium' for f in findings))
        medium = [f for f in findings if f.severity == 'medium'][0]
        self.assertIn('all', medium.evidence)

    def test_site_control_master_only_no_finding(self):
        xml = (
            '<cross-domain-policy>'
            '<site-control permitted-cross-domain-policies="master-only"/>'
            '</cross-domain-policy>'
        )
        findings = self._analyse(xml)
        self.assertFalse(any(f.severity == 'medium' for f in findings))

    def test_internal_ip_is_informational(self):
        xml = '<cross-domain-policy><allow-access-from domain="192.168.1.5"/></cross-domain-policy>'
        findings = self._analyse(xml)
        info = [f for f in findings if f.severity == 'informational']
        self.assertTrue(len(info) >= 1)
        self.assertIn('192.168.1.5', info[0].evidence)
        self.assertEqual(info[0].vulnerability_type, 'info_disclosure')

    def test_localhost_is_informational(self):
        xml = '<cross-domain-policy><allow-access-from domain="localhost"/></cross-domain-policy>'
        findings = self._analyse(xml)
        self.assertTrue(any(f.severity == 'informational' for f in findings))

    def test_broad_allowlist_is_informational(self):
        domains = ''.join(
            f'<allow-access-from domain="host{i}.com"/>'
            for i in range(6)
        )
        xml = f'<cross-domain-policy>{domains}</cross-domain-policy>'
        findings = self._analyse(xml)
        info = [f for f in findings if 'count' in f.evidence or 'entries' in f.description]
        self.assertTrue(len(info) >= 1)

    def test_malformed_xml_returns_empty(self):
        findings = self._analyse('<not valid xml')
        self.assertEqual(findings, [])

    def test_evidence_contains_url_status_content_type(self):
        xml = '<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>'
        findings = self._analyse(xml)
        self.assertTrue(len(findings) > 0)
        evidence = findings[0].evidence
        self.assertIn('http://example.com/crossdomain.xml', evidence)
        self.assertIn('200', evidence)

    def test_fixture_vulnerable_has_critical_and_high_and_medium(self):
        body = _load_fixture('crossdomain_vulnerable.xml')
        findings = self._analyse(body)
        severities = {f.severity for f in findings}
        self.assertIn('critical', severities)
        self.assertIn('high', severities)
        self.assertIn('medium', severities)

    def test_fixture_safe_no_critical_or_high(self):
        body = _load_fixture('crossdomain_safe.xml')
        findings = self._analyse(body)
        self.assertFalse(
            any(f.severity in ('critical', 'high') for f in findings),
            f"Unexpected findings: {findings}",
        )


class TestFlashCrossdomainScanHTTP(unittest.TestCase):
    """Integration-level tests for the scan() method with mocked HTTP."""

    def setUp(self):
        self.plugin = FlashCrossdomainDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.flash_crossdomain_detector.requests.get')
    def test_200_with_wildcard_yields_critical(self, mock_get):
        xml = '<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>'
        mock_get.return_value = _make_response(xml, 200, 'text/xml')
        findings = self.plugin.scan('http://example.com/page')
        self.assertTrue(any(f.severity == 'critical' for f in findings))

    @patch('scanner.scan_plugins.detectors.flash_crossdomain_detector.requests.get')
    def test_404_yields_no_finding(self, mock_get):
        mock_get.return_value = _make_response('', 404, 'text/html')
        findings = self.plugin.scan('http://example.com/')
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.flash_crossdomain_detector.requests.get')
    def test_correct_path_requested(self, mock_get):
        mock_get.return_value = _make_response('', 404)
        self.plugin.scan('http://example.com/some/path')
        called_url = mock_get.call_args[0][0]
        self.assertEqual(called_url, 'http://example.com/crossdomain.xml')

    @patch(
        'scanner.scan_plugins.detectors.flash_crossdomain_detector.requests.get',
        side_effect=Exception("network error"),
    )
    def test_network_error_returns_empty(self, _mock_get):
        findings = self.plugin.scan('http://example.com/')
        self.assertEqual(findings, [])


class TestPrivateIPRegex(unittest.TestCase):
    def test_matches_10_x_x_x(self):
        self.assertIsNotNone(_PRIVATE_IP_RE.search('10.0.0.1'))

    def test_matches_192_168(self):
        self.assertIsNotNone(_PRIVATE_IP_RE.search('192.168.0.1'))

    def test_matches_172_16(self):
        self.assertIsNotNone(_PRIVATE_IP_RE.search('172.16.0.5'))

    def test_matches_localhost(self):
        self.assertIsNotNone(_PRIVATE_IP_RE.search('localhost'))

    def test_no_match_public_ip(self):
        self.assertIsNone(_PRIVATE_IP_RE.search('8.8.8.8'))

    def test_no_match_plain_domain(self):
        self.assertIsNone(_PRIVATE_IP_RE.search('example.com'))


# ===========================================================================
# Silverlight clientaccesspolicy.xml tests
# ===========================================================================

class TestSilverlightDetectorProperties(unittest.TestCase):
    def setUp(self):
        self.plugin = SilverlightClientAccessDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'silverlight_clientaccess_detector')

    def test_name_contains_silverlight(self):
        self.assertIn('Silverlight', self.plugin.name)

    def test_description_mentions_clientaccesspolicy(self):
        self.assertIn('clientaccesspolicy', self.plugin.description.lower())

    def test_vulnerability_types(self):
        self.assertIn('cors', self.plugin.vulnerability_types)


class TestSilverlightPolicyAnalysis(unittest.TestCase):
    """Unit-test _analyse_policy directly."""

    def setUp(self):
        self.plugin = SilverlightClientAccessDetectorPlugin()

    def _analyse(self, xml_body: str):
        return self.plugin._analyse_policy(
            'http://example.com/clientaccesspolicy.xml', 200, 'text/xml', xml_body
        )

    def test_wildcard_uri_is_critical(self):
        xml = (
            '<access-policy><cross-domain-access><policy>'
            '<allow-from http-request-headers="X-Requested-With">'
            '<domain uri="*"/>'
            '</allow-from>'
            '<grant-to><resource path="/" include-subpaths="true"/></grant-to>'
            '</policy></cross-domain-access></access-policy>'
        )
        findings = self._analyse(xml)
        severities = {f.severity for f in findings}
        self.assertIn('critical', severities)
        critical = [f for f in findings if f.severity == 'critical'][0]
        self.assertIn('*', critical.evidence)
        self.assertEqual(critical.cwe_id, 'CWE-942')

    def test_wildcard_subdomain_is_high(self):
        xml = (
            '<access-policy><cross-domain-access><policy>'
            '<allow-from http-request-headers="X-Requested-With">'
            '<domain uri="*.example.com"/>'
            '</allow-from>'
            '<grant-to><resource path="/" include-subpaths="true"/></grant-to>'
            '</policy></cross-domain-access></access-policy>'
        )
        findings = self._analyse(xml)
        self.assertTrue(any(f.severity == 'high' for f in findings))

    def test_wildcard_request_headers_is_medium(self):
        xml = (
            '<access-policy><cross-domain-access><policy>'
            '<allow-from http-request-headers="*">'
            '<domain uri="trusted.example.com"/>'
            '</allow-from>'
            '<grant-to><resource path="/" include-subpaths="true"/></grant-to>'
            '</policy></cross-domain-access></access-policy>'
        )
        findings = self._analyse(xml)
        self.assertTrue(any(f.severity == 'medium' for f in findings))
        medium = [f for f in findings if f.severity == 'medium'][0]
        self.assertIn('http-request-headers', medium.evidence)

    def test_safe_policy_no_critical_or_high(self):
        body = _load_fixture('clientaccesspolicy_safe.xml')
        findings = self._analyse(body)
        self.assertFalse(
            any(f.severity in ('critical', 'high') for f in findings),
            f"Unexpected findings: {findings}",
        )

    def test_vulnerable_fixture_has_critical_high_medium(self):
        body = _load_fixture('clientaccesspolicy_vulnerable.xml')
        findings = self._analyse(body)
        severities = {f.severity for f in findings}
        self.assertIn('critical', severities)
        self.assertIn('high', severities)
        self.assertIn('medium', severities)

    def test_explicit_domain_no_finding(self):
        xml = (
            '<access-policy><cross-domain-access><policy>'
            '<allow-from http-request-headers="X-Requested-With">'
            '<domain uri="trusted.example.com"/>'
            '</allow-from>'
            '<grant-to><resource path="/" include-subpaths="false"/></grant-to>'
            '</policy></cross-domain-access></access-policy>'
        )
        findings = self._analyse(xml)
        self.assertFalse(
            any(f.severity in ('critical', 'high', 'medium') for f in findings)
        )

    def test_malformed_xml_returns_empty(self):
        findings = self._analyse('<not valid xml')
        self.assertEqual(findings, [])

    def test_evidence_contains_url_and_status(self):
        xml = (
            '<access-policy><cross-domain-access><policy>'
            '<allow-from><domain uri="*"/></allow-from>'
            '</policy></cross-domain-access></access-policy>'
        )
        findings = self._analyse(xml)
        self.assertTrue(len(findings) > 0)
        self.assertIn('http://example.com/clientaccesspolicy.xml', findings[0].evidence)
        self.assertIn('200', findings[0].evidence)


class TestSilverlightScanHTTP(unittest.TestCase):
    """Integration-level tests for scan() with mocked HTTP."""

    def setUp(self):
        self.plugin = SilverlightClientAccessDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.silverlight_clientaccess_detector.requests.get')
    def test_200_wildcard_yields_critical(self, mock_get):
        xml = (
            '<access-policy><cross-domain-access><policy>'
            '<allow-from><domain uri="*"/></allow-from>'
            '</policy></cross-domain-access></access-policy>'
        )
        mock_get.return_value = _make_response(xml, 200, 'text/xml')
        findings = self.plugin.scan('http://example.com/')
        self.assertTrue(any(f.severity == 'critical' for f in findings))

    @patch('scanner.scan_plugins.detectors.silverlight_clientaccess_detector.requests.get')
    def test_404_yields_informational_fallback(self, mock_get):
        mock_get.return_value = _make_response('', 404, 'text/html')
        findings = self.plugin.scan('http://example.com/')
        self.assertTrue(len(findings) == 1)
        self.assertEqual(findings[0].severity, 'informational')
        self.assertIn('crossdomain.xml', findings[0].description)

    @patch('scanner.scan_plugins.detectors.silverlight_clientaccess_detector.requests.get')
    def test_correct_path_requested(self, mock_get):
        mock_get.return_value = _make_response('', 404)
        self.plugin.scan('http://example.com/some/deep/path')
        called_url = mock_get.call_args[0][0]
        self.assertEqual(called_url, 'http://example.com/clientaccesspolicy.xml')

    @patch(
        'scanner.scan_plugins.detectors.silverlight_clientaccess_detector.requests.get',
        side_effect=Exception("connection refused"),
    )
    def test_network_error_returns_empty(self, _mock_get):
        findings = self.plugin.scan('http://example.com/')
        self.assertEqual(findings, [])


# ===========================================================================
# CORS scanner (enhanced) tests
# ===========================================================================

class TestCORSScannerProperties(unittest.TestCase):
    def setUp(self):
        self.plugin = CORSScannerPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'cors_scanner')

    def test_name_contains_cors(self):
        self.assertIn('CORS', self.plugin.name)

    def test_version_is_2(self):
        self.assertTrue(self.plugin.version.startswith('2'))

    def test_vulnerability_types(self):
        types = self.plugin.vulnerability_types
        self.assertIn('cors_misconfiguration', types)


class TestCORSLookalike(unittest.TestCase):
    def setUp(self):
        self.plugin = CORSScannerPlugin()

    def test_lookalike_normal_host(self):
        result = self.plugin._lookalike_origin('https://example.com/path')
        self.assertEqual(result, 'https://evil.example.com')

    def test_lookalike_localhost_returns_none(self):
        self.assertIsNone(self.plugin._lookalike_origin('http://localhost/'))

    def test_lookalike_127_returns_none(self):
        self.assertIsNone(self.plugin._lookalike_origin('http://127.0.0.1/'))

    def test_lookalike_preserves_scheme(self):
        result = self.plugin._lookalike_origin('http://example.com/')
        self.assertTrue(result.startswith('http://'))


class TestCORSProbeOrigin(unittest.TestCase):
    """Unit-test _probe_origin directly."""

    def setUp(self):
        self.plugin = CORSScannerPlugin()

    def _probe(self, acao: str, acac: str = '', vary: str = ''):
        mock_resp = MagicMock()
        mock_resp.headers = {
            'Access-Control-Allow-Origin': acao,
            'Access-Control-Allow-Credentials': acac,
            'Vary': vary,
        }
        with patch(
            'scanner.scan_plugins.detectors.cors_scanner.requests.get',
            return_value=mock_resp,
        ):
            return self.plugin._probe_origin(
                'http://example.com/', 'https://evil.example', False, 5
            )

    def test_wildcard_acao_without_creds_is_medium(self):
        findings = self._probe(acao='*', acac='')
        self.assertTrue(any(f.severity == 'medium' for f in findings))

    def test_wildcard_acao_with_creds_is_high(self):
        findings = self._probe(acao='*', acac='true')
        self.assertTrue(any(f.severity == 'high' for f in findings))

    def test_reflected_origin_without_creds_is_high(self):
        findings = self._probe(acao='https://evil.example', acac='')
        self.assertTrue(any(f.severity == 'high' for f in findings))

    def test_reflected_origin_with_creds_is_critical(self):
        findings = self._probe(acao='https://evil.example', acac='true')
        self.assertTrue(any(f.severity == 'critical' for f in findings))

    def test_reflected_origin_missing_vary_adds_low_finding(self):
        findings = self._probe(acao='https://evil.example', acac='', vary='')
        severities = {f.severity for f in findings}
        self.assertIn('low', severities)

    def test_reflected_origin_with_vary_no_low_finding(self):
        findings = self._probe(acao='https://evil.example', acac='', vary='Origin, Accept-Encoding')
        severities = {f.severity for f in findings}
        self.assertNotIn('low', severities)

    def test_no_cors_headers_no_findings(self):
        findings = self._probe(acao='', acac='')
        self.assertEqual(findings, [])

    def test_evidence_contains_request_origin(self):
        findings = self._probe(acao='*', acac='')
        self.assertTrue(len(findings) > 0)
        self.assertIn('https://evil.example', findings[0].evidence)

    def test_evidence_contains_acao_value(self):
        findings = self._probe(acao='*')
        self.assertIn("'*'", findings[0].evidence)


class TestCORSPreflight(unittest.TestCase):
    """Unit-test _probe_preflight directly."""

    def setUp(self):
        self.plugin = CORSScannerPlugin()

    def _preflight(self, acam: str, acah: str = ''):
        mock_resp = MagicMock()
        mock_resp.headers = {
            'Access-Control-Allow-Methods': acam,
            'Access-Control-Allow-Headers': acah,
        }
        with patch(
            'scanner.scan_plugins.detectors.cors_scanner.requests.options',
            return_value=mock_resp,
        ):
            return self.plugin._probe_preflight(
                'http://example.com/', 'https://evil.example', False, 5
            )

    def test_risky_method_delete_yields_medium(self):
        findings = self._preflight(acam='GET, POST, DELETE')
        self.assertTrue(any(f.severity == 'medium' for f in findings))

    def test_risky_method_put_yields_medium(self):
        findings = self._preflight(acam='GET, PUT')
        self.assertTrue(any(f.severity == 'medium' for f in findings))

    def test_risky_method_patch_yields_medium(self):
        findings = self._preflight(acam='GET, PATCH')
        self.assertTrue(any(f.severity == 'medium' for f in findings))

    def test_safe_methods_no_finding(self):
        findings = self._preflight(acam='GET, POST, HEAD, OPTIONS')
        self.assertFalse(any(f.severity == 'medium' for f in findings))

    def test_wildcard_headers_yields_medium(self):
        findings = self._preflight(acam='GET, POST', acah='*')
        self.assertTrue(any(f.severity == 'medium' for f in findings))
        medium = [f for f in findings if f.severity == 'medium'][0]
        self.assertIn('Authorization', medium.evidence)

    def test_no_acam_no_findings(self):
        findings = self._preflight(acam='')
        self.assertEqual(findings, [])

    def test_evidence_contains_request_headers(self):
        findings = self._preflight(acam='GET, DELETE')
        self.assertTrue(len(findings) > 0)
        self.assertIn('Authorization', findings[0].evidence)
        self.assertIn('X-Custom-Header', findings[0].evidence)


class TestCORSScanIntegration(unittest.TestCase):
    """Integration-level scan() tests with mocked HTTP."""

    def setUp(self):
        self.plugin = CORSScannerPlugin()

    def _mock_responses(self, acao='', acac='', vary='', acam='', acah=''):
        get_resp = MagicMock()
        get_resp.headers = {
            'Access-Control-Allow-Origin': acao,
            'Access-Control-Allow-Credentials': acac,
            'Vary': vary,
        }
        options_resp = MagicMock()
        options_resp.headers = {
            'Access-Control-Allow-Methods': acam,
            'Access-Control-Allow-Headers': acah,
        }
        return get_resp, options_resp

    @patch('scanner.scan_plugins.detectors.cors_scanner.requests.options')
    @patch('scanner.scan_plugins.detectors.cors_scanner.requests.get')
    def test_wildcard_acao_found_in_full_scan(self, mock_get, mock_options):
        mock_get.return_value = _make_get_response({'Access-Control-Allow-Origin': '*'})
        mock_options.return_value = _make_get_response({})
        findings = self.plugin.scan(
            'http://example.com/', config={'verify_ssl': False, 'timeout': 5, 'test_preflight': False}
        )
        self.assertTrue(any(f.severity == 'medium' for f in findings))

    @patch('scanner.scan_plugins.detectors.cors_scanner.requests.options')
    @patch('scanner.scan_plugins.detectors.cors_scanner.requests.get')
    def test_deduplication(self, mock_get, mock_options):
        # All probe origins get ACAO: * → same description, should deduplicate
        mock_get.return_value = _make_get_response({'Access-Control-Allow-Origin': '*'})
        mock_options.return_value = _make_get_response({})
        findings = self.plugin.scan(
            'http://example.com/',
            config={'verify_ssl': False, 'timeout': 5, 'test_preflight': False},
        )
        descriptions = [f.description[:60] for f in findings]
        # Deduplicated – no duplicate description+url pairs
        self.assertEqual(len(descriptions), len(set(descriptions)))


# ===========================================================================
# Registry auto-discovery
# ===========================================================================

class TestSOPRegistryDiscovery(unittest.TestCase):
    """Verify all three new plugins are auto-discovered by ScanPluginRegistry."""

    def setUp(self):
        reset_scan_registry()
        self.registry = ScanPluginRegistry()
        self.registry.discover_plugins()

    def test_flash_crossdomain_discovered(self):
        plugin = self.registry.get_plugin('flash_crossdomain_detector')
        self.assertIsNotNone(plugin, "flash_crossdomain_detector not discovered")
        self.assertIsInstance(plugin, FlashCrossdomainDetectorPlugin)

    def test_silverlight_clientaccess_discovered(self):
        plugin = self.registry.get_plugin('silverlight_clientaccess_detector')
        self.assertIsNotNone(plugin, "silverlight_clientaccess_detector not discovered")
        self.assertIsInstance(plugin, SilverlightClientAccessDetectorPlugin)

    def test_cors_scanner_discovered(self):
        plugin = self.registry.get_plugin('cors_scanner')
        self.assertIsNotNone(plugin, "cors_scanner not discovered")
        self.assertIsInstance(plugin, CORSScannerPlugin)

    def tearDown(self):
        reset_scan_registry()


if __name__ == '__main__':
    unittest.main()
