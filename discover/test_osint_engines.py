"""
Tests for the OSINT engines package.

Each engine is tested with mocked HTTP/DNS responses so that no real
external requests are made during the test suite.
"""
from unittest.mock import MagicMock, patch, PropertyMock

from django.test import TestCase

from discover.osint_engines.base_engine import BaseOSINTEngine, EngineResult
from discover.osint_engines.dns_engine import DNSEngine
from discover.osint_engines.subdomain_engine import SubdomainEngine
from discover.osint_engines.whois_engine import WHOISEngine
from discover.osint_engines.certificate_engine import CertificateEngine
from discover.osint_engines.technology_engine import TechnologyEngine
from discover.osint_engines.cloud_enum_engine import CloudEnumEngine
from discover.osint_engines.email_engine import EmailEngine
from discover.osint_engines.social_media_engine import SocialMediaEngine
from discover.osint_engines.threat_intel_engine import ThreatIntelEngine
from discover.osint_engines import ENGINE_REGISTRY


# ---------------------------------------------------------------------------
# BaseEngine
# ---------------------------------------------------------------------------

class ConcreteEngine(BaseOSINTEngine):
    """Minimal concrete subclass for testing the base class."""
    name = 'ConcreteEngine'

    def collect(self, target: str):
        return {'items': ['a', 'b', 'c']}


class FailingEngine(BaseOSINTEngine):
    """Engine that always raises."""
    name = 'FailingEngine'

    def collect(self, target: str):
        raise RuntimeError("simulated failure")


class TestBaseEngine(TestCase):

    def test_run_returns_engine_result(self):
        engine = ConcreteEngine()
        result = engine.run('example.com')
        self.assertIsInstance(result, EngineResult)

    def test_run_success(self):
        engine = ConcreteEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        self.assertEqual(result.engine_name, 'ConcreteEngine')
        self.assertGreater(result.items_found, 0)
        self.assertGreaterEqual(result.duration_seconds, 0)

    def test_run_handles_exception(self):
        engine = FailingEngine()
        result = engine.run('example.com')
        self.assertFalse(result.success)
        self.assertIn('simulated failure', result.errors[0])

    def test_count_items_default(self):
        engine = ConcreteEngine()
        data = {'items': ['a', 'b'], 'other': ['x']}
        self.assertEqual(engine._count_items(data), 3)

    def test_get_config(self):
        engine = ConcreteEngine(config={'key': 'value'})
        self.assertEqual(engine._get_config('key'), 'value')
        self.assertIsNone(engine._get_config('missing'))
        self.assertEqual(engine._get_config('missing', 'default'), 'default')

    def test_engine_result_to_dict(self):
        result = EngineResult(
            engine_name='Test',
            success=True,
            data={'foo': 'bar'},
            items_found=1,
        )
        d = result.to_dict()
        self.assertEqual(d['engine'], 'Test')
        self.assertTrue(d['success'])
        self.assertEqual(d['data']['foo'], 'bar')


# ---------------------------------------------------------------------------
# ENGINE_REGISTRY
# ---------------------------------------------------------------------------

class TestEngineRegistry(TestCase):

    def test_all_engines_in_registry(self):
        expected = [
            'dns', 'subdomains', 'whois', 'certificates',
            'technology', 'web_crawler', 'email', 'social_media',
            'cloud_enum', 'threat_intel',
        ]
        for name in expected:
            self.assertIn(name, ENGINE_REGISTRY, f"Engine '{name}' missing from registry")

    def test_registry_values_are_classes(self):
        for name, cls in ENGINE_REGISTRY.items():
            self.assertTrue(
                issubclass(cls, BaseOSINTEngine),
                f"ENGINE_REGISTRY['{name}'] is not a BaseOSINTEngine subclass",
            )


# ---------------------------------------------------------------------------
# DNS Engine
# ---------------------------------------------------------------------------

class TestDNSEngine(TestCase):

    @patch('discover.osint_engines.dns_engine.DNS_PYTHON_AVAILABLE', False)
    @patch('socket.getaddrinfo')
    def test_collect_socket_fallback(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ('1.2.3.4', 0)),
            (None, None, None, None, ('2001:db8::1', 0)),
        ]
        engine = DNSEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        data = result.data
        self.assertIn('1.2.3.4', data['records'].get('A', []))
        self.assertIn('2001:db8::1', data['records'].get('AAAA', []))

    @patch('discover.osint_engines.dns_engine.DNS_PYTHON_AVAILABLE', False)
    @patch('socket.getaddrinfo', side_effect=Exception("DNS failure"))
    def test_collect_socket_error(self, mock_getaddrinfo):
        engine = DNSEngine()
        result = engine.run('nonexistent.invalid')
        # Engine should succeed but return errors list
        self.assertTrue(result.success)
        self.assertTrue(len(result.data.get('errors', [])) > 0 or result.data.get('records') == {})


# ---------------------------------------------------------------------------
# Subdomain Engine
# ---------------------------------------------------------------------------

class TestSubdomainEngine(TestCase):

    @patch('discover.osint_engines.subdomain_engine.requests.get')
    @patch('socket.gethostbyname', side_effect=Exception("NXDOMAIN"))
    def test_collect_crtsh_results(self, mock_dns, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {'name_value': 'api.example.com\nwww.example.com'},
            {'name_value': 'mail.example.com'},
        ]
        mock_response.raise_for_status.return_value = None
        # Second call (hackertarget) returns empty
        mock_get.side_effect = [mock_response, Exception("hackertarget offline")]

        engine = SubdomainEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        subdomains = result.data.get('subdomains', [])
        self.assertIn('api.example.com', subdomains)
        self.assertIn('www.example.com', subdomains)
        self.assertIn('mail.example.com', subdomains)

    @patch('discover.osint_engines.subdomain_engine.requests.get', side_effect=Exception("network error"))
    @patch('socket.gethostbyname', side_effect=Exception("NXDOMAIN"))
    def test_collect_handles_errors_gracefully(self, mock_dns, mock_get):
        engine = SubdomainEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)  # Engine should not crash
        self.assertIn('crt.sh', result.data['errors'][0])


# ---------------------------------------------------------------------------
# WHOIS Engine
# ---------------------------------------------------------------------------

class TestWHOISEngine(TestCase):

    @patch('discover.osint_engines.whois_engine.WHOIS_AVAILABLE', False)
    @patch('discover.osint_engines.whois_engine.requests.get')
    @patch('socket.getaddrinfo', side_effect=Exception("offline"))
    def test_rdap_fallback(self, mock_gai, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'handle': 'EXAMPLE-1',
            'ldhName': 'example.com',
            'status': ['active'],
            'entities': [],
            'nameservers': [{'ldhName': 'ns1.example.com'}],
            'events': [],
        }
        mock_get.return_value = mock_response

        engine = WHOISEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        self.assertEqual(result.data['rdap']['handle'], 'EXAMPLE-1')


# ---------------------------------------------------------------------------
# Certificate Engine
# ---------------------------------------------------------------------------

class TestCertificateEngine(TestCase):

    @patch('discover.osint_engines.certificate_engine.requests.get')
    @patch('discover.osint_engines.certificate_engine.socket.create_connection', side_effect=Exception("connection refused"))
    def test_ct_log_search(self, mock_conn, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                'id': 123,
                'entry_timestamp': '2024-01-01T00:00:00Z',
                'not_before': '2024-01-01',
                'not_after': '2025-01-01',
                'common_name': 'example.com',
                'name_value': 'example.com\nwww.example.com',
                'issuer_name': "Let's Encrypt",
            }
        ]
        mock_get.return_value = mock_response

        engine = CertificateEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        ct_entries = result.data.get('ct_log_entries', [])
        self.assertEqual(len(ct_entries), 1)
        self.assertEqual(ct_entries[0]['id'], 123)


# ---------------------------------------------------------------------------
# Technology Engine
# ---------------------------------------------------------------------------

class TestTechnologyEngine(TestCase):

    @patch('discover.osint_engines.technology_engine.requests.get')
    def test_detect_nginx_and_wordpress(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx/1.18.0',
            'Content-Type': 'text/html',
        }
        mock_response.text = (
            '<html><head></head><body>'
            '<link rel="stylesheet" href="/wp-content/themes/theme/style.css">'
            '</body></html>'
        )
        mock_get.return_value = mock_response

        engine = TechnologyEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        tech_names = [t['name'] for t in result.data.get('technologies', [])]
        self.assertIn('Nginx', tech_names)
        self.assertIn('WordPress', tech_names)

    @patch('discover.osint_engines.technology_engine.requests.get', side_effect=Exception("no connection"))
    def test_handles_connection_failure(self, mock_get):
        engine = TechnologyEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        self.assertTrue(len(result.data.get('errors', [])) > 0)


# ---------------------------------------------------------------------------
# Cloud Enum Engine
# ---------------------------------------------------------------------------

class TestCloudEnumEngine(TestCase):

    @patch('discover.osint_engines.cloud_enum_engine.requests.get')
    def test_open_s3_bucket_detected(self, mock_get):
        open_response = MagicMock()
        open_response.status_code = 200

        private_response = MagicMock()
        private_response.status_code = 404

        def side_effect(url, **kwargs):
            if 'amazonaws' in url and 'example' in url and not any(
                suffix in url for suffix in ['-dev', '-staging', '-prod']
            ):
                return open_response
            return private_response

        mock_get.side_effect = side_effect

        engine = CloudEnumEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        open_buckets = [b for b in result.data['s3_buckets'] if b['status'] == 'open']
        self.assertGreater(len(open_buckets), 0)


# ---------------------------------------------------------------------------
# Email Engine
# ---------------------------------------------------------------------------

class TestEmailEngine(TestCase):

    @patch('discover.osint_engines.email_engine.requests.get')
    def test_hunter_io_integration(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'pattern': '{first}.{last}',
                'emails': [
                    {
                        'value': 'john.doe@example.com',
                        'type': 'personal',
                        'confidence': 90,
                        'first_name': 'John',
                        'last_name': 'Doe',
                        'position': 'CEO',
                    }
                ],
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        engine = EmailEngine(config={'hunter_api_key': 'test-key'})
        result = engine.run('example.com')
        self.assertTrue(result.success)
        emails = result.data.get('emails', [])
        self.assertGreater(len(emails), 0)
        self.assertEqual(emails[0]['email'], 'john.doe@example.com')

    def test_no_api_key_returns_error(self):
        engine = EmailEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)  # Should not crash
        errors = result.data.get('errors', [])
        self.assertTrue(any('Hunter.io API key not configured' == e for e in errors))


# ---------------------------------------------------------------------------
# Social Media Engine
# ---------------------------------------------------------------------------

class TestSocialMediaEngine(TestCase):

    @patch('discover.osint_engines.social_media_engine.requests.get')
    def test_github_org_found(self, mock_get):
        org_response = MagicMock()
        org_response.status_code = 200
        org_response.json.return_value = {
            'login': 'example',
            'name': 'Example Corp',
            'description': 'A test org',
            'public_repos': 5,
            'followers': 100,
            'html_url': 'https://github.com/example',
            'type': 'Organization',
        }

        repos_response = MagicMock()
        repos_response.status_code = 200
        repos_response.json.return_value = []

        platform_response = MagicMock()
        platform_response.status_code = 404

        def side_effect(url, **kwargs):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.netloc
            path = parsed.path
            if hostname == 'api.github.com' and '/orgs/example' in path:
                return org_response
            if hostname == 'api.github.com' and 'repos' in path:
                return repos_response
            return platform_response

        mock_get.side_effect = side_effect

        engine = SocialMediaEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        self.assertEqual(result.data['github_org'].get('login'), 'example')


# ---------------------------------------------------------------------------
# Threat Intel Engine
# ---------------------------------------------------------------------------

class TestThreatIntelEngine(TestCase):

    @patch('discover.osint_engines.threat_intel_engine.requests.get')
    @patch('discover.osint_engines.threat_intel_engine.requests.post')
    @patch('socket.getaddrinfo')
    def test_shodan_internetdb_lookup(self, mock_gai, mock_post, mock_get):
        mock_gai.return_value = [(None, None, None, None, ('1.2.3.4', 0))]

        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            from urllib.parse import urlparse
            hostname = urlparse(url).netloc
            if hostname == 'internetdb.shodan.io':
                resp.status_code = 200
                resp.json.return_value = {
                    'ports': [80, 443],
                    'cpes': [],
                    'hostnames': ['example.com'],
                    'tags': [],
                    'vulns': ['CVE-2021-1234'],
                }
            elif hostname == 'otx.alienvault.com':
                resp.status_code = 200
                resp.json.return_value = {'pulse_info': {'count': 2}, 'reputation': -1, 'indicator': 'example.com'}
            else:
                resp.status_code = 404
                resp.json.return_value = {}
            return resp

        mock_get.side_effect = get_side_effect

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {
            'query_status': 'is_host',
            'urls_count': 0,
            'blacklists': {},
        }
        mock_post.return_value = mock_post_resp

        engine = ThreatIntelEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)
        sdb = result.data.get('shodan_internetdb', [])
        self.assertEqual(len(sdb), 1)
        self.assertIn(80, sdb[0]['ports'])
        self.assertIn('CVE-2021-1234', sdb[0]['vulns'])

    @patch('discover.osint_engines.threat_intel_engine.requests.get')
    @patch('discover.osint_engines.threat_intel_engine.requests.post')
    @patch('socket.getaddrinfo', side_effect=Exception("offline"))
    def test_handles_offline_gracefully(self, mock_gai, mock_post, mock_get):
        mock_get.side_effect = Exception("offline")
        mock_post.side_effect = Exception("offline")
        engine = ThreatIntelEngine()
        result = engine.run('example.com')
        self.assertTrue(result.success)  # Should not crash
