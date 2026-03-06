"""
Tests for TechFingerprinter

Covers:
- Header-based detection (Server, X-Powered-By, X-Generator, CDN headers)
- Cookie-based detection (PHPSESSID, csrftoken, JSESSIONID, etc.)
- HTML pattern detection (WordPress, Drupal, framework markers)
- JavaScript framework detection from script tags
- TechStack assembly (highest-confidence wins per category)
- fingerprint_from_response() offline helper
"""

from unittest.mock import MagicMock, patch
from django.test import SimpleTestCase as TestCase

from scanner.tech_fingerprinter import TechFingerprinter, TechStack, TechEntry


def _make_response(headers=None, cookies=None, text='', status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    resp.cookies = [_cookie(k, v) for k, v in (cookies or {}).items()]
    resp.url = 'https://example.com'
    return resp


def _cookie(name, value):
    c = MagicMock()
    c.name = name
    c.value = value
    return c


class TestTechFingerprinterHeaders(TestCase):
    def setUp(self):
        self.fp = TechFingerprinter()

    def test_detects_nginx(self):
        entries = self.fp._from_headers({'Server': 'nginx/1.18.0'})
        names = [e.name for e in entries]
        self.assertIn('nginx', names)

    def test_detects_apache(self):
        entries = self.fp._from_headers({'Server': 'Apache/2.4.41'})
        names = [e.name for e in entries]
        self.assertIn('Apache', names)

    def test_detects_php_via_x_powered_by(self):
        entries = self.fp._from_headers({'X-Powered-By': 'PHP/7.4.0'})
        names = [e.name for e in entries]
        self.assertIn('PHP', names)

    def test_detects_aspnet(self):
        entries = self.fp._from_headers({'X-Powered-By': 'ASP.NET'})
        names = [e.name for e in entries]
        self.assertIn('ASP.NET', names)

    def test_detects_cloudflare(self):
        entries = self.fp._from_headers({'CF-Ray': '12345-LAX'})
        names = [e.name for e in entries]
        self.assertIn('Cloudflare', names)

    def test_detects_wordpress_via_x_generator(self):
        entries = self.fp._from_headers({'X-Generator': 'WordPress 6.0'})
        names = [e.name for e in entries]
        self.assertIn('WordPress', names)

    def test_case_insensitive_headers(self):
        entries = self.fp._from_headers({'server': 'nginx/1.18'})
        names = [e.name for e in entries]
        self.assertIn('nginx', names)

    def test_no_false_positive_empty_headers(self):
        entries = self.fp._from_headers({})
        self.assertEqual(entries, [])


class TestTechFingerprinterCookies(TestCase):
    def setUp(self):
        self.fp = TechFingerprinter()

    def test_detects_php_via_phpsessid(self):
        entries = self.fp._from_cookies_dict({'PHPSESSID': 'abc123'})
        names = [e.name for e in entries]
        self.assertIn('PHP', names)

    def test_detects_django_via_csrftoken(self):
        entries = self.fp._from_cookies_dict({'csrftoken': 'xyz'})
        names = [e.name for e in entries]
        self.assertIn('Django', names)

    def test_detects_java_via_jsessionid(self):
        entries = self.fp._from_cookies_dict({'JSESSIONID': 'abc'})
        names = [e.name for e in entries]
        self.assertIn('Java (Servlet)', names)

    def test_detects_wordpress_cookie(self):
        entries = self.fp._from_cookies_dict({'wordpress_logged_in_abc': 'true'})
        names = [e.name for e in entries]
        self.assertIn('WordPress', names)

    def test_detects_rails_session(self):
        entries = self.fp._from_cookies_dict({'_rails_session': 'abc'})
        names = [e.name for e in entries]
        self.assertIn('Ruby on Rails', names)

    def test_no_false_positive_empty_cookies(self):
        entries = self.fp._from_cookies_dict({})
        self.assertEqual(entries, [])


class TestTechFingerprinterHTML(TestCase):
    def setUp(self):
        self.fp = TechFingerprinter()

    def test_detects_wordpress_via_wp_content(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/default/style.css">'
        entries = self.fp._from_html(html)
        names = [e.name for e in entries]
        self.assertIn('WordPress', names)

    def test_detects_wordpress_meta_generator(self):
        html = '<meta name="generator" content="WordPress 6.0">'
        entries = self.fp._from_html(html)
        names = [e.name for e in entries]
        self.assertIn('WordPress', names)

    def test_detects_angular(self):
        html = '<div ng-app="myApp" ng-controller="ctrl"></div>'
        entries = self.fp._from_html(html)
        names = [e.name for e in entries]
        self.assertIn('AngularJS', names)

    def test_detects_react_via_script(self):
        html = '<script src="/static/react.min.js"></script>'
        entries = self.fp._from_html(html)
        names = [e.name for e in entries]
        self.assertIn('React', names)

    def test_detects_jquery_via_script(self):
        html = '<script src="/js/jquery.min.js"></script>'
        entries = self.fp._from_html(html)
        names = [e.name for e in entries]
        self.assertIn('jQuery', names)

    def test_detects_django_csrf(self):
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc">'
        entries = self.fp._from_html(html)
        names = [e.name for e in entries]
        self.assertIn('Django', names)

    def test_empty_html_returns_no_findings(self):
        entries = self.fp._from_html('')
        self.assertEqual(entries, [])


class TestTechStackBuilder(TestCase):
    def setUp(self):
        self.fp = TechFingerprinter()

    def test_highest_confidence_wins(self):
        entries = [
            TechEntry('nginx', 'web_server', 0.9, 'header'),
            TechEntry('Apache', 'web_server', 0.7, 'header'),
        ]
        stack = self.fp._build_stack(entries)
        self.assertEqual(stack.web_server, 'nginx')

    def test_all_categories_populated(self):
        entries = [
            TechEntry('nginx', 'web_server', 0.9, 'ev'),
            TechEntry('PHP', 'language', 0.9, 'ev'),
            TechEntry('WordPress', 'cms', 0.99, 'ev'),
            TechEntry('Cloudflare', 'cdn_waf', 0.99, 'ev'),
            TechEntry('React', 'js_framework', 0.9, 'ev'),
        ]
        stack = self.fp._build_stack(entries)
        self.assertEqual(stack.web_server, 'nginx')
        self.assertEqual(stack.programming_language, 'PHP')
        self.assertEqual(stack.cms, 'WordPress')
        self.assertEqual(stack.cdn_waf, 'Cloudflare')
        self.assertIn('React', stack.javascript_frameworks)

    def test_empty_entries_returns_empty_stack(self):
        stack = self.fp._build_stack([])
        self.assertIsNone(stack.web_server)
        self.assertIsNone(stack.framework)
        self.assertEqual(stack.javascript_frameworks, [])

    def test_detected_technologies_in_stack(self):
        entries = [TechEntry('nginx', 'web_server', 0.9, 'ev')]
        stack = self.fp._build_stack(entries)
        self.assertEqual(len(stack.detected_technologies), 1)
        self.assertEqual(stack.detected_technologies[0].name, 'nginx')


class TestTechFingerprinterOffline(TestCase):
    """Test fingerprint_from_response() without any network calls."""

    def test_fingerprint_from_response_headers(self):
        fp = TechFingerprinter()
        stack = fp.fingerprint_from_response(
            headers={'Server': 'nginx/1.18', 'X-Powered-By': 'PHP/8.0'},
            cookies={},
            html='',
        )
        self.assertEqual(stack.web_server, 'nginx')
        self.assertEqual(stack.programming_language, 'PHP')

    def test_fingerprint_from_response_cookies(self):
        fp = TechFingerprinter()
        stack = fp.fingerprint_from_response(
            headers={},
            cookies={'csrftoken': 'abc'},
            html='',
        )
        self.assertEqual(stack.framework, 'Django')

    def test_to_dict_structure(self):
        fp = TechFingerprinter()
        stack = fp.fingerprint_from_response(
            headers={'Server': 'nginx/1.18'},
            cookies={},
            html='',
        )
        d = stack.to_dict()
        self.assertIn('web_server', d)
        self.assertIn('detected_technologies', d)
        self.assertIsInstance(d['detected_technologies'], list)


class TestTechFingerprinterNetworkError(TestCase):
    @patch('scanner.tech_fingerprinter.HAS_REQUESTS', True)
    def test_fingerprint_returns_empty_stack_on_network_error(self):
        fp = TechFingerprinter()
        session_mock = MagicMock()
        session_mock.get.side_effect = ConnectionError('no network')
        fp._session = session_mock

        stack = fp.fingerprint('https://example.com')
        self.assertIsInstance(stack, TechStack)
        self.assertIsNone(stack.web_server)

    @patch('scanner.tech_fingerprinter.HAS_REQUESTS', False)
    def test_fingerprint_without_requests_library(self):
        fp = TechFingerprinter()
        stack = fp.fingerprint('https://example.com')
        self.assertIsInstance(stack, TechStack)
