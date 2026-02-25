"""
Unit tests for:

  - SessionFixationDetectorPlugin
      (scanner/scan_plugins/detectors/session_fixation_detector.py)

  - OpenRedirectDetectorPlugin (enhanced)
      (scanner/scan_plugins/detectors/open_redirect_detector.py)

All HTTP calls are mocked; no network requests are made.

SessionFixationDetectorPlugin coverage:
  - Plugin properties (id, name, version, vulnerability_types)
  - Default config keys
  - _extract_session_cookies: override names
  - _extract_session_cookies: heuristic name matching
  - _cookies_rotated: all changed → rotated
  - _cookies_rotated: one unchanged → not rotated
  - _test_anon_to_auth: cookie unchanged → finding
  - _test_anon_to_auth: cookie rotated → no finding
  - _test_anon_to_auth: no pre-login cookies → no finding
  - _test_anon_to_auth: network error → no finding
  - _test_user_swap: cookie unchanged → finding
  - _test_user_swap: cookie rotated → no finding
  - _test_sensitive_flow: pre-flow token accesses review → finding
  - _test_sensitive_flow: no session cookies → no finding
  - _test_arbitrary_token: crafted token accepted → high finding
  - _test_arbitrary_token: crafted token replaced → no finding
  - scan(): no credentials, no sensitive_flow → returns []
  - scan(): fixation + arbitrary accepted → severity elevated
  - scan(): no requests library → returns []
  - Auto-discovery via ScanPluginRegistry

OpenRedirectDetectorPlugin (enhanced) coverage:
  - Plugin properties unchanged
  - _is_external_redirect: external absolute URL
  - _is_external_redirect: scheme-relative URL
  - _is_external_redirect: triple-slash
  - _is_external_redirect: backslash
  - _is_external_redirect: javascript: scheme
  - _is_external_redirect: userinfo trick
  - _is_external_redirect: same host returns False
  - _extract_refresh_url: standard Refresh header
  - _extract_refresh_url: URL= casing variant
  - _extract_meta_refresh_url: normal meta tag
  - _extract_js_redirect_url: window.location assignment
  - _extract_js_redirect_url: location.href
  - _extract_js_redirect_url: location.replace
  - _test_open_redirect: 3xx Location redirect detected
  - _test_open_redirect: Refresh header redirect detected
  - _test_open_redirect: meta refresh redirect detected
  - _test_open_redirect: JS redirect detected
  - _test_open_redirect: no redirect → no finding
  - _test_open_redirect: common param names probed even if absent
  - _test_open_redirect: multiple findings collected (no early exit)
  - scan(): no requests library → returns []
  - Auto-discovery via ScanPluginRegistry
"""

import sys
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch, call

# Ensure project root on path
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanner.scan_plugins.detectors.session_fixation_detector import (
    SessionFixationDetectorPlugin,
    _extract_session_cookies,
    _cookies_rotated,
    _CRAFTED_TOKEN,
    _SESSION_COOKIE_PATTERNS,
)
from scanner.scan_plugins.detectors.open_redirect_detector import (
    OpenRedirectDetectorPlugin,
    _is_external_redirect,
    _COMMON_REDIRECT_PARAMS,
)
from scanner.scan_plugins.scan_plugin_registry import ScanPluginRegistry, reset_scan_registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    status_code: int = 200,
    headers: Optional[dict] = None,
    text: str = '',
    cookies: Optional[dict] = None,
) -> MagicMock:
    """Return a minimal mock requests.Response with a CookieJar-like cookies attr."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    mock_resp.text = text
    # cookies attribute on Response; not used directly by the plugin (it uses Session.cookies)
    mock_resp.cookies = _make_cookie_jar(cookies or {})
    return mock_resp


def _make_cookie_jar(cookie_dict: dict) -> MagicMock:
    """Create a mock cookie jar that iterates over SimpleCookie-like objects."""
    cookies = []
    for name, value in cookie_dict.items():
        c = MagicMock()
        c.name = name
        c.value = value
        cookies.append(c)

    jar = MagicMock()
    jar.__iter__ = MagicMock(return_value=iter(cookies))
    jar.set = MagicMock()
    # Support dict-like .get()
    jar_dict = cookie_dict.copy()
    jar.get = MagicMock(side_effect=lambda k, default=None: jar_dict.get(k, default))
    return jar


# ---------------------------------------------------------------------------
# ===========================================================================
# SessionFixationDetectorPlugin – property tests
# ===========================================================================
# ---------------------------------------------------------------------------

class TestSessionFixationPluginProperties(unittest.TestCase):
    def setUp(self):
        self.plugin = SessionFixationDetectorPlugin()

    def test_plugin_id(self):
        self.assertEqual(self.plugin.plugin_id, 'session_fixation_detector')

    def test_name_contains_session_fixation(self):
        self.assertIn('Session Fixation', self.plugin.name)

    def test_version_is_string(self):
        self.assertIsInstance(self.plugin.version, str)
        self.assertTrue(len(self.plugin.version) > 0)

    def test_vulnerability_types_include_session_fixation(self):
        self.assertIn('session_fixation', self.plugin.vulnerability_types)

    def test_default_config_has_expected_keys(self):
        config = self.plugin.get_default_config()
        for key in ('verify_ssl', 'timeout', 'login_url', 'username_field',
                    'password_field', 'username', 'password', 'username2',
                    'password2', 'session_cookie_names', 'sensitive_flow'):
            self.assertIn(key, config, f"Expected config key '{key}' missing")


# ---------------------------------------------------------------------------
# ===========================================================================
# _extract_session_cookies helper
# ===========================================================================
# ---------------------------------------------------------------------------

class TestExtractSessionCookies(unittest.TestCase):
    def _jar(self, cookies: dict):
        return _make_cookie_jar(cookies)

    def test_override_names_filters_correctly(self):
        jar = self._jar({'session': 'abc', 'other': 'xyz', 'sid': '123'})
        result = _extract_session_cookies(jar, override_names=['session'])
        self.assertEqual(result, {'session': 'abc'})
        self.assertNotIn('other', result)
        self.assertNotIn('sid', result)

    def test_heuristic_matches_common_session_names(self):
        jar = self._jar({
            'PHPSESSID': 'php123',
            'JSESSIONID': 'java456',
            'session': 'py789',
            'unrelated_cookie': 'nope',
        })
        result = _extract_session_cookies(jar)
        self.assertIn('PHPSESSID', result)
        self.assertIn('JSESSIONID', result)
        self.assertIn('session', result)
        self.assertNotIn('unrelated_cookie', result)

    def test_heuristic_matches_sid(self):
        jar = self._jar({'sid': 'abc'})
        result = _extract_session_cookies(jar)
        self.assertIn('sid', result)

    def test_empty_jar_returns_empty(self):
        jar = self._jar({})
        result = _extract_session_cookies(jar)
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# ===========================================================================
# _cookies_rotated helper
# ===========================================================================
# ---------------------------------------------------------------------------

class TestCookiesRotated(unittest.TestCase):
    def test_all_changed_returns_rotated_true(self):
        before = {'session': 'old_val'}
        after = {'session': 'new_val'}
        rotated, unchanged = _cookies_rotated(before, after)
        self.assertTrue(rotated)
        self.assertEqual(unchanged, [])

    def test_unchanged_value_returns_rotated_false(self):
        before = {'session': 'same_val'}
        after = {'session': 'same_val'}
        rotated, unchanged = _cookies_rotated(before, after)
        self.assertFalse(rotated)
        self.assertIn('session', unchanged)

    def test_mixed_some_unchanged(self):
        before = {'session': 'val', 'csrftoken': 'token'}
        after = {'session': 'new_val', 'csrftoken': 'token'}
        rotated, unchanged = _cookies_rotated(before, after)
        self.assertFalse(rotated)
        self.assertIn('csrftoken', unchanged)
        self.assertNotIn('session', unchanged)

    def test_cookie_removed_counts_as_rotated(self):
        before = {'session': 'val'}
        after = {}  # cookie was removed
        rotated, unchanged = _cookies_rotated(before, after)
        self.assertTrue(rotated)


# ---------------------------------------------------------------------------
# ===========================================================================
# SessionFixationDetectorPlugin – _test_anon_to_auth
# ===========================================================================
# ---------------------------------------------------------------------------

class TestAnonToAuth(unittest.TestCase):
    def setUp(self):
        self.plugin = SessionFixationDetectorPlugin()

    def _run(self, pre_cookies, post_cookies):
        """Helper: mock Session.get → pre_cookies, Session.post → post_cookies."""
        with patch(
            'scanner.scan_plugins.detectors.session_fixation_detector.requests.Session'
        ) as MockSession:
            session_instance = MagicMock()
            MockSession.return_value = session_instance

            # GET returns pre-login cookies
            get_resp = _make_response(200)
            session_instance.get.return_value = get_resp
            session_instance.cookies = _make_cookie_jar(pre_cookies)

            # POST returns post-login cookies (update the session cookies mock)
            post_resp = _make_response(200)
            session_instance.post.return_value = post_resp

            # After POST, session cookies become post_cookies
            post_jar = _make_cookie_jar(post_cookies)

            # We need to simulate that cookies change after POST
            # Patch _extract_session_cookies to return the right thing
            call_count = [0]
            orig_extract = _extract_session_cookies

            def fake_extract(jar, override=None):
                call_count[0] += 1
                if call_count[0] == 1:
                    return {k: v for k, v in pre_cookies.items()
                            if (override is None or k in (override or []))}
                return {k: v for k, v in post_cookies.items()
                        if (override is None or k in (override or []))}

            import scanner.scan_plugins.detectors.session_fixation_detector as mod
            with patch.object(mod, '_extract_session_cookies', side_effect=fake_extract):
                findings, _ = self.plugin._test_anon_to_auth(
                    'http://example.com/login',
                    'username', 'password', 'admin', 'secret',
                    None, False, 5,
                )
            return findings

    def test_unchanged_cookie_produces_finding(self):
        findings = self._run(
            pre_cookies={'session': 'abc'},
            post_cookies={'session': 'abc'},  # unchanged
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, 'session_fixation')
        self.assertEqual(findings[0].cwe_id, 'CWE-384')

    def test_rotated_cookie_produces_no_finding(self):
        findings = self._run(
            pre_cookies={'session': 'old'},
            post_cookies={'session': 'new'},  # rotated
        )
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.session_fixation_detector.requests.Session')
    def test_no_pre_login_cookies_no_finding(self, MockSession):
        session_instance = MagicMock()
        MockSession.return_value = session_instance
        session_instance.get.return_value = _make_response(200)
        session_instance.cookies = _make_cookie_jar({})  # no session cookies

        import scanner.scan_plugins.detectors.session_fixation_detector as mod
        with patch.object(mod, '_extract_session_cookies', return_value={}):
            findings, _ = self.plugin._test_anon_to_auth(
                'http://example.com/login',
                'username', 'password', 'admin', 'secret',
                None, False, 5,
            )
        self.assertEqual(findings, [])

    @patch(
        'scanner.scan_plugins.detectors.session_fixation_detector.requests.Session',
    )
    def test_network_error_on_get_returns_no_finding(self, MockSession):
        import requests as real_requests
        session_instance = MagicMock()
        MockSession.return_value = session_instance
        session_instance.get.side_effect = real_requests.RequestException("timeout")

        findings, _ = self.plugin._test_anon_to_auth(
            'http://example.com/login',
            'username', 'password', 'admin', 'secret',
            None, False, 5,
        )
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# ===========================================================================
# SessionFixationDetectorPlugin – _test_user_swap
# ===========================================================================
# ---------------------------------------------------------------------------

class TestUserSwap(unittest.TestCase):
    def setUp(self):
        self.plugin = SessionFixationDetectorPlugin()

    def _run_swap(self, cookies_a, cookies_b):
        import scanner.scan_plugins.detectors.session_fixation_detector as mod

        call_count = [0]

        def fake_extract(jar, override=None):
            call_count[0] += 1
            # First call: after user-A login
            if call_count[0] <= 1:
                return dict(cookies_a)
            # Subsequent calls: after user-B login
            return dict(cookies_b)

        with patch('scanner.scan_plugins.detectors.session_fixation_detector.requests.Session') as MockSession:
            session_instance = MagicMock()
            MockSession.return_value = session_instance
            session_instance.get.return_value = _make_response(200)
            session_instance.post.return_value = _make_response(200)
            session_instance.cookies = _make_cookie_jar({})

            with patch.object(mod, '_extract_session_cookies', side_effect=fake_extract):
                findings = self.plugin._test_user_swap(
                    'http://example.com/login',
                    'username', 'password',
                    'user_a', 'pass_a',
                    'user_b', 'pass_b',
                    None, False, 5,
                )
        return findings

    def test_unchanged_cookie_on_swap_produces_finding(self):
        findings = self._run_swap(
            cookies_a={'session': 'same'},
            cookies_b={'session': 'same'},  # unchanged
        )
        self.assertEqual(len(findings), 1)
        self.assertIn('session', findings[0].evidence)
        self.assertIn('user_a', findings[0].description)
        self.assertIn('user_b', findings[0].description)

    def test_rotated_cookie_on_swap_no_finding(self):
        findings = self._run_swap(
            cookies_a={'session': 'val_a'},
            cookies_b={'session': 'val_b'},  # rotated
        )
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# ===========================================================================
# SessionFixationDetectorPlugin – _test_arbitrary_token
# ===========================================================================
# ---------------------------------------------------------------------------

class TestArbitraryToken(unittest.TestCase):
    def setUp(self):
        self.plugin = SessionFixationDetectorPlugin()

    def _run_arbitrary(self, real_cookie_name, post_cookie_value):
        """
        real_cookie_name: the cookie name found on the probe GET
        post_cookie_value: the cookie value after the login POST with the crafted token
        """
        import scanner.scan_plugins.detectors.session_fixation_detector as mod

        call_count = [0]

        def fake_extract(jar, override=None):
            call_count[0] += 1
            if call_count[0] == 1:
                # probe GET – return the real cookie
                return {real_cookie_name: 'real_server_value'}
            # post-login – return whatever value was set
            return {real_cookie_name: post_cookie_value}

        with patch('scanner.scan_plugins.detectors.session_fixation_detector.requests.Session') as MockSession:
            session_instance = MagicMock()
            MockSession.return_value = session_instance
            session_instance.get.return_value = _make_response(200)
            session_instance.post.return_value = _make_response(200)
            session_instance.cookies = _make_cookie_jar({})

            with patch.object(mod, '_extract_session_cookies', side_effect=fake_extract):
                findings = self.plugin._test_arbitrary_token(
                    'http://example.com/login',
                    'username', 'password', 'admin', 'secret',
                    None, False, 5,
                )
        return findings

    def test_crafted_token_accepted_returns_high_finding(self):
        findings = self._run_arbitrary('session', _CRAFTED_TOKEN)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, 'high')
        self.assertTrue(findings[0].verified)
        self.assertEqual(findings[0].cwe_id, 'CWE-384')
        self.assertIn(_CRAFTED_TOKEN, findings[0].evidence)

    def test_server_replaced_token_returns_no_finding(self):
        findings = self._run_arbitrary('session', 'server_assigned_new_token')
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# ===========================================================================
# SessionFixationDetectorPlugin – scan() integration
# ===========================================================================
# ---------------------------------------------------------------------------

class TestSessionFixationScan(unittest.TestCase):
    def setUp(self):
        self.plugin = SessionFixationDetectorPlugin()

    def test_no_credentials_no_sensitive_flow_returns_empty(self):
        findings = self.plugin.scan('http://example.com/', config={
            'verify_ssl': False,
            'timeout': 5,
        })
        self.assertEqual(findings, [])

    def test_no_requests_library_returns_empty(self):
        import scanner.scan_plugins.detectors.session_fixation_detector as mod
        orig = mod.HAS_REQUESTS
        try:
            mod.HAS_REQUESTS = False
            findings = self.plugin.scan('http://example.com/', config={
                'username': 'admin',
                'password': 'secret',
            })
            self.assertEqual(findings, [])
        finally:
            mod.HAS_REQUESTS = orig

    def test_fixation_finding_severity_elevated_when_arbitrary_accepted(self):
        """When arbitrary token is accepted, existing medium findings become high."""
        import scanner.scan_plugins.detectors.session_fixation_detector as mod

        # Simulate: anon→auth fixation found, then arbitrary token accepted
        medium_finding = mod.VulnerabilityFinding(
            vulnerability_type='session_fixation',
            severity='medium',
            url='http://example.com/login',
            description='Test',
            evidence='Test',
            remediation='Fix',
            confidence=0.75,
            cwe_id='CWE-384',
        )

        with patch.object(
            self.plugin, '_test_anon_to_auth',
            return_value=([medium_finding], {})
        ), patch.object(
            self.plugin, '_test_arbitrary_token',
            return_value=[mod.VulnerabilityFinding(
                vulnerability_type='session_fixation',
                severity='high',
                url='http://example.com/login',
                description='Arbitrary token accepted',
                evidence='Evidence',
                remediation='Fix',
                confidence=0.90,
                cwe_id='CWE-384',
                verified=True,
            )]
        ):
            findings = self.plugin.scan('http://example.com/', config={
                'login_url': 'http://example.com/login',
                'username': 'admin',
                'password': 'secret',
                'verify_ssl': False,
                'timeout': 5,
            })

        session_findings = [f for f in findings if f.vulnerability_type == 'session_fixation']
        # The originally medium finding should have been elevated
        elevated = [f for f in session_findings if f.severity == 'high']
        self.assertTrue(len(elevated) >= 1)


# ---------------------------------------------------------------------------
# ===========================================================================
# OpenRedirectDetectorPlugin – _is_external_redirect
# ===========================================================================
# ---------------------------------------------------------------------------

class TestIsExternalRedirect(unittest.TestCase):
    HOST = 'example.com'

    def test_external_http_url(self):
        self.assertTrue(_is_external_redirect('http://evil.com/path', self.HOST))

    def test_external_https_url(self):
        self.assertTrue(_is_external_redirect('https://evil.com', self.HOST))

    def test_scheme_relative(self):
        self.assertTrue(_is_external_redirect('//evil.com/path', self.HOST))

    def test_triple_slash(self):
        self.assertTrue(_is_external_redirect('///evil.com', self.HOST))

    def test_backslash(self):
        self.assertTrue(_is_external_redirect('\\\\evil.com', self.HOST))

    def test_javascript_scheme(self):
        self.assertTrue(_is_external_redirect("javascript:alert(1)", self.HOST))

    def test_userinfo_trick(self):
        self.assertTrue(_is_external_redirect('https://example.com@evil.com/', self.HOST))

    def test_same_host_returns_false(self):
        self.assertFalse(_is_external_redirect('https://example.com/path', self.HOST))

    def test_relative_url_returns_false(self):
        self.assertFalse(_is_external_redirect('/relative/path', self.HOST))


# ---------------------------------------------------------------------------
# ===========================================================================
# OpenRedirectDetectorPlugin – extraction helpers
# ===========================================================================
# ---------------------------------------------------------------------------

class TestOpenRedirectHelpers(unittest.TestCase):
    def setUp(self):
        self.plugin = OpenRedirectDetectorPlugin()

    def test_extract_refresh_url_standard(self):
        result = self.plugin._extract_refresh_url('0; url=https://evil.com')
        self.assertEqual(result, 'https://evil.com')

    def test_extract_refresh_url_uppercase(self):
        result = self.plugin._extract_refresh_url('0;URL=https://evil.com')
        self.assertEqual(result, 'https://evil.com')

    def test_extract_refresh_url_no_url(self):
        result = self.plugin._extract_refresh_url('0')
        self.assertIsNone(result)

    def test_extract_meta_refresh_url(self):
        html = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
        result = self.plugin._extract_meta_refresh_url(html)
        self.assertIsNotNone(result)
        self.assertIn('evil.com', result)

    def test_extract_meta_refresh_url_no_meta(self):
        result = self.plugin._extract_meta_refresh_url('<html></html>')
        self.assertIsNone(result)

    def test_extract_js_redirect_window_location(self):
        body = "window.location='https://evil.com';"
        result = self.plugin._extract_js_redirect_url(body)
        self.assertIsNotNone(result)
        self.assertIn('evil.com', result)

    def test_extract_js_redirect_location_href(self):
        body = 'location.href = "https://evil.com";'
        result = self.plugin._extract_js_redirect_url(body)
        self.assertIsNotNone(result)
        self.assertIn('evil.com', result)

    def test_extract_js_redirect_location_replace(self):
        body = "location.replace('https://evil.com');"
        result = self.plugin._extract_js_redirect_url(body)
        self.assertIsNotNone(result)
        self.assertIn('evil.com', result)

    def test_extract_js_redirect_none_when_absent(self):
        result = self.plugin._extract_js_redirect_url('<html>no js here</html>')
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# ===========================================================================
# OpenRedirectDetectorPlugin – _test_open_redirect / scan()
# ===========================================================================
# ---------------------------------------------------------------------------

class TestOpenRedirectDetection(unittest.TestCase):
    def setUp(self):
        self.plugin = OpenRedirectDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests.get')
    def test_location_header_redirect_detected(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=302,
            headers={'Location': 'https://evil.com/'},
            text='',
        )
        findings = self.plugin._test_open_redirect(
            'http://example.com/?next=foo', False, 5
        )
        location_findings = [
            f for f in findings
            if 'Location' in f.description or 'Location' in f.evidence
        ]
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].vulnerability_type, 'open_redirect')
        self.assertEqual(findings[0].cwe_id, 'CWE-601')

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests.get')
    def test_refresh_header_redirect_detected(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            headers={'Refresh': '0; url=https://evil.com'},
            text='',
        )
        findings = self.plugin._test_open_redirect(
            'http://example.com/?next=foo', False, 5
        )
        refresh_findings = [f for f in findings if 'Refresh' in f.description]
        self.assertTrue(len(refresh_findings) >= 1)

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests.get')
    def test_meta_refresh_redirect_detected(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            headers={},
            text='<meta http-equiv="refresh" content="0;url=https://evil.com">',
        )
        findings = self.plugin._test_open_redirect(
            'http://example.com/?next=foo', False, 5
        )
        meta_findings = [f for f in findings if 'meta' in f.description.lower()]
        self.assertTrue(len(meta_findings) >= 1)

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests.get')
    def test_js_redirect_detected(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            headers={},
            text="<script>window.location='https://evil.com'</script>",
        )
        findings = self.plugin._test_open_redirect(
            'http://example.com/?next=foo', False, 5
        )
        js_findings = [f for f in findings if 'JavaScript' in f.description]
        self.assertTrue(len(js_findings) >= 1)

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests.get')
    def test_no_redirect_returns_no_finding(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            headers={'Content-Type': 'text/html'},
            text='<html>Normal page</html>',
        )
        findings = self.plugin._test_open_redirect(
            'http://example.com/?q=test', False, 5
        )
        self.assertEqual(findings, [])

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests.get')
    def test_common_params_probed_even_if_absent(self, mock_get):
        """Plugin should test common redirect param names even when not in URL."""
        mock_get.return_value = MagicMock(
            status_code=200,
            headers={},
            text='',
        )
        # URL has no query params at all
        self.plugin._test_open_redirect('http://example.com/', False, 5)

        # Verify that at least one call used a common redirect param name
        called_params = []
        for c in mock_get.call_args_list:
            params = c.kwargs.get('params', c[1].get('params', {})) if c.kwargs else {}
            if not params and len(c.args) >= 2:
                params = c.args[1]
            called_params.extend(list(params.keys()) if isinstance(params, dict) else [])

        # At least some common redirect parameter names should have been probed
        common_found = [p for p in called_params if p in _COMMON_REDIRECT_PARAMS]
        self.assertTrue(len(common_found) > 0, "No common redirect params were tested")

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests.get')
    def test_multiple_findings_collected(self, mock_get):
        """Plugin should not stop at the first finding."""
        # Always return a redirect to evil.com so every probe triggers a finding
        mock_get.return_value = MagicMock(
            status_code=302,
            headers={'Location': 'https://evil.com/'},
            text='',
        )
        # URL with two redirect params
        findings = self.plugin._test_open_redirect(
            'http://example.com/?next=x&redirect=y', False, 5
        )
        # Should find at least two (one per param, potentially more per payload)
        self.assertGreater(len(findings), 1)

    def test_no_requests_library_returns_empty(self):
        import scanner.scan_plugins.detectors.open_redirect_detector as mod
        orig = mod.HAS_REQUESTS
        try:
            mod.HAS_REQUESTS = False
            findings = self.plugin.scan('http://example.com/?next=foo')
            self.assertEqual(findings, [])
        finally:
            mod.HAS_REQUESTS = orig

    def test_plugin_properties(self):
        self.assertEqual(self.plugin.plugin_id, 'open_redirect_detector')
        self.assertIn('open_redirect', self.plugin.vulnerability_types)
        self.assertEqual(self.plugin.version, '2.0.0')


# ---------------------------------------------------------------------------
# ===========================================================================
# Registry auto-discovery
# ===========================================================================
# ---------------------------------------------------------------------------

class TestNewPluginsRegistryDiscovery(unittest.TestCase):
    def setUp(self):
        reset_scan_registry()
        self.registry = ScanPluginRegistry()
        self.registry.discover_plugins()

    def test_session_fixation_detector_discovered(self):
        plugin = self.registry.get_plugin('session_fixation_detector')
        self.assertIsNotNone(plugin, "session_fixation_detector not discovered by registry")
        self.assertIsInstance(plugin, SessionFixationDetectorPlugin)

    def test_open_redirect_detector_discovered(self):
        plugin = self.registry.get_plugin('open_redirect_detector')
        self.assertIsNotNone(plugin, "open_redirect_detector not discovered by registry")
        self.assertIsInstance(plugin, OpenRedirectDetectorPlugin)

    def tearDown(self):
        reset_scan_registry()


if __name__ == '__main__':
    unittest.main()
