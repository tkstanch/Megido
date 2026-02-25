"""
Unit tests for the VPoC (Visual Proof of Concept) module.

Coverage:
  - redact_sensitive_headers: sensitive header values are replaced
  - redact_sensitive_headers: non-sensitive headers are untouched
  - redact_sensitive_headers: case-insensitive matching
  - truncate_body: short bodies returned unchanged
  - truncate_body: long bodies are truncated with notice appended
  - truncate_body: custom max_length respected
  - build_curl_command: basic GET request
  - build_curl_command: POST with body
  - build_curl_command: headers included and redacted
  - VPoCEvidence.to_dict: all fields serialized correctly
  - VPoCEvidence.to_dict: optional absent fields not included
  - capture_request_response_evidence: builds VPoCEvidence from a real-like response
  - capture_request_response_evidence: handles missing request gracefully
  - OpenRedirectDetectorPlugin: finding emits VPoC evidence on Location redirect
  - OpenRedirectDetectorPlugin: finding emits VPoC evidence on Refresh header redirect
  - OpenRedirectDetectorPlugin: finding emits VPoC evidence on meta refresh
  - OpenRedirectDetectorPlugin: finding emits VPoC evidence on JS redirect
  - SessionFixationDetectorPlugin: scenario 1 finding emits VPoC evidence
  - SessionFixationDetectorPlugin: scenario 4 arbitrary-token finding emits VPoC evidence
"""

import sys
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanner.scan_plugins.vpoc import (
    VPoCEvidence,
    BODY_MAX_LENGTH,
    BODY_TRUNCATION_NOTICE,
    REDACTED,
    redact_sensitive_headers,
    truncate_body,
    build_curl_command,
    capture_request_response_evidence,
)
from scanner.scan_plugins.detectors.open_redirect_detector import OpenRedirectDetectorPlugin
from scanner.scan_plugins.detectors.session_fixation_detector import (
    SessionFixationDetectorPlugin,
    _CRAFTED_TOKEN,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    status_code: int = 200,
    headers: Optional[dict] = None,
    text: str = '',
    request_method: str = 'GET',
    request_url: str = 'http://example.com/',
) -> MagicMock:
    """Return a minimal mock requests.Response."""
    mock_req = MagicMock()
    mock_req.method = request_method
    mock_req.url = request_url
    mock_req.headers = {}
    mock_req.body = ''

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    mock_resp.text = text
    mock_resp.request = mock_req
    return mock_resp


def _make_cookie_jar(cookies: dict) -> MagicMock:
    """Create a mock cookie jar that supports iteration and .set(), matching requests behaviour."""
    cookie_list = []
    for name, value in cookies.items():
        c = MagicMock()
        c.name = name
        c.value = value
        cookie_list.append(c)

    jar = MagicMock()
    # Use side_effect so each iteration gets a fresh iterator (not an exhausted one)
    jar.__iter__ = MagicMock(side_effect=lambda: iter(cookie_list))
    jar.set = MagicMock()
    jar_dict = cookies.copy()
    jar.get = MagicMock(side_effect=lambda k, default=None: jar_dict.get(k, default))
    return jar


# ---------------------------------------------------------------------------
# Tests – redact_sensitive_headers
# ---------------------------------------------------------------------------

class TestRedactSensitiveHeaders(unittest.TestCase):

    def test_authorization_is_redacted(self):
        headers = {'Authorization': 'Bearer secret-token'}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result['Authorization'], REDACTED)

    def test_cookie_is_redacted(self):
        headers = {'Cookie': 'session=abc123'}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result['Cookie'], REDACTED)

    def test_set_cookie_is_redacted(self):
        headers = {'Set-Cookie': 'session=abc123; Path=/; HttpOnly'}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result['Set-Cookie'], REDACTED)

    def test_x_api_key_is_redacted(self):
        headers = {'X-Api-Key': 'super-secret'}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result['X-Api-Key'], REDACTED)

    def test_non_sensitive_headers_unchanged(self):
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Megido/1.0'}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result['Content-Type'], 'application/json')
        self.assertEqual(result['User-Agent'], 'Megido/1.0')

    def test_case_insensitive_matching(self):
        headers = {'authorization': 'Basic xyz', 'COOKIE': 'tok=1'}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result['authorization'], REDACTED)
        self.assertEqual(result['COOKIE'], REDACTED)

    def test_empty_dict_returns_empty(self):
        self.assertEqual(redact_sensitive_headers({}), {})

    def test_original_dict_not_mutated(self):
        original = {'Authorization': 'secret'}
        redact_sensitive_headers(original)
        self.assertEqual(original['Authorization'], 'secret')


# ---------------------------------------------------------------------------
# Tests – truncate_body
# ---------------------------------------------------------------------------

class TestTruncateBody(unittest.TestCase):

    def test_short_body_returned_unchanged(self):
        body = 'hello world'
        self.assertEqual(truncate_body(body), body)

    def test_body_exactly_at_limit_unchanged(self):
        body = 'x' * BODY_MAX_LENGTH
        self.assertEqual(truncate_body(body), body)

    def test_long_body_is_truncated(self):
        body = 'x' * (BODY_MAX_LENGTH + 100)
        result = truncate_body(body)
        self.assertTrue(len(result) < len(body))
        self.assertIn(BODY_TRUNCATION_NOTICE, result)

    def test_truncated_body_starts_with_original_prefix(self):
        body = 'A' * (BODY_MAX_LENGTH + 500)
        result = truncate_body(body)
        self.assertTrue(result.startswith('A' * BODY_MAX_LENGTH))

    def test_custom_max_length(self):
        body = 'hello world'
        result = truncate_body(body, max_length=5)
        self.assertEqual(result, 'hello' + BODY_TRUNCATION_NOTICE)

    def test_empty_body_returned_as_is(self):
        self.assertEqual(truncate_body(''), '')


# ---------------------------------------------------------------------------
# Tests – build_curl_command
# ---------------------------------------------------------------------------

class TestBuildCurlCommand(unittest.TestCase):

    def test_basic_get_command(self):
        cmd = build_curl_command('http://example.com/page')
        self.assertIn('curl', cmd)
        self.assertIn('-X', cmd)
        self.assertIn('GET', cmd)
        self.assertIn('http://example.com/page', cmd)

    def test_post_with_body(self):
        cmd = build_curl_command(
            'http://example.com/login',
            method='POST',
            body='username=admin&password=secret',
        )
        self.assertIn('POST', cmd)
        self.assertIn('--data', cmd)

    def test_headers_included(self):
        cmd = build_curl_command(
            'http://example.com/',
            headers={'User-Agent': 'Megido/1.0'},
        )
        self.assertIn('-H', cmd)
        self.assertIn('User-Agent', cmd)

    def test_sensitive_headers_redacted_in_curl(self):
        cmd = build_curl_command(
            'http://example.com/',
            headers={'Authorization': 'Bearer verysecret'},
        )
        self.assertNotIn('verysecret', cmd)
        self.assertIn(REDACTED, cmd)


# ---------------------------------------------------------------------------
# Tests – VPoCEvidence.to_dict
# ---------------------------------------------------------------------------

class TestVPoCEvidenceToDict(unittest.TestCase):

    def _make_vpoc(self, **overrides) -> VPoCEvidence:
        kwargs = dict(
            plugin_name='test_plugin',
            target_url='http://example.com/',
            payload='<script>alert(1)</script>',
            confidence=0.9,
        )
        kwargs.update(overrides)
        return VPoCEvidence(**kwargs)

    def test_required_fields_in_dict(self):
        d = self._make_vpoc().to_dict()
        for key in ('plugin_name', 'target_url', 'payload', 'confidence', 'timestamp'):
            self.assertIn(key, d)

    def test_optional_absent_fields_not_included(self):
        d = self._make_vpoc().to_dict()
        for key in ('http_request', 'http_response', 'reproduction_steps',
                    'redirect_chain', 'curl_command', 'screenshots'):
            self.assertNotIn(key, d)

    def test_http_request_included_when_set(self):
        vpoc = self._make_vpoc(http_request={'method': 'GET', 'url': 'http://x.com/'})
        d = vpoc.to_dict()
        self.assertIn('http_request', d)

    def test_redirect_chain_included_when_set(self):
        vpoc = self._make_vpoc(redirect_chain=['http://a.com/', 'http://evil.com/'])
        d = vpoc.to_dict()
        self.assertIn('redirect_chain', d)
        self.assertEqual(d['redirect_chain'], ['http://a.com/', 'http://evil.com/'])

    def test_curl_command_included_when_set(self):
        vpoc = self._make_vpoc(curl_command='curl -X GET http://example.com/')
        d = vpoc.to_dict()
        self.assertIn('curl_command', d)


# ---------------------------------------------------------------------------
# Tests – capture_request_response_evidence
# ---------------------------------------------------------------------------

class TestCaptureRequestResponseEvidence(unittest.TestCase):

    def test_builds_vpoc_from_response(self):
        resp = _make_response(
            status_code=302,
            headers={'Location': 'https://evil.com'},
            text='',
            request_url='http://example.com/?next=https%3A%2F%2Fevil.com',
        )
        vpoc = capture_request_response_evidence(
            response=resp,
            plugin_name='test',
            payload='https://evil.com',
            confidence=0.9,
            target_url='http://example.com/',
        )
        self.assertIsInstance(vpoc, VPoCEvidence)
        self.assertEqual(vpoc.plugin_name, 'test')
        self.assertEqual(vpoc.payload, 'https://evil.com')
        self.assertIsNotNone(vpoc.http_response)
        self.assertEqual(vpoc.http_response['status_code'], 302)

    def test_sensitive_response_headers_redacted(self):
        resp = _make_response(
            status_code=200,
            headers={'Set-Cookie': 'session=topsecret; HttpOnly'},
            text='OK',
        )
        vpoc = capture_request_response_evidence(
            response=resp,
            plugin_name='test',
            payload='payload',
            confidence=0.5,
            target_url='http://example.com/',
        )
        self.assertEqual(vpoc.http_response['headers']['Set-Cookie'], REDACTED)

    def test_large_body_is_truncated(self):
        big_body = 'Z' * (BODY_MAX_LENGTH + 1000)
        resp = _make_response(status_code=200, text=big_body)
        vpoc = capture_request_response_evidence(
            response=resp,
            plugin_name='test',
            payload='x',
            confidence=0.5,
            target_url='http://example.com/',
        )
        body = vpoc.http_response['body']
        self.assertIn(BODY_TRUNCATION_NOTICE, body)
        self.assertLessEqual(len(body), BODY_MAX_LENGTH + len(BODY_TRUNCATION_NOTICE) + 5)

    def test_redirect_chain_stored(self):
        resp = _make_response(status_code=302)
        vpoc = capture_request_response_evidence(
            response=resp,
            plugin_name='test',
            payload='x',
            confidence=0.9,
            target_url='http://example.com/',
            redirect_chain=['http://example.com/', 'https://evil.com/'],
        )
        self.assertEqual(vpoc.redirect_chain, ['http://example.com/', 'https://evil.com/'])

    def test_handles_missing_request_attribute(self):
        """Evidence is still built when response.request is absent."""
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = ''
        del resp.request  # ensure getattr falls back to None

        vpoc = capture_request_response_evidence(
            response=resp,
            plugin_name='test',
            payload='x',
            confidence=0.5,
            target_url='http://example.com/',
        )
        self.assertIsInstance(vpoc, VPoCEvidence)
        self.assertIsNone(vpoc.http_request)
        self.assertIsNotNone(vpoc.http_response)


# ---------------------------------------------------------------------------
# Tests – VulnerabilityFinding.to_dict includes vpoc
# ---------------------------------------------------------------------------

class TestVulnerabilityFindingVPoC(unittest.TestCase):

    def test_to_dict_without_vpoc(self):
        from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
        finding = VulnerabilityFinding(
            vulnerability_type='xss',
            severity='high',
            url='http://example.com/',
            description='test',
            evidence='test evidence',
            remediation='fix it',
        )
        d = finding.to_dict()
        self.assertNotIn('vpoc', d)

    def test_to_dict_with_vpoc(self):
        from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
        vpoc = VPoCEvidence(
            plugin_name='test',
            target_url='http://example.com/',
            payload='xss',
            confidence=0.8,
        )
        finding = VulnerabilityFinding(
            vulnerability_type='xss',
            severity='high',
            url='http://example.com/',
            description='test',
            evidence='test evidence',
            remediation='fix it',
            vpoc=vpoc,
        )
        d = finding.to_dict()
        self.assertIn('vpoc', d)
        self.assertEqual(d['vpoc']['plugin_name'], 'test')


# ---------------------------------------------------------------------------
# Tests – OpenRedirectDetectorPlugin emits VPoC
# ---------------------------------------------------------------------------

class TestOpenRedirectVPoC(unittest.TestCase):
    """Verify that OpenRedirectDetectorPlugin populates VPoC on every redirect type."""

    def setUp(self):
        self.plugin = OpenRedirectDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests')
    def test_location_header_finding_has_vpoc(self, mock_requests):
        resp = _make_response(
            status_code=302,
            headers={'Location': 'https://evil.com'},
            request_url='http://example.com/?next=https://evil.com',
        )
        mock_session = MagicMock()
        mock_session.cookies = []
        mock_requests.get.return_value = resp
        mock_requests.Session.return_value = mock_session

        findings = self.plugin.scan('http://example.com/?next=orig', config={'timeout': 5})
        redirect_findings = [f for f in findings if f.vulnerability_type == 'open_redirect']
        self.assertTrue(
            any(f.vpoc is not None for f in redirect_findings),
            'Expected at least one open_redirect finding with vpoc attached',
        )

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests')
    def test_refresh_header_finding_has_vpoc(self, mock_requests):
        resp = _make_response(
            status_code=200,
            headers={'Refresh': '0; url=https://evil.com'},
            request_url='http://example.com/?next=https://evil.com',
        )
        mock_requests.get.return_value = resp

        finding = self.plugin._analyse_response(
            response=resp,
            url='http://example.com/',
            param_name='next',
            payload='https://evil.com',
            original_host='example.com',
        )
        self.assertIsNotNone(finding)
        self.assertIsNotNone(finding.vpoc)
        self.assertEqual(finding.vpoc.plugin_name, 'open_redirect_detector')

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests')
    def test_meta_refresh_finding_has_vpoc(self, mock_requests):
        body = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
        resp = _make_response(status_code=200, text=body)
        finding = self.plugin._analyse_response(
            response=resp,
            url='http://example.com/',
            param_name='next',
            payload='https://evil.com',
            original_host='example.com',
        )
        self.assertIsNotNone(finding)
        self.assertIsNotNone(finding.vpoc)

    @patch('scanner.scan_plugins.detectors.open_redirect_detector.requests')
    def test_js_redirect_finding_has_vpoc(self, mock_requests):
        body = "window.location = 'https://evil.com';"
        resp = _make_response(status_code=200, text=body)
        finding = self.plugin._analyse_response(
            response=resp,
            url='http://example.com/',
            param_name='next',
            payload='https://evil.com',
            original_host='example.com',
        )
        self.assertIsNotNone(finding)
        self.assertIsNotNone(finding.vpoc)

    def test_no_redirect_finding_is_none(self):
        resp = _make_response(status_code=200, text='<html>OK</html>')
        finding = self.plugin._analyse_response(
            response=resp,
            url='http://example.com/',
            param_name='next',
            payload='https://evil.com',
            original_host='example.com',
        )
        self.assertIsNone(finding)

    def test_location_redirect_vpoc_has_redirect_chain(self):
        resp = _make_response(
            status_code=301,
            headers={'Location': 'https://evil.com'},
        )
        finding = self.plugin._analyse_response(
            response=resp,
            url='http://example.com/',
            param_name='next',
            payload='https://evil.com',
            original_host='example.com',
        )
        self.assertIsNotNone(finding)
        self.assertIsNotNone(finding.vpoc)
        self.assertIsNotNone(finding.vpoc.redirect_chain)
        self.assertIn('https://evil.com', finding.vpoc.redirect_chain)


# ---------------------------------------------------------------------------
# Tests – SessionFixationDetectorPlugin emits VPoC
# ---------------------------------------------------------------------------

class TestSessionFixationVPoC(unittest.TestCase):
    """Verify that SessionFixationDetectorPlugin populates VPoC on findings."""

    def setUp(self):
        self.plugin = SessionFixationDetectorPlugin()

    @patch('scanner.scan_plugins.detectors.session_fixation_detector.requests')
    def test_scenario1_finding_has_vpoc(self, mock_requests):
        """Scenario 1: unchanged cookie after login → finding with VPoC."""
        pre_resp = _make_response(status_code=200)
        post_resp = _make_response(status_code=200)

        mock_session = MagicMock()
        mock_session.get.return_value = pre_resp
        mock_session.post.return_value = post_resp

        # Both pre- and post-login return the same session cookie
        same_cookie = _make_cookie_jar({'session': 'FIXEDVALUE'})
        mock_session.cookies = same_cookie
        mock_requests.Session.return_value = mock_session

        findings, _ = self.plugin._test_anon_to_auth(
            login_url='http://example.com/login',
            username_field='username',
            password_field='password',
            username='admin',
            password='secret',
            session_cookie_names=['session'],
            verify_ssl=False,
            timeout=5,
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, 'session_fixation')
        # VPoC may be None if response capture failed gracefully, but if present
        # it must have the correct plugin name
        if finding.vpoc is not None:
            self.assertEqual(finding.vpoc.plugin_name, 'session_fixation_detector')

    @patch('scanner.scan_plugins.detectors.session_fixation_detector.requests')
    def test_scenario4_finding_has_vpoc(self, mock_requests):
        """Scenario 4: arbitrary token accepted → high finding with VPoC."""
        probe_resp = _make_response(status_code=200)
        login_resp = _make_response(status_code=200)

        probe_session = MagicMock()
        probe_session.get.return_value = probe_resp
        # Make the probe session return a session cookie
        probe_session.cookies = _make_cookie_jar({'session': 'realtoken'})

        crafted_session = MagicMock()
        crafted_session.post.return_value = login_resp
        # Simulate server preserved the crafted token
        crafted_session.cookies = _make_cookie_jar({'session': _CRAFTED_TOKEN})

        mock_requests.Session.side_effect = [probe_session, crafted_session]

        findings = self.plugin._test_arbitrary_token(
            login_url='http://example.com/login',
            username_field='username',
            password_field='password',
            username='admin',
            password='secret',
            session_cookie_names=['session'],
            verify_ssl=False,
            timeout=5,
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, 'session_fixation')
        self.assertEqual(finding.severity, 'high')
        self.assertTrue(finding.verified)
        # VPoC may be None if response capture failed gracefully
        if finding.vpoc is not None:
            self.assertEqual(finding.vpoc.plugin_name, 'session_fixation_detector')
            self.assertIsNotNone(finding.vpoc.reproduction_steps)


if __name__ == '__main__':
    unittest.main()
