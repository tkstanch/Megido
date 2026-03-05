"""
Unit tests for impact verification logic added to scanner plugins.

Tests cover:
- host_header_detector: password reset poisoning detection, generic body reflection downgrade
- clickjacking_detector: sensitive actions analysis, no-actions info downgrade
- sqli_scanner: data extraction attempt, confidence/verified update
- security_headers_scanner: impact categorization, hardening grouping
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Allow imports from repo root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scan_plugins.detectors.host_header_detector import HostHeaderDetectorPlugin
from scanner.scan_plugins.detectors.clickjacking_detector import ClickjackingDetectorPlugin
from scanner.scan_plugins.detectors.sqli_scanner import SQLiScannerPlugin
from scanner.scan_plugins.detectors.security_headers_scanner import SecurityHeadersScannerPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(text='', status_code=200, headers=None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {}
    return resp


# ---------------------------------------------------------------------------
# Host Header Detector tests
# ---------------------------------------------------------------------------

class TestHostHeaderDetector:
    plugin = HostHeaderDetectorPlugin()

    def test_is_reset_page_by_url(self):
        assert self.plugin._is_reset_page('https://example.com/forgot-password', '') is True
        assert self.plugin._is_reset_page('https://example.com/reset', '') is True
        assert self.plugin._is_reset_page('https://example.com/home', '') is False

    def test_is_reset_page_by_body(self):
        reset_body = '<form><input name="email"> forgot password reset link</form>'
        assert self.plugin._is_reset_page('https://example.com/', reset_body) is True

    def test_is_reset_page_generic_body(self):
        assert self.plugin._is_reset_page('https://example.com/', '<html>Welcome!</html>') is False

    def test_probe_host_header_generic_reflection_is_info(self):
        """Generic body reflection without a reset context → info severity."""
        baseline_text = 'Hello world'
        reflected_text = 'Hello evil.com world'
        probe_host = 'evil.com'

        # The probe response reflects the host but is not a reset page.
        # The reset-path probes return a 404 so poisoning is not confirmed.
        probe_resp = _mock_response(text=reflected_text, status_code=200)
        not_found_resp = _mock_response(text='Not Found', status_code=404)

        def side_effect(url, **kwargs):
            if any(p in url for p in ['/forgot', '/reset', '/recover', '/password']):
                return not_found_resp
            return probe_resp

        with patch('requests.get', side_effect=side_effect):
            finding = self.plugin._probe_host_header(
                'https://example.com/', probe_host, baseline_text,
                verify_ssl=False, timeout=5
            )

        assert finding is not None
        assert finding.severity == 'info'
        assert finding.confidence < 0.5
        assert finding.verified is False
        assert 'bounty_eligible: false' in finding.evidence

    def test_probe_host_header_reset_page_is_high(self):
        """Reflection on a reset page → high severity with verified=True."""
        baseline_text = 'Forgot your password?'
        reflected_text = f'Forgot your password? Reset link: http://evil.com/reset'

        mock_resp = _mock_response(text=reflected_text, status_code=200)

        # Make _check_password_reset_poisoning return None so we fall into
        # the _is_reset_page branch
        with patch('requests.get', return_value=mock_resp):
            finding = self.plugin._probe_host_header(
                'https://example.com/forgot', 'evil.com', baseline_text,
                verify_ssl=False, timeout=5
            )

        assert finding is not None
        assert finding.severity == 'high'
        assert finding.verified is True
        assert 'bounty_eligible: true' in finding.evidence

    def test_probe_host_header_location_reflection_is_high(self):
        """Reflection in Location header → high severity."""
        baseline_text = ''
        probe_host = 'evil.com'
        mock_resp = _mock_response(
            text='', status_code=302,
            headers={'Location': 'http://evil.com/redirect'}
        )

        with patch('requests.get', return_value=mock_resp):
            finding = self.plugin._probe_host_header(
                'https://example.com/', probe_host, baseline_text,
                verify_ssl=False, timeout=5
            )

        assert finding is not None
        assert finding.severity == 'high'
        assert 'bounty_eligible: true' in finding.evidence

    def test_check_password_reset_poisoning_returns_finding(self):
        """_check_password_reset_poisoning returns a finding when host is in reset response."""
        probe_host = 'evil.com'
        mock_resp = _mock_response(
            text='Your reset link: http://evil.com/reset?token=abc',
            status_code=200
        )

        with patch('requests.get', return_value=mock_resp):
            finding = self.plugin._check_password_reset_poisoning(
                'https://example.com/', probe_host, verify_ssl=False, timeout=5
            )

        assert finding is not None
        assert finding.severity == 'high'
        assert finding.verified is True
        assert 'bounty_eligible: true' in finding.evidence

    def test_check_password_reset_poisoning_no_reflection_returns_none(self):
        """_check_password_reset_poisoning returns None when host is not reflected."""
        mock_resp = _mock_response(text='Enter your email to reset your password.', status_code=200)

        with patch('requests.get', return_value=mock_resp):
            finding = self.plugin._check_password_reset_poisoning(
                'https://example.com/', 'evil.com', verify_ssl=False, timeout=5
            )

        assert finding is None


# ---------------------------------------------------------------------------
# Clickjacking Detector tests
# ---------------------------------------------------------------------------

class TestClickjackingDetector:
    plugin = ClickjackingDetectorPlugin()

    def test_check_sensitive_actions_empty_body(self):
        assert self.plugin._check_sensitive_actions('') == []

    def test_check_sensitive_actions_detects_password_input(self):
        html = '<form method="POST"><input name="password" type="password"></form>'
        actions = self.plugin._check_sensitive_actions(html)
        assert 'password input' in actions
        assert 'POST form' in actions

    def test_check_sensitive_actions_detects_email_input(self):
        html = '<form><input name="email"></form>'
        actions = self.plugin._check_sensitive_actions(html)
        assert 'email input' in actions

    def test_check_sensitive_actions_no_sensitive_elements(self):
        html = '<html><body><p>Hello world</p></body></html>'
        actions = self.plugin._check_sensitive_actions(html)
        assert actions == []

    def test_analyse_headers_no_protection_no_sensitive_actions_is_info(self):
        """HTML page without sensitive actions and no framing protection → info."""
        headers = {}  # no CSP, no XFO
        html_body = '<html><body><p>Read-only content</p></body></html>'

        findings = self.plugin._analyse_headers(
            'https://example.com/', headers,
            is_html=True, html_body=html_body
        )

        assert len(findings) == 1
        assert findings[0].severity == 'info'
        assert findings[0].confidence == 0.30
        assert 'bounty_eligible: false' in findings[0].evidence

    def test_analyse_headers_no_protection_with_sensitive_actions_is_high(self):
        """HTML page with sensitive forms and no framing protection → high."""
        headers = {}
        html_body = '<form method="POST"><input name="password" type="password"><input type="submit"></form>'

        findings = self.plugin._analyse_headers(
            'https://example.com/', headers,
            is_html=True, html_body=html_body
        )

        assert len(findings) == 1
        assert findings[0].severity == 'high'
        assert findings[0].confidence == 0.95
        assert 'bounty_eligible: true' in findings[0].evidence

    def test_analyse_headers_attack_scenario_in_description(self):
        """Findings should include an attack scenario description."""
        headers = {}
        html_body = '<form method="POST"><input name="email"><input type="submit"></form>'

        findings = self.plugin._analyse_headers(
            'https://example.com/', headers,
            is_html=True, html_body=html_body
        )

        assert len(findings) == 1
        assert 'Attack scenario' in findings[0].description

    def test_analyse_headers_protected_by_csp(self):
        """Page with strong CSP frame-ancestors should produce no findings."""
        headers = {'Content-Security-Policy': "frame-ancestors 'none'"}
        findings = self.plugin._analyse_headers(
            'https://example.com/', headers,
            is_html=True, html_body='<form method="POST"><input name="password"></form>'
        )
        assert findings == []

    def test_analyse_headers_protected_by_xfo(self):
        """Page with X-Frame-Options DENY should produce no findings."""
        headers = {'X-Frame-Options': 'DENY'}
        findings = self.plugin._analyse_headers(
            'https://example.com/', headers,
            is_html=True, html_body='<form method="POST"><input name="password"></form>'
        )
        assert findings == []


# ---------------------------------------------------------------------------
# SQLi Scanner tests
# ---------------------------------------------------------------------------

class TestSQLiDataExtraction:
    plugin = SQLiScannerPlugin()

    def test_attempt_data_extraction_error_based_success(self):
        """_attempt_data_extraction returns extracted data when markers present."""
        response_with_data = _mock_response(
            text="XPATH syntax error: '~8.0.32~root@localhost~mydb~'",
            status_code=200
        )

        with patch.object(self.plugin, '_send_request', return_value=response_with_data):
            result = self.plugin._attempt_data_extraction(
                'http://example.com/', 'GET', 'id', {'id': '1'},
                verify_ssl=False, timeout=5,
                technique='error', dbms='MySQL'
            )

        assert result is not None
        assert '8.0.32' in result or 'root@localhost' in result or 'mydb' in result

    def test_attempt_data_extraction_error_based_no_markers(self):
        """_attempt_data_extraction returns None when no markers found."""
        response_no_data = _mock_response(text='Some normal response', status_code=200)

        with patch.object(self.plugin, '_send_request', return_value=response_no_data):
            result = self.plugin._attempt_data_extraction(
                'http://example.com/', 'GET', 'id', {'id': '1'},
                verify_ssl=False, timeout=5,
                technique='error', dbms='MySQL'
            )

        assert result is None

    def test_error_based_detection_with_extraction_updates_confidence(self):
        """Error-based finding with successful extraction → confidence 0.99."""
        error_resp = _mock_response(
            text='you have an error in your sql syntax',
            status_code=200
        )
        extraction_resp = _mock_response(
            text="XPATH syntax error: '~8.0.32~'",
            status_code=200
        )

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return error_resp
            return extraction_resp

        with patch.object(self.plugin, '_send_request', side_effect=side_effect):
            finding = self.plugin._test_error_based(
                'http://example.com/', 'GET', 'id', {'id': '1'},
                verify_ssl=False, timeout=5
            )

        assert finding is not None
        assert finding.confidence == 0.99
        assert finding.verified is True
        assert 'Extracted data' in finding.evidence

    def test_error_based_detection_without_extraction_keeps_confidence(self):
        """Error-based finding without extraction → confidence 0.90, verified True."""
        error_resp = _mock_response(
            text='you have an error in your sql syntax',
            status_code=200
        )
        no_data_resp = _mock_response(text='ok', status_code=200)

        def side_effect(*args, **kwargs):
            if 'extractvalue' in str(args) or 'updatexml' in str(args):
                return no_data_resp
            return error_resp

        with patch.object(self.plugin, '_send_request', side_effect=side_effect):
            finding = self.plugin._test_error_based(
                'http://example.com/', 'GET', 'id', {'id': '1'},
                verify_ssl=False, timeout=5
            )

        assert finding is not None
        assert finding.confidence == 0.90
        assert finding.verified is True

    def test_attack_scenario_in_error_based_description(self):
        """Error-based finding should include attack scenario."""
        error_resp = _mock_response(
            text='you have an error in your sql syntax',
            status_code=200
        )
        no_data_resp = _mock_response(text='ok', status_code=200)

        with patch.object(self.plugin, '_send_request', side_effect=lambda *a, **kw: (
            error_resp if 'extractvalue' not in str(a) else no_data_resp
        )):
            finding = self.plugin._test_error_based(
                'http://example.com/', 'GET', 'id', {'id': '1'},
                verify_ssl=False, timeout=5
            )

        assert finding is not None
        assert 'Attack scenario' in finding.description


# ---------------------------------------------------------------------------
# Security Headers Scanner tests
# ---------------------------------------------------------------------------

class TestSecurityHeadersImpact:
    plugin = SecurityHeadersScannerPlugin()

    def test_assess_hsts_impact_with_login_form(self):
        """HSTS missing on page with login form → high severity."""
        body = '<form><input type="password" name="password"></form>'
        result = self.plugin._assess_header_impact(
            'Strict-Transport-Security', 'https://example.com', {}, body
        )
        assert result.get('severity') == 'high'
        assert 'Attack scenario' in result.get('note', '')

    def test_assess_hsts_impact_without_login_form(self):
        """HSTS missing on page without login form → info severity."""
        body = '<html><body>Welcome to our site</body></html>'
        result = self.plugin._assess_header_impact(
            'Strict-Transport-Security', 'https://example.com', {}, body
        )
        assert result.get('severity') == 'info'

    def test_assess_csp_impact_with_inline_scripts(self):
        """CSP missing on page with inline scripts → high severity."""
        body = '<html><script>alert(1)</script></html>'
        result = self.plugin._assess_header_impact(
            'Content-Security-Policy', 'https://example.com', {}, body
        )
        assert result.get('severity') == 'high'

    def test_assess_csp_impact_without_inline_scripts(self):
        """CSP missing on page without inline scripts → medium severity."""
        body = '<html><script src="/app.js"></script></html>'
        result = self.plugin._assess_header_impact(
            'Content-Security-Policy', 'https://example.com', {}, body
        )
        assert result.get('severity') == 'medium'

    def test_best_practice_headers_grouped_into_single_finding(self):
        """Best-practice headers produce a single grouped info finding."""
        headers = {}  # all headers missing
        body = '<html></html>'

        findings = self.plugin._check_missing_headers('https://example.com', headers, body)

        # Find grouped hardening finding
        hardening_findings = [
            f for f in findings
            if 'hardening recommendations' in f.description.lower()
        ]
        assert len(hardening_findings) == 1
        hardening = hardening_findings[0]
        assert hardening.severity == 'info'
        # All best-practice headers should be mentioned
        from scanner.scan_plugins.detectors.security_headers_scanner import _BEST_PRACTICE_HEADERS
        for hdr in _BEST_PRACTICE_HEADERS:
            assert hdr in hardening.description

    def test_exploitable_headers_reported_individually(self):
        """HSTS and CSP are reported as individual findings, not grouped."""
        headers = {}
        body = '<form><input type="password" name="password"></form>'

        findings = self.plugin._check_missing_headers('https://example.com', headers, body)

        types = [f.description for f in findings]
        hsts_findings = [f for f in findings if 'HSTS' in f.description or 'Strict-Transport-Security' in f.description]
        assert len(hsts_findings) >= 1

    def test_best_practice_note_in_grouped_finding(self):
        """Grouped finding should contain the best practice note."""
        from scanner.scan_plugins.detectors.security_headers_scanner import _BEST_PRACTICE_NOTE
        headers = {}
        body = ''

        findings = self.plugin._check_missing_headers('https://example.com', headers, body)

        hardening_findings = [
            f for f in findings
            if 'hardening recommendations' in f.description.lower()
        ]
        assert len(hardening_findings) == 1
        assert _BEST_PRACTICE_NOTE[:50] in hardening_findings[0].description


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
