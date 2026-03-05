"""
Tests for false-positive reduction improvements addressing bug-bounty rejection issues.

Covers:
- Problem 1: DOM XSS per-script-block analysis, data-flow tracing, _is_self_xss() classifier
- Problem 2: XSS plugin verify() Self-XSS rejection via trigger_source
- Problem 3: CSP weakness detection with injection-point awareness
- Problem 4: Admin panel / debug mode improved detection
- Problem 5: VulnerabilityFinding bounty_likelihood field
"""

import sys
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
from scanner.scan_plugins.detectors.xss_scanner import XSSScannerPlugin
from scanner.scan_plugins.detectors.other_detector import OtherDetectorPlugin
from scanner.plugins.exploits.xss_plugin import XSSPlugin
from scanner.plugins.exploits.other_plugin import OtherPlugin


# ---------------------------------------------------------------------------
# Problem 5: bounty_likelihood field on VulnerabilityFinding
# ---------------------------------------------------------------------------

class TestBountyLikelihood:
    """bounty_likelihood maps confidence → expected bug-bounty acceptance."""

    def _finding(self, confidence: float) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            vulnerability_type='xss',
            severity='high',
            url='https://example.com',
            description='test',
            evidence='test',
            remediation='test',
            confidence=confidence,
        )

    def test_high_likelihood(self):
        assert self._finding(0.9).bounty_likelihood == 'high'
        assert self._finding(0.8).bounty_likelihood == 'high'

    def test_medium_likelihood(self):
        assert self._finding(0.79).bounty_likelihood == 'medium'
        assert self._finding(0.6).bounty_likelihood == 'medium'

    def test_low_likelihood(self):
        assert self._finding(0.59).bounty_likelihood == 'low'
        assert self._finding(0.4).bounty_likelihood == 'low'

    def test_informational_likelihood(self):
        assert self._finding(0.39).bounty_likelihood == 'informational'
        assert self._finding(0.0).bounty_likelihood == 'informational'

    def test_bounty_likelihood_in_to_dict(self):
        d = self._finding(0.9).to_dict()
        assert 'bounty_likelihood' in d
        assert d['bounty_likelihood'] == 'high'

    def test_self_xss_risk_in_to_dict_when_true(self):
        f = VulnerabilityFinding(
            vulnerability_type='xss', severity='low',
            url='https://example.com', description='t', evidence='e',
            remediation='r', self_xss_risk=True,
        )
        d = f.to_dict()
        assert d.get('self_xss_risk') is True

    def test_exploitability_confirmed_in_to_dict_when_true(self):
        f = VulnerabilityFinding(
            vulnerability_type='xss', severity='low',
            url='https://example.com', description='t', evidence='e',
            remediation='r', exploitability_confirmed=True,
        )
        d = f.to_dict()
        assert d.get('exploitability_confirmed') is True

    def test_requires_authentication_in_to_dict(self):
        f = VulnerabilityFinding(
            vulnerability_type='other', severity='medium',
            url='https://example.com', description='t', evidence='e',
            remediation='r', requires_authentication=False,
        )
        d = f.to_dict()
        assert d.get('requires_authentication') is False


# ---------------------------------------------------------------------------
# Problem 1: DOM XSS per-script-block analysis
# ---------------------------------------------------------------------------

class TestDomXSSScannerPlugin:
    plugin = XSSScannerPlugin()

    # ------------------------------------------------------------------
    # _is_self_xss
    # ------------------------------------------------------------------

    def test_url_controllable_source_is_not_self_xss(self):
        block = "var x = location.hash; el.innerHTML = x;"
        assert self.plugin._is_self_xss(block, ['location\\.hash'], ['innerHTML\\s*=']) is False

    def test_storage_only_source_is_self_xss(self):
        block = "var x = localStorage.getItem('key'); el.innerHTML = x;"
        assert self.plugin._is_self_xss(block, ['localStorage\\.'], ['innerHTML\\s*=']) is True

    def test_cookie_source_is_self_xss(self):
        block = "var x = document.cookie; el.innerHTML = x;"
        assert self.plugin._is_self_xss(block, ['document\\.cookie'], ['innerHTML\\s*=']) is True

    def test_referrer_is_not_self_xss(self):
        # document.referrer is URL-controllable via a Referer header
        block = "var x = document.referrer; el.innerHTML = x;"
        assert self.plugin._is_self_xss(block, ['document\\.referrer'], ['innerHTML\\s*=']) is False

    # ------------------------------------------------------------------
    # _has_sanitizer
    # ------------------------------------------------------------------

    def test_dompurify_sanitizer_detected(self):
        block = "var clean = DOMPurify.sanitize(x); el.innerHTML = clean;"
        assert self.plugin._has_sanitizer(block) is True

    def test_encode_uri_component_sanitizer_detected(self):
        block = "var safe = encodeURIComponent(location.hash); el.href = safe;"
        assert self.plugin._has_sanitizer(block) is True

    def test_no_sanitizer(self):
        block = "var x = location.hash; el.innerHTML = x;"
        assert self.plugin._has_sanitizer(block) is False

    # ------------------------------------------------------------------
    # _trace_dataflow
    # ------------------------------------------------------------------

    def test_dataflow_traced_simple(self):
        block = "var x = location.hash;\ndocument.getElementById('out').innerHTML = x;"
        result = self.plugin._trace_dataflow(
            block,
            [r'location\.hash'],
            [r'innerHTML\s*='],
        )
        assert result is not None
        assert 'x' in result

    def test_dataflow_not_traced_unrelated_vars(self):
        block = "var a = location.hash;\nel.innerHTML = someOtherVar;"
        result = self.plugin._trace_dataflow(
            block,
            [r'location\.hash'],
            [r'innerHTML\s*='],
        )
        assert result is None

    def test_dataflow_not_traced_no_source_assignment(self):
        block = "el.innerHTML = location.hash;"  # direct use without intermediate var
        result = self.plugin._trace_dataflow(
            block,
            [r'location\.hash'],
            [r'innerHTML\s*='],
        )
        assert result is None

    # ------------------------------------------------------------------
    # _check_dom_xss confidence and self_xss_risk
    # ------------------------------------------------------------------

    def _make_soup(self, script_content: str):
        try:
            from bs4 import BeautifulSoup
            html = f"<html><body><script>{script_content}</script></body></html>"
            return BeautifulSoup(html, 'html.parser'), html
        except ImportError:
            return MagicMock(), ''

    def test_no_finding_when_sink_and_source_in_different_blocks(self):
        """Sinks and sources in separate scripts should NOT produce a high-confidence finding."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return  # skip if bs4 unavailable
        html = (
            "<html><body>"
            "<script>var x = location.hash;</script>"
            "<script>document.getElementById('a').innerHTML = 'static';</script>"
            "</body></html>"
        )
        soup = BeautifulSoup(html, 'html.parser')
        findings = self.plugin._check_dom_xss('https://example.com', soup, html)
        # Each block individually: first has source but no sink; second has sink but no source
        # So no findings should be produced
        assert len(findings) == 0

    def test_confirmed_dataflow_high_confidence(self):
        """Traced data-flow from URL source to sink → confidence >= 0.7."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return
        script = "var x = location.hash;\ndocument.getElementById('out').innerHTML = x;"
        soup, html = self._make_soup(script)
        findings = self.plugin._check_dom_xss('https://example.com', soup, html)
        assert len(findings) == 1
        assert findings[0].confidence >= 0.7
        assert findings[0].self_xss_risk is False

    def test_storage_source_flagged_as_self_xss(self):
        """Storage-based source → self_xss_risk should be True."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return
        script = "var x = localStorage.getItem('k');\ndocument.getElementById('out').innerHTML = x;"
        soup, html = self._make_soup(script)
        findings = self.plugin._check_dom_xss('https://example.com', soup, html)
        assert len(findings) == 1
        assert findings[0].self_xss_risk is True

    def test_sanitizer_lowers_confidence(self):
        """Sanitizer present → confidence should be low (0.2)."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return
        script = (
            "var x = location.hash;\n"
            "var clean = DOMPurify.sanitize(x);\n"
            "document.getElementById('out').innerHTML = clean;"
        )
        soup, html = self._make_soup(script)
        findings = self.plugin._check_dom_xss('https://example.com', soup, html)
        assert len(findings) == 1
        assert findings[0].confidence == 0.2

    def test_sink_source_same_block_no_flow_gives_low_confidence(self):
        """Same block, URL-controllable source, no traced flow → confidence 0.2."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            return
        # Sink and source in same block, but no variable assignment flow
        script = "function setup() { if (location.hash) { el.innerHTML = 'other'; } }"
        soup, html = self._make_soup(script)
        findings = self.plugin._check_dom_xss('https://example.com', soup, html)
        assert len(findings) == 1
        assert findings[0].confidence == 0.2


# ---------------------------------------------------------------------------
# Problem 2: XSS plugin verify() – Self-XSS rejection
# ---------------------------------------------------------------------------

class TestXSSPluginVerifySelfXSS:
    plugin = XSSPlugin()

    def _make_result(self, trigger_source=None, alert=True, console_logs=None):
        dom_evidence = {
            'alert_triggered': alert,
        }
        if console_logs is not None:
            dom_evidence['console_logs'] = console_logs
        if trigger_source is not None:
            dom_evidence['trigger_source'] = trigger_source
        return {
            'success': True,
            'payload': '<script>alert(1)</script>',
            'dom_evidence': dom_evidence,
        }

    def test_missing_trigger_source_returns_false(self):
        """No trigger_source → Self-XSS, not verified."""
        result = self._make_result(trigger_source=None)
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False
        assert proof is not None
        assert 'Self-XSS' in proof

    def test_console_trigger_source_returns_false(self):
        """trigger_source='console' → Self-XSS, not verified."""
        result = self._make_result(trigger_source='console')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False
        assert 'Self-XSS' in proof

    def test_devtools_trigger_source_returns_false(self):
        """trigger_source='devtools' → Self-XSS, not verified."""
        result = self._make_result(trigger_source='devtools')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False
        assert 'Self-XSS' in proof

    def test_url_fragment_trigger_source_verified(self):
        """trigger_source='url_fragment' → legitimate, should be verified."""
        result = self._make_result(trigger_source='url_fragment')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True
        assert proof is not None
        assert 'VERIFIED' in proof

    def test_query_param_trigger_source_verified(self):
        """trigger_source='query_param' → legitimate, should be verified."""
        result = self._make_result(trigger_source='query_param')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True

    def test_form_post_trigger_source_verified(self):
        """trigger_source='form_post' → legitimate, should be verified."""
        result = self._make_result(trigger_source='form_post')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True


# ---------------------------------------------------------------------------
# Problem 3: CSP validation with injection point awareness
# ---------------------------------------------------------------------------

class TestCSPValidation:
    from scanner.scan_plugins.detectors.security_headers_scanner import SecurityHeadersScannerPlugin
    plugin = SecurityHeadersScannerPlugin()

    def test_unsafe_inline_with_input_high_confidence(self):
        """unsafe-inline + reflected inputs → keep medium severity, high confidence."""
        body = '<input name="q" value=""><script>alert(1)</script>'
        findings = self.plugin._validate_csp(
            'https://example.com',
            "script-src 'unsafe-inline'",
            body,
        )
        assert len(findings) >= 1
        f = findings[0]
        assert f.confidence >= 0.8
        assert f.exploitability_confirmed is True

    def test_unsafe_inline_without_input_downgraded(self):
        """unsafe-inline but no injection point → downgrade to low severity, lower confidence."""
        body = '<p>Hello world</p>'
        findings = self.plugin._validate_csp(
            'https://example.com',
            "script-src 'unsafe-inline'",
            body,
        )
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity == 'low'
        assert f.confidence <= 0.6
        assert f.exploitability_confirmed is False
        assert 'no injection point' in f.evidence.lower()

    def test_unsafe_eval_without_eval_pattern_downgraded(self):
        """unsafe-eval but no eval with user input → downgrade."""
        body = '<p>No eval here</p>'
        findings = self.plugin._validate_csp(
            'https://example.com',
            "script-src 'unsafe-eval'",
            body,
        )
        eval_findings = [f for f in findings if 'unsafe-eval' in f.evidence.lower()]
        assert len(eval_findings) >= 1
        f = eval_findings[0]
        assert f.exploitability_confirmed is False
        assert f.confidence <= 0.6

    def test_wildcard_with_script_src_confirmed(self):
        """Wildcard + external script tag → exploitability_confirmed=True."""
        body = '<script src="https://cdn.example.com/lib.js"></script>'
        findings = self.plugin._validate_csp(
            'https://example.com',
            "script-src *",
            body,
        )
        wildcard_findings = [f for f in findings if 'wildcard' in f.description.lower()]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0].exploitability_confirmed is True

    def test_wildcard_without_script_src_not_confirmed(self):
        """Wildcard but no external script tag → exploitability_confirmed=False."""
        body = '<p>Static page</p>'
        findings = self.plugin._validate_csp(
            'https://example.com',
            "script-src *",
            body,
        )
        wildcard_findings = [f for f in findings if 'wildcard' in f.description.lower()]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0].exploitability_confirmed is False


# ---------------------------------------------------------------------------
# Problem 4: Admin panel and debug mode detection
# ---------------------------------------------------------------------------

class TestOtherDetectorPlugin:
    plugin = OtherDetectorPlugin()

    # ------------------------------------------------------------------
    # _is_debug_output
    # ------------------------------------------------------------------

    def test_django_traceback_detected(self):
        text = "Traceback (most recent call last):\n  File \"/app/views.py\", line 42"
        assert self.plugin._is_debug_output(text) is True

    def test_php_error_detected(self):
        text = "Fatal error: Uncaught TypeError in /var/www/html/index.php on line 10"
        assert self.plugin._is_debug_output(text) is True

    def test_aspnet_yellow_screen_detected(self):
        text = "<title>Runtime Error</title><h1>Server Error in '/' Application.</h1>"
        assert self.plugin._is_debug_output(text) is True

    def test_word_debug_alone_not_detected(self):
        """Simple presence of 'DEBUG' in HTML is NOT a vulnerability."""
        text = "<p>Set LOG_LEVEL=DEBUG in your configuration file.</p>"
        assert self.plugin._is_debug_output(text) is False

    def test_trace_log_level_not_detected(self):
        text = "<p>Available log levels: DEBUG, INFO, WARN, ERROR, TRACE</p>"
        assert self.plugin._is_debug_output(text) is False

    # ------------------------------------------------------------------
    # _is_admin_accessible_without_auth
    # ------------------------------------------------------------------

    def test_login_form_only_is_not_vulnerable(self):
        """A login form at /admin is expected behaviour, not a vulnerability."""
        html = (
            "<html><body><form action='/admin/login'>"
            "<input type='text' name='username'>"
            "<input type='password' name='password'>"
            "<button>Log in</button></form>"
            "<a href='/forgot-password'>Forgot your password?</a>"
            "</body></html>"
        )
        assert self.plugin._is_admin_accessible_without_auth(html) is False

    def test_admin_dashboard_is_vulnerable(self):
        """Admin dashboard visible without auth IS a vulnerability."""
        html = (
            "<html><body>"
            "<h1>Admin Dashboard</h1>"
            "<a href='/admin/users'>Manage users</a>"
            "<a href='/logout'>Sign out</a>"
            "<p>Welcome, admin</p>"
            "</body></html>"
        )
        assert self.plugin._is_admin_accessible_without_auth(html) is True

    def test_phpmyadmin_accessible_is_vulnerable(self):
        html = "<html><body><h1>phpMyAdmin</h1><p>SQL Query:</p></body></html>"
        assert self.plugin._is_admin_accessible_without_auth(html) is True

    def test_admin_functionality_with_login_form_is_still_vulnerable(self):
        """
        If admin functionality indicators are present alongside a login form
        (e.g., partial dashboard visible), it should still be flagged as a vulnerability.
        """
        html = (
            "<html><body>"
            "<form action='/admin/login'><input type='password' name='password'></form>"
            "<h1>Admin Dashboard</h1>"
            "<a href='/admin/users'>Manage users</a>"
            "</body></html>"
        )
        assert self.plugin._is_admin_accessible_without_auth(html) is True

    # ------------------------------------------------------------------
    # _is_backup_file_with_sensitive_data
    # ------------------------------------------------------------------

    def test_sql_backup_detected(self):
        response = MagicMock()
        response.headers = {'Content-Type': 'application/octet-stream'}
        response.content = b'X' * 200
        response.text = "CREATE TABLE users (id INT, password VARCHAR);\nINSERT INTO users VALUES (1, 'secret');"
        assert self.plugin._is_backup_file_with_sensitive_data(response) is True

    def test_html_response_not_backup(self):
        """200 response returning HTML (homepage) is NOT a backup file finding."""
        response = MagicMock()
        response.headers = {'Content-Type': 'text/html; charset=utf-8'}
        response.content = b'<html><body>Homepage</body></html>'
        response.text = '<html><body>Homepage</body></html>'
        assert self.plugin._is_backup_file_with_sensitive_data(response) is False

    def test_tiny_response_not_backup(self):
        response = MagicMock()
        response.headers = {'Content-Type': 'application/octet-stream'}
        response.content = b'tiny'
        response.text = 'tiny'
        assert self.plugin._is_backup_file_with_sensitive_data(response) is False


# ---------------------------------------------------------------------------
# Problem 4: OtherPlugin execute_attack improvements
# ---------------------------------------------------------------------------

class TestOtherPlugin:
    plugin = OtherPlugin()

    def test_login_form_only_admin_not_reported(self):
        """Admin path returning a login form should NOT be reported as exposed_admin."""
        login_html = (
            "<html><body><form action='/admin/login'>"
            "<input type='text' name='username'>"
            "<input type='password' name='password'>"
            "<button>Log in</button></form></body></html>"
        )
        assert self.plugin._is_admin_accessible_without_auth(login_html) is False

    def test_admin_dashboard_reported(self):
        """Admin panel with content management visible should be reported."""
        dashboard_html = (
            "<html><body>"
            "<h1>Admin Dashboard</h1>"
            "<a href='/admin/users'>Manage users</a>"
            "<a href='/logout'>Sign out</a>"
            "</body></html>"
        )
        assert self.plugin._is_admin_accessible_without_auth(dashboard_html) is True

    def test_debug_word_alone_not_reported(self):
        """Plain 'DEBUG' text should NOT trigger debug_mode detection."""
        assert self.plugin._is_debug_output("<p>Set LOG_LEVEL=DEBUG</p>") is False

    def test_django_traceback_reported(self):
        """Django traceback in response SHOULD trigger debug_mode detection."""
        text = "Traceback (most recent call last):\n  File '/app/views.py', line 42"
        assert self.plugin._is_debug_output(text) is True
