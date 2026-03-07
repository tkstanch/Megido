"""
Tests for TargetFingerprinter.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scan_plugins.fingerprinter import TargetFingerprinter, _TECH_PATTERNS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(headers=None, status_code=200):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


# ---------------------------------------------------------------------------
# Technology detection
# ---------------------------------------------------------------------------

class TestTechnologyDetection:
    def setup_method(self):
        self.fp = TargetFingerprinter(use_stealth_headers=False)

    def test_detects_nginx_from_server_header(self):
        headers = {'Server': 'nginx/1.20.1'}
        techs = self.fp._detect_technologies(headers)
        assert 'nginx' in techs

    def test_detects_apache_from_server_header(self):
        headers = {'Server': 'Apache/2.4.51 (Debian)'}
        techs = self.fp._detect_technologies(headers)
        assert 'apache' in techs

    def test_detects_php_from_x_powered_by(self):
        headers = {'X-Powered-By': 'PHP/8.1.0'}
        techs = self.fp._detect_technologies(headers)
        assert 'php' in techs

    def test_detects_aspnet_from_x_aspnet_version(self):
        headers = {'X-AspNet-Version': '4.0.30319'}
        techs = self.fp._detect_technologies(headers)
        assert 'asp.net' in techs

    def test_empty_headers_returns_empty_list(self):
        techs = self.fp._detect_technologies({})
        assert techs == []

    def test_multiple_technologies_detected(self):
        headers = {
            'Server': 'nginx/1.18',
            'X-Powered-By': 'PHP/7.4',
        }
        techs = self.fp._detect_technologies(headers)
        assert 'nginx' in techs
        assert 'php' in techs

    def test_no_duplicate_technologies(self):
        headers = {'Server': 'nginx nginx'}
        techs = self.fp._detect_technologies(headers)
        assert techs.count('nginx') == 1


# ---------------------------------------------------------------------------
# WAF detection
# ---------------------------------------------------------------------------

class TestWAFDetection:
    def setup_method(self):
        self.fp = TargetFingerprinter(use_stealth_headers=False)

    def test_detects_cloudflare_by_header(self):
        headers = {'CF-Ray': '1234567890abcdef-AMS'}
        waf = self.fp._detect_waf(headers)
        assert waf == 'Cloudflare'

    def test_detects_sucuri_by_header(self):
        headers = {'x-sucuri-id': 'abc123'}
        waf = self.fp._detect_waf(headers)
        assert waf == 'Sucuri'

    def test_no_waf_returns_none(self):
        headers = {'Server': 'nginx', 'Content-Type': 'text/html'}
        waf = self.fp._detect_waf(headers)
        assert waf is None

    def test_empty_headers_no_waf(self):
        assert self.fp._detect_waf({}) is None


# ---------------------------------------------------------------------------
# Rate limiting detection
# ---------------------------------------------------------------------------

class TestRateLimitingDetection:
    def setup_method(self):
        self.fp = TargetFingerprinter(use_stealth_headers=False)

    def test_429_triggers_rate_limit_flag(self):
        with patch('requests.get') as mock_get:
            mock_get.side_effect = [
                _mock_response(status_code=200, headers={'Server': 'nginx'}),
                _mock_response(status_code=429),
                _mock_response(status_code=200),
            ]
            result = self.fp.fingerprint('https://example.com')
        assert result['has_rate_limiting'] is True

    def test_no_rate_limiting_on_all_200s(self):
        headers = {'Server': 'nginx'}
        with patch('requests.get') as mock_get:
            mock_get.return_value = _mock_response(headers=headers)
            result = self.fp.fingerprint('https://example.com')
        # 3 consistent fast 200s should not trigger rate limiting
        assert result['has_rate_limiting'] is False


# ---------------------------------------------------------------------------
# Interesting headers
# ---------------------------------------------------------------------------

class TestInterestingHeaders:
    def setup_method(self):
        self.fp = TargetFingerprinter(use_stealth_headers=False)

    def test_csp_listed_as_interesting(self):
        headers = {'Content-Security-Policy': "default-src 'self'"}
        interesting = self.fp._find_interesting_headers(headers)
        assert 'content-security-policy' in interesting

    def test_missing_security_header_not_listed(self):
        headers = {'Content-Type': 'text/html'}
        interesting = self.fp._find_interesting_headers(headers)
        assert 'content-security-policy' not in interesting

    def test_server_always_interesting_when_present(self):
        headers = {'Server': 'Apache'}
        interesting = self.fp._find_interesting_headers(headers)
        assert 'server' in interesting


# ---------------------------------------------------------------------------
# fingerprint() integration
# ---------------------------------------------------------------------------

class TestFingerprintIntegration:
    def setup_method(self):
        self.fp = TargetFingerprinter(use_stealth_headers=False)

    def test_fingerprint_returns_all_keys(self):
        expected_keys = [
            'waf_detected', 'waf_name', 'technologies', 'response_time_ms',
            'has_rate_limiting', 'ssl_info', 'server_headers', 'interesting_headers',
            'detected_frameworks', 'api_endpoints_hint',
        ]
        with patch('requests.get', return_value=_mock_response(headers={'Server': 'nginx'})):
            result = self.fp.fingerprint('https://example.com')
        for key in expected_keys:
            assert key in result, f"Missing key: {key}"

    def test_fingerprint_gracefully_handles_connection_error(self):
        with patch('requests.get', side_effect=Exception('connection refused')):
            result = self.fp.fingerprint('https://unreachable.example')
        # Should still return a dict with defaults
        assert isinstance(result, dict)
        assert result['waf_detected'] is False
