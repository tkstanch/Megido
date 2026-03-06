"""
Tests for detection-based PoC evidence generation.

Covers:
- ProofReporter.generate_detection_proof(): builds ProofData from detection evidence
- build_detection_poc() helper
- InfoDisclosureDetectorPlugin: captures http_traffic in findings
- XSSPlugin: captures http_traffic in GET and form findings
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# ProofReporter.generate_detection_proof()
# ---------------------------------------------------------------------------

class TestProofReporterGenerateDetectionProof:
    """Tests for ProofReporter.generate_detection_proof()."""

    def _reporter(self):
        from scanner.proof_reporter import ProofReporter
        return ProofReporter(enable_visual_proof=False)

    def test_returns_proof_data_with_correct_type(self):
        reporter = self._reporter()
        proof = reporter.generate_detection_proof(
            vulnerability_type='info_disclosure',
            url='http://example.com',
            evidence='API key found',
            confidence=0.8,
        )
        assert proof.vulnerability_type == 'info_disclosure'

    def test_proof_data_is_not_verified(self):
        reporter = self._reporter()
        proof = reporter.generate_detection_proof(
            vulnerability_type='xss',
            url='http://example.com',
            evidence='XSS reflected',
            confidence=0.9,
        )
        assert proof.verified is False
        assert proof.success is False

    def test_proof_data_includes_http_request(self):
        reporter = self._reporter()
        traffic = {
            'request': {'method': 'GET', 'url': 'http://example.com', 'headers': {}, 'body': ''},
            'response': {'status_code': 200, 'headers': {}, 'body': 'ok'},
        }
        proof = reporter.generate_detection_proof(
            vulnerability_type='info_disclosure',
            url='http://example.com',
            evidence='data found',
            confidence=0.7,
            http_traffic=traffic,
        )
        assert len(proof.http_requests) == 1
        assert proof.http_requests[0]['method'] == 'GET'
        assert len(proof.http_responses) == 1
        assert proof.http_responses[0]['status_code'] == 200

    def test_proof_data_without_traffic(self):
        reporter = self._reporter()
        proof = reporter.generate_detection_proof(
            vulnerability_type='xss',
            url='http://example.com',
            evidence='something found',
            confidence=0.5,
            http_traffic=None,
        )
        assert len(proof.http_requests) == 0
        assert any('detection evidence' in log.lower() for log in proof.logs)

    def test_confidence_score_stored(self):
        reporter = self._reporter()
        proof = reporter.generate_detection_proof(
            vulnerability_type='sqli',
            url='http://example.com',
            evidence='error-based injection',
            confidence=0.65,
        )
        assert proof.confidence_score == 0.65

    def test_detection_only_metadata_set(self):
        reporter = self._reporter()
        proof = reporter.generate_detection_proof(
            vulnerability_type='cors',
            url='http://example.com',
            evidence='CORS misconfiguration',
            confidence=0.8,
        )
        assert proof.metadata.get('detection_only') is True

    def test_no_http_traffic_key_still_works(self):
        """generate_detection_proof should handle http_traffic with missing keys."""
        reporter = self._reporter()
        proof = reporter.generate_detection_proof(
            vulnerability_type='ssrf',
            url='http://example.com',
            evidence='SSRF found',
            confidence=0.75,
            http_traffic={'request': {'method': 'POST', 'url': 'http://example.com'}},
        )
        assert proof is not None


# ---------------------------------------------------------------------------
# build_detection_poc() helper
# ---------------------------------------------------------------------------

class TestBuildDetectionPocHelper:
    """Tests for proof_reporting_helpers.build_detection_poc()."""

    def test_returns_proof_data_object(self):
        from scanner.proof_reporting_helpers import build_detection_poc
        result = build_detection_poc(
            vulnerability_type='info_disclosure',
            url='http://example.com',
            evidence='API key exposed',
            confidence=0.8,
        )
        assert result is not None
        assert result.vulnerability_type == 'info_disclosure'

    def test_returns_none_gracefully_on_error(self):
        from scanner.proof_reporting_helpers import build_detection_poc
        # Should not raise even with unusual input
        result = build_detection_poc(
            vulnerability_type='',
            url='',
            evidence='',
            confidence=0.0,
        )
        # Either returns a ProofData or None — must not raise
        assert result is None or hasattr(result, 'vulnerability_type')

    def test_passes_http_traffic_through(self):
        from scanner.proof_reporting_helpers import build_detection_poc
        traffic = {
            'request': {'method': 'GET', 'url': 'http://example.com', 'headers': {}, 'body': ''},
            'response': {'status_code': 404, 'headers': {}, 'body': 'not found'},
        }
        result = build_detection_poc(
            vulnerability_type='info_disclosure',
            url='http://example.com',
            evidence='Something',
            confidence=0.6,
            http_traffic=traffic,
        )
        assert result is not None
        assert len(result.http_requests) == 1
        assert len(result.http_responses) == 1
        assert result.http_responses[0]['status_code'] == 404


# ---------------------------------------------------------------------------
# InfoDisclosureDetectorPlugin — http_traffic capture
# ---------------------------------------------------------------------------

class TestInfoDisclosureDetectorHTTPTraffic:
    """Verifies that InfoDisclosureDetectorPlugin populates http_traffic."""

    def test_finding_has_http_traffic_when_pattern_matched(self):
        from scanner.scan_plugins.detectors.info_disclosure_detector import InfoDisclosureDetectorPlugin

        mock_resp = MagicMock()
        mock_resp.text = 'AKIA1234567890ABCDEF'  # AWS key pattern
        mock_resp.status_code = 200
        mock_resp.headers = {'Content-Type': 'text/html'}

        with patch('requests.get', return_value=mock_resp):
            plugin = InfoDisclosureDetectorPlugin()
            findings = plugin.scan('http://example.com')

        assert len(findings) > 0
        for finding in findings:
            assert finding.http_traffic is not None
            assert isinstance(finding.http_traffic, dict)
            assert 'request' in finding.http_traffic
            assert 'response' in finding.http_traffic

    def test_http_traffic_request_method_is_get(self):
        from scanner.scan_plugins.detectors.info_disclosure_detector import InfoDisclosureDetectorPlugin

        mock_resp = MagicMock()
        mock_resp.text = 'password: s3cr3t123!'
        mock_resp.status_code = 200
        mock_resp.headers = {}

        with patch('requests.get', return_value=mock_resp):
            plugin = InfoDisclosureDetectorPlugin()
            findings = plugin.scan('http://example.com/page')

        assert len(findings) > 0
        assert findings[0].http_traffic['request']['method'] == 'GET'
        assert findings[0].http_traffic['request']['url'] == 'http://example.com/page'

    def test_http_traffic_response_status_code_captured(self):
        from scanner.scan_plugins.detectors.info_disclosure_detector import InfoDisclosureDetectorPlugin

        mock_resp = MagicMock()
        mock_resp.text = 'AKIA1234567890ABCDEF'
        mock_resp.status_code = 200
        mock_resp.headers = {'Server': 'Apache'}

        with patch('requests.get', return_value=mock_resp):
            plugin = InfoDisclosureDetectorPlugin()
            findings = plugin.scan('http://example.com')

        assert findings[0].http_traffic['response']['status_code'] == 200

    def test_all_findings_share_same_http_traffic(self):
        """All findings from one scan() call share the same request/response traffic."""
        from scanner.scan_plugins.detectors.info_disclosure_detector import InfoDisclosureDetectorPlugin

        # Include multiple patterns to generate multiple findings
        mock_resp = MagicMock()
        mock_resp.text = 'AKIA1234567890ABCDEF password: sekret'
        mock_resp.status_code = 200
        mock_resp.headers = {}

        with patch('requests.get', return_value=mock_resp):
            plugin = InfoDisclosureDetectorPlugin()
            findings = plugin.scan('http://example.com')

        assert len(findings) >= 2
        for f in findings:
            assert f.http_traffic['request']['url'] == 'http://example.com'
            assert f.http_traffic['response']['status_code'] == 200


# ---------------------------------------------------------------------------
# XSS scanner — http_traffic capture on GET reflected XSS
# ---------------------------------------------------------------------------

class TestXSSScannerGetReflectedHTTPTraffic:
    """Verifies XSSPlugin._test_reflected_xss_get populates http_traffic."""

    def test_get_xss_finding_has_http_traffic(self):
        from scanner.scan_plugins.detectors.xss_scanner import XSSScannerPlugin

        plugin = XSSScannerPlugin()

        # Build a mock response that reflects ANY payload marker
        import re as _re

        class ReflectingResponse:
            def __init__(self, url):
                from urllib.parse import urlparse, parse_qs
                params = parse_qs(urlparse(url).query)
                all_vals = [v for vals in params.values() for v in vals]
                self.text = ' '.join(all_vals) + ' xss reflected'
                self.status_code = 200
                self.headers = {}
                self.request = MagicMock()
                self.request.headers = {}

        session = MagicMock()

        def get_side_effect(url, **kwargs):
            return ReflectingResponse(url)

        session.get.side_effect = get_side_effect

        findings = plugin._test_reflected_xss_get(
            url='http://example.com/?q=test',
            session=session,
            payloads=['<script>alert(1)</script>'],
            verify_ssl=False,
            timeout=10,
        )

        assert len(findings) > 0
        f = findings[0]
        assert f.http_traffic is not None
        assert 'request' in f.http_traffic
        assert f.http_traffic['request']['method'] == 'GET'
        assert 'response' in f.http_traffic
        assert f.http_traffic['response']['status_code'] == 200

