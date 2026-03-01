"""
Tests for scanner.deduplication — focusing on the correlate() function.
"""

from django.test import SimpleTestCase

from scanner.deduplication import correlate, deduplicate
from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding


def _make_finding(vuln_type, url, param=None, severity='low', confidence=0.5, evidence='e'):
    return VulnerabilityFinding(
        vulnerability_type=vuln_type,
        severity=severity,
        url=url,
        description='desc',
        evidence=evidence,
        remediation='fix',
        parameter=param,
        confidence=confidence,
    )


class CorrelateGroupKeyTests(SimpleTestCase):
    """correlate() must include vulnerability_type in the group key."""

    def test_different_vuln_types_same_url_no_param_kept_separate(self):
        """
        Findings with different vulnerability types on the same URL (no param)
        must NOT be merged — they represent distinct issues.
        """
        findings = [
            _make_finding('missing_headers', 'https://example.com/'),
            _make_finding('csrf', 'https://example.com/'),
            _make_finding('cookie_security', 'https://example.com/'),
            _make_finding('info_disclosure', 'https://example.com/'),
        ]
        result = correlate(findings)
        self.assertEqual(len(result), 4)
        vuln_types = {f.vulnerability_type for f in result}
        self.assertEqual(vuln_types, {'missing_headers', 'csrf', 'cookie_security', 'info_disclosure'})

    def test_same_vuln_type_same_url_merged(self):
        """
        Multiple findings with the same vulnerability type on the same URL
        must be merged and confidence boosted.
        """
        findings = [
            _make_finding('xss', 'https://example.com/', confidence=0.5),
            _make_finding('xss', 'https://example.com/', confidence=0.6),
        ]
        result = correlate(findings)
        self.assertEqual(len(result), 1)
        # Confidence should be boosted (0.6 + 0.1 = 0.7)
        self.assertAlmostEqual(result[0].confidence, 0.7)

    def test_same_vuln_type_same_url_same_param_merged(self):
        """Multi-plugin confirmation for the same param+type must still merge."""
        findings = [
            _make_finding('sqli', 'https://example.com/', param='id', confidence=0.5),
            _make_finding('sqli', 'https://example.com/', param='id', confidence=0.7),
        ]
        result = correlate(findings)
        self.assertEqual(len(result), 1)
        self.assertAlmostEqual(result[0].confidence, 0.8)

    def test_different_vuln_types_same_url_same_param_kept_separate(self):
        """Different vuln types even on the same param must not be merged."""
        findings = [
            _make_finding('sqli', 'https://example.com/', param='id'),
            _make_finding('xss', 'https://example.com/', param='id'),
        ]
        result = correlate(findings)
        self.assertEqual(len(result), 2)

    def test_url_trailing_slash_normalised(self):
        """Trailing slashes on the URL must be normalised before grouping."""
        findings = [
            _make_finding('csrf', 'https://example.com', confidence=0.5),
            _make_finding('csrf', 'https://example.com/', confidence=0.6),
        ]
        result = correlate(findings)
        self.assertEqual(len(result), 1)

    def test_empty_input_returns_empty(self):
        self.assertEqual(correlate([]), [])

    def test_single_finding_returned_unchanged(self):
        finding = _make_finding('xss', 'https://example.com/')
        result = correlate([finding])
        self.assertEqual(len(result), 1)
        self.assertIs(result[0], finding)
