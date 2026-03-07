"""
Tests for ResultEnricher.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
from scanner.scan_plugins.result_enricher import (
    ResultEnricher,
    _CVSS_TABLE,
    _CWE_MAP,
    _REFERENCES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(vuln_type='xss', severity='high', remediation='Default remediation.'):
    return VulnerabilityFinding(
        vulnerability_type=vuln_type,
        severity=severity,
        url='https://example.com',
        description='Test',
        evidence='evidence',
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# CVSS estimation
# ---------------------------------------------------------------------------

class TestCVSSEstimation:
    def setup_method(self):
        self.enricher = ResultEnricher()

    def test_xss_high_severity(self):
        score = self.enricher._get_cvss_estimate('xss', 'high')
        assert score == 6.1

    def test_sqli_critical(self):
        score = self.enricher._get_cvss_estimate('sqli', 'critical')
        assert score == 9.8

    def test_rce_critical(self):
        score = self.enricher._get_cvss_estimate('rce', 'critical')
        assert score == 9.8

    def test_unknown_type_uses_severity_fallback(self):
        score = self.enricher._get_cvss_estimate('unknown_type', 'high')
        assert score == 7.5  # fallback

    def test_all_defined_vuln_types_have_scores(self):
        for vuln_type in _CVSS_TABLE:
            for severity in ('critical', 'high', 'medium', 'low'):
                score = self.enricher._get_cvss_estimate(vuln_type, severity)
                assert 0.0 <= score <= 10.0, (
                    f"Score out of range for {vuln_type}/{severity}: {score}"
                )


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------

class TestCWEMapping:
    def setup_method(self):
        self.enricher = ResultEnricher()

    def test_xss_mapped_to_cwe79(self):
        assert self.enricher._get_cwe_mapping('xss') == 'CWE-79'

    def test_sqli_mapped_to_cwe89(self):
        assert self.enricher._get_cwe_mapping('sqli') == 'CWE-89'

    def test_csrf_mapped_to_cwe352(self):
        assert self.enricher._get_cwe_mapping('csrf') == 'CWE-352'

    def test_rce_mapped_to_cwe78(self):
        assert self.enricher._get_cwe_mapping('rce') == 'CWE-78'

    def test_ssrf_mapped_to_cwe918(self):
        assert self.enricher._get_cwe_mapping('ssrf') == 'CWE-918'

    def test_unknown_type_returns_none(self):
        assert self.enricher._get_cwe_mapping('not_a_real_vuln') is None

    def test_all_common_vuln_types_have_cwe_mapping(self):
        common_types = [
            'xss', 'sqli', 'csrf', 'xxe', 'rce', 'lfi', 'rfi',
            'ssrf', 'info_disclosure', 'idor', 'cors', 'deserialization',
        ]
        for vtype in common_types:
            cwe = self.enricher._get_cwe_mapping(vtype)
            assert cwe is not None, f"No CWE mapping for {vtype}"
            assert cwe.startswith('CWE-'), f"Invalid CWE format for {vtype}: {cwe}"


# ---------------------------------------------------------------------------
# Reference generation
# ---------------------------------------------------------------------------

class TestReferenceGeneration:
    def setup_method(self):
        self.enricher = ResultEnricher()

    def test_xss_references_not_empty(self):
        refs = self.enricher._get_references('xss')
        assert len(refs) > 0

    def test_sqli_contains_owasp_link(self):
        refs = self.enricher._get_references('sqli')
        assert any('owasp.org' in r for r in refs)

    def test_unknown_type_returns_generic_references(self):
        refs = self.enricher._get_references('unknown_vuln')
        assert len(refs) > 0  # falls back to 'other'

    def test_all_defined_types_have_references(self):
        for vuln_type in _REFERENCES:
            refs = self.enricher._get_references(vuln_type)
            assert len(refs) > 0, f"No references for {vuln_type}"


# ---------------------------------------------------------------------------
# Risk score (via VulnerabilityFinding.risk_score property)
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_risk_score_increases_with_severity(self):
        low = _make_finding(severity='low')
        high = _make_finding(severity='high')
        assert high.risk_score > low.risk_score

    def test_risk_score_range(self):
        finding = _make_finding(severity='critical')
        finding.confidence = 1.0
        finding.cvss_score = 10.0
        assert 0.0 <= finding.risk_score <= 100.0

    def test_risk_score_zero_confidence(self):
        finding = _make_finding(severity='low')
        finding.confidence = 0.0
        finding.cvss_score = 0.0
        assert finding.risk_score >= 0.0

    def test_risk_score_with_waf_active(self):
        """WAF presence currently does not directly alter risk_score;
        test that it remains valid after enrichment."""
        enricher = ResultEnricher()
        finding = _make_finding(severity='high')
        fingerprint = {'waf_detected': True, 'technologies': []}
        enriched = enricher.enrich(finding, fingerprint)
        assert 0.0 <= enriched.risk_score <= 100.0


# ---------------------------------------------------------------------------
# enrich() integration
# ---------------------------------------------------------------------------

class TestEnrichIntegration:
    def setup_method(self):
        self.enricher = ResultEnricher()

    def test_enrich_sets_cvss_score(self):
        finding = _make_finding('xss', 'high')
        self.enricher.enrich(finding)
        assert finding.cvss_score is not None
        assert isinstance(finding.cvss_score, float)

    def test_enrich_sets_cwe_id(self):
        finding = _make_finding('sqli')
        self.enricher.enrich(finding)
        assert finding.cwe_id == 'CWE-89'

    def test_enrich_sets_references(self):
        finding = _make_finding('xss')
        self.enricher.enrich(finding)
        assert finding.references is not None
        assert len(finding.references) > 0

    def test_enrich_sets_attack_complexity(self):
        finding = _make_finding('xss')
        self.enricher.enrich(finding)
        assert finding.attack_complexity in ('low', 'high')

    def test_enrich_does_not_overwrite_existing_cwe(self):
        finding = _make_finding('xss')
        finding.cwe_id = 'CWE-999'
        self.enricher.enrich(finding)
        assert finding.cwe_id == 'CWE-999'

    def test_enrich_does_not_overwrite_existing_cvss(self):
        finding = _make_finding('xss')
        finding.cvss_score = 1.1
        self.enricher.enrich(finding)
        assert finding.cvss_score == 1.1

    def test_enrich_adds_tech_remediation(self):
        finding = _make_finding('xss')
        fingerprint = {'technologies': ['php'], 'waf_detected': False}
        self.enricher.enrich(finding, fingerprint)
        assert 'php' in finding.remediation.lower() or 'htmlspecialchars' in finding.remediation

    def test_enrich_no_fingerprint_still_works(self):
        finding = _make_finding('rce', 'critical')
        self.enricher.enrich(finding, None)
        assert finding.cvss_score is not None

    def test_attack_complexity_high_for_csrf(self):
        finding = _make_finding('csrf')
        self.enricher.enrich(finding)
        assert finding.attack_complexity == 'high'

    def test_attack_complexity_low_for_xss(self):
        finding = _make_finding('xss')
        self.enricher.enrich(finding)
        assert finding.attack_complexity == 'low'
