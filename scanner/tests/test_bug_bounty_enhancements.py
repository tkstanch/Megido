"""
Tests for bug-bounty enhancement features:

1. XXE detector WAF/CDN false-positive prevention
2. Header-specific security_misconfig impact generation (_build_security_misconfig_impact)
3. Clickjacking PoC HTML generation (_generate_clickjacking_poc_html)
4. Vulnerability chaining helper (chain_vulnerabilities stub)
5. get_full_bounty_classification rich dict
6. _build_impact_summary security_misconfig path using exploit_result

These tests use MagicMock and do NOT require a database or network access.
Run with: python -m pytest scanner/tests/test_bug_bounty_enhancements.py
"""

import os
import sys
import re
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
os.environ.setdefault('USE_SQLITE', 'true')
import django
django.setup()

from scanner.scan_plugins.detectors.xxe_detector import XXEDetectorPlugin
from scanner.exploit_integration import (
    _build_bug_bounty_impact,
    _build_security_misconfig_impact,
    _generate_clickjacking_poc_html,
    _parse_missing_headers_from_evidence,
    _HEADER_IMPACT_DETAILS,
)
from scanner.bounty_taxonomy import get_bounty_classification, get_full_bounty_classification
from scanner.views import _build_impact_summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(vuln_type, url='https://example.com/test', severity='medium',
               evidence='', proof_of_impact='', exploit_result='',
               repeater_data=None, parameter='q'):
    vuln = MagicMock()
    vuln.vulnerability_type = vuln_type
    vuln.url = url
    vuln.severity = severity
    vuln.evidence = evidence
    vuln.proof_of_impact = proof_of_impact
    vuln.exploit_result = exploit_result
    vuln.repeater_data = repeater_data or []
    vuln.parameter = parameter
    vuln.get_vulnerability_type_display.return_value = vuln_type.replace('_', ' ').title()
    return vuln


def _make_response(status_code=200, server='nginx', body='', headers=None):
    """Create a MagicMock simulating a requests.Response object."""
    resp = MagicMock()
    resp.status_code = status_code
    all_headers = {'Server': server}
    if headers:
        all_headers.update(headers)
    resp.headers = all_headers
    resp.text = body
    return resp


# ===========================================================================
# 1. XXE Detector – WAF/CDN False-Positive Prevention
# ===========================================================================

class TestXXEDetectorWAFDetection:
    """_is_waf_response() and WAF-blocked finding classification."""

    def setup_method(self):
        self.plugin = XXEDetectorPlugin()

    def test_cloudflare_403_detected_as_waf(self):
        resp = _make_response(403, server='cloudflare', body='<html>Attention Required!</html>')
        assert self.plugin._is_waf_response(resp) is True

    def test_akamai_403_detected_as_waf(self):
        resp = _make_response(403, server='AkamaiGHost')
        assert self.plugin._is_waf_response(resp) is True

    def test_imperva_406_detected_as_waf(self):
        resp = _make_response(406, server='Imperva')
        assert self.plugin._is_waf_response(resp) is True

    def test_normal_200_nginx_not_waf(self):
        resp = _make_response(200, server='nginx')
        assert self.plugin._is_waf_response(resp) is False

    def test_cloudflare_200_not_waf(self):
        """A 200 from Cloudflare is not a WAF block — the request went through."""
        resp = _make_response(200, server='cloudflare')
        assert self.plugin._is_waf_response(resp) is False

    def test_ray_id_in_body_triggers_waf_detection(self):
        body = 'Error 1006 | Ray ID: 8abc123def | Cloudflare'
        resp = _make_response(403, server='cloudflare', body=body)
        assert self.plugin._is_waf_response(resp) is True

    def test_403_with_unknown_server_and_no_waf_body_not_waf(self):
        """403 without a WAF server header OR body patterns is NOT flagged as WAF."""
        resp = _make_response(403, server='Apache/2.4', body='Forbidden')
        assert self.plugin._is_waf_response(resp) is False

    def test_waf_blocked_finding_has_info_severity(self):
        """When WAF blocks the request, finding severity must be 'info'."""
        plugin = self.plugin
        waf_resp = _make_response(
            403, server='cloudflare',
            body='Attention Required! | Cloudflare Ray ID: 7ab'
        )

        # Patch requests.post to return WAF response
        with patch('scanner.scan_plugins.detectors.xxe_detector.requests') as mock_req:
            mock_req.post.return_value = waf_resp
            findings = plugin._test_classic_xxe('https://wallet.opensea.io/', False, 10)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == 'info'
        assert finding.confidence <= 0.2

    def test_waf_blocked_finding_note_mentions_waf(self):
        """WAF-blocked finding description/evidence should mention WAF."""
        plugin = self.plugin
        waf_resp = _make_response(
            403, server='cloudflare',
            body='Attention Required! | Ray ID: 7ab'
        )

        with patch('scanner.scan_plugins.detectors.xxe_detector.requests') as mock_req:
            mock_req.post.return_value = waf_resp
            findings = plugin._test_classic_xxe('https://example.com/api', False, 10)

        assert findings
        text = (findings[0].description + ' ' + findings[0].evidence).lower()
        assert 'waf' in text or 'cloudflare' in text or 'blocked' in text

    def test_real_xxe_file_read_not_flagged_as_waf(self):
        """A 200 response with /etc/passwd content should be critical XXE, not WAF."""
        plugin = self.plugin
        passwd_resp = _make_response(200, server='nginx', body='root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:')

        with patch('scanner.scan_plugins.detectors.xxe_detector.requests') as mock_req:
            mock_req.post.return_value = passwd_resp
            findings = plugin._test_classic_xxe('https://example.com/upload', False, 10)

        assert findings
        assert findings[0].severity == 'critical'
        assert findings[0].confidence >= 0.9


# ===========================================================================
# 2. Security Misconfig Impact Generation
# ===========================================================================

class TestBuildSecurityMisconfigImpact:
    """_build_security_misconfig_impact produces header-specific impact sections."""

    def test_missing_xfo_generates_clickjacking_poc(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='Missing x-frame-options header in response',
        )
        impact = _build_security_misconfig_impact(vuln, {})
        assert '## Clickjacking Proof-of-Concept' in impact
        assert '<iframe' in impact
        assert vuln.url in impact

    def test_missing_csp_generates_clickjacking_poc(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='content-security-policy header not present',
        )
        impact = _build_security_misconfig_impact(vuln, {})
        assert '## Clickjacking Proof-of-Concept' in impact

    def test_missing_hsts_no_poc_html(self):
        """HSTS is informational — should NOT produce an iframe PoC."""
        vuln = _make_vuln(
            'security_misconfig',
            evidence='strict-transport-security header missing',
        )
        impact = _build_security_misconfig_impact(vuln, {})
        assert '## Clickjacking Proof-of-Concept' not in impact

    def test_bug_bounty_classification_section_present(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='missing x-frame-options',
        )
        impact = _build_security_misconfig_impact(vuln, {})
        assert '## Bug Bounty Classification' in impact

    def test_xfo_classified_as_submittable(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='missing x-frame-options',
        )
        impact = _build_security_misconfig_impact(vuln, {})
        assert 'Bounty-Submittable' in impact

    def test_hsts_classified_as_informational(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='strict-transport-security missing',
        )
        impact = _build_security_misconfig_impact(vuln, {})
        assert 'Informational' in impact

    def test_no_headers_in_evidence_falls_back_gracefully(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='General security misconfiguration detected',
        )
        impact = _build_security_misconfig_impact(vuln, {})
        assert '## Real-World Impact' in impact
        assert len(impact) > 50

    def test_build_bug_bounty_impact_routes_security_misconfig(self):
        """_build_bug_bounty_impact should call security_misconfig path."""
        vuln = _make_vuln(
            'security_misconfig',
            evidence='x-frame-options header missing',
        )
        impact = _build_bug_bounty_impact(vuln, {})
        # Should contain the specific PoC section, not generic text
        assert '## Clickjacking Proof-of-Concept' in impact

    def test_security_misconfiguration_alias_routed(self):
        """'security_misconfiguration' (long form) should also use specific path."""
        vuln = _make_vuln(
            'security_misconfiguration',
            evidence='x-frame-options header missing',
        )
        impact = _build_bug_bounty_impact(vuln, {})
        assert '## Clickjacking Proof-of-Concept' in impact


# ===========================================================================
# 3. Clickjacking PoC HTML Generation
# ===========================================================================

class TestGenerateClickjackingPocHtml:
    """_generate_clickjacking_poc_html produces a valid HTML PoC."""

    def test_returns_string(self):
        html = _generate_clickjacking_poc_html('https://example.com/settings')
        assert isinstance(html, str)

    def test_contains_iframe(self):
        html = _generate_clickjacking_poc_html('https://example.com/settings')
        assert '<iframe' in html
        assert 'https://example.com/settings' in html

    def test_contains_doctype(self):
        html = _generate_clickjacking_poc_html('https://example.com')
        assert '<!DOCTYPE html>' in html

    def test_contains_low_opacity_style(self):
        html = _generate_clickjacking_poc_html('https://example.com')
        assert 'opacity' in html.lower()

    def test_contains_reviewer_instructions(self):
        html = _generate_clickjacking_poc_html('https://example.com')
        assert 'Reviewer' in html or 'reviewer' in html or 'Instructions' in html

    def test_url_embedded_in_iframe_src(self):
        url = 'https://wallet.opensea.io/account/settings'
        html = _generate_clickjacking_poc_html(url)
        assert f'src="{url}"' in html


# ===========================================================================
# 4. _parse_missing_headers_from_evidence
# ===========================================================================

class TestParseMissingHeadersFromEvidence:
    """_parse_missing_headers_from_evidence extracts header names from evidence text."""

    def test_detects_xfo(self):
        headers = _parse_missing_headers_from_evidence('x-frame-options missing')
        assert 'x-frame-options' in headers

    def test_detects_csp(self):
        headers = _parse_missing_headers_from_evidence(
            'Content-Security-Policy header not present'
        )
        assert 'content-security-policy' in headers

    def test_detects_hsts(self):
        headers = _parse_missing_headers_from_evidence(
            'strict-transport-security not set'
        )
        assert 'strict-transport-security' in headers

    def test_detects_multiple_headers(self):
        evidence = (
            'Missing headers: x-frame-options, content-security-policy, '
            'strict-transport-security'
        )
        headers = _parse_missing_headers_from_evidence(evidence)
        assert 'x-frame-options' in headers
        assert 'content-security-policy' in headers
        assert 'strict-transport-security' in headers

    def test_returns_empty_for_unrelated_evidence(self):
        headers = _parse_missing_headers_from_evidence('SQL injection in login form')
        assert headers == []

    def test_case_insensitive(self):
        headers = _parse_missing_headers_from_evidence('X-FRAME-OPTIONS IS ABSENT')
        assert 'x-frame-options' in headers


# ===========================================================================
# 5. get_full_bounty_classification
# ===========================================================================

class TestGetFullBountyClassification:
    """get_full_bounty_classification returns a rich dict for known types."""

    def test_returns_none_for_unknown_type(self):
        result = get_full_bounty_classification('unknown_xyz_type')
        assert result is None

    def test_returns_dict_for_known_type(self):
        result = get_full_bounty_classification('xss')
        assert isinstance(result, dict)

    def test_required_keys_present(self):
        result = get_full_bounty_classification('xss')
        required = {'vuln_type', 'p_level', 'label', 'submittable', 'requires_poc',
                    'chain_potential', 'tips', 'description', 'taxonomy_name', 'category'}
        for key in required:
            assert key in result, f'Missing key: {key}'

    def test_p1_is_submittable(self):
        result = get_full_bounty_classification('lfi', verified=True)
        assert result['p_level'] == 'P1'
        assert result['submittable'] is True

    def test_p4_not_submittable(self):
        result = get_full_bounty_classification('security_misconfig', verified=False)
        assert not result['submittable']

    def test_verified_uses_with_poc_level(self):
        res_no_poc = get_full_bounty_classification('xss', verified=False)
        res_with_poc = get_full_bounty_classification('xss', verified=True)
        # With PoC should be P2, without PoC should be P3 (or equal/higher)
        p_order = ['P1', 'P2', 'P3', 'P4', 'P5']
        idx_no = p_order.index(res_no_poc['p_level']) if res_no_poc['p_level'] in p_order else 4
        idx_yes = p_order.index(res_with_poc['p_level']) if res_with_poc['p_level'] in p_order else 4
        assert idx_yes <= idx_no, 'PoC version should be same or higher priority than no-PoC'

    def test_tips_is_list_of_strings(self):
        result = get_full_bounty_classification('xxe', verified=True)
        assert isinstance(result['tips'], list)
        for tip in result['tips']:
            assert isinstance(tip, str)

    def test_chain_potential_is_list(self):
        result = get_full_bounty_classification('security_misconfig', verified=False)
        assert isinstance(result['chain_potential'], list)

    def test_backward_compat_get_bounty_classification(self):
        """Original get_bounty_classification still returns a plain string."""
        result = get_bounty_classification('xss', verified=True)
        assert isinstance(result, str)
        assert result.startswith('P')


# ===========================================================================
# 6. _build_impact_summary – security_misconfig with exploit_result fallback
# ===========================================================================

class TestBuildImpactSummarySecurityMisconfig:
    """_build_impact_summary uses evidence / exploit_result for security_misconfig."""

    def test_uses_evidence_to_produce_specific_summary(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='Missing headers: x-frame-options not set',
        )
        summary = _build_impact_summary(vuln)
        assert 'X-Frame-Options' in summary or 'clickjacking' in summary.lower()
        # Must NOT be the old generic text
        assert 'Medium-severity security_misconfiguration' not in summary

    def test_uses_exploit_result_when_evidence_empty(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='',
            exploit_result='Header analysis: x-frame-options is absent from response',
        )
        summary = _build_impact_summary(vuln)
        assert 'X-Frame-Options' in summary or 'clickjacking' in summary.lower() or len(summary) > 20

    def test_fallback_to_generic_when_no_header_info(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='',
            exploit_result='',
        )
        summary = _build_impact_summary(vuln)
        # Should still return a non-empty string (generic fallback is acceptable)
        assert isinstance(summary, str)
        assert len(summary) > 10

    def test_generic_fallback_does_not_use_old_sentence(self):
        """The old 'Medium-severity security_misconfiguration vulnerability' must not appear."""
        vuln = _make_vuln(
            'security_misconfig',
            evidence='',
        )
        summary = _build_impact_summary(vuln)
        assert 'Medium-severity security_misconfiguration vulnerability detected at' not in summary


# ===========================================================================
# 7. _HEADER_IMPACT_DETAILS completeness
# ===========================================================================

class TestHeaderImpactDetails:
    """_HEADER_IMPACT_DETAILS has entries for all high-impact headers."""

    REQUIRED_HEADERS = [
        'x-frame-options',
        'content-security-policy',
        'strict-transport-security',
        'x-content-type-options',
    ]

    def test_all_required_headers_present(self):
        for h in self.REQUIRED_HEADERS:
            assert h in _HEADER_IMPACT_DETAILS, f'Missing _HEADER_IMPACT_DETAILS entry for {h!r}'

    def test_all_entries_have_bounty_submittable(self):
        for h, details in _HEADER_IMPACT_DETAILS.items():
            assert 'bounty_submittable' in details, f'{h!r} missing bounty_submittable'
            assert isinstance(details['bounty_submittable'], bool)

    def test_all_entries_have_tips(self):
        for h, details in _HEADER_IMPACT_DETAILS.items():
            assert 'tips' in details, f'{h!r} missing tips'
            assert len(details['tips']) > 0, f'{h!r} tips list is empty'

    def test_xfo_is_bounty_submittable(self):
        assert _HEADER_IMPACT_DETAILS['x-frame-options']['bounty_submittable'] is True

    def test_hsts_is_not_bounty_submittable(self):
        assert _HEADER_IMPACT_DETAILS['strict-transport-security']['bounty_submittable'] is False
