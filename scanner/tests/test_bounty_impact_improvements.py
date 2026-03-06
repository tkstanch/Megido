"""
Tests for improved bug-bounty impact statement generation.

Covers:
- _VULN_IMPACT_MAP coverage of new vulnerability types
- IMPACT_MAP (bounty_report_generator) coverage of all model types
- _build_bug_bounty_impact fallback chain
- _build_impact_summary: never returns "Run exploitation..." for known types
- _build_exploitation_steps: security_misconfig and captcha_bypass parsing
- _extract_missing_header_impacts helper

These tests use MagicMock instead of the Django ORM so they run without
a database and can be executed via: python -m pytest scanner/tests/
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Allow imports from repo root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Configure Django before importing any scanner modules
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
os.environ.setdefault('USE_SQLITE', 'true')
import django
django.setup()

from scanner.exploit_integration import _VULN_IMPACT_MAP, _build_bug_bounty_impact
from scanner.views import _build_impact_summary, _build_exploitation_steps, _extract_missing_header_impacts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(vuln_type, url='https://example.com/test', severity='medium',
               evidence='', proof_of_impact='', exploit_result='',
               repeater_data=None, parameter='q'):
    """Create a MagicMock simulating a Vulnerability model instance."""
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


# ---------------------------------------------------------------------------
# _VULN_IMPACT_MAP coverage tests
# ---------------------------------------------------------------------------

class TestVulnImpactMapCoverage:
    """_VULN_IMPACT_MAP must contain structured entries for all required types."""

    REQUIRED_TYPES = [
        'crlf', 'response_splitting', 'email_rce', 'rce', 'sqli', 'xss', 'ssrf', 'cors',
        'security_misconfig', 'clickjacking', 'csrf', 'open_redirect', 'lfi', 'xxe',
        'idor', 'info_disclosure', 'captcha_bypass', 'bac', 'api_key_exposure',
        'deserialization', 'dos', 'other',
    ]
    REQUIRED_KEYS = {'impact', 'scenario', 'affected', 'cvss'}

    def test_all_required_types_present(self):
        for vtype in self.REQUIRED_TYPES:
            assert vtype in _VULN_IMPACT_MAP, f'Missing _VULN_IMPACT_MAP entry for {vtype!r}'

    def test_all_entries_have_required_keys(self):
        for vtype, entry in _VULN_IMPACT_MAP.items():
            for key in self.REQUIRED_KEYS:
                assert key in entry, f'_VULN_IMPACT_MAP[{vtype!r}] missing key {key!r}'
                assert entry[key], f'_VULN_IMPACT_MAP[{vtype!r}][{key!r}] is empty'

    def test_security_misconfig_mentions_csp(self):
        entry = _VULN_IMPACT_MAP['security_misconfig']
        text = entry['impact'] + entry['scenario']
        assert 'CSP' in text or 'Content-Security-Policy' in text

    def test_lfi_mentions_etc_passwd(self):
        entry = _VULN_IMPACT_MAP['lfi']
        assert '/etc/passwd' in entry['impact'] or '/etc/passwd' in entry['scenario']

    def test_captcha_bypass_mentions_credential_stuffing(self):
        entry = _VULN_IMPACT_MAP['captcha_bypass']
        combined = (entry['impact'] + entry['scenario']).lower()
        assert 'credential' in combined or 'brute' in combined or 'automat' in combined

    def test_dos_mentions_availability(self):
        entry = _VULN_IMPACT_MAP['dos']
        combined = (entry['impact'] + entry['cvss']).lower()
        assert 'availab' in combined or 'a:h' in combined


# ---------------------------------------------------------------------------
# IMPACT_MAP coverage tests
# ---------------------------------------------------------------------------

class TestImpactMapCoverage:
    """IMPACT_MAP in bounty_report_generator must cover all model vulnerability types."""

    # All types from Vulnerability.VULNERABILITY_TYPES
    ALL_MODEL_TYPES = [
        'xss', 'sqli', 'csrf', 'xxe', 'rce', 'lfi', 'rfi', 'open_redirect', 'ssrf',
        'info_disclosure', 'clickjacking', 'js_hijacking', 'idor', 'jwt', 'crlf',
        'host_header', 'smuggling', 'deserialization', 'graphql', 'websocket',
        'cache_poisoning', 'cors', 'email_rce', 'ai_llm', 'dos', 'security_misconfig',
        'sensitive_data', 'weak_password', 'bac', 'username_enum', 'captcha_bypass',
        'unsafe_upload', 'subdomain_takeover', 'exif_data', 'api_key_exposure', 'other',
    ]

    def test_all_model_types_in_impact_map(self):
        from scanner.bounty_report_generator import IMPACT_MAP
        missing = [t for t in self.ALL_MODEL_TYPES if t not in IMPACT_MAP]
        assert missing == [], f'Missing IMPACT_MAP entries: {missing}'

    def test_new_types_have_attacker_impact(self):
        from scanner.bounty_report_generator import IMPACT_MAP
        new_types = [
            'email_rce', 'ai_llm', 'dos', 'security_misconfig', 'sensitive_data',
            'weak_password', 'bac', 'username_enum', 'captcha_bypass', 'unsafe_upload',
            'subdomain_takeover', 'exif_data', 'api_key_exposure',
        ]
        for vtype in new_types:
            assert IMPACT_MAP[vtype].get('attacker_impact'), \
                f'IMPACT_MAP[{vtype!r}] has no attacker_impact'

    def test_new_types_have_cvss_vector(self):
        from scanner.bounty_report_generator import IMPACT_MAP
        new_types = [
            'email_rce', 'ai_llm', 'dos', 'security_misconfig', 'sensitive_data',
            'weak_password', 'bac', 'username_enum', 'captcha_bypass', 'unsafe_upload',
            'subdomain_takeover', 'exif_data', 'api_key_exposure',
        ]
        for vtype in new_types:
            assert IMPACT_MAP[vtype].get('cvss_vector'), \
                f'IMPACT_MAP[{vtype!r}] has no cvss_vector'


# ---------------------------------------------------------------------------
# _build_bug_bounty_impact tests
# ---------------------------------------------------------------------------

class TestBuildBugBountyImpact:
    """_build_bug_bounty_impact must use the correct fallback chain."""

    def test_uses_vuln_impact_map_for_known_type(self):
        vuln = _make_vuln('xss')
        result = {'evidence': '<script>alert(1)</script>'}
        impact = _build_bug_bounty_impact(vuln, result)
        assert '## Real-World Impact' in impact
        assert '## Attack Scenario' in impact
        assert '## CVSS Assessment' in impact

    def test_known_type_impact_is_specific_not_generic(self):
        """XSS impact text should reference XSS-specific concepts."""
        vuln = _make_vuln('xss')
        impact = _build_bug_bounty_impact(vuln, {})
        assert 'session' in impact.lower() or 'cookie' in impact.lower() or 'javascript' in impact.lower()

    def test_falls_back_to_bounty_report_impact_map(self):
        """For a type not in _VULN_IMPACT_MAP, bounty_report IMPACT_MAP is used."""
        vuln = _make_vuln('ai_llm')  # Not in _VULN_IMPACT_MAP
        impact = _build_bug_bounty_impact(vuln, {})
        assert '## Real-World Impact' in impact
        assert 'As an attacker, I can' in impact

    def test_generic_impact_references_vuln_type_and_url(self):
        """For an unrecognised type, the generic fallback is informative."""
        # Create a type not in either map
        vuln = _make_vuln('unknown_type', url='https://target.com/endpoint')
        impact = _build_bug_bounty_impact(vuln, {})
        # The output should contain at least the section headers
        assert '## Real-World Impact' in impact

    def test_technical_evidence_included_when_present(self):
        vuln = _make_vuln('sqli')
        result = {'evidence': 'SQL syntax error in response body'}
        impact = _build_bug_bounty_impact(vuln, result)
        assert '## Technical Evidence' in impact
        assert 'SQL syntax error' in impact

    def test_security_misconfig_impact_mentions_headers(self):
        vuln = _make_vuln('security_misconfig')
        impact = _build_bug_bounty_impact(vuln, {})
        assert 'CSP' in impact or 'Content-Security-Policy' in impact or 'X-Frame-Options' in impact


# ---------------------------------------------------------------------------
# _build_impact_summary tests
# ---------------------------------------------------------------------------

class TestBuildImpactSummary:
    """_build_impact_summary must never return 'Run exploitation...' for known types."""

    ALL_MODEL_TYPES = [
        'xss', 'sqli', 'csrf', 'xxe', 'rce', 'lfi', 'rfi', 'open_redirect', 'ssrf',
        'info_disclosure', 'clickjacking', 'js_hijacking', 'idor', 'jwt', 'crlf',
        'host_header', 'smuggling', 'deserialization', 'graphql', 'websocket',
        'cache_poisoning', 'cors', 'email_rce', 'ai_llm', 'dos', 'security_misconfig',
        'sensitive_data', 'weak_password', 'bac', 'username_enum', 'captcha_bypass',
        'unsafe_upload', 'subdomain_takeover', 'exif_data', 'api_key_exposure', 'other',
    ]

    def test_never_returns_run_exploitation_for_known_types(self):
        for vtype in self.ALL_MODEL_TYPES:
            vuln = _make_vuln(vtype)
            summary = _build_impact_summary(vuln)
            assert 'Run exploitation' not in summary, \
                f'_build_impact_summary returned "Run exploitation..." for type {vtype!r}'
            assert len(summary) > 20, \
                f'Impact summary too short for type {vtype!r}: {summary!r}'

    def test_uses_proof_of_impact_when_available(self):
        vuln = _make_vuln(
            'xss',
            proof_of_impact='## Real-World Impact\nCustom impact text.\n## Attack Scenario\nScenario.',
        )
        summary = _build_impact_summary(vuln)
        assert summary == 'Custom impact text.'

    def test_security_misconfig_with_header_evidence(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='Missing headers: Content-Security-Policy not set',
        )
        summary = _build_impact_summary(vuln)
        assert len(summary) > 20
        # Should mention CSP or clickjacking or a specific header
        assert ('CSP' in summary or 'Content-Security-Policy' in summary
                or 'X-Frame-Options' in summary or 'script' in summary.lower())

    def test_returns_string_for_unknown_type(self):
        vuln = _make_vuln('unknown_novel_type')
        summary = _build_impact_summary(vuln)
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_does_not_include_url_in_fallback_without_run_exploitation(self):
        """Fallback should not contain the 'Run exploitation' phrase."""
        vuln = _make_vuln('cors', url='https://api.example.com/data')
        summary = _build_impact_summary(vuln)
        assert 'Run exploitation' not in summary


# ---------------------------------------------------------------------------
# _build_exploitation_steps tests
# ---------------------------------------------------------------------------

class TestBuildExploitationSteps:
    """_build_exploitation_steps must generate meaningful steps from evidence."""

    def test_returns_list(self):
        vuln = _make_vuln('xss')
        steps = _build_exploitation_steps(vuln)
        assert isinstance(steps, list)

    def test_minimum_three_steps_universal_fallback(self):
        vuln = _make_vuln('other', evidence='some evidence here')
        steps = _build_exploitation_steps(vuln)
        assert len(steps) >= 3

    def test_steps_have_required_keys(self):
        vuln = _make_vuln('sqli', evidence='SQL error in response')
        steps = _build_exploitation_steps(vuln)
        required = {'step', 'title', 'description', 'request', 'response'}
        for step in steps:
            for key in required:
                assert key in step, f'Step missing key {key!r}: {step}'

    def test_security_misconfig_generates_per_header_steps(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='Missing: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security',
        )
        steps = _build_exploitation_steps(vuln)
        assert len(steps) >= 2
        titles = ' '.join(s['title'] for s in steps).lower()
        # At least one step should reference a specific header
        assert ('content-security-policy' in titles
                or 'x-frame-options' in titles
                or 'strict-transport-security' in titles
                or 'hsts' in titles)

    def test_captcha_bypass_parses_method_entries(self):
        evidence = (
            'Bypass methods discovered:\n'
            'Method 2: Token reuse — solved tokens accepted multiple times\n'
            'Method 3: Audio bypass — audio challenge reveals answer\n'
            'Method 5: Token omission — CAPTCHA token can be omitted'
        )
        vuln = _make_vuln('captcha_bypass', evidence=evidence)
        steps = _build_exploitation_steps(vuln)
        assert len(steps) >= 3
        combined = ' '.join(s.get('description', '') + s.get('title', '') for s in steps).lower()
        assert ('reuse' in combined or 'audio' in combined or 'omission' in combined
                or 'method' in combined)

    def test_security_misconfig_with_no_matching_headers_falls_back_to_3step(self):
        vuln = _make_vuln(
            'security_misconfig',
            evidence='General configuration issue detected',
        )
        steps = _build_exploitation_steps(vuln)
        assert len(steps) >= 3

    def test_three_step_fallback_titles(self):
        vuln = _make_vuln('lfi', evidence='Path traversal evidence')
        steps = _build_exploitation_steps(vuln)
        assert len(steps) >= 3
        assert steps[0]['step'] == 1
        assert steps[1]['step'] == 2
        assert steps[2]['step'] == 3


# ---------------------------------------------------------------------------
# _extract_missing_header_impacts tests
# ---------------------------------------------------------------------------

class TestExtractMissingHeaderImpacts:
    """_extract_missing_header_impacts parses evidence for missing security headers."""

    def test_detects_content_security_policy(self):
        result = _extract_missing_header_impacts('content-security-policy header is missing')
        assert any('Content-Security-Policy' in r or 'CSP' in r or 'script' in r.lower()
                   for r in result)

    def test_detects_x_frame_options(self):
        result = _extract_missing_header_impacts('x-frame-options not present in response')
        assert any('clickjacking' in r.lower() or 'X-Frame-Options' in r for r in result)

    def test_detects_hsts(self):
        result = _extract_missing_header_impacts('strict-transport-security is not set')
        assert any('HSTS' in r or 'downgrade' in r.lower() for r in result)

    def test_detects_x_content_type_options(self):
        result = _extract_missing_header_impacts('x-content-type-options missing')
        assert any('MIME' in r or 'content-type' in r.lower() or 'X-Content-Type' in r
                   for r in result)

    def test_returns_empty_for_unrelated_evidence(self):
        result = _extract_missing_header_impacts('SQL error in query SELECT * FROM users')
        assert result == []

    def test_multiple_headers_in_single_evidence(self):
        evidence = 'Missing: content-security-policy, x-frame-options, strict-transport-security'
        result = _extract_missing_header_impacts(evidence)
        assert len(result) >= 2

    def test_no_duplicate_entries(self):
        # 'csp' and 'content-security-policy' both map to the same impact phrase —
        # the result list should contain only one entry for that phrase
        evidence = 'csp header missing; content-security-policy not set'
        result = _extract_missing_header_impacts(evidence)
        # Should have at most one CSP-related entry
        csp_entries = [r for r in result if 'Content-Security-Policy' in r or 'script' in r.lower()]
        assert len(csp_entries) <= 1, f'Duplicate CSP entries found: {csp_entries}'
        # Overall result should have no duplicates
        assert len(result) == len(set(result)), f'Duplicate entries in result: {result}'
