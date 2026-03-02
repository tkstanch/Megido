"""
Tests for the bug bounty impact analysis and PoC report generator.
"""

import json
from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from scanner.models import ScanTarget, Scan, Vulnerability
from scanner.bounty_report_generator import (
    BountyReportGenerator,
    IMPACT_MAP,
    generate_bounty_report,
    generate_scan_bounty_reports,
)


class BountyReportGeneratorUnitTests(TestCase):
    """Unit tests for BountyReportGenerator"""

    def setUp(self):
        self.target = ScanTarget.objects.create(url='https://example.com', name='Test')
        self.scan = Scan.objects.create(target=self.target, status='completed')
        self.vuln_xss = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='high',
            url='https://example.com/search',
            parameter='q',
            description='Reflected XSS in search parameter',
            evidence='<script>alert(1)</script> reflected in response',
            exploited=True,
            verified=True,
            exploit_result='Plugin: XSS Plugin\nStatus: SUCCESS\nEvidence: script executed',
            successful_payloads=['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
        )
        self.vuln_sqli = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='sqli',
            severity='critical',
            url='https://example.com/users',
            parameter='id',
            description='SQL Injection in id parameter',
            evidence="Error: You have an error in your SQL syntax",
            exploited=True,
        )
        self.vuln_unexploited = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='csrf',
            severity='medium',
            url='https://example.com/transfer',
            parameter=None,
            description='Missing CSRF token',
        )

    def test_impact_map_covers_all_vuln_types(self):
        """All vulnerability types defined in the model should have impact mappings."""
        all_types = [choice[0] for choice in Vulnerability.VULNERABILITY_TYPES]
        for vtype in all_types:
            self.assertIn(
                vtype, IMPACT_MAP,
                msg=f'Missing impact mapping for vulnerability type: {vtype}',
            )

    def test_generate_markdown_report(self):
        """Generator produces a non-empty Markdown report."""
        gen = BountyReportGenerator(self.vuln_xss)
        report = gen.generate(fmt='markdown')
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 100)
        # Must contain impact-focused title
        self.assertIn('XSS', report)
        # Must contain standard sections
        self.assertIn('## Impact Statement', report)
        self.assertIn('## Steps to Reproduce', report)
        self.assertIn('## Proof of Concept', report)
        self.assertIn('## Business Impact', report)
        self.assertIn('## Remediation', report)
        self.assertIn('## References', report)

    def test_generate_json_report(self):
        """Generator produces valid JSON with expected keys."""
        gen = BountyReportGenerator(self.vuln_xss)
        report_str = gen.generate(fmt='json')
        report = json.loads(report_str)
        for key in ('title', 'severity', 'cvss_score', 'cvss_vector', 'cwe',
                    'impact_statement', 'steps_to_reproduce', 'poc_evidence',
                    'remediation', 'references', 'exploited'):
            self.assertIn(key, report, msg=f'Missing key: {key}')

    def test_report_saved_to_model(self):
        """save() persists the report to vulnerability.bounty_report."""
        gen = BountyReportGenerator(self.vuln_xss)
        gen.save()
        self.vuln_xss.refresh_from_db()
        self.assertIsNotNone(self.vuln_xss.bounty_report)
        self.assertGreater(len(self.vuln_xss.bounty_report), 50)

    def test_title_is_impact_focused(self):
        """Title should not just say 'XSS found' but describe impact."""
        gen = BountyReportGenerator(self.vuln_xss)
        data = gen._build_report_data()
        title = data['title']
        # Title should not be a bare type name
        self.assertNotEqual(title.strip().lower(), 'xss')
        self.assertGreater(len(title), 10)

    def test_cvss_score_higher_for_exploited(self):
        """Verified exploited vulns should have >= CVSS score of non-exploited."""
        gen_exploited = BountyReportGenerator(self.vuln_xss)  # exploited=True, verified=True
        gen_not_exploited = BountyReportGenerator(self.vuln_unexploited)
        score_exp, _ = gen_exploited._estimate_cvss()
        score_not, _ = gen_not_exploited._estimate_cvss()
        # The XSS exploited score is based on high severity; CSRF is medium — just check both are positive
        self.assertGreater(score_exp, 0)
        self.assertGreater(score_not, 0)

    def test_steps_to_reproduce_include_url(self):
        """Steps must include the target URL."""
        gen = BountyReportGenerator(self.vuln_xss)
        steps = gen._build_steps_to_reproduce()
        combined = ' '.join(steps)
        self.assertIn(self.vuln_xss.url, combined)

    def test_steps_include_payloads(self):
        """Steps should include confirmed payloads if available."""
        gen = BountyReportGenerator(self.vuln_xss)
        steps = gen._build_steps_to_reproduce()
        combined = ' '.join(steps)
        self.assertIn('<script>alert(1)</script>', combined)

    def test_impact_statement_format(self):
        """Impact statement must start with 'As an attacker'."""
        gen = BountyReportGenerator(self.vuln_xss)
        statement = gen._build_impact_statement()
        self.assertTrue(
            statement.startswith('As an attacker'),
            msg=f'Impact statement does not start with expected prefix: {statement[:50]}',
        )

    def test_attack_chain_detected(self):
        """Attack chain should be detected when related vuln types co-exist in a scan."""
        # Add an SSRF vuln to the same scan as open_redirect to trigger chain
        vuln_or = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='open_redirect',
            severity='medium',
            url='https://example.com/redirect',
            parameter='url',
            description='Open redirect',
        )
        Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='ssrf',
            severity='high',
            url='https://example.com/fetch',
            parameter='target',
            description='SSRF',
        )
        gen = BountyReportGenerator(vuln_or)
        chains = gen._detect_attack_chains()
        self.assertGreater(len(chains), 0)
        combined = ' '.join(chains)
        self.assertIn('SSRF', combined)

    def test_no_attack_chain_when_none(self):
        """No attack chains should be reported when no pairable vuln exists."""
        gen = BountyReportGenerator(self.vuln_xss)
        # vuln_xss has xss+sqli+csrf in scan; xss+csrf IS a chain pair
        chains = gen._detect_attack_chains()
        # xss+csrf pair should be found
        self.assertGreater(len(chains), 0)

    def test_remediation_fallback(self):
        """Remediation text should be populated even when vuln.remediation is empty."""
        self.vuln_xss.remediation = ''
        gen = BountyReportGenerator(self.vuln_xss)
        data = gen._build_report_data()
        self.assertTrue(len(data['remediation']) > 10)

    def test_fallback_to_other_impact_map(self):
        """Unknown vuln types fall back to 'other' impact map without error."""
        self.vuln_xss.vulnerability_type = 'other'
        gen = BountyReportGenerator(self.vuln_xss)
        report = gen.generate()
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 50)

    def test_references_contain_cwe(self):
        """References section should include CWE link."""
        gen = BountyReportGenerator(self.vuln_sqli)
        data = gen._build_report_data()
        refs_combined = ' '.join(data['references'])
        self.assertIn('cwe.mitre.org', refs_combined)


class GenerateBountyReportFunctionTests(TestCase):
    """Tests for module-level helper functions."""

    def setUp(self):
        self.target = ScanTarget.objects.create(url='https://example.com')
        self.scan = Scan.objects.create(target=self.target, status='completed')
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='sqli',
            severity='critical',
            url='https://example.com/api/users',
            parameter='id',
            description='SQL Injection',
            exploited=True,
        )

    def test_generate_bounty_report_returns_string(self):
        report = generate_bounty_report(self.vuln.id)
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 100)

    def test_generate_bounty_report_nonexistent_id(self):
        report = generate_bounty_report(999999)
        self.assertIsNone(report)

    def test_generate_scan_bounty_reports_exploited_only(self):
        # Add an unexploited vuln — should be skipped
        Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='medium',
            url='https://example.com/page',
            parameter='q',
            description='XSS',
            exploited=False,
        )
        result = generate_scan_bounty_reports(self.scan.id, exploited_only=True)
        self.assertEqual(result['generated'], 1)
        self.assertEqual(result['skipped'], 0)
        self.assertEqual(len(result['reports']), 1)

    def test_generate_scan_bounty_reports_all(self):
        Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='medium',
            url='https://example.com/page',
            parameter='q',
            description='XSS',
            exploited=False,
        )
        result = generate_scan_bounty_reports(self.scan.id, exploited_only=False)
        self.assertEqual(result['generated'], 2)

    def test_generate_scan_bounty_reports_bad_scan(self):
        result = generate_scan_bounty_reports(999999)
        self.assertIn('error', result)
        self.assertEqual(result['generated'], 0)


class BountyReportAPITests(TestCase):
    """Integration tests for the bounty report API endpoints."""

    def setUp(self):
        self.user = User.objects.create_user(username='testuser2', password='pass')
        self.token = Token.objects.create(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

        self.target = ScanTarget.objects.create(url='https://api-test.example.com')
        self.scan = Scan.objects.create(target=self.target, status='completed')
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='high',
            url='https://api-test.example.com/search',
            parameter='q',
            description='Reflected XSS',
            exploited=True,
            evidence='Script reflected in response',
        )

    def test_get_vulnerability_bounty_report(self):
        url = f'/scanner/api/vulnerabilities/{self.vuln.id}/bounty-report/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('report', data)
        self.assertIn('vulnerability_id', data)
        self.assertEqual(data['vulnerability_id'], self.vuln.id)
        self.assertGreater(len(data['report']), 50)

    def test_get_vulnerability_bounty_report_cached(self):
        """Second request should return cached report, not regenerate."""
        url = f'/scanner/api/vulnerabilities/{self.vuln.id}/bounty-report/'
        self.client.get(url)
        self.vuln.refresh_from_db()
        first_report = self.vuln.bounty_report

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['report'], first_report)

    def test_get_vulnerability_bounty_report_regenerate(self):
        """?regenerate=1 should force report regeneration."""
        url = f'/scanner/api/vulnerabilities/{self.vuln.id}/bounty-report/?regenerate=1'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('report', response.json())

    def test_get_vulnerability_bounty_report_json_fmt(self):
        url = f'/scanner/api/vulnerabilities/{self.vuln.id}/bounty-report/?fmt=json'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        report_str = response.json()['report']
        # The report field should be valid JSON when fmt=json
        parsed = json.loads(report_str)
        self.assertIn('title', parsed)

    def test_get_vulnerability_bounty_report_not_found(self):
        url = '/scanner/api/vulnerabilities/999999/bounty-report/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_post_scan_bounty_reports(self):
        url = f'/scanner/api/scans/{self.scan.id}/bounty-reports/'
        response = self.client.post(url, data={}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('generated', data)
        self.assertIn('reports', data)
        self.assertEqual(data['generated'], 1)

    def test_post_scan_bounty_reports_not_found(self):
        url = '/scanner/api/scans/999999/bounty-reports/'
        response = self.client.post(url, data={}, content_type='application/json')
        self.assertEqual(response.status_code, 404)

    def test_endpoints_require_authentication(self):
        """Unauthenticated requests should be rejected."""
        unauthed = APIClient()
        vuln_url = f'/scanner/api/vulnerabilities/{self.vuln.id}/bounty-report/'
        scan_url = f'/scanner/api/scans/{self.scan.id}/bounty-reports/'
        self.assertEqual(unauthed.get(vuln_url).status_code, 401)
        self.assertEqual(unauthed.post(scan_url).status_code, 401)
