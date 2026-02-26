"""
Tests for the reporting module.
"""
import json
from unittest.mock import patch, MagicMock

from django.test import TestCase

from discover.models import Scan, SensitiveFinding, Subdomain, Technology
from discover.reporting import ReconReportBuilder


class TestReconReportBuilder(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')
        # Add some findings
        SensitiveFinding.objects.create(
            scan=self.scan,
            url='https://example.com/config.php',
            finding_type='AWS Access Key',
            value='AKIAIOSFODNN7EXAMPLE',
            context='export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
            severity='critical',
        )
        SensitiveFinding.objects.create(
            scan=self.scan,
            url='https://example.com/debug.log',
            finding_type='Password Field',
            value='password=secret123',
            context='db_password=secret123',
            severity='high',
        )
        # Update scan totals
        self.scan.total_findings = 2
        self.scan.high_risk_findings = 2
        self.scan.save()

    def test_build_html_returns_html_string(self):
        builder = ReconReportBuilder(self.scan)
        html = builder.build_html()
        self.assertIsInstance(html, str)
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('example.com', html)
        self.assertIn('Executive Summary', html)

    def test_build_html_includes_findings(self):
        builder = ReconReportBuilder(self.scan)
        html = builder.build_html()
        self.assertIn('AWS Access Key', html)
        self.assertIn('critical', html)

    def test_build_json_returns_valid_json(self):
        builder = ReconReportBuilder(self.scan)
        json_str = builder.build_json()
        data = json.loads(json_str)
        self.assertEqual(data['report_version'], '2.0')
        self.assertEqual(data['scan']['target'], 'example.com')
        self.assertEqual(len(data['sensitive_findings']), 2)

    def test_build_csv_contains_findings(self):
        builder = ReconReportBuilder(self.scan)
        csv_str = builder.build_csv_findings()
        self.assertIn('AWS Access Key', csv_str)
        self.assertIn('critical', csv_str)

    def test_build_markdown_returns_markdown(self):
        builder = ReconReportBuilder(self.scan)
        md = builder.build_markdown()
        self.assertIn('# Reconnaissance Report', md)
        self.assertIn('example.com', md)
        self.assertIn('## Sensitive Findings', md)

    def test_as_http_response_html(self):
        builder = ReconReportBuilder(self.scan)
        response = builder.as_http_response('html')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response['Content-Type'])

    def test_as_http_response_json(self):
        builder = ReconReportBuilder(self.scan)
        response = builder.as_http_response('json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/json', response['Content-Type'])

    def test_as_http_response_csv(self):
        builder = ReconReportBuilder(self.scan)
        response = builder.as_http_response('csv')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response['Content-Type'])
        self.assertIn('attachment', response['Content-Disposition'])

    def test_as_http_response_markdown(self):
        builder = ReconReportBuilder(self.scan)
        response = builder.as_http_response('markdown')
        self.assertEqual(response.status_code, 200)
        self.assertIn('attachment', response['Content-Disposition'])

    def test_as_http_response_unknown_format(self):
        builder = ReconReportBuilder(self.scan)
        response = builder.as_http_response('unknownformat')
        self.assertEqual(response.status_code, 400)

    def test_risk_score_calculation(self):
        builder = ReconReportBuilder(self.scan)
        findings = list(self.scan.sensitive_findings.all())
        score = builder._calculate_risk_score(self.scan, findings, [])
        # 1 critical (×20) + 1 high (×10) = 30
        self.assertEqual(score, 30)

    def test_risk_class_critical(self):
        builder = ReconReportBuilder(self.scan)
        self.assertEqual(builder._risk_class(80), 'risk-critical')
        self.assertEqual(builder._risk_class(70), 'risk-critical')

    def test_risk_class_high(self):
        builder = ReconReportBuilder(self.scan)
        self.assertEqual(builder._risk_class(60), 'risk-high')

    def test_risk_class_medium(self):
        builder = ReconReportBuilder(self.scan)
        self.assertEqual(builder._risk_class(40), 'risk-medium')

    def test_risk_class_low(self):
        builder = ReconReportBuilder(self.scan)
        self.assertEqual(builder._risk_class(15), 'risk-low')

    def test_risk_class_info(self):
        builder = ReconReportBuilder(self.scan)
        self.assertEqual(builder._risk_class(0), 'risk-info')

    def test_html_escaping(self):
        builder = ReconReportBuilder(self.scan)
        result = builder._esc('<script>alert(1)</script>')
        self.assertNotIn('<script>', result)
        self.assertIn('&lt;script&gt;', result)

    def test_executive_summary_includes_counts(self):
        builder = ReconReportBuilder(self.scan)
        findings = list(self.scan.sensitive_findings.all())
        summary = builder._build_executive_summary(self.scan, findings, [], 30)
        self.assertIn('example.com', summary)
        self.assertIn('1 critical', summary)
        self.assertIn('1 high', summary)

    def test_build_html_with_subdomains(self):
        Subdomain.objects.create(
            scan=self.scan,
            subdomain='api.example.com',
            ip_address='1.2.3.4',
            source='crt.sh',
        )
        builder = ReconReportBuilder(self.scan)
        html = builder.build_html()
        self.assertIn('api.example.com', html)

    def test_build_html_with_technologies(self):
        Technology.objects.create(
            scan=self.scan,
            name='WordPress',
            category='CMS',
            confidence='high',
        )
        builder = ReconReportBuilder(self.scan)
        html = builder.build_html()
        self.assertIn('WordPress', html)

    @patch('discover.reporting.REPORTLAB_AVAILABLE', False)
    def test_pdf_returns_none_when_reportlab_missing(self):
        builder = ReconReportBuilder(self.scan)
        result = builder.build_pdf()
        self.assertIsNone(result)

    @patch('discover.reporting.REPORTLAB_AVAILABLE', False)
    def test_as_http_response_pdf_without_reportlab(self):
        builder = ReconReportBuilder(self.scan)
        response = builder.as_http_response('pdf')
        self.assertEqual(response.status_code, 501)
