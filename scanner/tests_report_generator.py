"""
Tests for ReportGenerator

Covers:
- JSON report generation and structure
- Markdown report generation (executive summary, findings, tech stack)
- SARIF 2.1.0 report generation
- Executive summary accuracy (severity counts, risk rating)
- Findings sorted by severity
- to_json / to_markdown / to_sarif string methods
- write_json / write_markdown / write_sarif file helpers
"""

import json
import os
import tempfile
from django.test import SimpleTestCase as TestCase

from scanner.report_generator import ReportGenerator, ScanReport
from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding


def _make_finding(
    vuln_type: str = 'xss',
    severity: str = 'high',
    url: str = 'https://example.com/page',
    confidence: float = 0.8,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_type=vuln_type,
        severity=severity,
        url=url,
        description=f'{vuln_type} vulnerability found',
        evidence=f'Proof of {vuln_type}',
        remediation=f'Fix the {vuln_type}',
        confidence=confidence,
        cwe_id='CWE-79',
        parameter='q',
    )


def _make_report(**kwargs) -> ScanReport:
    defaults = {
        'target': 'https://example.com',
        'scan_duration': 12.5,
        'urls_scanned': 20,
        'vulnerabilities_found': 3,
        'risk_score': 45.0,
        'findings': [
            _make_finding('sqli', 'critical'),
            _make_finding('xss', 'high'),
            _make_finding('cors', 'medium'),
        ],
        'technology_stack': {'web_server': 'nginx', 'framework': 'Django'},
        'recommendations': ['Fix SQL injection', 'Add CSP header'],
        'scan_metrics': {'plugin_count': 10, 'total_duration_seconds': 8.0},
    }
    defaults.update(kwargs)
    return ScanReport(**defaults)


class TestReportGeneratorJSON(TestCase):
    def setUp(self):
        self.gen = ReportGenerator()
        self.report = _make_report()

    def test_to_json_returns_string(self):
        result = self.gen.to_json(self.report)
        self.assertIsInstance(result, str)

    def test_json_is_valid(self):
        result = self.gen.to_json(self.report)
        parsed = json.loads(result)
        self.assertIsInstance(parsed, dict)

    def test_json_contains_required_keys(self):
        parsed = json.loads(self.gen.to_json(self.report))
        for key in ('target', 'timestamp', 'vulnerabilities_found', 'findings',
                    'severity_summary', 'risk_score', 'overall_risk_rating'):
            self.assertIn(key, parsed, f"Missing key: {key}")

    def test_json_severity_summary_correct(self):
        parsed = json.loads(self.gen.to_json(self.report))
        summary = parsed['severity_summary']
        self.assertEqual(summary['critical'], 1)
        self.assertEqual(summary['high'], 1)
        self.assertEqual(summary['medium'], 1)
        self.assertEqual(summary['low'], 0)

    def test_json_findings_sorted_by_severity(self):
        parsed = json.loads(self.gen.to_json(self.report))
        severities = [f['severity'] for f in parsed['findings']]
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        ranks = [order.get(s.lower(), 99) for s in severities]
        self.assertEqual(ranks, sorted(ranks))

    def test_write_json_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = f.name
        try:
            self.gen.write_json(self.report, path)
            self.assertTrue(os.path.exists(path))
            with open(path) as fh:
                parsed = json.loads(fh.read())
            self.assertEqual(parsed['target'], 'https://example.com')
        finally:
            os.unlink(path)

    def test_json_top5_findings(self):
        report = _make_report(findings=[_make_finding(f'type{i}', 'high') for i in range(8)])
        parsed = json.loads(self.gen.to_json(report))
        self.assertLessEqual(len(parsed['top_5_findings']), 5)

    def test_json_overall_risk_rating_critical(self):
        report = _make_report(risk_score=90.0)
        parsed = json.loads(self.gen.to_json(report))
        self.assertEqual(parsed['overall_risk_rating'], 'Critical')

    def test_json_overall_risk_rating_low(self):
        report = _make_report(risk_score=10.0)
        parsed = json.loads(self.gen.to_json(report))
        self.assertEqual(parsed['overall_risk_rating'], 'Low')


class TestReportGeneratorMarkdown(TestCase):
    def setUp(self):
        self.gen = ReportGenerator()
        self.report = _make_report()

    def test_to_markdown_returns_string(self):
        result = self.gen.to_markdown(self.report)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_markdown_contains_target(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('https://example.com', result)

    def test_markdown_contains_executive_summary(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('Executive Summary', result)

    def test_markdown_contains_risk_score(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('45', result)

    def test_markdown_contains_findings_section(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('Findings', result)

    def test_markdown_contains_critical_section(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('Critical', result)

    def test_markdown_contains_vulnerability_types(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('SQLI', result)
        self.assertIn('XSS', result)

    def test_markdown_contains_tech_stack(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('Technology Stack', result)
        self.assertIn('nginx', result)

    def test_markdown_contains_recommendations(self):
        result = self.gen.to_markdown(self.report)
        self.assertIn('Remediation', result)
        self.assertIn('Fix SQL injection', result)

    def test_write_markdown_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix='.md', delete=False) as f:
            path = f.name
        try:
            self.gen.write_markdown(self.report, path)
            self.assertTrue(os.path.exists(path))
            content = open(path).read()
            self.assertIn('Security Assessment Report', content)
        finally:
            os.unlink(path)

    def test_markdown_no_findings(self):
        report = _make_report(findings=[], vulnerabilities_found=0, risk_score=0)
        result = self.gen.to_markdown(report)
        self.assertIsInstance(result, str)
        self.assertIn('Executive Summary', result)


class TestReportGeneratorSARIF(TestCase):
    def setUp(self):
        self.gen = ReportGenerator()
        self.report = _make_report()

    def test_to_sarif_returns_string(self):
        result = self.gen.to_sarif(self.report)
        self.assertIsInstance(result, str)

    def test_sarif_is_valid_json(self):
        result = json.loads(self.gen.to_sarif(self.report))
        self.assertIsInstance(result, dict)

    def test_sarif_version(self):
        parsed = json.loads(self.gen.to_sarif(self.report))
        self.assertEqual(parsed['version'], '2.1.0')

    def test_sarif_schema_present(self):
        parsed = json.loads(self.gen.to_sarif(self.report))
        self.assertIn('$schema', parsed)
        self.assertIn('sarif', parsed['$schema'])

    def test_sarif_tool_driver(self):
        parsed = json.loads(self.gen.to_sarif(self.report))
        driver = parsed['runs'][0]['tool']['driver']
        self.assertEqual(driver['name'], 'Megido')
        self.assertIn('rules', driver)

    def test_sarif_results_count_matches_findings(self):
        parsed = json.loads(self.gen.to_sarif(self.report))
        results = parsed['runs'][0]['results']
        self.assertEqual(len(results), len(self.report.findings))

    def test_sarif_result_severity_mapping(self):
        parsed = json.loads(self.gen.to_sarif(self.report))
        results = parsed['runs'][0]['results']
        for result in results:
            self.assertIn(result['level'], ('error', 'warning', 'note'))

    def test_sarif_result_location_uri(self):
        parsed = json.loads(self.gen.to_sarif(self.report))
        for result in parsed['runs'][0]['results']:
            loc = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
            self.assertTrue(loc.startswith('http'))

    def test_write_sarif_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = f.name
        try:
            self.gen.write_sarif(self.report, path)
            self.assertTrue(os.path.exists(path))
            parsed = json.loads(open(path).read())
            self.assertEqual(parsed['version'], '2.1.0')
        finally:
            os.unlink(path)

    def test_sarif_no_findings(self):
        report = _make_report(findings=[])
        parsed = json.loads(self.gen.to_sarif(report))
        self.assertEqual(parsed['runs'][0]['results'], [])
        self.assertEqual(parsed['runs'][0]['tool']['driver']['rules'], [])


class TestReportGeneratorHelpers(TestCase):
    def setUp(self):
        self.gen = ReportGenerator()

    def test_risk_rating_critical(self):
        self.assertEqual(self.gen._risk_rating(80), 'Critical')

    def test_risk_rating_high(self):
        self.assertEqual(self.gen._risk_rating(60), 'High')

    def test_risk_rating_medium(self):
        self.assertEqual(self.gen._risk_rating(30), 'Medium')

    def test_risk_rating_low(self):
        self.assertEqual(self.gen._risk_rating(10), 'Low')

    def test_sarif_level_mapping(self):
        self.assertEqual(self.gen._sarif_level('critical'), 'error')
        self.assertEqual(self.gen._sarif_level('high'), 'error')
        self.assertEqual(self.gen._sarif_level('medium'), 'warning')
        self.assertEqual(self.gen._sarif_level('low'), 'note')

    def test_severity_counts(self):
        findings = [
            _make_finding('a', 'critical'),
            _make_finding('b', 'high'),
            _make_finding('c', 'high'),
            _make_finding('d', 'medium'),
        ]
        counts = self.gen._severity_counts(findings)
        self.assertEqual(counts['critical'], 1)
        self.assertEqual(counts['high'], 2)
        self.assertEqual(counts['medium'], 1)
        self.assertEqual(counts['low'], 0)

    def test_sort_findings_order(self):
        findings = [
            _make_finding('a', 'low'),
            _make_finding('b', 'critical'),
            _make_finding('c', 'medium'),
        ]
        sorted_f = self.gen._sort_findings(findings)
        self.assertEqual(sorted_f[0].severity, 'critical')
        self.assertEqual(sorted_f[-1].severity, 'low')
