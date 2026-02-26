"""
Professional report generation engine for Data Tracer.
Implements executive summary generation, technical report building,
multi-format output, CVSS scoring, and compliance mapping.
"""

import json
import csv
import io
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


# CVSS v3.1 scoring vectors
CVSS_ATTACK_VECTOR = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
CVSS_ATTACK_COMPLEXITY = {'L': 0.77, 'H': 0.44}
CVSS_PRIVILEGES_REQUIRED = {'N': 0.85, 'L': 0.62, 'H': 0.27}
CVSS_USER_INTERACTION = {'N': 0.85, 'R': 0.62}
CVSS_SCOPE = {'U': 0.0, 'C': 0.0}  # Handled differently
CVSS_IMPACT = {'N': 0.0, 'L': 0.22, 'H': 0.56}

# Compliance framework control mappings
COMPLIANCE_MAPPINGS = {
    'pci_dss': {
        'sqli': ['6.2.4', '6.3.1'],
        'xss': ['6.2.4'],
        'weak_ssl': ['4.2.1'],
        'default_credentials': ['8.2.1'],
        'missing_encryption': ['3.5.1', '4.2.1'],
        'information_disclosure': ['6.3.3'],
        'csrf': ['6.2.4'],
    },
    'hipaa': {
        'weak_ssl': ['§164.312(e)(2)(i)'],
        'missing_encryption': ['§164.312(e)(2)(ii)'],
        'default_credentials': ['§164.312(d)'],
        'information_disclosure': ['§164.312(a)(1)'],
        'audit_logging': ['§164.312(b)'],
    },
    'nist': {
        'sqli': ['SI-3', 'SA-11'],
        'xss': ['SI-3', 'SA-11'],
        'weak_ssl': ['SC-8', 'SC-28'],
        'default_credentials': ['IA-5'],
        'missing_encryption': ['SC-8', 'SC-28'],
        'missing_mfa': ['IA-2'],
    },
    'iso_27001': {
        'sqli': ['A.14.2.5'],
        'xss': ['A.14.2.5'],
        'weak_ssl': ['A.10.1.1'],
        'default_credentials': ['A.9.4.3'],
        'information_disclosure': ['A.13.2.1'],
        'audit_logging': ['A.12.4.1'],
    },
}

# Risk matrix thresholds
RISK_MATRIX = {
    (1, 1): 'low', (1, 2): 'low', (1, 3): 'medium', (1, 4): 'medium', (1, 5): 'high',
    (2, 1): 'low', (2, 2): 'medium', (2, 3): 'medium', (2, 4): 'high', (2, 5): 'high',
    (3, 1): 'medium', (3, 2): 'medium', (3, 3): 'high', (3, 4): 'high', (3, 5): 'critical',
    (4, 1): 'medium', (4, 2): 'high', (4, 3): 'high', (4, 4): 'critical', (4, 5): 'critical',
    (5, 1): 'high', (5, 2): 'high', (5, 3): 'critical', (5, 4): 'critical', (5, 5): 'critical',
}


class ReportGenerator:
    """
    Professional reporting engine for generating security assessment reports
    in multiple formats with executive summaries and compliance mappings.
    """

    def __init__(self):
        """Initialize the report generator."""
        self.report_data: Dict = {}
        self.findings: List[Dict] = []

    def generate_executive_summary(self, scan_results: Dict) -> Dict:
        """
        Generate an executive summary of security assessment results.

        Args:
            scan_results: Dictionary containing all scan findings

        Returns:
            Executive summary with key risk indicators
        """
        summary = {
            'title': 'Security Assessment Executive Summary',
            'target': scan_results.get('target', 'Unknown'),
            'assessment_date': datetime.utcnow().strftime('%Y-%m-%d'),
            'overall_risk': 'unknown',
            'overall_score': 0.0,
            'key_findings': [],
            'risk_breakdown': {},
            'top_recommendations': [],
            'compliance_status': {},
            'trend': 'new_assessment',
        }

        all_findings = self._collect_all_findings(scan_results)

        # Risk breakdown
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in all_findings:
            severity = finding.get('severity', 'info').lower()
            if severity in risk_counts:
                risk_counts[severity] += 1

        summary['risk_breakdown'] = risk_counts

        # Overall risk determination
        if risk_counts['critical'] > 0:
            summary['overall_risk'] = 'critical'
            summary['overall_score'] = 9.0
        elif risk_counts['high'] > 3:
            summary['overall_risk'] = 'high'
            summary['overall_score'] = 7.5
        elif risk_counts['high'] > 0:
            summary['overall_risk'] = 'high'
            summary['overall_score'] = 7.0
        elif risk_counts['medium'] > 5:
            summary['overall_risk'] = 'medium'
            summary['overall_score'] = 5.5
        elif risk_counts['medium'] > 0:
            summary['overall_risk'] = 'medium'
            summary['overall_score'] = 4.5
        else:
            summary['overall_risk'] = 'low'
            summary['overall_score'] = 2.0

        # Key findings (top 5 critical/high)
        critical_high = [
            f for f in all_findings
            if f.get('severity', '').lower() in ['critical', 'high']
        ]
        summary['key_findings'] = critical_high[:5]

        # Top recommendations
        summary['top_recommendations'] = self._generate_prioritized_recommendations(all_findings)

        # Compliance status
        summary['compliance_status'] = self._assess_compliance_status(all_findings)

        # Business impact
        summary['business_impact'] = self._assess_business_impact(risk_counts)

        return summary

    def _collect_all_findings(self, scan_results: Dict) -> List[Dict]:
        """Collect all findings from scan results."""
        all_findings = []

        # Collect from various scan types
        for key in ['cve_findings', 'web_vulnerabilities', 'ssl_findings',
                    'config_issues', 'cloud_findings', 'api_findings',
                    'wireless_findings', 'credential_findings']:
            findings = scan_results.get(key, [])
            if isinstance(findings, list):
                all_findings.extend(findings)

        # Also collect direct findings array
        direct_findings = scan_results.get('findings', [])
        if isinstance(direct_findings, list):
            all_findings.extend(direct_findings)

        return all_findings

    def _generate_prioritized_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation recommendations."""
        recommendations = []
        seen_types = set()

        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get('severity', 'info').lower(), 4)
        )

        for finding in sorted_findings[:10]:
            finding_type = finding.get('type', '')
            if finding_type not in seen_types:
                seen_types.add(finding_type)
                remediation = finding.get('remediation', finding.get('recommendation', ''))
                if remediation:
                    recommendations.append({
                        'priority': len(recommendations) + 1,
                        'severity': finding.get('severity', 'info'),
                        'finding': finding.get('name', finding.get('description', 'Unknown finding')),
                        'remediation': remediation,
                        'effort': self._estimate_effort(finding.get('severity', 'info')),
                    })

        return recommendations

    def _estimate_effort(self, severity: str) -> str:
        """Estimate remediation effort for a finding."""
        effort_map = {
            'critical': 'immediate (< 24 hours)',
            'high': 'urgent (< 1 week)',
            'medium': 'planned (< 1 month)',
            'low': 'backlog (< 3 months)',
            'info': 'informational',
        }
        return effort_map.get(severity.lower(), 'unknown')

    def _assess_compliance_status(self, findings: List[Dict]) -> Dict:
        """Assess compliance status based on findings."""
        status = {}

        for framework, controls in COMPLIANCE_MAPPINGS.items():
            violations = []
            for finding in findings:
                finding_type = finding.get('type', '').lower()
                finding_name = finding.get('name', '').lower()

                for control_type, control_ids in controls.items():
                    if control_type in finding_type or control_type in finding_name:
                        violations.extend(control_ids)

            violations = list(set(violations))
            compliance_score = max(0, 100 - len(violations) * 10)

            status[framework.replace('_', '-').upper()] = {
                'violations': violations,
                'compliance_score': compliance_score,
                'status': 'compliant' if not violations else 'non-compliant',
            }

        return status

    def _assess_business_impact(self, risk_counts: Dict) -> Dict:
        """Assess potential business impact of findings."""
        impact = {
            'data_breach_risk': 'low',
            'availability_risk': 'low',
            'reputational_risk': 'low',
            'financial_risk': 'low',
            'regulatory_risk': 'low',
        }

        if risk_counts.get('critical', 0) > 0:
            impact['data_breach_risk'] = 'critical'
            impact['reputational_risk'] = 'high'
            impact['financial_risk'] = 'high'
            impact['regulatory_risk'] = 'high'
        elif risk_counts.get('high', 0) > 0:
            impact['data_breach_risk'] = 'high'
            impact['reputational_risk'] = 'medium'
            impact['financial_risk'] = 'medium'
            impact['regulatory_risk'] = 'medium'
        elif risk_counts.get('medium', 0) > 0:
            impact['data_breach_risk'] = 'medium'
            impact['availability_risk'] = 'medium'

        return impact

    def calculate_cvss_v31(self, vector: Dict) -> Dict:
        """
        Calculate CVSS v3.1 score from vector components.

        Args:
            vector: Dictionary with CVSS vector components
                AV (Attack Vector): N, A, L, P
                AC (Attack Complexity): L, H
                PR (Privileges Required): N, L, H
                UI (User Interaction): N, R
                S (Scope): U, C
                C (Confidentiality Impact): N, L, H
                I (Integrity Impact): N, L, H
                A (Availability Impact): N, L, H

        Returns:
            CVSS scoring results
        """
        try:
            av = CVSS_ATTACK_VECTOR.get(vector.get('AV', 'N'), 0.85)
            ac = CVSS_ATTACK_COMPLEXITY.get(vector.get('AC', 'L'), 0.77)
            pr_val = vector.get('PR', 'N')
            scope = vector.get('S', 'U')

            # Adjust PR based on scope
            if scope == 'C':
                pr_scores = {'N': 0.85, 'L': 0.68, 'H': 0.50}
            else:
                pr_scores = {'N': 0.85, 'L': 0.62, 'H': 0.27}
            pr = pr_scores.get(pr_val, 0.85)

            ui = CVSS_USER_INTERACTION.get(vector.get('UI', 'N'), 0.85)

            conf_impact = CVSS_IMPACT.get(vector.get('C', 'N'), 0.0)
            integ_impact = CVSS_IMPACT.get(vector.get('I', 'N'), 0.0)
            avail_impact = CVSS_IMPACT.get(vector.get('A', 'N'), 0.0)

            # Calculate ISC (Impact Sub-Score)
            iss = 1.0 - ((1.0 - conf_impact) * (1.0 - integ_impact) * (1.0 - avail_impact))

            # Calculate Impact score
            if scope == 'U':
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

            # Calculate Exploitability score
            exploitability = 8.22 * av * ac * pr * ui

            # Calculate base score
            if impact <= 0:
                base_score = 0.0
            elif scope == 'U':
                base_score = min(impact + exploitability, 10.0)
            else:
                base_score = min(1.08 * (impact + exploitability), 10.0)

            # Round up to one decimal
            base_score = round(base_score * 10) / 10

            # Determine severity
            if base_score >= 9.0:
                severity = 'Critical'
            elif base_score >= 7.0:
                severity = 'High'
            elif base_score >= 4.0:
                severity = 'Medium'
            elif base_score > 0:
                severity = 'Low'
            else:
                severity = 'None'

            vector_string = (
                f"CVSS:3.1/AV:{vector.get('AV','N')}/AC:{vector.get('AC','L')}/"
                f"PR:{vector.get('PR','N')}/UI:{vector.get('UI','N')}/"
                f"S:{vector.get('S','U')}/C:{vector.get('C','N')}/"
                f"I:{vector.get('I','N')}/A:{vector.get('A','N')}"
            )

            return {
                'base_score': base_score,
                'severity': severity,
                'vector_string': vector_string,
                'impact_score': round(impact, 2),
                'exploitability_score': round(exploitability, 2),
                'components': {
                    'attack_vector': av,
                    'attack_complexity': ac,
                    'privileges_required': pr,
                    'user_interaction': ui,
                    'iss': round(iss, 3),
                },
            }

        except Exception as e:
            return {'error': f'CVSS calculation error: {str(e)}', 'base_score': 0.0}

    def generate_technical_report(self, scan_results: Dict) -> Dict:
        """
        Generate detailed technical security report.

        Args:
            scan_results: Complete scan results

        Returns:
            Technical report with full findings and evidence
        """
        report = {
            'title': 'Technical Security Assessment Report',
            'version': '1.0',
            'generated_at': datetime.utcnow().isoformat(),
            'target': scan_results.get('target', 'Unknown'),
            'scope': scan_results.get('scope', 'Full assessment'),
            'methodology': [
                'Network reconnaissance and port scanning',
                'Service and version detection',
                'Vulnerability scanning (CVE database)',
                'Web application security testing (OWASP Top 10)',
                'SSL/TLS configuration analysis',
                'Authentication and authorization testing',
                'Configuration review',
                'Cloud security assessment',
                'Container security scanning',
            ],
            'findings': [],
            'statistics': {},
            'appendices': {},
        }

        # Collect and enrich findings
        all_findings = self._collect_all_findings(scan_results)

        for i, finding in enumerate(all_findings, 1):
            enriched = {
                'finding_id': f'F-{i:04d}',
                'title': finding.get('name', finding.get('description', 'Unknown')[:80]),
                'severity': finding.get('severity', 'info'),
                'cvss_score': finding.get('cvss_score', None),
                'cve_id': finding.get('cve_id', None),
                'type': finding.get('type', 'unknown'),
                'description': finding.get('description', ''),
                'affected_component': finding.get('url', finding.get('resource', finding.get('target', 'Unknown'))),
                'evidence': finding.get('evidence', ''),
                'reproduction_steps': self._get_reproduction_steps(finding),
                'remediation': finding.get('remediation', finding.get('recommendation', '')),
                'references': self._get_references(finding),
                'compliance_impact': self._get_compliance_impact(finding),
            }
            report['findings'].append(enriched)

        # Statistics
        report['statistics'] = self._generate_statistics(report['findings'])

        # Appendices
        report['appendices'] = {
            'scan_configuration': scan_results.get('config', {}),
            'tools_used': ['Data Tracer Network Intelligence Platform'],
            'limitations': [
                'Automated scanning may produce false positives',
                'Manual verification recommended for all critical findings',
                'Scan was conducted without active exploitation',
            ],
        }

        return report

    def _get_reproduction_steps(self, finding: Dict) -> List[str]:
        """Get reproduction steps for a finding."""
        steps = []
        finding_type = finding.get('type', '').lower()

        if finding_type == 'sqli':
            steps = [
                '1. Navigate to the vulnerable parameter',
                '2. Insert SQL injection payload',
                '3. Observe database error or unexpected behavior',
            ]
        elif finding_type == 'xss':
            steps = [
                '1. Navigate to the vulnerable input field',
                '2. Insert XSS payload: <script>alert(1)</script>',
                '3. Observe JavaScript execution',
            ]
        elif finding_type == 'weak_protocol':
            steps = [
                f"1. Connect to {finding.get('resource', 'target')} using {finding.get('protocol', 'weak')} protocol",
                '2. Observe that connection is established with weak/insecure protocol',
            ]
        else:
            steps = ['1. Access the affected endpoint or resource', '2. Trigger the vulnerable condition']

        return steps

    def _get_references(self, finding: Dict) -> List[str]:
        """Get reference links for a finding."""
        refs = []
        cve = finding.get('cve_id', finding.get('cve', ''))
        finding_type = finding.get('type', '').lower()

        if cve:
            refs.append(f'https://nvd.nist.gov/vuln/detail/{cve}')
            refs.append(f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}')

        if 'sqli' in finding_type:
            refs.append('https://owasp.org/www-community/attacks/SQL_Injection')
        elif 'xss' in finding_type:
            refs.append('https://owasp.org/www-community/attacks/xss/')
        elif 'ssl' in finding_type or 'tls' in finding_type:
            refs.append('https://ssl-config.mozilla.org/')

        return refs

    def _get_compliance_impact(self, finding: Dict) -> Dict:
        """Get compliance frameworks impacted by a finding."""
        finding_type = finding.get('type', '').lower()
        impacts = {}

        for framework, controls in COMPLIANCE_MAPPINGS.items():
            for control_type, control_ids in controls.items():
                if control_type in finding_type:
                    impacts[framework.upper().replace('_', '-')] = control_ids
                    break

        return impacts

    def _generate_statistics(self, findings: List[Dict]) -> Dict:
        """Generate statistical summary of findings."""
        stats = {
            'total_findings': len(findings),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_type': {},
            'cvss_scores': [],
            'average_cvss': 0.0,
            'max_cvss': 0.0,
        }

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in stats['by_severity']:
                stats['by_severity'][severity] += 1

            finding_type = finding.get('type', 'unknown')
            stats['by_type'][finding_type] = stats['by_type'].get(finding_type, 0) + 1

            cvss = finding.get('cvss_score')
            if cvss and isinstance(cvss, (int, float)):
                stats['cvss_scores'].append(cvss)

        if stats['cvss_scores']:
            stats['average_cvss'] = round(sum(stats['cvss_scores']) / len(stats['cvss_scores']), 2)
            stats['max_cvss'] = max(stats['cvss_scores'])

        return stats

    def export_report(self, report: Dict, format: str = 'json') -> str:
        """
        Export report in the specified format.

        Args:
            report: Report data dictionary
            format: Output format (json, csv, html, markdown, text)

        Returns:
            Formatted report string
        """
        if format == 'json':
            return json.dumps(report, indent=2, default=str)

        elif format == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Finding ID', 'Title', 'Severity', 'CVSS', 'CVE', 'Description', 'Remediation'])
            for finding in report.get('findings', []):
                writer.writerow([
                    finding.get('finding_id', ''),
                    finding.get('title', ''),
                    finding.get('severity', ''),
                    finding.get('cvss_score', ''),
                    finding.get('cve_id', ''),
                    finding.get('description', '')[:200],
                    finding.get('remediation', '')[:200],
                ])
            return output.getvalue()

        elif format == 'markdown':
            return self._export_markdown(report)

        elif format == 'html':
            return self._export_html(report)

        elif format == 'text':
            return self._export_text(report)

        return json.dumps(report, default=str)

    def _export_markdown(self, report: Dict) -> str:
        """Export report as Markdown."""
        lines = [
            f"# {report.get('title', 'Security Report')}",
            f"\n**Generated:** {report.get('generated_at', '')}",
            f"**Target:** {report.get('target', 'Unknown')}",
            "",
            "## Summary",
        ]

        stats = report.get('statistics', {})
        by_sev = stats.get('by_severity', {})
        lines.extend([
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {by_sev.get('critical', 0)} |",
            f"| 🟠 High | {by_sev.get('high', 0)} |",
            f"| 🟡 Medium | {by_sev.get('medium', 0)} |",
            f"| 🔵 Low | {by_sev.get('low', 0)} |",
            f"| ⚪ Info | {by_sev.get('info', 0)} |",
            "",
            "## Findings",
            "",
        ])

        for finding in report.get('findings', []):
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}
            emoji = severity_emoji.get(finding.get('severity', 'info').lower(), '⚪')
            lines.extend([
                f"### {emoji} {finding.get('finding_id', '')} - {finding.get('title', '')}",
                f"**Severity:** {finding.get('severity', '').title()}",
                "",
                f"{finding.get('description', '')}",
                "",
                f"**Remediation:** {finding.get('remediation', '')}",
                "",
                "---",
                "",
            ])

        return '\n'.join(lines)

    def _export_html(self, report: Dict) -> str:
        """Export report as HTML."""
        stats = report.get('statistics', {})
        by_sev = stats.get('by_severity', {})

        severity_colors = {
            'critical': '#dc2626', 'high': '#ea580c',
            'medium': '#ca8a04', 'low': '#2563eb', 'info': '#6b7280'
        }

        findings_html = ''
        for finding in report.get('findings', []):
            sev = finding.get('severity', 'info').lower()
            color = severity_colors.get(sev, '#6b7280')
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; margin: 20px 0; padding: 15px; background: #f9fafb;">
                <h3 style="margin: 0 0 10px 0; color: {color};">
                    {finding.get('finding_id', '')} - {finding.get('title', '')}
                    <span style="font-size: 12px; background: {color}; color: white; padding: 2px 8px; border-radius: 12px; margin-left: 10px;">
                        {sev.upper()}
                    </span>
                </h3>
                <p>{finding.get('description', '')}</p>
                <p><strong>Remediation:</strong> {finding.get('remediation', '')}</p>
            </div>"""

        return f"""<!DOCTYPE html>
<html>
<head><title>{report.get('title', 'Security Report')}</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
h1 {{ color: #1f2937; }} h2 {{ color: #374151; }}
.summary-table {{ width: 100%; border-collapse: collapse; }}
.summary-table td, .summary-table th {{ padding: 8px 16px; border: 1px solid #e5e7eb; }}
</style>
</head>
<body>
<h1>{report.get('title', 'Security Report')}</h1>
<p><strong>Generated:</strong> {report.get('generated_at', '')} | <strong>Target:</strong> {report.get('target', 'Unknown')}</p>
<h2>Summary</h2>
<table class="summary-table">
<tr><th>Severity</th><th>Count</th></tr>
<tr><td style="color: #dc2626;">Critical</td><td>{by_sev.get('critical', 0)}</td></tr>
<tr><td style="color: #ea580c;">High</td><td>{by_sev.get('high', 0)}</td></tr>
<tr><td style="color: #ca8a04;">Medium</td><td>{by_sev.get('medium', 0)}</td></tr>
<tr><td style="color: #2563eb;">Low</td><td>{by_sev.get('low', 0)}</td></tr>
<tr><td style="color: #6b7280;">Info</td><td>{by_sev.get('info', 0)}</td></tr>
</table>
<h2>Findings</h2>
{findings_html}
</body>
</html>"""

    def _export_text(self, report: Dict) -> str:
        """Export report as plain text."""
        lines = [
            '=' * 80,
            report.get('title', 'Security Report').center(80),
            '=' * 80,
            f"Generated: {report.get('generated_at', '')}",
            f"Target: {report.get('target', 'Unknown')}",
            '',
            'FINDINGS SUMMARY',
            '-' * 40,
        ]

        stats = report.get('statistics', {})
        by_sev = stats.get('by_severity', {})
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = by_sev.get(sev, 0)
            lines.append(f"{sev.upper():<12} {count}")

        lines.extend(['', 'DETAILED FINDINGS', '-' * 40, ''])

        for finding in report.get('findings', []):
            lines.extend([
                f"[{finding.get('severity', 'INFO').upper()}] {finding.get('finding_id', '')} - {finding.get('title', '')}",
                f"Description: {finding.get('description', '')}",
                f"Remediation: {finding.get('remediation', '')}",
                '-' * 40,
            ])

        return '\n'.join(lines)

    def generate_risk_matrix(self, findings: List[Dict]) -> Dict:
        """
        Generate a risk matrix with likelihood vs. impact scoring.

        Args:
            findings: List of security findings

        Returns:
            Risk matrix data for visualization
        """
        matrix = {
            'cells': {},
            'findings_by_cell': {},
            'legend': {
                'x_axis': 'Likelihood (1=Rare, 5=Almost Certain)',
                'y_axis': 'Impact (1=Negligible, 5=Catastrophic)',
                'colors': {
                    'critical': '#dc2626',
                    'high': '#ea580c',
                    'medium': '#ca8a04',
                    'low': '#2563eb',
                }
            }
        }

        # Map findings to risk matrix cells
        for finding in findings:
            likelihood = self._estimate_likelihood(finding)
            impact = self._estimate_impact(finding)
            cell_key = f"{likelihood},{impact}"
            risk_level = RISK_MATRIX.get((likelihood, impact), 'low')

            if cell_key not in matrix['cells']:
                matrix['cells'][cell_key] = {
                    'likelihood': likelihood,
                    'impact': impact,
                    'risk': risk_level,
                    'count': 0,
                }
                matrix['findings_by_cell'][cell_key] = []

            matrix['cells'][cell_key]['count'] += 1
            matrix['findings_by_cell'][cell_key].append(
                finding.get('title', finding.get('description', ''))[:80]
            )

        return matrix

    def _estimate_likelihood(self, finding: Dict) -> int:
        """Estimate likelihood score (1-5) for a finding."""
        cvss = finding.get('cvss_score', 0) or 0
        exploit_available = finding.get('exploit_available', {})
        has_exploit = (
            isinstance(exploit_available, dict) and
            any(exploit_available.values())
        ) or exploit_available is True

        if has_exploit and cvss >= 7.0:
            return 5
        elif has_exploit or cvss >= 9.0:
            return 4
        elif cvss >= 7.0:
            return 3
        elif cvss >= 4.0:
            return 2
        return 1

    def _estimate_impact(self, finding: Dict) -> int:
        """Estimate impact score (1-5) for a finding."""
        severity = finding.get('severity', 'info').lower()
        severity_map = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1,
        }
        return severity_map.get(severity, 1)
