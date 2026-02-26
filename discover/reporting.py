"""
Advanced Reporting Module

Generates reconnaissance reports in multiple formats:
  - HTML  (standalone interactive)
  - JSON  (machine-readable)
  - CSV   (findings export)
  - Markdown (bug-bounty friendly)

PDF generation is supported when ``reportlab`` is installed; if not, a
graceful fallback is provided.
"""
import csv
import json
import logging
import os
from datetime import datetime
from io import StringIO, BytesIO
from typing import Any, Dict, List, Optional

from django.http import HttpResponse
from django.utils import timezone

from .models import (
    Scan,
    SensitiveFinding,
    Subdomain,
    DNSRecord,
    Certificate,
    Technology,
    EmailAddress,
    SocialProfile,
    CloudResource,
    PortService,
    ThreatIntelIndicator,
)

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.info("reportlab not installed — PDF export unavailable")


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

class ReconReportBuilder:
    """
    Builds rich reconnaissance reports from a ``Scan`` instance.
    """

    def __init__(self, scan: Scan):
        self.scan = scan
        self.generated_at = timezone.now()

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def build_html(self) -> str:
        """Return a standalone HTML report string."""
        scan = self.scan
        findings = list(scan.sensitive_findings.all().order_by('-discovered_at'))
        subdomains = list(scan.subdomains.all()) if hasattr(scan, 'subdomains') else []
        dns_records = list(scan.dns_records.all()) if hasattr(scan, 'dns_records') else []
        technologies = list(scan.technologies.all()) if hasattr(scan, 'technologies') else []
        emails = list(scan.email_addresses.all()) if hasattr(scan, 'email_addresses') else []
        clouds = list(scan.cloud_resources.all()) if hasattr(scan, 'cloud_resources') else []
        threat_intel = list(scan.threat_intel.all()) if hasattr(scan, 'threat_intel') else []

        risk_score = self._calculate_risk_score(scan, findings, threat_intel)
        summary = self._build_executive_summary(scan, findings, subdomains, risk_score)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report: {self._esc(scan.target)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  h1 {{ color: #38bdf8; font-size: 2rem; margin-bottom: 0.5rem; }}
  h2 {{ color: #7dd3fc; font-size: 1.3rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; margin-top: 2rem; }}
  h3 {{ color: #93c5fd; font-size: 1rem; }}
  .meta {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }}
  .risk-badge {{ display: inline-block; padding: 0.3rem 1rem; border-radius: 9999px; font-weight: bold; font-size: 1rem; }}
  .risk-critical {{ background: #7f1d1d; color: #fca5a5; }}
  .risk-high {{ background: #7c2d12; color: #fdba74; }}
  .risk-medium {{ background: #713f12; color: #fde68a; }}
  .risk-low {{ background: #14532d; color: #86efac; }}
  .risk-info {{ background: #164e63; color: #67e8f9; }}
  .summary-box {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 2rem; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: #1e293b; border-radius: 0.5rem; padding: 1rem; text-align: center; }}
  .stat-value {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
  .stat-label {{ color: #94a3b8; font-size: 0.8rem; margin-top: 0.25rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 0.5rem; overflow: hidden; margin-bottom: 1.5rem; }}
  th {{ background: #334155; color: #94a3b8; text-align: left; padding: 0.75rem 1rem; font-size: 0.85rem; text-transform: uppercase; }}
  td {{ padding: 0.6rem 1rem; border-top: 1px solid #334155; font-size: 0.9rem; word-break: break-all; }}
  tr:hover td {{ background: #263248; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
  .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-high {{ background: #7c2d12; color: #fdba74; }}
  .badge-medium {{ background: #713f12; color: #fde68a; }}
  .badge-low {{ background: #14532d; color: #86efac; }}
  .badge-info {{ background: #164e63; color: #67e8f9; }}
  pre {{ background: #0f172a; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; font-size: 0.8rem; color: #a5f3fc; }}
  .footer {{ margin-top: 3rem; text-align: center; color: #475569; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>🔍 Reconnaissance Report</h1>
  <div class="meta">
    Target: <strong>{self._esc(scan.target)}</strong> &nbsp;|&nbsp;
    Scan ID: {scan.pk} &nbsp;|&nbsp;
    Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}
  </div>

  <div class="summary-box">
    <h2 style="margin-top:0">Executive Summary</h2>
    <p>{self._esc(summary)}</p>
    <p>Overall Risk Score: <span class="risk-badge {self._risk_class(risk_score)}">{risk_score}/100</span></p>
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-value">{len(subdomains)}</div><div class="stat-label">Subdomains</div></div>
    <div class="stat-card"><div class="stat-value">{len(dns_records)}</div><div class="stat-label">DNS Records</div></div>
    <div class="stat-card"><div class="stat-value">{len(technologies)}</div><div class="stat-label">Technologies</div></div>
    <div class="stat-card"><div class="stat-value">{len(emails)}</div><div class="stat-label">Emails Found</div></div>
    <div class="stat-card"><div class="stat-value">{len(clouds)}</div><div class="stat-label">Cloud Resources</div></div>
    <div class="stat-card"><div class="stat-value">{scan.total_findings}</div><div class="stat-label">Sensitive Findings</div></div>
    <div class="stat-card"><div class="stat-value">{scan.high_risk_findings}</div><div class="stat-label">High Risk Findings</div></div>
  </div>

  {self._html_subdomains_section(subdomains)}
  {self._html_findings_section(findings)}
  {self._html_dns_section(dns_records)}
  {self._html_tech_section(technologies)}
  {self._html_emails_section(emails)}
  {self._html_cloud_section(clouds)}
  {self._html_threat_section(threat_intel)}

  <div class="footer">Generated by Megido OSINT Framework · {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}</div>
</div>
</body>
</html>"""
        return html

    # ------------------------------------------------------------------
    # JSON report
    # ------------------------------------------------------------------

    def build_json(self) -> str:
        """Return a JSON string containing all scan data."""
        scan = self.scan
        data = {
            'report_version': '2.0',
            'generated_at': self.generated_at.isoformat(),
            'scan': {
                'id': scan.pk,
                'target': scan.target,
                'scan_date': scan.scan_date.isoformat(),
                'total_findings': scan.total_findings,
                'high_risk_findings': scan.high_risk_findings,
                'total_urls': scan.total_urls,
                'total_emails': scan.total_emails,
            },
            'sensitive_findings': [
                {
                    'type': f.finding_type,
                    'severity': f.severity,
                    'url': f.url,
                    'value': f.value[:200],
                    'context': f.context[:300],
                }
                for f in scan.sensitive_findings.all()[:500]
            ],
            'subdomains': [
                {'subdomain': s.subdomain, 'ip': s.ip_address, 'source': s.source}
                for s in (scan.subdomains.all() if hasattr(scan, 'subdomains') else [])
            ],
            'dns_records': [
                {'type': r.record_type, 'name': r.name, 'value': r.value}
                for r in (scan.dns_records.all() if hasattr(scan, 'dns_records') else [])
            ],
            'technologies': [
                {'name': t.name, 'category': t.category, 'confidence': t.confidence}
                for t in (scan.technologies.all() if hasattr(scan, 'technologies') else [])
            ],
            'emails': [
                {'email': e.email, 'source': e.source, 'verified': e.verified}
                for e in (scan.email_addresses.all() if hasattr(scan, 'email_addresses') else [])
            ],
            'cloud_resources': [
                {'type': c.resource_type, 'name': c.name, 'url': c.url, 'access': c.access_level}
                for c in (scan.cloud_resources.all() if hasattr(scan, 'cloud_resources') else [])
            ],
        }
        return json.dumps(data, indent=2, default=str)

    # ------------------------------------------------------------------
    # CSV report
    # ------------------------------------------------------------------

    def build_csv_findings(self) -> str:
        """Return a CSV string of all sensitive findings."""
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Severity', 'Type', 'URL', 'Value', 'Context', 'Discovered At'])
        for f in self.scan.sensitive_findings.all().order_by('-discovered_at'):
            writer.writerow([
                f.severity,
                f.finding_type,
                f.url,
                f.value[:300],
                f.context[:300],
                f.discovered_at.isoformat(),
            ])
        return output.getvalue()

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def build_markdown(self) -> str:
        """Return a Markdown report suitable for bug bounty submissions."""
        scan = self.scan
        risk_score = self._calculate_risk_score(scan, list(scan.sensitive_findings.all()), [])
        lines = [
            f'# Reconnaissance Report: {scan.target}',
            '',
            f'**Scan Date:** {scan.scan_date.strftime("%Y-%m-%d %H:%M UTC")}  ',
            f'**Risk Score:** {risk_score}/100  ',
            f'**Sensitive Findings:** {scan.total_findings} ({scan.high_risk_findings} high-risk)  ',
            '',
            '## Executive Summary',
            '',
            self._build_executive_summary(
                scan,
                list(scan.sensitive_findings.all()),
                list(scan.subdomains.all()) if hasattr(scan, 'subdomains') else [],
                risk_score,
            ),
            '',
            '## Sensitive Findings',
            '',
            '| Severity | Type | URL | Value |',
            '|----------|------|-----|-------|',
        ]
        for f in scan.sensitive_findings.all().order_by('-discovered_at')[:50]:
            val = f.value[:80].replace('|', '\\|')
            lines.append(f'| {f.severity} | {f.finding_type} | {f.url[:60]} | `{val}` |')

        lines += [
            '',
            '## Subdomains Discovered',
            '',
        ]
        for s in (scan.subdomains.all() if hasattr(scan, 'subdomains') else []):
            lines.append(f'- `{s.subdomain}` ({s.ip_address or "unknown IP"})')

        lines += ['', '---', f'*Report generated by Megido OSINT Framework*']
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # PDF report
    # ------------------------------------------------------------------

    def build_pdf(self) -> Optional[bytes]:
        """Return PDF bytes, or None if reportlab is not installed."""
        if not REPORTLAB_AVAILABLE:
            logger.warning("reportlab not installed — cannot generate PDF")
            return None

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        elements.append(Paragraph(f"Reconnaissance Report: {self.scan.target}", styles['Title']))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(
            f"Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            styles['Normal'],
        ))
        elements.append(Spacer(1, 0.3 * inch))

        # Findings table
        findings = list(self.scan.sensitive_findings.all().order_by('-discovered_at')[:100])
        if findings:
            elements.append(Paragraph("Sensitive Findings", styles['Heading2']))
            elements.append(Spacer(1, 0.1 * inch))
            table_data = [['Severity', 'Type', 'URL']]
            for f in findings:
                table_data.append([f.severity.upper(), f.finding_type[:30], f.url[:60]])
            table = Table(table_data, colWidths=[1 * inch, 2 * inch, 4 * inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ]))
            elements.append(table)

        doc.build(elements)
        return buffer.getvalue()

    # ------------------------------------------------------------------
    # HTTP response helpers
    # ------------------------------------------------------------------

    def as_http_response(self, fmt: str = 'html') -> HttpResponse:
        """Return an appropriate HttpResponse for the requested format."""
        fmt = fmt.lower()
        if fmt == 'html':
            return HttpResponse(self.build_html(), content_type='text/html; charset=utf-8')
        elif fmt == 'json':
            return HttpResponse(self.build_json(), content_type='application/json')
        elif fmt == 'csv':
            resp = HttpResponse(self.build_csv_findings(), content_type='text/csv')
            resp['Content-Disposition'] = (
                f'attachment; filename="scan_{self.scan.pk}_findings.csv"'
            )
            return resp
        elif fmt == 'markdown':
            resp = HttpResponse(self.build_markdown(), content_type='text/markdown')
            resp['Content-Disposition'] = f'attachment; filename="scan_{self.scan.pk}_report.md"'
            return resp
        elif fmt == 'pdf':
            pdf = self.build_pdf()
            if pdf is None:
                return HttpResponse('PDF generation not available (reportlab required)', status=501)
            resp = HttpResponse(pdf, content_type='application/pdf')
            resp['Content-Disposition'] = f'attachment; filename="scan_{self.scan.pk}_report.pdf"'
            return resp
        else:
            return HttpResponse(f'Unknown format: {fmt}', status=400)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _calculate_risk_score(
        self,
        scan: Scan,
        findings: List,
        threat_intel: List,
    ) -> int:
        score = 0
        critical = sum(1 for f in findings if f.severity == 'critical')
        high = sum(1 for f in findings if f.severity == 'high')
        score += min(critical * 20, 50)
        score += min(high * 10, 30)
        for ti in threat_intel:
            score += min(getattr(ti, 'threat_score', 0), 20)
        return min(score, 100)

    def _build_executive_summary(
        self,
        scan: Scan,
        findings: List,
        subdomains: List,
        risk_score: int,
    ) -> str:
        critical = sum(1 for f in findings if f.severity == 'critical')
        high = sum(1 for f in findings if f.severity == 'high')
        return (
            f"Reconnaissance scan of {scan.target} discovered {len(subdomains)} subdomains "
            f"and {len(findings)} sensitive findings ({critical} critical, {high} high severity). "
            f"The overall risk score is {risk_score}/100. "
            f"Immediate attention is recommended for any critical and high severity findings."
        )

    def _risk_class(self, score: int) -> str:
        if score >= 70:
            return 'risk-critical'
        elif score >= 50:
            return 'risk-high'
        elif score >= 30:
            return 'risk-medium'
        elif score >= 10:
            return 'risk-low'
        return 'risk-info'

    @staticmethod
    def _esc(text: str) -> str:
        """HTML-escape a string."""
        return (
            str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
        )

    def _html_findings_section(self, findings: List) -> str:
        if not findings:
            return ''
        rows = ''.join(
            f'<tr><td><span class="badge badge-{f.severity}">{f.severity}</span></td>'
            f'<td>{self._esc(f.finding_type)}</td>'
            f'<td>{self._esc(f.url[:80])}</td>'
            f'<td><code>{self._esc(f.value[:80])}</code></td></tr>'
            for f in findings[:200]
        )
        return f'''
<h2>Sensitive Findings ({len(findings)})</h2>
<table>
<thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Value</th></tr></thead>
<tbody>{rows}</tbody>
</table>'''

    def _html_subdomains_section(self, subdomains: List) -> str:
        if not subdomains:
            return ''
        rows = ''.join(
            f'<tr><td>{self._esc(s.subdomain)}</td><td>{self._esc(s.ip_address or "—")}</td>'
            f'<td>{self._esc(s.source or "—")}</td></tr>'
            for s in subdomains[:200]
        )
        return f'''
<h2>Subdomains ({len(subdomains)})</h2>
<table>
<thead><tr><th>Subdomain</th><th>IP Address</th><th>Source</th></tr></thead>
<tbody>{rows}</tbody>
</table>'''

    def _html_dns_section(self, dns_records: List) -> str:
        if not dns_records:
            return ''
        rows = ''.join(
            f'<tr><td>{self._esc(r.record_type)}</td><td>{self._esc(r.name)}</td>'
            f'<td>{self._esc(r.value[:120])}</td></tr>'
            for r in dns_records[:100]
        )
        return f'''
<h2>DNS Records ({len(dns_records)})</h2>
<table>
<thead><tr><th>Type</th><th>Name</th><th>Value</th></tr></thead>
<tbody>{rows}</tbody>
</table>'''

    def _html_tech_section(self, technologies: List) -> str:
        if not technologies:
            return ''
        rows = ''.join(
            f'<tr><td>{self._esc(t.name)}</td><td>{self._esc(t.category)}</td>'
            f'<td>{self._esc(t.confidence)}</td></tr>'
            for t in technologies
        )
        return f'''
<h2>Technologies ({len(technologies)})</h2>
<table>
<thead><tr><th>Technology</th><th>Category</th><th>Confidence</th></tr></thead>
<tbody>{rows}</tbody>
</table>'''

    def _html_emails_section(self, emails: List) -> str:
        if not emails:
            return ''
        rows = ''.join(
            f'<tr><td>{self._esc(e.email)}</td><td>{self._esc(e.source or "—")}</td>'
            f'<td>{"✓" if e.verified else "—"}</td></tr>'
            for e in emails[:200]
        )
        return f'''
<h2>Email Addresses ({len(emails)})</h2>
<table>
<thead><tr><th>Email</th><th>Source</th><th>Verified</th></tr></thead>
<tbody>{rows}</tbody>
</table>'''

    def _html_cloud_section(self, clouds: List) -> str:
        if not clouds:
            return ''
        rows = ''.join(
            f'<tr><td>{self._esc(c.get_resource_type_display())}</td>'
            f'<td>{self._esc(c.name)}</td>'
            f'<td><span class="badge badge-{"critical" if c.access_level == "open" else "medium"}">'
            f'{self._esc(c.access_level)}</span></td></tr>'
            for c in clouds
        )
        return f'''
<h2>Cloud Resources ({len(clouds)})</h2>
<table>
<thead><tr><th>Type</th><th>Name</th><th>Access</th></tr></thead>
<tbody>{rows}</tbody>
</table>'''

    def _html_threat_section(self, threat_intel: List) -> str:
        if not threat_intel:
            return ''
        rows = ''.join(
            f'<tr><td>{self._esc(ti.source)}</td>'
            f'<td>{self._esc(ti.value[:80])}</td>'
            f'<td>{ti.threat_score}</td></tr>'
            for ti in threat_intel
        )
        return f'''
<h2>Threat Intelligence ({len(threat_intel)})</h2>
<table>
<thead><tr><th>Source</th><th>Indicator</th><th>Score</th></tr></thead>
<tbody>{rows}</tbody>
</table>'''
