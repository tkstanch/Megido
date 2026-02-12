"""
Advanced Reporting System for SQL Injection Findings

Generates professional reports in multiple formats (Markdown, HTML, JSON)
with comprehensive findings, visualizations, and actionable recommendations.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Advanced report generator for SQL injection findings.
    Supports multiple output formats with rich content.
    """
    
    def __init__(self):
        """Initialize report generator"""
        self.findings = []
        self.metadata = {
            'scan_start': None,
            'scan_end': None,
            'target_url': None,
            'total_requests': 0,
            'vulnerabilities_found': 0,
        }
    
    def add_finding(self, finding: Dict[str, Any]):
        """Add a vulnerability finding to the report"""
        self.findings.append(finding)
        self.metadata['vulnerabilities_found'] = len(self.findings)
    
    def set_metadata(self, **kwargs):
        """Set report metadata"""
        self.metadata.update(kwargs)
    
    def generate_markdown(self, output_path: Optional[str] = None) -> str:
        """
        Generate Markdown report.
        
        Args:
            output_path: Optional path to save report
        
        Returns:
            Markdown report string
        """
        lines = []
        
        # Header
        lines.append("# SQL Injection Security Assessment Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Target:** {self.metadata.get('target_url', 'N/A')}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"This security assessment identified **{self.metadata['vulnerabilities_found']}** ")
        lines.append(f"SQL injection vulnerabilities in the target application.")
        lines.append("")
        
        if self.metadata['vulnerabilities_found'] > 0:
            critical = sum(1 for f in self.findings if f.get('severity') == 'critical')
            high = sum(1 for f in self.findings if f.get('severity') == 'high')
            medium = sum(1 for f in self.findings if f.get('severity') == 'medium')
            low = sum(1 for f in self.findings if f.get('severity') == 'low')
            
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append(f"- 🔴 **Critical**: {critical}")
            lines.append(f"- 🟠 **High**: {high}")
            lines.append(f"- 🟡 **Medium**: {medium}")
            lines.append(f"- 🟢 **Low**: {low}")
            lines.append("")
        
        # Scan Statistics
        lines.append("## Scan Statistics")
        lines.append("")
        lines.append(f"- **Total Requests**: {self.metadata.get('total_requests', 'N/A')}")
        lines.append(f"- **Scan Duration**: {self._format_duration()}")
        lines.append(f"- **Vulnerabilities Found**: {self.metadata['vulnerabilities_found']}")
        lines.append("")
        
        # Detailed Findings
        if self.findings:
            lines.append("## Detailed Findings")
            lines.append("")
            
            for i, finding in enumerate(self.findings, 1):
                lines.append(f"### {i}. {finding.get('title', 'SQL Injection Vulnerability')}")
                lines.append("")
                
                # Severity badge
                severity = finding.get('severity', 'medium').upper()
                severity_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(severity, '⚪')
                
                lines.append(f"**Severity:** {severity_emoji} {severity}")
                lines.append(f"**Confidence:** {finding.get('confidence_score', 0):.1%}")
                lines.append(f"**Risk Score:** {finding.get('risk_score', 0)}/100")
                lines.append("")
                
                # Vulnerability Details
                lines.append("#### Vulnerability Details")
                lines.append("")
                lines.append(f"- **Injection Type:** {finding.get('injection_type', 'Unknown')}")
                lines.append(f"- **Vulnerable Parameter:** `{finding.get('vulnerable_parameter', 'N/A')}`")
                lines.append(f"- **Parameter Type:** {finding.get('parameter_type', 'N/A')}")
                lines.append(f"- **Database Type:** {finding.get('database_type', 'Unknown')}")
                lines.append("")
                
                # Test Payload
                if finding.get('test_payload'):
                    lines.append("#### Test Payload")
                    lines.append("")
                    lines.append("```sql")
                    lines.append(finding['test_payload'])
                    lines.append("```")
                    lines.append("")
                
                # Detection Evidence
                if finding.get('detection_evidence'):
                    lines.append("#### Detection Evidence")
                    lines.append("")
                    lines.append(f"```")
                    lines.append(finding['detection_evidence'][:500])  # Truncate long evidence
                    if len(finding['detection_evidence']) > 500:
                        lines.append("... (truncated)")
                    lines.append("```")
                    lines.append("")
                
                # Impact Analysis
                if finding.get('impact_analysis'):
                    impact = finding['impact_analysis']
                    lines.append("#### Impact Analysis")
                    lines.append("")
                    lines.append(f"- **Exploitable:** {'Yes' if impact.get('exploitable') else 'No'}")
                    lines.append(f"- **Data Extracted:** {'Yes' if impact.get('data_extracted') else 'No'}")
                    lines.append(f"- **Schema Enumerated:** {'Yes' if impact.get('schema_enumerated') else 'No'}")
                    
                    if impact.get('extracted_info'):
                        info = impact['extracted_info']
                        if info.get('database_version'):
                            lines.append(f"- **Database Version:** {info['database_version']}")
                        if info.get('current_database'):
                            lines.append(f"- **Current Database:** {info['current_database']}")
                    lines.append("")
                
                # Proof of Concept
                if finding.get('impact_analysis', {}).get('proof_of_concept'):
                    lines.append("#### Proof of Concept")
                    lines.append("")
                    for poc in finding['impact_analysis']['proof_of_concept'][:5]:
                        lines.append(f"- {poc}")
                    lines.append("")
                
                # Privilege Escalation
                if finding.get('comprehensive_analysis', {}).get('escalation_paths'):
                    paths = finding['comprehensive_analysis']['escalation_paths']
                    lines.append("#### ⚠️ Privilege Escalation Opportunities")
                    lines.append("")
                    for path in paths:
                        lines.append(f"- **{path['name']}** ({path['risk_level']} risk)")
                        lines.append(f"  - Exploitability: {path['exploitability']:.1%}")
                        lines.append(f"  - {path['description']}")
                    lines.append("")
                
                lines.append("---")
                lines.append("")
        
        # Recommendations
        lines.append("## Security Recommendations")
        lines.append("")
        lines.append("### Immediate Actions")
        lines.append("")
        lines.append("1. **Apply Input Validation**: Implement strict input validation for all user inputs")
        lines.append("2. **Use Parameterized Queries**: Replace all dynamic SQL with parameterized queries/prepared statements")
        lines.append("3. **Apply Least Privilege**: Ensure database accounts have minimal required privileges")
        lines.append("4. **Enable WAF**: Deploy or configure Web Application Firewall with SQLi rules")
        lines.append("")
        
        lines.append("### Long-term Improvements")
        lines.append("")
        lines.append("1. **Code Review**: Conduct comprehensive security code review")
        lines.append("2. **Security Testing**: Implement automated security testing in CI/CD pipeline")
        lines.append("3. **Developer Training**: Provide secure coding training for development team")
        lines.append("4. **Security Monitoring**: Implement logging and monitoring for attack detection")
        lines.append("")
        
        # Appendix
        lines.append("## Appendix")
        lines.append("")
        lines.append("### References")
        lines.append("")
        lines.append("- OWASP Top 10: Injection")
        lines.append("- CWE-89: SQL Injection")
        lines.append("- MITRE ATT&CK: T1190 - Exploit Public-Facing Application")
        lines.append("")
        
        report = "\n".join(lines)
        
        # Save to file if path provided
        if output_path:
            Path(output_path).write_text(report)
            logger.info(f"Markdown report saved to: {output_path}")
        
        return report
    
    def generate_html(self, output_path: Optional[str] = None) -> str:
        """
        Generate HTML report with styling.
        
        Args:
            output_path: Optional path to save report
        
        Returns:
            HTML report string
        """
        html = []
        
        # HTML header with CSS
        html.append("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 5px;
        }
        h3 {
            color: #7f8c8d;
        }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #e67e22; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 5px;
        }
        .badge-critical { background: #e74c3c; color: white; }
        .badge-high { background: #e67e22; color: white; }
        .badge-medium { background: #f39c12; color: white; }
        .badge-low { background: #27ae60; color: white; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            text-align: center;
        }
        .stat-number {
            font-size: 32px;
            font-weight: bold;
            color: #3498db;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 14px;
        }
        .finding {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .code {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .recommendation {
            background: #e8f5e9;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
        }
        tr:hover {
            background: #f5f5f5;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SQL Injection Security Assessment Report</h1>
        <p><strong>Generated:</strong> """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        <p><strong>Target:</strong> """ + self.metadata.get('target_url', 'N/A') + """</p>
        """)
        
        # Executive Summary
        html.append("""
        <h2>Executive Summary</h2>
        <p>This security assessment identified <strong>""" + str(self.metadata['vulnerabilities_found']) + """</strong> 
        SQL injection vulnerabilities in the target application.</p>
        """)
        
        # Statistics
        if self.findings:
            critical = sum(1 for f in self.findings if f.get('severity') == 'critical')
            high = sum(1 for f in self.findings if f.get('severity') == 'high')
            medium = sum(1 for f in self.findings if f.get('severity') == 'medium')
            low = sum(1 for f in self.findings if f.get('severity') == 'low')
            
            html.append("""
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">""" + str(critical) + """</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">""" + str(high) + """</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">""" + str(medium) + """</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">""" + str(low) + """</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
            """)
        
        # Findings
        if self.findings:
            html.append("<h2>Detailed Findings</h2>")
            
            for i, finding in enumerate(self.findings, 1):
                severity = finding.get('severity', 'medium')
                html.append(f"""
        <div class="finding">
            <h3>{i}. {finding.get('title', 'SQL Injection Vulnerability')}</h3>
            <p>
                <span class="badge badge-{severity}">{severity.upper()}</span>
                <span class="badge" style="background: #95a5a6; color: white;">
                    Confidence: {finding.get('confidence_score', 0):.0%}
                </span>
            </p>
            <p><strong>Vulnerable Parameter:</strong> <code>{finding.get('vulnerable_parameter', 'N/A')}</code></p>
            <p><strong>Injection Type:</strong> {finding.get('injection_type', 'Unknown')}</p>
            <p><strong>Database:</strong> {finding.get('database_type', 'Unknown')}</p>
                """)
                
                if finding.get('test_payload'):
                    html.append(f"""
            <p><strong>Test Payload:</strong></p>
            <div class="code">{self._html_escape(finding['test_payload'])}</div>
                    """)
                
                html.append("</div>")
        
        # Recommendations
        html.append("""
        <h2>Security Recommendations</h2>
        <div class="recommendation">
            <h3>Immediate Actions</h3>
            <ol>
                <li>Apply strict input validation for all user inputs</li>
                <li>Use parameterized queries/prepared statements</li>
                <li>Apply least privilege principle to database accounts</li>
                <li>Deploy or configure Web Application Firewall</li>
            </ol>
        </div>
        """)
        
        html.append("""
    </div>
</body>
</html>
        """)
        
        report = "".join(html)
        
        if output_path:
            Path(output_path).write_text(report)
            logger.info(f"HTML report saved to: {output_path}")
        
        return report
    
    def generate_json(self, output_path: Optional[str] = None) -> str:
        """
        Generate JSON report for automation.
        
        Args:
            output_path: Optional path to save report
        
        Returns:
            JSON report string
        """
        report_data = {
            'metadata': self.metadata,
            'summary': {
                'total_vulnerabilities': self.metadata['vulnerabilities_found'],
                'severity_breakdown': self._get_severity_breakdown(),
                'scan_duration': self._format_duration(),
            },
            'findings': self.findings,
            'generated_at': datetime.now().isoformat(),
        }
        
        report = json.dumps(report_data, indent=2)
        
        if output_path:
            Path(output_path).write_text(report)
            logger.info(f"JSON report saved to: {output_path}")
        
        return report
    
    def _format_duration(self) -> str:
        """Format scan duration"""
        start = self.metadata.get('scan_start')
        end = self.metadata.get('scan_end')
        
        if start and end:
            duration = (end - start).total_seconds()
            return f"{duration:.2f} seconds"
        return "N/A"
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get severity breakdown"""
        return {
            'critical': sum(1 for f in self.findings if f.get('severity') == 'critical'),
            'high': sum(1 for f in self.findings if f.get('severity') == 'high'),
            'medium': sum(1 for f in self.findings if f.get('severity') == 'medium'),
            'low': sum(1 for f in self.findings if f.get('severity') == 'low'),
        }
    
    def _html_escape(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
