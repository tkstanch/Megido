"""
Report Generator

Generates professional security assessment reports in multiple formats:
- **JSON**: Machine-readable findings + metadata
- **Markdown**: Human-readable report with executive summary and remediation guidance
- **SARIF 2.1**: Compatible with GitHub Code Scanning / Azure DevOps

Usage::

    from scanner.report_generator import ReportGenerator, ScanReport

    report = ScanReport(target='https://example.com', ...)
    gen = ReportGenerator()
    gen.write_json(report, '/tmp/report.json')
    gen.write_markdown(report, '/tmp/report.md')
    gen.write_sarif(report, '/tmp/report.sarif.json')
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


@dataclass
class ScanReport:
    """
    Complete scan report produced by the orchestrator or any scan engine.

    Attributes:
        target: URL that was scanned.
        scan_duration: Wall-clock duration in seconds.
        urls_scanned: Number of individual URLs tested.
        vulnerabilities_found: Total number of findings (post dedup).
        risk_score: Aggregate risk score 0–100.
        technology_stack: Tech stack dictionary (from TechFingerprinter).
        findings: Vulnerability findings sorted by severity.
        scan_metrics: Raw performance metrics dict.
        recommendations: Prioritised list of remediation steps.
        scan_id: Optional identifier for this scan run.
        timestamp: ISO-8601 timestamp of scan start.
    """
    target: str
    scan_duration: float = 0.0
    urls_scanned: int = 0
    vulnerabilities_found: int = 0
    risk_score: float = 0.0
    technology_stack: Dict[str, Any] = field(default_factory=dict)
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    scan_metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    scan_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generate professional security assessment reports from a :class:`ScanReport`.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_json(self, report: ScanReport) -> str:
        """
        Serialise *report* to a JSON string.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(self._report_to_dict(report), indent=2, default=str)

    def write_json(self, report: ScanReport, path: str) -> None:
        """Write JSON report to *path*."""
        Path(path).write_text(self.to_json(report), encoding='utf-8')
        logger.info("JSON report written to %s", path)

    def to_markdown(self, report: ScanReport) -> str:
        """
        Render *report* as a Markdown document.

        Returns:
            Markdown string.
        """
        lines: List[str] = []
        sorted_findings = self._sort_findings(report.findings)

        # Header
        lines += [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {report.target}  ",
            f"**Scan Date:** {report.timestamp}  ",
            f"**Scan Duration:** {report.scan_duration:.1f}s  ",
            f"**URLs Scanned:** {report.urls_scanned}  ",
            f"**Risk Score:** {report.risk_score:.0f}/100  ",
            f"",
            "---",
            "",
        ]

        # Executive Summary
        lines += self._executive_summary_md(report, sorted_findings)

        # Technology Stack
        if report.technology_stack:
            lines += self._tech_stack_md(report.technology_stack)

        # Findings by severity
        lines += ["## Findings", ""]
        for severity in ('critical', 'high', 'medium', 'low'):
            sev_findings = [f for f in sorted_findings if f.severity.lower() == severity]
            if sev_findings:
                lines += self._severity_section_md(severity.capitalize(), sev_findings)

        # Remediation Priorities
        if report.recommendations:
            lines += ["## Remediation Priorities", ""]
            for i, rec in enumerate(report.recommendations, start=1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Scan Metrics
        if report.scan_metrics:
            lines += self._metrics_md(report.scan_metrics)

        return "\n".join(lines)

    def write_markdown(self, report: ScanReport, path: str) -> None:
        """Write Markdown report to *path*."""
        Path(path).write_text(self.to_markdown(report), encoding='utf-8')
        logger.info("Markdown report written to %s", path)

    def to_sarif(self, report: ScanReport) -> str:
        """
        Serialise *report* as a SARIF 2.1.0 JSON string.

        Returns:
            SARIF-formatted JSON string.
        """
        sarif = self._build_sarif(report)
        return json.dumps(sarif, indent=2, default=str)

    def write_sarif(self, report: ScanReport, path: str) -> None:
        """Write SARIF report to *path*."""
        Path(path).write_text(self.to_sarif(report), encoding='utf-8')
        logger.info("SARIF report written to %s", path)

    # ------------------------------------------------------------------
    # JSON helpers
    # ------------------------------------------------------------------

    def _report_to_dict(self, report: ScanReport) -> Dict[str, Any]:
        sorted_findings = self._sort_findings(report.findings)
        severity_counts = self._severity_counts(sorted_findings)
        top5 = [f.to_dict() for f in sorted_findings[:5]]

        return {
            'scan_id': report.scan_id,
            'target': report.target,
            'timestamp': report.timestamp,
            'scan_duration_seconds': report.scan_duration,
            'urls_scanned': report.urls_scanned,
            'vulnerabilities_found': report.vulnerabilities_found,
            'risk_score': report.risk_score,
            'severity_summary': severity_counts,
            'overall_risk_rating': self._risk_rating(report.risk_score),
            'top_5_findings': top5,
            'technology_stack': report.technology_stack,
            'findings': [f.to_dict() for f in sorted_findings],
            'scan_metrics': report.scan_metrics,
            'recommendations': report.recommendations,
        }

    # ------------------------------------------------------------------
    # Markdown helpers
    # ------------------------------------------------------------------

    def _executive_summary_md(
        self,
        report: ScanReport,
        sorted_findings: List[VulnerabilityFinding],
    ) -> List[str]:
        counts = self._severity_counts(sorted_findings)
        rating = self._risk_rating(report.risk_score)
        lines = [
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Overall Risk | **{rating}** |",
            f"| Risk Score | {report.risk_score:.0f}/100 |",
            f"| Critical | {counts.get('critical', 0)} |",
            f"| High | {counts.get('high', 0)} |",
            f"| Medium | {counts.get('medium', 0)} |",
            f"| Low | {counts.get('low', 0)} |",
            f"| Total | {report.vulnerabilities_found} |",
            "",
        ]

        top5 = sorted_findings[:5]
        if top5:
            lines += ["### Top 5 Critical Findings", ""]
            for i, f in enumerate(top5, start=1):
                lines.append(
                    f"{i}. **[{f.severity.upper()}]** `{f.vulnerability_type}` — {f.url}"
                )
            lines.append("")

        return lines

    def _tech_stack_md(self, tech: Dict[str, Any]) -> List[str]:
        lines = ["## Technology Stack", "", "| Component | Value |", "|-----------|-------|"]
        for key, value in tech.items():
            if key == 'detected_technologies':
                continue
            if value:
                lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
        lines.append("")
        return lines

    def _severity_section_md(
        self,
        severity_label: str,
        findings: List[VulnerabilityFinding],
    ) -> List[str]:
        _icons = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢',
        }
        icon = _icons.get(severity_label, '')
        lines = [f"### {icon} {severity_label} ({len(findings)})", ""]
        for f in findings:
            lines += [
                f"#### {f.vulnerability_type.upper()} — `{f.url}`",
                f"",
                f"- **Parameter:** {f.parameter or 'N/A'}",
                f"- **Confidence:** {f.confidence:.0%}",
                f"- **CWE:** {f.cwe_id or 'N/A'}",
                f"- **Description:** {f.description}",
                f"- **Evidence:** {f.evidence}",
                f"- **Remediation:** {f.remediation}",
                "",
            ]
        return lines

    def _metrics_md(self, metrics: Dict[str, Any]) -> List[str]:
        lines = ["## Scan Metrics", ""]
        for k, v in metrics.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # SARIF builder
    # ------------------------------------------------------------------

    def _build_sarif(self, report: ScanReport) -> Dict[str, Any]:
        rules: List[Dict] = []
        results: List[Dict] = []

        seen_rules: Dict[str, bool] = {}

        for finding in report.findings:
            rule_id = finding.vulnerability_type.upper()
            if rule_id not in seen_rules:
                seen_rules[rule_id] = True
                rules.append({
                    'id': rule_id,
                    'name': finding.vulnerability_type.replace('_', ' ').title(),
                    'shortDescription': {'text': finding.description[:100]},
                    'fullDescription': {'text': finding.description},
                    'helpUri': f"https://cwe.mitre.org/data/definitions/{(finding.cwe_id or 'N/A').replace('CWE-', '')}.html",
                    'properties': {
                        'tags': ['security', finding.severity],
                        'security-severity': self._sarif_severity(finding.severity),
                    },
                })

            results.append({
                'ruleId': rule_id,
                'level': self._sarif_level(finding.severity),
                'message': {
                    'text': (
                        f"{finding.description}\n\n"
                        f"Evidence: {finding.evidence}\n\n"
                        f"Remediation: {finding.remediation}"
                    )
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': finding.url, 'uriBaseId': '%SRCROOT%'},
                    },
                }],
                'properties': {
                    'parameter': finding.parameter,
                    'confidence': finding.confidence,
                    'cwe': finding.cwe_id,
                    'verified': finding.verified,
                },
            })

        return {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'Megido',
                        'version': '5.0',
                        'informationUri': 'https://github.com/tkstanch/Megido',
                        'rules': rules,
                    },
                },
                'results': results,
                'properties': {
                    'target': report.target,
                    'scanDuration': report.scan_duration,
                    'riskScore': report.risk_score,
                    'timestamp': report.timestamp,
                },
            }],
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sort_findings(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        return sorted(
            findings,
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity.lower(), 99),
                -(f.confidence or 0),
            ),
        )

    @staticmethod
    def _severity_counts(findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        counts: Dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in findings:
            key = f.severity.lower()
            if key in counts:
                counts[key] += 1
        return counts

    @staticmethod
    def _risk_rating(score: float) -> str:
        if score >= 75:
            return 'Critical'
        if score >= 50:
            return 'High'
        if score >= 25:
            return 'Medium'
        return 'Low'

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
        }.get(severity.lower(), 'note')

    @staticmethod
    def _sarif_severity(severity: str) -> str:
        """Map to CVSS-inspired numeric string for GitHub Advanced Security."""
        return {
            'critical': '9.0',
            'high': '7.0',
            'medium': '5.0',
            'low': '3.0',
        }.get(severity.lower(), '1.0')
