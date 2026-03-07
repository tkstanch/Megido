"""
Tests for EnhancedReportBuilder.

Covers JSON and Markdown report generation, executive summary,
false positive summary, chain analysis, and remediation roadmap.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.report_builder_enhanced import EnhancedReportBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    finding_id="abc-001",
    vuln_type="XSS",
    severity="high",
    status="confirmed",
    target_url="https://example.com/search",
    parameter="q",
    has_real_impact=True,
    has_tracker=False,
    chain_with=None,
):
    real_impact = None
    if has_real_impact:
        real_impact = {
            "impact_summary": "Session tokens can be stolen via injected JavaScript.",
            "business_impact": "high",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            "cwe_id": "CWE-79",
            "affected_cia": {
                "confidentiality": "high",
                "integrity": "high",
                "availability": "none",
            },
            "remediation_priority": "immediate",
            "technical_impact": {"session_hijack_possible": True},
            "submittable_report": "## Vulnerability: XSS\n**CVSS Score:** 8.8",
        }

    return {
        "finding_id": finding_id,
        "vulnerability_type": vuln_type,
        "target_url": target_url,
        "parameter": parameter,
        "severity": severity,
        "confidence_score": 0.95,
        "status": status,
        "detection_evidence": "Payload reflected in response.",
        "verification_evidence": "Browser confirmed execution.",
        "exploitation_evidence": "Cookie captured.",
        "real_impact": real_impact,
        "false_positive_reason": None if status != "false_positive" else "WAF blocked payload",
        "tracker_issue_id": "SEC-123" if has_tracker else None,
        "tracker_issue_url": "https://jira.example.com/browse/SEC-123" if has_tracker else None,
        "chain_findings": [chain_with] if chain_with else [],
    }


# ---------------------------------------------------------------------------
# Builder basics
# ---------------------------------------------------------------------------

class TestEnhancedReportBuilderBasics:
    def test_empty_report_json(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        data = json.loads(builder.build("json"))
        assert data["executive_summary"]["total_findings"] == 0

    def test_add_finding_increases_count(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        builder.add_finding(_make_finding())
        data = json.loads(builder.build("json"))
        assert data["executive_summary"]["total_findings"] == 1

    def test_add_findings_bulk(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        builder.add_findings([_make_finding("id1"), _make_finding("id2")])
        data = json.loads(builder.build("json"))
        assert data["executive_summary"]["total_findings"] == 2

    def test_unsupported_format_raises(self):
        builder = EnhancedReportBuilder()
        try:
            builder.build("xml")
            assert False, "Expected ValueError"
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

class TestExecutiveSummary:
    def test_severity_breakdown_counts_correctly(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        builder.add_finding(_make_finding(severity="critical"))
        builder.add_finding(_make_finding(finding_id="id2", severity="high"))
        builder.add_finding(_make_finding(finding_id="id3", severity="medium"))

        data = json.loads(builder.build("json"))
        breakdown = data["executive_summary"]["severity_breakdown"]
        assert breakdown["critical"] == 1
        assert breakdown["high"] == 1
        assert breakdown["medium"] == 1

    def test_overall_risk_critical_when_critical_finding(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        builder.add_finding(_make_finding(severity="critical"))
        data = json.loads(builder.build("json"))
        assert data["executive_summary"]["overall_risk"] == "Critical"

    def test_overall_risk_high_when_only_high(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        builder.add_finding(_make_finding(severity="high"))
        data = json.loads(builder.build("json"))
        assert data["executive_summary"]["overall_risk"] == "High"

    def test_false_positives_excluded_from_total(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        builder.add_finding(_make_finding(finding_id="id1", status="confirmed"))
        builder.add_finding(_make_finding(finding_id="id2", status="false_positive"))
        data = json.loads(builder.build("json"))
        assert data["executive_summary"]["total_findings"] == 1
        assert data["executive_summary"]["false_positives_excluded"] == 1


# ---------------------------------------------------------------------------
# Vulnerability details
# ---------------------------------------------------------------------------

class TestVulnerabilityDetails:
    def test_finding_detail_contains_expected_keys(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding())
        data = json.loads(builder.build("json"))
        detail = data["vulnerability_details"][0]

        for key in (
            "finding_id", "vulnerability_type", "target_url", "severity",
            "real_impact_assessment", "submittable_impact", "real_world_scenario",
            "business_risk", "tracker_integration",
        ):
            assert key in detail, f"Missing key: {key}"

    def test_real_impact_assessment_populated(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(has_real_impact=True))
        data = json.loads(builder.build("json"))
        impact = data["vulnerability_details"][0]["real_impact_assessment"]
        assert impact["cvss_score"] == 8.8
        assert impact["cwe_id"] == "CWE-79"

    def test_tracker_integration_populated(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(has_tracker=True))
        data = json.loads(builder.build("json"))
        tracker = data["vulnerability_details"][0]["tracker_integration"]
        assert tracker["issue_id"] == "SEC-123"
        assert "SEC-123" in tracker["issue_url"]

    def test_findings_sorted_by_severity(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="id-low", severity="low"))
        builder.add_finding(_make_finding(finding_id="id-critical", severity="critical"))
        builder.add_finding(_make_finding(finding_id="id-medium", severity="medium"))
        data = json.loads(builder.build("json"))
        severities = [d["severity"] for d in data["vulnerability_details"]]
        assert severities == ["critical", "medium", "low"]


# ---------------------------------------------------------------------------
# False positive summary
# ---------------------------------------------------------------------------

class TestFalsePositiveSummary:
    def test_fp_summary_count(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="fp1", status="false_positive"))
        builder.add_finding(_make_finding(finding_id="fp2", status="false_positive"))
        data = json.loads(builder.build("json"))
        assert data["false_positive_summary"]["count"] == 2

    def test_fp_summary_items_include_reason(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="fp1", status="false_positive"))
        data = json.loads(builder.build("json"))
        item = data["false_positive_summary"]["items"][0]
        assert "reason" in item
        assert item["finding_id"] == "fp1"


# ---------------------------------------------------------------------------
# Vulnerability chain analysis
# ---------------------------------------------------------------------------

class TestChainAnalysis:
    def test_chain_analysis_detects_chained_findings(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="f1", vuln_type="SSRF", chain_with="f2"))
        builder.add_finding(_make_finding(finding_id="f2", vuln_type="XXE"))
        data = json.loads(builder.build("json"))
        chains = data["vulnerability_chain_analysis"]
        assert len(chains) >= 1
        assert "f1" in chains[0]["members"]

    def test_chain_analysis_empty_when_no_chains(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="f1"))
        data = json.loads(builder.build("json"))
        assert data["vulnerability_chain_analysis"] == []


# ---------------------------------------------------------------------------
# Remediation roadmap
# ---------------------------------------------------------------------------

class TestRemediationRoadmap:
    def test_critical_finding_in_immediate_bucket(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="f1", severity="critical"))
        data = json.loads(builder.build("json"))
        immediate = data["remediation_roadmap"]["immediate"]
        assert any(item["finding_id"] == "f1" for item in immediate)

    def test_info_finding_in_backlog_bucket(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="f2", severity="info", has_real_impact=False))
        data = json.loads(builder.build("json"))
        backlog = data["remediation_roadmap"]["backlog"]
        assert any(item["finding_id"] == "f2" for item in backlog)


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

class TestMarkdownOutput:
    def test_markdown_contains_header(self):
        builder = EnhancedReportBuilder(scan_target="https://example.com")
        output = builder.build("markdown")
        assert "# Megido Vulnerability Report" in output
        assert "https://example.com" in output

    def test_markdown_contains_finding_severity(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(severity="high"))
        output = builder.build("markdown")
        assert "HIGH" in output

    def test_markdown_contains_false_positive_section(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(finding_id="fp1", status="false_positive"))
        output = builder.build("markdown")
        assert "False Positive" in output

    def test_markdown_contains_remediation_roadmap(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(severity="high"))
        output = builder.build("markdown")
        assert "Remediation Roadmap" in output

    def test_markdown_alias_md(self):
        builder = EnhancedReportBuilder()
        output_md = builder.build("md")
        output_markdown = builder.build("markdown")
        # Both formats should produce equivalent structure; ignore timestamp differences
        # by stripping the generated_at line before comparing
        import re
        strip_ts = lambda s: re.sub(r'\*\*Generated:\*\* [^\n]+', '**Generated:** <ts>', s)
        assert strip_ts(output_md) == strip_ts(output_markdown)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class TestStatistics:
    def test_statistics_with_tracker_link(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(has_tracker=True))
        data = json.loads(builder.build("json"))
        assert data["statistics"]["with_tracker_tickets"] == 1

    def test_statistics_with_real_impact(self):
        builder = EnhancedReportBuilder()
        builder.add_finding(_make_finding(has_real_impact=True))
        data = json.loads(builder.build("json"))
        assert data["statistics"]["with_real_impact_analysis"] == 1


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
