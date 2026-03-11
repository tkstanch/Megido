To enhance the `EnhancedReportBuilder` class to generate robust and comprehensive vulnerability reports, we need to ensure it can handle various 
sections and output formats. Here’s an enhanced version of the `EnhancedReportBuilder` class:

### EnhancedReportBuilder Code

```python
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RealImpact dataclass
# ---------------------------------------------------------------------------

@dataclass
class RealImpact:
    """Structured real-world impact of an exploited vulnerability."""
    
    # Define fields
    impact_description: str
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    confidentiality_loss: Optional[int] = None
    integrity_loss: Optional[int] = None
    availability_loss: Optional[int] = None
    economic_impact: Optional[int] = None
    legal_impact: Optional[int] = None
    evidence: Optional[str] = None  # Additional field to store exploitation evidence
    
    # Constructor with logging
    def __post_init__(self):
        logger.info("Creating RealImpact object with fields: %s", self.__dict__)
    
    # Method to calculate overall impact
    def calculate_overall_impact(self) -> int:
        """Calculate the overall impact based on individual loss metrics."""
        total_impact = 0
        for loss in [self.confidentiality_loss, self.integrity_loss, self.availability_loss]:
            if loss is not None:
                total_impact += loss
        return total_impact
    
    # Method to generate report
    def generate_report(self) -> str:
        """Generate a structured report of the impact."""
        report = f"RealImpact Report:\n"
        report += f"Impact Description: {self.impact_description}\n"
        report += f"Evidence: {self.evidence}\n"
        report += f"Affected Systems: {', '.join(self.affected_systems)}\n"
        report += f"Affected Users: {', '.join(self.affected_users)}\n"
        if self.confidentiality_loss:
            report += f"Confidentiality Loss: {self.confidentiality_loss}\n"
        if self.integrity_loss:
            report += f"Integrity Loss: {self.integrity_loss}\n"
        if self.availability_loss:
            report += f"Availability Loss: {self.availability_loss}\n"
        if self.economic_impact:
            report += f"Economic Impact: {self.economic_impact}\n"
        if self.legal_impact:
            report += f"Legal Impact: {self.legal_impact}\n"
        return report

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single vulnerability finding with its full lifecycle state."""
    uuid: uuid.UUID = field(default_factory=uuid.uuid4)
    status: FindingStatus = FindingStatus.DETECTED
    evidence: Optional[str] = None
    real_impact: Optional[RealImpact] = field(default=None, init=False)  # Lazy initialization

    # Method to mark a finding as exploited
    def mark_exploited(self, exploitation_evidence: str) -> None:
        """Mark the finding as exploited and analyze the exploitation evidence."""
        if self.status == FindingStatus.EXPLOITED:
            logger.warning("Finding is already marked as exploited.")
            return

        self.status = FindingStatus.EXPLOITED
        self.evidence = exploitation_evidence
        self.real_impact = analyze_exploitation_evidence(exploitation_evidence)
        logger.info("Finding %s marked as exploited with evidence: %s", self.uuid, self.evidence)

    # Method to get the real impact
    def get_real_impact(self) -> Optional[RealImpact]:
        """Return the RealImpact object for the finding."""
        return self.real_impact

# ---------------------------------------------------------------------------
# EnhancedReportBuilder Class
# ---------------------------------------------------------------------------

class EnhancedReportBuilder:
    """Generates bug-bounty-ready and pentest-ready vulnerability reports."""
    
    def __init__(self):
        self.findings: Dict[uuid.UUID, Finding] = {}
        self.executive_summary = ""
        self.full_finding_details = []
        self.real_impact_assessment = []
        self.poc_steps = []
        self.vulnerability_chain_analysis = []
        self.false_positive_summary = []
        self.tracker_integration_links = []
        self.remediation_roadmap = []
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self.findings[finding.uuid] = finding
        self.full_finding_details.append(self._get_finding_details(finding))
    
    def update_finding(self, finding_uuid: uuid.UUID, new_status: FindingStatus, new_evidence: Optional[str] = None) -> None:
        """Update the status of a finding."""
        if finding_uuid in self.findings:
            finding = self.findings[finding_uuid]
            if new_status in _VALID_TRANSITIONS[finding.status]:
                finding.status = new_status
                if new_evidence:
                    finding.evidence = new_evidence
                logger.info("Updated finding %s status to %s with evidence: %s", finding.uuid, new_status, new_evidence)
            else:
                logger.error("Invalid state transition from %s to %s.", finding.status, new_status)
        else:
            logger.error("Finding with UUID %s not found.", finding_uuid)
    
    def _get_finding_details(self, finding: Finding) -> Dict[str, Any]:
        """Get detailed information about a finding."""
        return {
            "UUID": str(finding.uuid),
            "Status": finding.status.value,
            "Evidence": finding.evidence,
            "RealImpact": asdict(finding.real_impact),
            "Timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def add_executive_summary(self, summary: str) -> None:
        """Add an executive summary to the report."""
        self.executive_summary = summary
    
    def add_full_finding_details(self, details: List[Dict[str, Any]]) -> None:
        """Add full finding details to the report."""
        self.full_finding_details.extend(details)
    
    def add_real_impact_assessment(self, assessment: str) -> None:
        """Add real impact assessment to the report."""
        self.real_impact_assessment.append(assessment)
    
    def add_poc_steps(self, steps: List[str]) -> None:
        """Add proof of concept steps to the report."""
        self.poc_steps.extend(steps)
    
    def add_vulnerability_chain_analysis(self, analysis: List[str]) -> None:
        """Add vulnerability chain analysis to the report."""
        self.vulnerability_chain_analysis.extend(analysis)
    
    def add_false_positive_summary(self, summary: str) -> None:
        """Add false positive summary to the report."""
        self.false_positive_summary.append(summary)
    
    def add_tracker_integration_links(self, links: List[str]) -> None:
        """Add tracker integration links to the report."""
        self.tracker_integration_links.extend(links)
    
    def add_remediation_roadmap(self, roadmap: List[str]) -> None:
        """Add remediation roadmap to the report."""
        self.remediation_roadmap.extend(roadmap)
    
    def generate_report(self, output_format: str = "json") -> str:
        """Generate the report in the specified format."""
        if output_format == "json":
            report = {
                "ExecutiveSummary": self.executive_summary,
                "FullFindingDetails": self.full_finding_details,
                "RealImpactAssessment": self.real_impact_assessment,
                "ProofOfConceptSteps": self.poc_steps,
                "VulnerabilityChainAnalysis": self.vulnerability_chain_analysis,
                "FalsePositiveSummary": self.false_positive_summary,
                "TrackerIntegrationLinks": self.tracker_integration_links,
                "RemediationRoadmap": self.remediation_roadmap
            }
            return json.dumps(report, indent=4)
        elif output_format == "markdown":
            # Example: Generate Markdown report
            markdown_report = ""
            markdown_report += f"# Executive Summary\n{self.executive_summary}\n\n"
            markdown_report += f"# Full Finding Details\n\n"
            for detail in self.full_finding_details:
                markdown_report += f"## UUID: {detail['UUID']}\n"
                markdown_report += f"Status: {detail['Status']}\n"
                markdown_report += f"Timestamp: {detail['Timestamp']}\n\n"
                if detail["Evidence"]:
                    markdown_report += f"Evidence: {detail['Evidence']}\n\n"
                if detail["RealImpact"]:
                    markdown_report += f"Real Impact: {detail['RealImpact']}\n\n"
                markdown_report += "\n"
            markdown_report += f"# Real Impact Assessment\n{self.real_impact_assessment}\n\n"
            markdown_report += f"# Proof of Concept Steps\n{self.poc_steps}\n\n"
            markdown_report += f"# Vulnerability Chain Analysis\n{self.vulnerability_chain_analysis}\n\n"
            markdown_report += f"# False Positive Summary\n{self.false_positive_summary}\n\n"
            markdown_report += f"# Tracker Integration Links\n{self.tracker_integration_links}\n\n"
            markdown_report += f"# Remediation Roadmap\n{self.remediation_roadmap}\n\n"
            return markdown_report
        else:
            raise ValueError("Unsupported output format: {}".format(output_format))

# Example Usage
if __name__ == "__main__":
    # Initialize EnhancedReportBuilder
    report_builder = EnhancedReportBuilder()

    # Add findings
    finding1 = Finding()
    finding1.mark_exploited("Vulnerability exploited by attacker on 2023-10-01, affecting multiple systems and users.")
    report_builder.add_finding(finding1)

    # Generate report in JSON format
    json_report = report_builder.generate_report(output_format="json")
    print("JSON Report:\n", json_report)

    # Generate report in Markdown format
    markdown_report = report_builder.generate_report(output_format="markdown")
    print("Markdown Report:\n", markdown_report)
```

### Explanation of Enhancements

1. **Data Classes for `Finding` and `RealImpact`:**
   - These classes provide a structured way to manage finding details and real impact assessments.

2. **EnhancedReportBuilder Class:**
   - Added methods to add various sections of the report, such as executive summary, full finding details, real impact assessment, proof of 
concept steps, etc.
   - Added methods to update the status and evidence of findings.
   - Added a method to generate the report in different formats (JSON and Markdown).

3. **Report Generation:**
   - The `generate_report` method can output the report in JSON or Markdown format. The Markdown format is generated as a string, which can be 
converted to HTML or PDF using additional tools.

4. **Example Usage:**
   - Provided an example of how to use the `EnhancedReportBuilder` to add findings and generate reports.

This structure ensures that the report builder is robust and flexible, capable of handling various types of vulnerability data and generating 
comprehensive reports in multiple formats.

...     Produces submission-ready vulnerability reports.
... 
...     Args:
...         scan_target:  The URL / path that was scanned.
...         scan_id:      Optional identifier for the scan session.
...         scanner_version: Scanner version string.
...     """
... 
...     def __init__(
...         self,
...         scan_target: str = "",
...         scan_id: Optional[str] = None,
...         scanner_version: str = "Megido",
...     ) -> None:
...         self.scan_target = scan_target
...         self.scan_id = scan_id
...         self.scanner_version = scanner_version
...         self._findings: List[Dict[str, Any]] = []
... 
...     # ------------------------------------------------------------------
...     # Public API
...     # ------------------------------------------------------------------
... 
...     def add_finding(self, finding: Dict[str, Any]) -> None:
...         """Add a finding (from FindingTracker.get_finding().to_dict()) to the report."""
...         self._findings.append(finding)
... 
...     def add_findings(self, findings: List[Dict[str, Any]]) -> None:
...         """Bulk-add findings."""
...         for f in findings:
...             self.add_finding(f)
... 
...     def build(self, fmt: str = "json") -> str:
...         """
...         Build and return the full report.
... 
...         Args:
...             fmt: Output format — ``"json"`` or ``"markdown"``.
... 
...         Returns:
...             Report string in the requested format.
...         """
...         if fmt == "json":
...             return self._build_json()
...         if fmt in ("markdown", "md"):
...             return self._build_markdown()
...         raise ValueError(f"Unsupported report format: {fmt!r}")
... 
...     # ------------------------------------------------------------------
...     # Internal builders
...     # ------------------------------------------------------------------
... 
...     def _report_data(self) -> Dict[str, Any]:
...         """Assemble the full report data structure."""
...         confirmed = [
...             f for f in self._findings
...             if f.get("status") not in ("false_positive",)
...         ]
...         false_positives = [
...             f for f in self._findings
...             if f.get("status") == "false_positive"
...         ]
... 
...         severity_order = ["critical", "high", "medium", "low", "info"]
... 
...         def sev_key(f: Dict[str, Any]) -> int:
...             return severity_order.index(f.get("severity", "info").lower())
... 
...         confirmed_sorted = sorted(confirmed, key=sev_key)
... 
...         # Chain analysis
...         chains = self._build_chain_analysis()
... 
...         # Remediation roadmap
...         roadmap = self._build_remediation_roadmap(confirmed_sorted)
... 
...         return {
...             "report_metadata": {
...                 "generated_at": datetime.now(timezone.utc).isoformat(),
...                 "scanner": self.scanner_version,
...                 "scan_id": self.scan_id,
...                 "target": self.scan_target,
...             },
...             "executive_summary": self._build_executive_summary(confirmed, false_positives),
...             "vulnerability_details": [
...                 self._format_finding_detail(f) for f in confirmed_sorted
...             ],
...             "false_positive_summary": {
...                 "count": len(false_positives),
...                 "items": [
...                     {
...                         "finding_id": f.get("finding_id"),
...                         "vulnerability_type": f.get("vulnerability_type"),
...                         "target_url": f.get("target_url"),
...                         "reason": f.get("false_positive_reason", "Not specified"),
...                     }
...                     for f in false_positives
...                 ],
...             },
...             "vulnerability_chain_analysis": chains,
...             "remediation_roadmap": roadmap,
...             "statistics": self._build_statistics(confirmed, false_positives),
...         }
... 
...     def _build_json(self) -> str:
...         return json.dumps(self._report_data(), indent=2, default=str)
... 
...     def _build_markdown(self) -> str:
...         data = self._report_data()
...         meta = data["report_metadata"]
...         exec_sum = data["executive_summary"]
... 
...         lines: List[str] = [
...             f"# Megido Vulnerability Report",
...             f"",
...             f"**Target:** {meta['target']}  ",
...             f"**Generated:** {meta['generated_at']}  ",
...             f"**Scanner:** {meta['scanner']}  ",
...             f"**Scan ID:** {meta['scan_id'] or 'N/A'}",
...             f"",
...             f"---",
...             f"",
...             f"## Executive Summary",
...             f"",
...             exec_sum["overview"],
...             f"",
...             f"| Severity | Count |",
...             f"|----------|-------|",
...         ]
...         for sev, cnt in exec_sum["severity_breakdown"].items():
...             lines.append(f"| {sev.capitalize()} | {cnt} |")
...         lines += ["", "---", ""]
... 
...         # Vulnerability details
...         lines += ["## Vulnerability Details", ""]
...         for detail in data["vulnerability_details"]:
...             lines += self._finding_detail_to_markdown(detail)
...             lines += ["---", ""]
... 
...         # False positive summary
...         fp = data["false_positive_summary"]
...         if fp["count"] > 0:
...             lines += [
...                 "## False Positive Summary",
...                 f"",
...                 f"{fp['count']} finding(s) were classified as false positives:",
...                 "",
...             ]
...             for item in fp["items"]:
...                 lines += [
...                     f"- **{item['vulnerability_type']}** on `{item['target_url']}`",
...                     f"  - Reason: {item['reason']}",
...                     f"  - Finding ID: `{item['finding_id']}`",
...                 ]
...             lines += [""]
... 
...         # Vulnerability chain analysis
...         chains = data["vulnerability_chain_analysis"]
...         if chains:
...             lines += ["## Vulnerability Chain Analysis", ""]
...             for chain in chains:
...                 lines += [
...                     f"### Chain: {' → '.join(chain['types'])}",
...                     f"",
...                     f"**Combined Impact:** {chain['combined_impact']}",
...                     f"",
...                     f"**Chain Members:**",
...                 ]
...                 for member in chain["members"]:
...                     lines.append(f"- `{member}`")
...                 lines += [""]
... 
...         # Remediation roadmap
...         lines += ["## Remediation Roadmap", ""]
...         for priority, items in data["remediation_roadmap"].items():
...             if items:
...                 lines += [f"### {priority.replace('-', ' ').title()}", ""]
...                 for item in items:
...                     lines.append(
...                         f"- **{item['vulnerability_type']}** "
...                         f"({item['severity'].upper()}) — `{item['target_url']}`"
...                     )
...                 lines += [""]
... 
...         return "\n".join(lines)
... 
...     # ------------------------------------------------------------------
...     # Helper builders
...     # ------------------------------------------------------------------
... 
...     def _build_executive_summary(
...         self,
...         confirmed: List[Dict[str, Any]],
...         false_positives: List[Dict[str, Any]],
...     ) -> Dict[str, Any]:
...         sev_counts: Dict[str, int] = {
...             "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
...         }
...         for f in confirmed:
...             sev = f.get("severity", "info").lower()
...             if sev in sev_counts:
...                 sev_counts[sev] += 1
... 
...         total_confirmed = len(confirmed)
...         total_fp = len(false_positives)
...         risk_level = "Low"
...         if sev_counts["critical"] > 0:
...             risk_level = "Critical"
...         elif sev_counts["high"] > 0:
...             risk_level = "High"
...         elif sev_counts["medium"] > 0:
...             risk_level = "Medium"
... 
...         overview = (
...             f"The security scan of **{self.scan_target or 'the target'}** identified "
...             f"**{total_confirmed}** confirmed vulnerability finding(s) with an overall risk level "
...             f"of **{risk_level}**. "
...             f"Additionally, {total_fp} finding(s) were reviewed and classified as false positives. "
...         )
...         if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
...             overview += (
...                 f"Immediate attention is required for the "
...                 f"{sev_counts['critical']} critical and {sev_counts['high']} high severity issues."
...             )
... 
...         return {
...             "overall_risk": risk_level,
...             "total_findings": total_confirmed,
...             "false_positives_excluded": total_fp,
...             "severity_breakdown": sev_counts,
...             "overview": overview,
...         }
... 
...     def _format_finding_detail(self, finding: Dict[str, Any]) -> Dict[str, Any]:
...         """Format a single finding into a structured report section."""
...         real_impact = finding.get("real_impact") or {}
...         tracker_issue_id = finding.get("tracker_issue_id")
...         tracker_issue_url = finding.get("tracker_issue_url")
... 
...         detail: Dict[str, Any] = {
...             "finding_id": finding.get("finding_id"),
...             "vulnerability_type": finding.get("vulnerability_type"),
...             "target_url": finding.get("target_url"),
...             "parameter": finding.get("parameter"),
...             "severity": finding.get("severity", "medium"),
...             "confidence_score": finding.get("confidence_score", 0.0),
...             "status": finding.get("status"),
...             # Evidence
...             "detection_evidence": finding.get("detection_evidence"),
...             "verification_evidence": finding.get("verification_evidence"),
...             "exploitation_evidence": finding.get("exploitation_evidence"),
...             # Impact
...             "real_impact_assessment": {
...                 "impact_summary": real_impact.get("impact_summary", "Not yet analyzed"),
...                 "business_impact": real_impact.get("business_impact", "unknown"),
...                 "cvss_score": real_impact.get("cvss_score"),
...                 "cvss_vector": real_impact.get("cvss_vector"),
...                 "cwe_id": real_impact.get("cwe_id"),
...                 "affected_cia": real_impact.get("affected_cia"),
...                 "remediation_priority": real_impact.get("remediation_priority"),
...                 "technical_impact": real_impact.get("technical_impact"),
...             },
...             # Bug-bounty ready content
...             "submittable_impact": real_impact.get(
...                 "submittable_report",
...                 self._build_default_submittable_impact(finding),
...             ),
...             "real_world_scenario": self._build_real_world_scenario(finding),
...             "business_risk": self._build_business_risk(finding, real_impact),
...             # Tracker
...             "tracker_integration": {
...                 "issue_id": tracker_issue_id,
...                 "issue_url": tracker_issue_url,
...             },
...             # Chaining
...             "chain_findings": finding.get("chain_findings", []),
...         }
...         return detail
... 
...     def _build_default_submittable_impact(self, finding: Dict[str, Any]) -> str:
...         vuln = finding.get("vulnerability_type", "Vulnerability")
...         url = finding.get("target_url", "the target")
...         sev = finding.get("severity", "medium").upper()
...         return (
...             f"A {sev} severity {vuln} was discovered on {url}. "
...             "This vulnerability has been confirmed through active testing. "
...             "Manual impact analysis is recommended to assess the full business risk."
...         )
... 
...     def _build_real_world_scenario(self, finding: Dict[str, Any]) -> str:
...         vuln = finding.get("vulnerability_type", "").lower()
...         url = finding.get("target_url", "the target endpoint")
...         param = finding.get("parameter", "")
...         param_str = f" via the `{param}` parameter" if param else ""
... 
...         scenarios = {
...             "xss": (
...                 f"An attacker sends a crafted URL{param_str} to an authenticated user. "
...                 f"When the victim visits {url}, the injected JavaScript executes in their browser, "
...                 "exfiltrating their session token to an attacker-controlled server."
...             ),
...             "sqli": (
...                 f"An attacker submits a malicious SQL payload{param_str} to {url}. "
...                 "The database executes the injected statement, returning sensitive data "
...                 "including user credentials and personal information."
...             ),
...             "ssrf": (
...                 f"An attacker supplies a crafted URL{param_str} pointing to an internal resource. "
...                 f"The server fetches the attacker-specified URL, exposing internal services "
...                 "and potentially cloud metadata credentials."
...             ),
...             "xxe": (
...                 f"An attacker submits a crafted XML document{param_str} containing an external "
...                 "entity reference. The XML parser processes the entity, reading sensitive "
...                 "files from the server's filesystem."
...             ),
...             "clickjacking": (
...                 f"An attacker hosts a transparent iframe over a legitimate-looking page. "
...                 f"When a victim visits the attacker's page, they unknowingly interact with "
...                 f"{url}, performing unintended sensitive actions."
...             ),
...         }
... 
...         for key, scenario in scenarios.items():
...             if key in vuln:
...                 return scenario
... 
...         return (
...             f"An attacker exploits the vulnerability{param_str} on {url} to achieve "
...             "unauthorized access or data exposure."
...         )
... 
...     def _build_business_risk(
...         self, finding: Dict[str, Any], real_impact: Dict[str, Any]
...     ) -> str:
...         business_impact = real_impact.get("business_impact", finding.get("severity", "medium"))
...         vuln = finding.get("vulnerability_type", "Vulnerability")
... 
...         risk_statements = {
...             "critical": (
...                 f"This {vuln} poses a **critical** business risk. "
...                 "Immediate exploitation could result in complete system compromise, "
...                 "mass data breach, regulatory penalties (GDPR/PCI-DSS), and significant "
...                 "reputational damage."
...             ),
...             "high": (
...                 f"This {vuln} poses a **high** business risk. "
...                 "Exploitation could lead to unauthorized access to sensitive data, "
...                 "account takeover, or significant service disruption."
...             ),
...             "medium": (
...                 f"This {vuln} poses a **medium** business risk. "
...                 "While not immediately catastrophic, exploitation could compromise "
...                 "user data integrity or enable further attacks."
...             ),
...             "low": (
...                 f"This {vuln} poses a **low** business risk. "
...                 "The vulnerability has limited exploitability or impact but should "
...                 "be remediated to reduce the attack surface."
...             ),
...         }
...         return risk_statements.get(
...             business_impact.lower(),
...             risk_statements["medium"],
...         )
... 
...     def _build_chain_analysis(self) -> List[Dict[str, Any]]:
...         """Identify and describe vulnerability chains."""
...         chains: List[Dict[str, Any]] = []
...         processed: set = set()
... 
...         for finding in self._findings:
...             fid = finding.get("finding_id")
...             chain_ids = finding.get("chain_findings", [])
...             if not chain_ids or fid in processed:
...                 continue
... 
...             # Collect all members of this chain
...             members = [fid] + chain_ids
...             for m in members:
...                 processed.add(m)
... 
...             member_findings = [
...                 f for f in self._findings
...                 if f.get("finding_id") in members
...             ]
...             types = [f.get("vulnerability_type", "Unknown") for f in member_findings]
...             severities = [f.get("severity", "low") for f in member_findings]
... 
...             # Combined impact is the highest severity in the chain
...             sev_order = ["critical", "high", "medium", "low", "info"]
...             highest = min(severities, key=lambda s: sev_order.index(s.lower()) if s.lower() in sev_order else 99)
... 
...             chains.append({
...                 "members": members,
...                 "types": types,
...                 "combined_impact": (
...                     f"Chaining {' + '.join(types)} elevates overall impact to "
...                     f"{highest.upper()} — enabling a multi-stage attack path."
...                 ),
...             })
... 
...         return chains
... 
...     def _build_remediation_roadmap(
...         self, findings: List[Dict[str, Any]]
...     ) -> Dict[str, List[Dict[str, Any]]]:
...         """Group findings by remediation priority."""
...         roadmap: Dict[str, List[Dict[str, Any]]] = {
...             "immediate": [],
...             "next-sprint": [],
...             "backlog": [],
...         }
... 
...         sev_to_priority = {
...             "critical": "immediate",
...             "high": "immediate",
...             "medium": "next-sprint",
...             "low": "backlog",
...             "info": "backlog",
...         }
... 
...         for finding in findings:
...             real_impact = finding.get("real_impact") or {}
...             priority = real_impact.get(
...                 "remediation_priority",
...                 sev_to_priority.get(finding.get("severity", "medium").lower(), "next-sprint"),
...             )
...             if priority not in roadmap:
...                 priority = "next-sprint"
...             roadmap[priority].append({
...                 "finding_id": finding.get("finding_id"),
...                 "vulnerability_type": finding.get("vulnerability_type"),
...                 "target_url": finding.get("target_url"),
...                 "severity": finding.get("severity"),
...                 "tracker_issue_id": finding.get("tracker_issue_id"),
...                 "tracker_issue_url": finding.get("tracker_issue_url"),
...             })
... 
...         return roadmap
... 
...     def _build_statistics(
...         self,
...         confirmed: List[Dict[str, Any]],
...         false_positives: List[Dict[str, Any]],
...     ) -> Dict[str, Any]:
...         status_counts: Dict[str, int] = {}
...         for f in confirmed:
...             status = f.get("status", "unknown")
...             status_counts[status] = status_counts.get(status, 0) + 1
... 
...         return {
...             "total_confirmed": len(confirmed),
...             "total_false_positives": len(false_positives),
...             "by_status": status_counts,
...             "with_tracker_tickets": sum(
...                 1 for f in confirmed if f.get("tracker_issue_id")
...             ),
...             "with_real_impact_analysis": sum(
...                 1 for f in confirmed if f.get("real_impact")
...             ),
...             "in_vulnerability_chains": sum(
...                 1 for f in confirmed if f.get("chain_findings")
...             ),
...         }
... 
...     def _finding_detail_to_markdown(self, detail: Dict[str, Any]) -> List[str]:
...         """Convert a formatted finding detail dict to Markdown lines."""
...         lines: List[str] = [
...             f"### [{detail['severity'].upper()}] {detail['vulnerability_type']}",
...             f"",
...             f"**Finding ID:** `{detail['finding_id']}`  ",
...             f"**Target URL:** `{detail['target_url']}`  ",
...             f"**Parameter:** `{detail.get('parameter') or 'N/A'}`  ",
...             f"**Severity:** {detail['severity'].upper()}  ",
...             f"**Confidence:** {detail.get('confidence_score', 'N/A')}  ",
...             f"**Status:** {detail.get('status', 'N/A')}",
...             f"",
...         ]
... 
...         # Real impact
...         impact = detail.get("real_impact_assessment", {})
...         if impact.get("impact_summary"):
...             lines += [
...                 "#### Real Impact Assessment",
...                 f"",
...                 impact["impact_summary"],
...                 f"",
...                 f"- **Business Impact:** {(impact.get('business_impact') or 'unknown').upper()}",
...                 f"- **CVSS Score:** {impact.get('cvss_score', 'N/A')} — `{impact.get('cvss_vector', 'N/A')}`",
...                 f"- **CWE:** {impact.get('cwe_id', 'N/A')}",
...                 f"- **Remediation Priority:** {impact.get('remediation_priority', 'N/A')}",
...                 f"",
...             ]
... 
...         # Real-world scenario
...         if detail.get("real_world_scenario"):
...             lines += [
...                 "#### Real-World Attack Scenario",
...                 f"",
...                 detail["real_world_scenario"],
...                 f"",
...             ]
... 
...         # Business risk
...         if detail.get("business_risk"):
...             lines += [
...                 "#### Business Risk",
...                 f"",
...                 detail["business_risk"],
...                 f"",
...             ]
... 
...         # Evidence
...         if detail.get("detection_evidence"):
...             lines += [
...                 "#### Detection Evidence",
...                 f"```",
...                 str(detail["detection_evidence"])[:2000],
...                 f"```",
...                 f"",
...             ]
... 
...         # Submittable impact
...         if detail.get("submittable_impact"):
...             lines += [
...                 "#### Submittable Impact Statement",
...                 f"",
...                 detail["submittable_impact"],
...                 f"",
...             ]
... 
...         # Tracker
...         tracker = detail.get("tracker_integration", {})
...         if tracker.get("issue_id"):
...             lines += [
...                 "#### Tracker",
...                 f"",
...                 f"- **Issue ID:** {tracker['issue_id']}",
...                 f"- **Issue URL:** {tracker.get('issue_url', 'N/A')}",
...                 f"",
...             ]
... 
...         # Chaining
...         if detail.get("chain_findings"):
...             lines += [
...                 "#### Vulnerability Chain",
...                 f"",
...                 f"This finding is part of a vulnerability chain with: "
...                 + ", ".join(f"`{fid}`" for fid in detail["chain_findings"]),
...                 f"",
...             ]
... 
...         return lines
