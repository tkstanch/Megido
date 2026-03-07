"""
Jira Issue Tracker Integration

Implements ``BaseIssueTracker`` for Atlassian Jira Cloud / Server using the
Jira REST API v2/v3 via the ``jira`` Python client library.

The ``jira`` package is an optional dependency; if it is not installed the
class can still be imported but instantiation will raise ``ImportError`` with
a helpful message.
"""

import logging
from typing import Any, Dict, List, Optional

from .base_tracker import BaseIssueTracker

logger = logging.getLogger(__name__)


class JiraTracker(BaseIssueTracker):
    """
    Jira integration for Megido finding lifecycle tracking.

    Configuration is injected via the constructor (typically from a
    ``TrackerConfig`` instance).

    Args:
        jira_url:        Base URL of your Jira instance (e.g. ``https://org.atlassian.net``).
        project_key:     Jira project key (e.g. ``SEC``).
        api_token:       API token (Jira Cloud) or password (Jira Server).
        email:           Email address associated with the API token.
        issue_type:      Default issue type to create (default: ``"Bug"``).
        priority_mapping: Mapping of Megido severity → Jira priority name.
    """

    # Default severity → Jira priority mapping
    DEFAULT_PRIORITY_MAPPING: Dict[str, str] = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }

    def __init__(
        self,
        jira_url: str,
        project_key: str,
        api_token: str,
        email: str,
        issue_type: str = "Bug",
        priority_mapping: Optional[Dict[str, str]] = None,
    ) -> None:
        try:
            from jira import JIRA  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'jira' package is required for Jira integration. "
                "Install it with: pip install jira>=3.5.0"
            ) from exc

        self.jira_url = jira_url.rstrip("/")
        self.project_key = project_key
        self.issue_type = issue_type
        self.priority_mapping = priority_mapping or self.DEFAULT_PRIORITY_MAPPING

        self._client = JIRA(
            server=self.jira_url,
            basic_auth=(email, api_token),
        )
        logger.info("JiraTracker initialised for project %s at %s", project_key, jira_url)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_description(self, finding: Dict[str, Any]) -> str:
        """Build a Jira-markup description block from a finding dict."""
        lines = [
            f"h2. Megido Security Finding",
            f"",
            f"*Vulnerability Type:* {finding.get('vulnerability_type', 'Unknown')}",
            f"*Target URL:* {finding.get('target_url', finding.get('url', 'N/A'))}",
            f"*Parameter:* {finding.get('parameter', 'N/A')}",
            f"*Severity:* {finding.get('severity', 'unknown').upper()}",
            f"*Confidence Score:* {finding.get('confidence_score', 'N/A')}",
            f"*Finding ID:* {finding.get('finding_id', 'N/A')}",
            f"",
            f"h3. Detection Evidence",
            f"{finding.get('detection_evidence', finding.get('evidence', 'N/A'))}",
            f"",
        ]
        if finding.get("verification_evidence"):
            lines += [
                "h3. Verification Evidence",
                f"{finding['verification_evidence']}",
                "",
            ]
        if finding.get("exploitation_evidence"):
            lines += [
                "h3. Exploitation Evidence",
                f"{finding['exploitation_evidence']}",
                "",
            ]
        if finding.get("real_impact"):
            impact = finding["real_impact"]
            lines += [
                "h3. Real Impact",
                f"{impact.get('impact_summary', '')}",
                "",
            ]
        if finding.get("remediation"):
            lines += [
                "h3. Remediation",
                f"{finding['remediation']}",
                "",
            ]
        return "\n".join(lines)

    def _build_labels(
        self, finding: Dict[str, Any], extra_labels: Optional[List[str]] = None
    ) -> List[str]:
        """Assemble label list from finding data."""
        vuln_type = (
            finding.get("vulnerability_type", "unknown")
            .lower()
            .replace(" ", "-")
        )
        labels = ["megido", "vulnerability", vuln_type]
        if extra_labels:
            labels.extend(extra_labels)
        return labels

    def _priority_for(self, severity: str) -> Dict[str, str]:
        """Return Jira priority dict for the given severity string."""
        priority_name = self.priority_mapping.get(severity.lower(), "Medium")
        return {"name": priority_name}

    # ------------------------------------------------------------------
    # BaseIssueTracker implementation
    # ------------------------------------------------------------------

    def create_issue(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Jira issue for a confirmed finding."""
        vuln_type = finding.get("vulnerability_type", "Vulnerability")
        target_url = finding.get("target_url", finding.get("url", "unknown"))
        severity = finding.get("severity", "medium")

        fields: Dict[str, Any] = {
            "project": {"key": self.project_key},
            "summary": f"[Megido] {vuln_type} - {target_url}",
            "description": self._build_description(finding),
            "issuetype": {"name": self.issue_type},
            "priority": self._priority_for(severity),
            "labels": self._build_labels(finding),
        }

        # Optional custom fields
        if finding.get("cvss_score"):
            fields["customfield_cvss"] = str(finding["cvss_score"])
        if finding.get("cwe_id"):
            fields["customfield_cwe"] = finding["cwe_id"]

        issue = self._client.create_issue(fields=fields)
        issue_url = f"{self.jira_url}/browse/{issue.key}"
        logger.info("Created Jira issue %s for finding %s", issue.key, finding.get("finding_id"))
        return {"issue_id": issue.key, "issue_url": issue_url}

    def create_false_positive_issue(
        self, finding: Dict[str, Any], reason: str
    ) -> Dict[str, Any]:
        """Create a Jira issue specifically for false-positive tracking."""
        fp_finding = dict(finding)
        fp_finding["false_positive_reason"] = reason

        vuln_type = finding.get("vulnerability_type", "Vulnerability")
        target_url = finding.get("target_url", finding.get("url", "unknown"))
        severity = finding.get("severity", "medium")

        description_lines = [
            "h2. False Positive Classification",
            "",
            f"*Reason:* {reason}",
            "",
            "h3. Original Detection Evidence",
            f"{finding.get('detection_evidence', finding.get('evidence', 'N/A'))}",
            "",
        ]
        description_lines += self._build_description(fp_finding).splitlines()

        fields: Dict[str, Any] = {
            "project": {"key": self.project_key},
            "summary": f"[Megido][FP] {vuln_type} - {target_url}",
            "description": "\n".join(description_lines),
            "issuetype": {"name": self.issue_type},
            "priority": self._priority_for(severity),
            "labels": self._build_labels(finding, extra_labels=["false-positive"]),
        }

        issue = self._client.create_issue(fields=fields)
        issue_url = f"{self.jira_url}/browse/{issue.key}"
        logger.info(
            "Created Jira FP issue %s for finding %s",
            issue.key,
            finding.get("finding_id"),
        )
        return {"issue_id": issue.key, "issue_url": issue_url}

    def update_issue(
        self, issue_id: str, status: str, comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Transition a Jira issue to *status* and optionally add a comment."""
        issue = self._client.issue(issue_id)

        # Find the available transition whose name matches *status*
        transitions = self._client.transitions(issue)
        transition_id = None
        for t in transitions:
            if t["name"].lower() == status.lower():
                transition_id = t["id"]
                break

        if transition_id:
            self._client.transition_issue(issue, transition_id)
            logger.info("Transitioned Jira issue %s → %s", issue_id, status)
        else:
            logger.warning(
                "No transition named '%s' found for issue %s", status, issue_id
            )

        if comment:
            self._client.add_comment(issue, comment)

        issue = self._client.issue(issue_id)
        return {
            "issue_id": issue_id,
            "status": issue.fields.status.name,
            "issue_url": f"{self.jira_url}/browse/{issue_id}",
        }

    def get_issue(self, issue_id: str) -> Dict[str, Any]:
        """Retrieve Jira issue details."""
        issue = self._client.issue(issue_id)
        return {
            "issue_id": issue.key,
            "summary": issue.fields.summary,
            "status": issue.fields.status.name,
            "priority": issue.fields.priority.name if issue.fields.priority else None,
            "labels": list(issue.fields.labels),
            "issue_url": f"{self.jira_url}/browse/{issue.key}",
        }

    def sync_status(self, finding_id: str) -> Dict[str, Any]:
        """
        Pull the current Jira status for the issue linked to *finding_id*.

        This implementation searches Jira for an issue whose summary contains
        the finding UUID and returns a status mapping.
        """
        results = self.search_issues(f'summary ~ "{finding_id}" AND project = {self.project_key}')
        if not results:
            return {"finding_id": finding_id, "tracker_status": None, "megido_status": None}

        issue_data = results[0]
        tracker_status = issue_data.get("status", "")

        # Map Jira statuses to Megido finding statuses
        status_map = {
            "open": "confirmed",
            "in progress": "verified",
            "done": "remediated",
            "resolved": "remediated",
            "closed": "remediated",
            "won't fix": "false_positive",
        }
        megido_status = status_map.get(tracker_status.lower(), "confirmed")

        return {
            "finding_id": finding_id,
            "tracker_status": tracker_status,
            "megido_status": megido_status,
            "issue_id": issue_data.get("issue_id"),
            "issue_url": issue_data.get("issue_url"),
        }

    def search_issues(self, query: str) -> List[Dict[str, Any]]:
        """Search Jira issues using JQL."""
        issues = self._client.search_issues(query, maxResults=50)
        results = []
        for issue in issues:
            results.append({
                "issue_id": issue.key,
                "summary": issue.fields.summary,
                "status": issue.fields.status.name,
                "issue_url": f"{self.jira_url}/browse/{issue.key}",
            })
        return results

    def close_issue(self, issue_id: str, resolution: str) -> Dict[str, Any]:
        """Close a Jira issue with the given resolution."""
        # Set resolution field if supported
        try:
            self._client.issue(issue_id).update(
                fields={"resolution": {"name": resolution}}
            )
        except Exception:  # noqa: BLE001
            logger.debug("Could not set resolution field on %s (may not be supported)", issue_id)

        return self.update_issue(issue_id, status="Done")
