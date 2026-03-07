"""
Bugzilla Issue Tracker Integration

Implements ``BaseIssueTracker`` for Mozilla Bugzilla instances using the
Bugzilla REST API via the ``python-bugzilla`` library.

The ``bugzilla`` package is an optional dependency; if it is not installed the
class can still be imported but instantiation will raise ``ImportError`` with
a helpful message.
"""

import logging
from typing import Any, Dict, List, Optional

from .base_tracker import BaseIssueTracker

logger = logging.getLogger(__name__)


class BugzillaTracker(BaseIssueTracker):
    """
    Bugzilla integration for Megido finding lifecycle tracking.

    Args:
        bugzilla_url: Base URL of the Bugzilla instance.
        api_key:      Bugzilla API key for authentication.
        product:      Default product to file bugs under.
        component:    Default component to file bugs under.
        version:      Default version string (default: ``"unspecified"``).
        priority_mapping: Mapping of Megido severity → Bugzilla priority.
    """

    DEFAULT_PRIORITY_MAPPING: Dict[str, str] = {
        "critical": "Highest",
        "high": "High",
        "medium": "Normal",
        "low": "Low",
        "info": "Lowest",
    }

    DEFAULT_SEVERITY_MAPPING: Dict[str, str] = {
        "critical": "critical",
        "high": "major",
        "medium": "normal",
        "low": "minor",
        "info": "trivial",
    }

    def __init__(
        self,
        bugzilla_url: str,
        api_key: str,
        product: str,
        component: str,
        version: str = "unspecified",
        priority_mapping: Optional[Dict[str, str]] = None,
    ) -> None:
        try:
            import bugzilla as _bugzilla  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "The 'python-bugzilla' package is required for Bugzilla integration. "
                "Install it with: pip install python-bugzilla>=3.2.0"
            ) from exc

        self.bugzilla_url = bugzilla_url.rstrip("/")
        self.product = product
        self.component = component
        self.version = version
        self.priority_mapping = priority_mapping or self.DEFAULT_PRIORITY_MAPPING

        self._client = _bugzilla.Bugzilla(self.bugzilla_url, api_key=api_key)
        logger.info(
            "BugzillaTracker initialised for product '%s' at %s", product, bugzilla_url
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_description(self, finding: Dict[str, Any]) -> str:
        """Build a plain-text description block from a finding dict."""
        lines = [
            "== Megido Security Finding ==",
            "",
            f"Vulnerability Type: {finding.get('vulnerability_type', 'Unknown')}",
            f"Target URL: {finding.get('target_url', finding.get('url', 'N/A'))}",
            f"Parameter: {finding.get('parameter', 'N/A')}",
            f"Severity: {finding.get('severity', 'unknown').upper()}",
            f"Confidence Score: {finding.get('confidence_score', 'N/A')}",
            f"Finding ID: {finding.get('finding_id', 'N/A')}",
            "",
            "=== Detection Evidence ===",
            f"{finding.get('detection_evidence', finding.get('evidence', 'N/A'))}",
            "",
        ]
        if finding.get("verification_evidence"):
            lines += [
                "=== Verification Evidence ===",
                f"{finding['verification_evidence']}",
                "",
            ]
        if finding.get("exploitation_evidence"):
            lines += [
                "=== Exploitation Evidence ===",
                f"{finding['exploitation_evidence']}",
                "",
            ]
        if finding.get("real_impact"):
            impact = finding["real_impact"]
            lines += [
                "=== Real Impact ===",
                f"{impact.get('impact_summary', '')}",
                "",
            ]
        if finding.get("remediation"):
            lines += [
                "=== Remediation ===",
                f"{finding['remediation']}",
                "",
            ]
        return "\n".join(lines)

    def _build_keywords(
        self, finding: Dict[str, Any], extra_keywords: Optional[List[str]] = None
    ) -> List[str]:
        """Assemble keyword list from finding data."""
        keywords = ["megido", "security"]
        vuln_type = (
            finding.get("vulnerability_type", "unknown")
            .lower()
            .replace(" ", "-")
        )
        keywords.append(vuln_type)
        if extra_keywords:
            keywords.extend(extra_keywords)
        return keywords

    def _severity_for(self, severity: str) -> str:
        return self.DEFAULT_SEVERITY_MAPPING.get(severity.lower(), "normal")

    def _priority_for(self, severity: str) -> str:
        return self.priority_mapping.get(severity.lower(), "Normal")

    # ------------------------------------------------------------------
    # BaseIssueTracker implementation
    # ------------------------------------------------------------------

    def create_issue(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Bugzilla bug for a confirmed finding."""
        vuln_type = finding.get("vulnerability_type", "Vulnerability")
        target_url = finding.get("target_url", finding.get("url", "unknown"))
        severity = finding.get("severity", "medium")

        bug_data = self._client.build_createbug(
            product=self.product,
            component=self.component,
            version=self.version,
            summary=f"[Megido] {vuln_type} - {target_url}",
            description=self._build_description(finding),
            severity=self._severity_for(severity),
            priority=self._priority_for(severity),
            keywords=self._build_keywords(finding),
        )
        bug = self._client.createbug(bug_data)
        issue_url = f"{self.bugzilla_url}/show_bug.cgi?id={bug.id}"
        logger.info("Created Bugzilla bug %s for finding %s", bug.id, finding.get("finding_id"))
        return {"issue_id": str(bug.id), "issue_url": issue_url}

    def create_false_positive_issue(
        self, finding: Dict[str, Any], reason: str
    ) -> Dict[str, Any]:
        """Create a Bugzilla bug specifically for false-positive tracking."""
        vuln_type = finding.get("vulnerability_type", "Vulnerability")
        target_url = finding.get("target_url", finding.get("url", "unknown"))
        severity = finding.get("severity", "medium")

        fp_description = "\n".join([
            "== False Positive Classification ==",
            "",
            f"Reason: {reason}",
            "",
            "=== Original Detection Evidence ===",
            f"{finding.get('detection_evidence', finding.get('evidence', 'N/A'))}",
            "",
            self._build_description(finding),
        ])

        bug_data = self._client.build_createbug(
            product=self.product,
            component=self.component,
            version=self.version,
            summary=f"[Megido][FP] {vuln_type} - {target_url}",
            description=fp_description,
            severity=self._severity_for(severity),
            priority=self._priority_for(severity),
            keywords=self._build_keywords(finding, extra_keywords=["false-positive"]),
        )
        bug = self._client.createbug(bug_data)
        issue_url = f"{self.bugzilla_url}/show_bug.cgi?id={bug.id}"
        logger.info(
            "Created Bugzilla FP bug %s for finding %s", bug.id, finding.get("finding_id")
        )
        return {"issue_id": str(bug.id), "issue_url": issue_url}

    def update_issue(
        self, issue_id: str, status: str, comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a Bugzilla bug's status and optionally add a comment."""
        bug = self._client.getbug(int(issue_id))
        update = self._client.build_update(status=status.upper())
        self._client.update_bugs([int(issue_id)], update)
        logger.info("Updated Bugzilla bug %s → %s", issue_id, status)

        if comment:
            self._client.add_comment(int(issue_id), comment)

        bug = self._client.getbug(int(issue_id))
        return {
            "issue_id": issue_id,
            "status": bug.status,
            "issue_url": f"{self.bugzilla_url}/show_bug.cgi?id={issue_id}",
        }

    def get_issue(self, issue_id: str) -> Dict[str, Any]:
        """Retrieve Bugzilla bug details."""
        bug = self._client.getbug(int(issue_id))
        return {
            "issue_id": str(bug.id),
            "summary": bug.summary,
            "status": bug.status,
            "severity": bug.severity,
            "priority": bug.priority,
            "keywords": list(getattr(bug, "keywords", [])),
            "issue_url": f"{self.bugzilla_url}/show_bug.cgi?id={bug.id}",
        }

    def sync_status(self, finding_id: str) -> Dict[str, Any]:
        """
        Pull the current Bugzilla status for the bug linked to *finding_id*.
        """
        results = self.search_issues(f"[Megido] {finding_id}")
        if not results:
            return {"finding_id": finding_id, "tracker_status": None, "megido_status": None}

        bug_data = results[0]
        tracker_status = bug_data.get("status", "")

        status_map = {
            "new": "confirmed",
            "assigned": "verified",
            "in_progress": "verified",
            "resolved": "remediated",
            "verified": "remediated",
            "closed": "remediated",
            "wontfix": "false_positive",
        }
        megido_status = status_map.get(tracker_status.lower(), "confirmed")

        return {
            "finding_id": finding_id,
            "tracker_status": tracker_status,
            "megido_status": megido_status,
            "issue_id": bug_data.get("issue_id"),
            "issue_url": bug_data.get("issue_url"),
        }

    def search_issues(self, query: str) -> List[Dict[str, Any]]:
        """Search Bugzilla bugs by summary keyword."""
        bugs = self._client.query({
            "product": self.product,
            "summary": query,
            "limit": 50,
        })
        results = []
        for bug in bugs:
            results.append({
                "issue_id": str(bug.id),
                "summary": bug.summary,
                "status": bug.status,
                "issue_url": f"{self.bugzilla_url}/show_bug.cgi?id={bug.id}",
            })
        return results

    def close_issue(self, issue_id: str, resolution: str) -> Dict[str, Any]:
        """Close a Bugzilla bug with the given resolution."""
        update = self._client.build_update(
            status="RESOLVED",
            resolution=resolution.upper().replace(" ", "_"),
        )
        self._client.update_bugs([int(issue_id)], update)
        logger.info("Closed Bugzilla bug %s with resolution '%s'", issue_id, resolution)
        return {
            "issue_id": issue_id,
            "status": "RESOLVED",
            "resolution": resolution,
            "issue_url": f"{self.bugzilla_url}/show_bug.cgi?id={issue_id}",
        }
