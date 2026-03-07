"""
Tests for BugzillaTracker integration.

All Bugzilla REST API calls are mocked so these tests run without a live
Bugzilla instance.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tracker(**kwargs):
    """Build a BugzillaTracker with a mocked bugzilla client."""
    from scanner.integrations.bugzilla_tracker import BugzillaTracker

    mock_client = MagicMock()

    with patch("scanner.integrations.bugzilla_tracker.BugzillaTracker.__init__", return_value=None):
        tracker = BugzillaTracker.__new__(BugzillaTracker)

    tracker.bugzilla_url = kwargs.get("bugzilla_url", "https://bugzilla.example.com")
    tracker.product = kwargs.get("product", "Security")
    tracker.component = kwargs.get("component", "Vulnerabilities")
    tracker.version = kwargs.get("version", "unspecified")
    tracker.priority_mapping = BugzillaTracker.DEFAULT_PRIORITY_MAPPING.copy()
    tracker._client = mock_client
    return tracker, mock_client


def _make_finding(**kwargs):
    data = {
        "finding_id": "test-bugzilla-001",
        "vulnerability_type": "SQLi",
        "target_url": "https://example.com/api/users",
        "parameter": "id",
        "severity": "critical",
        "confidence_score": 0.99,
        "detection_evidence": "Error-based SQLi confirmed.",
        "status": "confirmed",
    }
    data.update(kwargs)
    return data


# ---------------------------------------------------------------------------
# create_issue
# ---------------------------------------------------------------------------

class TestBugzillaCreateIssue:
    def test_create_issue_calls_client(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 42
        mock_client.createbug.return_value = mock_bug

        finding = _make_finding()
        result = tracker.create_issue(finding)

        mock_client.createbug.assert_called_once()
        assert result["issue_id"] == "42"
        assert "42" in result["issue_url"]

    def test_create_issue_summary_format(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 1
        mock_client.createbug.return_value = mock_bug

        finding = _make_finding(vulnerability_type="SSRF", target_url="https://victim.com/fetch")
        tracker.create_issue(finding)

        build_call = mock_client.build_createbug.call_args
        assert "SSRF" in build_call.kwargs.get("summary", "")
        assert "victim.com" in build_call.kwargs.get("summary", "")

    def test_create_issue_severity_mapping_critical(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 2
        mock_client.createbug.return_value = mock_bug

        finding = _make_finding(severity="critical")
        tracker.create_issue(finding)

        build_call = mock_client.build_createbug.call_args
        assert build_call.kwargs.get("severity") == "critical"

    def test_create_issue_keywords_include_megido(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 3
        mock_client.createbug.return_value = mock_bug

        finding = _make_finding()
        tracker.create_issue(finding)

        build_call = mock_client.build_createbug.call_args
        keywords = build_call.kwargs.get("keywords", [])
        assert "megido" in keywords
        assert "security" in keywords


# ---------------------------------------------------------------------------
# create_false_positive_issue
# ---------------------------------------------------------------------------

class TestBugzillaCreateFalsePositive:
    def test_fp_issue_summary_contains_fp_marker(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 100
        mock_client.createbug.return_value = mock_bug

        finding = _make_finding()
        tracker.create_false_positive_issue(finding, reason="Not exploitable in context")

        build_call = mock_client.build_createbug.call_args
        assert "[FP]" in build_call.kwargs.get("summary", "")

    def test_fp_keywords_include_false_positive(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 101
        mock_client.createbug.return_value = mock_bug

        finding = _make_finding()
        tracker.create_false_positive_issue(finding, reason="Test reason")

        build_call = mock_client.build_createbug.call_args
        keywords = build_call.kwargs.get("keywords", [])
        assert "false-positive" in keywords

    def test_fp_description_contains_reason(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 102
        mock_client.createbug.return_value = mock_bug

        finding = _make_finding()
        tracker.create_false_positive_issue(finding, reason="Unique reason XYZ")

        build_call = mock_client.build_createbug.call_args
        description = build_call.kwargs.get("description", "")
        assert "Unique reason XYZ" in description


# ---------------------------------------------------------------------------
# update_issue
# ---------------------------------------------------------------------------

class TestBugzillaUpdateIssue:
    def test_update_status(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.status = "ASSIGNED"
        mock_client.getbug.return_value = mock_bug

        result = tracker.update_issue("42", status="ASSIGNED")
        mock_client.update_bugs.assert_called_once()
        assert result["issue_id"] == "42"

    def test_update_issue_adds_comment(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.status = "ASSIGNED"
        mock_client.getbug.return_value = mock_bug

        tracker.update_issue("42", status="ASSIGNED", comment="Investigation started")
        mock_client.add_comment.assert_called_once_with(42, "Investigation started")


# ---------------------------------------------------------------------------
# get_issue
# ---------------------------------------------------------------------------

class TestBugzillaGetIssue:
    def test_get_issue_returns_dict(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 55
        mock_bug.summary = "Test bug summary"
        mock_bug.status = "NEW"
        mock_bug.severity = "critical"
        mock_bug.priority = "Highest"
        mock_bug.keywords = ["megido", "security"]
        mock_client.getbug.return_value = mock_bug

        result = tracker.get_issue("55")
        assert result["issue_id"] == "55"
        assert result["summary"] == "Test bug summary"
        assert result["status"] == "NEW"
        assert "megido" in result["keywords"]


# ---------------------------------------------------------------------------
# search_issues
# ---------------------------------------------------------------------------

class TestBugzillaSearch:
    def test_search_issues_returns_list(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 77
        mock_bug.summary = "Security finding"
        mock_bug.status = "NEW"
        mock_client.query.return_value = [mock_bug]

        results = tracker.search_issues("Security finding")
        assert len(results) == 1
        assert results[0]["issue_id"] == "77"

    def test_search_issues_empty_returns_empty_list(self):
        tracker, mock_client = _make_tracker()
        mock_client.query.return_value = []

        results = tracker.search_issues("nonexistent")
        assert results == []


# ---------------------------------------------------------------------------
# sync_status
# ---------------------------------------------------------------------------

class TestBugzillaSyncStatus:
    def test_sync_status_resolved_maps_to_remediated(self):
        tracker, mock_client = _make_tracker()

        mock_bug = MagicMock()
        mock_bug.id = 88
        mock_bug.summary = "Security finding"
        mock_bug.status = "RESOLVED"
        mock_client.query.return_value = [mock_bug]

        result = tracker.sync_status("finding-abc")
        assert result["megido_status"] == "remediated"

    def test_sync_status_no_bugs_found(self):
        tracker, mock_client = _make_tracker()
        mock_client.query.return_value = []

        result = tracker.sync_status("finding-xyz")
        assert result["tracker_status"] is None


# ---------------------------------------------------------------------------
# close_issue
# ---------------------------------------------------------------------------

class TestBugzillaCloseIssue:
    def test_close_issue_resolves_bug(self):
        tracker, mock_client = _make_tracker()

        result = tracker.close_issue("99", resolution="FIXED")
        mock_client.update_bugs.assert_called_once()
        assert result["status"] == "RESOLVED"
        assert result["issue_id"] == "99"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
