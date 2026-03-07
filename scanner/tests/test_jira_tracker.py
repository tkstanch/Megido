"""
Tests for JiraTracker integration.

All Jira REST API calls are mocked so these tests run without a live Jira
instance.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_tracker(**kwargs):
    """
    Build a JiraTracker with a mocked JIRA client.

    Returns (tracker, mock_client).
    """
    from scanner.integrations.jira_tracker import JiraTracker

    mock_client = MagicMock()

    with patch("scanner.integrations.jira_tracker.JiraTracker.__init__", return_value=None):
        tracker = JiraTracker.__new__(JiraTracker)

    tracker.jira_url = kwargs.get("jira_url", "https://jira.example.com")
    tracker.project_key = kwargs.get("project_key", "SEC")
    tracker.issue_type = kwargs.get("issue_type", "Bug")
    tracker.priority_mapping = JiraTracker.DEFAULT_PRIORITY_MAPPING.copy()
    tracker._client = mock_client
    return tracker, mock_client


def _make_finding(**kwargs):
    data = {
        "finding_id": "test-uuid-001",
        "vulnerability_type": "XSS",
        "target_url": "https://example.com/search",
        "parameter": "q",
        "severity": "high",
        "confidence_score": 0.95,
        "detection_evidence": "Payload reflected in response.",
        "status": "confirmed",
    }
    data.update(kwargs)
    return data


# ---------------------------------------------------------------------------
# create_issue
# ---------------------------------------------------------------------------

class TestJiraCreateIssue:
    def test_create_issue_calls_client(self):
        tracker, mock_client = _make_tracker()
        mock_issue = MagicMock()
        mock_issue.key = "SEC-42"
        mock_client.create_issue.return_value = mock_issue

        finding = _make_finding()
        result = tracker.create_issue(finding)

        mock_client.create_issue.assert_called_once()
        assert result["issue_id"] == "SEC-42"
        assert "SEC-42" in result["issue_url"]

    def test_create_issue_summary_contains_vuln_type_and_url(self):
        tracker, mock_client = _make_tracker()
        mock_issue = MagicMock()
        mock_issue.key = "SEC-1"
        mock_client.create_issue.return_value = mock_issue

        finding = _make_finding(vulnerability_type="SQLi", target_url="https://victim.com/api")
        tracker.create_issue(finding)

        call_kwargs = mock_client.create_issue.call_args
        fields = call_kwargs[1]["fields"] if call_kwargs[1] else call_kwargs[0][0]
        # fields may be passed as keyword arg
        fields = call_kwargs.kwargs.get("fields") or call_kwargs.args[0] if not fields else fields
        assert "SQLi" in fields.get("summary", "")
        assert "victim.com" in fields.get("summary", "")

    def test_create_issue_priority_mapping_high(self):
        tracker, mock_client = _make_tracker()
        mock_issue = MagicMock()
        mock_issue.key = "SEC-2"
        mock_client.create_issue.return_value = mock_issue

        finding = _make_finding(severity="high")
        tracker.create_issue(finding)

        fields = mock_client.create_issue.call_args.kwargs.get("fields", {})
        assert fields.get("priority", {}).get("name") == "High"

    def test_create_issue_priority_mapping_critical(self):
        tracker, mock_client = _make_tracker()
        mock_issue = MagicMock()
        mock_issue.key = "SEC-3"
        mock_client.create_issue.return_value = mock_issue

        finding = _make_finding(severity="critical")
        tracker.create_issue(finding)

        fields = mock_client.create_issue.call_args.kwargs.get("fields", {})
        assert fields.get("priority", {}).get("name") == "Highest"

    def test_create_issue_labels_include_megido(self):
        tracker, mock_client = _make_tracker()
        mock_issue = MagicMock()
        mock_issue.key = "SEC-4"
        mock_client.create_issue.return_value = mock_issue

        finding = _make_finding()
        tracker.create_issue(finding)

        fields = mock_client.create_issue.call_args.kwargs.get("fields", {})
        assert "megido" in fields.get("labels", [])
        assert "vulnerability" in fields.get("labels", [])


# ---------------------------------------------------------------------------
# create_false_positive_issue
# ---------------------------------------------------------------------------

class TestJiraCreateFalsePositiveIssue:
    def test_fp_issue_summary_contains_fp_marker(self):
        tracker, mock_client = _make_tracker()
        mock_issue = MagicMock()
        mock_issue.key = "SEC-99"
        mock_client.create_issue.return_value = mock_issue

        finding = _make_finding()
        tracker.create_false_positive_issue(finding, reason="WAF rewriting payload")

        fields = mock_client.create_issue.call_args.kwargs.get("fields", {})
        assert "[FP]" in fields.get("summary", "")

    def test_fp_issue_labels_include_false_positive(self):
        tracker, mock_client = _make_tracker()
        mock_issue = MagicMock()
        mock_issue.key = "SEC-100"
        mock_client.create_issue.return_value = mock_issue

        finding = _make_finding()
        tracker.create_false_positive_issue(finding, reason="Not exploitable")

        fields = mock_client.create_issue.call_args.kwargs.get("fields", {})
        assert "false-positive" in fields.get("labels", [])


# ---------------------------------------------------------------------------
# update_issue
# ---------------------------------------------------------------------------

class TestJiraUpdateIssue:
    def test_update_issue_transitions(self):
        tracker, mock_client = _make_tracker()

        mock_issue = MagicMock()
        mock_issue.fields.status.name = "In Progress"
        mock_client.issue.return_value = mock_issue
        mock_client.transitions.return_value = [
            {"id": "31", "name": "In Progress"},
        ]

        result = tracker.update_issue("SEC-10", status="In Progress", comment="Working on it")

        mock_client.transition_issue.assert_called_once()
        mock_client.add_comment.assert_called_once()
        assert result["issue_id"] == "SEC-10"

    def test_update_issue_no_matching_transition_logs_warning(self):
        tracker, mock_client = _make_tracker()

        mock_issue = MagicMock()
        mock_issue.fields.status.name = "Open"
        mock_client.issue.return_value = mock_issue
        mock_client.transitions.return_value = [{"id": "1", "name": "Close"}]

        # Should not raise; just logs a warning
        result = tracker.update_issue("SEC-11", status="Nonexistent Status")
        assert result["issue_id"] == "SEC-11"


# ---------------------------------------------------------------------------
# get_issue
# ---------------------------------------------------------------------------

class TestJiraGetIssue:
    def test_get_issue_returns_dict(self):
        tracker, mock_client = _make_tracker()

        mock_issue = MagicMock()
        mock_issue.key = "SEC-20"
        mock_issue.fields.summary = "Test summary"
        mock_issue.fields.status.name = "Open"
        mock_issue.fields.priority.name = "High"
        mock_issue.fields.labels = ["megido"]
        mock_client.issue.return_value = mock_issue

        result = tracker.get_issue("SEC-20")
        assert result["issue_id"] == "SEC-20"
        assert result["summary"] == "Test summary"
        assert result["status"] == "Open"


# ---------------------------------------------------------------------------
# search_issues / sync_status
# ---------------------------------------------------------------------------

class TestJiraSearchAndSync:
    def test_search_issues_returns_list(self):
        tracker, mock_client = _make_tracker()

        mock_issue = MagicMock()
        mock_issue.key = "SEC-30"
        mock_issue.fields.summary = "Found issue"
        mock_issue.fields.status.name = "Open"
        mock_client.search_issues.return_value = [mock_issue]

        results = tracker.search_issues("summary ~ 'Found'")
        assert len(results) == 1
        assert results[0]["issue_id"] == "SEC-30"

    def test_sync_status_no_results(self):
        tracker, mock_client = _make_tracker()
        mock_client.search_issues.return_value = []

        result = tracker.sync_status("finding-uuid-xyz")
        assert result["tracker_status"] is None
        assert result["megido_status"] is None


# ---------------------------------------------------------------------------
# close_issue
# ---------------------------------------------------------------------------

class TestJiraCloseIssue:
    def test_close_issue_calls_update(self):
        tracker, mock_client = _make_tracker()

        mock_issue = MagicMock()
        mock_issue.fields.status.name = "Done"
        mock_client.issue.return_value = mock_issue
        mock_client.transitions.return_value = [{"id": "51", "name": "Done"}]

        result = tracker.close_issue("SEC-50", resolution="Fixed")
        # transition_issue is called for "Done"
        mock_client.transition_issue.assert_called()
        assert result["issue_id"] == "SEC-50"


# ---------------------------------------------------------------------------
# TrackerConfig
# ---------------------------------------------------------------------------

class TestTrackerConfig:
    def test_from_env_defaults(self):
        from scanner.integrations.tracker_config import TrackerConfig
        config = TrackerConfig()
        assert config.tracker_type == "none"
        assert config.auto_create_on_confirmed is True
        assert config.severity_threshold == "medium"

    def test_from_env_reads_env_vars(self):
        import os
        from scanner.integrations.tracker_config import TrackerConfig

        env_patch = {
            "TRACKER_TYPE": "jira",
            "JIRA_URL": "https://test.atlassian.net",
            "JIRA_PROJECT_KEY": "TST",
            "TRACKER_AUTO_CREATE_CONFIRMED": "false",
            "TRACKER_SEVERITY_THRESHOLD": "high",
        }
        with patch.dict(os.environ, env_patch):
            config = TrackerConfig.from_env()

        assert config.tracker_type == "jira"
        assert config.jira_url == "https://test.atlassian.net"
        assert config.jira_project_key == "TST"
        assert config.auto_create_on_confirmed is False
        assert config.severity_threshold == "high"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
