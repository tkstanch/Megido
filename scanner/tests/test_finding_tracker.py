"""
Tests for FindingTracker — finding lifecycle, state transitions, FP marking,
vulnerability chaining, and export.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.finding_tracker import Finding, FindingStatus, FindingTracker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_finding(**kwargs):
    """Return a minimal finding data dict."""
    data = {
        "vulnerability_type": "XSS",
        "target_url": "https://example.com/search",
        "parameter": "q",
        "severity": "high",
        "confidence_score": 0.95,
        "detection_evidence": "Payload <script>alert(1)</script> reflected in response.",
    }
    data.update(kwargs)
    return data


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------

class TestAddFinding:
    def test_add_finding_creates_entry(self):
        tracker = FindingTracker()
        finding = tracker.add_finding(_minimal_finding())
        assert finding.finding_id is not None
        assert tracker.get_finding(finding.finding_id) is finding

    def test_add_finding_defaults_status_to_detected(self):
        tracker = FindingTracker()
        finding = tracker.add_finding(_minimal_finding())
        assert finding.status == FindingStatus.DETECTED

    def test_add_finding_with_explicit_id(self):
        tracker = FindingTracker()
        fid = "custom-uuid-1234"
        finding = tracker.add_finding(_minimal_finding(finding_id=fid))
        assert finding.finding_id == fid

    def test_get_finding_unknown_raises_key_error(self):
        tracker = FindingTracker()
        try:
            tracker.get_finding("nonexistent")
            assert False, "Expected KeyError"
        except KeyError:
            pass


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------

class TestUpdateStatus:
    def test_detected_to_verified(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED, evidence="Verified via browser")
        assert f.status == FindingStatus.VERIFIED
        assert f.verification_evidence == "Verified via browser"
        assert f.verified_at is not None

    def test_verified_to_confirmed(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED)
        tracker.update_status(f.finding_id, FindingStatus.CONFIRMED)
        assert f.status == FindingStatus.CONFIRMED

    def test_confirmed_to_exploited(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED)
        tracker.update_status(f.finding_id, FindingStatus.CONFIRMED)
        tracker.update_status(f.finding_id, FindingStatus.EXPLOITED, evidence="Cookie stolen")
        assert f.status == FindingStatus.EXPLOITED
        assert f.exploitation_evidence == "Cookie stolen"
        assert f.exploited_at is not None

    def test_invalid_transition_raises_value_error(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        try:
            tracker.update_status(f.finding_id, FindingStatus.REMEDIATED)
            assert False, "Expected ValueError"
        except ValueError:
            pass

    def test_exploited_to_reported(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED)
        tracker.update_status(f.finding_id, FindingStatus.CONFIRMED)
        tracker.update_status(f.finding_id, FindingStatus.EXPLOITED)
        tracker.update_status(f.finding_id, FindingStatus.REPORTED)
        assert f.status == FindingStatus.REPORTED

    def test_reported_to_remediated(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED)
        tracker.update_status(f.finding_id, FindingStatus.CONFIRMED)
        tracker.update_status(f.finding_id, FindingStatus.EXPLOITED)
        tracker.update_status(f.finding_id, FindingStatus.REPORTED)
        tracker.update_status(f.finding_id, FindingStatus.REMEDIATED)
        assert f.status == FindingStatus.REMEDIATED


# ---------------------------------------------------------------------------
# False positive marking
# ---------------------------------------------------------------------------

class TestMarkFalsePositive:
    def test_mark_detected_finding_as_fp(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.mark_false_positive(f.finding_id, "Header present, WAF stripping it")
        assert f.status == FindingStatus.FALSE_POSITIVE
        assert "WAF" in f.false_positive_reason

    def test_mark_confirmed_finding_as_fp(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED)
        tracker.update_status(f.finding_id, FindingStatus.CONFIRMED)
        tracker.mark_false_positive(f.finding_id, "Scanner artifact")
        assert f.status == FindingStatus.FALSE_POSITIVE

    def test_mark_remediated_raises(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED)
        tracker.update_status(f.finding_id, FindingStatus.CONFIRMED)
        tracker.update_status(f.finding_id, FindingStatus.REMEDIATED)
        try:
            tracker.mark_false_positive(f.finding_id, "reason")
            assert False, "Expected ValueError"
        except ValueError:
            pass

    def test_already_fp_is_idempotent(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.mark_false_positive(f.finding_id, "reason A")
        tracker.mark_false_positive(f.finding_id, "reason B")
        # First reason is preserved; no error raised
        assert f.false_positive_reason == "reason A"


# ---------------------------------------------------------------------------
# mark_exploited
# ---------------------------------------------------------------------------

class TestMarkExploited:
    def test_mark_confirmed_as_exploited(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.update_status(f.finding_id, FindingStatus.VERIFIED)
        tracker.update_status(f.finding_id, FindingStatus.CONFIRMED)
        tracker.mark_exploited(
            f.finding_id,
            exploitation_result="Cookie exfiltrated",
            real_impact={"impact_summary": "Session hijacked"},
        )
        assert f.status == FindingStatus.EXPLOITED
        assert f.real_impact["impact_summary"] == "Session hijacked"

    def test_mark_detected_finding_as_exploited_auto_transitions(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        # Should auto-transition through verified → confirmed → exploited
        tracker.mark_exploited(f.finding_id, exploitation_result="proof")
        assert f.status == FindingStatus.EXPLOITED


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

class TestQueries:
    def test_get_findings_by_status(self):
        tracker = FindingTracker()
        f1 = tracker.add_finding(_minimal_finding(vulnerability_type="XSS"))
        f2 = tracker.add_finding(_minimal_finding(vulnerability_type="SQLi"))
        tracker.update_status(f1.finding_id, FindingStatus.VERIFIED)

        verified = tracker.get_findings_by_status(FindingStatus.VERIFIED)
        assert f1 in verified
        assert f2 not in verified

    def test_get_findings_summary_counts(self):
        tracker = FindingTracker()
        tracker.add_finding(_minimal_finding(severity="high"))
        tracker.add_finding(_minimal_finding(severity="medium"))
        f3 = tracker.add_finding(_minimal_finding(severity="low"))
        tracker.mark_false_positive(f3.finding_id, "FP reason")

        summary = tracker.get_findings_summary()
        assert summary["total"] == 3
        assert summary["by_status"]["false_positive"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1


# ---------------------------------------------------------------------------
# Tracker linking
# ---------------------------------------------------------------------------

class TestTrackerLinking:
    def test_link_to_tracker(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        tracker.link_to_tracker(f.finding_id, "JIRA-123", "https://jira.example.com/JIRA-123")
        assert f.tracker_issue_id == "JIRA-123"
        assert "JIRA-123" in f.tracker_issue_url


# ---------------------------------------------------------------------------
# Vulnerability chaining
# ---------------------------------------------------------------------------

class TestVulnerabilityChaining:
    def test_add_chain_links_both_findings(self):
        tracker = FindingTracker()
        f1 = tracker.add_finding(_minimal_finding(vulnerability_type="SSRF"))
        f2 = tracker.add_finding(_minimal_finding(vulnerability_type="XXE"))
        tracker.add_chain(f1.finding_id, f2.finding_id)
        assert f2.finding_id in f1.chain_findings
        assert f1.finding_id in f2.chain_findings

    def test_chain_is_not_duplicated(self):
        tracker = FindingTracker()
        f1 = tracker.add_finding(_minimal_finding())
        f2 = tracker.add_finding(_minimal_finding())
        tracker.add_chain(f1.finding_id, f2.finding_id)
        tracker.add_chain(f1.finding_id, f2.finding_id)
        assert f1.chain_findings.count(f2.finding_id) == 1


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class TestExport:
    def test_export_json_returns_valid_json(self):
        import json
        tracker = FindingTracker()
        tracker.add_finding(_minimal_finding())
        output = tracker.export_findings(fmt="json")
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert "finding_id" in data[0]

    def test_export_unsupported_format_raises(self):
        tracker = FindingTracker()
        try:
            tracker.export_findings(fmt="xml")
            assert False, "Expected ValueError"
        except ValueError:
            pass

    def test_to_dict_status_is_string(self):
        tracker = FindingTracker()
        f = tracker.add_finding(_minimal_finding())
        d = f.to_dict()
        assert isinstance(d["status"], str)
        assert d["status"] == "detected"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
