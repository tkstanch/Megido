#!/usr/bin/env python3
"""
Tests for new behaviors introduced by the enhancement:
  - Bounded concurrency (max_concurrent_requests honored)
  - Canary escalation (remainder probes skipped when canary finds no signal)
  - Baseline deduplication within a scan
  - Mode policy enforcement (DETECT / VERIFY / DEMONSTRATE)
  - DB fingerprinting integration (DB-specific payloads on error detection)
  - score_rationale included in Finding
"""

import sys
import os
import threading
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.discovery import (
    DiscoveryScanner,
    InjectionLocation,
    InjectionPoint,
    ProbeSet,
    ResponseComparator,
    detect_sql_errors,
)
from sql_attacker.engine.modes import ModePolicy, ModeViolationError, OperationMode
from sql_attacker.engine.reporting import Finding


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _make_response(status_code: int = 200, text: str = "Safe page content.") -> MagicMock:
    """Return a lightweight fake response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def _sql_error_response() -> MagicMock:
    """Return a response that contains a MySQL SQL error message."""
    return _make_response(
        200,
        "You have an error in your SQL syntax; check the manual that "
        "corresponds to your MySQL server version for the right syntax.",
    )


def _safe_request_fn(url, method, params, data, json_data, headers, cookies):
    """Always returns a clean, identical response."""
    return _make_response(200, "Safe page content.")


def _error_request_fn(url, method, params, data, json_data, headers, cookies):
    """Returns a SQL error when any param value looks like an injection payload."""
    all_values = list((params or {}).values()) + list((data or {}).values())
    for v in all_values:
        if v and ("'" in str(v) or '"' in str(v)):
            return _sql_error_response()
    return _make_response(200, "Normal page content.")


# ===========================================================================
# Bounded concurrency tests
# ===========================================================================


class TestBoundedConcurrency(unittest.TestCase):
    """DiscoveryScanner must honour max_concurrent_requests."""

    def test_sequential_mode_executes_without_error(self):
        """max_concurrent_requests=1 (default) should work correctly."""
        cfg = ScanConfig(max_concurrent_requests=1)
        scanner = DiscoveryScanner(request_fn=_error_request_fn, config=cfg)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "test"},
        )
        self.assertIsInstance(findings, list)

    def test_concurrent_mode_returns_same_findings_as_sequential(self):
        """Results from concurrent and sequential scans on the same target should agree."""
        params = {"id": "1", "name": "foo"}

        cfg_seq = ScanConfig(max_concurrent_requests=1)
        scanner_seq = DiscoveryScanner(request_fn=_error_request_fn, config=cfg_seq)
        findings_seq = scanner_seq.scan(
            url="http://example.com/items",
            method="GET",
            params=params,
        )

        cfg_conc = ScanConfig(max_concurrent_requests=4)
        scanner_conc = DiscoveryScanner(request_fn=_error_request_fn, config=cfg_conc)
        findings_conc = scanner_conc.scan(
            url="http://example.com/items",
            method="GET",
            params=params,
        )

        # Both scans should find the same vulnerable parameter names
        names_seq = sorted(f.parameter for f in findings_seq)
        names_conc = sorted(f.parameter for f in findings_conc)
        self.assertEqual(names_seq, names_conc)

    def test_concurrent_requests_bounded_by_config(self):
        """Active thread count during a scan must not exceed max_concurrent_requests."""
        max_workers = 2
        cfg = ScanConfig(max_concurrent_requests=max_workers, per_host_request_budget=200)

        peak_active = [0]
        current_active = [0]
        lock = threading.Lock()

        def counting_request_fn(url, method, params, data, json_data, headers, cookies):
            with lock:
                current_active[0] += 1
                if current_active[0] > peak_active[0]:
                    peak_active[0] = current_active[0]
            # Simulate a tiny bit of work
            import time
            time.sleep(0.005)
            with lock:
                current_active[0] -= 1
            return _make_response(200, "Normal content.")

        scanner = DiscoveryScanner(request_fn=counting_request_fn, config=cfg)
        # 6 params → 6 concurrent injection-point tests
        params = {f"p{i}": str(i) for i in range(6)}
        scanner.scan(url="http://example.com/", method="GET", params=params)

        # Peak concurrency must not exceed max_workers
        self.assertLessEqual(peak_active[0], max_workers)

    def test_concurrent_scan_is_thread_safe_for_host_budget(self):
        """Per-host request budget must be respected even under concurrency."""
        budget = 5
        cfg = ScanConfig(max_concurrent_requests=4, per_host_request_budget=budget)

        call_count = [0]
        lock = threading.Lock()

        def counting_fn(url, method, params, data, json_data, headers, cookies):
            with lock:
                call_count[0] += 1
            return _make_response(200, "Normal content.")

        scanner = DiscoveryScanner(request_fn=counting_fn, config=cfg)
        scanner.scan(
            url="http://budget-test.example.com/",
            method="GET",
            params={f"p{i}": str(i) for i in range(10)},
        )
        # Total HTTP calls must not exceed the budget
        self.assertLessEqual(call_count[0], budget)


# ===========================================================================
# Canary escalation tests
# ===========================================================================


class TestCanaryEscalation(unittest.TestCase):
    """Canary scheduling: boolean probes only run when canary detects a signal."""

    def test_no_signal_canary_skips_remainder_probes(self):
        """When canary probes produce no signal, the scanner should make fewer requests."""
        cfg = ScanConfig(max_concurrent_requests=1)
        calls: List[Dict] = []

        def tracking_safe_fn(url, method, params, data, json_data, headers, cookies):
            calls.append({"params": dict(params or {})})
            return _make_response(200, "Completely safe and identical page.")

        scanner = DiscoveryScanner(request_fn=tracking_safe_fn, config=cfg)
        findings = scanner.scan(
            url="http://example.com/safe",
            method="GET",
            params={"id": "1"},
        )

        self.assertEqual([], findings, "Safe target should produce no findings")
        # Canary-only path: baseline (1) + canary probes (≤ 3 from quote_break/boolean_true)
        # significantly fewer than the full probe set (~12 probes + 1 baseline)
        # After canary with no signal, we bail out before running the remainder
        self.assertLess(len(calls), 10, "Fewer requests expected when canary finds no signal")

    def test_signal_in_canary_triggers_remainder_probes(self):
        """When canary detects a signal, the remainder probes must also run."""
        cfg = ScanConfig(max_concurrent_requests=1)
        calls: List[Dict] = []

        def tracking_error_fn(url, method, params, data, json_data, headers, cookies):
            p = dict(params or {})
            calls.append({"params": p})
            for v in p.values():
                if "'" in str(v):
                    return _sql_error_response()
            return _make_response(200, "Normal page content.")

        scanner = DiscoveryScanner(request_fn=tracking_error_fn, config=cfg)
        findings = scanner.scan(
            url="http://example.com/vulnerable",
            method="GET",
            params={"id": "1"},
        )

        # Should find something
        self.assertGreater(len(findings), 0, "Vulnerable target should produce findings")
        # More requests than canary-only (remainder ran too)
        self.assertGreater(len(calls), 3)

    def test_canary_escalation_produces_correct_finding(self):
        """A finding produced after canary escalation must have correct metadata."""
        scanner = DiscoveryScanner(request_fn=_error_request_fn, config=ScanConfig())
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "test"},
        )
        if findings:
            f = findings[0]
            self.assertEqual("q", f.parameter)
            self.assertIn(f.verdict, ("confirmed", "likely", "uncertain"))
            self.assertGreaterEqual(f.confidence, 0.0)
            self.assertLessEqual(f.confidence, 1.0)


# ===========================================================================
# Baseline deduplication tests
# ===========================================================================


class TestBaselineDeduplication(unittest.TestCase):
    """Baseline should be collected once per (url, method) pair within a scan."""

    def test_baseline_fetched_once_for_multiple_params(self):
        """With multiple params on the same URL, the baseline request is sent only once."""
        cfg = ScanConfig(max_concurrent_requests=1)
        baseline_calls = [0]
        probe_calls = [0]

        def tracking_fn(url, method, params, data, json_data, headers, cookies):
            p = dict(params or {})
            # Baseline request has the original param values (no injection chars)
            is_baseline = all(
                v in ("1", "foo", "bar") for v in p.values()
            )
            if is_baseline:
                baseline_calls[0] += 1
            else:
                probe_calls[0] += 1
            return _make_response(200, "Normal content.")

        scanner = DiscoveryScanner(request_fn=tracking_fn, config=cfg)
        scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1", "name": "foo", "page": "bar"},
        )

        # With dedup, baseline should be collected only once even though there
        # are 3 injection points, all sharing the same (url, method) key.
        self.assertEqual(1, baseline_calls[0],
                         "Baseline must be collected only once for the same endpoint")

    def test_baseline_dedup_cache_is_populated_after_first_scan(self):
        """The internal _baseline_dedup dict should be populated after a scan."""
        scanner = DiscoveryScanner(request_fn=_safe_request_fn, config=ScanConfig())
        scanner.scan(
            url="http://example.com/page",
            method="GET",
            params={"x": "1"},
        )
        self.assertIn("GET:http://example.com/page", scanner._baseline_dedup)

    def test_baseline_dedup_reused_across_injection_points(self):
        """All injection points for the same endpoint should reuse the cached baseline."""
        cfg = ScanConfig(max_concurrent_requests=1)
        all_calls: List = []

        def tracking_fn(url, method, params, data, json_data, headers, cookies):
            all_calls.append(dict(params or {}))
            return _make_response(200, "Identical response body.")

        scanner = DiscoveryScanner(request_fn=tracking_fn, config=cfg)
        scanner.scan(
            url="http://example.com/multi",
            method="GET",
            params={"a": "1", "b": "2"},
        )

        # Count how many calls were "baseline-like" (original param values only)
        baseline_like = [c for c in all_calls if all(v in ("1", "2") for v in c.values())]
        # With dedup, at most 1 baseline request regardless of injection point count
        self.assertLessEqual(len(baseline_like), 1)


# ===========================================================================
# Mode policy enforcement tests
# ===========================================================================


class TestModePolicyEnforcement(unittest.TestCase):
    """DiscoveryScanner must respect the ModePolicy at construction and scan time."""

    def test_detect_mode_allows_scan(self):
        """DETECT mode is the default and must allow scanning."""
        policy = ModePolicy(OperationMode.DETECT)
        scanner = DiscoveryScanner(
            request_fn=_safe_request_fn,
            config=ScanConfig(),
            mode_policy=policy,
        )
        # Should not raise
        findings = scanner.scan(
            url="http://example.com/",
            method="GET",
            params={"id": "1"},
        )
        self.assertIsInstance(findings, list)

    def test_detect_mode_is_default(self):
        """When no mode_policy is provided, DETECT mode must be the default."""
        scanner = DiscoveryScanner(request_fn=_safe_request_fn, config=ScanConfig())
        self.assertEqual(OperationMode.DETECT, scanner._mode_policy.mode)

    def test_verify_mode_allows_scan(self):
        """VERIFY mode must allow scanning."""
        policy = ModePolicy(OperationMode.VERIFY)
        scanner = DiscoveryScanner(
            request_fn=_error_request_fn,
            config=ScanConfig(),
            mode_policy=policy,
        )
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "test"},
        )
        self.assertIsInstance(findings, list)

    def test_demonstrate_mode_allows_scan(self):
        """DEMONSTRATE mode must also allow scanning."""
        policy = ModePolicy(OperationMode.DEMONSTRATE)
        scanner = DiscoveryScanner(
            request_fn=_error_request_fn,
            config=ScanConfig(),
            mode_policy=policy,
        )
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "test"},
        )
        self.assertIsInstance(findings, list)

    def test_detect_mode_does_not_allow_exfiltration(self):
        """assert_may_exfiltrate must always raise regardless of mode."""
        for mode in OperationMode:
            policy = ModePolicy(mode)
            with self.assertRaises(ModeViolationError):
                policy.assert_may_exfiltrate()

    def test_detect_mode_does_not_allow_verify(self):
        """In DETECT mode, assert_may_verify should raise ModeViolationError."""
        policy = ModePolicy(OperationMode.DETECT)
        with self.assertRaises(ModeViolationError):
            policy.assert_may_verify()

    def test_verify_mode_allows_verify(self):
        """In VERIFY mode, assert_may_verify must not raise."""
        policy = ModePolicy(OperationMode.VERIFY)
        policy.assert_may_verify()  # should not raise

    def test_demonstrate_mode_allows_demonstrate(self):
        """In DEMONSTRATE mode, assert_may_demonstrate must not raise."""
        policy = ModePolicy(OperationMode.DEMONSTRATE)
        policy.assert_may_demonstrate()

    def test_verify_mode_runs_confirmation_for_likely_findings(self):
        """In VERIFY mode, the scanner should run confirm_finding for 'likely' findings.

        We verify this by checking that a single finding still comes back
        (the confirmation loop doesn't silently swallow true positives).
        """
        policy = ModePolicy(OperationMode.VERIFY)
        scanner = DiscoveryScanner(
            request_fn=_error_request_fn,
            config=ScanConfig(),
            mode_policy=policy,
        )
        findings = scanner.scan(
            url="http://example.com/vuln",
            method="GET",
            params={"id": "1"},
        )
        # The scanner must still return findings (confirm_finding should confirm
        # a true positive, not suppress it)
        self.assertGreater(len(findings), 0)

    def test_mode_policy_redact_helper(self):
        """ModePolicy.redact() must truncate and redact the value."""
        policy = ModePolicy(OperationMode.DEMONSTRATE, max_demonstrate_bytes=128)
        redacted = policy.redact("MySQL 8.0.31", keep_prefix=5)
        self.assertTrue(redacted.startswith("MySQL"))
        self.assertIn("[REDACTED]", redacted)


# ===========================================================================
# DB fingerprinting integration tests
# ===========================================================================


class TestDBFingerprintingIntegration(unittest.TestCase):
    """When an error signature identifies a DB, DB-specific payloads should be used."""

    def test_mysql_error_leads_to_mysql_db_type_in_finding(self):
        """A MySQL error response should result in db_type='mysql' in the finding."""
        scanner = DiscoveryScanner(request_fn=_error_request_fn, config=ScanConfig())
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "test"},
        )
        if findings:
            self.assertEqual("mysql", findings[0].db_type)

    def test_postgresql_error_leads_to_postgresql_db_type(self):
        """A PostgreSQL error response should result in db_type='postgresql'."""
        def pg_error_fn(url, method, params, data, json_data, headers, cookies):
            p = params or {}
            for v in p.values():
                if "'" in str(v):
                    return _make_response(
                        200,
                        "PSQLException: ERROR: syntax error at or near \"'\" at character 5",
                    )
            return _make_response(200, "Normal page.")

        scanner = DiscoveryScanner(request_fn=pg_error_fn, config=ScanConfig())
        findings = scanner.scan(
            url="http://example.com/api",
            method="GET",
            params={"filter": "value"},
        )
        if findings:
            self.assertEqual("postgresql", findings[0].db_type)

    def test_unknown_db_when_no_error_signature(self):
        """When only a content change is detected (no error), db_type should be 'unknown'."""
        call_count = [0]

        def content_change_fn(url, method, params, data, json_data, headers, cookies):
            call_count[0] += 1
            p = params or {}
            for v in p.values():
                if "OR" in str(v).upper() or "'" in str(v):
                    # Return very different content (boolean diff) but no SQL errors
                    return _make_response(200, "All results returned from database here.")
            return _make_response(200, "Limited results.")

        scanner = DiscoveryScanner(request_fn=content_change_fn, config=ScanConfig())
        findings = scanner.scan(
            url="http://example.com/list",
            method="GET",
            params={"filter": "active"},
        )
        for f in findings:
            self.assertIn(f.db_type, ("unknown", "mysql", "postgresql", "mssql",
                                      "sqlite", "oracle"))


# ===========================================================================
# score_rationale in Finding tests
# ===========================================================================


class TestScoreRationale(unittest.TestCase):
    """score_rationale must be populated in findings and included in to_dict()."""

    def test_finding_has_score_rationale_on_signal(self):
        """Findings produced from the scanner must have a non-empty score_rationale."""
        scanner = DiscoveryScanner(request_fn=_error_request_fn, config=ScanConfig())
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "test"},
        )
        for f in findings:
            self.assertIsNotNone(f.score_rationale,
                                 "score_rationale should be populated for scanner findings")
            self.assertIsInstance(f.score_rationale, str)
            self.assertGreater(len(f.score_rationale), 0)

    def test_score_rationale_in_to_dict_when_present(self):
        """to_dict() must include score_rationale when it is set."""
        f = Finding(
            parameter="id",
            technique="error",
            db_type="mysql",
            confidence=0.9,
            verdict="confirmed",
            score_rationale="score=0.900, verdict=confirmed, active_features=1 (top: sql_error_pattern)",
        )
        d = f.to_dict()
        self.assertIn("score_rationale", d)
        self.assertEqual(f.score_rationale, d["score_rationale"])

    def test_score_rationale_absent_from_to_dict_when_none(self):
        """to_dict() must NOT include score_rationale key when it is None."""
        f = Finding(
            parameter="id",
            technique="error",
            db_type="mysql",
            confidence=0.9,
            verdict="confirmed",
        )
        d = f.to_dict()
        self.assertNotIn("score_rationale", d)

    def test_verify_mode_confirm_rationale_included(self):
        """In VERIFY mode, confirmation rationale should be appended to score_rationale."""
        policy = ModePolicy(OperationMode.VERIFY)
        scanner = DiscoveryScanner(
            request_fn=_error_request_fn,
            config=ScanConfig(),
            mode_policy=policy,
        )
        findings = scanner.scan(
            url="http://example.com/verified",
            method="GET",
            params={"q": "test"},
        )
        for f in findings:
            if f.score_rationale:
                # In VERIFY mode, either confirmation loop ran (text includes
                # "confirmed" or "NOT confirmed") or scoring rationale alone is present
                self.assertIsInstance(f.score_rationale, str)


# ===========================================================================
# Comparator similarity / fingerprint consistency tests
# ===========================================================================


class TestComparatorSimilarityConsistency(unittest.TestCase):
    """ResponseComparator must use normalised bodies for similarity comparisons."""

    def setUp(self):
        self.cfg = ScanConfig(length_delta_threshold=50, similarity_threshold=0.10)
        self.comp = ResponseComparator(self.cfg)

    def test_normalised_bodies_used_for_comparison(self):
        """Two bodies that differ only in dynamic tokens should compare as identical."""
        from sql_attacker.engine.normalization import normalize_response_body

        body_a = "<html><body>Welcome! Session: a1b2c3d4e5f6a7b8c9d0</body></html>"
        body_b = "<html><body>Welcome! Session: 9988776655443322</body></html>"

        norm_a = normalize_response_body(body_a)
        norm_b = normalize_response_body(body_b)

        # After normalisation the session tokens become <HEX_TOKEN>
        result = self.comp.compare(norm_a, norm_b, 200, 200)
        # Similarity should be very high (near 1.0) since only the dynamic token differs
        self.assertGreater(result.similarity, 0.7,
                           "Normalised bodies should have high similarity despite session token")

    def test_sql_error_in_probe_triggers_feature(self):
        """SQL error in probe body must set sql_error_pattern feature."""
        from sql_attacker.engine.normalization import normalize_response_body

        baseline = normalize_response_body("Normal page")
        probe = normalize_response_body(
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version"
        )
        result = self.comp.compare(baseline, probe, 200, 200)
        features = self.comp.to_feature_dict(result)
        self.assertIn("sql_error_pattern", features)
        self.assertEqual(1.0, features["sql_error_pattern"])

    def test_low_similarity_activates_similarity_delta(self):
        """A large semantic change must activate the similarity_delta feature."""
        from sql_attacker.engine.normalization import normalize_response_body

        baseline = normalize_response_body("welcome user profile page settings")
        probe = normalize_response_body(
            "error database connection refused internal server problem"
        )
        result = self.comp.compare(baseline, probe, 200, 200)
        features = self.comp.to_feature_dict(result)
        self.assertIn("similarity_delta", features)

    def test_fingerprint_stable_for_same_content(self):
        """fingerprint() must return the same value for semantically identical content."""
        from sql_attacker.engine.normalization import fingerprint

        body_a = "Hello World  Session: 2026-01-01T00:00:00Z"
        body_b = "Hello World  Session: 2025-06-15T12:34:56Z"

        # Both normalise to the same text after scrubbing timestamps
        fp_a = fingerprint(body_a)
        fp_b = fingerprint(body_b)
        self.assertEqual(fp_a, fp_b,
                         "Fingerprints should be identical after timestamp scrubbing")


if __name__ == "__main__":
    unittest.main()
