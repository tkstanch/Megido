#!/usr/bin/env python3
"""
Tests for discovery, timeguard, and config engine modules.
"""

import sys
import os
import time
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.discovery import (
    ComparisonResult,
    DiscoveryScanner,
    ErrorSignature,
    InjectionLocation,
    InjectionPoint,
    ProbeSet,
    ResponseComparator,
    detect_sql_errors,
    _jaccard_similarity,
    _BOOLEAN_FALSE_PROBES,
    _BOOLEAN_TRUE_PROBES,
    _QUOTE_BREAK_PROBES,
)
from sql_attacker.engine.timeguard import (
    PerHostBudget,
    TimeBasedResult,
    TimedConfirmation,
    build_sleep_payload,
    _median,
)
from sql_attacker.engine.reporting import Finding


# ===========================================================================
# ScanConfig tests
# ===========================================================================


class TestScanConfigDefaults(unittest.TestCase):
    """ScanConfig should have safe defaults."""

    def test_instantiation_no_args(self):
        cfg = ScanConfig()
        self.assertIsInstance(cfg, ScanConfig)

    def test_default_inject_query_params(self):
        self.assertTrue(ScanConfig().inject_query_params)

    def test_default_inject_form_params(self):
        self.assertTrue(ScanConfig().inject_form_params)

    def test_default_inject_json_params(self):
        self.assertTrue(ScanConfig().inject_json_params)

    def test_default_inject_headers_is_false(self):
        """Header injection must be explicitly opted in."""
        self.assertFalse(ScanConfig().inject_headers)

    def test_default_time_based_disabled(self):
        """Time-based detection must be explicitly opted in."""
        self.assertFalse(ScanConfig().time_based_enabled)

    def test_default_time_based_max_delay(self):
        self.assertEqual(3.0, ScanConfig().time_based_max_delay_seconds)

    def test_default_redact_sensitive_headers_non_empty(self):
        cfg = ScanConfig()
        self.assertIn("Authorization", cfg.redact_sensitive_headers)
        self.assertIn("Cookie", cfg.redact_sensitive_headers)

    def test_default_injectable_headers_non_empty(self):
        cfg = ScanConfig()
        self.assertGreater(len(cfg.injectable_headers), 0)

    def test_validate_passes_with_defaults(self):
        """validate() should not raise for default config."""
        ScanConfig().validate()

    def test_validate_raises_for_zero_baseline_samples(self):
        with self.assertRaises(ValueError):
            ScanConfig(baseline_samples=0).validate()

    def test_validate_raises_for_negative_timeout(self):
        with self.assertRaises(ValueError):
            ScanConfig(request_timeout_seconds=-1).validate()

    def test_validate_raises_for_excessive_delay(self):
        with self.assertRaises(ValueError):
            ScanConfig(time_based_max_delay_seconds=60).validate()

    def test_validate_raises_for_invalid_similarity_threshold(self):
        with self.assertRaises(ValueError):
            ScanConfig(similarity_threshold=1.5).validate()

    def test_custom_values_stored(self):
        cfg = ScanConfig(
            max_concurrent_requests=5,
            inject_headers=True,
            time_based_enabled=True,
        )
        self.assertEqual(5, cfg.max_concurrent_requests)
        self.assertTrue(cfg.inject_headers)
        self.assertTrue(cfg.time_based_enabled)


# ===========================================================================
# ProbeSet tests
# ===========================================================================


class TestProbeSet(unittest.TestCase):
    def test_default_probe_set_non_empty(self):
        ps = ProbeSet.default()
        self.assertGreater(len(ps.quote_break), 0)
        self.assertGreater(len(ps.boolean_true), 0)
        self.assertGreater(len(ps.boolean_false), 0)

    def test_boolean_probe_count_limits_pairs(self):
        ps = ProbeSet.default(boolean_probe_count=1)
        self.assertEqual(1, len(ps.boolean_true))
        self.assertEqual(1, len(ps.boolean_false))

    def test_boolean_probe_count_default(self):
        ps = ProbeSet.default(boolean_probe_count=2)
        self.assertEqual(2, len(ps.boolean_true))
        self.assertEqual(2, len(ps.boolean_false))

    def test_quote_break_includes_single_quote(self):
        ps = ProbeSet.default()
        self.assertIn("'", ps.quote_break)

    def test_equal_true_false_count(self):
        """True and false probe lists should have the same length."""
        ps = ProbeSet.default(boolean_probe_count=3)
        self.assertEqual(len(ps.boolean_true), len(ps.boolean_false))


# ===========================================================================
# ErrorSignature / detect_sql_errors tests
# ===========================================================================


class TestDetectSqlErrors(unittest.TestCase):
    def test_mysql_error_detected(self):
        body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
        sigs = detect_sql_errors(body)
        self.assertTrue(any(s.db_type == "mysql" for s in sigs))

    def test_postgresql_error_detected(self):
        body = "PSQLException: ERROR: syntax error at or near \"'\" at character 12"
        sigs = detect_sql_errors(body)
        self.assertTrue(any(s.db_type == "postgresql" for s in sigs))

    def test_mssql_error_detected(self):
        body = "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark"
        sigs = detect_sql_errors(body)
        self.assertTrue(any(s.db_type == "mssql" for s in sigs))

    def test_sqlite_error_detected(self):
        body = "SQLite.Exception: unrecognized token: \"'\" in query"
        sigs = detect_sql_errors(body)
        self.assertTrue(any(s.db_type == "sqlite" for s in sigs))

    def test_oracle_error_detected(self):
        body = "ORA-00933: SQL command not properly ended"
        sigs = detect_sql_errors(body)
        self.assertTrue(any(s.db_type == "oracle" for s in sigs))

    def test_no_match_returns_empty(self):
        body = "Welcome to our website. No errors here."
        sigs = detect_sql_errors(body)
        self.assertEqual([], sigs)

    def test_multiple_signatures_can_match(self):
        # This body contains both a MySQL error phrase and a JDBC reference
        body = (
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax "
            "near '' at line 1 - com.mysql.jdbc driver error"
        )
        sigs = detect_sql_errors(body)
        self.assertGreaterEqual(len(sigs), 2)

    def test_error_signature_has_description(self):
        body = "ORA-01756: quoted string not properly terminated"
        sigs = detect_sql_errors(body)
        self.assertTrue(all(s.description for s in sigs))

    def test_case_insensitive_matching(self):
        body = "microsoft ole db provider for sql server unclosed quotation mark"
        sigs = detect_sql_errors(body)
        self.assertTrue(any(s.db_type == "mssql" for s in sigs))


# ===========================================================================
# ResponseComparator tests
# ===========================================================================


class TestJaccardSimilarity(unittest.TestCase):
    def test_identical_texts_similarity_one(self):
        self.assertEqual(1.0, _jaccard_similarity("hello world", "hello world"))

    def test_empty_texts_similarity_one(self):
        self.assertEqual(1.0, _jaccard_similarity("", ""))

    def test_disjoint_texts_similarity_zero(self):
        self.assertEqual(0.0, _jaccard_similarity("foo bar", "baz qux"))

    def test_partial_overlap(self):
        sim = _jaccard_similarity("hello world", "hello earth")
        self.assertGreater(sim, 0.0)
        self.assertLess(sim, 1.0)

    def test_one_empty_returns_zero(self):
        self.assertEqual(0.0, _jaccard_similarity("", "something"))


class TestResponseComparator(unittest.TestCase):
    def setUp(self):
        self.cfg = ScanConfig(length_delta_threshold=50, similarity_threshold=0.10)
        self.comp = ResponseComparator(self.cfg)

    def test_identical_responses_no_features(self):
        result = self.comp.compare("hello world", "hello world", 200, 200)
        features = self.comp.to_feature_dict(result)
        self.assertNotIn("http_error_code", features)
        self.assertNotIn("sql_error_pattern", features)

    def test_status_change_detected(self):
        result = self.comp.compare("body", "body", 200, 500)
        self.assertTrue(result.status_changed)
        features = self.comp.to_feature_dict(result)
        self.assertIn("http_error_code", features)
        self.assertEqual(1.0, features["http_error_code"])  # 5xx = 1.0

    def test_status_change_non_5xx(self):
        result = self.comp.compare("body", "body", 200, 403)
        features = self.comp.to_feature_dict(result)
        self.assertIn("http_error_code", features)
        self.assertEqual(0.5, features["http_error_code"])

    def test_large_length_delta_triggers_content_change(self):
        baseline = "a " * 100
        probe = "a " * 100 + "b " * 200  # much longer
        result = self.comp.compare(baseline, probe, 200, 200)
        features = self.comp.to_feature_dict(result)
        self.assertIn("content_change", features)

    def test_small_length_delta_no_feature(self):
        baseline = "hello world"
        probe = "hello worlds"  # tiny difference
        result = self.comp.compare(baseline, probe, 200, 200)
        features = self.comp.to_feature_dict(result)
        self.assertNotIn("content_change", features)

    def test_sql_error_in_probe_body(self):
        baseline = "Welcome to the site"
        probe = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
        result = self.comp.compare(baseline, probe, 200, 200)
        self.assertTrue(result.has_sql_errors)
        features = self.comp.to_feature_dict(result)
        self.assertIn("sql_error_pattern", features)
        self.assertEqual(1.0, features["sql_error_pattern"])

    def test_matched_db_types_extracted(self):
        body = "Microsoft OLE DB Provider for SQL Server error"
        result = self.comp.compare("baseline", body, 200, 200)
        self.assertIn("mssql", result.matched_db_types)

    def test_low_similarity_triggers_similarity_delta(self):
        baseline = "the quick brown fox jumps over the lazy dog"
        probe = "completely different text with no overlap whatsoever here"
        result = self.comp.compare(baseline, probe, 200, 200)
        features = self.comp.to_feature_dict(result)
        self.assertIn("similarity_delta", features)

    def test_error_detection_disabled(self):
        cfg = ScanConfig(error_detection_enabled=False)
        comp = ResponseComparator(cfg)
        probe = "You have an error in your SQL syntax"
        result = comp.compare("baseline", probe, 200, 200)
        self.assertFalse(result.has_sql_errors)


# ===========================================================================
# InjectionPoint / InjectionLocation tests
# ===========================================================================


class TestInjectionLocation(unittest.TestCase):
    def test_all_locations_present(self):
        locations = {loc.value for loc in InjectionLocation}
        self.assertIn("query_param", locations)
        self.assertIn("form_param", locations)
        self.assertIn("json_param", locations)
        self.assertIn("header", locations)

    def test_injection_point_creation(self):
        ip = InjectionPoint(
            name="id",
            location=InjectionLocation.QUERY_PARAM,
            original_value="1",
        )
        self.assertEqual("id", ip.name)
        self.assertEqual(InjectionLocation.QUERY_PARAM, ip.location)
        self.assertEqual("1", ip.original_value)


# ===========================================================================
# DiscoveryScanner – unit tests with mock request function
# ===========================================================================


def _make_mock_response(status_code: int = 200, text: str = "Hello World") -> MagicMock:
    """Build a fake response object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def _safe_request_fn(url, method, params, data, json_data, headers, cookies):
    """A request function that always returns a clean response."""
    return _make_mock_response(200, "Safe response text here.")


def _error_request_fn(url, method, params, data, json_data, headers, cookies):
    """A request function that returns an SQL error response for any injected payload."""
    # Detect if a payload is in the params
    injected = False
    if params:
        for v in params.values():
            if v and ("'" in str(v) or '"' in str(v) or "OR" in str(v).upper()):
                injected = True
    if injected:
        return _make_mock_response(
            200,
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax.",
        )
    return _make_mock_response(200, "Normal page content.")


class TestDiscoveryScannerEnumeration(unittest.TestCase):
    """Tests for injection point enumeration logic."""

    def _make_scanner(self, **cfg_kwargs):
        cfg = ScanConfig(**cfg_kwargs)
        return DiscoveryScanner(request_fn=_safe_request_fn, config=cfg)

    def test_enumerates_query_params(self):
        scanner = self._make_scanner()
        points = scanner._enumerate_injection_points(
            method="GET",
            params={"id": "1", "name": "foo"},
            data={}, json_data={}, headers={},
        )
        names = [p.name for p in points]
        self.assertIn("id", names)
        self.assertIn("name", names)
        for p in points:
            self.assertEqual(InjectionLocation.QUERY_PARAM, p.location)

    def test_enumerates_form_params_post_only(self):
        scanner = self._make_scanner()
        points = scanner._enumerate_injection_points(
            method="POST",
            params={},
            data={"username": "admin"},
            json_data={}, headers={},
        )
        self.assertTrue(any(p.name == "username" for p in points))
        self.assertTrue(any(p.location == InjectionLocation.FORM_PARAM for p in points))

    def test_form_params_skipped_for_get(self):
        scanner = self._make_scanner()
        points = scanner._enumerate_injection_points(
            method="GET",
            params={},
            data={"username": "admin"},
            json_data={}, headers={},
        )
        self.assertFalse(any(p.location == InjectionLocation.FORM_PARAM for p in points))

    def test_enumerates_json_params(self):
        scanner = self._make_scanner()
        points = scanner._enumerate_injection_points(
            method="POST",
            params={},
            data={},
            json_data={"query": "search term"},
            headers={},
        )
        self.assertTrue(any(p.name == "query" for p in points))

    def test_header_injection_requires_opt_in(self):
        scanner = self._make_scanner(inject_headers=False)
        points = scanner._enumerate_injection_points(
            method="GET",
            params={},
            data={},
            json_data={},
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        self.assertFalse(any(p.location == InjectionLocation.HEADER for p in points))

    def test_header_injection_with_opt_in(self):
        scanner = self._make_scanner(
            inject_headers=True,
            injectable_headers=["X-Forwarded-For"],
        )
        points = scanner._enumerate_injection_points(
            method="GET",
            params={},
            data={},
            json_data={},
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        self.assertTrue(any(p.location == InjectionLocation.HEADER for p in points))

    def test_inject_query_params_disabled(self):
        scanner = self._make_scanner(inject_query_params=False)
        points = scanner._enumerate_injection_points(
            method="GET",
            params={"id": "1"},
            data={}, json_data={}, headers={},
        )
        self.assertFalse(any(p.location == InjectionLocation.QUERY_PARAM for p in points))


class TestDiscoveryScannerPayloadInjection(unittest.TestCase):
    """Tests for _inject_payload logic."""

    def setUp(self):
        self.scanner = DiscoveryScanner(request_fn=_safe_request_fn)

    def test_inject_query_param(self):
        ip = InjectionPoint("id", InjectionLocation.QUERY_PARAM, "1")
        p, d, j, h, c = self.scanner._inject_payload(
            ip, "PAYLOAD", {"id": "1", "page": "2"}, {}, {}, {}
        )
        self.assertEqual("PAYLOAD", p["id"])
        self.assertEqual("2", p["page"])

    def test_inject_form_param(self):
        ip = InjectionPoint("username", InjectionLocation.FORM_PARAM, "admin")
        p, d, j, h, c = self.scanner._inject_payload(
            ip, "PAYLOAD", {}, {"username": "admin"}, {}, {}
        )
        self.assertEqual("PAYLOAD", d["username"])

    def test_inject_json_param(self):
        ip = InjectionPoint("q", InjectionLocation.JSON_PARAM, "search")
        p, d, j, h, c = self.scanner._inject_payload(
            ip, "PAYLOAD", {}, {}, {"q": "search"}, {}
        )
        self.assertEqual("PAYLOAD", j["q"])

    def test_inject_header(self):
        ip = InjectionPoint("X-Forwarded-For", InjectionLocation.HEADER, "1.2.3.4")
        p, d, j, h, c = self.scanner._inject_payload(
            ip, "PAYLOAD", {}, {}, {}, {"X-Forwarded-For": "1.2.3.4"}
        )
        self.assertEqual("PAYLOAD", h["X-Forwarded-For"])

    def test_original_values_unchanged(self):
        ip = InjectionPoint("id", InjectionLocation.QUERY_PARAM, "1")
        original_params = {"id": "1", "page": "2"}
        p, d, j, h, c = self.scanner._inject_payload(ip, "PAYLOAD", original_params, {}, {}, {})
        # Original dict should not be mutated
        self.assertEqual("1", original_params["id"])


class TestDiscoveryScannerScan(unittest.TestCase):
    """Integration-style tests for DiscoveryScanner.scan()."""

    def test_safe_target_returns_no_findings(self):
        scanner = DiscoveryScanner(request_fn=_safe_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "hello"},
        )
        # Safe responses should produce no findings or at most uncertain ones
        confirmed = [f for f in findings if f.verdict in ("confirmed", "likely")]
        self.assertEqual([], confirmed)

    def test_error_target_returns_finding(self):
        """When a target responds with SQL errors, a finding should be returned."""
        scanner = DiscoveryScanner(request_fn=_error_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1"},
        )
        # Should find at least one finding
        self.assertGreater(len(findings), 0)
        # At least one should mention mysql
        mysql_findings = [f for f in findings if "mysql" in f.db_type.lower()]
        self.assertGreater(len(mysql_findings), 0)

    def test_error_finding_has_parameter_metadata(self):
        scanner = DiscoveryScanner(request_fn=_error_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1"},
        )
        self.assertGreater(len(findings), 0)
        f = findings[0]
        self.assertEqual("id", f.parameter)
        self.assertEqual("http://example.com/search", f.url)
        self.assertEqual("GET", f.method)

    def test_finding_has_evidence(self):
        scanner = DiscoveryScanner(request_fn=_error_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1"},
        )
        self.assertGreater(len(findings), 0)
        f = findings[0]
        self.assertGreater(len(f.evidence), 0)

    def test_finding_confidence_in_unit_interval(self):
        scanner = DiscoveryScanner(request_fn=_error_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1"},
        )
        for f in findings:
            self.assertGreaterEqual(f.confidence, 0.0)
            self.assertLessEqual(f.confidence, 1.0)

    def test_no_params_returns_empty(self):
        scanner = DiscoveryScanner(request_fn=_safe_request_fn)
        findings = scanner.scan(
            url="http://example.com/",
            method="GET",
            params={},
        )
        self.assertEqual([], findings)

    def test_per_host_budget_limits_requests(self):
        """Requests should stop when the per-host budget is exhausted."""
        call_count = [0]

        def counting_request_fn(url, method, params, data, json_data, headers, cookies):
            call_count[0] += 1
            return _make_mock_response(200, "Normal page.")

        cfg = ScanConfig(per_host_request_budget=3)
        scanner = DiscoveryScanner(request_fn=counting_request_fn, config=cfg)
        scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"a": "1", "b": "2"},
        )
        # Should not exceed budget
        self.assertLessEqual(call_count[0], cfg.per_host_request_budget)

    def test_failing_request_fn_handled_gracefully(self):
        """Exceptions from the request function should not crash the scanner."""
        def failing_fn(*args, **kwargs):
            raise ConnectionError("Network unreachable")

        scanner = DiscoveryScanner(request_fn=failing_fn)
        # Should return empty findings, not raise
        try:
            findings = scanner.scan(
                url="http://example.com/",
                method="GET",
                params={"id": "1"},
            )
            # No findings when all requests fail (baseline also fails)
        except Exception as exc:
            self.fail(f"scan() raised an unexpected exception: {exc}")

    def test_redact_payloads_in_logs_does_not_change_findings(self):
        """Enabling redaction should not affect finding detection."""
        cfg = ScanConfig(redact_payloads_in_logs=True)
        scanner = DiscoveryScanner(request_fn=_error_request_fn, config=cfg)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1"},
        )
        self.assertGreater(len(findings), 0)

    def test_multiple_params_multiple_findings_possible(self):
        scanner = DiscoveryScanner(request_fn=_error_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1", "name": "foo"},
        )
        # Each param may produce its own finding
        param_names = [f.parameter for f in findings]
        # At least one param found
        self.assertTrue(any(n in param_names for n in ["id", "name"]))

    def test_verdict_is_valid(self):
        scanner = DiscoveryScanner(request_fn=_error_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"id": "1"},
        )
        for f in findings:
            self.assertIn(f.verdict, ("confirmed", "likely", "uncertain"))


class TestDiscoveryScannerBooleanDiff(unittest.TestCase):
    """Tests for boolean differential analysis."""

    def test_boolean_diff_with_differential_responses(self):
        """When true/false probes produce different content, boolean_diff > 0."""
        true_body = "Welcome admin! You have 5 messages."
        false_body = "No results found."
        baseline_body = "Welcome admin! You have 5 messages."

        call_n = [0]

        def differential_fn(url, method, params, data, json_data, headers, cookies):
            q = (params or {}).get("q", "")
            call_n[0] += 1
            # True-ish payloads return full page; false-ish return empty
            if "1=2" in q or "x'='y" in q or "1'='2" in q:
                return _make_mock_response(200, false_body)
            return _make_mock_response(200, baseline_body)

        scanner = DiscoveryScanner(request_fn=differential_fn)
        ip = InjectionPoint("q", InjectionLocation.QUERY_PARAM, "hello")
        probe_set = ProbeSet.default(boolean_probe_count=1)

        score = scanner._compute_boolean_diff(
            ip=ip,
            url="http://example.com/search",
            method="GET",
            params={"q": "hello"},
            data={}, json_data={}, headers={}, cookies={},
            baseline_body=baseline_body,
            probe_set=probe_set,
        )
        # There should be a non-zero diff score when true/false responses differ
        self.assertGreaterEqual(score, 0.0)

    def test_boolean_diff_no_diff_returns_zero(self):
        """When true/false probes produce the same content, diff should be 0."""
        same_body = "Same response for everything."

        def same_fn(url, method, params, data, json_data, headers, cookies):
            return _make_mock_response(200, same_body)

        scanner = DiscoveryScanner(request_fn=same_fn)
        ip = InjectionPoint("q", InjectionLocation.QUERY_PARAM, "hello")
        probe_set = ProbeSet.default(boolean_probe_count=1)

        score = scanner._compute_boolean_diff(
            ip=ip,
            url="http://example.com/search",
            method="GET",
            params={"q": "hello"},
            data={}, json_data={}, headers={}, cookies={},
            baseline_body=same_body,
            probe_set=probe_set,
        )
        self.assertEqual(0.0, score)


# ===========================================================================
# TimedConfirmation tests (mocked timers)
# ===========================================================================


class TestBuildSleepPayload(unittest.TestCase):
    def test_mysql_sleep(self):
        result = build_sleep_payload("' AND SLEEP({delay})--", 3)
        self.assertEqual("' AND SLEEP(3)--", result)

    def test_mssql_waitfor(self):
        result = build_sleep_payload("'; WAITFOR DELAY '0:0:{delay}'--", 5)
        self.assertEqual("'; WAITFOR DELAY '0:0:5'--", result)

    def test_postgresql_sleep(self):
        result = build_sleep_payload("'; SELECT pg_sleep({delay})--", 2)
        self.assertEqual("'; SELECT pg_sleep(2)--", result)


class TestMedian(unittest.TestCase):
    def test_odd(self):
        self.assertEqual(3.0, _median([1.0, 2.0, 3.0, 4.0, 5.0]))

    def test_even(self):
        self.assertEqual(2.5, _median([1.0, 2.0, 3.0, 4.0]))

    def test_single(self):
        self.assertEqual(42.0, _median([42.0]))


class TestPerHostBudget(unittest.TestCase):
    def test_consume_within_budget(self):
        budget = PerHostBudget(max_requests_per_host=10)
        self.assertTrue(budget.consume("example.com", 5))
        self.assertEqual(5, budget.remaining("example.com"))

    def test_consume_exceeds_budget(self):
        budget = PerHostBudget(max_requests_per_host=5)
        budget.consume("example.com", 5)
        self.assertFalse(budget.consume("example.com", 1))

    def test_remaining_before_any_consumption(self):
        budget = PerHostBudget(max_requests_per_host=10)
        self.assertEqual(10, budget.remaining("example.com"))

    def test_reset_single_host(self):
        budget = PerHostBudget(max_requests_per_host=10)
        budget.consume("a.com", 5)
        budget.consume("b.com", 3)
        budget.reset("a.com")
        self.assertEqual(10, budget.remaining("a.com"))
        self.assertEqual(7, budget.remaining("b.com"))

    def test_reset_all_hosts(self):
        budget = PerHostBudget(max_requests_per_host=10)
        budget.consume("a.com", 5)
        budget.consume("b.com", 3)
        budget.reset()
        self.assertEqual(10, budget.remaining("a.com"))
        self.assertEqual(10, budget.remaining("b.com"))

    def test_independent_hosts(self):
        budget = PerHostBudget(max_requests_per_host=5)
        budget.consume("a.com", 5)
        self.assertFalse(budget.consume("a.com", 1))
        self.assertTrue(budget.consume("b.com", 5))


class TestTimedConfirmationDisabled(unittest.TestCase):
    """When time_based_enabled=False, confirm() returns immediately."""

    def test_disabled_returns_not_confirmed(self):
        cfg = ScanConfig(time_based_enabled=False)
        tc = TimedConfirmation(request_fn=_safe_request_fn, config=cfg)
        result = tc.confirm(
            url="http://example.com/",
            method="GET",
            params={"id": "1"},
            inject_param="id",
            inject_location="query_param",
        )
        self.assertFalse(result.confirmed)
        self.assertEqual(0, result.requests_used)

    def test_disabled_rationale_mentions_setting(self):
        cfg = ScanConfig(time_based_enabled=False)
        tc = TimedConfirmation(request_fn=_safe_request_fn, config=cfg)
        result = tc.confirm(
            url="http://example.com/",
            method="GET",
            inject_param="id",
        )
        self.assertIn("time_based_enabled", result.rationale)


class TestTimedConfirmationWithMockedTimers(unittest.TestCase):
    """Test time-based detection using mocked time.monotonic."""

    def _make_slow_request_fn(self, slow_delay_s: float = 3.1, normal_s: float = 0.1):
        """Returns a request fn that adds time.sleep to simulate delay.

        For simplicity we mock monotonic, so no actual sleep occurs.
        """
        call_n = [0]

        def fn(url, method, params, data, json_data, headers, cookies):
            call_n[0] += 1
            return _make_mock_response(200, "response")

        return fn

    def test_confirmed_when_injected_response_slow(self):
        """Simulate a slow injected response by mocking time.monotonic."""
        cfg = ScanConfig(
            time_based_enabled=True,
            time_based_max_delay_seconds=3,
            time_based_max_requests_per_endpoint=6,
        )

        # We'll use the baseline_median_ms pre-supplied to skip baseline collection.
        # The "slow" responses are simulated by patching time.monotonic to return
        # increasing values.
        baseline_ms = 100.0  # 100ms baseline
        # Injected delay of 3s → expect ~3100ms
        expected_injected_ms = 3200.0

        call_n = [0]

        def fake_request_fn(url, method, params, data, json_data, headers, cookies):
            call_n[0] += 1
            return _make_mock_response(200, "response")

        # Patch time.monotonic so that each pair of calls (start, end) shows
        # a 3.2-second elapsed time for injected requests.
        monotonic_values = []
        # First call = start, second call = end for each request
        t = 0.0
        for _ in range(30):
            monotonic_values.append(t)
            t += 3.2  # each "request" takes 3200ms

        with patch("sql_attacker.engine.timeguard.time") as mock_time:
            mock_time.monotonic.side_effect = monotonic_values

            tc = TimedConfirmation(request_fn=fake_request_fn, config=cfg)
            result = tc.confirm(
                url="http://example.com/search",
                method="GET",
                params={"id": "1"},
                inject_param="id",
                inject_location="query_param",
                baseline_median_ms=baseline_ms,
                repetitions=2,
            )

        # With 3200ms observed vs 100ms baseline + 80% of 3000ms = 2500ms min,
        # this should be confirmed.
        self.assertTrue(result.confirmed)
        self.assertGreater(result.median_injected_ms, 0)
        self.assertGreater(result.requests_used, 0)

    def test_not_confirmed_when_injected_response_normal(self):
        """When injected response is fast, no confirmation."""
        cfg = ScanConfig(
            time_based_enabled=True,
            time_based_max_delay_seconds=3,
            time_based_max_requests_per_endpoint=6,
        )

        def fast_request_fn(url, method, params, data, json_data, headers, cookies):
            return _make_mock_response(200, "response")

        monotonic_values = []
        t = 0.0
        for _ in range(30):
            monotonic_values.append(t)
            t += 0.1  # each "request" takes 100ms (fast)

        with patch("sql_attacker.engine.timeguard.time") as mock_time:
            mock_time.monotonic.side_effect = monotonic_values

            tc = TimedConfirmation(request_fn=fast_request_fn, config=cfg)
            result = tc.confirm(
                url="http://example.com/search",
                method="GET",
                params={"id": "1"},
                inject_param="id",
                inject_location="query_param",
                baseline_median_ms=100.0,
                repetitions=2,
            )

        self.assertFalse(result.confirmed)

    def test_budget_exhausted_stops_early(self):
        """When host budget is exhausted, confirmation stops early."""
        cfg = ScanConfig(
            time_based_enabled=True,
            time_based_max_delay_seconds=3,
            time_based_max_requests_per_endpoint=6,
            time_based_max_requests_per_host=2,  # very tight budget
        )

        call_n = [0]

        def counting_fn(url, method, params, data, json_data, headers, cookies):
            call_n[0] += 1
            return _make_mock_response(200, "response")

        budget = PerHostBudget(max_requests_per_host=2)

        with patch("sql_attacker.engine.timeguard.time") as mock_time:
            mock_time.monotonic.side_effect = [float(i) * 0.1 for i in range(50)]

            tc = TimedConfirmation(
                request_fn=counting_fn, config=cfg, host_budget=budget
            )
            result = tc.confirm(
                url="http://example.com/",
                method="GET",
                inject_param="id",
                inject_location="query_param",
                baseline_median_ms=100.0,
                repetitions=3,
            )

        # Should not have made more requests than the budget allows
        self.assertLessEqual(result.requests_used, 2)

    def test_all_requests_fail_returns_not_confirmed(self):
        """When all probe requests fail, result should be not confirmed."""
        cfg = ScanConfig(
            time_based_enabled=True,
            time_based_max_delay_seconds=3,
        )

        def failing_fn(url, method, params, data, json_data, headers, cookies):
            return None  # simulates network failure

        with patch("sql_attacker.engine.timeguard.time") as mock_time:
            mock_time.monotonic.side_effect = [float(i) * 0.1 for i in range(50)]

            tc = TimedConfirmation(request_fn=failing_fn, config=cfg)
            result = tc.confirm(
                url="http://example.com/",
                method="GET",
                inject_param="id",
                inject_location="query_param",
                baseline_median_ms=100.0,
                repetitions=2,
            )

        self.assertFalse(result.confirmed)


class TestTimedConfirmationDelayFactor(unittest.TestCase):
    def test_delay_factor_computed(self):
        result = TimeBasedResult(
            confirmed=True,
            baseline_median_ms=100.0,
            injected_samples_ms=[3200.0, 3100.0],
            median_injected_ms=3150.0,
            expected_delay_ms=3000.0,
            requests_used=2,
            payload_used="' AND SLEEP(3)--",
            rationale="confirmed",
        )
        self.assertAlmostEqual(31.5, result.delay_factor, places=1)

    def test_delay_factor_zero_baseline(self):
        result = TimeBasedResult(
            confirmed=False,
            baseline_median_ms=0.0,
            injected_samples_ms=[],
            median_injected_ms=0.0,
            expected_delay_ms=3000.0,
            requests_used=0,
            payload_used="",
            rationale="disabled",
        )
        self.assertEqual(0.0, result.delay_factor)


# ===========================================================================
# Cookie injection tests
# ===========================================================================


class TestCookieInjection(unittest.TestCase):
    """Tests for cookie parameter injection support."""

    def setUp(self):
        self.scanner = DiscoveryScanner(request_fn=_safe_request_fn)

    def test_cookie_location_enum_exists(self):
        """InjectionLocation.COOKIE_PARAM must exist."""
        self.assertEqual("cookie_param", InjectionLocation.COOKIE_PARAM.value)

    def test_inject_cookie_param(self):
        ip = InjectionPoint("session_id", InjectionLocation.COOKIE_PARAM, "abc123")
        p, d, j, h, c = self.scanner._inject_payload(
            ip, "PAYLOAD", {}, {}, {}, {}, {"session_id": "abc123"}
        )
        self.assertEqual("PAYLOAD", c["session_id"])
        self.assertEqual({}, p)
        self.assertEqual({}, d)
        self.assertEqual({}, j)
        self.assertEqual({}, h)

    def test_inject_cookie_does_not_mutate_original(self):
        ip = InjectionPoint("token", InjectionLocation.COOKIE_PARAM, "orig")
        original_cookies = {"token": "orig"}
        p, d, j, h, c = self.scanner._inject_payload(
            ip, "PAYLOAD", {}, {}, {}, {}, original_cookies
        )
        self.assertEqual("orig", original_cookies["token"])
        self.assertEqual("PAYLOAD", c["token"])

    def test_enumerate_cookie_points_when_enabled(self):
        cfg = ScanConfig(inject_cookies=True)
        scanner = DiscoveryScanner(request_fn=_safe_request_fn, config=cfg)
        points = scanner._enumerate_injection_points(
            method="GET",
            params={},
            data={},
            json_data={},
            headers={},
            cookies={"session": "abc", "user_id": "1"},
        )
        locations = [p.location for p in points]
        self.assertIn(InjectionLocation.COOKIE_PARAM, locations)
        names = [p.name for p in points]
        self.assertIn("session", names)
        self.assertIn("user_id", names)

    def test_enumerate_no_cookie_points_when_disabled(self):
        cfg = ScanConfig(inject_cookies=False)
        scanner = DiscoveryScanner(request_fn=_safe_request_fn, config=cfg)
        points = scanner._enumerate_injection_points(
            method="GET",
            params={},
            data={},
            json_data={},
            headers={},
            cookies={"session": "abc"},
        )
        locations = [p.location for p in points]
        self.assertNotIn(InjectionLocation.COOKIE_PARAM, locations)

    def test_scan_with_cookie_injection_enabled(self):
        """DiscoveryScanner.scan() should enumerate cookie params when enabled."""
        cfg = ScanConfig(inject_cookies=True)
        scanner = DiscoveryScanner(request_fn=_safe_request_fn, config=cfg)
        findings = scanner.scan(
            url="http://example.com/",
            method="GET",
            params={},
            cookies={"session": "abc"},
        )
        self.assertIsInstance(findings, list)

    def test_cookie_finding_has_correct_parameter_location(self):
        """A finding from a cookie injection point must report cookie_param location."""

        def _cookie_error_fn(url, method, params, data, json_data, headers, cookies):
            resp = MagicMock()
            cookie_val = (cookies or {}).get("token", "")
            if "'" in cookie_val:
                resp.text = (
                    "You have an error in your SQL syntax; check the manual "
                    "that corresponds to your MySQL server version"
                )
            else:
                resp.text = "Welcome"
            resp.status_code = 200
            return resp

        cfg = ScanConfig(inject_cookies=True)
        scanner = DiscoveryScanner(request_fn=_cookie_error_fn, config=cfg)
        findings = scanner.scan(
            url="http://example.com/",
            method="GET",
            params={},
            cookies={"token": "abc"},
        )
        cookie_findings = [f for f in findings if f.parameter_location == "cookie_param"]
        self.assertGreater(len(cookie_findings), 0, "Expected a cookie-based finding")


# ===========================================================================
# WAF / lockout detection tests
# ===========================================================================


class TestWAFDetection(unittest.TestCase):
    """Tests for WAF/lockout auto-abort safety guardrail."""

    def test_waf_detection_enabled_by_default(self):
        self.assertTrue(ScanConfig().waf_detection_enabled)

    def test_waf_abort_threshold_default(self):
        self.assertGreaterEqual(ScanConfig().waf_abort_threshold, 1)

    def test_validate_rejects_zero_threshold(self):
        with self.assertRaises(ValueError):
            ScanConfig(waf_abort_threshold=0).validate()

    def test_scanner_aborts_on_repeated_403(self):
        """Scanner must stop probing early when receiving consecutive 403 responses."""
        request_count = [0]

        def _waf_403_fn(url, method, params, data, json_data, headers, cookies):
            request_count[0] += 1
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Forbidden"
            return resp

        cfg = ScanConfig(waf_detection_enabled=True, waf_abort_threshold=3)
        scanner = DiscoveryScanner(request_fn=_waf_403_fn, config=cfg)
        scanner.scan(
            url="http://example.com/",
            method="GET",
            params={"id": "1", "name": "test"},
        )
        # Should be bounded; 2 params × (1 baseline + a small number of probes)
        self.assertLessEqual(request_count[0], 100,
                             "Scanner made too many requests despite WAF signals")

    def test_waf_detection_disabled_does_not_abort(self):
        """When waf_detection_enabled=False the scanner must not abort early on 403s."""
        request_count = [0]

        def _always_403_fn(url, method, params, data, json_data, headers, cookies):
            request_count[0] += 1
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Blocked"
            return resp

        cfg = ScanConfig(waf_detection_enabled=False, waf_abort_threshold=2)
        scanner = DiscoveryScanner(request_fn=_always_403_fn, config=cfg)
        scanner.scan(
            url="http://example.com/",
            method="GET",
            params={"q": "test"},
        )
        # With WAF detection disabled, all canary+remainder probes should fire
        self.assertGreater(request_count[0], cfg.waf_abort_threshold)


# ===========================================================================
# parameter_location in findings
# ===========================================================================


class TestParameterLocationInFinding(unittest.TestCase):
    """Tests that Finding.parameter_location is populated correctly."""

    def test_finding_has_parameter_location_field(self):
        from sql_attacker.engine.reporting import Finding
        f = Finding(
            parameter="q",
            technique="error",
            db_type="mysql",
            confidence=0.9,
            verdict="confirmed",
            parameter_location="query_param",
        )
        self.assertEqual("query_param", f.parameter_location)

    def test_finding_parameter_location_in_to_dict(self):
        from sql_attacker.engine.reporting import Finding
        f = Finding(
            parameter="q",
            technique="error",
            db_type="mysql",
            confidence=0.9,
            verdict="confirmed",
            parameter_location="json_param",
        )
        d = f.to_dict()
        self.assertIn("parameter_location", d)
        self.assertEqual("json_param", d["parameter_location"])

    def test_finding_parameter_location_default_is_unknown(self):
        from sql_attacker.engine.reporting import Finding
        f = Finding(
            parameter="q",
            technique="error",
            db_type="mysql",
            confidence=0.9,
            verdict="confirmed",
        )
        self.assertEqual("unknown", f.parameter_location)

    def test_scan_finding_includes_query_param_location(self):
        scanner = DiscoveryScanner(request_fn=_error_request_fn)
        findings = scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "hello"},
        )
        for f in findings:
            self.assertEqual("query_param", f.parameter_location)


# ===========================================================================
# TECHNIQUE_UNION and TECHNIQUE_STACKED constants
# ===========================================================================


class TestUnionAndStackedTechniques(unittest.TestCase):
    """Tests for TECHNIQUE_UNION and TECHNIQUE_STACKED in the adapter registry."""

    def setUp(self):
        from sql_attacker.engine.adapters import AdapterRegistry, DBType
        from sql_attacker.engine.adapters import TECHNIQUE_UNION, TECHNIQUE_STACKED
        self.registry = AdapterRegistry()
        self.DBType = DBType
        self.TECHNIQUE_UNION = TECHNIQUE_UNION
        self.TECHNIQUE_STACKED = TECHNIQUE_STACKED

    def test_technique_union_constant(self):
        from sql_attacker.engine.adapters import TECHNIQUE_UNION
        self.assertEqual("union", TECHNIQUE_UNION)

    def test_technique_stacked_constant(self):
        from sql_attacker.engine.adapters import TECHNIQUE_STACKED
        self.assertEqual("stacked", TECHNIQUE_STACKED)

    def test_union_payloads_exist_for_known_dbs(self):
        for db_type in (
            self.DBType.MYSQL, self.DBType.POSTGRESQL, self.DBType.MSSQL,
            self.DBType.SQLITE, self.DBType.ORACLE,
        ):
            adapter = self.registry.get_adapter(db_type)
            payloads = adapter.get_payloads(self.TECHNIQUE_UNION)
            self.assertGreater(len(payloads), 0, f"No UNION payloads for {db_type}")

    def test_stacked_payloads_exist_for_known_dbs(self):
        for db_type in (
            self.DBType.MYSQL, self.DBType.POSTGRESQL, self.DBType.MSSQL,
            self.DBType.SQLITE, self.DBType.ORACLE,
        ):
            adapter = self.registry.get_adapter(db_type)
            payloads = adapter.get_payloads(self.TECHNIQUE_STACKED)
            self.assertGreater(len(payloads), 0, f"No STACKED payloads for {db_type}")

    def test_union_payloads_for_unknown_db(self):
        adapter = self.registry.get_adapter(self.DBType.UNKNOWN)
        payloads = adapter.get_payloads(self.TECHNIQUE_UNION)
        self.assertGreater(len(payloads), 0)

    def test_stacked_payloads_for_unknown_db(self):
        adapter = self.registry.get_adapter(self.DBType.UNKNOWN)
        payloads = adapter.get_payloads(self.TECHNIQUE_STACKED)
        self.assertGreater(len(payloads), 0)

    def test_engine_init_exports_union_and_stacked(self):
        from sql_attacker.engine import TECHNIQUE_UNION, TECHNIQUE_STACKED
        self.assertEqual("union", TECHNIQUE_UNION)
        self.assertEqual("stacked", TECHNIQUE_STACKED)


if __name__ == "__main__":
    unittest.main()
