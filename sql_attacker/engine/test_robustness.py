#!/usr/bin/env python3
"""
Robustness and safety tests for the SQL injection assessment engine.

Covers:
  - Cookie injection edge cases
  - JSON body parameter injection
  - Duplicate parameter names across locations
  - WAF abort threshold behaviour
  - Baseline jitter model behaviour (dynamic content)
  - Evidence body redaction
  - BaselineSampler jitter-aware timing/content comparisons
  - WafBlockWindow window-based abort logic
"""

import sys
import os
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.engine.config import ScanConfig
from sql_attacker.engine.discovery import (
    DiscoveryScanner,
    InjectionLocation,
    InjectionPoint,
)
from sql_attacker.engine.reporting import Evidence, Finding, ReportBuilder, redact_response_body
from sql_attacker.false_positive_filter import BaselineSampler, FalsePositiveFilter
from sql_attacker.http_utils import (
    ALLOWED,
    BLOCKED,
    CHALLENGE,
    RATE_LIMITED,
    WafBlockWindow,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status_code: int = 200, text: str = "Safe page content.") -> MagicMock:
    """Return a lightweight fake response object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {}
    return resp


def _sql_error_response() -> MagicMock:
    return _make_response(
        200,
        "You have an error in your SQL syntax; check the manual that "
        "corresponds to your MySQL server version for the right syntax.",
    )


def _safe_response(text: str = "Safe page content.") -> MagicMock:
    return _make_response(200, text)


# ===========================================================================
# Cookie injection edge cases
# ===========================================================================


class TestCookieInjection(unittest.TestCase):
    """InjectionPoint cookie injection is isolated and safe-encoded."""

    def _make_scanner_with_cookie_tracking(self):
        """Return a scanner whose request_fn records what cookies were passed."""
        received: List[Dict] = []

        def request_fn(url, method, params, data, json_data, headers, cookies):
            received.append({
                "params": dict(params or {}),
                "data": dict(data or {}),
                "json_data": dict(json_data or {}),
                "cookies": dict(cookies or {}),
            })
            # Return SQL error only when cookie contains injection payload
            if cookies and any("'" in str(v) for v in cookies.values()):
                return _sql_error_response()
            return _safe_response()

        cfg = ScanConfig(inject_cookies=True, baseline_samples=1)
        scanner = DiscoveryScanner(request_fn=request_fn, config=cfg)
        return scanner, received

    def test_cookie_injection_does_not_modify_query_params(self):
        """Injecting into a cookie must not alter query parameters."""
        scanner, received = self._make_scanner_with_cookie_tracking()
        scanner.scan(
            url="http://example.com/page",
            method="GET",
            params={"page": "1"},
            cookies={"session": "abc123"},
        )
        # All requests should preserve the original query param value
        param_values = {r["params"].get("page") for r in received}
        self.assertIn("1", param_values, "Original query param must be preserved")

    def test_cookie_injection_only_modifies_target_cookie(self):
        """When injecting into one cookie, other cookies remain unchanged."""
        received: List[Dict] = []

        def request_fn(url, method, params, data, json_data, headers, cookies):
            received.append({"cookies": dict(cookies or {})})
            return _safe_response()

        cfg = ScanConfig(inject_cookies=True, baseline_samples=1)
        scanner = DiscoveryScanner(request_fn=request_fn, config=cfg)
        scanner.scan(
            url="http://example.com/page",
            method="GET",
            cookies={"session": "abc123", "tracking": "xyz"},
        )
        # Verify that for any request, only one cookie at a time was modified
        for req in received[1:]:  # skip baseline
            cookies = req["cookies"]
            # The unchanged cookie must still be present
            if "session" in cookies and cookies["session"] != "abc123":
                # session was the injection target – tracking should be untouched
                self.assertEqual(cookies.get("tracking"), "xyz",
                                 "Non-targeted cookie must not be modified")
            if "tracking" in cookies and cookies["tracking"] != "xyz":
                self.assertEqual(cookies.get("session"), "abc123",
                                 "Non-targeted cookie must not be modified")

    def test_cookie_injection_point_location_enum(self):
        """InjectionLocation.COOKIE_PARAM must exist and have the expected value."""
        self.assertEqual(InjectionLocation.COOKIE_PARAM.value, "cookie_param")

    def test_cookie_injection_empty_cookie_dict(self):
        """Scanning with an empty cookies dict must not raise."""
        cfg = ScanConfig(inject_cookies=True, baseline_samples=1)
        scanner = DiscoveryScanner(request_fn=lambda *a, **kw: _safe_response(), config=cfg)
        # Should not raise
        findings = scanner.scan(
            url="http://example.com/page",
            method="GET",
            cookies={},
        )
        self.assertIsInstance(findings, list)

    def test_cookie_with_special_characters_does_not_raise(self):
        """Cookie values containing special characters must not raise during injection."""
        cfg = ScanConfig(inject_cookies=True, baseline_samples=1)
        scanner = DiscoveryScanner(request_fn=lambda *a, **kw: _safe_response(), config=cfg)
        findings = scanner.scan(
            url="http://example.com/page",
            method="GET",
            cookies={"data": "value with spaces & special=chars"},
        )
        self.assertIsInstance(findings, list)


# ===========================================================================
# JSON body parameter injection
# ===========================================================================


class TestJsonBodyInjection(unittest.TestCase):
    """InjectionPoint JSON body injection isolates changes to the json_data dict."""

    def _make_json_tracking_scanner(self, return_error_on_json_payload=True):
        received: List[Dict] = []

        def request_fn(url, method, params, data, json_data, headers, cookies):
            received.append({
                "params": dict(params or {}),
                "data": dict(data or {}),
                "json_data": dict(json_data or {}),
            })
            if return_error_on_json_payload and json_data:
                if any("'" in str(v) for v in json_data.values()):
                    return _sql_error_response()
            return _safe_response()

        cfg = ScanConfig(inject_json_params=True, inject_form_params=False, inject_query_params=False, baseline_samples=1)
        scanner = DiscoveryScanner(request_fn=request_fn, config=cfg)
        return scanner, received

    def test_json_injection_does_not_modify_form_data(self):
        """Injecting into a JSON field must not modify form-encoded data."""
        scanner, received = self._make_json_tracking_scanner()
        scanner.scan(
            url="http://example.com/api",
            method="POST",
            data={"form_field": "form_value"},
            json_data={"name": "Alice"},
        )
        for req in received:
            self.assertEqual(req["data"].get("form_field"), "form_value",
                             "Form data must not be modified during JSON injection")

    def test_json_injection_does_not_modify_query_params(self):
        """Injecting into a JSON field must not modify query parameters."""
        scanner, received = self._make_json_tracking_scanner()
        scanner.scan(
            url="http://example.com/api",
            method="POST",
            params={"version": "2"},
            json_data={"name": "Alice"},
        )
        for req in received:
            self.assertEqual(req["params"].get("version"), "2",
                             "Query params must not be modified during JSON injection")

    def test_json_injection_location_enum(self):
        self.assertEqual(InjectionLocation.JSON_PARAM.value, "json_param")

    def test_json_injection_with_nested_value_does_not_raise(self):
        """Top-level JSON params with non-string original values must not raise."""
        cfg = ScanConfig(inject_json_params=True, baseline_samples=1)
        scanner = DiscoveryScanner(
            request_fn=lambda *a, **kw: _safe_response(), config=cfg
        )
        findings = scanner.scan(
            url="http://example.com/api",
            method="POST",
            json_data={"count": 42, "active": True, "name": "Bob"},
        )
        self.assertIsInstance(findings, list)


# ===========================================================================
# Duplicate parameter names across locations
# ===========================================================================


class TestDuplicateParameterNames(unittest.TestCase):
    """Parameters with the same name in different locations are handled independently."""

    def test_same_name_in_query_and_form_tracked_separately(self):
        """A parameter named 'id' in both query params and form data should produce
        two independent injection points without one overwriting the other.
        """
        injected_locations: List[str] = []

        def request_fn(url, method, params, data, json_data, headers, cookies):
            if params and "'" in str(params.get("id", "")):
                injected_locations.append("query")
                return _sql_error_response()
            if data and "'" in str(data.get("id", "")):
                injected_locations.append("form")
                return _sql_error_response()
            return _safe_response()

        cfg = ScanConfig(
            inject_query_params=True,
            inject_form_params=True,
            baseline_samples=1,
        )
        scanner = DiscoveryScanner(request_fn=request_fn, config=cfg)
        scanner.scan(
            url="http://example.com/search",
            method="POST",
            params={"id": "10"},
            data={"id": "20"},
        )
        # Both locations should have been injected
        self.assertIn("query", injected_locations,
                      "Query param 'id' should have been injected")
        self.assertIn("form", injected_locations,
                      "Form param 'id' should have been injected")

    def test_query_injection_preserves_form_value_when_names_match(self):
        """When 'id' in params is injected, form 'id' must keep its original value."""
        received: List[Dict] = []

        def request_fn(url, method, params, data, json_data, headers, cookies):
            received.append({"params": dict(params or {}), "data": dict(data or {})})
            return _safe_response()

        cfg = ScanConfig(inject_query_params=True, inject_form_params=False, baseline_samples=1)
        scanner = DiscoveryScanner(request_fn=request_fn, config=cfg)
        scanner.scan(
            url="http://example.com/search",
            method="POST",
            params={"id": "10"},
            data={"id": "20"},
        )
        for req in received[1:]:  # skip baseline
            # When query param is being probed, form data must stay unchanged
            if req["params"].get("id") != "10":  # query param was modified
                self.assertEqual(req["data"].get("id"), "20",
                                 "Form 'id' must not change when query 'id' is injected")


# ===========================================================================
# WAF abort threshold behaviour
# ===========================================================================


class TestWafBlockWindow(unittest.TestCase):
    """WafBlockWindow correctly aborts when block threshold is exceeded."""

    def test_no_abort_below_threshold(self):
        window = WafBlockWindow(window_size=10, block_threshold=3)
        for _ in range(2):
            window.record(BLOCKED)
        self.assertFalse(window.should_abort())

    def test_abort_at_threshold(self):
        window = WafBlockWindow(window_size=10, block_threshold=3)
        for _ in range(3):
            window.record(BLOCKED)
        self.assertTrue(window.should_abort())

    def test_abort_reason_set_on_trigger(self):
        window = WafBlockWindow(window_size=10, block_threshold=3)
        for _ in range(3):
            window.record(BLOCKED)
        window.should_abort()
        self.assertIsNotNone(window.abort_reason)
        self.assertIn("Aborting", window.abort_reason)

    def test_abort_resets_after_reset_call(self):
        window = WafBlockWindow(window_size=10, block_threshold=3)
        for _ in range(3):
            window.record(BLOCKED)
        self.assertTrue(window.should_abort())
        window.reset()
        self.assertFalse(window.should_abort())
        self.assertIsNone(window.abort_reason)

    def test_window_only_uses_last_n_requests(self):
        """Old outcomes outside the window must not count toward threshold."""
        window = WafBlockWindow(window_size=5, block_threshold=3)
        # Record 3 blocks then 5 allowed – blocks now fall outside window
        for _ in range(3):
            window.record(BLOCKED)
        for _ in range(5):
            window.record(ALLOWED)
        self.assertFalse(window.should_abort(),
                         "Old blocks outside the window must not trigger abort")

    def test_challenge_counts_as_block(self):
        window = WafBlockWindow(window_size=10, block_threshold=3)
        window.record(BLOCKED)
        window.record(CHALLENGE)
        window.record(RATE_LIMITED)
        self.assertTrue(window.should_abort())

    def test_allowed_outcomes_do_not_count(self):
        window = WafBlockWindow(window_size=10, block_threshold=3)
        for _ in range(5):
            window.record(ALLOWED)
        self.assertFalse(window.should_abort())

    def test_custom_count_outcomes(self):
        """Callers can restrict which outcomes count as blocks."""
        window = WafBlockWindow(
            window_size=10, block_threshold=2,
            count_outcomes={RATE_LIMITED},  # only rate-limit counts
        )
        window.record(BLOCKED)   # should not count
        window.record(CHALLENGE)  # should not count
        self.assertFalse(window.should_abort())
        window.record(RATE_LIMITED)
        window.record(RATE_LIMITED)
        self.assertTrue(window.should_abort())

    def test_waf_abort_threshold_integration_with_scanner(self):
        """DiscoveryScanner stops probing when waf_abort_threshold is exceeded."""
        call_count = [0]

        def blocking_request_fn(url, method, params, data, json_data, headers, cookies):
            call_count[0] += 1
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Forbidden"
            return resp

        cfg = ScanConfig(
            waf_detection_enabled=True,
            waf_abort_threshold=2,
            baseline_samples=1,
        )
        scanner = DiscoveryScanner(request_fn=blocking_request_fn, config=cfg)
        scanner.scan(
            url="http://example.com/search",
            method="GET",
            params={"q": "test", "page": "1"},
        )
        # With abort at threshold=2, the scanner should stop early rather than
        # exhausting all probe payloads. The probe set has ~15 payloads per param.
        # Without abort: 1 baseline + 2 params * ~15 probes = ~31 requests.
        # With abort at threshold=2: 1 baseline + 2 params * 2 probes = ~5 requests.
        total_without_abort = 1 + 2 * 15  # conservative upper bound
        self.assertLess(call_count[0], total_without_abort,
                        "WAF abort should reduce total probe count")


# ===========================================================================
# Baseline jitter model behaviour (dynamic content)
# ===========================================================================


class TestBaselineSampler(unittest.TestCase):
    """BaselineSampler correctly models jitter and reduces false positives."""

    def test_add_sample_increments_count(self):
        sampler = BaselineSampler(n_samples=3)
        sampler.add_sample("body1", 0.1)
        sampler.add_sample("body2", 0.2)
        self.assertEqual(sampler.sample_count, 2)

    def test_timing_mean_correct(self):
        sampler = BaselineSampler()
        for t in [0.1, 0.3, 0.5]:
            sampler.add_sample("body", t)
        self.assertAlmostEqual(sampler.timing_mean, 0.3, places=5)

    def test_timing_stddev_correct(self):
        sampler = BaselineSampler()
        sampler.add_sample("body", 0.1)
        sampler.add_sample("body", 0.3)
        self.assertIsNotNone(sampler.timing_stddev)
        self.assertGreater(sampler.timing_stddev, 0.0)

    def test_timing_stddev_none_with_one_sample(self):
        sampler = BaselineSampler()
        sampler.add_sample("body", 0.5)
        self.assertIsNone(sampler.timing_stddev)

    def test_body_fingerprint_stable_across_dynamic_tokens(self):
        """Dynamic tokens (timestamps, UUIDs) should not change the fingerprint."""
        sampler = BaselineSampler()
        sampler.add_sample("Welcome! Session: 2024-01-01T00:00:00Z", 0.1)
        sampler.add_sample("Welcome! Session: 2024-06-15T12:30:00Z", 0.1)
        fp1 = sampler.body_fingerprint
        sampler2 = BaselineSampler()
        sampler2.add_sample("Welcome! Session: 2025-12-31T23:59:59Z", 0.1)
        sampler2.add_sample("Welcome! Session: 2026-01-01T00:00:00Z", 0.1)
        self.assertEqual(fp1, sampler2.body_fingerprint,
                         "Fingerprint should be stable across volatile tokens")

    def test_is_timing_anomaly_detects_genuine_delay(self):
        """A response significantly longer than baseline should be flagged."""
        sampler = BaselineSampler()
        for _ in range(3):
            sampler.add_sample("body", 0.1)
        self.assertTrue(sampler.is_timing_anomaly(5.5),
                        "A 5.5s response against a 0.1s baseline should be anomalous")

    def test_is_timing_anomaly_ignores_normal_jitter(self):
        """Normal network jitter should not be flagged as anomalous."""
        sampler = BaselineSampler()
        for t in [0.15, 0.18, 0.12]:
            sampler.add_sample("body", t)
        # 0.25s is only ~0.1s above mean — within normal jitter
        self.assertFalse(sampler.is_timing_anomaly(0.25),
                         "Normal network jitter should not be flagged as anomalous")

    def test_is_content_anomaly_with_sql_error_body(self):
        """A body containing a SQL error should be flagged as a content anomaly."""
        sampler = BaselineSampler()
        for _ in range(3):
            sampler.add_sample("Normal page content here. Welcome user.", 0.1)
        sql_error_body = (
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version near ''"
        )
        self.assertTrue(sampler.is_content_anomaly(sql_error_body),
                        "SQL error body should be flagged as a content anomaly")

    def test_is_content_anomaly_ignores_dynamic_tokens_only(self):
        """Responses that differ only by timestamps should not be content anomalies."""
        sampler = BaselineSampler()
        sampler.add_sample("Page rendered at 2024-01-01T00:00:00Z. Welcome!", 0.1)
        sampler.add_sample("Page rendered at 2024-06-15T12:30:00Z. Welcome!", 0.1)
        candidate = "Page rendered at 2025-03-01T08:00:00Z. Welcome!"
        self.assertFalse(sampler.is_content_anomaly(candidate),
                         "Timestamp-only differences should not be content anomalies")

    def test_fp_filter_uses_sampler_for_timing(self):
        """FalsePositiveFilter.is_timing_anomaly delegates to sampler when set."""
        sampler = BaselineSampler()
        for _ in range(3):
            sampler.add_sample("body", 0.05)

        fp_filter = FalsePositiveFilter()
        baseline_resp = _make_response(200, "body")
        fp_filter.set_baseline(baseline_resp, sampler=sampler)

        self.assertTrue(fp_filter.is_timing_anomaly(6.0),
                        "6s response against 0.05s baseline should be anomalous")
        self.assertFalse(fp_filter.is_timing_anomaly(0.1),
                         "0.1s response against 0.05s baseline should not be anomalous")

    def test_fp_filter_falls_back_without_sampler(self):
        """FalsePositiveFilter.is_timing_anomaly works without a sampler (legacy)."""
        fp_filter = FalsePositiveFilter()
        # Without sampler and without baseline, timing check should return False
        self.assertFalse(fp_filter.is_timing_anomaly(10.0))


# ===========================================================================
# Evidence body redaction
# ===========================================================================


class TestEvidenceBodyRedaction(unittest.TestCase):
    """redact_response_body correctly removes sensitive patterns."""

    def test_jwt_is_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact_response_body(f"Token: {jwt}")
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", result)
        self.assertIn("<JWT_REDACTED>", result)

    def test_authorization_header_value_redacted(self):
        body = "Authorization: Bearer supersecrettoken12345678"
        result = redact_response_body(body)
        self.assertNotIn("supersecrettoken12345678", result)
        self.assertIn("<REDACTED>", result)

    def test_cookie_header_value_redacted(self):
        body = "Cookie: session=abc123xyz; tracking=user42"
        result = redact_response_body(body)
        self.assertNotIn("abc123xyz", result)
        self.assertIn("<REDACTED>", result)

    def test_api_key_redacted(self):
        body = "api_key=supersecret&other=value"
        result = redact_response_body(body)
        self.assertNotIn("supersecret", result)
        self.assertIn("<REDACTED>", result)

    def test_non_sensitive_content_preserved(self):
        body = "MySQL syntax error near '' at line 1"
        result = redact_response_body(body)
        self.assertIn("MySQL syntax error", result)

    def test_truncation_applied_by_default(self):
        body = "A" * 1000
        result = redact_response_body(body)
        self.assertLessEqual(len(result), 512,
                             "Response body should be truncated to max_length")
        self.assertIn("truncated", result)

    def test_no_truncation_with_max_length_zero(self):
        body = "A" * 1000
        result = redact_response_body(body, max_length=0)
        self.assertEqual(len(result), 1000)

    def test_empty_string_returns_empty(self):
        self.assertEqual(redact_response_body(""), "")

    def test_evidence_to_dict_applies_redaction(self):
        """Evidence.to_dict() must redact JWT tokens from the body excerpt."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ev = Evidence(
            payload="'",
            request_summary="GET /test?id='",
            response_body_excerpt=f"Token found: {jwt}; Error near ''",
        )
        d = ev.to_dict()
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", d["response_body_excerpt"])
        self.assertIn("<JWT_REDACTED>", d["response_body_excerpt"])

    def test_evidence_to_dict_include_full_body_flag(self):
        """include_full_body=True should preserve body up to redaction."""
        body = "Normal content. " * 100  # > 500 chars
        ev = Evidence(
            payload="'",
            request_summary="GET /test?id='",
            response_body_excerpt=body,
        )
        truncated = ev.to_dict()["response_body_excerpt"]
        full = ev.to_dict(include_full_body=True)["response_body_excerpt"]
        self.assertLessEqual(len(truncated), 600)
        self.assertGreater(len(full), len(truncated))


# ===========================================================================
# DiscoveryScanner _inject_payload isolation
# ===========================================================================


class TestInjectPayloadIsolation(unittest.TestCase):
    """_inject_payload must only modify the targeted location."""

    def setUp(self):
        self.cfg = ScanConfig()
        self.scanner = DiscoveryScanner(
            request_fn=lambda *a, **kw: _safe_response(), config=self.cfg
        )

    def _inject(self, location, name, payload, **kwargs):
        ip = InjectionPoint(name=name, location=location, original_value="original")
        params = kwargs.get("params", {"q": "test"})
        data = kwargs.get("data", {"form": "data"})
        json_data = kwargs.get("json_data", {"key": "val"})
        headers = kwargs.get("headers", {"X-Header": "header_val"})
        cookies = kwargs.get("cookies", {"cookie1": "cookie_val"})
        return self.scanner._inject_payload(ip, payload, params, data, json_data, headers, cookies)

    def test_query_injection_does_not_touch_other_locations(self):
        new_p, new_d, new_j, new_h, new_c = self._inject(
            InjectionLocation.QUERY_PARAM, "q", "' OR 1=1--"
        )
        self.assertEqual(new_p["q"], "' OR 1=1--")
        self.assertEqual(new_d, {"form": "data"})
        self.assertEqual(new_j, {"key": "val"})
        self.assertEqual(new_c, {"cookie1": "cookie_val"})

    def test_form_injection_does_not_touch_query_params(self):
        new_p, new_d, new_j, new_h, new_c = self._inject(
            InjectionLocation.FORM_PARAM, "form", "' OR 1=1--"
        )
        self.assertEqual(new_d["form"], "' OR 1=1--")
        self.assertEqual(new_p, {"q": "test"})
        self.assertEqual(new_j, {"key": "val"})

    def test_json_injection_does_not_touch_query_or_form(self):
        new_p, new_d, new_j, new_h, new_c = self._inject(
            InjectionLocation.JSON_PARAM, "key", "' OR 1=1--"
        )
        self.assertEqual(new_j["key"], "' OR 1=1--")
        self.assertEqual(new_p, {"q": "test"})
        self.assertEqual(new_d, {"form": "data"})

    def test_cookie_injection_does_not_touch_other_locations(self):
        new_p, new_d, new_j, new_h, new_c = self._inject(
            InjectionLocation.COOKIE_PARAM, "cookie1", "' OR 1=1--"
        )
        self.assertEqual(new_c["cookie1"], "' OR 1=1--")
        self.assertEqual(new_p, {"q": "test"})
        self.assertEqual(new_d, {"form": "data"})
        self.assertEqual(new_j, {"key": "val"})

    def test_original_dicts_are_not_mutated(self):
        """_inject_payload must return new dicts, not mutate the originals."""
        params = {"q": "test"}
        data = {"form": "data"}
        ip = InjectionPoint(name="q", location=InjectionLocation.QUERY_PARAM)
        self.scanner._inject_payload(ip, "' OR 1=1--", params, data, {}, {}, {})
        self.assertEqual(params["q"], "test", "Original params dict must not be mutated")
        self.assertEqual(data["form"], "data", "Original data dict must not be mutated")


if __name__ == "__main__":
    unittest.main(verbosity=2)
