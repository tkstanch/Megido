#!/usr/bin/env python3
"""
Tests for safety guardrails, response normalisation, and confidence scoring.
"""

import sys
import os
import time
import threading
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.guardrails import (
    AuthorizationError,
    BudgetConfig,
    BudgetExceededError,
    RequestBudget,
    ScopeViolationError,
    check_authorization,
    check_scope,
    is_private_ip,
    _host_matches_any,
)
from sql_attacker.response_normalizer import (
    MIN_CORROBORATING_SIGNALS,
    Signal,
    compute_confidence,
    confirm_time_based,
    diff_responses,
    normalize_response,
)
from sql_attacker.sqlmap_integration import (
    HTTPRequest,
    SQLMapAttacker,
    SQLMapConfig,
    create_attacker,
)


# ---------------------------------------------------------------------------
# Guardrail tests
# ---------------------------------------------------------------------------

class TestAuthorization(unittest.TestCase):
    """Tests for the authorization fail-closed gate."""

    def test_raises_when_not_authorized(self):
        """check_authorization must raise when authorized=False."""
        with self.assertRaises(AuthorizationError):
            check_authorization(False)

    def test_passes_when_authorized(self):
        """check_authorization must not raise when authorized=True."""
        check_authorization(True)  # Should not raise

    def test_sqlmap_config_defaults_to_not_authorized(self):
        """SQLMapConfig.authorized must default to False (fail-closed)."""
        config = SQLMapConfig()
        self.assertFalse(config.authorized)

    def test_test_injection_raises_without_authorization(self):
        """test_injection must raise AuthorizationError when not authorized."""
        config = SQLMapConfig(authorized=False)
        attacker = SQLMapAttacker(config=config)
        request = HTTPRequest(url="http://example.com/test?id=1")
        with self.assertRaises(AuthorizationError):
            attacker.test_injection(request)

    def test_test_injection_passes_with_authorization(self):
        """test_injection must pass the auth check when authorized=True."""
        config = SQLMapConfig(
            authorized=True,
            allowed_domains=["example.com"],
        )
        attacker = SQLMapAttacker(config=config)
        request = HTTPRequest(url="http://example.com/test?id=1")
        # Mock sqlmap execution so no real subprocess is spawned
        with patch.object(attacker, "_execute_sqlmap", return_value=(0, "", "")):
            result = attacker.test_injection(request)
        self.assertIsNotNone(result)

    def test_orchestrate_attack_raises_without_authorization(self):
        """orchestrate_attack must raise AuthorizationError when not authorized."""
        config = SQLMapConfig(authorized=False)
        attacker = SQLMapAttacker(config=config)
        request = HTTPRequest(url="http://example.com/test?id=1")
        with self.assertRaises(AuthorizationError):
            attacker.orchestrate_attack(request)

    def test_create_attacker_authorized_flag(self):
        """create_attacker must pass the authorized flag to config."""
        attacker = create_attacker(authorized=True, allowed_domains=["example.com"])
        self.assertTrue(attacker.config.authorized)


# ---------------------------------------------------------------------------
# Scope tests
# ---------------------------------------------------------------------------

class TestScopeAllowlisting(unittest.TestCase):
    """Tests for domain/IP scope enforcement."""

    def test_private_ip_is_detected(self):
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))

    def test_public_ip_is_not_private(self):
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("93.184.216.34"))  # example.com

    def test_hostname_is_not_flagged_as_private(self):
        """Hostnames (not raw IPs) should return False from is_private_ip."""
        self.assertFalse(is_private_ip("example.com"))
        self.assertFalse(is_private_ip("internal.corp"))

    def test_block_private_ip_by_default(self):
        """check_scope raises when target is a private IP and block_private_ips=True."""
        with self.assertRaises(ScopeViolationError):
            check_scope("http://192.168.1.1/page", allowed_domains=[], block_private_ips=True)

    def test_allow_private_ip_when_explicitly_allowlisted(self):
        """Private IPs should be reachable when block_private_ips=False."""
        check_scope(
            "http://192.168.1.1/page",
            allowed_domains=["192.168.1.1"],
            block_private_ips=False,
        )

    def test_empty_allowed_domains_permits_public_host(self):
        """Empty allowed_domains list should permit any public host."""
        check_scope("http://example.com/page", allowed_domains=[], block_private_ips=True)

    def test_host_blocked_when_not_in_allowlist(self):
        """When allowed_domains is set, unlisted hosts must be blocked."""
        with self.assertRaises(ScopeViolationError):
            check_scope(
                "http://evil.com/page",
                allowed_domains=["example.com"],
                block_private_ips=True,
            )

    def test_exact_domain_match(self):
        """Exact hostname in allowed_domains permits the host."""
        check_scope("http://example.com/page", allowed_domains=["example.com"])

    def test_wildcard_domain_match(self):
        """Wildcard entries like *.example.com should match subdomains."""
        check_scope("http://sub.example.com/page", allowed_domains=["*.example.com"])

    def test_wildcard_does_not_match_parent(self):
        """*.example.com should not match example.com or unrelated hosts."""
        for host in ["http://attacker.com/page", "http://example.com/page"]:
            with self.assertRaises(ScopeViolationError):
                check_scope(host, allowed_domains=["*.example.com"])

    def test_host_matches_any_case_insensitive(self):
        self.assertTrue(_host_matches_any("Example.COM", ["example.com"]))
        self.assertTrue(_host_matches_any("Sub.Example.Com", ["*.example.com"]))


# ---------------------------------------------------------------------------
# Request budget tests
# ---------------------------------------------------------------------------

class TestRequestBudget(unittest.TestCase):
    """Tests for per-host request budget enforcement."""

    def test_budget_charges_correctly(self):
        budget = RequestBudget(BudgetConfig(max_requests_per_target=5))
        for _ in range(5):
            budget.charge("example.com")
        self.assertEqual(budget.get_count("example.com"), 5)

    def test_budget_exceeded_raises(self):
        budget = RequestBudget(BudgetConfig(max_requests_per_target=2))
        budget.charge("example.com")
        budget.charge("example.com")
        with self.assertRaises(BudgetExceededError):
            budget.charge("example.com")

    def test_budget_independent_per_host(self):
        budget = RequestBudget(BudgetConfig(max_requests_per_target=1))
        budget.charge("a.com")
        budget.charge("b.com")  # Should not raise – different host
        with self.assertRaises(BudgetExceededError):
            budget.charge("a.com")  # a.com is now at limit

    def test_budget_reset(self):
        budget = RequestBudget(BudgetConfig(max_requests_per_target=1))
        budget.charge("example.com")
        budget.reset("example.com")
        budget.charge("example.com")  # Should not raise after reset

    def test_budget_rate_limit_enforced(self):
        """Verify that request_delay introduces a measurable pause."""
        delay = 0.1
        budget = RequestBudget(BudgetConfig(request_delay=delay))
        budget.charge("example.com")  # First request – no delay
        t0 = time.monotonic()
        budget.charge("example.com")  # Second request – should wait
        elapsed = time.monotonic() - t0
        self.assertGreaterEqual(elapsed, delay * 0.8)  # 20% tolerance

    def test_sqlmap_config_budget_defaults(self):
        config = SQLMapConfig()
        self.assertIsNotNone(config.budget)
        self.assertGreater(config.budget.max_requests_per_target, 0)

    def test_sqlmap_attacker_respects_budget(self):
        """SQLMapAttacker._check_guardrails charges the budget."""
        config = SQLMapConfig(
            authorized=True,
            allowed_domains=["example.com"],
            budget=BudgetConfig(max_requests_per_target=1),
        )
        attacker = SQLMapAttacker(config=config)
        request = HTTPRequest(url="http://example.com/test?id=1")
        with patch.object(attacker, "_execute_sqlmap", return_value=(0, "", "")):
            attacker.test_injection(request)
        # Second call should exhaust the budget
        with self.assertRaises(BudgetExceededError):
            attacker.test_injection(request)


# ---------------------------------------------------------------------------
# Response normalisation tests
# ---------------------------------------------------------------------------

class TestResponseNormalization(unittest.TestCase):
    """Tests for the normalize_response utility."""

    def test_timestamp_replaced(self):
        text = "Request at 2024-01-15T12:34:56Z completed."
        normalized = normalize_response(text)
        self.assertNotIn("2024-01-15", normalized)
        self.assertIn("<TIMESTAMP>", normalized)

    def test_uuid_replaced(self):
        text = "Session: 550e8400-e29b-41d4-a716-446655440000"
        normalized = normalize_response(text)
        self.assertNotIn("550e8400", normalized)
        self.assertIn("<UUID>", normalized)

    def test_same_text_after_normalization_matches(self):
        """Two identical responses should remain identical after normalisation."""
        text = "Hello world"
        self.assertEqual(normalize_response(text), normalize_response(text))

    def test_volatile_tokens_stripped_for_comparison(self):
        """Two responses that differ only by timestamp should look the same."""
        r1 = "Result at 2024-01-01T00:00:00Z: OK"
        r2 = "Result at 2024-12-31T23:59:59Z: OK"
        self.assertEqual(normalize_response(r1), normalize_response(r2))


# ---------------------------------------------------------------------------
# Response diffing tests
# ---------------------------------------------------------------------------

class TestResponseDiff(unittest.TestCase):
    """Tests for diff_responses utility."""

    def test_identical_responses_not_changed(self):
        info = diff_responses("Hello world", "Hello world")
        self.assertFalse(info["changed"])
        self.assertAlmostEqual(info["ratio"], 1.0, places=2)

    def test_different_responses_flagged(self):
        info = diff_responses("Hello world", "Something completely different xyz")
        self.assertTrue(info["changed"])
        self.assertLess(info["ratio"], 0.98)

    def test_length_delta_computed(self):
        info = diff_responses("abc", "abcdef")
        self.assertEqual(info["length_delta"], 3)

    def test_volatile_tokens_ignored_in_diff(self):
        """Responses differing only in timestamp should be treated as identical."""
        r1 = "Data: value token=2024-01-01T00:00:00Z"
        r2 = "Data: value token=2025-06-15T10:20:30Z"
        info = diff_responses(r1, r2)
        self.assertFalse(info["changed"])


# ---------------------------------------------------------------------------
# Confidence scoring tests
# ---------------------------------------------------------------------------

class TestConfidenceScoring(unittest.TestCase):
    """Tests for compute_confidence."""

    def test_no_signals_returns_uncertain(self):
        score, verdict = compute_confidence([])
        self.assertEqual(score, 0.0)
        self.assertEqual(verdict, "uncertain")

    def test_single_weak_signal_is_uncertain(self):
        # An unrecognised signal name gets a default weight of 0.3 → score=0.3 < 0.5 → "uncertain"
        score, verdict = compute_confidence(["unknown_weak_signal"])
        self.assertEqual(verdict, "uncertain")

    def test_two_strong_signals_confirmed(self):
        score, verdict = compute_confidence([Signal.SQL_ERROR, Signal.BOOLEAN_DIFF])
        self.assertEqual(verdict, "confirmed")
        self.assertGreaterEqual(score, 0.7)

    def test_requires_min_corroborating_signals(self):
        """Only one signal should not yield 'confirmed'."""
        score, verdict = compute_confidence([Signal.SQL_ERROR])
        # One signal, however strong, must not be 'confirmed'
        self.assertNotEqual(verdict, "confirmed")

    def test_duplicate_signals_deduplicated(self):
        """Duplicate signal names count only once."""
        score1, _ = compute_confidence([Signal.SQL_ERROR])
        score2, _ = compute_confidence([Signal.SQL_ERROR, Signal.SQL_ERROR])
        self.assertAlmostEqual(score1, score2, places=4)

    def test_min_corroborating_signals_constant(self):
        self.assertGreaterEqual(MIN_CORROBORATING_SIGNALS, 2)


# ---------------------------------------------------------------------------
# Time-based confirmation tests
# ---------------------------------------------------------------------------

class TestTimeBasedConfirmation(unittest.TestCase):
    """Tests for confirm_time_based."""

    def test_slow_probe_confirmed(self):
        """A probe that consistently takes longer than the threshold is confirmed."""

        def slow_probe():
            time.sleep(0.15)

        result = confirm_time_based(slow_probe, sleep_seconds=0.1, retries=3, tolerance=0.8)
        self.assertTrue(result)

    def test_fast_probe_not_confirmed(self):
        """A probe that returns immediately (no delay) is not confirmed."""

        def fast_probe():
            pass  # No sleep

        result = confirm_time_based(fast_probe, sleep_seconds=5.0, retries=3, tolerance=0.8)
        self.assertFalse(result)

    def test_flaky_probe_requires_majority(self):
        """Confirm when majority (≥ ceil(retries/2)) of probes show the delay."""
        call_count = [0]

        def sometimes_slow():
            call_count[0] += 1
            if call_count[0] % 2 == 1:  # Odd calls are slow
                time.sleep(0.15)

        result = confirm_time_based(
            sometimes_slow, sleep_seconds=0.1, retries=4, tolerance=0.8
        )
        # 2 out of 4 calls are slow; ceil(4/2)=2, so should confirm
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
