"""
Tests for AdaptiveRateLimiter.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scan_plugins.rate_limiter import AdaptiveRateLimiter


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

class TestInitialState:
    def test_initial_delay_set_correctly(self):
        limiter = AdaptiveRateLimiter(initial_delay=2.0)
        assert limiter.get_current_delay() == 2.0

    def test_default_values(self):
        limiter = AdaptiveRateLimiter()
        assert limiter.get_current_delay() == 1.0


# ---------------------------------------------------------------------------
# record_response — 429 handling
# ---------------------------------------------------------------------------

class TestRateLimitResponse:
    def test_429_doubles_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=1.0, max_delay=30.0)
        limiter.record_response(429, 100.0)
        assert limiter.get_current_delay() == 2.0

    def test_429_doubles_again_on_repeat(self):
        limiter = AdaptiveRateLimiter(initial_delay=1.0, max_delay=30.0)
        limiter.record_response(429, 100.0)  # 2.0
        limiter.record_response(429, 100.0)  # 4.0
        assert limiter.get_current_delay() == 4.0

    def test_429_capped_at_max_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=20.0, max_delay=30.0)
        limiter.record_response(429, 100.0)  # 40.0 → capped at 30.0
        assert limiter.get_current_delay() == 30.0


# ---------------------------------------------------------------------------
# record_response — slow response
# ---------------------------------------------------------------------------

class TestSlowResponse:
    def test_slow_response_increases_delay_by_50_percent(self):
        limiter = AdaptiveRateLimiter(initial_delay=2.0, max_delay=30.0)
        limiter.record_response(200, 6000.0)  # > 5s
        assert limiter.get_current_delay() == _approx(3.0)

    def test_fast_response_does_not_increase_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=1.0)
        limiter.record_response(200, 100.0)  # fast
        # Only 1 consecutive OK; delay should stay at 1.0
        assert limiter.get_current_delay() == 1.0


# ---------------------------------------------------------------------------
# record_response — 5 consecutive 200s decrease delay
# ---------------------------------------------------------------------------

class TestConsecutiveSuccesses:
    def test_5_consecutive_200s_decrease_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=2.0, min_delay=0.1)
        for _ in range(5):
            limiter.record_response(200, 100.0)
        assert limiter.get_current_delay() < 2.0

    def test_delay_not_below_min_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=0.1, min_delay=0.1)
        for _ in range(20):
            limiter.record_response(200, 50.0)
        assert limiter.get_current_delay() >= 0.1

    def test_non_2xx_resets_consecutive_counter(self):
        limiter = AdaptiveRateLimiter(initial_delay=1.0)
        for _ in range(4):
            limiter.record_response(200, 100.0)
        limiter.record_response(500, 200.0)  # resets counter
        limiter.record_response(200, 100.0)  # only 1 ok now
        # Should not have decreased (need 5 consecutive)
        assert limiter.get_current_delay() == 1.0


# ---------------------------------------------------------------------------
# WAF block (403 with WAF headers)
# ---------------------------------------------------------------------------

class TestWAFBlock:
    def test_waf_block_triples_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=1.0, max_delay=30.0)
        waf_headers = {'CF-Ray': 'abc123'}
        limiter.record_response(403, 200.0, response_headers=waf_headers)
        assert limiter.get_current_delay() == 3.0

    def test_403_without_waf_headers_not_tripled(self):
        limiter = AdaptiveRateLimiter(initial_delay=1.0, max_delay=30.0)
        limiter.record_response(403, 200.0, response_headers={})
        # 403 without WAF headers just resets consecutive ok counter
        assert limiter.get_current_delay() == 1.0

    def test_waf_block_capped_at_max_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=15.0, max_delay=30.0)
        waf_headers = {'x-sucuri-id': 'abc'}
        limiter.record_response(403, 100.0, response_headers=waf_headers)
        assert limiter.get_current_delay() == 30.0


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_restores_initial_delay(self):
        limiter = AdaptiveRateLimiter(initial_delay=1.0, max_delay=30.0)
        limiter.record_response(429, 100.0)
        assert limiter.get_current_delay() != 1.0
        limiter.reset()
        assert limiter.get_current_delay() == 1.0

    def test_reset_clears_consecutive_counter(self):
        limiter = AdaptiveRateLimiter(initial_delay=2.0)
        for _ in range(4):
            limiter.record_response(200, 100.0)
        limiter.reset()
        # After reset, 4 more OK responses should not reduce delay
        for _ in range(4):
            limiter.record_response(200, 100.0)
        assert limiter.get_current_delay() == 2.0


# ---------------------------------------------------------------------------
# wait() — smoke test (no actual sleep in tests)
# ---------------------------------------------------------------------------

class TestWait:
    def test_wait_does_not_raise(self, monkeypatch):
        import scanner.scan_plugins.rate_limiter as rl_module
        monkeypatch.setattr(rl_module.time, 'sleep', lambda _: None)
        limiter = AdaptiveRateLimiter(initial_delay=1.0)
        limiter.wait()  # should not raise


# ---------------------------------------------------------------------------
# Pytest helper import
# ---------------------------------------------------------------------------

try:
    from pytest import approx as _approx
except ImportError:
    def _approx(val, rel=None, abs=None):  # noqa: F811 — plain equality fallback
        return val
