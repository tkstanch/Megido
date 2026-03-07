"""
Adaptive Rate Limiter

An intelligent rate limiter that observes HTTP response characteristics and
automatically adjusts request pacing to avoid triggering server-side rate
limiting or WAF blocking.

Usage::

    limiter = AdaptiveRateLimiter(initial_delay=1.0)

    response = requests.get(url)
    limiter.record_response(response.status_code, response_time_s * 1000)
    limiter.wait()  # sleeps for the adaptive delay before the next request
"""

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class AdaptiveRateLimiter:
    """Intelligent rate limiting that adapts to target responses.

    The limiter starts with ``initial_delay`` seconds between requests and
    adjusts the delay based on observed response characteristics:

    - **HTTP 429 (Too Many Requests):** doubles the delay (capped at
      ``max_delay``).
    - **Response time > 5 s:** increases the delay by 50 %.
    - **WAF block (HTTP 403 with WAF-like headers):** triples the delay.
    - **5 consecutive fast 2xx responses:** decreases the delay by 10 %
      (floor at ``min_delay``).

    All adjustments are logged at DEBUG level.
    """

    # WAF-related header names that indicate a block (lowercase)
    _WAF_BLOCK_HEADERS = frozenset([
        'cf-ray',          # Cloudflare
        'x-sucuri-id',     # Sucuri
        'x-iinfo',         # Imperva / Incapsula
        'x-akamai-request-id',  # Akamai
        'x-amzn-requestid',    # AWS WAF
        'x-fastly-request-id', # Fastly
    ])

    def __init__(
        self,
        initial_delay: float = 1.0,
        min_delay: float = 0.1,
        max_delay: float = 30.0,
    ):
        """
        Initialise the adaptive rate limiter.

        Args:
            initial_delay: Starting delay between requests in seconds.
            min_delay: Minimum allowed delay in seconds.
            max_delay: Maximum allowed delay in seconds.
        """
        self._initial_delay = initial_delay
        self._min_delay = min_delay
        self._max_delay = max_delay

        self._current_delay: float = initial_delay
        self._consecutive_ok: int = 0
        self._last_response_headers: dict = {}

        logger.debug(
            "AdaptiveRateLimiter initialised (initial=%.2fs, min=%.2fs, max=%.2fs)",
            initial_delay, min_delay, max_delay,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def wait(self) -> None:
        """Wait before the next request, sleeping for the current adaptive delay.

        This should be called *before* each outgoing request (or after, as a
        post-request pause — either convention is fine as long as it is used
        consistently).
        """
        delay = self._current_delay
        if delay > 0:
            logger.debug("AdaptiveRateLimiter: sleeping %.3fs", delay)
            time.sleep(delay)

    def record_response(
        self,
        status_code: int,
        response_time_ms: float,
        response_headers: Optional[dict] = None,
    ) -> None:
        """Adjust the rate limit based on the observed response.

        Args:
            status_code: HTTP status code of the response.
            response_time_ms: Response time in milliseconds.
            response_headers: Optional response headers dict used to detect WAF
                              blocks on HTTP 403 responses.
        """
        response_headers = response_headers or {}
        response_time_s = response_time_ms / 1000.0

        # --- WAF block: triple the delay ---
        if status_code == 403 and self._looks_like_waf_block(response_headers):
            old = self._current_delay
            self._current_delay = min(self._current_delay * 3.0, self._max_delay)
            self._consecutive_ok = 0
            logger.debug(
                "WAF block detected (403). Delay %.2fs → %.2fs",
                old, self._current_delay,
            )
            return

        # --- Rate limit hit: double the delay ---
        if status_code == 429:
            old = self._current_delay
            self._current_delay = min(self._current_delay * 2.0, self._max_delay)
            self._consecutive_ok = 0
            logger.debug(
                "HTTP 429 received. Delay %.2fs → %.2fs",
                old, self._current_delay,
            )
            return

        # --- Slow response: increase delay by 50 % ---
        if response_time_s > 5.0:
            old = self._current_delay
            self._current_delay = min(self._current_delay * 1.5, self._max_delay)
            self._consecutive_ok = 0
            logger.debug(
                "Slow response (%.1fs > 5s). Delay %.2fs → %.2fs",
                response_time_s, old, self._current_delay,
            )
            return

        # --- Happy path: 2xx with acceptable response time ---
        if 200 <= status_code < 300:
            self._consecutive_ok += 1
            if self._consecutive_ok >= 5:
                old = self._current_delay
                self._current_delay = max(self._current_delay * 0.9, self._min_delay)
                logger.debug(
                    "5 consecutive OK responses. Delay %.2fs → %.2fs",
                    old, self._current_delay,
                )
                self._consecutive_ok = 0  # reset counter after each reduction
        else:
            # Any other non-2xx (4xx, 5xx) resets the consecutive-ok counter
            self._consecutive_ok = 0

    def get_current_delay(self) -> float:
        """Return the current adaptive delay in seconds.

        Returns:
            float: Current delay value.
        """
        return self._current_delay

    def reset(self) -> None:
        """Reset the limiter to its initial state."""
        self._current_delay = self._initial_delay
        self._consecutive_ok = 0
        logger.debug("AdaptiveRateLimiter reset to initial delay %.2fs", self._initial_delay)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _looks_like_waf_block(self, headers: dict) -> bool:
        """Return True if the response headers suggest a WAF-generated block.

        Args:
            headers: Response headers dict (keys compared case-insensitively).

        Returns:
            bool: True if WAF-specific headers are present.
        """
        lowered = {k.lower() for k in headers}
        return bool(lowered & self._WAF_BLOCK_HEADERS)
