"""
Safety Guardrails for SQL Injection Testing

Enforces authorization requirements, scope restrictions, and request budgets
to ensure the testing engine is only used for authorized penetration testing.
"""

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class AuthorizationError(Exception):
    """Raised when authorization is not confirmed."""


class ScopeViolationError(Exception):
    """Raised when a target is outside the allowed scope."""


class BudgetExceededError(Exception):
    """Raised when the request budget for a target is exceeded."""


# Private IP ranges that are blocked by default
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private_ip(host: str) -> bool:
    """Return True if *host* resolves to a private/loopback address."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        # Not a bare IP — could be a hostname; treat as not-private
        return False


def check_authorization(authorized: bool) -> None:
    """
    Raise :class:`AuthorizationError` unless *authorized* is explicitly True.

    This is the fail-closed gate: every active test method must call this
    before making any requests.
    """
    if not authorized:
        raise AuthorizationError(
            "Active SQL injection testing requires explicit authorization. "
            "Set authorized=True in your SQLMapConfig or ScanConfig only when "
            "you have written permission to test the target."
        )


def check_scope(url: str, allowed_domains: List[str], block_private_ips: bool = True) -> None:
    """
    Verify that *url* is within the allowed scope.

    Args:
        url: The target URL to check.
        allowed_domains: Allowlisted domain patterns (exact hostnames or
            ``*.example.com`` wildcards).  An empty list means *all public*
            hosts are allowed (private IPs are still blocked unless
            *block_private_ips* is False).
        block_private_ips: When True (default), reject targets whose host is a
            private/loopback IP address.

    Raises:
        ScopeViolationError: When the target is outside the allowed scope or is
            a private IP and *block_private_ips* is True.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if block_private_ips and is_private_ip(host):
        raise ScopeViolationError(
            f"Target host '{host}' is a private IP address. "
            "Explicitly add it to allowed_domains and set block_private_ips=False "
            "if you intentionally want to test an internal host."
        )

    if allowed_domains:
        if not _host_matches_any(host, allowed_domains):
            raise ScopeViolationError(
                f"Target host '{host}' is not in the allowed_domains list: "
                f"{allowed_domains}"
            )


def _host_matches_any(host: str, allowed_domains: List[str]) -> bool:
    """Return True if *host* matches at least one entry in *allowed_domains*."""
    host = host.lower()
    for pattern in allowed_domains:
        pattern = pattern.lower()
        if pattern.startswith("*."):
            suffix = pattern[1:]  # e.g. ".example.com"
            if host.endswith(suffix):
                return True
        else:
            if host == pattern:
                return True
    return False


@dataclass
class BudgetConfig:
    """Request-budget configuration for a single scan session."""

    max_requests_per_target: int = 200
    """Maximum total HTTP requests allowed against any single host."""

    max_concurrent: int = 1
    """Maximum number of concurrent requests (concurrency cap)."""

    request_delay: float = 0.0
    """Minimum delay in seconds between consecutive requests to the same host."""


class RequestBudget:
    """
    Thread-safe per-host request counter and rate limiter.

    Usage::

        budget = RequestBudget(BudgetConfig(max_requests_per_target=50))
        budget.charge("example.com")   # call before each request
    """

    def __init__(self, config: Optional[BudgetConfig] = None) -> None:
        self._config = config or BudgetConfig()
        self._counts: Dict[str, int] = {}
        self._last_request: Dict[str, float] = {}
        self._lock = threading.Lock()

    def charge(self, host: str) -> None:
        """
        Record one request against *host*.

        Enforces the per-host request cap and minimum inter-request delay.

        Raises:
            BudgetExceededError: If the host has reached its request cap.
        """
        with self._lock:
            count = self._counts.get(host, 0)
            if count >= self._config.max_requests_per_target:
                raise BudgetExceededError(
                    f"Request budget for '{host}' exhausted "
                    f"(limit={self._config.max_requests_per_target}). "
                    "Increase max_requests_per_target if this is intentional."
                )
            # Enforce per-host rate limit
            if self._config.request_delay > 0:
                last = self._last_request.get(host, 0.0)
                elapsed = time.monotonic() - last
                if elapsed < self._config.request_delay:
                    time.sleep(self._config.request_delay - elapsed)

            self._counts[host] = count + 1
            self._last_request[host] = time.monotonic()

    def get_count(self, host: str) -> int:
        """Return the number of requests made to *host* so far."""
        with self._lock:
            return self._counts.get(host, 0)

    def reset(self, host: Optional[str] = None) -> None:
        """Reset counters (all hosts if *host* is None, otherwise just *host*)."""
        with self._lock:
            if host is None:
                self._counts.clear()
                self._last_request.clear()
            else:
                self._counts.pop(host, None)
                self._last_request.pop(host, None)
