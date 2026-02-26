"""
Scan Profiles System

Pre-defined scan configurations that control which plugins are enabled,
concurrency settings, and scan behaviour.

Available profiles:

* ``quick``       — Security headers + SSL + CORS only (fast, low noise).
* ``standard``    — All passive detectors.
* ``full``        — All detectors including active injection tests.
* ``api``         — Focus on GraphQL, JWT, CORS, IDOR, auth-related plugins.
* ``owasp_top10`` — Plugins mapped to OWASP Top 10 categories.
* ``stealth``     — Enable stealth/evasion features with rate limiting.

Usage::

    from scanner.scan_profiles import get_profile, PROFILES

    config = get_profile('full')
    # config is a dict ready to pass to the scan engine
"""

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

# Shared defaults applied to every profile before profile-specific overrides
_DEFAULTS: Dict[str, Any] = {
    'verify_ssl': False,
    'timeout': 15,
    'active_scan': False,
    'enable_stealth': False,
    'max_payloads': 5,
    'max_concurrent_plugins': 5,
    'max_concurrent_requests': 10,
}

PROFILES: Dict[str, Dict[str, Any]] = {
    # ------------------------------------------------------------------
    # Quick scan: passive checks only — no injection, very fast
    # ------------------------------------------------------------------
    'quick': {
        'description': 'Fast passive scan: security headers, SSL/TLS, and CORS only.',
        'enabled_plugins': [
            'security_headers_scanner',
            'ssl_scanner',
            'cors_scanner',
        ],
        'timeout': 10,
        'max_concurrent_plugins': 3,
    },

    # ------------------------------------------------------------------
    # Standard scan: all passive detectors
    # ------------------------------------------------------------------
    'standard': {
        'description': 'All passive detectors — no active injection tests.',
        'enabled_plugins': [
            'security_headers_scanner',
            'ssl_scanner',
            'cors_scanner',
            'csrf_scanner',
            'clickjacking_detector',
            'cookie_security_scanner',
            'info_disclosure_detector',
            'javascript_hijacking_detector',
            'sensitive_data_scanner',
            'session_fixation_detector',
            'xss_scanner',
            'xxe_detector',
            'ssrf_detector',
            'graphql_scanner',
            'jwt_scanner',
            'websocket_scanner',
        ],
        'active_scan': False,
        'timeout': 15,
    },

    # ------------------------------------------------------------------
    # Full scan: all detectors including active injection tests
    # ------------------------------------------------------------------
    'full': {
        'description': (
            'All detectors including active injection tests. '
            'May generate significant traffic to the target.'
        ),
        'enabled_plugins': None,  # None = run ALL registered plugins
        'active_scan': True,
        'max_payloads': 15,
        'timeout': 20,
        'max_concurrent_plugins': 8,
    },

    # ------------------------------------------------------------------
    # API scan: focus on API/auth-related checks
    # ------------------------------------------------------------------
    'api': {
        'description': 'API-focused scan: GraphQL, JWT, CORS, IDOR, and auth.',
        'enabled_plugins': [
            'graphql_scanner',
            'jwt_scanner',
            'cors_scanner',
            'idor_detector',
            'ssrf_detector',
            'crlf_detector',
            'host_header_detector',
            'cache_poisoning_detector',
        ],
        'active_scan': True,
        'max_payloads': 10,
        'timeout': 15,
    },

    # ------------------------------------------------------------------
    # OWASP Top 10 scan
    # ------------------------------------------------------------------
    'owasp_top10': {
        'description': 'Plugins mapped to OWASP Top 10 (2021) categories.',
        'enabled_plugins': [
            # A01 - Broken Access Control
            'idor_detector',
            'cors_scanner',
            # A02 - Cryptographic Failures
            'ssl_scanner',
            'sensitive_data_scanner',
            # A03 - Injection
            'xss_scanner',
            'sqli_scanner',
            'xxe_detector',
            'crlf_detector',
            # A04 - Insecure Design (covered by multiple detectors)
            'csrf_scanner',
            # A05 - Security Misconfiguration
            'security_headers_scanner',
            'cors_scanner',
            'info_disclosure_detector',
            # A06 - Vulnerable and Outdated Components
            # (covered by engine plugins / SCA)
            # A07 - Identification and Authentication Failures
            'jwt_scanner',
            'session_fixation_detector',
            'cookie_security_scanner',
            # A08 - Software and Data Integrity Failures
            'deserialization_detector',
            # A09 - Security Logging and Monitoring Failures
            # (out of scope for DAST)
            # A10 - Server-Side Request Forgery
            'ssrf_detector',
            'open_redirect_detector',
            'host_header_detector',
        ],
        'active_scan': True,
        'max_payloads': 10,
        'timeout': 20,
    },

    # ------------------------------------------------------------------
    # Stealth scan: evasion features enabled
    # ------------------------------------------------------------------
    'stealth': {
        'description': (
            'All detectors with stealth/evasion features: randomised delays, '
            'user-agent rotation, rate limiting.'
        ),
        'enabled_plugins': None,  # All plugins
        'active_scan': True,
        'max_payloads': 10,
        'enable_stealth': True,
        'stealth_delay_min': 1.0,
        'stealth_delay_max': 3.0,
        'timeout': 25,
        'max_concurrent_plugins': 2,  # Low concurrency to avoid detection
    },
}

# OWASP category annotations (informational — used in reports)
OWASP_MAPPING: Dict[str, List[str]] = {
    'xss_scanner': ['A03:2021 – Injection'],
    'sqli_scanner': ['A03:2021 – Injection'],
    'xxe_detector': ['A03:2021 – Injection'],
    'crlf_detector': ['A03:2021 – Injection'],
    'ssrf_detector': ['A10:2021 – SSRF'],
    'idor_detector': ['A01:2021 – Broken Access Control'],
    'cors_scanner': ['A01:2021 – Broken Access Control', 'A05:2021 – Security Misconfiguration'],
    'csrf_scanner': ['A01:2021 – Broken Access Control'],
    'jwt_scanner': ['A07:2021 – Identification and Authentication Failures'],
    'ssl_scanner': ['A02:2021 – Cryptographic Failures'],
    'security_headers_scanner': ['A05:2021 – Security Misconfiguration'],
    'clickjacking_detector': ['A05:2021 – Security Misconfiguration'],
    'deserialization_detector': ['A08:2021 – Software and Data Integrity Failures'],
    'host_header_detector': ['A05:2021 – Security Misconfiguration'],
    'cache_poisoning_detector': ['A05:2021 – Security Misconfiguration'],
    'graphql_scanner': ['A05:2021 – Security Misconfiguration'],
    'websocket_scanner': ['A01:2021 – Broken Access Control'],
    'open_redirect_detector': ['A01:2021 – Broken Access Control'],
    'smuggling_detector': ['A05:2021 – Security Misconfiguration'],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_profile(name: str) -> Dict[str, Any]:
    """
    Return a resolved configuration dict for the named profile.

    The returned dict merges global defaults with profile-specific overrides
    and is ready to be passed directly to the scan engine or AsyncScanEngine.

    Args:
        name: Profile name — one of ``quick``, ``standard``, ``full``,
              ``api``, ``owasp_top10``, ``stealth``.

    Returns:
        Merged configuration dict.

    Raises:
        ValueError: If the profile name is unknown.
    """
    if name not in PROFILES:
        raise ValueError(
            f"Unknown scan profile '{name}'. "
            f"Available profiles: {list(PROFILES.keys())}"
        )
    config = dict(_DEFAULTS)
    config.update(PROFILES[name])
    config['profile_name'] = name
    return config


def list_profiles() -> List[Dict[str, Any]]:
    """
    Return a list of profile summaries (name + description).

    Returns:
        List of dicts with ``name`` and ``description`` keys.
    """
    return [
        {'name': name, 'description': profile.get('description', '')}
        for name, profile in PROFILES.items()
    ]


def get_owasp_categories(plugin_id: str) -> List[str]:
    """
    Return the OWASP Top 10 categories associated with a plugin.

    Args:
        plugin_id: Plugin identifier string.

    Returns:
        List of OWASP category strings, or empty list if not mapped.
    """
    return OWASP_MAPPING.get(plugin_id, [])
