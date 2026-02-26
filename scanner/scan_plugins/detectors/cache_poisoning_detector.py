"""
Web Cache Poisoning Detector Plugin

Tests for web cache poisoning vulnerabilities by injecting values into
unkeyed HTTP headers (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
and checking whether the injected values are reflected in the response,
indicating that the response could be cached and served to other users.

CWE-444 (Inconsistent Interpretation of HTTP Requests)
"""

import logging
import uuid
from typing import Dict, List, Any, Optional, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# Headers commonly excluded from cache keys (unkeyed headers)
_UNKEYED_HEADERS: List[Tuple[str, str]] = [
    ('X-Forwarded-Host', 'evil.com'),
    ('X-Original-URL', '/poisoned-path'),
    ('X-Rewrite-URL', '/poisoned-path'),
    ('X-Forwarded-Scheme', 'https'),
    ('X-Forwarded-Proto', 'https'),
    ('X-Host', 'evil.com'),
    ('X-Forwarded-For', '127.0.0.1'),
]

# Cache-control header values that indicate cacheable responses
_CACHEABLE_CC_VALUES = {'public', 's-maxage', 'max-age'}

_REMEDIATION = (
    "Ensure that all HTTP request headers used in constructing responses are "
    "included in the cache key, or strip them before caching. "
    "Validate and sanitize all proxy/forwarding headers before using them to "
    "construct URLs, host headers, or redirects. "
    "Use a cache-busting mechanism and configure your CDN/proxy to use a "
    "strict cache-key policy that includes relevant headers. "
    "See James Kettle's web cache poisoning research for detailed guidance."
)


class CachePoisoningDetectorPlugin(BaseScanPlugin):
    """
    Web cache poisoning detector plugin.

    Injects unique probe values into headers commonly excluded from cache keys
    and checks whether the injected values appear in the response body or
    redirect headers, indicating that the response could be poisoned.
    """

    @property
    def plugin_id(self) -> str:
        return 'cache_poisoning_detector'

    @property
    def name(self) -> str:
        return 'Web Cache Poisoning Detector'

    @property
    def description(self) -> str:
        return (
            'Detects web cache poisoning vulnerabilities via unkeyed headers '
            '(X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, etc.)'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['cache_poisoning']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for web cache poisoning vulnerabilities.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl      (bool, default False)
                      timeout         (int,  default 10)
                      check_cacheable (bool, default True) – also flag if response
                          is cacheable when injection is detected.

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping cache poisoning scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            # Get a clean baseline
            try:
                baseline = requests.get(url, timeout=timeout, verify=verify_ssl)
                baseline_text = baseline.text
            except Exception as exc:
                logger.error("Baseline request failed for %s: %s", url, exc)
                return findings

            for header_name, default_probe_value in _UNKEYED_HEADERS:
                # Use a unique probe value to distinguish reflection from coincidence
                unique_probe = f"{default_probe_value}-probe-{uuid.uuid4().hex[:8]}"
                finding = self._probe_header(
                    url, header_name, unique_probe,
                    baseline_text, baseline, verify_ssl, timeout, config
                )
                if finding:
                    findings.append(finding)

        except Exception as exc:
            logger.error("Unexpected error during cache poisoning scan of %s: %s", url, exc)

        logger.info("Cache poisoning scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe_header(
        self,
        url: str,
        header_name: str,
        probe_value: str,
        baseline_text: str,
        baseline_response: 'requests.Response',
        verify_ssl: bool,
        timeout: int,
        config: Dict[str, Any],
    ) -> Optional[VulnerabilityFinding]:
        """Inject a unique probe value via an unkeyed header and check for reflection."""
        try:
            response = requests.get(
                url,
                headers={header_name: probe_value},
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except Exception as exc:
            logger.debug("Cache poisoning probe failed (header=%s): %s", header_name, exc)
            return None

        reflected_in_body = probe_value in response.text and probe_value not in baseline_text
        location = response.headers.get('Location', '')
        reflected_in_redirect = probe_value in location

        if not (reflected_in_body or reflected_in_redirect):
            return None

        is_cacheable = self._is_cacheable(response)
        severity = 'high' if is_cacheable else 'medium'

        reflection_location = 'response body' if reflected_in_body else f'Location header ({location!r})'

        description = (
            f'Web cache poisoning vector detected via header "{header_name}". '
            f'Injected probe value "{probe_value}" was reflected in the {reflection_location}.'
        )
        if is_cacheable and config.get('check_cacheable', True):
            description += (
                ' The response appears to be cacheable '
                '(Cache-Control header indicates public caching), '
                'making cache poisoning likely exploitable.'
            )

        return VulnerabilityFinding(
            vulnerability_type='cache_poisoning',
            severity=severity,
            url=url,
            description=description,
            evidence=(
                f'Header: {header_name}: {probe_value!r} | '
                f'Reflected in: {reflection_location} | '
                f'Response status: {response.status_code} | '
                f'Cacheable: {is_cacheable} | '
                f'Cache-Control: {response.headers.get("Cache-Control", "not set")!r}'
            ),
            remediation=_REMEDIATION,
            confidence=0.85,
            cwe_id='CWE-444',
        )

    @staticmethod
    def _is_cacheable(response: 'requests.Response') -> bool:
        """Return True if the response appears to be publicly cacheable."""
        cc = response.headers.get('Cache-Control', '').lower()
        if 'no-store' in cc or 'private' in cc:
            return False
        if any(v in cc for v in _CACHEABLE_CC_VALUES):
            return True
        # Presence of Expires or Age header also indicates cacheability
        if response.headers.get('Expires') or response.headers.get('Age'):
            return True
        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for cache poisoning scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_cacheable': True,
        }
