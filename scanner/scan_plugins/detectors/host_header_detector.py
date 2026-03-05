"""
Host Header Injection Detector Plugin

Detects Host header injection vulnerabilities by sending requests with
manipulated Host header values and checking whether the injected value
is reflected in the response body or redirect Location headers.

Also tests for web cache poisoning via host header manipulation and
password reset poisoning in account-recovery flows.

CWE-644 (Improper Neutralization of HTTP Headers for Scripting Syntax)
"""

import logging
import re
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# Malicious Host header values to test
_PROBE_HOSTS = [
    'evil.com',
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'attacker.evil.com',
]

# Additional headers used in some frameworks/proxies
_OVERRIDE_HEADERS = [
    'X-Forwarded-Host',
    'X-Host',
    'X-Forwarded-Server',
    'X-HTTP-Host-Override',
]

# Common password-reset / account-recovery URL path patterns
_RESET_PATHS = [
    '/forgot',
    '/forgot-password',
    '/forgot_password',
    '/reset',
    '/reset-password',
    '/reset_password',
    '/password/reset',
    '/password/forgot',
    '/account/recover',
    '/account/reset',
    '/recover',
    '/auth/reset',
    '/users/password',
]

# HTML patterns that indicate a password-reset form or page
_RESET_FORM_PATTERNS = [
    r'<form[^>]*action=[^>]*(reset|forgot|recover|password)[^>]*>',
    r'<input[^>]*name=["\']?(email|username)["\']?[^>]*>',
    r'(forgot|reset|recover).{0,30}password',
    r'password.{0,30}(forgot|reset|recover)',
    r'send.{0,20}(reset|recovery).{0,20}(link|email|token)',
]

_REMEDIATION = (
    "Validate the Host header against a strict allowlist of expected hostnames. "
    "Do not use the Host header value to construct absolute URLs or redirects "
    "without first validating it. Configure your web server and application to "
    "reject requests with unexpected Host headers. Use a reverse proxy that "
    "enforces the correct Host header."
)


class HostHeaderDetectorPlugin(BaseScanPlugin):
    """
    Host header injection detection plugin.

    Sends requests with manipulated Host headers and X-Forwarded-Host headers,
    then inspects the response for reflection of the injected host value.
    """

    @property
    def plugin_id(self) -> str:
        return 'host_header_detector'

    @property
    def name(self) -> str:
        return 'Host Header Injection Detector'

    @property
    def description(self) -> str:
        return (
            'Detects Host header injection vulnerabilities including response body '
            'reflection, redirect manipulation, and web cache poisoning vectors'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['host_header']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for Host header injection vulnerabilities.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl       (bool, default False)
                      timeout          (int,  default 10)
                      probe_hosts      (list) – additional host values to probe
                      test_x_forwarded (bool, default True) – also test override headers

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping Host header scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            extra_hosts = config.get('probe_hosts', [])
            probe_hosts = list(_PROBE_HOSTS) + list(extra_hosts)

            # Get a baseline response with the original Host header
            try:
                baseline = requests.get(url, timeout=timeout, verify=verify_ssl)
                baseline_text = baseline.text
            except Exception as exc:
                logger.error("Baseline request failed for %s: %s", url, exc)
                return findings

            # Test Host header directly
            for host in probe_hosts:
                finding = self._probe_host_header(
                    url, host, baseline_text, verify_ssl, timeout
                )
                if finding:
                    findings.append(finding)

            # Test X-Forwarded-Host and similar override headers
            if config.get('test_x_forwarded', True):
                for override_header in _OVERRIDE_HEADERS:
                    for host in probe_hosts[:2]:  # test first two probe hosts
                        finding = self._probe_override_header(
                            url, override_header, host, baseline_text, verify_ssl, timeout
                        )
                        if finding:
                            findings.append(finding)

        except Exception as exc:
            logger.error("Unexpected error during Host header scan of %s: %s", url, exc)

        # Deduplicate
        seen: set = set()
        unique: List[VulnerabilityFinding] = []
        for f in findings:
            key = (f.description[:80], f.url)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        logger.info("Host header scan of %s – %d finding(s)", url, len(unique))
        return unique

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe_host_header(
        self,
        url: str,
        probe_host: str,
        baseline_text: str,
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Send a request with a manipulated Host header and check for reflection."""
        try:
            response = requests.get(
                url,
                headers={'Host': probe_host},
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except Exception as exc:
            logger.debug("Host header probe failed (host=%s): %s", probe_host, exc)
            return None

        # Check reflection in response body
        if probe_host in response.text and probe_host not in baseline_text:
            # First, try to confirm a high-impact password-reset poisoning scenario
            reset_finding = self._check_password_reset_poisoning(
                url, probe_host, verify_ssl, timeout
            )
            if reset_finding:
                return reset_finding

            # Check if the current page itself is a reset page
            if self._is_reset_page(url, response.text):
                return VulnerabilityFinding(
                    vulnerability_type='host_header',
                    severity='high',
                    url=url,
                    description=(
                        f'Host header injection — password reset poisoning: '
                        f'injected host "{probe_host}" is reflected on a '
                        f'password-reset page. '
                        'Attack scenario: An attacker can poison password-reset '
                        'emails so that reset links point to the attacker\'s domain, '
                        'allowing credential theft.'
                    ),
                    evidence=(
                        f'Probe Host: {probe_host!r} | '
                        f'Response status: {response.status_code} | '
                        f'Host value reflected on reset page | '
                        f'bounty_eligible: true'
                    ),
                    remediation=_REMEDIATION,
                    confidence=0.90,
                    cwe_id='CWE-644',
                    verified=True,
                )

            # Generic body reflection only — no confirmed exploitable impact
            return VulnerabilityFinding(
                vulnerability_type='host_header',
                severity='info',
                url=url,
                description=(
                    f'Host header injection: injected host "{probe_host}" is '
                    'reflected in the response body, but no exploitable impact '
                    '(e.g. password-reset poisoning) was confirmed. '
                    'Attack scenario: Reflection alone may enable cache-poisoning '
                    'or open-redirect attacks depending on application context, '
                    'but further manual investigation is required.'
                ),
                evidence=(
                    f'Probe Host: {probe_host!r} | '
                    f'Response status: {response.status_code} | '
                    f'Host value found in response body | '
                    f'impact_verified: false | bounty_eligible: false'
                ),
                remediation=_REMEDIATION,
                confidence=0.40,
                cwe_id='CWE-644',
                verified=False,
            )

        # Check reflection in Location redirect header
        location = response.headers.get('Location', '')
        if probe_host in location:
            return VulnerabilityFinding(
                vulnerability_type='host_header',
                severity='high',
                url=url,
                description=(
                    f'Host header injection: injected host "{probe_host}" '
                    f'appears in the redirect Location header: {location!r}. '
                    'Attack scenario: An attacker can redirect users to an '
                    'attacker-controlled domain by manipulating the Host header, '
                    'enabling phishing or credential theft.'
                ),
                evidence=(
                    f'Probe Host: {probe_host!r} | '
                    f'Response status: {response.status_code} | '
                    f'Location: {location!r} | '
                    f'bounty_eligible: true'
                ),
                remediation=_REMEDIATION,
                confidence=0.90,
                cwe_id='CWE-644',
                verified=True,
            )

        return None

    def _probe_override_header(
        self,
        url: str,
        override_header: str,
        probe_host: str,
        baseline_text: str,
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Send a request with an X-Forwarded-Host / override header and check reflection."""
        try:
            response = requests.get(
                url,
                headers={override_header: probe_host},
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except Exception as exc:
            logger.debug(
                "Override header probe failed (header=%s, host=%s): %s",
                override_header, probe_host, exc
            )
            return None

        if probe_host in response.text and probe_host not in baseline_text:
            return VulnerabilityFinding(
                vulnerability_type='host_header',
                severity='medium',
                url=url,
                description=(
                    f'Host override header injection via "{override_header}": '
                    f'injected host "{probe_host}" is reflected in the response body. '
                    'Attack scenario: This may be exploitable for web cache poisoning — '
                    'an attacker can poison the cache with a response containing the '
                    'attacker-controlled host, affecting subsequent users who receive '
                    'the cached response.'
                ),
                evidence=(
                    f'Header: {override_header}: {probe_host!r} | '
                    f'Response status: {response.status_code} | '
                    f'Host value found in response body | '
                    f'bounty_eligible: true'
                ),
                remediation=_REMEDIATION,
                confidence=0.75,
                cwe_id='CWE-644',
            )

        return None

    def _is_reset_page(self, url: str, body: str) -> bool:
        """Return True if the URL path or page body indicates a password-reset flow."""
        url_lower = url.lower()
        for path in _RESET_PATHS:
            if path in url_lower:
                return True
        for pattern in _RESET_FORM_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def _check_password_reset_poisoning(
        self,
        url: str,
        probe_host: str,
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """
        Request common password-reset endpoints with the injected Host header and
        check whether the attacker-controlled host appears in any response —
        simulating password-reset link poisoning.
        """
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _RESET_PATHS:
            reset_url = base + path
            try:
                response = requests.get(
                    reset_url,
                    headers={'Host': probe_host},
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True,
                )
            except Exception:
                continue

            if response.status_code in (200, 302) and probe_host in response.text:
                return VulnerabilityFinding(
                    vulnerability_type='host_header',
                    severity='high',
                    url=reset_url,
                    description=(
                        f'Host header injection — password reset poisoning confirmed: '
                        f'injected host "{probe_host}" appears in the password-reset '
                        f'response at {reset_url}. '
                        'Attack scenario: An attacker sends the victim a password-reset '
                        'email whose reset link points to the attacker\'s domain, '
                        'allowing credential theft when the victim clicks the link.'
                    ),
                    evidence=(
                        f'Reset endpoint: {reset_url} | '
                        f'Injected Host: {probe_host!r} | '
                        f'Attacker host found in response body | '
                        f'bounty_eligible: true'
                    ),
                    remediation=_REMEDIATION,
                    confidence=0.95,
                    cwe_id='CWE-644',
                    verified=True,
                )
        return None

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for Host header injection scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'probe_hosts': [],
            'test_x_forwarded': True,
        }
