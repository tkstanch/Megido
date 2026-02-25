"""
Open Redirect Detection Plugin

This plugin detects Open Redirect vulnerabilities where attackers can redirect users
to malicious external sites.

Detection mechanisms:
- HTTP 3xx Location header redirect
- Refresh response header (Refresh: 0; url=...)
- HTML meta refresh tag (<meta http-equiv="refresh" content="0;url=...">)
- JavaScript-based redirects (window.location, location.href, document.location,
  location.replace)

Payload coverage:
- Absolute URLs for external domains
- Scheme-relative URLs (//evil.com)
- URL-encoded variants (/%2F%2Fevil.com)
- Backslash separator (\\evil.com)
- Triple-slash (///evil.com)
- Userinfo-based trick (https://trusted.com@evil.com/)
- javascript: payloads

Parameter coverage:
- Existing URL query parameters
- Common redirect parameter names: next, url, target, redir, redirect, return,
  returnUrl, continue, dest, destination, callback
"""

import logging
import re
from typing import Dict, List, Any, Optional, Set
from urllib.parse import parse_qs, urlparse, urlencode

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# External test domain used across payloads
_TEST_HOST = 'evil.com'

# Common redirect parameter names to probe even when not present in the URL
_COMMON_REDIRECT_PARAMS = [
    'next', 'url', 'target', 'redir', 'redirect', 'return', 'returnUrl',
    'continue', 'dest', 'destination', 'callback',
]

# Payloads – each is a string that should cause a redirect to an external host
_REDIRECT_PAYLOADS = [
    f'http://{_TEST_HOST}',
    f'https://{_TEST_HOST}',
    f'//{_TEST_HOST}',
    f'/{_TEST_HOST}',
    f'/%2F%2F{_TEST_HOST}',
    f'\\\\{_TEST_HOST}',
    f'///{_TEST_HOST}',
    f'https://trusted.com@{_TEST_HOST}/',
    f'javascript:window.location=\'http://{_TEST_HOST}\'',
]

# Regex patterns for JavaScript-based redirects
_JS_REDIRECT_PATTERNS = [
    re.compile(r'window\.location\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'document\.location\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'location\.replace\s*\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    re.compile(r'location\.assign\s*\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
]

# Regex for HTML meta refresh
_META_REFRESH_PATTERN = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+content\s*=\s*["\'][^"\']*url\s*=\s*([^\s"\'>]+)',
    re.IGNORECASE,
)
_META_REFRESH_PATTERN_ALT = re.compile(
    r'<meta[^>]+content\s*=\s*["\'][^"\']*url\s*=\s*([^\s"\'>]+)[^>]+http-equiv\s*=\s*["\']refresh["\']',
    re.IGNORECASE,
)

_REMEDIATION = (
    'Validate redirect URLs against a whitelist of allowed destinations. '
    'Prefer relative URLs for redirects. If absolute URLs are required, '
    'parse and verify that the host matches the application host. '
    'Implement redirect token validation for dynamic redirect destinations. '
    'Avoid reflecting user-supplied URLs directly into redirect sinks.'
)


def _is_external_redirect(target: str, original_host: str) -> bool:
    """
    Return True when *target* resolves to a host that differs from *original_host*.

    Handles absolute, scheme-relative, and common bypass variants.
    """
    target = target.strip()

    # javascript: scheme is always considered an external/dangerous redirect
    if target.lower().startswith('javascript:'):
        return True

    # Triple-slash and backslash variants are always suspicious
    if target.startswith('///') or target.startswith('\\\\') or target.startswith('\\'):
        return True

    # Normalise scheme-relative URLs so urlparse can handle them
    if target.startswith('//'):
        target = 'https:' + target

    try:
        parsed = urlparse(target)
        target_host = parsed.hostname or ''
        if not target_host:
            return False
        # Userinfo-based trick: https://trusted.com@evil.com/
        # urlparse puts the *last* host in hostname, so this is handled naturally.
        return target_host.lower() != original_host.lower()
    except Exception:
        return False


class OpenRedirectDetectorPlugin(BaseScanPlugin):
    """Open Redirect vulnerability detection plugin."""

    @property
    def plugin_id(self) -> str:
        return 'open_redirect_detector'

    @property
    def name(self) -> str:
        return 'Open Redirect Vulnerability Detector'

    @property
    def description(self) -> str:
        return (
            'Detects Open Redirect vulnerabilities via Location headers, '
            'Refresh headers, HTML meta refresh, and JavaScript-based redirects'
        )

    @property
    def version(self) -> str:
        return '2.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['open_redirect']

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """Scan for Open Redirect vulnerabilities."""
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            findings = self._test_open_redirect(url, verify_ssl, timeout)
            logger.info(f"Open Redirect scan of {url} found {len(findings)} vulnerability(ies)")

        except Exception as e:
            logger.error(f"Error during Open Redirect scan: {e}")

        return findings

    def _test_open_redirect(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for open redirect vulnerabilities across all param names and payloads."""
        findings: List[VulnerabilityFinding] = []
        seen: Set[str] = set()  # deduplicate by (param, payload mechanism)

        try:
            parsed = urlparse(url)
            original_host = parsed.hostname or ''
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            existing_params = parse_qs(parsed.query)

            # Build the full set of parameter names to probe
            param_names_to_test: List[str] = list(existing_params.keys())
            for common_param in _COMMON_REDIRECT_PARAMS:
                if common_param not in param_names_to_test:
                    param_names_to_test.append(common_param)

            for param_name in param_names_to_test:
                for payload in _REDIRECT_PAYLOADS:
                    dedup_key = f"{param_name}::{payload}"
                    if dedup_key in seen:
                        continue

                    # Build test params: use existing values, override the target param
                    test_params = {k: v[0] for k, v in existing_params.items()}
                    test_params[param_name] = payload

                    try:
                        response = requests.get(
                            base_url,
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl,
                            allow_redirects=False,
                        )
                    except Exception as e:
                        logger.debug(f"Error testing open redirect param={param_name}: {e}")
                        continue

                    finding = self._analyse_response(
                        response, url, param_name, payload, original_host
                    )
                    if finding:
                        seen.add(dedup_key)
                        findings.append(finding)

        except Exception as e:
            logger.error(f"Error in open redirect testing: {e}")

        return findings

    def _analyse_response(
        self,
        response: 'requests.Response',
        url: str,
        param_name: str,
        payload: str,
        original_host: str,
    ) -> Optional[VulnerabilityFinding]:
        """
        Inspect a response for any open redirect mechanism and return a finding
        if an external redirect is detected.
        """
        # 1. HTTP 3xx Location header
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get('Location', '')
            if location and _is_external_redirect(location, original_host):
                return VulnerabilityFinding(
                    vulnerability_type='open_redirect',
                    severity='medium',
                    url=url,
                    description=f'Open Redirect via Location header in parameter "{param_name}"',
                    evidence=f'Payload: {payload!r} | Response status: {response.status_code} | Location: {location}',
                    remediation=_REMEDIATION,
                    parameter=param_name,
                    confidence=0.9,
                    cwe_id='CWE-601',
                )

        body = response.text or ''

        # 2. Refresh response header (Refresh: 0; url=https://evil.com)
        refresh_header = response.headers.get('Refresh', '')
        if refresh_header:
            refresh_url = self._extract_refresh_url(refresh_header)
            if refresh_url and _is_external_redirect(refresh_url, original_host):
                return VulnerabilityFinding(
                    vulnerability_type='open_redirect',
                    severity='medium',
                    url=url,
                    description=f'Open Redirect via Refresh header in parameter "{param_name}"',
                    evidence=f'Payload: {payload!r} | Refresh header: {refresh_header!r} | Redirect target: {refresh_url}',
                    remediation=_REMEDIATION,
                    parameter=param_name,
                    confidence=0.85,
                    cwe_id='CWE-601',
                )

        # 3. HTML meta refresh
        meta_url = self._extract_meta_refresh_url(body)
        if meta_url and _is_external_redirect(meta_url, original_host):
            return VulnerabilityFinding(
                vulnerability_type='open_redirect',
                severity='medium',
                url=url,
                description=f'Open Redirect via HTML meta refresh in parameter "{param_name}"',
                evidence=f'Payload: {payload!r} | Meta refresh target: {meta_url}',
                remediation=_REMEDIATION,
                parameter=param_name,
                confidence=0.80,
                cwe_id='CWE-601',
            )

        # 4. JavaScript-based redirects
        js_target = self._extract_js_redirect_url(body)
        if js_target and _is_external_redirect(js_target, original_host):
            return VulnerabilityFinding(
                vulnerability_type='open_redirect',
                severity='medium',
                url=url,
                description=f'Open Redirect via JavaScript redirect in parameter "{param_name}"',
                evidence=f'Payload: {payload!r} | JavaScript redirect target: {js_target}',
                remediation=_REMEDIATION,
                parameter=param_name,
                confidence=0.75,
                cwe_id='CWE-601',
            )

        return None

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_refresh_url(header_value: str) -> Optional[str]:
        """
        Extract the URL from a Refresh header value such as
        ``0; url=https://evil.com`` or ``0;URL=https://evil.com``.
        """
        match = re.search(r'url\s*=\s*([^\s,;]+)', header_value, re.IGNORECASE)
        if match:
            return match.group(1).strip('\'"')
        return None

    @staticmethod
    def _extract_meta_refresh_url(body: str) -> Optional[str]:
        """Extract the redirect URL from an HTML meta refresh tag."""
        for pattern in (_META_REFRESH_PATTERN, _META_REFRESH_PATTERN_ALT):
            match = pattern.search(body)
            if match:
                return match.group(1).strip('\'"')
        return None

    @staticmethod
    def _extract_js_redirect_url(body: str) -> Optional[str]:
        """Extract the first JS-based redirect target found in *body*."""
        for pattern in _JS_REDIRECT_PATTERNS:
            match = pattern.search(body)
            if match:
                return match.group(1)
        return None

    def get_default_config(self) -> Dict[str, Any]:
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
