"""
WebSocket Scanner Plugin

Detects WebSocket endpoints by scanning HTML for websocket upgrade references,
and tests for Cross-Site WebSocket Hijacking (CSWSH) by checking whether
WebSocket connections lack proper authentication or Origin validation.

CWE-1385 (Missing Origin Validation in WebSockets)
"""

import logging
import re
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse, urljoin

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# Patterns for detecting WebSocket usage in HTML/JS
_WS_URL_PATTERN = re.compile(r'(wss?://[^\s\'"<>]+)', re.IGNORECASE)
_WS_CONSTRUCTOR_PATTERN = re.compile(
    r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE
)
_WS_UPGRADE_PATTERN = re.compile(
    r'[\'"]upgrade[\'"]\s*:\s*[\'"]websocket[\'"]', re.IGNORECASE
)

_REMEDIATION_CSWSH = (
    "Protect WebSocket connections against Cross-Site WebSocket Hijacking: "
    "1. Validate the Origin header on the server-side WebSocket handshake and "
    "reject connections from unexpected origins. "
    "2. Use CSRF tokens or other authentication in the WebSocket handshake. "
    "3. Require authentication cookies to have the SameSite attribute. "
    "See OWASP WebSocket Security Cheat Sheet for full guidance."
)

_REMEDIATION_WS_DETECTED = (
    "Ensure all WebSocket endpoints enforce authentication and authorisation. "
    "Validate the Origin header and require valid session credentials during "
    "the WebSocket handshake. Use wss:// (TLS) for all WebSocket connections."
)


class WebSocketScannerPlugin(BaseScanPlugin):
    """
    WebSocket security scanner plugin.

    Detects WebSocket endpoints referenced in the target page and checks for
    Cross-Site WebSocket Hijacking (CSWSH) indicators by analysing whether
    the HTTP upgrade endpoint accepts connections from arbitrary origins.
    """

    @property
    def plugin_id(self) -> str:
        return 'websocket_scanner'

    @property
    def name(self) -> str:
        return 'WebSocket Security Scanner'

    @property
    def description(self) -> str:
        return (
            'Detects WebSocket endpoints and tests for Cross-Site WebSocket '
            'Hijacking (CSWSH) by checking origin validation in HTTP upgrade handshakes'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['websocket']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for WebSocket security issues.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl     (bool, default False)
                      timeout        (int,  default 10)
                      test_cswsh     (bool, default True)

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping WebSocket scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            ws_endpoints = self._discover_ws_endpoints(url, response.text)

            if not ws_endpoints:
                logger.info("WebSocket scan of %s – no WebSocket endpoints found", url)
                return findings

            for ws_url in ws_endpoints:
                # Report the discovered WebSocket endpoint
                findings.append(VulnerabilityFinding(
                    vulnerability_type='websocket',
                    severity='low',
                    url=url,
                    description=f'WebSocket endpoint discovered: {ws_url}',
                    evidence=(
                        f'WebSocket URL found in page source: {ws_url} | '
                        f'Source page: {url}'
                    ),
                    remediation=_REMEDIATION_WS_DETECTED,
                    confidence=0.85,
                    cwe_id='CWE-1385',
                ))

                # Test for CSWSH if enabled
                if config.get('test_cswsh', True):
                    http_url = self._ws_to_http_url(ws_url)
                    if http_url:
                        cswsh_finding = self._test_cswsh(
                            url, ws_url, http_url, verify_ssl, timeout
                        )
                        if cswsh_finding:
                            findings.append(cswsh_finding)

        except requests.RequestException as exc:
            logger.error("Network error during WebSocket scan of %s: %s", url, exc)
        except Exception as exc:
            logger.error("Unexpected error during WebSocket scan of %s: %s", url, exc)

        logger.info("WebSocket scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # WebSocket endpoint discovery
    # ------------------------------------------------------------------

    def _discover_ws_endpoints(self, base_url: str, html: str) -> Set[str]:
        """Extract WebSocket URLs from page source."""
        endpoints: Set[str] = set()

        # Direct ws:// or wss:// URLs
        for match in _WS_URL_PATTERN.finditer(html):
            endpoints.add(match.group(1).rstrip('",\''))

        # new WebSocket("...") constructors
        for match in _WS_CONSTRUCTOR_PATTERN.finditer(html):
            ws_url = match.group(1)
            if ws_url.startswith(('ws://', 'wss://')):
                endpoints.add(ws_url)
            else:
                # Relative URL – convert to absolute ws URL
                http_abs = urljoin(base_url, ws_url)
                parsed = urlparse(http_abs)
                ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'
                endpoints.add(urlparse(http_abs)._replace(scheme=ws_scheme).geturl())

        return endpoints

    # ------------------------------------------------------------------
    # CSWSH testing
    # ------------------------------------------------------------------

    def _test_cswsh(
        self,
        source_url: str,
        ws_url: str,
        http_url: str,
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """
        Send an HTTP GET request with WebSocket Upgrade headers from an evil origin
        and check if the server accepts the connection (101 Switching Protocols).

        If the server responds 101 to a cross-origin upgrade request, it is likely
        vulnerable to CSWSH.
        """
        evil_origin = 'https://evil.com'
        try:
            response = requests.get(
                http_url,
                headers={
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'Origin': evil_origin,
                },
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except Exception as exc:
            logger.debug("CSWSH probe failed for %s: %s", http_url, exc)
            return None

        if response.status_code == 101:
            return VulnerabilityFinding(
                vulnerability_type='websocket',
                severity='high',
                url=source_url,
                description=(
                    f'Cross-Site WebSocket Hijacking (CSWSH) potential at {ws_url}. '
                    f'The server accepted a WebSocket upgrade from evil origin '
                    f'"{evil_origin}" with HTTP 101 Switching Protocols.'
                ),
                evidence=(
                    f'WebSocket URL: {ws_url} | '
                    f'HTTP upgrade URL: {http_url} | '
                    f'Probe origin: {evil_origin} | '
                    f'Response status: {response.status_code} | '
                    f'Response headers: {dict(response.headers)}'
                ),
                remediation=_REMEDIATION_CSWSH,
                confidence=0.85,
                cwe_id='CWE-1385',
            )

        return None

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _ws_to_http_url(ws_url: str) -> Optional[str]:
        """Convert a ws:// or wss:// URL to http:// or https://."""
        try:
            parsed = urlparse(ws_url)
            if parsed.scheme == 'ws':
                return parsed._replace(scheme='http').geturl()
            if parsed.scheme == 'wss':
                return parsed._replace(scheme='https').geturl()
        except Exception:
            pass
        return None

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for WebSocket scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_cswsh': True,
        }
