"""
CRLF Injection Detector Plugin

Detects HTTP header injection vulnerabilities by injecting CRLF sequences
(%0d%0a) into URL parameters and checking whether the injected headers
appear in the response.

Also tests for HTTP response splitting.

CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
"""

import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# CRLF injection payloads; each injects a recognisable header
_CRLF_PAYLOADS = [
    '%0d%0aX-Injected: crlf-test',
    '%0aX-Injected: crlf-test',
    '%0d%0aSet-Cookie: crlf_test=1',
    '%0d%0a%0d%0a<script>alert(1)</script>',
    '%E5%98%8D%E5%98%8AX-Injected: crlf-test',   # UTF-8 CRLF bypass
    'crlf%0d%0aX-Injected: crlf-test',
]

_INJECTED_HEADERS = ('x-injected', 'set-cookie')

_REMEDIATION = (
    "Strip or reject CR (\\r / %0d) and LF (\\n / %0a) characters from all "
    "user-controlled input before using it in HTTP response headers. Use your "
    "framework's safe redirect/header-setting APIs rather than constructing "
    "raw header strings. Apply input validation on both raw and percent-decoded forms."
)


class CRLFDetectorPlugin(BaseScanPlugin):
    """
    CRLF injection / HTTP header injection detection plugin.

    Injects CRLF payloads into query-string parameters and checks whether
    the injected header names appear as parsed response headers.
    """

    @property
    def plugin_id(self) -> str:
        return 'crlf_detector'

    @property
    def name(self) -> str:
        return 'CRLF Injection Detector'

    @property
    def description(self) -> str:
        return (
            'Detects CRLF injection / HTTP header injection vulnerabilities by '
            'injecting CR/LF sequences into parameters and inspecting response headers'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['crlf']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for CRLF injection vulnerabilities.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl (bool, default False)
                      timeout    (int,  default 10)

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping CRLF scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if not params:
                logger.info("CRLF scan of %s – no query parameters found", url)
                return findings

            for param in params:
                for payload in _CRLF_PAYLOADS:
                    finding = self._test_payload(
                        url, base_url, param, payload, params, verify_ssl, timeout
                    )
                    if finding:
                        findings.append(finding)
                        break  # one confirmed finding per parameter is enough

        except Exception as exc:
            logger.error("Unexpected error during CRLF scan of %s: %s", url, exc)

        logger.info("CRLF scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _test_payload(
        self,
        original_url: str,
        base_url: str,
        param: str,
        payload: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Inject a CRLF payload and check for injected headers in the response."""
        test_params = dict(all_params)
        test_params[param] = payload

        try:
            response = requests.get(
                base_url,
                params=test_params,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except Exception as exc:
            logger.debug("CRLF payload request failed (param=%s): %s", param, exc)
            return None

        # Check for injected header names in the parsed response headers
        for header_name in response.headers:
            if header_name.lower() in _INJECTED_HEADERS:
                header_value = response.headers[header_name]
                if 'crlf' in header_value.lower() or 'crlf_test' in header_value.lower():
                    return VulnerabilityFinding(
                        vulnerability_type='crlf',
                        severity='high',
                        url=original_url,
                        description=(
                            f'CRLF injection confirmed in parameter "{param}". '
                            f'Injected header "{header_name}" appeared in response.'
                        ),
                        evidence=(
                            f'Parameter: {param!r} | '
                            f'Payload: {payload!r} | '
                            f'Injected header: {header_name}: {header_value!r} | '
                            f'Response status: {response.status_code}'
                        ),
                        remediation=_REMEDIATION,
                        parameter=param,
                        confidence=0.95,
                        cwe_id='CWE-113',
                        verified=True,
                        successful_payloads=[payload],
                    )

        return None

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for CRLF injection scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
