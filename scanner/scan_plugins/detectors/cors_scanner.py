"""
CORS Misconfiguration Scanner Plugin

Same-Origin Policy Revisited: CORS Misconfiguration Detection

This plugin probes the target URL for common CORS misconfigurations by
sending requests with hostile Origin values and analysing the returned
CORS response headers.

Checks performed:
  1. Access-Control-Allow-Origin: * (wildcard)
  2. Origin reflection (ACAO mirrors the request Origin), including null origin
     and lookalike-subdomain origins
  3. ACAO + Access-Control-Allow-Credentials: true with untrusted origins
  4. Missing Vary: Origin header when dynamic ACAO is used
  5. OPTIONS preflight: overly permissive methods (DELETE, PUT, PATCH) and
     wildcard Access-Control-Allow-Headers

Severity guidance:
  - Critical : ACAO reflects untrusted origin AND ACAC: true
  - High     : ACAO: * AND ACAC: true, or ACAO reflects untrusted origin
               without credentials
  - Medium   : ACAO: * without credentials, preflight allows risky methods /
               wildcard headers
  - Low      : Missing Vary: Origin only (no credentials concern)

CWE: CWE-346 (Origin Validation Error) / CWE-942 (Permissive Cross-domain Policy)
"""

import logging
import urllib.parse
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# Hostile origin values used in probe requests
_PROBE_ORIGINS = [
    'https://evil.example',
    'null',
]

# Risky HTTP methods that preflight should not permit unless strictly necessary
_RISKY_METHODS = {'DELETE', 'PUT', 'PATCH'}

_REMEDIATION_WILDCARD = (
    "Do not use Access-Control-Allow-Origin: * for endpoints that return "
    "user-specific or sensitive data. Maintain an explicit allowlist of trusted "
    "origins and validate the incoming Origin header against it."
)

_REMEDIATION_REFLECTION = (
    "Validate the incoming Origin header against an explicit allowlist of "
    "trusted origins before reflecting it in Access-Control-Allow-Origin. "
    "Never dynamically reflect arbitrary origins. Also ensure Vary: Origin is "
    "returned so caches do not serve one origin's response to another."
)

_REMEDIATION_CREDENTIALS = (
    "Never combine Access-Control-Allow-Credentials: true with a wildcard or "
    "dynamically reflected untrusted origin. Use an explicit trusted-origin "
    "allowlist and consider whether credential-sharing cross-origin is necessary."
)

_REMEDIATION_VARY = (
    "When returning a dynamic Access-Control-Allow-Origin value, always include "
    "'Origin' in the Vary response header to prevent cache poisoning."
)

_REMEDIATION_PREFLIGHT = (
    "Restrict Access-Control-Allow-Methods to only the HTTP methods genuinely "
    "needed by the API. Avoid permitting DELETE, PUT, or PATCH unless required. "
    "Similarly, restrict Access-Control-Allow-Headers to the minimum required set."
)


class CORSScannerPlugin(BaseScanPlugin):
    """
    CORS misconfiguration scanner plugin.

    Probes the target with hostile Origin values (evil.example, null, and a
    lookalike subdomain) and sends an OPTIONS preflight request to detect:
      - Wildcard ACAO
      - Origin reflection (with and without ACAC: true)
      - Missing Vary: Origin for dynamic ACAO
      - Overly permissive preflight methods / headers
    """

    @property
    def plugin_id(self) -> str:
        return 'cors_scanner'

    @property
    def name(self) -> str:
        return 'CORS Misconfiguration Scanner'

    @property
    def description(self) -> str:
        return (
            'Detects CORS misconfigurations including wildcard origins, origin '
            'reflection, credential exposure, missing Vary: Origin, and overly '
            'permissive preflight responses'
        )

    @property
    def version(self) -> str:
        return '2.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['cors', 'cors_misconfiguration', 'security_misconfiguration']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan a URL for CORS misconfigurations.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl          (bool, default False)
                      timeout             (int,  default 10)
                      test_preflight      (bool, default True)
                      extra_probe_origins (list, default []) – additional hostile
                          Origin values to probe with.

        Returns:
            List of VulnerabilityFinding instances (empty if no issues found).
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping CORS scan")
            return []

        config = config or self.get_default_config()
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)
        extra_origins = config.get('extra_probe_origins', [])

        probe_origins = list(_PROBE_ORIGINS) + list(extra_origins)

        # Derive a lookalike subdomain origin from the target URL
        lookalike = self._lookalike_origin(url)
        if lookalike:
            probe_origins.append(lookalike)

        findings: List[VulnerabilityFinding] = []

        for origin in probe_origins:
            try:
                findings.extend(
                    self._probe_origin(url, origin, verify_ssl, timeout)
                )
            except requests.RequestException as exc:
                logger.error(
                    "CORS probe of %s (origin=%s) failed: %s", url, origin, exc
                )
            except Exception as exc:
                logger.error(
                    "Unexpected CORS probe error (%s, origin=%s): %s", url, origin, exc
                )

        # OPTIONS preflight check
        if config.get('test_preflight', True):
            preflight_origin = probe_origins[0] if probe_origins else 'https://evil.example'
            try:
                findings.extend(
                    self._probe_preflight(url, preflight_origin, verify_ssl, timeout)
                )
            except requests.RequestException as exc:
                logger.error("CORS preflight probe of %s failed: %s", url, exc)
            except Exception as exc:
                logger.error("Unexpected CORS preflight error (%s): %s", url, exc)

        # Deduplicate by (vulnerability_type, description prefix, url)
        seen: set = set()
        unique_findings: List[VulnerabilityFinding] = []
        for f in findings:
            key = (f.vulnerability_type, f.description[:60], f.url)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        logger.info("CORS scan of %s – %d finding(s)", url, len(unique_findings))
        return unique_findings

    # ------------------------------------------------------------------
    # Internal probing helpers
    # ------------------------------------------------------------------

    def _probe_origin(
        self, url: str, origin: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """
        Send a GET request with the given Origin header and analyse CORS headers.

        Returns a list of findings; empty if no issues detected.
        """
        findings: List[VulnerabilityFinding] = []

        response = requests.get(
            url,
            headers={'Origin': origin},
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        vary = response.headers.get('Vary', '')
        has_credentials = acac == 'true'

        evidence_base = (
            f"Request Origin: {origin} | "
            f"Access-Control-Allow-Origin: {acao!r} | "
            f"Access-Control-Allow-Credentials: {acac!r} | "
            f"Vary: {vary!r}"
        )

        if acao == '*':
            if has_credentials:
                # Browsers reject this combination but it indicates misconfiguration.
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors_misconfiguration',
                    severity='high',
                    url=url,
                    description=(
                        'CORS wildcard (Access-Control-Allow-Origin: *) combined '
                        'with Access-Control-Allow-Credentials: true. Browsers '
                        'reject this combination but it indicates a misconfigured '
                        'CORS policy.'
                    ),
                    evidence=evidence_base,
                    remediation=_REMEDIATION_CREDENTIALS,
                    confidence=0.95,
                    cwe_id='CWE-942',
                ))
            else:
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors_misconfiguration',
                    severity='medium',
                    url=url,
                    description=(
                        'CORS policy allows all origins '
                        '(Access-Control-Allow-Origin: *). Sensitive endpoints '
                        'should restrict cross-origin access to trusted origins.'
                    ),
                    evidence=evidence_base,
                    remediation=_REMEDIATION_WILDCARD,
                    confidence=0.95,
                    cwe_id='CWE-942',
                ))

        elif acao and acao == origin:
            # Dynamic origin reflection detected
            if has_credentials:
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors_misconfiguration',
                    severity='critical',
                    url=url,
                    description=(
                        'CORS policy reflects an untrusted origin back in '
                        'Access-Control-Allow-Origin AND sets '
                        'Access-Control-Allow-Credentials: true. An attacker-'
                        'controlled page can make credentialed cross-origin '
                        'requests to this endpoint.'
                    ),
                    evidence=evidence_base,
                    remediation=_REMEDIATION_CREDENTIALS,
                    confidence=0.95,
                    cwe_id='CWE-942',
                ))
            else:
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors_misconfiguration',
                    severity='high',
                    url=url,
                    description=(
                        'CORS policy dynamically reflects the request Origin in '
                        'Access-Control-Allow-Origin without validating against '
                        'a trusted-origin allowlist.'
                    ),
                    evidence=evidence_base,
                    remediation=_REMEDIATION_REFLECTION,
                    confidence=0.90,
                    cwe_id='CWE-942',
                ))

            # Also flag missing Vary: Origin when dynamic ACAO is in use
            if 'origin' not in vary.lower():
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors_misconfiguration',
                    severity='low',
                    url=url,
                    description=(
                        'Dynamic Access-Control-Allow-Origin is returned but the '
                        'response does not include Vary: Origin. This may cause '
                        'caches to serve a CORS-enabled response to an origin '
                        'that should not receive it.'
                    ),
                    evidence=evidence_base,
                    remediation=_REMEDIATION_VARY,
                    confidence=0.80,
                    cwe_id='CWE-346',
                ))

        return findings

    def _probe_preflight(
        self, url: str, origin: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """
        Send an OPTIONS preflight request with Authorization + X-Custom-Header
        and analyse the Access-Control-Allow-Methods / Headers response.
        """
        findings: List[VulnerabilityFinding] = []

        try:
            response = requests.options(
                url,
                headers={
                    'Origin': origin,
                    'Access-Control-Request-Method': 'POST',
                    'Access-Control-Request-Headers': 'Authorization, X-Custom-Header',
                },
                timeout=timeout,
                verify=verify_ssl,
            )
        except requests.RequestException:
            return findings

        acam = response.headers.get('Access-Control-Allow-Methods', '')
        acah = response.headers.get('Access-Control-Allow-Headers', '')

        if not acam:
            return findings

        allowed_methods_upper = {m.strip().upper() for m in acam.split(',')}
        found_risky = _RISKY_METHODS & allowed_methods_upper

        evidence_preflight = (
            f"Request Origin: {origin} | "
            f"Access-Control-Request-Headers: Authorization, X-Custom-Header | "
            f"Access-Control-Allow-Methods: {acam!r} | "
            f"Access-Control-Allow-Headers: {acah!r}"
        )

        if found_risky:
            findings.append(VulnerabilityFinding(
                vulnerability_type='cors_misconfiguration',
                severity='medium',
                url=url,
                description=(
                    f'CORS preflight allows risky HTTP methods: '
                    f'{", ".join(sorted(found_risky))}. These should only be '
                    'permitted if genuinely required by the API.'
                ),
                evidence=evidence_preflight,
                remediation=_REMEDIATION_PREFLIGHT,
                confidence=0.75,
                cwe_id='CWE-942',
            ))

        if acah and '*' in acah:
            findings.append(VulnerabilityFinding(
                vulnerability_type='cors_misconfiguration',
                severity='medium',
                url=url,
                description=(
                    'CORS preflight allows all request headers '
                    '(Access-Control-Allow-Headers: *). Restrict to the minimum '
                    'required set.'
                ),
                evidence=evidence_preflight,
                remediation=_REMEDIATION_PREFLIGHT,
                confidence=0.75,
                cwe_id='CWE-942',
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _lookalike_origin(url: str) -> Optional[str]:
        """
        Derive a lookalike subdomain origin from the target URL.

        For example, https://example.com → https://evil.example.com
        Returns None when the URL cannot be parsed to a meaningful lookalike
        (e.g. localhost, bare IP addresses).
        """
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ''
            if not host or host in ('localhost', '127.0.0.1'):
                return None
            scheme = parsed.scheme or 'https'
            return f"{scheme}://evil.{host}"
        except Exception:
            return None

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for CORS scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_preflight': True,
            'extra_probe_origins': [],
        }
