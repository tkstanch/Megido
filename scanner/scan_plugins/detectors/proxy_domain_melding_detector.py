"""
Proxy-Service Domain-Melding Detector

Detects when a target URL is accessible via proxy-translation services
(e.g. Google Translate), enabling "domain-melding" attacks where two
otherwise cross-origin pages can interact because they are both served
under the proxy's origin.

Background
----------
Services like Google Translate proxy arbitrary web content through their
own domain (e.g. translate.goog).  If an attacker loads two different
target URLs through the same proxy, both pages appear to the browser as
same-origin (the proxy's origin), bypassing the Same-Origin Policy.
This enables:

  - Reading responses from a victim page loaded via the proxy
  - Jikto-style XSS worm propagation when stored XSS is present on the
    proxied site (each victim visits the target through the proxy and the
    XSS payload can read cross-origin resources as if they were same-origin)
  - Cookie theft if the SameSite / Secure cookie attributes are absent

This plugin is categorised as an **Exposure / Technique** finding by default
(not necessarily a vulnerability in the target itself) because the target has
limited control over whether proxy services choose to forward it.

However, when **stored/persistent XSS** is simultaneously detected on the
target, the severity is elevated and the Jikto-style propagation vector is
noted explicitly.

Proxy list
----------
The list of proxy services to test is modular and configurable via the
``proxy_services`` config key.  Each entry is a dict with:

    name     (str) – human-readable service name
    url_template (str) – URL template; use ``{url}`` as placeholder for the
                         full target URL and ``{host}`` for the hostname only.

The default list includes Google Translate.  Additional services can be
appended via configuration without modifying this file.

CWE: CWE-346 (Origin Validation Error)
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

# ---------------------------------------------------------------------------
# Default proxy service definitions
# ---------------------------------------------------------------------------

DEFAULT_PROXY_SERVICES: List[Dict[str, str]] = [
    {
        'name': 'Google Translate',
        'url_template': 'https://translate.google.com/translate?sl=auto&tl=en&u={url}',
    },
]

# ---------------------------------------------------------------------------
# Remediation text
# ---------------------------------------------------------------------------

_REMEDIATION_PROXY_EXPOSURE = (
    "The target content is served through a third-party proxy service, allowing "
    "two otherwise cross-origin pages to interact under the proxy's origin "
    "(domain-melding). To reduce risk: (1) Add an 'X-Frame-Options: DENY' or "
    "Content-Security-Policy 'frame-ancestors' directive to prevent framing; "
    "(2) Set SameSite=Strict on all session cookies so they are not forwarded "
    "through the proxy; (3) Implement a Content Security Policy that restricts "
    "external embedding; (4) Consider whether blocking known proxy/translation "
    "service IP ranges is feasible for sensitive endpoints."
)

_REMEDIATION_PROXY_XSS_ELEVATED = (
    "CRITICAL COMBINATION: Stored/persistent XSS was detected on this target AND "
    "the content is accessible via a domain-melding proxy service. This combination "
    "enables Jikto-style XSS worm propagation: the injected script runs under the "
    "proxy's origin and can make cross-origin requests to other resources loaded "
    "through the same proxy. Immediately remediate the XSS vulnerability. Also "
    "apply the proxy exposure mitigations (X-Frame-Options, SameSite cookies, CSP)."
)


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class ProxyDomainMeldingDetectorPlugin(BaseScanPlugin):
    """
    Proxy-service / domain-melding exposure detector.

    Detection strategy
    ------------------
    For each proxy service in the configured list:

    1. Construct the proxy URL for the target.
    2. Fetch the proxy URL and check whether:
       a. The response is successful (HTTP 2xx).
       b. The response body contains recognisable target content (a unique
          substring from the original target response is searched for).
    3. If both conditions are met, report an Exposure finding.

    XSS correlation
    ---------------
    If the caller passes ``xss_confirmed=True`` (or a non-empty
    ``xss_findings`` list) in the config, any proxy exposure finding is
    elevated from 'medium' to 'high' severity and the Jikto-style
    propagation vector is noted.
    """

    @property
    def plugin_id(self) -> str:
        return 'proxy_domain_melding_detector'

    @property
    def name(self) -> str:
        return 'Proxy-Service Domain-Melding Detector'

    @property
    def description(self) -> str:
        return (
            'Detects when target content is accessible via proxy-translation services '
            '(e.g. Google Translate), enabling domain-melding / cross-origin bypass attacks'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['proxy_exposure', 'domain_melding', 'cors']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for proxy-service domain-melding exposure.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl      (bool,  default False)
                      timeout         (int,   default 10)
                      proxy_services  (list,  default DEFAULT_PROXY_SERVICES)
                          List of proxy service dicts (name, url_template).
                      enable_proxy_checks (bool, default True)
                          Set to False to skip all proxy checks.
                      xss_confirmed   (bool,  default False)
                          True if stored/persistent XSS is confirmed on target.
                      xss_findings    (list,  default [])
                          List of XSS VulnerabilityFinding objects for correlation.
                      content_markers (list,  default [])
                          Additional strings to look for in the proxied response
                          body as evidence that the target content is served.

        Returns:
            List of VulnerabilityFinding instances (empty if not exposed).
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping proxy domain-melding scan")
            return []

        config = config or self.get_default_config()

        if not config.get('enable_proxy_checks', True):
            logger.info("Proxy domain-melding checks disabled via config")
            return []

        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)
        proxy_services = config.get('proxy_services', DEFAULT_PROXY_SERVICES)
        xss_confirmed = config.get('xss_confirmed', False) or bool(config.get('xss_findings'))
        extra_markers = config.get('content_markers', [])

        # Fetch original target to collect content markers
        target_markers = self._collect_target_markers(url, verify_ssl, timeout, extra_markers)

        findings: List[VulnerabilityFinding] = []

        for service in proxy_services:
            try:
                service_findings = self._check_proxy_service(
                    url=url,
                    service=service,
                    target_markers=target_markers,
                    xss_confirmed=xss_confirmed,
                    verify_ssl=verify_ssl,
                    timeout=timeout,
                )
                findings.extend(service_findings)
            except Exception as exc:
                logger.error(
                    "Proxy domain-melding check failed for service %s: %s",
                    service.get('name', '?'), exc,
                )

        logger.info("Proxy domain-melding scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_target_markers(
        self,
        url: str,
        verify_ssl: bool,
        timeout: int,
        extra_markers: List[str],
    ) -> List[str]:
        """
        Fetch the target URL directly and extract short unique substrings that
        can be used to confirm the proxy is serving target content.

        Falls back to hostname + path as markers if the fetch fails.
        """
        markers: List[str] = list(extra_markers)

        # Always include hostname as a basic marker
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ''
            if hostname:
                markers.append(hostname)
        except Exception:
            pass

        try:
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            body = response.text

            # Look for a <title> tag value as a reliable content marker
            title_match = _RE_TITLE.search(body)
            if title_match:
                title = title_match.group(1).strip()
                if len(title) >= 4:
                    markers.append(title[:60])  # cap length for safety

            # Look for a meta description
            meta_match = _RE_META_DESC.search(body)
            if meta_match:
                desc = meta_match.group(1).strip()
                if len(desc) >= 8:
                    markers.append(desc[:60])

        except Exception as exc:
            logger.debug("Could not fetch target for marker collection: %s", exc)

        return markers

    def _check_proxy_service(
        self,
        url: str,
        service: Dict[str, str],
        target_markers: List[str],
        xss_confirmed: bool,
        verify_ssl: bool,
        timeout: int,
    ) -> List[VulnerabilityFinding]:
        """
        Test whether a single proxy service exposes the target.

        Returns a list of findings (0 or 1 items).
        """
        findings: List[VulnerabilityFinding] = []
        service_name = service.get('name', 'Unknown proxy')
        url_template = service.get('url_template', '')

        if not url_template:
            logger.warning("Proxy service %r has no url_template – skipping", service_name)
            return findings

        encoded_url = urllib.parse.quote(url, safe='')
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ''
        proxy_url = url_template.replace('{url}', encoded_url).replace('{host}', host)

        try:
            response = requests.get(
                proxy_url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; MegidoScanner/1.0)'},
            )
        except Exception as exc:
            logger.debug("Proxy fetch failed (%s): %s", service_name, exc)
            return findings

        if response.status_code < 200 or response.status_code >= 400:
            logger.debug(
                "Proxy %s returned status %d for %s – not exposed",
                service_name, response.status_code, url,
            )
            return findings

        # Check whether target content markers appear in the proxied response
        body = response.text
        matched_markers = [m for m in target_markers if m and m.lower() in body.lower()]

        if not matched_markers:
            logger.debug(
                "Proxy %s returned 2xx but no target content markers found",
                service_name,
            )
            return findings

        # Exposure confirmed
        if xss_confirmed:
            severity = 'high'
            description = (
                f'[ELEVATED] Target is accessible via {service_name} proxy (domain-melding '
                f'exposure) AND stored/persistent XSS is confirmed. This combination '
                f'enables Jikto-style XSS worm propagation: the injected script executes '
                f'under the proxy\'s origin and can make same-origin requests to other '
                f'resources proxied through {service_name}.'
            )
            remediation = _REMEDIATION_PROXY_XSS_ELEVATED
            vuln_type = 'proxy_xss_propagation'
        else:
            severity = 'medium'
            description = (
                f'Target is accessible via {service_name} proxy service. Domain-melding '
                f'exposure: content from two different origins can be loaded under the '
                f'proxy\'s single origin, bypassing the Same-Origin Policy and enabling '
                f'cross-origin interaction between otherwise isolated pages.'
            )
            remediation = _REMEDIATION_PROXY_EXPOSURE
            vuln_type = 'proxy_exposure'

        evidence = (
            f"Proxy service: {service_name!r} | "
            f"Proxy URL: {proxy_url!r} | "
            f"Response status: {response.status_code} | "
            f"Target content markers matched: {matched_markers!r} | "
            f"XSS confirmed on target: {xss_confirmed}"
        )

        findings.append(VulnerabilityFinding(
            vulnerability_type=vuln_type,
            severity=severity,
            url=url,
            description=description,
            evidence=evidence,
            remediation=remediation,
            confidence=0.75,
            cwe_id='CWE-346',
        ))

        return findings

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for proxy domain-melding scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'proxy_services': DEFAULT_PROXY_SERVICES,
            'enable_proxy_checks': True,
            'xss_confirmed': False,
            'xss_findings': [],
            'content_markers': [],
        }


# ---------------------------------------------------------------------------
# Module-level compiled regexes
# ---------------------------------------------------------------------------

import re as _re

_RE_TITLE = _re.compile(r'<title[^>]*>(.*?)</title>', _re.IGNORECASE | _re.DOTALL)
_RE_META_DESC = _re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{8,})["\']',
    _re.IGNORECASE,
)
