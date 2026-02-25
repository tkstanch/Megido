"""
Silverlight Client Access Policy Detector Plugin

Same-Origin Policy Revisited: Silverlight clientaccesspolicy.xml Checks

Requests /clientaccesspolicy.xml on the scanned origin and analyses the policy
for security issues.

Silverlight's client access policy is less strict than Flash in one important
respect: it does not segregate access by scheme or port. A policy that trusts
http://example.com will also permit HTTPS and any port from that host, which
can widen the attack surface beyond what the policy author intended.

Checks performed:
  1. <domain uri="*">                         → critical
  2. Wildcard subdomain grants (*.example.com) → high
  3. <http-request-headers> with wildcard     → medium
  4. Missing policy (404/not found)           → informational note about
     Silverlight fallback to /crossdomain.xml

Evidence included in every finding: URL, status code, Content-Type, and the
matched XML snippet / attribute.

CWE: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
"""

import logging
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

_POLICY_PATH = '/clientaccesspolicy.xml'

_REMEDIATION_WILDCARD = (
    'Remove the wildcard (<domain uri="*">) from the client access policy. '
    'Specify only the exact trusted domains that require cross-domain access. '
    'Note: Silverlight does not segregate access by scheme or port, so even a '
    'narrowly named domain entry may grant broader access than intended.'
)

_REMEDIATION_WILDCARD_SUBDOMAIN = (
    'Replace wildcard subdomain grants (e.g. *.example.com) with explicit '
    'subdomain entries. Wildcard subdomain grants allow any subdomain, '
    'including attacker-controlled ones, to access your resources.'
)

_REMEDIATION_HEADERS = (
    'Restrict <http-request-headers> to the minimum required set. '
    'Using a wildcard (<header name="*">) allows any request header, '
    'which may expose sensitive header-based authentication mechanisms.'
)

_REMEDIATION_FALLBACK = (
    'Deploy a restrictive /clientaccesspolicy.xml to explicitly control '
    'Silverlight cross-domain access rather than relying on /crossdomain.xml '
    'fallback. The fallback policy may be more permissive than intended for '
    'Silverlight clients.'
)


class SilverlightClientAccessDetectorPlugin(BaseScanPlugin):
    """
    Detects Silverlight client access policy misconfigurations via
    /clientaccesspolicy.xml.

    Sends a single GET request to <origin>/clientaccesspolicy.xml and, if the
    file is present and parseable, analyses every <domain> element and every
    <http-request-headers> block. When the policy is absent, adds an
    informational note about the Silverlight fallback to /crossdomain.xml.
    """

    @property
    def plugin_id(self) -> str:
        return 'silverlight_clientaccess_detector'

    @property
    def name(self) -> str:
        return 'Silverlight Client Access Policy Detector'

    @property
    def description(self) -> str:
        return (
            'Checks /clientaccesspolicy.xml for Silverlight cross-domain policy '
            'misconfigurations including wildcard domains, wildcard subdomain '
            'grants, and wildcard request-header allowances. Notes Silverlight '
            'fallback to /crossdomain.xml when the policy is absent.'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['cors', 'security_misconfiguration']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan the origin derived from *url* for a Silverlight client access policy.

        Args:
            url:    Target URL (scheme + host are used; path is ignored).
            config: Optional dict with keys:
                      verify_ssl (bool, default False)
                      timeout    (int,  default 10)

        Returns:
            List of VulnerabilityFinding instances (empty when no issues found).
        """
        if not HAS_REQUESTS:
            logger.warning(
                "requests library not available – skipping Silverlight "
                "clientaccesspolicy scan"
            )
            return []

        config = config or self.get_default_config()
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        policy_url = base_url + _POLICY_PATH

        findings: List[VulnerabilityFinding] = []

        try:
            response = requests.get(
                policy_url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
            )

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                findings.extend(
                    self._analyse_policy(
                        policy_url,
                        response.status_code,
                        content_type,
                        response.text,
                    )
                )
            else:
                # Policy absent – note the Silverlight fallback behaviour
                logger.debug(
                    "No clientaccesspolicy.xml at %s (HTTP %d). "
                    "Silverlight falls back to /crossdomain.xml.",
                    policy_url,
                    response.status_code,
                )
                findings.append(VulnerabilityFinding(
                    vulnerability_type='info_disclosure',
                    severity='informational',
                    url=policy_url,
                    description=(
                        'No /clientaccesspolicy.xml found (HTTP %d). Silverlight '
                        'will fall back to /crossdomain.xml; ensure that file is '
                        'also reviewed for overly permissive grants.'
                        % response.status_code
                    ),
                    evidence=(
                        f"URL: {policy_url} | Status: {response.status_code}"
                    ),
                    remediation=_REMEDIATION_FALLBACK,
                    confidence=0.70,
                    cwe_id='CWE-942',
                ))

        except requests.RequestException as exc:
            logger.error("Error fetching %s: %s", policy_url, exc)
        except Exception as exc:
            logger.error("Unexpected error fetching %s: %s", policy_url, exc)

        logger.info(
            "Silverlight clientaccess scan of %s – %d finding(s)", url, len(findings)
        )
        return findings

    # ------------------------------------------------------------------
    # Policy analysis
    # ------------------------------------------------------------------

    def _analyse_policy(
        self,
        policy_url: str,
        status_code: int,
        content_type: str,
        body: str,
    ) -> List[VulnerabilityFinding]:
        """Parse clientaccesspolicy.xml body and return findings."""
        findings: List[VulnerabilityFinding] = []

        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            logger.warning(
                "Failed to parse clientaccesspolicy.xml at %s: %s", policy_url, exc
            )
            return findings

        evidence_prefix = (
            f"URL: {policy_url} | "
            f"Status: {status_code} | "
            f"Content-Type: {content_type!r}"
        )

        # --- <domain> elements -------------------------------------------
        for elem in root.iter('domain'):
            uri = elem.get('uri', '')
            evidence = f"{evidence_prefix} | <domain uri=\"{uri}\">"

            if uri == '*':
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors',
                    severity='critical',
                    url=policy_url,
                    description=(
                        'Silverlight client access policy grants access to all '
                        'domains (<domain uri="*">). Any website can make '
                        'cross-domain requests to this origin. Note: Silverlight '
                        'does not segregate access by scheme or port.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_WILDCARD,
                    confidence=1.0,
                    cwe_id='CWE-942',
                ))

            elif uri.startswith('*'):
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors',
                    severity='high',
                    url=policy_url,
                    description=(
                        f'Silverlight client access policy uses a wildcard '
                        f'subdomain grant (<domain uri="{uri}">). Any subdomain '
                        'matching this pattern can make cross-domain requests.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_WILDCARD_SUBDOMAIN,
                    confidence=0.95,
                    cwe_id='CWE-942',
                ))

        # --- http-request-headers wildcard check -------------------------
        # The Silverlight format specifies allowed headers as an attribute on
        # <allow-from http-request-headers="...">, not as child elements.
        for allow_from_elem in root.iter('allow-from'):
            req_headers = allow_from_elem.get('http-request-headers', '')
            if req_headers.strip() == '*':
                evidence = (
                    f"{evidence_prefix} | "
                    '<allow-from http-request-headers="*">'
                )
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors',
                    severity='medium',
                    url=policy_url,
                    description=(
                        'Silverlight client access policy allows all request '
                        'headers (http-request-headers="*"). Restrict to the '
                        'minimum required set.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_HEADERS,
                    confidence=0.85,
                    cwe_id='CWE-942',
                ))

        return findings
