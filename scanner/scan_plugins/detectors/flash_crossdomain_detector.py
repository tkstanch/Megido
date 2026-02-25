"""
Flash Cross-Domain Policy Detector Plugin

Same-Origin Policy Revisited: Flash crossdomain.xml Checks

Requests /crossdomain.xml on the scanned origin and analyses the policy for
security issues.

Checks performed:
  1. allow-access-from domain="*"              → critical
  2. Wildcard subdomain grants (*.example.com) → high
  3. Broad allowlists (many entries)           → high (informational note)
  4. site-control permissiveness               → medium
  5. Internal hostname / IP disclosure         → informational

Evidence included in every finding: URL, status code, Content-Type, and the
matched XML snippet / attribute.

CWE: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
"""

import logging
import re
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

_CROSSDOMAIN_PATH = '/crossdomain.xml'

# Threshold above which the number of allow-access-from entries is considered
# a broad allowlist (informational note).
_BROAD_ALLOWLIST_THRESHOLD = 5

_REMEDIATION_WILDCARD = (
    "Remove the wildcard (domain=\"*\") from the cross-domain policy. "
    "Specify only the exact trusted domains that require cross-domain access. "
    "If cross-domain access is not required, remove /crossdomain.xml entirely."
)

_REMEDIATION_WILDCARD_SUBDOMAIN = (
    "Replace wildcard subdomain grants (e.g. *.example.com) with explicit "
    "subdomain entries. Wildcard subdomain grants allow any subdomain, "
    "including attacker-controlled ones, to access your resources."
)

_REMEDIATION_BROAD_ALLOWLIST = (
    "Review all entries in the cross-domain policy and remove any that are no "
    "longer required. A large number of trusted domains increases the attack "
    "surface; prefer a minimal allowlist."
)

_REMEDIATION_SITE_CONTROL = (
    "Set the site-control meta-policy to 'master-only' or 'none' to restrict "
    "which cross-domain policy files are honoured. Avoid 'all', "
    "'by-ftp-filename', or 'by-content-type' which permit overly broad "
    "cross-domain access."
)

_REMEDIATION_INTERNAL = (
    "Ensure the cross-domain policy does not disclose internal hostnames or "
    "IP addresses. This information can assist attackers in mapping internal "
    "infrastructure. Use only externally resolvable domain names."
)

# Regex for private/internal IPv4 ranges and localhost
_PRIVATE_IP_RE = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|localhost'
    r')\b',
    re.IGNORECASE,
)


class FlashCrossdomainDetectorPlugin(BaseScanPlugin):
    """
    Detects Flash cross-domain policy misconfigurations via /crossdomain.xml.

    Sends a single GET request to <origin>/crossdomain.xml and, if the file
    is present and parseable, analyses every allow-access-from element and
    the site-control meta-policy element.
    """

    @property
    def plugin_id(self) -> str:
        return 'flash_crossdomain_detector'

    @property
    def name(self) -> str:
        return 'Flash Cross-Domain Policy Detector'

    @property
    def description(self) -> str:
        return (
            'Checks /crossdomain.xml for Flash cross-domain policy '
            'misconfigurations including wildcard domains, wildcard subdomain '
            'grants, overly permissive site-control, and internal IP disclosure'
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
        Scan the origin derived from *url* for a Flash cross-domain policy.

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
                "requests library not available – skipping Flash crossdomain scan"
            )
            return []

        config = config or self.get_default_config()
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        crossdomain_url = base_url + _CROSSDOMAIN_PATH

        findings: List[VulnerabilityFinding] = []

        try:
            response = requests.get(
                crossdomain_url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
            )

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                findings.extend(
                    self._analyse_policy(
                        crossdomain_url,
                        response.status_code,
                        content_type,
                        response.text,
                    )
                )
            else:
                logger.debug(
                    "No crossdomain.xml at %s (HTTP %d)",
                    crossdomain_url,
                    response.status_code,
                )

        except requests.RequestException as exc:
            logger.error("Error fetching %s: %s", crossdomain_url, exc)
        except Exception as exc:
            logger.error("Unexpected error fetching %s: %s", crossdomain_url, exc)

        logger.info(
            "Flash crossdomain scan of %s – %d finding(s)", url, len(findings)
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
        """Parse crossdomain.xml body and return findings."""
        findings: List[VulnerabilityFinding] = []

        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            logger.warning(
                "Failed to parse crossdomain.xml at %s: %s", policy_url, exc
            )
            return findings

        evidence_prefix = (
            f"URL: {policy_url} | "
            f"Status: {status_code} | "
            f"Content-Type: {content_type!r}"
        )

        # --- allow-access-from elements ----------------------------------
        access_from_elements = list(root.iter('allow-access-from'))

        if len(access_from_elements) > _BROAD_ALLOWLIST_THRESHOLD:
            findings.append(VulnerabilityFinding(
                vulnerability_type='cors',
                severity='informational',
                url=policy_url,
                description=(
                    f'Flash cross-domain policy contains {len(access_from_elements)} '
                    'allow-access-from entries. A broad allowlist increases the '
                    'attack surface.'
                ),
                evidence=(
                    f"{evidence_prefix} | "
                    f"allow-access-from entry count: {len(access_from_elements)}"
                ),
                remediation=_REMEDIATION_BROAD_ALLOWLIST,
                confidence=0.80,
                cwe_id='CWE-942',
            ))

        for elem in access_from_elements:
            domain = elem.get('domain', '')
            evidence = (
                f"{evidence_prefix} | "
                f'<allow-access-from domain="{domain}">'
            )

            if domain == '*':
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors',
                    severity='critical',
                    url=policy_url,
                    description=(
                        'Flash cross-domain policy grants access to all domains '
                        '(allow-access-from domain="*"). Any website can read '
                        'responses from this origin via Flash.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_WILDCARD,
                    confidence=1.0,
                    cwe_id='CWE-942',
                ))

            elif domain.startswith('*'):
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors',
                    severity='high',
                    url=policy_url,
                    description=(
                        f'Flash cross-domain policy uses a wildcard subdomain grant '
                        f'(allow-access-from domain="{domain}"). Any subdomain '
                        'matching this pattern can access resources.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_WILDCARD_SUBDOMAIN,
                    confidence=0.95,
                    cwe_id='CWE-942',
                ))

            # Internal hostname / IP disclosure (informational)
            if _PRIVATE_IP_RE.search(domain):
                findings.append(VulnerabilityFinding(
                    vulnerability_type='info_disclosure',
                    severity='informational',
                    url=policy_url,
                    description=(
                        f'Flash cross-domain policy discloses an internal hostname '
                        f'or IP address (allow-access-from domain="{domain}").'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_INTERNAL,
                    confidence=0.85,
                    cwe_id='CWE-200',
                ))

        # --- site-control elements ---------------------------------------
        for elem in root.iter('site-control'):
            permitted = elem.get('permitted-cross-domain-policies', '').lower()
            evidence = (
                f"{evidence_prefix} | "
                f'<site-control permitted-cross-domain-policies="{permitted}">'
            )
            if permitted in ('all', 'by-ftp-filename', 'by-content-type'):
                findings.append(VulnerabilityFinding(
                    vulnerability_type='cors',
                    severity='medium',
                    url=policy_url,
                    description=(
                        f'Flash cross-domain site-control permits '
                        f'"{permitted}" which allows additional policy files to '
                        'grant broad cross-domain access.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_SITE_CONTROL,
                    confidence=0.90,
                    cwe_id='CWE-942',
                ))

        return findings
