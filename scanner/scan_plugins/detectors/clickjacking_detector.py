"""
Clickjacking / UI Redress Detector Plugin

This plugin detects UI redress (clickjacking) exposure by analysing anti-framing
protections sent by the target:

  - Content-Security-Policy  frame-ancestors directive
  - X-Frame-Options header

Classification:
  - Protected  : CSP frame-ancestors 'none' or a restrictive allow-list, **or**
                 X-Frame-Options DENY / SAMEORIGIN.
  - Weak       : X-Frame-Options ALLOW-FROM (obsolete, not universally honoured).
  - Vulnerable : Neither CSP frame-ancestors nor effective XFO protection present,
                 **or** CSP frame-ancestors uses a broad wildcard (*).

CWE: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
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

_REMEDIATION = (
    "Add a Content-Security-Policy header with a frame-ancestors directive, e.g.: "
    "Content-Security-Policy: frame-ancestors 'none'  (to block all framing) or "
    "frame-ancestors 'self'  (to allow same-origin framing only). "
    "For legacy browser support, also set X-Frame-Options: DENY or SAMEORIGIN. "
    "Do NOT rely solely on X-Frame-Options ALLOW-FROM as it is obsolete and ignored "
    "by most modern browsers."
)


class ClickjackingDetectorPlugin(BaseScanPlugin):
    """
    Detects UI Redress / Clickjacking exposure via anti-framing header analysis.

    The plugin sends a single GET request to the target URL and inspects the
    response headers for:
      - Content-Security-Policy: frame-ancestors …
      - X-Frame-Options: DENY | SAMEORIGIN | ALLOW-FROM …

    A finding is raised whenever effective framing protection is absent or
    only a weak (ALLOW-FROM) directive is present.
    """

    @property
    def plugin_id(self) -> str:
        return 'clickjacking_detector'

    @property
    def name(self) -> str:
        return 'Clickjacking / UI Redress Detector'

    @property
    def description(self) -> str:
        return (
            'Detects UI redress (clickjacking) exposure by checking '
            'Content-Security-Policy frame-ancestors and X-Frame-Options headers'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['clickjacking']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan a URL for clickjacking / UI redress vulnerability.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl (bool, default False)
                      timeout    (int,  default 10)

        Returns:
            List of VulnerabilityFinding instances (empty if protected).
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping clickjacking scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            response = requests.get(url, timeout=timeout, verify=verify_ssl,
                                    allow_redirects=True)
            headers = response.headers

            findings = self._analyse_headers(url, headers)

            logger.info(
                "Clickjacking scan of %s – %d finding(s)", url, len(findings)
            )

        except requests.RequestException as exc:
            logger.error("Error fetching %s during clickjacking scan: %s", url, exc)
        except Exception as exc:
            logger.error("Unexpected error in clickjacking scan of %s: %s", url, exc)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _analyse_headers(
        self, url: str, headers: Dict
    ) -> List[VulnerabilityFinding]:
        """
        Inspect response headers and return appropriate findings.

        Priority:
          1. CSP frame-ancestors is checked first (it supersedes XFO in modern
             browsers).
          2. If no CSP frame-ancestors is present, XFO is checked.
          3. If neither provides sufficient protection a finding is emitted.
        """
        findings: List[VulnerabilityFinding] = []

        csp_value = headers.get('Content-Security-Policy', '')
        xfo_value = headers.get('X-Frame-Options', '')

        csp_fa = self._extract_csp_frame_ancestors(csp_value)
        xfo = xfo_value.strip().upper() if xfo_value else None

        # --- Evaluate CSP frame-ancestors ---
        csp_status = self._evaluate_csp_frame_ancestors(csp_fa)
        # 'protected' | 'vulnerable' | 'absent'

        # --- Evaluate X-Frame-Options ---
        xfo_status = self._evaluate_xfo(xfo)
        # 'protected' | 'weak' | 'absent'

        # --- Build evidence string ---
        csp_evidence = (
            f"Content-Security-Policy frame-ancestors: {csp_fa}"
            if csp_fa else "Content-Security-Policy frame-ancestors: missing"
        )
        xfo_evidence = f"X-Frame-Options: {xfo}" if xfo else "X-Frame-Options: missing"
        evidence = f"{csp_evidence}; {xfo_evidence}"

        # --- Classification ---
        if csp_status == 'protected':
            # CSP frame-ancestors provides strong protection – no finding
            return findings

        if csp_status == 'vulnerable':
            # CSP frame-ancestors is present but uses a wildcard / broad policy
            findings.append(VulnerabilityFinding(
                vulnerability_type='clickjacking',
                severity='medium',
                url=url,
                description=(
                    'Content-Security-Policy frame-ancestors uses an overly broad '
                    'policy (*) which does not protect against clickjacking.'
                ),
                evidence=evidence,
                remediation=_REMEDIATION,
                confidence=0.90,
                cwe_id='CWE-1021',
            ))
            return findings

        # csp_status == 'absent' – fall back to XFO
        if xfo_status == 'protected':
            # XFO DENY or SAMEORIGIN – protected (no finding)
            return findings

        if xfo_status == 'weak':
            # XFO ALLOW-FROM is obsolete and not supported by modern browsers
            findings.append(VulnerabilityFinding(
                vulnerability_type='clickjacking',
                severity='low',
                url=url,
                description=(
                    'X-Frame-Options ALLOW-FROM is an obsolete directive not '
                    'honoured by most modern browsers. The page may still be '
                    'frameable in browsers that ignore this header.'
                ),
                evidence=evidence,
                remediation=_REMEDIATION,
                confidence=0.75,
                cwe_id='CWE-1021',
            ))
            return findings

        # Neither CSP frame-ancestors nor effective XFO – vulnerable
        findings.append(VulnerabilityFinding(
            vulnerability_type='clickjacking',
            severity='medium',
            url=url,
            description=(
                'The page does not set Content-Security-Policy frame-ancestors '
                'or X-Frame-Options, leaving it exposed to UI redress '
                '(clickjacking) attacks.'
            ),
            evidence=evidence,
            remediation=_REMEDIATION,
            confidence=0.95,
            cwe_id='CWE-1021',
        ))
        return findings

    # ------------------------------------------------------------------
    # Header parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_csp_frame_ancestors(csp_header: str) -> Optional[str]:
        """
        Extract the frame-ancestors directive value from a CSP header string.

        Returns the directive value string (e.g. "'none'", "'self' example.com",
        "*") or None if frame-ancestors is not present.
        """
        if not csp_header:
            return None
        match = re.search(
            r'frame-ancestors\s+([^;]+)',
            csp_header,
            re.IGNORECASE,
        )
        if not match:
            return None
        return match.group(1).strip()

    @staticmethod
    def _evaluate_csp_frame_ancestors(fa_value: Optional[str]) -> str:
        """
        Evaluate a frame-ancestors directive value.

        Returns:
            'absent'    – directive not present
            'protected' – directive blocks or meaningfully restricts framing
            'vulnerable'– directive uses a wildcard (*) offering no protection
        """
        if fa_value is None:
            return 'absent'

        normalized = fa_value.strip().lower()

        # A bare wildcard offers no protection
        if normalized == '*':
            return 'vulnerable'

        # Any other value ('none', 'self', explicit host list) is considered
        # a meaningful restriction
        return 'protected'

    @staticmethod
    def _evaluate_xfo(xfo_value: Optional[str]) -> str:
        """
        Evaluate an X-Frame-Options header value.

        Returns:
            'absent'    – header not present
            'protected' – DENY or SAMEORIGIN
            'weak'      – ALLOW-FROM (obsolete)
        """
        if xfo_value is None:
            return 'absent'

        upper = xfo_value.strip().upper()

        if upper in ('DENY', 'SAMEORIGIN'):
            return 'protected'

        if upper.startswith('ALLOW-FROM'):
            return 'weak'

        # Unknown / malformed value – treat as absent
        return 'absent'
