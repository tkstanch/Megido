"""
Clickjacking / UI Redress Detector Plugin

This plugin detects UI redress (clickjacking) exposure by analysing anti-framing
protections sent by the target:

  - Content-Security-Policy  frame-ancestors directive
  - X-Frame-Options header
  - Client-side JavaScript framebusting patterns (when response is HTML)

Classification:
  - Protected  : CSP frame-ancestors 'none' or a restrictive allow-list, **or**
                 X-Frame-Options DENY / SAMEORIGIN.
  - Weak       : X-Frame-Options ALLOW-FROM (obsolete, not universally honoured).
  - JS-only    : Only JavaScript framebusting present — legacy / bypassable.
  - Vulnerable : Neither CSP frame-ancestors nor effective XFO protection present,
                 **or** CSP frame-ancestors uses a broad wildcard (*).

Severity guidance:
  - High   : No CSP/XFO on an HTML page (readily frameable UI).
  - Medium : Only JavaScript framebusting present (legacy / bypassable), or
             CSP frame-ancestors uses a wildcard.
  - Low    : X-Frame-Options ALLOW-FROM only (obsolete directive).

CWE: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
"""

import logging
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple

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
    "by most modern browsers. "
    "JavaScript-only framebusting is bypassable (e.g. via sandbox attribute on the "
    "attacker-controlled iframe) and should not be used as the sole defence."
)

# Common JavaScript framebusting patterns with human-readable labels.
# Each entry is (regex_pattern, label).
_JS_FRAMEBUST_PATTERNS: List[Tuple[str, str]] = [
    (r'top\.location\s*!==?\s*self\.location', 'top.location != self.location'),
    (r'window\.top\s*!==?\s*window\.self', 'window.top !== window.self'),
    (r'\btop\s*!=\s*self\b', 'top != self'),
    (r'window\.frameElement', 'window.frameElement'),
    (r'top\.location(?:\.href)?\s*=', 'top.location assignment'),
    (r'window\.top\.location(?:\.href)?\s*=', 'window.top.location assignment'),
]

# Small set of mobile / alternate paths checked when scan_alternate_paths is enabled.
_ALTERNATE_PATHS: List[str] = ['/mobile', '/m', '/app', '/lite']


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
        return '2.0.0'

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
                      verify_ssl          (bool, default False)
                      timeout             (int,  default 10)
                      scan_alternate_paths (bool, default False) – also check
                          common mobile/alternate paths derived from the base URL.

        Returns:
            List of VulnerabilityFinding instances (empty if protected).
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping clickjacking scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        urls_to_scan = [url]
        if config.get('scan_alternate_paths', False):
            parsed = urllib.parse.urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in _ALTERNATE_PATHS:
                urls_to_scan.append(base + path)

        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)

        for target_url in urls_to_scan:
            try:
                response = requests.get(target_url, timeout=timeout,
                                        verify=verify_ssl, allow_redirects=True)
                headers = response.headers
                content_type = headers.get('Content-Type', '')
                is_html = 'text/html' in content_type.lower()

                js_defenses: List[str] = []
                if is_html and response.text:
                    js_defenses = self._scan_js_framebusting(response.text)

                url_findings = self._analyse_headers(
                    target_url, headers, js_defenses=js_defenses, is_html=is_html
                )
                findings.extend(url_findings)

                logger.info(
                    "Clickjacking scan of %s – %d finding(s)", target_url, len(url_findings)
                )

            except requests.RequestException as exc:
                logger.error(
                    "Error fetching %s during clickjacking scan: %s", target_url, exc
                )
            except Exception as exc:
                logger.error(
                    "Unexpected error in clickjacking scan of %s: %s", target_url, exc
                )

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _analyse_headers(
        self,
        url: str,
        headers: Dict,
        js_defenses: Optional[List[str]] = None,
        is_html: bool = False,
    ) -> List[VulnerabilityFinding]:
        """
        Inspect response headers (and optional JS-defense matches) and return findings.

        Priority:
          1. CSP frame-ancestors is checked first (supersedes XFO in modern browsers).
          2. If no CSP frame-ancestors is present, XFO is checked.
          3. If neither provides sufficient protection, JS framebusting is considered.
          4. A finding is emitted with severity reflecting the level of exposure.
        """
        findings: List[VulnerabilityFinding] = []
        js_defenses = js_defenses or []

        csp_value = headers.get('Content-Security-Policy', '')
        xfo_value = headers.get('X-Frame-Options', '')

        csp_fa = self._extract_csp_frame_ancestors(csp_value)
        xfo = xfo_value.strip().upper() if xfo_value else None

        # --- Evaluate CSP frame-ancestors ---
        csp_status = self._evaluate_csp_frame_ancestors(csp_fa)

        # --- Evaluate X-Frame-Options ---
        xfo_status = self._evaluate_xfo(xfo)

        # --- Overall protection rating ---
        protection_rating = self._protection_rating(csp_status, xfo_status)

        # --- Build evidence string ---
        csp_evidence = (
            f"Content-Security-Policy frame-ancestors: {csp_fa}"
            if csp_fa else "Content-Security-Policy frame-ancestors: missing"
        )
        xfo_evidence = f"X-Frame-Options: {xfo}" if xfo else "X-Frame-Options: missing"
        js_evidence = (
            f"JS framebusting patterns: {', '.join(js_defenses)}"
            if js_defenses else "JS framebusting patterns: none detected"
        )
        evidence = f"{csp_evidence}; {xfo_evidence}; {js_evidence}; protection: {protection_rating}"

        # --- Classification ---
        if csp_status == 'protected':
            return findings

        if csp_status == 'vulnerable':
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
            return findings

        if xfo_status == 'weak':
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

        # Neither CSP frame-ancestors nor effective XFO present.
        if js_defenses:
            # JavaScript-only framebusting is legacy and bypassable.
            shown = js_defenses[:3]
            ellipsis = ', …' if len(js_defenses) > 3 else ''
            findings.append(VulnerabilityFinding(
                vulnerability_type='clickjacking',
                severity='medium',
                url=url,
                description=(
                    'The page relies only on JavaScript framebusting for clickjacking '
                    'protection (patterns found: '
                    f"{', '.join(shown)}{ellipsis}). "
                    'JavaScript defences are bypassable (e.g. via the sandbox attribute '
                    'on the embedding iframe) and should not be the sole protection. '
                    'No Content-Security-Policy frame-ancestors or X-Frame-Options '
                    'header was detected.'
                ),
                evidence=evidence,
                remediation=_REMEDIATION,
                confidence=0.85,
                cwe_id='CWE-1021',
            ))
        else:
            # No protection at all.  Severity is high for HTML pages (directly frameable UI).
            severity = 'high' if is_html else 'medium'
            findings.append(VulnerabilityFinding(
                vulnerability_type='clickjacking',
                severity=severity,
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

    # ------------------------------------------------------------------
    # JS framebusting and protection-rating helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_js_framebusting(html_body: str) -> List[str]:
        """
        Scan an HTML body for common JavaScript framebusting patterns.

        Returns a list of human-readable labels for each distinct pattern found.
        An empty list means no framebusting JavaScript was detected.
        """
        found: List[str] = []
        for pattern, label in _JS_FRAMEBUST_PATTERNS:
            if re.search(pattern, html_body, re.IGNORECASE):
                found.append(label)
        return found

    @staticmethod
    def _protection_rating(csp_status: str, xfo_status: str) -> str:
        """
        Derive an overall protection rating string.

        Returns:
            'strong'  – CSP frame-ancestors present and not a wildcard.
            'partial' – XFO DENY/SAMEORIGIN present but no CSP frame-ancestors, or
                        XFO ALLOW-FROM only.
            'none'    – No effective server-side protection.
        """
        if csp_status == 'protected':
            return 'strong'
        if xfo_status in ('protected', 'weak'):
            return 'partial'
        return 'none'
