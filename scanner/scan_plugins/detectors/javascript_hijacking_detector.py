"""
JavaScript Hijacking / JSONP Data Exposure Detector Plugin

This plugin detects endpoints that may be vulnerable to JavaScript hijacking,
where user-specific sensitive data is returned in a response that is executable
as JavaScript when included cross-domain via <script src=...>.

Common vulnerable patterns:
  - JSONP / callback responses: ``showUserInfo([...])``
  - JavaScript variable assignment: ``var nonce = '...';`` or ``window.__DATA__ = {...}``
  - Pure JSON arrays/objects served with JS MIME types without XSSI protection

Detection modes:
  1. Discovery mode: if the target URL returns HTML, extract same-origin candidate
     script endpoints from <script src> tags and inline JS patterns.
  2. Heuristic probing mode: try a small bounded set of JSONP query-param variations
     only when the URL already has a query string or looks like an API endpoint.

Severity guidance:
  - critical/high : tokens, passwords, session identifiers, CSRF nonces
  - medium        : PII (email, username, uid)
  - low           : generic bootstrap/config data, no clear user-specific secrets

CWE: CWE-345 (Insufficient Verification of Data Authenticity) /
     CWE-346 (Origin Validation Error)
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum bytes to read from a response body to keep scanning bounded.
_MAX_RESPONSE_BYTES = 8192

# JSONP callback query-param names to probe (heuristic mode).
_JSONP_PROBE_PARAMS = ['callback', 'jsonp']

# Sentinel callback name used when probing.
_PROBE_CALLBACK = 'megidoCb'

# Regex: matches a JSONP wrapper like ``someFunc(...)`` or ``_cb123({...})``
_RE_JSONP_WRAPPER = re.compile(
    r'^\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\(\s*(\{|\[)',
    re.MULTILINE,
)

# Regex: matches JS variable/property assignments of likely-sensitive names.
_RE_SENSITIVE_ASSIGNMENT = re.compile(
    r'(?:var|let|const|window\s*\[\s*["\']|window\.)\s*'
    r'(?P<key>[a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'
    r'(?P<value>["\'][^"\']{4,}["\']|\{[^}]{0,200}\}|\[[^\]]{0,200}\])',
    re.IGNORECASE,
)

# Keywords that indicate a sensitive value is present in the response.
_SENSITIVE_KEYWORDS = re.compile(
    r'\b(nonce|csrf|token|session|auth|password|secret|apikey|api_key|jwt|bearer|uid|email)\b',
    re.IGNORECASE,
)

# Same keywords but without word boundaries, for matching against variable/key names
# where the keyword may appear as a substring (e.g. "csrfToken", "authToken").
_SENSITIVE_KEY_SUBSTR = re.compile(
    r'nonce|csrf|token|session|auth|password|secret|apikey|api_key|jwt|bearer|uid|email',
    re.IGNORECASE,
)

# JS MIME types that make a response executable via <script src>.
_JS_MIME_TYPES = {'application/javascript', 'text/javascript', 'application/x-javascript'}

# Regex patterns to extract candidate script endpoints from HTML / inline JS.
_RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_RE_FETCH_URL = re.compile(r'fetch\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_GETJSON_URL = re.compile(r'\$\.getJSON\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
_RE_XHR_OPEN = re.compile(
    r'XMLHttpRequest[^;]+\.open\(\s*["\']GET["\']'
    r'\s*,\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Patterns that look like API endpoints (used to gate heuristic probing).
_RE_API_PATH = re.compile(r'(/api/|/v\d+/|\.json\b|/data/|/feed/)', re.IGNORECASE)

_REMEDIATION = (
    "To remediate JavaScript Hijacking / JSONP Data Exposure: "
    "(1) Replace JSONP endpoints with CORS-protected JSON APIs "
    "    (set 'Content-Type: application/json' and proper 'Access-Control-Allow-Origin'). "
    "(2) Prefix JSON responses with an XSSI guard: ')]}\\n' or a while(1); loop "
    "    to prevent execution as a script. "
    "(3) Never return sensitive or user-specific data from URLs that can be included "
    "    cross-domain via <script src=...>. "
    "(4) Use SameSite=Strict or SameSite=Lax cookies so cookies are not sent on "
    "    cross-origin script includes. "
    "(5) Validate the 'callback' parameter against a strict allow-list; never reflect "
    "    arbitrary callback names into the response."
)


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class JavaScriptHijackingDetectorPlugin(BaseScanPlugin):
    """
    Detects JavaScript Hijacking / JSONP Data Exposure vulnerabilities.

    The plugin operates in two modes:

    1. **Discovery mode** – when the target URL returns an HTML document, the
       plugin extracts same-origin candidate script src URLs and inline JS fetch /
       XHR / $.getJSON call targets.

    2. **Heuristic probing mode** – when the URL contains a query string or its
       path looks like an API endpoint, the plugin appends common JSONP callback
       parameters (``?callback=megidoCb``, ``?jsonp=megidoCb``) and checks the
       response.

    For each candidate endpoint, the plugin fetches the response (bounded to
    ``_MAX_RESPONSE_BYTES``) and analyses it for:
      - JSONP wrappers (``callbackName({...})``)
      - JavaScript variable assignments of sensitive names
      - Pure JSON served with a JS MIME type (no XSSI protection)
    """

    @property
    def plugin_id(self) -> str:
        return 'javascript_hijacking_detector'

    @property
    def name(self) -> str:
        return 'JavaScript Hijacking / JSONP Data Exposure Detector'

    @property
    def description(self) -> str:
        return (
            'Detects endpoints that return user-specific sensitive data in a '
            'JavaScript-executable context (JSONP callbacks, JS variable '
            'assignments) which can be read cross-domain via <script src=...>.'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['js_hijacking']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan a URL for JavaScript hijacking / JSONP data exposure.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl  (bool, default False)
                      timeout     (int,  default 10)
                      headers     (dict, optional extra request headers)
                      cookies     (dict, optional cookies to send)

        Returns:
            List of VulnerabilityFinding instances (empty if none found).
        """
        if not HAS_REQUESTS:
            logger.warning('requests library not available – skipping JS hijacking scan')
            return []

        config = config or self.get_default_config()
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)
        extra_headers = config.get('headers', {})
        cookies = config.get('cookies', {})

        findings: List[VulnerabilityFinding] = []

        # Step 1: fetch the target URL and decide what to do next.
        try:
            resp = requests.get(
                url,
                headers=extra_headers,
                cookies=cookies,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
                stream=True,
            )
            body = resp.raw.read(_MAX_RESPONSE_BYTES, decode_content=True).decode(
                'utf-8', errors='replace'
            )
        except requests.RequestException as exc:
            logger.error('Error fetching %s during JS hijacking scan: %s', url, exc)
            return []

        content_type = resp.headers.get('Content-Type', '').lower()
        is_html = 'text/html' in content_type

        candidates: List[str] = []

        if is_html:
            # Discovery mode: extract same-origin script / fetch endpoints.
            candidates.extend(self._extract_script_candidates(url, body))
        else:
            # Non-HTML: analyse the fetched URL directly.
            finding = self._analyse_response(url, resp.headers, body)
            if finding:
                findings.append(finding)

        # Step 2: Heuristic probing (only for API-like URLs or those with a QS).
        parsed = urllib.parse.urlparse(url)
        if parsed.query or _RE_API_PATH.search(parsed.path):
            candidates.extend(self._jsonp_probe_urls(url))

        # Deduplicate candidates (preserve order).
        seen_urls: set = {url}
        deduped: List[str] = []
        for c in candidates:
            if c not in seen_urls:
                seen_urls.add(c)
                deduped.append(c)

        # Limit to a safe bounded number of probes.
        for candidate_url in deduped[:10]:
            try:
                c_resp = requests.get(
                    candidate_url,
                    headers=extra_headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True,
                    stream=True,
                )
                c_body = c_resp.raw.read(_MAX_RESPONSE_BYTES, decode_content=True).decode(
                    'utf-8', errors='replace'
                )
            except requests.RequestException as exc:
                logger.debug('Error fetching candidate %s: %s', candidate_url, exc)
                continue

            finding = self._analyse_response(candidate_url, c_resp.headers, c_body)
            if finding:
                findings.append(finding)

        logger.info('JS hijacking scan of %s – %d finding(s)', url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_script_candidates(base_url: str, html: str) -> List[str]:
        """Extract same-origin candidate script endpoints from HTML."""
        parsed_base = urllib.parse.urlparse(base_url)
        base_origin = f'{parsed_base.scheme}://{parsed_base.netloc}'
        candidates: List[str] = []

        def _resolve(href: str) -> Optional[str]:
            if not href or href.startswith(('data:', 'javascript:', '#')):
                return None
            resolved = urllib.parse.urljoin(base_url, href)
            rp = urllib.parse.urlparse(resolved)
            # Only return same-origin URLs.
            if rp.scheme in ('http', 'https') and f'{rp.scheme}://{rp.netloc}' == base_origin:
                return resolved
            return None

        for pattern in (_RE_SCRIPT_SRC, _RE_FETCH_URL, _RE_GETJSON_URL, _RE_XHR_OPEN):
            for m in pattern.finditer(html):
                resolved = _resolve(m.group(1))
                if resolved:
                    candidates.append(resolved)

        return candidates

    @staticmethod
    def _jsonp_probe_urls(url: str) -> List[str]:
        """Return JSONP-probed variants of *url*."""
        parsed = urllib.parse.urlparse(url)
        # Strip any existing callback/jsonp params to avoid duplicates.
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        probes = []
        for param in _JSONP_PROBE_PARAMS:
            new_qs = dict(qs)
            new_qs[param] = [_PROBE_CALLBACK]
            new_query = urllib.parse.urlencode(new_qs, doseq=True)
            probed = parsed._replace(query=new_query).geturl()
            probes.append(probed)
        return probes

    @classmethod
    def _analyse_response(
        cls,
        url: str,
        headers: Any,
        body: str,
    ) -> Optional[VulnerabilityFinding]:
        """
        Analyse a response body and headers for JS hijacking indicators.

        Returns a VulnerabilityFinding if a vulnerability is detected, else None.
        """
        content_type_raw = headers.get('Content-Type', '')
        content_type = content_type_raw.lower().split(';')[0].strip()
        is_js_mime = content_type in _JS_MIME_TYPES

        # --- Check 1: JSONP wrapper ---
        jsonp_match = _RE_JSONP_WRAPPER.match(body)
        if jsonp_match:
            callback_name = jsonp_match.group(1)
            has_sensitive = bool(_SENSITIVE_KEYWORDS.search(body))
            severity, confidence = cls._jsonp_severity(callback_name, has_sensitive)
            snippet = body[:300].replace('\n', ' ')
            return VulnerabilityFinding(
                vulnerability_type='js_hijacking',
                severity=severity,
                url=url,
                description=(
                    f'JSONP callback wrapper detected: {callback_name}(…). '
                    'This endpoint returns data wrapped in a JavaScript function call '
                    'and can be read cross-domain by including the URL via '
                    '<script src=...>.'
                ),
                evidence=f'Response begins with JSONP wrapper: {snippet!r}',
                remediation=_REMEDIATION,
                confidence=confidence,
                cwe_id='CWE-346',
            )

        # --- Check 2: JS variable/property assignments of sensitive names ---
        if is_js_mime:
            sensitive_assignments = [
                m for m in _RE_SENSITIVE_ASSIGNMENT.finditer(body)
                if _SENSITIVE_KEY_SUBSTR.search(m.group('key'))
            ]
            if sensitive_assignments:
                first = sensitive_assignments[0]
                severity = cls._assignment_severity(first.group('key'))
                snippet = body[:300].replace('\n', ' ')
                return VulnerabilityFinding(
                    vulnerability_type='js_hijacking',
                    severity=severity,
                    url=url,
                    description=(
                        f'JavaScript assignment of sensitive value detected '
                        f'(key: {first.group("key")!r}). '
                        'This JS response is served with a JS MIME type and can be '
                        'read cross-domain.'
                    ),
                    evidence=f'JS assignment found: {first.group(0)[:200]!r}',
                    remediation=_REMEDIATION,
                    confidence=0.65,
                    cwe_id='CWE-345',
                )

        # --- Check 3: Pure JSON served with JS MIME type (no XSSI protection) ---
        if is_js_mime:
            stripped = body.lstrip()
            if stripped.startswith(('{', '[')):
                has_sensitive = bool(_SENSITIVE_KEYWORDS.search(body))
                severity = 'medium' if has_sensitive else 'low'
                confidence = 0.60 if has_sensitive else 0.40
                snippet = body[:200].replace('\n', ' ')
                return VulnerabilityFinding(
                    vulnerability_type='js_hijacking',
                    severity=severity,
                    url=url,
                    description=(
                        'JSON data is served with a JavaScript MIME type and no '
                        'XSSI protection prefix. It can be included cross-domain '
                        'via <script src=...> in some browser contexts.'
                    ),
                    evidence=f'JS-MIME JSON response (no XSSI guard): {snippet!r}',
                    remediation=_REMEDIATION,
                    confidence=confidence,
                    cwe_id='CWE-346',
                )

        return None

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _jsonp_severity(callback_name: str, has_sensitive: bool) -> Tuple[str, float]:
        """Return (severity, confidence) for a detected JSONP wrapper."""
        if has_sensitive:
            return 'high', 0.85
        return 'medium', 0.70

    @staticmethod
    def _assignment_severity(key: str) -> str:
        """Map a sensitive key name to a severity string."""
        # Use substring matching (no word boundaries) so compound names like
        # "csrfToken" or "authToken" are correctly classified.
        critical_keys = re.compile(
            r'password|secret|apikey|api_key|jwt|bearer|token|csrf|nonce|session|auth',
            re.IGNORECASE,
        )
        medium_keys = re.compile(r'uid|email|username', re.IGNORECASE)
        if critical_keys.search(key):
            return 'high'
        if medium_keys.search(key):
            return 'medium'
        return 'low'
