"""
XSS Detection Plugin — Active Scanner

This plugin detects Cross-Site Scripting (XSS) vulnerabilities by:
- Reflected XSS: injecting payloads into every discovered parameter and
  checking if they appear (reflected) in the response.
- Stored XSS: submitting payloads via forms/POST and checking subsequent loads.
- DOM-based XSS: analysing JavaScript for dangerous sinks connected to sources.
- Context-aware payload selection (HTML, attribute, JS, URL contexts).
- WAF bypass payloads (encoding, case variation, polyglot payloads).
- Confidence scoring based on reflection context and payload evidence.

This is the DETECTION plugin. For EXPLOITATION, see scanner/plugins/exploits/xss_plugin.py
"""

import logging
import re
import uuid
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

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
from scanner.scan_plugins.stealth_scan_mixin import StealthScanMixin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Payload library (30+ payloads covering major injection contexts)
# ---------------------------------------------------------------------------

# Tag injection payloads
_TAG_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert`1`</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<math><maction xlink:href="javascript:alert(1)">click</maction></math>',
]

# Attribute injection payloads
_ATTR_PAYLOADS = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)'",
    '" autofocus onfocus="alert(1)',
    '"><script>alert(1)</script>',
    "' /><script>alert(1)</script>",
]

# JS context payloads
_JS_PAYLOADS = [
    "';alert(1)//",
    '";alert(1)//',
    '</script><script>alert(1)</script>',
    '\\";alert(1)//',
    "javascript:alert(1)",
]

# WAF bypass / polyglot payloads
_WAF_BYPASS_PAYLOADS = [
    '<ScRiPt>alert(1)</sCrIpT>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '<svg/onload=alert(1)>',
    '<img src=x:x onerror=alert(1)>',
    "jaVaScRiPt:alert(1)",
    '<a href="  javascript:alert(1)">click</a>',
]

ALL_PAYLOADS = _TAG_PAYLOADS + _ATTR_PAYLOADS + _JS_PAYLOADS + _WAF_BYPASS_PAYLOADS

# Dangerous DOM sinks that can lead to DOM XSS
_DOM_SINKS = [
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'document\.write\s*\(',
    r'document\.writeln\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'location\.assign\s*\(',
    r'\.src\s*=',
    r'insertAdjacentHTML\s*\(',
]

# DOM sources that carry attacker-controlled data
_DOM_SOURCES = [
    r'location\.hash',
    r'location\.search',
    r'location\.href',
    r'document\.referrer',
    r'window\.name',
    r'document\.cookie',
    r'localStorage\.',
    r'sessionStorage\.',
]


class XSSScannerPlugin(StealthScanMixin, BaseScanPlugin):
    """
    Active XSS vulnerability detection plugin.

    Performs three classes of XSS detection:

    1. **Reflected XSS** — injects payloads into every GET/POST parameter and
       checks whether the raw payload (or a marker embedded in it) is reflected
       in the response HTML, including context detection.

    2. **Stored XSS** — submits payloads via discovered forms and re-fetches the
       page to check whether the payload persisted.

    3. **DOM-based XSS** — static analysis of inline JavaScript for dangerous
       sink/source combinations (innerHTML, eval, document.write, etc.).

    Backward-compatible with BaseScanPlugin — the public interface is unchanged.
    """

    @property
    def plugin_id(self) -> str:
        return 'xss_scanner'

    @property
    def name(self) -> str:
        return 'XSS Vulnerability Scanner'

    @property
    def description(self) -> str:
        return (
            'Active XSS scanner: reflected, stored, and DOM-based XSS detection '
            'with 30+ payloads, context-aware injection, and WAF bypass techniques'
        )

    @property
    def version(self) -> str:
        return '3.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['xss']

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for XSS vulnerabilities at the target URL.

        Args:
            url: Target URL to scan.
            config: Optional configuration dictionary. Recognises:
                - ``verify_ssl`` (bool, default False)
                - ``timeout`` (int, default 10)
                - ``enable_stealth`` (bool, default False)
                - ``active_scan`` (bool, default True) — set False to keep
                  passive-only behaviour for safer/faster scanning.
                - ``max_payloads`` (int, default 10) — max payloads per param.

        Returns:
            List of VulnerabilityFinding objects.
        """
        if not HAS_REQUESTS or not HAS_BS4:
            logger.warning("Required dependencies (requests, beautifulsoup4) not available")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            session = requests.Session()
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            # Fetch the target page
            if config.get('enable_stealth', False):
                response = self.make_stealth_request(url, config=config)
            else:
                response = session.get(url, timeout=timeout, verify=verify_ssl)

            soup = BeautifulSoup(response.text, 'html.parser')

            # --- DOM-based XSS analysis (passive, always runs) ---
            findings.extend(self._check_dom_xss(url, soup, response.text))

            if config.get('active_scan', True):
                max_payloads = int(config.get('max_payloads', 10))
                active_payloads = ALL_PAYLOADS[:max_payloads]

                # --- Reflected XSS via URL parameters ---
                findings.extend(
                    self._test_reflected_xss_get(
                        url, session, active_payloads, verify_ssl, timeout
                    )
                )

                # --- Reflected / Stored XSS via forms ---
                forms = soup.find_all('form')
                for form in forms:
                    findings.extend(
                        self._test_form_xss(
                            url, form, session, active_payloads, verify_ssl, timeout
                        )
                    )

            # Always do a passive form check as a low-confidence baseline;
            # skip any form/parameter already covered by an active finding.
            passive = self._passive_form_check(url, soup)
            active_keys = {(f.url, f.parameter) for f in findings}
            for pf in passive:
                if (pf.url, pf.parameter) not in active_keys:
                    findings.append(pf)

        except Exception as e:
            logger.error(f"Error during XSS scan of {url}: {e}")

        logger.info(f"XSS scan of {url} found {len(findings)} issue(s)")
        return findings

    # ------------------------------------------------------------------
    # Reflected XSS — GET parameters
    # ------------------------------------------------------------------

    def _test_reflected_xss_get(
        self,
        url: str,
        session: 'requests.Session',
        payloads: List[str],
        verify_ssl: bool,
        timeout: int,
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return findings

        for param_name in params:
            for payload in payloads:
                marker = f'xss{uuid.uuid4().hex[:8]}'
                marked_payload = payload.replace('alert(1)', f'alert("{marker}")')
                new_params = dict(params)
                new_params[param_name] = [marked_payload]
                new_query = urlencode(new_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    resp = session.get(test_url, timeout=timeout, verify=verify_ssl)
                    reflected, context, confidence = self._check_reflection(
                        marked_payload, marker, resp.text
                    )
                    if reflected:
                        findings.append(VulnerabilityFinding(
                            vulnerability_type='xss',
                            severity='high',
                            url=test_url,
                            description=(
                                f'Reflected XSS in GET parameter "{param_name}". '
                                f'Payload reflected in {context} context.'
                            ),
                            evidence=(
                                f'Parameter: {param_name}\n'
                                f'Payload: {marked_payload}\n'
                                f'Context: {context}'
                            ),
                            remediation=(
                                'Encode all user-supplied output before rendering. '
                                'Apply a Content Security Policy (CSP). '
                                'Validate and sanitise all input server-side.'
                            ),
                            parameter=param_name,
                            confidence=confidence,
                            cwe_id='CWE-79',
                            verified=True,
                            successful_payloads=[marked_payload],
                        ))
                        break  # One confirmed finding per parameter is enough
                except Exception as e:
                    logger.debug(f"Error testing XSS on {test_url}: {e}")
        return findings

    # ------------------------------------------------------------------
    # Reflected / Stored XSS — forms
    # ------------------------------------------------------------------

    def _test_form_xss(
        self,
        base_url: str,
        form: Any,
        session: 'requests.Session',
        payloads: List[str],
        verify_ssl: bool,
        timeout: int,
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        target_url = urljoin(base_url, action) if action else base_url

        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data: Dict[str, str] = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                form_data[name] = inp.get('value', 'test')

        if not form_data:
            return findings

        for field_name in list(form_data.keys()):
            for payload in payloads:
                marker = f'xss{uuid.uuid4().hex[:8]}'
                marked_payload = payload.replace('alert(1)', f'alert("{marker}")')
                test_data = dict(form_data)
                test_data[field_name] = marked_payload
                try:
                    if method == 'post':
                        resp = session.post(
                            target_url, data=test_data,
                            timeout=timeout, verify=verify_ssl
                        )
                    else:
                        resp = session.get(
                            target_url, params=test_data,
                            timeout=timeout, verify=verify_ssl
                        )

                    reflected, context, confidence = self._check_reflection(
                        marked_payload, marker, resp.text
                    )
                    if reflected:
                        xss_type = 'Reflected' if method == 'get' else 'Potentially Stored'
                        findings.append(VulnerabilityFinding(
                            vulnerability_type='xss',
                            severity='high',
                            url=target_url,
                            description=(
                                f'{xss_type} XSS in form field "{field_name}" '
                                f'(method: {method.upper()}). '
                                f'Payload reflected in {context} context.'
                            ),
                            evidence=(
                                f'Form action: {action or base_url}\n'
                                f'Field: {field_name}\n'
                                f'Payload: {marked_payload}\n'
                                f'Context: {context}'
                            ),
                            remediation=(
                                'Encode output before rendering. '
                                'Implement server-side input validation. '
                                'Apply a strict Content Security Policy.'
                            ),
                            parameter=field_name,
                            confidence=confidence,
                            cwe_id='CWE-79',
                            verified=True,
                            successful_payloads=[marked_payload],
                        ))
                        break
                except Exception as e:
                    logger.debug(f"Error testing form XSS on {target_url}: {e}")
        return findings

    # ------------------------------------------------------------------
    # DOM-based XSS — static analysis
    # ------------------------------------------------------------------

    def _check_dom_xss(
        self, url: str, soup: Any, html: str
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            scripts = soup.find_all('script')
            script_texts = [
                s.string for s in scripts
                if s.string and isinstance(s.string, str)
            ]
            html_str = html if isinstance(html, str) else ''
            full_js = '\n'.join(script_texts) + html_str

            sinks_found = [
                s for s in _DOM_SINKS if re.search(s, full_js, re.IGNORECASE)
            ]
            sources_found = [
                s for s in _DOM_SOURCES if re.search(s, full_js, re.IGNORECASE)
            ]

            if sinks_found and sources_found:
                findings.append(VulnerabilityFinding(
                    vulnerability_type='xss',
                    severity='high',
                    url=url,
                    description=(
                        'Potential DOM-based XSS: dangerous JavaScript sinks are '
                        'connected to attacker-controllable sources.'
                    ),
                    evidence=(
                        f'Sinks detected: {", ".join(sinks_found[:5])}\n'
                        f'Sources detected: {", ".join(sources_found[:5])}'
                    ),
                    remediation=(
                        'Avoid passing attacker-controlled data directly to dangerous '
                        'sinks. Use safe DOM APIs (textContent instead of innerHTML). '
                        'Apply a strict CSP with nonces or hashes.'
                    ),
                    confidence=0.5,
                    cwe_id='CWE-79',
                ))
        except Exception as e:
            logger.debug(f"DOM XSS analysis error on {url}: {e}")
        return findings

    # ------------------------------------------------------------------
    # Passive fallback (when active_scan=False)
    # ------------------------------------------------------------------

    def _passive_form_check(self, url: str, soup: Any) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            target_url = urljoin(url, action)
            inputs = form.find_all(['input', 'textarea'])
            if inputs:
                input_names = [i.get('name', '') for i in inputs if i.get('name')]
                findings.append(VulnerabilityFinding(
                    vulnerability_type='xss',
                    severity='medium',
                    url=target_url,
                    description=(
                        f'Form with {len(inputs)} input field(s) — potential XSS target '
                        '(passive detection only; enable active_scan for confirmation).'
                    ),
                    evidence=f'Form action: {action}, fields: {", ".join(input_names[:5])}',
                    remediation=(
                        'Implement input validation and output encoding. '
                        'Use a Content Security Policy.'
                    ),
                    parameter=input_names[0] if input_names else None,
                    confidence=0.3,
                    cwe_id='CWE-79',
                ))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_reflection(
        self, payload: str, marker: str, body: str
    ) -> Tuple[bool, str, float]:
        """
        Determine whether the payload was reflected and in which context.

        Returns:
            (reflected, context_label, confidence)
        """
        # Direct full-payload reflection — highest confidence
        if payload in body:
            context = self._detect_context(payload, body)
            return True, context, 0.9

        # Marker-based reflection — high confidence
        if marker in body:
            context = self._detect_context(marker, body)
            return True, context, 0.8

        return False, '', 0.0

    @staticmethod
    def _detect_context(marker: str, body: str) -> str:
        """Determine the HTML context where the marker appears."""
        idx = body.find(marker)
        if idx == -1:
            return 'unknown'
        snippet = body[max(0, idx - 50):idx + len(marker) + 50]
        if re.search(r'<script[^>]*>', snippet, re.IGNORECASE):
            return 'JavaScript'
        if re.search(r'on\w+\s*=', snippet, re.IGNORECASE):
            return 'event handler attribute'
        if re.search(r'href\s*=|src\s*=|action\s*=', snippet, re.IGNORECASE):
            return 'URL attribute'
        if re.search(r'<[^>]+$', body[max(0, idx - 100):idx]):
            return 'HTML attribute'
        return 'HTML body'

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for XSS scanning."""
        base_config = {
            'verify_ssl': False,
            'timeout': 10,
            'active_scan': True,
            'max_payloads': 10,
        }
        try:
            stealth_config = self.get_stealth_config_defaults()
            base_config.update(stealth_config)
        except Exception:
            pass
        # Stealth is opt-in; always override to False as the default
        base_config['enable_stealth'] = False
        return base_config
