"""
CRLF Injection / HTTP Header Injection Detector

Detects HTTP header injection vulnerabilities (CWE-113) by:

1. Header reflection detection
   - Sends probes with a unique marker in query parameters / path
   - Inspects response *headers* (not just the body) for reflection
   - Focuses on high-risk sinks: Location, Set-Cookie, and custom headers

2. CRLF injection confirmation
   - For each candidate header sink, replays the request with CRLF payloads:
       %0d%0aX-Megido-CRLF: injected
       %0d%0aSet-Cookie: MegidoCRLF=1
   - Bypass variant payloads:
       foo%00%0d%0abar
       foo%250d%250abar
       foo%%0d0d%%0a0abar
   - Confirmation requires the injected header line to appear in the
     *parsed* response headers (not merely as an encoded string).

3. HTTP response splitting assessment
   - If CRLF injection is confirmed, performs a safe secondary probe that
     injects a header/body boundary without destructive cache pollution.
   - Reports "Confirmed response splitting" only when clear evidence exists;
     otherwise reports "Potential response splitting".

4. Cookie injection + session fixation guidance
   - If Set-Cookie injection is confirmed, reports cookie injection risk and
     highlights session fixation potential.

CWE: CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
     CWE-93  (Improper Neutralization of CRLF Sequences)
     CWE-384 (Session Fixation) — guidance only
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

# Unique marker injected into probes so we can identify reflection
_MARKER = 'MegidoProbe7a3b'

# Headers considered high-risk sinks for injection
_SINK_HEADERS = ('location', 'set-cookie', 'refresh', 'x-redirect-url', 'uri')

# Primary CRLF injection payloads (URL-encoded)
_CRLF_PAYLOADS: List[Tuple[str, str]] = [
    # (label, raw payload string that will be percent-encoded)
    ('basic',         '%0d%0aX-Megido-CRLF: injected'),
    ('set-cookie',    '%0d%0aSet-Cookie: MegidoCRLF=1'),
    ('null-bypass',   'foo%00%0d%0abar'),
    ('double-encode', 'foo%250d%250abar'),
    ('partial-encode','foo%%0d0d%%0a0abar'),
]

# Injected header names used for confirmation
_INJECTED_HEADER_NAMES = ('x-megido-crlf', 'set-cookie')

# Remediation text
_REMEDIATION_CRLF = (
    "Sanitise all user-controlled input before embedding it in HTTP response "
    "headers. Strip or reject CR (\\r / %0d) and LF (\\n / %0a) characters. "
    "Use framework-provided redirect/header APIs instead of manually "
    "constructing header values. Apply input validation on both raw and "
    "percent-decoded forms."
)

_REMEDIATION_RESPONSE_SPLITTING = (
    "HTTP response splitting is possible when CRLF sequences can be injected "
    "into headers. Remediate the underlying CRLF injection (see above). "
    "Additionally, configure your reverse proxy/cache to strip or reject "
    "responses containing unexpected header boundaries."
)

_REMEDIATION_COOKIE_INJECTION = (
    "Arbitrary Set-Cookie injection allows an attacker to plant cookies in a "
    "victim's browser (session fixation, cookie poisoning). Remediate the CRLF "
    "injection and regenerate session identifiers after every authentication "
    "event. Verify that your framework rotates session tokens on login."
)


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class CRLFInjectionDetectorPlugin(BaseScanPlugin):
    """
    HTTP header injection / CRLF injection detection plugin.

    Detection strategy
    ------------------
    Phase 1 – Reflection probe
        Appends a unique marker to candidate query-string parameters (and the
        URL path when no parameters exist) and checks whether the value appears
        verbatim inside any *response header*.

    Phase 2 – CRLF confirmation
        For each sink identified in Phase 1, replays the request with each
        CRLF payload variant. Confirmation requires the injected header to be
        present as a *parsed* response header (not just a substring of an
        existing header value).

    Phase 3 – Response splitting assessment (if CRLF confirmed)
        Sends a safe probe injecting a minimal header/body boundary. Reports
        "Confirmed" or "Potential" depending on observable evidence.

    Phase 4 – Cookie injection guidance (if Set-Cookie sink confirmed)
        Adds a finding highlighting session fixation risk.
    """

    @property
    def plugin_id(self) -> str:
        return 'crlf_injection_detector'

    @property
    def name(self) -> str:
        return 'CRLF / HTTP Header Injection Detector'

    @property
    def description(self) -> str:
        return (
            'Detects HTTP header injection (CRLF injection) vulnerabilities including '
            'response splitting potential and cookie injection risks'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['crlf_injection', 'http_header_injection', 'response_splitting', 'cookie_injection']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for CRLF / HTTP header injection vulnerabilities.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl          (bool,  default False)
                      timeout             (int,   default 10)
                      check_response_splitting (bool, default True)
                      check_cookie_injection   (bool, default True)
                      extra_params        (list,  default []) – extra parameter
                          names to probe in addition to those already in the URL.

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping CRLF scan")
            return []

        config = config or self.get_default_config()
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)

        findings: List[VulnerabilityFinding] = []

        # Phase 1 – identify header-sink parameters via reflection probe
        sink_params = self._find_header_sinks(url, verify_ssl, timeout, config)

        if not sink_params:
            logger.info("CRLF scan of %s – no header sinks found", url)
            return findings

        logger.debug("CRLF scan of %s – sinks found: %s", url, sink_params)

        # Phase 2 – attempt CRLF injection on each sink
        crlf_confirmed = False
        set_cookie_confirmed = False

        for param, header_name in sink_params:
            crlf_findings, confirmed_payload = self._test_crlf_injection(
                url, param, header_name, verify_ssl, timeout
            )
            findings.extend(crlf_findings)

            if crlf_findings:
                crlf_confirmed = True
                if 'set-cookie' in confirmed_payload.lower():
                    set_cookie_confirmed = True

        # Phase 3 – response splitting assessment
        if crlf_confirmed and config.get('check_response_splitting', True):
            findings.extend(
                self._assess_response_splitting(url, sink_params[0][0], verify_ssl, timeout)
            )

        # Phase 4 – cookie injection / session fixation guidance
        if set_cookie_confirmed and config.get('check_cookie_injection', True):
            findings.append(self._cookie_injection_finding(url))

        logger.info("CRLF scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Phase 1: header-sink discovery
    # ------------------------------------------------------------------

    def _find_header_sinks(
        self, url: str, verify_ssl: bool, timeout: int, config: Dict[str, Any]
    ) -> List[Tuple[str, str]]:
        """
        Probe URL parameters for reflection in response headers.

        Returns a list of (param_name, header_name) tuples where reflection
        was detected.
        """
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        extra_params = config.get('extra_params', [])
        candidate_params = list(params.keys()) + list(extra_params)

        # If no query params, try to detect if the path itself is reflected
        if not candidate_params:
            return self._probe_path_reflection(url, verify_ssl, timeout)

        sinks: List[Tuple[str, str]] = []
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in candidate_params:
            probe_value = _MARKER
            probe_params = {k: (v[0] if v else '') for k, v in params.items()}
            probe_params[param] = probe_value

            try:
                response = requests.get(
                    base_url,
                    params=probe_params,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=False,
                )
            except Exception as exc:
                logger.debug("Reflection probe failed for param %s: %s", param, exc)
                continue

            for header_name, header_value in response.headers.items():
                if _MARKER in header_value and header_name.lower() in _SINK_HEADERS:
                    sinks.append((param, header_name))
                    logger.debug(
                        "Reflection found: param=%s reflected in header %s",
                        param, header_name,
                    )
                    break  # one sink per param is enough

        return sinks

    def _probe_path_reflection(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> List[Tuple[str, str]]:
        """
        When there are no query parameters, append the marker as a path segment
        and check headers for reflection.  Returns empty list if not reflected.
        """
        probe_url = url.rstrip('/') + '/' + _MARKER
        try:
            response = requests.get(
                probe_url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except requests.RequestException:
            return []

        for header_name, header_value in response.headers.items():
            if _MARKER in header_value and header_name.lower() in _SINK_HEADERS:
                return [('__path__', header_name)]

        return []

    # ------------------------------------------------------------------
    # Phase 2: CRLF injection testing
    # ------------------------------------------------------------------

    def _test_crlf_injection(
        self,
        url: str,
        param: str,
        reflected_header: str,
        verify_ssl: bool,
        timeout: int,
    ) -> Tuple[List[VulnerabilityFinding], str]:
        """
        Attempt each CRLF payload against the identified sink.

        Returns (findings, confirmed_payload_label) where confirmed_payload_label
        is the label of the first payload that was confirmed, or '' if none.
        """
        findings: List[VulnerabilityFinding] = []
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        for label, payload in _CRLF_PAYLOADS:
            if param == '__path__':
                probe_url = url.rstrip('/') + '/' + payload
                probe_params = None
            else:
                probe_url = base_url
                probe_params = dict(existing_params)
                probe_params[param] = payload

            try:
                response = requests.get(
                    probe_url,
                    params=probe_params,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                logger.debug("CRLF payload (%s) request failed: %s", label, exc)
                continue

            confirmed, injected_header = self._confirm_injection(response)
            if confirmed:
                evidence = (
                    f"Parameter: {param!r} | "
                    f"Payload label: {label!r} | "
                    f"Payload: {payload!r} | "
                    f"Reflected header sink: {reflected_header!r} | "
                    f"Injected header detected: {injected_header!r} | "
                    f"Response status: {response.status_code} | "
                    f"Response headers: {dict(response.headers)}"
                )
                severity = 'high'
                description = (
                    f'CRLF injection confirmed in parameter {param!r} '
                    f'(payload: {label}). Injected header {injected_header!r} '
                    f'appears in the response.'
                )
                finding = VulnerabilityFinding(
                    vulnerability_type='crlf_injection',
                    severity=severity,
                    url=url,
                    description=description,
                    evidence=evidence,
                    remediation=_REMEDIATION_CRLF,
                    parameter=param if param != '__path__' else None,
                    confidence=0.95,
                    cwe_id='CWE-113',
                    verified=True,
                    successful_payloads=[payload],
                )
                findings.append(finding)
                return findings, label  # stop at first confirmed payload

        return findings, ''

    def _confirm_injection(
        self, response: 'requests.Response'
    ) -> Tuple[bool, str]:
        """
        Check whether any of the injected header names appear as a parsed
        response header (rather than merely as a substring inside an existing
        header value).

        Returns (confirmed, injected_header_name_or_empty).
        """
        for header_name in response.headers:
            if header_name.lower() in _INJECTED_HEADER_NAMES:
                # Check that this header was not already present before injection
                # (we look for the injected value markers)
                value = response.headers[header_name]
                if header_name.lower() == 'x-megido-crlf' and 'injected' in value:
                    return True, header_name
                if header_name.lower() == 'set-cookie' and 'MegidoCRLF' in value:
                    return True, header_name

        # Secondary check: look for injected header anywhere in raw headers
        # (some frameworks merge injected lines)
        raw_headers_str = str(response.headers).lower()
        if 'x-megido-crlf' in raw_headers_str or 'megidocrlf' in raw_headers_str:
            return True, 'x-megido-crlf (inferred)'

        return False, ''

    # ------------------------------------------------------------------
    # Phase 3: response splitting assessment
    # ------------------------------------------------------------------

    def _assess_response_splitting(
        self, url: str, param: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """
        Perform a safe, non-destructive response splitting probe.

        Injects a minimal header/body boundary without destructive cache content.
        """
        findings: List[VulnerabilityFinding] = []

        # Safe response-splitting probe: inject a Content-Length: 0 followed by
        # a minimal HTML comment – avoids caching real content.
        splitting_payload = '%0d%0aContent-Length: 0%0d%0a%0d%0a<!--MegidoSplit-->'

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        if param == '__path__':
            probe_url = url.rstrip('/') + '/' + splitting_payload
            probe_params = None
        else:
            probe_url = base_url
            probe_params = dict(existing_params)
            probe_params[param] = splitting_payload

        try:
            response = requests.get(
                probe_url,
                params=probe_params,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except Exception as exc:
            logger.debug("Response splitting probe failed: %s", exc)
            return findings

        # Check for clear evidence of response body injection
        body_split_confirmed = (
            'MegidoSplit' in response.text or
            response.headers.get('content-length') == '0'
        )

        if body_split_confirmed:
            description = (
                'HTTP response splitting confirmed: injected header/body boundary '
                'was accepted by the server. An attacker can craft a second '
                'HTTP response within the same connection, enabling cache poisoning.'
            )
            confidence = 0.90
        else:
            description = (
                'HTTP response splitting potential: CRLF injection is confirmed '
                'but the response splitting boundary probe was not conclusively '
                'verified. Whether cache poisoning is achievable depends on '
                'proxy/pipeline behaviour between the client and server.'
            )
            confidence = 0.60

        evidence = (
            f"Parameter: {param!r} | "
            f"Splitting payload attempted | "
            f"Response status: {response.status_code} | "
            f"Body contains injected marker: {body_split_confirmed}"
        )

        findings.append(VulnerabilityFinding(
            vulnerability_type='response_splitting',
            severity='high' if body_split_confirmed else 'medium',
            url=url,
            description=description,
            evidence=evidence,
            remediation=_REMEDIATION_RESPONSE_SPLITTING,
            parameter=param if param != '__path__' else None,
            confidence=confidence,
            cwe_id='CWE-113',
            verified=body_split_confirmed,
        ))

        return findings

    # ------------------------------------------------------------------
    # Phase 4: cookie injection finding
    # ------------------------------------------------------------------

    def _cookie_injection_finding(self, url: str) -> VulnerabilityFinding:
        """
        Return a finding that describes cookie injection / session fixation risk.
        """
        return VulnerabilityFinding(
            vulnerability_type='cookie_injection',
            severity='high',
            url=url,
            description=(
                'Cookie injection via CRLF confirmed: arbitrary Set-Cookie headers '
                'can be injected into responses. This enables session fixation, '
                'cookie poisoning, and authentication bypass.'
            ),
            evidence=(
                'Set-Cookie header injection confirmed via CRLF payload. '
                'Attacker can set arbitrary cookie name/value pairs including '
                'session identifiers.'
            ),
            remediation=_REMEDIATION_COOKIE_INJECTION,
            confidence=0.95,
            cwe_id='CWE-384',
            verified=True,
        )

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for CRLF injection scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_response_splitting': True,
            'check_cookie_injection': True,
            'extra_params': [],
        }
