"""
IDOR (Insecure Direct Object Reference) Detection Plugin

Detects IDOR vulnerabilities by manipulating numeric IDs and UUIDs in
URL parameters and path segments to test for unauthorized data access.

Detection techniques:
- Increment/decrement numeric IDs
- Substitute well-known test UUIDs
- Sequential ID enumeration
- Compare response content to detect unauthorized data leakage

CWE-639 (Authorization Bypass Through User-Controlled Key)
"""

import logging
import re
import uuid
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# Regex to detect numeric IDs and UUIDs in parameter values / path segments
_NUMERIC_RE = re.compile(r'^\d+$')
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)

# Test UUIDs used for substitution probes
_TEST_UUIDS = [
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
    'ffffffff-ffff-ffff-ffff-ffffffffffff',
]

_REMEDIATION = (
    "Implement proper access control checks on every object access. "
    "Verify that the authenticated user has permission to access the requested "
    "resource before returning data. Use indirect references (e.g., random tokens "
    "instead of sequential IDs) or map user-specific references server-side. "
    "Never rely solely on the client-provided ID for authorization."
)


class IDORDetectorPlugin(BaseScanPlugin):
    """
    IDOR vulnerability detection plugin.

    Tests numeric and UUID parameters by incrementing, decrementing, or
    substituting values and comparing response content to detect unauthorized
    data exposure.
    """

    @property
    def plugin_id(self) -> str:
        return 'idor_detector'

    @property
    def name(self) -> str:
        return 'IDOR (Insecure Direct Object Reference) Detector'

    @property
    def description(self) -> str:
        return (
            'Detects IDOR vulnerabilities by manipulating numeric/UUID parameters '
            'and comparing responses for unauthorized data access indicators'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['idor']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for IDOR vulnerabilities.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl    (bool, default False)
                      timeout       (int,  default 10)
                      id_delta      (int,  default 1) – delta for increment/decrement
                      test_path     (bool, default True) – also test path segments
                      sequential_n  (int,  default 3)  – number of sequential IDs to test

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping IDOR scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            # Test query-string parameters
            parsed = urlparse(url)
            qs_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param, value in qs_params.items():
                findings.extend(
                    self._test_param(url, 'query', param, value, qs_params, base_url, config)
                )

            # Test numeric path segments
            if config.get('test_path', True):
                findings.extend(self._test_path_segments(url, config))

        except Exception as exc:
            logger.error("Unexpected error during IDOR scan of %s: %s", url, exc)

        # Deduplicate by parameter + substituted value
        seen: set = set()
        unique: List[VulnerabilityFinding] = []
        for f in findings:
            key = (f.parameter, f.description[:80])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        logger.info("IDOR scan of %s – %d finding(s)", url, len(unique))
        return unique

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _test_param(
        self,
        original_url: str,
        location: str,
        param: str,
        value: str,
        all_params: Dict[str, str],
        base_url: str,
        config: Dict[str, Any],
    ) -> List[VulnerabilityFinding]:
        """Test a single parameter for IDOR."""
        findings: List[VulnerabilityFinding] = []
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)
        delta = config.get('id_delta', 1)
        sequential_n = config.get('sequential_n', 3)

        if _NUMERIC_RE.match(value):
            orig_id = int(value)
            candidates: List[int] = []
            candidates.append(orig_id + delta)
            candidates.append(max(0, orig_id - delta))
            for i in range(1, sequential_n + 1):
                if i != orig_id:
                    candidates.append(i)

            for candidate in candidates:
                finding = self._probe_numeric(
                    original_url, base_url, param, str(orig_id),
                    str(candidate), all_params, verify_ssl, timeout
                )
                if finding:
                    findings.append(finding)

        elif _UUID_RE.match(value):
            for test_uuid in _TEST_UUIDS:
                if test_uuid.lower() == value.lower():
                    continue
                finding = self._probe_uuid(
                    original_url, base_url, param, value,
                    test_uuid, all_params, verify_ssl, timeout
                )
                if finding:
                    findings.append(finding)

        return findings

    def _probe_numeric(
        self,
        original_url: str,
        base_url: str,
        param: str,
        original_value: str,
        candidate_value: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Probe a numeric ID substitution and compare responses."""
        try:
            orig_params = dict(all_params)
            orig_params[param] = original_value
            orig_response = requests.get(
                base_url, params=orig_params, timeout=timeout, verify=verify_ssl
            )

            test_params = dict(all_params)
            test_params[param] = candidate_value
            test_response = requests.get(
                base_url, params=test_params, timeout=timeout, verify=verify_ssl
            )
        except Exception as exc:
            logger.debug("IDOR probe failed (param=%s): %s", param, exc)
            return None

        # Significant data if both return 200 with sizeable, differing content
        if (
            orig_response.status_code == 200 and
            test_response.status_code == 200 and
            len(test_response.text) > 100 and
            len(test_response.text) != len(orig_response.text)
        ):
            severity = 'high'
            return VulnerabilityFinding(
                vulnerability_type='idor',
                severity=severity,
                url=original_url,
                description=(
                    f'Potential IDOR in numeric parameter "{param}": '
                    f'substituting ID {original_value!r} with {candidate_value!r} '
                    'returned a non-empty 200 response with different content.'
                ),
                evidence=(
                    f'Parameter: {param!r} | Original ID: {original_value} | '
                    f'Probe ID: {candidate_value} | '
                    f'Original response len: {len(orig_response.text)} | '
                    f'Probe response len: {len(test_response.text)} | '
                    f'Probe status: {test_response.status_code}'
                ),
                remediation=_REMEDIATION,
                parameter=param,
                confidence=0.60,
                cwe_id='CWE-639',
            )
        return None

    def _probe_uuid(
        self,
        original_url: str,
        base_url: str,
        param: str,
        original_value: str,
        candidate_uuid: str,
        all_params: Dict[str, str],
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Probe a UUID substitution and compare responses."""
        try:
            test_params = dict(all_params)
            test_params[param] = candidate_uuid
            test_response = requests.get(
                base_url, params=test_params, timeout=timeout, verify=verify_ssl
            )
        except Exception as exc:
            logger.debug("IDOR UUID probe failed (param=%s): %s", param, exc)
            return None

        if test_response.status_code == 200 and len(test_response.text) > 100:
            return VulnerabilityFinding(
                vulnerability_type='idor',
                severity='medium',
                url=original_url,
                description=(
                    f'Potential IDOR in UUID parameter "{param}": '
                    f'substituting UUID with test value {candidate_uuid!r} '
                    'returned a non-empty 200 response.'
                ),
                evidence=(
                    f'Parameter: {param!r} | Original UUID: {original_value} | '
                    f'Test UUID: {candidate_uuid} | '
                    f'Probe status: {test_response.status_code} | '
                    f'Probe response len: {len(test_response.text)}'
                ),
                remediation=_REMEDIATION,
                parameter=param,
                confidence=0.50,
                cwe_id='CWE-639',
            )
        return None

    def _test_path_segments(
        self, url: str, config: Dict[str, Any]
    ) -> List[VulnerabilityFinding]:
        """Test numeric segments in the URL path for IDOR."""
        findings: List[VulnerabilityFinding] = []
        verify_ssl = config.get('verify_ssl', False)
        timeout = config.get('timeout', 10)
        delta = config.get('id_delta', 1)

        parsed = urlparse(url)
        segments = parsed.path.split('/')

        for idx, segment in enumerate(segments):
            if not _NUMERIC_RE.match(segment):
                continue

            orig_id = int(segment)
            for candidate in [orig_id + delta, max(0, orig_id - delta)]:
                new_segments = list(segments)
                new_segments[idx] = str(candidate)
                new_path = '/'.join(new_segments)
                test_url = urlunparse(parsed._replace(path=new_path))

                try:
                    orig_response = requests.get(url, timeout=timeout, verify=verify_ssl)
                    test_response = requests.get(test_url, timeout=timeout, verify=verify_ssl)
                except Exception as exc:
                    logger.debug("IDOR path probe failed: %s", exc)
                    continue

                if (
                    orig_response.status_code == 200 and
                    test_response.status_code == 200 and
                    len(test_response.text) > 100 and
                    len(test_response.text) != len(orig_response.text)
                ):
                    findings.append(VulnerabilityFinding(
                        vulnerability_type='idor',
                        severity='high',
                        url=url,
                        description=(
                            f'Potential IDOR in URL path segment (position {idx}): '
                            f'substituting ID {orig_id} with {candidate} '
                            'returned different non-empty content.'
                        ),
                        evidence=(
                            f'Original URL: {url} | '
                            f'Probe URL: {test_url} | '
                            f'Original response len: {len(orig_response.text)} | '
                            f'Probe response len: {len(test_response.text)}'
                        ),
                        remediation=_REMEDIATION,
                        parameter=f'path[{idx}]',
                        confidence=0.60,
                        cwe_id='CWE-639',
                    ))
                    break  # one finding per path segment is sufficient

        return findings

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for IDOR scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'id_delta': 1,
            'test_path': True,
            'sequential_n': 3,
        }
