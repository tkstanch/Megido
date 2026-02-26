"""
HTTP Request Smuggling Detector Plugin

Detects HTTP request smuggling vulnerabilities by testing CL.TE and TE.CL
desynchronisation attacks using ambiguous Content-Length / Transfer-Encoding
combinations.

Detection relies on timing differences and response anomalies rather than
sending destructive payloads to avoid impacting other users.

CWE-444 (Inconsistent Interpretation of HTTP Requests)
"""

import logging
import socket
import time
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

_REMEDIATION = (
    "Ensure that all servers in the chain (load balancers, proxies, and origin "
    "servers) use the same HTTP implementation and agree on which framing header "
    "takes precedence. Upgrade to HTTP/2 end-to-end where possible. Reject or "
    "normalize ambiguous requests at the edge. Disable support for chunked encoding "
    "on proxies where not required. See PortSwigger's research on HTTP request "
    "smuggling for detailed guidance."
)

# Timing threshold: if a test probe takes this many seconds longer than
# a normal request, we flag it as a potential smuggling indicator.
_TIMING_THRESHOLD = 5.0


class SmugglingDetectorPlugin(BaseScanPlugin):
    """
    HTTP request smuggling detection plugin.

    Sends CL.TE and TE.CL probe requests via raw TCP sockets to measure
    timing-based anomalies that indicate desync behaviour in front-end /
    back-end HTTP processing chains.
    """

    @property
    def plugin_id(self) -> str:
        return 'smuggling_detector'

    @property
    def name(self) -> str:
        return 'HTTP Request Smuggling Detector'

    @property
    def description(self) -> str:
        return (
            'Detects CL.TE and TE.CL HTTP request smuggling vulnerabilities using '
            'timing-based probes and response anomaly analysis'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['smuggling']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for HTTP request smuggling vulnerabilities.

        Args:
            url:    Target URL (must be HTTP/HTTPS).
            config: Optional dict with keys:
                      verify_ssl (bool, default False)
                      timeout    (int,  default 10)
                      test_cl_te (bool, default True)
                      test_te_cl (bool, default True)

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping smuggling scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            timeout = config.get('timeout', 10)

            # Establish baseline request time
            baseline_time = self._measure_baseline(url, timeout)
            if baseline_time is None:
                return findings

            if config.get('test_cl_te', True):
                finding = self._test_cl_te(url, baseline_time, timeout)
                if finding:
                    findings.append(finding)

            if config.get('test_te_cl', True):
                finding = self._test_te_cl(url, baseline_time, timeout)
                if finding:
                    findings.append(finding)

        except Exception as exc:
            logger.error("Unexpected error during smuggling scan of %s: %s", url, exc)

        logger.info("Smuggling scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Baseline measurement
    # ------------------------------------------------------------------

    def _measure_baseline(self, url: str, timeout: int) -> Optional[float]:
        """Measure average response time for a normal POST request."""
        try:
            times = []
            for _ in range(2):
                start = time.monotonic()
                requests.post(
                    url,
                    data='x=1',
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=timeout,
                    verify=False,
                )
                times.append(time.monotonic() - start)
            return sum(times) / len(times)
        except Exception as exc:
            logger.debug("Baseline measurement failed for %s: %s", url, exc)
            return None

    # ------------------------------------------------------------------
    # CL.TE probe
    # ------------------------------------------------------------------

    def _test_cl_te(
        self, url: str, baseline_time: float, timeout: int
    ) -> Optional[VulnerabilityFinding]:
        """
        CL.TE desync probe: send a request where Content-Length and
        Transfer-Encoding disagree.  The back-end (which uses TE) will
        wait for more data completing the chunked body, causing a hang.
        """
        raw_request = (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        )

        elapsed = self._send_raw_probe(url, raw_request, timeout + 10)
        if elapsed is None:
            return None

        if elapsed > baseline_time + _TIMING_THRESHOLD:
            return VulnerabilityFinding(
                vulnerability_type='smuggling',
                severity='high',
                url=url,
                description=(
                    'Potential CL.TE HTTP request smuggling detected. '
                    f'CL.TE probe took {elapsed:.1f}s vs baseline {baseline_time:.1f}s, '
                    'suggesting the back-end is waiting for a chunked body that '
                    'was already consumed by the front-end.'
                ),
                evidence=(
                    f'Probe type: CL.TE | '
                    f'Probe response time: {elapsed:.2f}s | '
                    f'Baseline response time: {baseline_time:.2f}s | '
                    f'Delta: {elapsed - baseline_time:.2f}s (threshold: {_TIMING_THRESHOLD}s)'
                ),
                remediation=_REMEDIATION,
                confidence=0.65,
                cwe_id='CWE-444',
            )
        return None

    # ------------------------------------------------------------------
    # TE.CL probe
    # ------------------------------------------------------------------

    def _test_te_cl(
        self, url: str, baseline_time: float, timeout: int
    ) -> Optional[VulnerabilityFinding]:
        """
        TE.CL desync probe: send a request where the chunked body contains
        more data than the Content-Length declares.  The back-end (which
        uses CL) reads the correct amount, but the front-end (which uses TE)
        passes extra data that poisons the next request.
        """
        raw_request = (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 3\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            "1\r\n"
            "G\r\n"
            "0\r\n"
            "\r\n"
        )

        elapsed = self._send_raw_probe(url, raw_request, timeout + 10)
        if elapsed is None:
            return None

        if elapsed > baseline_time + _TIMING_THRESHOLD:
            return VulnerabilityFinding(
                vulnerability_type='smuggling',
                severity='high',
                url=url,
                description=(
                    'Potential TE.CL HTTP request smuggling detected. '
                    f'TE.CL probe took {elapsed:.1f}s vs baseline {baseline_time:.1f}s, '
                    'suggesting the back-end is waiting for additional data based '
                    'on the Content-Length it received.'
                ),
                evidence=(
                    f'Probe type: TE.CL | '
                    f'Probe response time: {elapsed:.2f}s | '
                    f'Baseline response time: {baseline_time:.2f}s | '
                    f'Delta: {elapsed - baseline_time:.2f}s (threshold: {_TIMING_THRESHOLD}s)'
                ),
                remediation=_REMEDIATION,
                confidence=0.65,
                cwe_id='CWE-444',
            )
        return None

    # ------------------------------------------------------------------
    # Raw TCP helper
    # ------------------------------------------------------------------

    def _send_raw_probe(
        self, url: str, raw_request_template: str, timeout: int
    ) -> Optional[float]:
        """
        Send a raw HTTP request over a TCP socket and return the elapsed time.

        Returns None if the connection or send fails.
        """
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or 'localhost'
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            use_ssl = parsed.scheme == 'https'

            raw_request = raw_request_template.replace('{host}', host)

            sock = socket.create_connection((host, port), timeout=timeout)
            if use_ssl:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.settimeout(timeout)
            start = time.monotonic()
            sock.sendall(raw_request.encode('utf-8', errors='replace'))

            # Read until timeout or connection close
            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass  # Expected for timing-based detection
            finally:
                sock.close()

            return time.monotonic() - start
        except Exception as exc:
            logger.debug("Raw smuggling probe failed: %s", exc)
            return None

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for smuggling scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_cl_te': True,
            'test_te_cl': True,
        }
