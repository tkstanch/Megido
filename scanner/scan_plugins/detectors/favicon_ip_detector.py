"""
Favicon Hash Real IP Detector

Discovers real IP addresses behind CDN/WAF using favicon hashes:
- Fetch /favicon.ico from target
- Calculate MurmurHash3 (Shodan-compatible) of favicon content
- Report hash for Shodan/Censys lookup
- Detect CDN/WAF presence (Cloudflare, AWS CloudFront, Akamai, Fastly)
- Cross-reference with known favicon hashes
"""

import logging
import struct
from typing import Dict, List, Any, Optional, Tuple
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

# CDN/WAF detection by response headers
CDN_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cf-cache-status', 'cf-request-id', '__cfduid'],
    'AWS CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop', 'via'],
    'Akamai': ['x-akamai-request-id', 'x-akamai-transformed', 'x-check-cacheable'],
    'Fastly': ['x-fastly-request-id', 'x-served-by', 'x-cache', 'fastly-restarts'],
    'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
    'Imperva': ['x-iinfo', 'incap_ses'],
    'Azure CDN': ['x-azure-ref', 'x-ms-ags-diagnostic'],
    'Varnish': ['via', 'x-varnish'],
}

# Known favicon hashes associated with popular services (for cross-referencing)
KNOWN_FAVICON_HASHES = {
    -2121005356: 'Fortinet FortiGate',
    -335242539: 'Citrix Netscaler',
    -1328521940: 'Microsoft Exchange OWA',
    116323821: 'Apache HTTP Server',
    -1350222480: 'Nginx default page',
    1775552053: 'Jenkins',
    -1474255033: 'Jira',
    -2082108095: 'GitLab',
    708578229: 'WordPress',
    -1999002633: 'Drupal',
    1529787349: 'phpMyAdmin',
    -1043360568: 'Grafana',
    -397628964: 'Kibana',
    1489308896: 'Splunk',
}

# Alternative favicon paths to probe
FAVICON_PATHS = [
    '/favicon.ico',
    '/favicon.png',
    '/apple-touch-icon.png',
    '/static/favicon.ico',
    '/assets/favicon.ico',
    '/img/favicon.ico',
    '/images/favicon.ico',
]


def _mmh3_hash(data: bytes) -> int:
    """
    Calculate MurmurHash3 (32-bit) of data — Shodan-compatible favicon hash.

    This is the standard algorithm used by Shodan to index favicons.
    Implementation based on the MurmurHash3 specification (Austin Appleby).
    """
    seed = 0
    length = len(data)
    h1 = seed

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    # Process 4-byte blocks
    nblocks = length // 4
    for block_start in range(0, nblocks * 4, 4):
        k1 = struct.unpack('<I', data[block_start:block_start + 4])[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # Process tail bytes
    tail = data[nblocks * 4:]
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= tail[2] << 16
    if tail_size >= 2:
        k1 ^= tail[1] << 8
    if tail_size >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # Finalize
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit int (matching Python mmh3 library behavior)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


class FaviconIPDetectorPlugin(BaseScanPlugin):
    """
    Favicon Hash Real IP Detector.

    Uses MurmurHash3 of the favicon to:
    - Generate a Shodan-compatible hash for IP discovery
    - Detect CDN/WAF presence
    - Cross-reference known product favicon hashes
    - Help discover real IP addresses behind CDNs
    """

    @property
    def plugin_id(self) -> str:
        return 'favicon_ip_detector'

    @property
    def name(self) -> str:
        return 'Favicon Hash Real IP Detector'

    @property
    def description(self) -> str:
        return (
            'Calculates MurmurHash3 of favicon.ico (Shodan-compatible) to help discover '
            'real IP addresses behind CDN/WAF, and detects CDN presence via response headers'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['info_disclosure']

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for real IP disclosure via favicon hash.

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

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Step 1: Detect CDN/WAF presence
            cdn_name = self._detect_cdn(url, verify_ssl, timeout)

            # Step 2: Fetch favicon and compute hash
            favicon_data, favicon_url = self._fetch_favicon(base_url, verify_ssl, timeout)

            if favicon_data:
                favicon_hash = _mmh3_hash(favicon_data)
                known_product = KNOWN_FAVICON_HASHES.get(favicon_hash)

                # Build Shodan search queries
                shodan_query = f'http.favicon.hash:{favicon_hash}'
                censys_query = f'services.http.response.favicons.md5_hash:{favicon_hash}'

                description_parts = [
                    f'Favicon hash calculated: {favicon_hash}',
                    f'Use Shodan query: {shodan_query} to find servers with this favicon',
                ]
                if cdn_name:
                    description_parts.append(
                        f'CDN/WAF detected: {cdn_name} — real server IP may differ from DNS resolution'
                    )
                if known_product:
                    description_parts.append(f'Favicon matches known product: {known_product}')

                severity = 'medium' if cdn_name else 'low'
                confidence = 0.9 if favicon_data else 0.5

                vpoc = None
                if HAS_VPOC:
                    curl_cmd = build_curl_command(favicon_url, method='GET')
                    vpoc = None  # No response object, build manually
                    from scanner.scan_plugins.vpoc import VPoCEvidence
                    vpoc = VPoCEvidence(
                        plugin_name=self.plugin_id,
                        target_url=favicon_url,
                        payload=f'Favicon hash: {favicon_hash}',
                        confidence=confidence,
                        http_request={
                            'method': 'GET',
                            'url': favicon_url,
                            'headers': {},
                            'body': '',
                        },
                        http_response={
                            'status_code': 200,
                            'headers': {},
                            'body': f'[Binary favicon data, {len(favicon_data)} bytes]',
                        },
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. curl -o favicon.ico {favicon_url}\n"
                            f"2. Calculate MurmurHash3: python3 -c \"import mmh3, base64; "
                            f"print(mmh3.hash(base64.encodebytes(open('favicon.ico','rb').read())))\"\n"
                            f"3. Search Shodan: {shodan_query}\n"
                            f"4. Compare found IPs with current DNS resolution to discover real origin IP"
                        ),
                    )

                finding = VulnerabilityFinding(
                    vulnerability_type='info_disclosure',
                    severity=severity,
                    url=favicon_url,
                    description='\n'.join(description_parts),
                    evidence=(
                        f'Favicon URL: {favicon_url}\n'
                        f'Favicon size: {len(favicon_data)} bytes\n'
                        f'MurmurHash3: {favicon_hash}\n'
                        f'Shodan query: {shodan_query}\n'
                        f'Censys query: {censys_query}\n'
                        + (f'Detected CDN: {cdn_name}\n' if cdn_name else '')
                        + (f'Known product: {known_product}\n' if known_product else '')
                    ),
                    remediation=(
                        'Serve a unique or generic favicon to prevent fingerprinting. '
                        'If behind a CDN, ensure the origin server is not discoverable via '
                        'Shodan favicon hash searches. Consider rotating favicons periodically.'
                    ),
                    confidence=confidence,
                    cwe_id='CWE-200',
                    vpoc=vpoc,
                )
                findings.append(finding)
                logger.info(
                    f"Favicon hash calculated for {url}: {favicon_hash}"
                    + (f" (CDN: {cdn_name})" if cdn_name else "")
                )

            logger.info(f"Favicon IP scan of {url} found {len(findings)} finding(s)")

        except Exception as e:
            logger.error(f"Unexpected error during favicon IP scan of {url}: {e}")

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_cdn(self, url: str, verify_ssl: bool, timeout: int) -> Optional[str]:
        """Detect CDN/WAF from response headers."""
        try:
            resp = requests.get(url, timeout=timeout, verify=verify_ssl)
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            for cdn_name, header_list in CDN_SIGNATURES.items():
                for h in header_list:
                    if h.lower() in headers_lower:
                        return cdn_name
        except Exception as e:
            logger.debug(f"Error detecting CDN: {e}")
        return None

    def _fetch_favicon(
        self, base_url: str, verify_ssl: bool, timeout: int
    ) -> Tuple[Optional[bytes], str]:
        """Fetch favicon from various paths and return content and URL."""
        for path in FAVICON_PATHS:
            favicon_url = base_url + path
            try:
                resp = requests.get(
                    favicon_url,
                    timeout=timeout,
                    verify=verify_ssl,
                    stream=True,
                )
                if resp.status_code == 200 and resp.content:
                    content_type = resp.headers.get('content-type', '').lower()
                    # Accept image types and octet-stream
                    if ('image' in content_type or
                            'octet-stream' in content_type or
                            path.endswith('.ico') or
                            path.endswith('.png')):
                        return resp.content, favicon_url
            except Exception as e:
                logger.debug(f"Error fetching favicon at {favicon_url}: {e}")

        return None, base_url + '/favicon.ico'

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for favicon IP detection."""
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
