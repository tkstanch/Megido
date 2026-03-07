"""
Target Fingerprinter

Pre-scan target analysis module for intelligent, adaptive scanning.

Performs lightweight reconnaissance against a target URL to gather information
that can guide plugin selection, payload tuning, and timing decisions:

- WAF detection (reuses WAF_SIGNATURES from waf_bypass_detector)
- Technology stack detection (server headers, framework hints)
- Response time baselining and rate-limit detection
- SSL/TLS certificate inspection
- Framework-specific path probing (WordPress, API, GraphQL, etc.)
"""

import logging
import ssl
import socket
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from scanner.scan_plugins.detectors.waf_bypass_detector import WAF_SIGNATURES
    _HAS_WAF_SIGS = True
except ImportError:
    WAF_SIGNATURES = {}
    _HAS_WAF_SIGS = False

logger = logging.getLogger(__name__)

# Common framework/technology probe paths
_FRAMEWORK_PATHS: Dict[str, str] = {
    'wordpress': '/wp-admin/',
    'wordpress_api': '/wp-json/',
    'django_admin': '/admin/',
    'graphql': '/graphql',
    'graphiql': '/graphiql',
    'api_v1': '/api/v1/',
    'api_v2': '/api/v2/',
    'swagger': '/swagger.json',
    'openapi': '/openapi.json',
    'phpinfo': '/phpinfo.php',
    'joomla': '/administrator/',
    'drupal': '/user/login',
    'laravel_horizon': '/horizon/',
}

# Server header patterns mapped to technology names
_TECH_PATTERNS: Dict[str, List[str]] = {
    'nginx': ['nginx'],
    'apache': ['apache'],
    'iis': ['iis', 'microsoft-iis'],
    'litespeed': ['litespeed'],
    'caddy': ['caddy'],
    'php': ['php'],
    'asp.net': ['asp.net'],
    'node.js': ['node', 'express'],
    'ruby': ['ruby', 'passenger', 'thin', 'puma'],
    'python': ['gunicorn', 'uvicorn', 'django', 'flask', 'tornado', 'wsgiserver'],
    'java': ['jetty', 'tomcat', 'jboss', 'weblogic', 'websphere'],
    'wordpress': ['wordpress'],
    'drupal': ['drupal'],
    'joomla': ['joomla'],
}


class TargetFingerprinter:
    """Pre-scan target analysis for intelligent scanning.

    Sends a small number of baseline requests to the target to gather
    information about its environment before the main scan plugins run.
    All results are returned as a plain dictionary so they can be stored
    in the scan ``config`` and consumed by any plugin.

    Usage::

        fp = TargetFingerprinter()
        fingerprint = fp.fingerprint('https://example.com', config={})
        # fingerprint['waf_detected'] → bool
        # fingerprint['technologies'] → ['nginx', 'php']
        # ...
    """

    def __init__(self, timeout: int = 10, use_stealth_headers: bool = True):
        """
        Initialise the fingerprinter.

        Args:
            timeout: Request timeout in seconds.
            use_stealth_headers: Whether to use randomised browser headers.
        """
        self.timeout = timeout
        self.use_stealth_headers = use_stealth_headers
        self._stealth_engine: Optional[Any] = None
        if use_stealth_headers:
            try:
                from scanner.stealth_engine import StealthEngine
                self._stealth_engine = StealthEngine()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fingerprint(self, url: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return a comprehensive target fingerprint.

        Sends up to 3 baseline requests to the target to measure response
        time, detect rate limiting, and gather header intelligence.

        Args:
            url: Target URL to fingerprint.
            config: Optional configuration dict (used for ``timeout``,
                    ``verify_ssl``).

        Returns:
            Dict with the following keys:

            - ``waf_detected`` (bool): Whether a WAF was detected.
            - ``waf_name`` (Optional[str]): Name of the detected WAF, if any.
            - ``technologies`` (List[str]): Detected server technologies.
            - ``response_time_ms`` (float): Average baseline response time (ms).
            - ``has_rate_limiting`` (bool): Whether rate limiting was observed.
            - ``ssl_info`` (Dict): TLS certificate details (empty if HTTP).
            - ``server_headers`` (Dict): Raw response headers from first request.
            - ``interesting_headers`` (List[str]): Security-relevant header names.
            - ``detected_frameworks`` (List[str]): Detected web framework hints.
            - ``api_endpoints_hint`` (bool): True if JSON/API responses detected.
        """
        cfg = config or {}
        verify_ssl = cfg.get('verify_ssl', False)
        timeout = cfg.get('timeout', self.timeout)

        result: Dict[str, Any] = {
            'waf_detected': False,
            'waf_name': None,
            'technologies': [],
            'response_time_ms': 0.0,
            'has_rate_limiting': False,
            'ssl_info': {},
            'server_headers': {},
            'interesting_headers': [],
            'detected_frameworks': [],
            'api_endpoints_hint': False,
        }

        if not _HAS_REQUESTS:
            logger.warning("requests library not available; fingerprinting skipped")
            return result

        # 1. Collect baseline response times and headers
        times: List[float] = []
        status_codes: List[int] = []
        first_headers: Dict[str, str] = {}

        for i in range(3):
            try:
                t_start = time.time()
                resp = requests.get(
                    url,
                    headers=self._get_headers(),
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True,
                )
                elapsed_ms = (time.time() - t_start) * 1000.0
                times.append(elapsed_ms)
                status_codes.append(resp.status_code)
                if i == 0:
                    first_headers = dict(resp.headers)
            except Exception as exc:
                logger.debug("Fingerprint baseline request %d failed: %s", i + 1, exc)

        if not times:
            logger.debug("All fingerprint baseline requests failed for %s", url)
            return result

        result['response_time_ms'] = round(sum(times) / len(times), 2)
        result['server_headers'] = first_headers

        # 2. Rate limiting detection — look for 429 or dramatic time increases
        if 429 in status_codes:
            result['has_rate_limiting'] = True
        elif len(times) >= 3:
            # If the last request was >3× slower than the first, suspect throttling
            if times[-1] > times[0] * 3.0:
                result['has_rate_limiting'] = True

        # 3. Technology detection from headers
        result['technologies'] = self._detect_technologies(first_headers)

        # 4. WAF detection
        waf_name = self._detect_waf(first_headers)
        if waf_name:
            result['waf_detected'] = True
            result['waf_name'] = waf_name

        # 5. Interesting security headers
        result['interesting_headers'] = self._find_interesting_headers(first_headers)

        # 6. SSL info (HTTPS only)
        if url.startswith('https://'):
            result['ssl_info'] = self._get_ssl_info(url)

        # 7. Framework path probing
        detected_frameworks, api_hint = self._probe_framework_paths(url, verify_ssl, timeout)
        result['detected_frameworks'] = detected_frameworks
        result['api_endpoints_hint'] = api_hint

        logger.info(
            "Fingerprint complete for %s: techs=%s, waf=%s, rate_limit=%s",
            url,
            result['technologies'],
            result['waf_name'] or 'none',
            result['has_rate_limiting'],
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_headers(self) -> Dict[str, str]:
        """Return stealth headers or a minimal fallback set."""
        if self._stealth_engine is not None:
            try:
                return self._stealth_engine.get_randomized_headers()
            except Exception:
                pass
        return {'User-Agent': 'Mozilla/5.0 (compatible; Scanner/1.0)'}

    def _detect_technologies(self, headers: Dict[str, str]) -> List[str]:
        """Detect server technologies from response headers.

        Args:
            headers: Raw response headers dict.

        Returns:
            List of detected technology names.
        """
        detected: List[str] = []
        lowered = {k.lower(): v.lower() for k, v in headers.items()}

        search_values = ' '.join([
            lowered.get('server', ''),
            lowered.get('x-powered-by', ''),
            lowered.get('x-generator', ''),
            lowered.get('x-aspnet-version', ''),
            lowered.get('x-drupal-cache', ''),
            lowered.get('x-wordpress-version', ''),
        ])

        for tech_name, patterns in _TECH_PATTERNS.items():
            for pattern in patterns:
                if pattern in search_values:
                    if tech_name not in detected:
                        detected.append(tech_name)
                    break

        if lowered.get('x-aspnet-version'):
            if 'asp.net' not in detected:
                detected.append('asp.net')

        return detected

    def _detect_waf(self, headers: Dict[str, str]) -> Optional[str]:
        """Detect WAF from response headers using known signatures.

        Args:
            headers: Raw response headers dict.

        Returns:
            WAF name string if detected, otherwise ``None``.
        """
        lowered = {k.lower(): v.lower() for k, v in headers.items()}
        for waf_name, sigs in WAF_SIGNATURES.items():
            for header_key in sigs.get('headers', []):
                if header_key.lower() in lowered:
                    return waf_name
            server_val = lowered.get('server', '')
            for server_hint in sigs.get('server', []):
                if server_hint.lower() in server_val:
                    return waf_name
        return None

    def _find_interesting_headers(self, headers: Dict[str, str]) -> List[str]:
        """Return names of security-relevant response headers present in *headers*.

        Args:
            headers: Raw response headers dict.

        Returns:
            List of interesting header names (lowercase).
        """
        interesting = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'permissions-policy',
            'referrer-policy',
            'access-control-allow-origin',
            'x-powered-by',
            'server',
            'set-cookie',
            'www-authenticate',
        ]
        lowered_keys = {k.lower() for k in headers}
        return [h for h in interesting if h in lowered_keys]

    def _get_ssl_info(self, url: str) -> Dict[str, Any]:
        """Retrieve SSL/TLS certificate information for an HTTPS URL.

        Args:
            url: Target HTTPS URL.

        Returns:
            Dict with certificate details or empty dict on failure.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            port = parsed.port or 443
            ctx = ssl.create_default_context()
            # Intentionally bypass certificate validation: fingerprinting needs
            # to retrieve certificate metadata even from self-signed or expired
            # certificates that are common on internal/staging targets.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                    }
        except Exception as exc:
            logger.debug("SSL info retrieval failed: %s", exc)
            return {}

    def _probe_framework_paths(
        self,
        base_url: str,
        verify_ssl: bool,
        timeout: int,
    ) -> tuple:
        """Check common framework-specific paths to detect installed software.

        Args:
            base_url: Base URL (scheme + host).
            verify_ssl: Whether to verify SSL certificates.
            timeout: Request timeout in seconds.

        Returns:
            Tuple of (detected_frameworks: List[str], api_hint: bool).
        """
        detected: List[str] = []
        api_hint = False

        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for label, path in _FRAMEWORK_PATHS.items():
            probe_url = base + path
            try:
                resp = requests.get(
                    probe_url,
                    headers=self._get_headers(),
                    timeout=min(timeout, 5),
                    verify=verify_ssl,
                    allow_redirects=False,
                )
                # A non-404 response is a reasonable indicator
                if resp.status_code not in (404, 410):
                    if label not in detected:
                        detected.append(label)
                    # Detect API / JSON endpoints
                    ct = resp.headers.get('Content-Type', '').lower()
                    if 'json' in ct or 'api' in label:
                        api_hint = True
            except Exception:
                pass

        return detected, api_hint
