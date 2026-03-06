"""
403 Forbidden Bypass Detector Plugin

Detects cases where a 403 Forbidden response can be bypassed using known access-control
evasion techniques. The plugin categorises bypass attempts into six groups:

  1. HTTP Method Tampering         – try alternate HTTP verbs and override headers
  2. Path Manipulation             – normalisation tricks (double-slash, encoded dots, …)
  3. Header-Based Bypasses         – reverse-proxy / WAF header spoofing
  4. Protocol-Level Tricks         – CRLF injection, HTTP/1.0 downgrade
  5. Reverse-Proxy Chain Escapes   – combined header sets and alternate Host values
  6. Service-Mesh / Internal-Routing – internal Host names and service-router headers

Classification:
  CWE-284 (Improper Access Control)

Severity:
  critical – full admin panel access confirmed (path contains 'admin', 'root', etc.)
  high     – sensitive path bypass confirmed
  medium   – directory existence confirmation (e.g. 301 / 302 redirect)
"""

import logging
import random
import time
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding
from scanner.scan_plugins.vpoc_mixin import VPoCDetectorMixin


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_ADMIN_KEYWORDS = [
    'admin', 'administrator', 'root', 'superuser', 'management',
    'console', 'dashboard', 'panel', 'control', 'config', 'setup',
]

_SENSITIVE_KEYWORDS = [
    'api', 'secret', 'private', 'internal', 'secure', 'auth',
    'login', 'user', 'account', 'profile', 'token', 'key',
]

_SUCCESS_CODES = {200, 201, 301, 302, 307}


def _severity_for_path(path: str) -> str:
    """Return a severity level based on the requested path."""
    lower = path.lower()
    for kw in _ADMIN_KEYWORDS:
        if kw in lower:
            return 'critical'
    for kw in _SENSITIVE_KEYWORDS:
        if kw in lower:
            return 'high'
    return 'medium'


def _build_remediation(technique: str, bypass_url: str) -> str:
    return (
        f"A 403 Forbidden response was bypassed using: {technique}. "
        "To remediate: (1) enforce access control at the application layer, not only at the "
        "WAF or reverse-proxy layer; (2) canonicalise paths before applying ACL rules; "
        "(3) reject unexpected HTTP methods server-side; (4) strip or ignore spoofed "
        "forwarding headers (X-Forwarded-For, X-Original-URL, etc.) from untrusted clients; "
        "(5) use a deny-by-default ACL policy so unrecognised requests are rejected."
    )


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class ForbiddenBypassDetectorPlugin(VPoCDetectorMixin, BaseScanPlugin):
    """
    Detects 403 Forbidden bypass vulnerabilities via multiple evasion categories.

    The plugin first checks whether the target URL returns 403.  If it does, it
    systematically tries the six bypass categories and records a VulnerabilityFinding
    for every technique that produces a success status code.
    """

    # -----------------------------------------------------------------------
    # Plugin identity
    # -----------------------------------------------------------------------

    @property
    def plugin_id(self) -> str:
        return 'forbidden_bypass_detector'

    @property
    def name(self) -> str:
        return '403 Forbidden Bypass Detector'

    @property
    def description(self) -> str:
        return (
            'Detects 403 Forbidden bypass vulnerabilities via HTTP method tampering, '
            'path normalisation tricks, header injection, protocol-level tricks, '
            'reverse-proxy chain escapes, and service-mesh routing bypasses (CWE-284)'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['access_control', 'forbidden_bypass']

    # -----------------------------------------------------------------------
    # Default config
    # -----------------------------------------------------------------------

    def get_default_config(self) -> Dict[str, Any]:
        return {
            'verify_ssl': False,
            'timeout': 10,
            # Category toggles
            'check_method_tampering': True,
            'check_path_manipulation': True,
            'check_header_bypass': True,
            'check_protocol_tricks': True,
            'check_proxy_chain': True,
            'check_service_mesh': True,
            # Stealth options
            'delay_between_attempts': 0.0,   # seconds; increase for stealth
            'randomize_order': False,
        }

    # -----------------------------------------------------------------------
    # Main scan entry-point
    # -----------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan the target URL for 403 bypass opportunities.

        Args:
            url:    Target URL (e.g. https://example.com/admin)
            config: Optional configuration dict (see get_default_config).

        Returns:
            List of VulnerabilityFinding instances – one per successful bypass technique.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping forbidden-bypass scan")
            return []

        cfg = {**self.get_default_config(), **(config or {})}
        findings: List[VulnerabilityFinding] = []

        # Step 1: Confirm the URL returns 403.
        try:
            baseline = requests.get(
                url,
                timeout=cfg['timeout'],
                verify=cfg['verify_ssl'],
                allow_redirects=False,
            )
        except Exception as exc:
            logger.debug("Baseline request to %s failed: %s", url, exc)
            return []

        if baseline.status_code != 403:
            logger.debug(
                "URL %s returned %d (not 403) – skipping bypass checks",
                url, baseline.status_code,
            )
            return []

        logger.info("403 confirmed on %s – attempting bypass techniques", url)

        parsed = urllib.parse.urlparse(url)
        path = parsed.path or '/'

        delay = cfg.get('delay_between_attempts', 0.0)

        # Collect (technique_name, callable) pairs
        categories: List[Tuple[str, Any]] = []

        if cfg.get('check_method_tampering', True):
            categories.append(('Method Tampering', lambda: self._check_method_tampering(url, cfg)))
        if cfg.get('check_path_manipulation', True):
            categories.append(('Path Manipulation', lambda: self._check_path_manipulation(url, path, parsed, cfg)))
        if cfg.get('check_header_bypass', True):
            categories.append(('Header Bypass', lambda: self._check_header_bypass(url, path, cfg)))
        if cfg.get('check_protocol_tricks', True):
            categories.append(('Protocol Tricks', lambda: self._check_protocol_tricks(url, path, cfg)))
        if cfg.get('check_proxy_chain', True):
            categories.append(('Proxy Chain Escape', lambda: self._check_proxy_chain(url, path, cfg)))
        if cfg.get('check_service_mesh', True):
            categories.append(('Service Mesh Bypass', lambda: self._check_service_mesh(url, path, cfg)))

        if cfg.get('randomize_order', False):
            random.shuffle(categories)

        for category_name, check_fn in categories:
            try:
                category_findings = check_fn()
                findings.extend(category_findings)
                if delay > 0:
                    time.sleep(delay)
            except Exception as exc:
                logger.error("Error in category '%s' for %s: %s", category_name, url, exc)

        logger.info(
            "Forbidden bypass scan of %s completed – %d bypass(es) found",
            url, len(findings),
        )
        return findings

    # -----------------------------------------------------------------------
    # Category 1: HTTP Method Tampering
    # -----------------------------------------------------------------------

    def _check_method_tampering(self, url: str, cfg: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Try alternate HTTP methods and override headers."""
        findings: List[VulnerabilityFinding] = []
        timeout = cfg['timeout']
        verify = cfg['verify_ssl']

        alternate_methods = ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE']
        override_headers = ['X-HTTP-Method-Override', 'X-Method-Override']

        # 1a. Try alternate HTTP methods directly
        for method in alternate_methods:
            try:
                resp = requests.request(
                    method, url,
                    timeout=timeout, verify=verify, allow_redirects=False,
                )
                if resp.status_code in _SUCCESS_CODES:
                    technique = f"HTTP method changed to {method}"
                    logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                    _f = self._make_finding(
                        url=url,
                        technique=technique,
                        bypass_url=url,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        body_preview=resp.text[:500] if resp.text else '',
                        category='Method Tampering',
                    )
                    self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                    findings.append(_f)
            except Exception as exc:
                logger.debug("Method %s on %s failed: %s", method, url, exc)

        # 1b. X-HTTP-Method-Override and X-Method-Override with alternate methods
        for override_header in override_headers:
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                try:
                    resp = requests.request(
                        'GET', url,
                        headers={override_header: method},
                        timeout=timeout, verify=verify, allow_redirects=False,
                    )
                    if resp.status_code in _SUCCESS_CODES:
                        technique = f"{override_header}: {method} override header"
                        logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                        _f = self._make_finding(
                            url=url,
                            technique=technique,
                            bypass_url=url,
                            status_code=resp.status_code,
                            response_headers=dict(resp.headers),
                            body_preview=resp.text[:500] if resp.text else '',
                            category='Method Tampering',
                        )
                        self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                        findings.append(_f)
                except Exception as exc:
                    logger.debug("Override header %s=%s on %s failed: %s",
                                 override_header, method, url, exc)

        return findings

    # -----------------------------------------------------------------------
    # Category 2: Path Manipulation / Normalisation Bypasses
    # -----------------------------------------------------------------------

    def _check_path_manipulation(
        self, url: str, path: str, parsed: urllib.parse.ParseResult, cfg: Dict[str, Any]
    ) -> List[VulnerabilityFinding]:
        """Try path variations that may bypass ACL rules."""
        findings: List[VulnerabilityFinding] = []
        timeout = cfg['timeout']
        verify = cfg['verify_ssl']
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Strip leading slash for use in patterns below
        bare = path.rstrip('/')

        # Build candidate paths (deduplicated via dict to preserve order)
        bare_no_slash = bare.lstrip('/')
        mixed_case = (bare[0].upper() + bare[1:].lower()) if len(bare) > 1 else bare.upper()
        _variants_ordered = [
            (f"{bare}..;/",            "Tomcat/Spring path traversal"),
            (f"/%2e/{bare_no_slash}",  "URL-encoded dot (/./ traversal)"),
            (f"{bare}%20",             "trailing space"),
            (f"{bare}%09",             "trailing tab"),
            (f"{bare}.",               "trailing dot"),
            (f"{bare}/",               "trailing slash"),
            (f"//{bare_no_slash}",     "double slash"),
            (f"/.{bare}",              "current directory prefix"),
            (f"{bare}..",              "double dot suffix"),
            (bare.upper(),             "uppercase"),
            (mixed_case,               "mixed case"),
            (f"/;{bare_no_slash}",     "semicolon prefix"),
            (f"/..;{bare}",            "Spring semicolon bypass"),
            (f"/.;{bare}",             "dot-semicolon"),
            (f"{bare};/",              "trailing semicolon"),
        ]
        # Deduplicate while preserving order
        seen: set = set()
        path_variants = []
        for v_path, _ in _variants_ordered:
            if v_path not in seen:
                seen.add(v_path)
                path_variants.append(v_path)

        for variant_path in path_variants:
            variant_url = base + variant_path
            if variant_url == url:
                continue
            try:
                resp = requests.get(
                    variant_url,
                    timeout=timeout, verify=verify, allow_redirects=False,
                )
                if resp.status_code in _SUCCESS_CODES:
                    technique = f"Path manipulation: {variant_path}"
                    logger.info("Bypass found [%s]: %s → %d", technique, variant_url, resp.status_code)
                    _f = self._make_finding(
                        url=url,
                        technique=technique,
                        bypass_url=variant_url,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        body_preview=resp.text[:500] if resp.text else '',
                        category='Path Manipulation',
                    )
                    self._attach_vpoc(_f, resp, variant_url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                    findings.append(_f)
            except Exception as exc:
                logger.debug("Path variant %s on %s failed: %s", variant_url, url, exc)

        return findings

    # -----------------------------------------------------------------------
    # Category 3: Header-Based Bypasses
    # -----------------------------------------------------------------------

    def _check_header_bypass(self, url: str, path: str, cfg: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Inject reverse-proxy / WAF spoofing headers."""
        findings: List[VulnerabilityFinding] = []
        timeout = cfg['timeout']
        verify = cfg['verify_ssl']

        header_sets = [
            {'X-Original-URL': path},
            {'X-Rewrite-URL': path},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-Forwarded-Port': '443'},
            {'X-Forwarded-Port': '80'},
            {'X-Forwarded-Scheme': 'https'},
            {'X-ProxyUser-Ip': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'Cluster-Client-IP': '127.0.0.1'},
            {'X-Accel-Redirect': path},
            {'X-Forwarded-Path': path},
            {'Content-Length': '0'},
        ]

        for headers in header_sets:
            header_desc = ', '.join(f"{k}: {v}" for k, v in headers.items())
            try:
                method = 'POST' if 'Content-Length' in headers else 'GET'
                resp = requests.request(
                    method, url,
                    headers=headers,
                    timeout=timeout, verify=verify, allow_redirects=False,
                )
                if resp.status_code in _SUCCESS_CODES:
                    technique = f"Header bypass: {header_desc}"
                    logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                    _f = self._make_finding(
                        url=url,
                        technique=technique,
                        bypass_url=url,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        body_preview=resp.text[:500] if resp.text else '',
                        category='Header Bypass',
                    )
                    self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                    findings.append(_f)
            except Exception as exc:
                logger.debug("Header set [%s] on %s failed: %s", header_desc, url, exc)

        return findings

    # -----------------------------------------------------------------------
    # Category 4: Protocol-Level Tricks
    # -----------------------------------------------------------------------

    def _check_protocol_tricks(self, url: str, path: str, cfg: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """CRLF injection into path, HTTP/1.0 downgrade."""
        findings: List[VulnerabilityFinding] = []
        timeout = cfg['timeout']
        verify = cfg['verify_ssl']

        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 4a. CRLF into Rewrite Bypass
        crlf_path = path + '%0d%0aX-Rewrite-URL:%20' + urllib.parse.quote(path)
        crlf_url = base + crlf_path
        try:
            resp = requests.get(
                crlf_url,
                timeout=timeout, verify=verify, allow_redirects=False,
            )
            if resp.status_code in _SUCCESS_CODES:
                technique = "CRLF injection into URL path (X-Rewrite-URL bypass)"
                logger.info("Bypass found [%s]: %s → %d", technique, crlf_url, resp.status_code)
                _f = self._make_finding(
                    url=url,
                    technique=technique,
                    bypass_url=crlf_url,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    body_preview=resp.text[:500] if resp.text else '',
                    category='Protocol Tricks',
                )
                self._attach_vpoc(_f, resp, crlf_url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                findings.append(_f)
        except Exception as exc:
            logger.debug("CRLF bypass on %s failed: %s", crlf_url, exc)

        # 4b. HTTP/1.0 downgrade (via requests with explicit HTTP version isn't
        #     directly supported; we approximate by clearing connection headers)
        try:
            resp = requests.get(
                url,
                headers={'Connection': 'close', 'Cache-Control': 'no-cache'},
                timeout=timeout, verify=verify, allow_redirects=False,
            )
            if resp.status_code in _SUCCESS_CODES:
                technique = "HTTP/1.0 downgrade (Connection: close)"
                logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                _f = self._make_finding(
                    url=url,
                    technique=technique,
                    bypass_url=url,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    body_preview=resp.text[:500] if resp.text else '',
                    category='Protocol Tricks',
                )
                self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                findings.append(_f)
        except Exception as exc:
            logger.debug("HTTP/1.0 downgrade on %s failed: %s", url, exc)

        return findings

    # -----------------------------------------------------------------------
    # Category 5: Reverse Proxy Chain Escapes
    # -----------------------------------------------------------------------

    def _check_proxy_chain(self, url: str, path: str, cfg: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Combine proxy-escape headers; test alternate Host header values."""
        findings: List[VulnerabilityFinding] = []
        timeout = cfg['timeout']
        verify = cfg['verify_ssl']

        combined_headers = {
            'X-Accel-Redirect': path,
            'X-Forwarded-Path': path,
            'X-Original-URL': path,
            'X-Rewrite-URL': path,
        }

        # 5a. Combined proxy headers
        try:
            resp = requests.get(
                url,
                headers=combined_headers,
                timeout=timeout, verify=verify, allow_redirects=False,
            )
            if resp.status_code in _SUCCESS_CODES:
                technique = "Combined proxy-escape headers (X-Accel-Redirect + X-Forwarded-Path + X-Original-URL + X-Rewrite-URL)"
                logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                _f = self._make_finding(
                    url=url,
                    technique=technique,
                    bypass_url=url,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    body_preview=resp.text[:500] if resp.text else '',
                    category='Proxy Chain Escape',
                )
                self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                findings.append(_f)
        except Exception as exc:
            logger.debug("Combined proxy headers on %s failed: %s", url, exc)

        # 5b. Alternate Host header values
        host_values = ['localhost', '127.0.0.1', 'internal', 'admin.internal.svc.cluster.local']
        for host in host_values:
            try:
                resp = requests.get(
                    url,
                    headers={'Host': host},
                    timeout=timeout, verify=verify, allow_redirects=False,
                )
                if resp.status_code in _SUCCESS_CODES:
                    technique = f"Alternate Host header: Host: {host}"
                    logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                    _f = self._make_finding(
                        url=url,
                        technique=technique,
                        bypass_url=url,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        body_preview=resp.text[:500] if resp.text else '',
                        category='Proxy Chain Escape',
                    )
                    self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                    findings.append(_f)
            except Exception as exc:
                logger.debug("Host header %s on %s failed: %s", host, url, exc)

        return findings

    # -----------------------------------------------------------------------
    # Category 6: Service Mesh / Internal Routing Bypass
    # -----------------------------------------------------------------------

    def _check_service_mesh(self, url: str, path: str, cfg: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test internal-style Host names and X-Service-Router header."""
        findings: List[VulnerabilityFinding] = []
        timeout = cfg['timeout']
        verify = cfg['verify_ssl']

        internal_hosts = [
            'admin.internal.svc.cluster.local',
            'admin.internal',
        ]

        for host in internal_hosts:
            try:
                resp = requests.get(
                    url,
                    headers={'Host': host},
                    timeout=timeout, verify=verify, allow_redirects=False,
                )
                if resp.status_code in _SUCCESS_CODES:
                    technique = f"Service mesh internal Host header: Host: {host}"
                    logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                    _f = self._make_finding(
                        url=url,
                        technique=technique,
                        bypass_url=url,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        body_preview=resp.text[:500] if resp.text else '',
                        category='Service Mesh Bypass',
                    )
                    self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                    findings.append(_f)
            except Exception as exc:
                logger.debug("Service mesh Host %s on %s failed: %s", host, url, exc)

        # X-Service-Router header
        try:
            resp = requests.get(
                url,
                headers={'X-Service-Router': 'admin'},
                timeout=timeout, verify=verify, allow_redirects=False,
            )
            if resp.status_code in _SUCCESS_CODES:
                technique = "X-Service-Router: admin header"
                logger.info("Bypass found [%s]: %s → %d", technique, url, resp.status_code)
                _f = self._make_finding(
                    url=url,
                    technique=technique,
                    bypass_url=url,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    body_preview=resp.text[:500] if resp.text else '',
                    category='Service Mesh Bypass',
                )
                self._attach_vpoc(_f, resp, url, 0.85, reproduction_steps="1. Send request to restricted path\n2. Observe 403 bypass with alternate technique")
                findings.append(_f)
        except Exception as exc:
            logger.debug("X-Service-Router on %s failed: %s", url, exc)

        return findings

    # -----------------------------------------------------------------------
    # Finding factory
    # -----------------------------------------------------------------------

    def _make_finding(
        self,
        url: str,
        technique: str,
        bypass_url: str,
        status_code: int,
        response_headers: Dict[str, str],
        body_preview: str,
        category: str,
    ) -> VulnerabilityFinding:
        """Construct a VulnerabilityFinding for a successful bypass."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or '/'
        severity = _severity_for_path(path)

        evidence = (
            f"Bypass technique: {technique}\n"
            f"Original URL (403): {url}\n"
            f"Bypass URL: {bypass_url}\n"
            f"Response status: {status_code}\n"
            f"Category: {category}\n"
            f"Response headers (partial): {dict(list(response_headers.items())[:5])}\n"
            f"Body preview: {body_preview[:300]}"
        )

        return VulnerabilityFinding(
            vulnerability_type='forbidden_bypass',
            severity=severity,
            url=url,
            description=(
                f"403 Forbidden bypass confirmed via {category}. "
                f"Technique: {technique}. "
                f"Bypass URL returned HTTP {status_code}."
            ),
            evidence=evidence,
            remediation=_build_remediation(technique, bypass_url),
            confidence=0.9,
            cwe_id='CWE-284',
        )
