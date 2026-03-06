"""
Technology Fingerprinting Module

Identifies the technology stack of a target web application from HTTP
response headers, cookies, HTML meta tags, common file paths, and
JavaScript framework markers.

Features:
- HTTP header analysis (Server, X-Powered-By, X-Generator, etc.)
- Cookie-based language/framework detection
- HTML meta-tag and generator-tag parsing
- Common path probing for CMS detection
- JavaScript framework detection from ``<script>`` tags
- CDN/WAF detection via response headers
- Confidence-scored technology entries

Usage::

    from scanner.tech_fingerprinter import TechFingerprinter, TechStack

    fp = TechFingerprinter()
    stack = fp.fingerprint('https://example.com')
    print(stack.framework, stack.cms, stack.web_server)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:  # pragma: no cover
    HAS_BS4 = False


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TechEntry:
    """A single detected technology with confidence score."""
    name: str
    category: str   # e.g. 'web_server', 'framework', 'cms', 'language'
    confidence: float  # 0.0 – 1.0
    evidence: str = ''


@dataclass
class TechStack:
    """
    Complete technology stack detected for a target.

    Attributes:
        web_server: Detected web server (e.g. 'nginx', 'Apache').
        programming_language: Inferred language (e.g. 'PHP', 'Python').
        framework: Detected framework (e.g. 'Django', 'Rails').
        cms: CMS if detected (e.g. 'WordPress', 'Joomla').
        cdn_waf: CDN or WAF product (e.g. 'Cloudflare', 'Akamai').
        javascript_frameworks: List of detected JS frameworks.
        detected_technologies: Full list of all evidence-backed detections.
    """
    web_server: Optional[str] = None
    programming_language: Optional[str] = None
    framework: Optional[str] = None
    cms: Optional[str] = None
    cdn_waf: Optional[str] = None
    javascript_frameworks: List[str] = field(default_factory=list)
    detected_technologies: List[TechEntry] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'web_server': self.web_server,
            'programming_language': self.programming_language,
            'framework': self.framework,
            'cms': self.cms,
            'cdn_waf': self.cdn_waf,
            'javascript_frameworks': self.javascript_frameworks,
            'detected_technologies': [
                {
                    'name': t.name,
                    'category': t.category,
                    'confidence': t.confidence,
                    'evidence': t.evidence,
                }
                for t in self.detected_technologies
            ],
        }


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# (regex pattern, tech name, category, confidence)
_HEADER_RULES: List[Tuple[str, str, str, str, float]] = [
    # (header_name_lower, value_pattern, tech_name, category, confidence)
    ('server', r'nginx', 'nginx', 'web_server', 0.9),
    ('server', r'Apache', 'Apache', 'web_server', 0.9),
    ('server', r'Microsoft-IIS', 'IIS', 'web_server', 0.9),
    ('server', r'LiteSpeed', 'LiteSpeed', 'web_server', 0.9),
    ('server', r'Caddy', 'Caddy', 'web_server', 0.9),
    ('server', r'lighttpd', 'lighttpd', 'web_server', 0.9),
    ('server', r'gunicorn', 'Gunicorn', 'web_server', 0.85),
    ('server', r'uvicorn', 'Uvicorn', 'web_server', 0.85),
    ('x-powered-by', r'PHP/?([\d.]+)?', 'PHP', 'language', 0.95),
    ('x-powered-by', r'ASP\.NET', 'ASP.NET', 'framework', 0.95),
    ('x-powered-by', r'Express', 'Express', 'framework', 0.9),
    ('x-powered-by', r'Next\.js', 'Next.js', 'framework', 0.9),
    ('x-powered-by', r'Nuxt', 'Nuxt', 'framework', 0.9),
    ('x-aspnet-version', r'.+', 'ASP.NET', 'framework', 0.95),
    ('x-aspnetmvc-version', r'.+', 'ASP.NET MVC', 'framework', 0.95),
    ('x-generator', r'WordPress', 'WordPress', 'cms', 0.95),
    ('x-generator', r'Drupal', 'Drupal', 'cms', 0.95),
    ('x-generator', r'Joomla', 'Joomla', 'cms', 0.95),
    ('x-drupal-cache', r'.+', 'Drupal', 'cms', 0.9),
    ('x-wp-total', r'.+', 'WordPress', 'cms', 0.9),
    ('cf-ray', r'.+', 'Cloudflare', 'cdn_waf', 0.99),
    ('x-amz-cf-id', r'.+', 'AWS CloudFront', 'cdn_waf', 0.99),
    ('x-cache', r'HIT|MISS', 'Generic CDN', 'cdn_waf', 0.6),
    ('via', r'1\.1 varnish', 'Varnish', 'cdn_waf', 0.85),
    ('x-sucuri-id', r'.+', 'Sucuri WAF', 'cdn_waf', 0.99),
    ('x-fw-server', r'.+', 'Fastly', 'cdn_waf', 0.9),
    ('x-akamai-request-id', r'.+', 'Akamai', 'cdn_waf', 0.99),
]

_COOKIE_RULES: List[Tuple[str, str, str, float]] = [
    # (cookie_name_pattern, tech_name, category, confidence)
    (r'PHPSESSID', 'PHP', 'language', 0.85),
    (r'csrftoken', 'Django', 'framework', 0.85),
    (r'sessionid', 'Django', 'framework', 0.7),
    (r'JSESSIONID', 'Java (Servlet)', 'language', 0.85),
    (r'ASP\.NET_SessionId', 'ASP.NET', 'framework', 0.95),
    (r'__RequestVerificationToken', 'ASP.NET MVC', 'framework', 0.9),
    (r'laravel_session', 'Laravel', 'framework', 0.95),
    (r'wordpress_logged_in', 'WordPress', 'cms', 0.99),
    (r'wp-settings', 'WordPress', 'cms', 0.95),
    (r'Drupal\.visitor', 'Drupal', 'cms', 0.9),
    (r'ci_session', 'CodeIgniter', 'framework', 0.85),
    (r'rack\.session', 'Ruby (Rack)', 'language', 0.8),
    (r'_rails_session', 'Ruby on Rails', 'framework', 0.95),
    (r'connect\.sid', 'Node.js (Connect)', 'framework', 0.85),
]

_PATH_PROBES: List[Tuple[str, str, str, float]] = [
    # (path, tech_name, category, confidence)
    ('/wp-content/', 'WordPress', 'cms', 0.99),
    ('/wp-admin/', 'WordPress', 'cms', 0.99),
    ('/wp-login.php', 'WordPress', 'cms', 0.99),
    ('/administrator/', 'Joomla', 'cms', 0.9),
    ('/components/com_', 'Joomla', 'cms', 0.95),
    ('/sites/default/', 'Drupal', 'cms', 0.9),
    ('/typo3/', 'TYPO3', 'cms', 0.95),
    ('/magento/', 'Magento', 'cms', 0.9),
    ('/mage/', 'Magento', 'cms', 0.85),
    ('/index.php/api/', 'Magento', 'cms', 0.8),
]

_HTML_PATTERNS: List[Tuple[str, str, str, float]] = [
    # (regex on full HTML, tech_name, category, confidence)
    (r'wp-content|wp-includes', 'WordPress', 'cms', 0.9),
    (r'Drupal\.settings|drupal\.js', 'Drupal', 'cms', 0.9),
    (r'Joomla!', 'Joomla', 'cms', 0.9),
    (r'<meta[^>]+generator[^>]+WordPress', 'WordPress', 'cms', 0.99),
    (r'<meta[^>]+generator[^>]+Joomla', 'Joomla', 'cms', 0.99),
    (r'<meta[^>]+generator[^>]+Drupal', 'Drupal', 'cms', 0.99),
    (r'ng-app|ng-controller|angular\.js', 'AngularJS', 'js_framework', 0.8),
    (r'data-reactroot|__NEXT_DATA__|_next/static', 'React/Next.js', 'js_framework', 0.85),
    (r'__NUXT__|nuxt\.js', 'Vue/Nuxt.js', 'js_framework', 0.85),
    (r'vue\.js|Vue\.component', 'Vue.js', 'js_framework', 0.8),
    (r'ember\.js|Ember\.Application', 'Ember.js', 'js_framework', 0.8),
    (r'backbone\.js|Backbone\.Model', 'Backbone.js', 'js_framework', 0.8),
    (r'jquery(?:\.min)?\.js|jQuery\.fn', 'jQuery', 'js_framework', 0.7),
    (r'bootstrap(?:\.min)?\.js|bootstrap(?:\.min)?\.css', 'Bootstrap', 'js_framework', 0.7),
    (r'__DJANGO_STATIC__|csrfmiddlewaretoken', 'Django', 'framework', 0.8),
    (r'Powered by <a[^>]*>Ruby on Rails', 'Ruby on Rails', 'framework', 0.95),
    (r'laravel|Laravel', 'Laravel', 'framework', 0.75),
]

_JS_SCRIPT_PATTERNS: List[Tuple[str, str, str, float]] = [
    # (regex on script src/content, tech_name, category, confidence)
    (r'react(?:\.min)?\.js|react-dom', 'React', 'js_framework', 0.9),
    (r'angular(?:\.min)?\.js', 'AngularJS', 'js_framework', 0.9),
    (r'vue(?:\.min)?\.js', 'Vue.js', 'js_framework', 0.9),
    (r'next(?:\.min)?\.js|/_next/', 'Next.js', 'js_framework', 0.9),
    (r'nuxt(?:\.min)?\.js', 'Nuxt.js', 'js_framework', 0.9),
    (r'svelte(?:\.min)?\.js', 'Svelte', 'js_framework', 0.9),
    (r'ember(?:\.min)?\.js', 'Ember.js', 'js_framework', 0.9),
    (r'backbone(?:\.min)?\.js', 'Backbone.js', 'js_framework', 0.9),
    (r'jquery(?:\.min)?\.js', 'jQuery', 'js_framework', 0.8),
    (r'bootstrap(?:\.min)?\.js', 'Bootstrap', 'js_framework', 0.8),
    (r'tailwind(?:\.min)?\.css', 'Tailwind CSS', 'js_framework', 0.8),
    (r'lodash(?:\.min)?\.js', 'Lodash', 'js_framework', 0.7),
    (r'moment(?:\.min)?\.js', 'Moment.js', 'js_framework', 0.7),
    (r'axios(?:\.min)?\.js', 'Axios', 'js_framework', 0.7),
]


# ---------------------------------------------------------------------------
# TechFingerprinter
# ---------------------------------------------------------------------------

class TechFingerprinter:
    """
    Detect the technology stack of a target web application.

    Args:
        timeout: Per-request timeout in seconds (default: 10).
        verify_ssl: Verify TLS certificates (default: False).
        probe_paths: Whether to probe known CMS paths (default: False).
        session: Optional pre-configured ``requests.Session``.
    """

    def __init__(
        self,
        timeout: int = 10,
        verify_ssl: bool = False,
        probe_paths: bool = False,
        session: Optional['requests.Session'] = None,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.probe_paths = probe_paths
        self._session = session

    def fingerprint(self, url: str) -> TechStack:
        """
        Fingerprint the technology stack at *url*.

        Args:
            url: Target URL.

        Returns:
            :class:`TechStack` with all detected technologies.
        """
        if not HAS_REQUESTS:
            logger.error("requests library not available; fingerprinting aborted")
            return TechStack()

        session = self._session or self._build_session()
        try:
            response = session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to fetch %s for fingerprinting: %s", url, exc)
            return TechStack()

        entries: List[TechEntry] = []
        entries.extend(self._from_headers(response.headers))
        entries.extend(self._from_cookies(response.cookies))
        entries.extend(self._from_html(response.text))

        if self.probe_paths:
            from urllib.parse import urlparse as _up
            base = _up(url)
            base_url = f"{base.scheme}://{base.netloc}"
            entries.extend(self._from_path_probes(base_url, session))

        return self._build_stack(entries)

    def fingerprint_from_response(
        self,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        html: str,
    ) -> TechStack:
        """
        Fingerprint without making a network request; use provided data.

        Useful for integration with a crawl result or proxy interceptor.
        """
        entries: List[TechEntry] = []
        entries.extend(self._from_headers(headers))
        entries.extend(self._from_cookies_dict(cookies))
        entries.extend(self._from_html(html))
        return self._build_stack(entries)

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _from_headers(self, headers) -> List[TechEntry]:
        """Analyse HTTP response headers."""
        entries: List[TechEntry] = []
        headers_lower = {k.lower(): v for k, v in dict(headers).items()}

        for header_name, value_pattern, tech_name, category, confidence in _HEADER_RULES:
            value = headers_lower.get(header_name, '')
            if value and re.search(value_pattern, value, re.IGNORECASE):
                entries.append(TechEntry(
                    name=tech_name,
                    category=category,
                    confidence=confidence,
                    evidence=f"Header {header_name}: {value[:80]}",
                ))
        return entries

    def _from_cookies(self, cookies) -> List[TechEntry]:
        """Analyse response cookies (requests.cookies.RequestsCookieJar)."""
        return self._from_cookies_dict({c.name: c.value for c in cookies})

    def _from_cookies_dict(self, cookies: Dict[str, str]) -> List[TechEntry]:
        """Analyse a plain cookie name→value mapping."""
        entries: List[TechEntry] = []
        for cookie_name in cookies:
            for pattern, tech_name, category, confidence in _COOKIE_RULES:
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    entries.append(TechEntry(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        evidence=f"Cookie: {cookie_name}",
                    ))
        return entries

    def _from_html(self, html: str) -> List[TechEntry]:
        """Analyse HTML body for technology markers."""
        entries: List[TechEntry] = []

        # Full-body pattern matching
        for pattern, tech_name, category, confidence in _HTML_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                match = re.search(pattern, html, re.IGNORECASE)
                evidence = match.group(0)[:80] if match else ''
                entries.append(TechEntry(
                    name=tech_name,
                    category=category,
                    confidence=confidence,
                    evidence=f"HTML pattern: {evidence}",
                ))

        # Script src analysis
        for src_match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = src_match.group(1)
            for pattern, tech_name, category, confidence in _JS_SCRIPT_PATTERNS:
                if re.search(pattern, src, re.IGNORECASE):
                    entries.append(TechEntry(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        evidence=f"Script src: {src[:80]}",
                    ))

        return entries

    def _from_path_probes(
        self, base_url: str, session: 'requests.Session'
    ) -> List[TechEntry]:
        """Probe known CMS paths to infer technology."""
        entries: List[TechEntry] = []
        for path, tech_name, category, confidence in _PATH_PROBES:
            probe_url = base_url.rstrip('/') + path
            try:
                resp = session.get(
                    probe_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )
                if resp.status_code not in (404, 410):
                    entries.append(TechEntry(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        evidence=f"Path probe: {path} → HTTP {resp.status_code}",
                    ))
            except Exception:  # noqa: BLE001
                pass
        return entries

    # ------------------------------------------------------------------
    # Stack builder
    # ------------------------------------------------------------------

    def _build_stack(self, entries: List[TechEntry]) -> TechStack:
        """Aggregate raw detection entries into a coherent TechStack."""
        # Deduplicate: keep highest-confidence entry per tech name
        best: Dict[str, TechEntry] = {}
        for entry in entries:
            key = entry.name.lower()
            if key not in best or entry.confidence > best[key].confidence:
                best[key] = entry

        unique = list(best.values())

        stack = TechStack(detected_technologies=unique)

        def _pick(category: str) -> Optional[str]:
            candidates = [e for e in unique if e.category == category]
            if not candidates:
                return None
            return max(candidates, key=lambda e: e.confidence).name

        stack.web_server = _pick('web_server')
        stack.programming_language = _pick('language')
        stack.framework = _pick('framework')
        stack.cms = _pick('cms')
        stack.cdn_waf = _pick('cdn_waf')
        stack.javascript_frameworks = sorted(
            {e.name for e in unique if e.category == 'js_framework'},
            key=lambda n: -max(e.confidence for e in unique if e.name == n),
        )

        logger.info(
            "TechFingerprinter: server=%s lang=%s framework=%s cms=%s cdn_waf=%s js=%s",
            stack.web_server,
            stack.programming_language,
            stack.framework,
            stack.cms,
            stack.cdn_waf,
            stack.javascript_frameworks,
        )
        return stack

    @staticmethod
    def _build_session() -> 'requests.Session':
        session = requests.Session()
        session.headers['User-Agent'] = (
            'Mozilla/5.0 (compatible; MegidoScanner/5.0; +https://github.com/tkstanch/Megido)'
        )
        return session
