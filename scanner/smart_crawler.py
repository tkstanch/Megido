"""
Smart Recursive Crawler

Dramatically improves attack surface discovery beyond the basic ``Crawler``.

Features:
- Recursive crawling with configurable depth and URL caps
- robots.txt and sitemap.xml parsing
- JavaScript link and API endpoint extraction via regex
- Form action discovery
- URL normalisation and deduplication
- Scope enforcement (stays on target domain)
- Configurable rate limiting
- Priority queue (parameters > login pages > API endpoints > other)

Usage::

    from scanner.smart_crawler import SmartCrawler, CrawlResult

    crawler = SmartCrawler(max_depth=3, max_urls=500, delay=0.1)
    result = crawler.crawl('https://example.com')
    print(result.urls)
    print(result.forms)
    print(result.api_endpoints)
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    parse_qs,
    urlencode,
)

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
class FormInfo:
    """Metadata about a discovered HTML form."""
    url: str
    action: str
    method: str
    fields: List[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    """
    Structured result from SmartCrawler.

    Attributes:
        urls: All in-scope URLs discovered (normalised, deduplicated).
        forms: Metadata for every HTML form found.
        api_endpoints: URLs that appear to be API endpoints.
        javascript_files: ``.js`` resource URLs.
        parameters_found: Mapping of URL → list of query-parameter names.
        errors: Per-URL errors encountered during crawling.
    """
    urls: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    javascript_files: List[str] = field(default_factory=list)
    parameters_found: Dict[str, List[str]] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Priority helpers
# ---------------------------------------------------------------------------

_HIGH_VALUE_PATTERNS = re.compile(
    r'(login|signin|admin|dashboard|upload|api|graphql|search|register|'
    r'checkout|account|profile|password|reset|token|key|secret)',
    re.IGNORECASE,
)

_JS_URL_PATTERNS = [
    # Absolute or root-relative URLs in string literals
    re.compile(r'''(?:"|')(/(?:api|v\d+|rest|graphql)[^"'?#\s]*?)(?:"|')'''),
    # fetch / axios / XHR calls
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*(?:"|')([^"']+)(?:"|')'''),
    # href / src attributes inside JS strings
    re.compile(r'''(?:href|src|url)\s*[=:]\s*(?:"|')([^"']+)(?:"|')'''),
]

_API_PATH_RE = re.compile(r'/(?:api|v\d+|rest|graphql)/', re.IGNORECASE)


def _url_priority(url: str) -> int:
    """Return a priority score for a URL (higher → scan first)."""
    parsed = urlparse(url)
    path = parsed.path
    score = 0
    if parsed.query:
        score += 30          # URLs with parameters are high-value targets
    if _HIGH_VALUE_PATTERNS.search(path):
        score += 20
    if _API_PATH_RE.search(path):
        score += 15
    return score


# ---------------------------------------------------------------------------
# SmartCrawler
# ---------------------------------------------------------------------------

class SmartCrawler:
    """
    Smart recursive web crawler for attack surface discovery.

    Args:
        max_depth: Maximum recursion depth (default: 3).
        max_urls: Maximum number of URLs to visit (default: 500).
        delay: Seconds to wait between requests (default: 0.1).
        timeout: Per-request timeout in seconds (default: 10).
        verify_ssl: Verify TLS certificates (default: False).
        session: Optional pre-configured ``requests.Session``.
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_urls: int = 500,
        delay: float = 0.1,
        timeout: int = 10,
        verify_ssl: bool = False,
        session: Optional['requests.Session'] = None,
    ) -> None:
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._session = session

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl ``start_url`` recursively.

        Args:
            start_url: Seed URL for the crawl.

        Returns:
            :class:`CrawlResult` with all discovered attack surface.
        """
        if not HAS_REQUESTS:
            logger.error("requests library is not available; crawl aborted")
            return CrawlResult()

        result = CrawlResult()
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        visited: Set[str] = set()
        # Priority queue implemented as a list sorted by priority descending.
        # Each entry: (priority, depth, url)
        queue: List[Tuple[int, int, str]] = [(-_url_priority(start_url), 0, start_url)]

        # Seed with robots.txt and sitemap URLs
        self._seed_from_robots(start_url, base_domain, queue, visited)

        session = self._get_session()

        while queue and len(visited) < self.max_urls:
            queue.sort(key=lambda x: x[0])  # sort ascending (negative priority → high first)
            _, depth, url = queue.pop(0)

            norm_url = self._normalize_url(url)
            if norm_url in visited:
                continue
            if not self._in_scope(norm_url, base_domain):
                continue

            visited.add(norm_url)
            if norm_url not in result.urls:
                result.urls.append(norm_url)

            if depth >= self.max_depth:
                continue

            # Fetch the page
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                response = session.get(
                    norm_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Error fetching %s: %s", norm_url, exc)
                result.errors[norm_url] = str(exc)
                continue

            content_type = response.headers.get('Content-Type', '')

            # Record parameters
            params = self._extract_params(norm_url)
            if params:
                result.parameters_found[norm_url] = params

            # Classify API endpoints
            if _API_PATH_RE.search(urlparse(norm_url).path) or 'application/json' in content_type:
                if norm_url not in result.api_endpoints:
                    result.api_endpoints.append(norm_url)

            if 'text/html' in content_type:
                self._process_html(
                    norm_url, response.text, base_domain, depth, queue, visited, result
                )
            elif 'javascript' in content_type or norm_url.endswith('.js'):
                self._process_javascript(norm_url, response.text, base_domain, depth, queue, visited)
                if norm_url not in result.javascript_files:
                    result.javascript_files.append(norm_url)

        logger.info(
            "SmartCrawler finished: %d URLs, %d forms, %d API endpoints, %d JS files",
            len(result.urls),
            len(result.forms),
            len(result.api_endpoints),
            len(result.javascript_files),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_session(self) -> 'requests.Session':
        if self._session is not None:
            return self._session
        session = requests.Session()
        session.headers['User-Agent'] = (
            'Mozilla/5.0 (compatible; MegidoScanner/5.0; +https://github.com/tkstanch/Megido)'
        )
        return session

    def _normalize_url(self, url: str) -> str:
        """Normalise a URL by removing fragments and sorting query params."""
        parsed = urlparse(url)
        # Remove fragment
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params.items()), doseq=True)
        normalised = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            sorted_query,
            '',  # no fragment
        ))
        return normalised.rstrip('/')

    def _in_scope(self, url: str, base_domain: str) -> bool:
        """Return True if the URL is within the target domain."""
        parsed = urlparse(url)
        if not parsed.scheme.startswith('http'):
            return False
        return parsed.netloc == base_domain or parsed.netloc.endswith('.' + base_domain)

    def _extract_params(self, url: str) -> List[str]:
        """Return a list of query-parameter names from *url*."""
        return list(parse_qs(urlparse(url).query).keys())

    def _enqueue(
        self,
        url: str,
        depth: int,
        base_domain: str,
        queue: List[Tuple[int, int, str]],
        visited: Set[str],
    ) -> None:
        """Normalise *url* and add it to the priority queue if unseen and in scope."""
        norm = self._normalize_url(url)
        if norm not in visited and self._in_scope(norm, base_domain):
            priority = -_url_priority(norm)  # negate so high-priority items sort first
            queue.append((priority, depth + 1, norm))

    def _process_html(
        self,
        page_url: str,
        html: str,
        base_domain: str,
        depth: int,
        queue: List[Tuple[int, int, str]],
        visited: Set[str],
        result: CrawlResult,
    ) -> None:
        """Extract links, forms, and JS files from an HTML page."""
        if not HAS_BS4:
            self._process_html_regex(page_url, html, base_domain, depth, queue, visited, result)
            return

        soup = BeautifulSoup(html, 'html.parser')

        # Links
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if href and not href.startswith(('mailto:', 'javascript:', '#', 'tel:')):
                abs_url = urljoin(page_url, href)
                self._enqueue(abs_url, depth, base_domain, queue, visited)

        # Forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            abs_action = urljoin(page_url, action) if action else page_url
            fields = [
                inp.get('name', '')
                for inp in form.find_all(['input', 'select', 'textarea'])
                if inp.get('name')
            ]
            form_info = FormInfo(url=page_url, action=abs_action, method=method, fields=fields)
            result.forms.append(form_info)
            # Enqueue form action URL
            self._enqueue(abs_action, depth, base_domain, queue, visited)

        # JavaScript files
        for script in soup.find_all('script', src=True):
            src = script['src'].strip()
            if src:
                abs_src = urljoin(page_url, src)
                if self._in_scope(abs_src, base_domain):
                    if abs_src not in result.javascript_files:
                        result.javascript_files.append(abs_src)
                    self._enqueue(abs_src, depth, base_domain, queue, visited)

        # Inline script content
        for script in soup.find_all('script'):
            if script.string:
                self._process_javascript(
                    page_url, script.string, base_domain, depth, queue, visited
                )

    def _process_html_regex(
        self,
        page_url: str,
        html: str,
        base_domain: str,
        depth: int,
        queue: List[Tuple[int, int, str]],
        visited: Set[str],
        result: CrawlResult,
    ) -> None:
        """Fallback HTML link extraction using regex (no bs4)."""
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = match.group(1).strip()
            if href and not href.startswith(('mailto:', 'javascript:', '#', 'tel:')):
                abs_url = urljoin(page_url, href)
                self._enqueue(abs_url, depth, base_domain, queue, visited)

    def _process_javascript(
        self,
        page_url: str,
        js_code: str,
        base_domain: str,
        depth: int,
        queue: List[Tuple[int, int, str]],
        visited: Set[str],
    ) -> None:
        """Extract URLs and API paths embedded in JavaScript source."""
        for pattern in _JS_URL_PATTERNS:
            for match in pattern.finditer(js_code):
                candidate = match.group(1).strip()
                if not candidate:
                    continue
                # Build absolute URL from root-relative or relative paths
                if candidate.startswith('/'):
                    parsed = urlparse(page_url)
                    abs_url = f"{parsed.scheme}://{parsed.netloc}{candidate}"
                elif candidate.startswith('http'):
                    abs_url = candidate
                else:
                    abs_url = urljoin(page_url, candidate)
                self._enqueue(abs_url, depth, base_domain, queue, visited)

    def _seed_from_robots(
        self,
        start_url: str,
        base_domain: str,
        queue: List[Tuple[int, int, str]],
        visited: Set[str],
    ) -> None:
        """Fetch robots.txt and sitemap.xml and seed the queue with discovered URLs."""
        parsed = urlparse(start_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        session = self._get_session()

        # robots.txt
        robots_url = f"{base}/robots.txt"
        try:
            resp = session.get(robots_url, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code == 200:
                self._parse_robots(resp.text, base, base_domain, queue, visited)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not fetch robots.txt: %s", exc)

        # sitemap.xml
        sitemap_url = f"{base}/sitemap.xml"
        try:
            resp = session.get(sitemap_url, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code == 200:
                self._parse_sitemap(resp.text, base_domain, queue, visited)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not fetch sitemap.xml: %s", exc)

    def _parse_robots(
        self,
        content: str,
        base: str,
        base_domain: str,
        queue: List[Tuple[int, int, str]],
        visited: Set[str],
    ) -> None:
        """Extract allowed/disallowed paths from robots.txt and enqueue them."""
        sitemap_re = re.compile(r'^Sitemap:\s*(.+)', re.IGNORECASE | re.MULTILINE)
        disallow_re = re.compile(r'^(?:Disallow|Allow):\s*(/\S*)', re.IGNORECASE | re.MULTILINE)

        for match in sitemap_re.finditer(content):
            sitemap_url = match.group(1).strip()
            self._enqueue(sitemap_url, 0, base_domain, queue, visited)

        for match in disallow_re.finditer(content):
            path = match.group(1).strip()
            if path and path != '/':
                abs_url = base + path
                self._enqueue(abs_url, 0, base_domain, queue, visited)

    def _parse_sitemap(
        self,
        content: str,
        base_domain: str,
        queue: List[Tuple[int, int, str]],
        visited: Set[str],
    ) -> None:
        """Extract URLs from sitemap.xml (including sitemap index files)."""
        url_re = re.compile(r'<loc>\s*(https?://[^<]+)\s*</loc>', re.IGNORECASE)
        for match in url_re.finditer(content):
            url = match.group(1).strip()
            self._enqueue(url, 0, base_domain, queue, visited)
