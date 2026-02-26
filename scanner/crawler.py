"""
Web Crawler / Spider

Crawls a seed URL to auto-discover endpoints, forms, and API surface before
scanning.  The ``Crawler`` class is intentionally dependency-light: it only
requires ``requests`` and ``beautifulsoup4``.

Usage::

    from scanner.crawler import Crawler
    result = Crawler().crawl('https://example.com', max_depth=2)
    print(result.discovered_urls)
    print(result.forms)
    print(result.parameters)

The ``CrawlResult`` dataclass is the integration point with the scan engine:
pass ``result.discovered_urls`` to the engine to scan every discovered page.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import (
    urljoin,
    urlparse,
    parse_qs,
    urlencode,
    urlunparse,
)

logger = logging.getLogger(__name__)

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
    Complete crawl result containing all discovered attack surface.

    Attributes:
        discovered_urls: All reachable URLs on the same domain.
        forms: Metadata for every discovered form.
        parameters: Mapping of URL → list of discovered parameter names.
        api_endpoints: URLs that look like API endpoints (JSON responses,
            ``/api/`` path prefix, etc.).
        sitemap: Ordered list of visited URLs (breadth-first order).
        seed_url: The URL crawling started from.
        errors: Any errors encountered during crawling.
    """
    seed_url: str
    discovered_urls: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    api_endpoints: List[str] = field(default_factory=list)
    sitemap: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class Crawler:
    """
    Simple breadth-first web crawler.

    Args:
        max_depth: Maximum crawl depth from the seed URL (default: 3).
        max_urls: Maximum total URLs to visit (default: 100).
        same_domain: If True (default), only follow links on the same domain.
        respect_robots: If True, skip paths disallowed by ``robots.txt``.
        timeout: Request timeout in seconds (default: 10).
        verify_ssl: Whether to verify SSL certificates (default: False).
        session: Optional pre-configured ``requests.Session``.
    """

    # Patterns that suggest an API endpoint
    _API_PATTERNS = re.compile(
        r'(/api/|/v\d+/|\.json$|/graphql|/rest/|/rpc)',
        re.IGNORECASE,
    )

    def __init__(
        self,
        max_depth: int = 3,
        max_urls: int = 100,
        same_domain: bool = True,
        respect_robots: bool = False,
        timeout: int = 10,
        verify_ssl: bool = False,
        session: Optional[Any] = None,
    ) -> None:
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.same_domain = same_domain
        self.respect_robots = respect_robots
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._session = session
        self._disallowed_paths: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, seed_url: str, config: Optional[Dict[str, Any]] = None) -> CrawlResult:
        """
        Crawl from *seed_url* and return a :class:`CrawlResult`.

        Args:
            seed_url: Starting URL.
            config: Optional config overrides (same keys as ``__init__``).

        Returns:
            CrawlResult with all discovered URLs, forms, and parameters.
        """
        if not HAS_REQUESTS or not HAS_BS4:
            logger.warning("Crawler requires requests and beautifulsoup4")
            return CrawlResult(seed_url=seed_url, errors=['Missing dependencies'])

        config = config or {}
        max_depth = int(config.get('max_depth', self.max_depth))
        max_urls = int(config.get('max_urls', self.max_urls))
        same_domain = bool(config.get('same_domain', self.same_domain))
        timeout = int(config.get('timeout', self.timeout))
        verify_ssl = bool(config.get('verify_ssl', self.verify_ssl))

        parsed_seed = urlparse(seed_url)
        base_domain = parsed_seed.netloc

        session = self._session or requests.Session()
        session.headers.update({'User-Agent': 'Megido-Scanner/1.0'})

        if self.respect_robots:
            self._load_robots(seed_url, session, timeout, verify_ssl)

        result = CrawlResult(seed_url=seed_url)
        visited: Set[str] = set()
        # Queue entries: (url, depth)
        queue: List[tuple] = [(seed_url, 0)]

        while queue and len(visited) < max_urls:
            url, depth = queue.pop(0)
            url = self._normalise(url)

            if url in visited:
                continue
            if same_domain and urlparse(url).netloc != base_domain:
                continue
            if self._is_disallowed(url):
                continue

            visited.add(url)
            result.sitemap.append(url)

            try:
                resp = session.get(
                    url, timeout=timeout, verify=verify_ssl, allow_redirects=True
                )
            except Exception as exc:
                result.errors.append(f"{url}: {exc}")
                continue

            # Detect API endpoints
            if self._API_PATTERNS.search(url) or 'application/json' in resp.headers.get(
                'Content-Type', ''
            ):
                if url not in result.api_endpoints:
                    result.api_endpoints.append(url)

            # Collect URL parameters
            params = parse_qs(urlparse(url).query)
            if params:
                result.parameters[url] = list(params.keys())

            # Only parse HTML responses
            ctype = resp.headers.get('Content-Type', '')
            if 'html' not in ctype and 'text' not in ctype:
                continue

            try:
                soup = BeautifulSoup(resp.text, 'html.parser')
            except Exception:
                continue

            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url
                method = form.get('method', 'get').lower()
                fields = [
                    i.get('name', '')
                    for i in form.find_all(['input', 'textarea', 'select'])
                    if i.get('name')
                ]
                result.forms.append(FormInfo(
                    url=url,
                    action=form_url,
                    method=method,
                    fields=fields,
                ))

                # Also collect POST parameters
                if fields:
                    result.parameters.setdefault(form_url, [])
                    for f in fields:
                        if f not in result.parameters[form_url]:
                            result.parameters[form_url].append(f)

            if depth >= max_depth:
                continue

            # Extract links
            for tag in soup.find_all(['a', 'link'], href=True):
                href = tag['href']
                if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                    continue
                abs_url = urljoin(url, href)
                norm = self._normalise(abs_url)
                if norm not in visited:
                    queue.append((norm, depth + 1))

            # Extract JS src references
            for tag in soup.find_all('script', src=True):
                abs_url = urljoin(url, tag['src'])
                norm = self._normalise(abs_url)
                if norm not in visited and (not same_domain or urlparse(norm).netloc == base_domain):
                    queue.append((norm, depth + 1))

        result.discovered_urls = list(visited)
        logger.info(
            "Crawl of %s complete: %d URL(s), %d form(s), %d param URL(s)",
            seed_url,
            len(result.discovered_urls),
            len(result.forms),
            len(result.parameters),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise(url: str) -> str:
        """Strip fragments and normalise the URL."""
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=''))

    def _load_robots(
        self, seed_url: str, session: Any, timeout: int, verify_ssl: bool
    ) -> None:
        """Parse robots.txt and populate ``_disallowed_paths``."""
        parsed = urlparse(seed_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            resp = session.get(robots_url, timeout=timeout, verify=verify_ssl)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self._disallowed_paths.add(path)
        except Exception:
            pass

    def _is_disallowed(self, url: str) -> bool:
        if not self._disallowed_paths:
            return False
        path = urlparse(url).path
        return any(path.startswith(d) for d in self._disallowed_paths)
