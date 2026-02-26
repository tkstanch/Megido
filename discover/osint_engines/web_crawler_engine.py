"""
Web Crawler Engine

Intelligent web crawling:
  - robots.txt / sitemap.xml parsing
  - Link extraction
  - Form and hidden input enumeration
  - HTML comment extraction
  - JavaScript endpoint extraction (LinkFinder-style)
  - API route / GraphQL introspection hints
"""
import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

# Regex patterns to find API endpoints / paths inside JS files
JS_ENDPOINT_PATTERNS = [
    r"""(?:"|')(/(?:api|v\d|graphql|rest|endpoint)[^"'<> \t\n\r\f\v]*)(?:"|')""",
    r"""(?:url|path|endpoint)\s*[:=]\s*(?:"|')([^"']+)(?:"|')""",
    r"""fetch\s*\(\s*(?:"|')([^"']+)(?:"|')""",
    r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*(?:"|')([^"']+)(?:"|')""",
]


class WebCrawlerEngine(BaseOSINTEngine):
    """
    Lightweight web crawler for reconnaissance.

    Performs a shallow crawl (configurable depth, default 2) to enumerate
    links, forms, comments, and JS-extracted endpoints.
    """

    name = 'WebCrawlerEngine'
    description = 'Intelligent web crawling — links, forms, JS endpoints, comments'
    is_active = True
    rate_limit_delay = 0.5

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        max_pages = self._get_config('max_pages', 30)
        depth = self._get_config('max_depth', 2)

        results: Dict[str, Any] = {
            'domain': domain,
            'links': [],
            'forms': [],
            'comments': [],
            'js_endpoints': [],
            'robots_txt': None,
            'sitemaps': [],
            'errors': [],
        }

        base_url = self._build_base_url(domain)

        # robots.txt
        robots = self._fetch_robots(base_url)
        if robots:
            results['robots_txt'] = robots

        # sitemap.xml
        sitemaps = self._fetch_sitemaps(base_url, robots)
        results['sitemaps'] = sitemaps

        # Crawl
        visited: Set[str] = set()
        queue = [(base_url, 0)]
        all_links: Set[str] = set()
        all_forms: List[Dict] = []
        all_comments: Set[str] = set()
        all_js_endpoints: Set[str] = set()

        while queue and len(visited) < max_pages:
            url, current_depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            page_data = self._crawl_page(url, domain)
            if page_data is None:
                continue

            all_links.update(page_data['links'])
            all_forms.extend(page_data['forms'])
            all_comments.update(page_data['comments'])
            all_js_endpoints.update(page_data['js_endpoints'])

            if current_depth < depth:
                for link in page_data['links']:
                    if link not in visited and urlparse(link).netloc.endswith(domain):
                        queue.append((link, current_depth + 1))

        results['links'] = sorted(all_links)
        results['forms'] = all_forms
        results['comments'] = sorted(all_comments)
        results['js_endpoints'] = sorted(all_js_endpoints)
        return results

    # ------------------------------------------------------------------

    def _build_base_url(self, domain: str) -> str:
        for scheme in ('https', 'http'):
            url = f'{scheme}://{domain}'
            try:
                resp = requests.head(url, timeout=5, verify=False, allow_redirects=True)  # noqa: S501
                if resp.status_code < 500:
                    return url
            except Exception:
                pass
        return f'https://{domain}'

    def _fetch_robots(self, base_url: str) -> Optional[str]:
        try:
            resp = requests.get(f'{base_url}/robots.txt', timeout=10, verify=False)  # noqa: S501
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def _fetch_sitemaps(self, base_url: str, robots_txt: Optional[str]) -> List[str]:
        sitemaps = [f'{base_url}/sitemap.xml']
        if robots_txt:
            for line in robots_txt.splitlines():
                if line.lower().startswith('sitemap:'):
                    sitemaps.append(line.split(':', 1)[1].strip())
        found = []
        for sm_url in sitemaps[:5]:
            try:
                resp = requests.get(sm_url, timeout=10, verify=False)  # noqa: S501
                if resp.status_code == 200:
                    found.append(sm_url)
            except Exception:
                pass
        return found

    def _crawl_page(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.get(
                url,
                timeout=15,
                verify=False,  # noqa: S501
                headers={'User-Agent': 'Mozilla/5.0 (OSINT-Crawler)'},
                allow_redirects=True,
            )
            if resp.status_code >= 400:
                return None

            content_type = resp.headers.get('Content-Type', '')
            if 'html' not in content_type and 'javascript' not in content_type:
                return {'links': set(), 'forms': [], 'comments': set(), 'js_endpoints': set()}

            soup = BeautifulSoup(resp.text, 'html.parser')

            # Links
            links: Set[str] = set()
            for tag in soup.find_all(['a', 'link'], href=True):
                href = urljoin(url, tag['href'])
                parsed = urlparse(href)
                if parsed.scheme in ('http', 'https'):
                    links.add(href)
            for tag in soup.find_all(['script', 'img', 'form'], src=True):
                src = urljoin(url, tag['src'])
                links.add(src)

            # Forms
            forms: List[Dict] = []
            for form in soup.find_all('form'):
                form_data: Dict[str, Any] = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': [],
                }
                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                    })
                forms.append(form_data)

            # HTML comments
            comments: Set[str] = set()
            for comment in soup.find_all(string=lambda t: isinstance(t, str) and t.strip().startswith('<!--')):
                stripped = comment.strip()[:500]
                if stripped:
                    comments.add(stripped)

            # JS endpoints
            js_endpoints: Set[str] = set()
            scripts = [tag.string or '' for tag in soup.find_all('script') if tag.string]
            # Also fetch external JS files
            for tag in soup.find_all('script', src=True)[:5]:
                js_url = urljoin(url, tag['src'])
                try:
                    js_resp = requests.get(js_url, timeout=5, verify=False)  # noqa: S501
                    if js_resp.status_code == 200:
                        scripts.append(js_resp.text[:200_000])
                except Exception:
                    pass

            for script_content in scripts:
                for pat in JS_ENDPOINT_PATTERNS:
                    for match in re.finditer(pat, script_content, re.IGNORECASE):
                        endpoint = match.group(1)
                        if len(endpoint) > 2:
                            js_endpoints.add(endpoint)

            return {
                'links': links,
                'forms': forms,
                'comments': comments,
                'js_endpoints': js_endpoints,
            }
        except Exception as exc:
            logger.debug("Crawl error for %s: %s", url, exc)
            return None

    def _count_items(self, data: Dict[str, Any]) -> int:
        return (
            len(data.get('links', []))
            + len(data.get('forms', []))
            + len(data.get('js_endpoints', []))
        )
