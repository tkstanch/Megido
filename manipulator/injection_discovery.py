"""
Injection Point Discovery Engine.
Crawls target web applications to discover all possible injection points.
"""
import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

try:
    from html.parser import HTMLParser
except ImportError:
    HTMLParser = None

logger = logging.getLogger(__name__)


class FormParser(HTMLParser):
    """Simple HTML form parser using stdlib html.parser."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None
        self._current_fields = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self._current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'enctype': attrs_dict.get('enctype', 'application/x-www-form-urlencoded'),
                'fields': [],
            }
            self._current_fields = []
        elif tag in ('input', 'textarea', 'select') and self._current_form is not None:
            field = {
                'name': attrs_dict.get('name', ''),
                'type': attrs_dict.get('type', 'text'),
                'value': attrs_dict.get('value', ''),
            }
            if field['name']:
                self._current_fields.append(field)

    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form is not None:
            self._current_form['fields'] = self._current_fields
            if self._current_form['fields']:
                self.forms.append(self._current_form)
            self._current_form = None
            self._current_fields = []


class LinkParser(HTMLParser):
    """Extract all links from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        href = None
        if tag == 'a':
            href = attrs_dict.get('href')
        elif tag == 'form':
            href = attrs_dict.get('action')
        elif tag == 'script':
            href = attrs_dict.get('src')
        elif tag == 'link':
            href = attrs_dict.get('href')

        if href and not href.startswith(('javascript:', 'mailto:', '#', 'data:')):
            full_url = urljoin(self.base_url, href)
            parsed = urlparse(full_url)
            clean = parsed._replace(fragment='').geturl()
            self.links.add(clean)


class InjectionPointDiscovery:
    """
    Discovers injection points in a target web application by crawling pages
    and extracting all possible injection locations.
    """

    INJECTABLE_HEADERS = [
        'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Forwarded-Host',
        'X-Real-IP', 'Accept', 'Accept-Language', 'Accept-Encoding',
        'Cookie', 'Origin', 'Host',
    ]

    def __init__(self, target_url: str, max_depth: int = 3,
                 max_pages: int = 50, timeout: int = 10,
                 custom_headers: Optional[Dict] = None,
                 auth_cookies: Optional[Dict] = None,
                 include_headers: bool = True,
                 include_cookies: bool = True):
        self.target_url = target_url.rstrip('/')
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.custom_headers = custom_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.include_headers = include_headers
        self.include_cookies = include_cookies

        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        self._visited: Set[str] = set()
        self._injection_points: List[Dict] = []

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope (same domain)."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain
        except Exception:
            return False

    def _make_request(self, url: str, method: str = 'GET',
                      data: Optional[Dict] = None) -> Optional[object]:
        """Make an HTTP request and return the response."""
        if requests is None:
            return None
        try:
            headers = {'User-Agent': 'Megido Security Scanner/1.0'}
            headers.update(self.custom_headers)
            if method.upper() == 'GET':
                resp = requests.get(url, headers=headers, cookies=self.auth_cookies,
                                    timeout=self.timeout, allow_redirects=True)
            else:
                resp = requests.post(url, data=data, headers=headers,
                                     cookies=self.auth_cookies,
                                     timeout=self.timeout, allow_redirects=True)
            return resp
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def _extract_injection_points_from_url(self, url: str) -> List[Dict]:
        """Extract GET parameter injection points from a URL."""
        points = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name, values in params.items():
            points.append({
                'url': url,
                'parameter_name': param_name,
                'parameter_type': 'GET',
                'injection_location': f'Query parameter: {param_name}',
                'original_value': values[0] if values else '',
                'form_action': '',
                'form_method': 'GET',
            })
        return points

    def _extract_injection_points_from_form(self, form: Dict, page_url: str) -> List[Dict]:
        """Extract injection points from a form."""
        points = []
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()

        action_url = urljoin(page_url, action) if action else page_url

        for field in form.get('fields', []):
            if field.get('type') in ('submit', 'button', 'image', 'reset'):
                continue

            param_type = 'file' if field.get('type') == 'file' else method

            points.append({
                'url': page_url,
                'parameter_name': field['name'],
                'parameter_type': param_type,
                'injection_location': f'Form field: {field["name"]}',
                'original_value': field.get('value', ''),
                'form_action': action_url,
                'form_method': method,
            })
        return points

    def _extract_cookie_injection_points(self, url: str, cookies: Dict) -> List[Dict]:
        """Extract injection points from cookies."""
        points = []
        for cookie_name, cookie_value in cookies.items():
            points.append({
                'url': url,
                'parameter_name': cookie_name,
                'parameter_type': 'cookie',
                'injection_location': f'Cookie: {cookie_name}',
                'original_value': str(cookie_value),
                'form_action': '',
                'form_method': '',
            })
        return points

    def _extract_header_injection_points(self, url: str) -> List[Dict]:
        """Create header injection point entries."""
        points = []
        for header_name in self.INJECTABLE_HEADERS:
            points.append({
                'url': url,
                'parameter_name': header_name,
                'parameter_type': 'header',
                'injection_location': f'HTTP Header: {header_name}',
                'original_value': '',
                'form_action': '',
                'form_method': '',
            })
        return points

    def _parse_page(self, url: str, html_content: str) -> Tuple[List[Dict], Set[str]]:
        """Parse a page to extract injection points and links."""
        injection_points = []

        injection_points.extend(self._extract_injection_points_from_url(url))

        form_parser = FormParser()
        try:
            form_parser.feed(html_content)
        except Exception:
            pass

        for form in form_parser.forms:
            injection_points.extend(self._extract_injection_points_from_form(form, url))

        link_parser = LinkParser(url)
        try:
            link_parser.feed(html_content)
        except Exception:
            pass

        links = {l for l in link_parser.links if self._is_in_scope(l)}

        return injection_points, links

    def discover(self) -> List[Dict]:
        """
        Crawl the target and discover all injection points.
        Returns list of injection point dicts.
        """
        if requests is None:
            logger.error("requests library not available")
            return []

        queue = [(self.target_url, 0)]  # (url, depth)

        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.pop(0)

            if url in self._visited:
                continue
            if depth > self.max_depth:
                continue
            if not self._is_in_scope(url):
                continue

            self._visited.add(url)
            logger.debug(f"Crawling {url} (depth={depth})")

            response = self._make_request(url)
            if response is None:
                continue

            try:
                html_content = response.text
            except Exception:
                html_content = ''

            points, links = self._parse_page(url, html_content)

            if self.include_cookies and response.cookies:
                cookie_dict = dict(response.cookies)
                points.extend(self._extract_cookie_injection_points(url, cookie_dict))

            if self.include_headers and len(self._visited) == 1:
                points.extend(self._extract_header_injection_points(url))

            for point in points:
                key = (point['url'], point['parameter_name'], point['parameter_type'])
                if not any(
                    (p['url'], p['parameter_name'], p['parameter_type']) == key
                    for p in self._injection_points
                ):
                    self._injection_points.append(point)

            for link in links:
                if link not in self._visited:
                    queue.append((link, depth + 1))

        return self._injection_points
