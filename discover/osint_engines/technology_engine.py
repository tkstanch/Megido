"""
Technology Fingerprinting Engine

Detects CMS, frameworks, servers, CDNs, analytics tools, JS libraries,
WAFs, load balancers, and programming languages from HTTP headers and
page content — similar to Wappalyzer/WhatWeb.
"""
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)


# Each signature: (category, tech_name, match_type, pattern)
# match_type: 'header' => checks response headers
#             'body'   => checks response body
#             'header_value:<Header-Name>' => checks specific header value
SIGNATURES: List[Tuple[str, str, str, str]] = [
    # Web servers
    ('Server', 'Apache', 'header_value:Server', r'Apache'),
    ('Server', 'Nginx', 'header_value:Server', r'nginx'),
    ('Server', 'IIS', 'header_value:Server', r'Microsoft-IIS'),
    ('Server', 'LiteSpeed', 'header_value:Server', r'LiteSpeed'),
    ('Server', 'Caddy', 'header_value:Server', r'Caddy'),
    ('Server', 'OpenResty', 'header_value:Server', r'openresty'),
    # CDN / WAF
    ('CDN', 'Cloudflare', 'header_value:Server', r'cloudflare'),
    ('CDN', 'Cloudflare', 'header', r'CF-RAY'),
    ('CDN', 'Akamai', 'header', r'X-Akamai'),
    ('CDN', 'CloudFront', 'header_value:Via', r'CloudFront'),
    ('CDN', 'Fastly', 'header', r'X-Served-By'),
    ('WAF', 'Sucuri', 'header', r'X-Sucuri-ID'),
    ('WAF', 'Imperva Incapsula', 'header', r'X-Iinfo'),
    ('WAF', 'ModSecurity', 'header_value:Server', r'mod_security'),
    # CMS
    ('CMS', 'WordPress', 'body', r'wp-content|wp-includes|WordPress'),
    ('CMS', 'Drupal', 'body', r'Drupal\.settings|drupal\.org'),
    ('CMS', 'Joomla', 'body', r'Joomla!|/components/com_'),
    ('CMS', 'Magento', 'body', r'Mage\.Cookies|/skin/frontend/'),
    ('CMS', 'Shopify', 'body', r'cdn\.shopify\.com'),
    ('CMS', 'Ghost', 'header_value:X-Powered-By', r'Ghost'),
    ('CMS', 'Wix', 'body', r'wixstatic\.com|static\.wixstatic'),
    ('CMS', 'Squarespace', 'body', r'squarespace\.com'),
    # Frameworks
    ('Framework', 'Django', 'header_value:X-Frame-Options', r'SAMEORIGIN'),
    ('Framework', 'Django', 'body', r'csrfmiddlewaretoken'),
    ('Framework', 'Ruby on Rails', 'header_value:X-Powered-By', r'Phusion Passenger'),
    ('Framework', 'Laravel', 'header_value:Set-Cookie', r'laravel_session'),
    ('Framework', 'ASP.NET', 'header_value:X-Powered-By', r'ASP\.NET'),
    ('Framework', 'ASP.NET', 'header', r'X-AspNet-Version'),
    ('Framework', 'Express.js', 'header_value:X-Powered-By', r'Express'),
    # JS Frameworks (from body)
    ('JS Framework', 'React', 'body', r'react(?:\.min)?\.js|data-reactroot'),
    ('JS Framework', 'Vue.js', 'body', r'vue(?:\.min)?\.js|data-v-'),
    ('JS Framework', 'Angular', 'body', r'ng-version=|angular(?:\.min)?\.js'),
    ('JS Framework', 'jQuery', 'body', r'jquery(?:\.min)?\.js'),
    ('JS Framework', 'Next.js', 'body', r'__NEXT_DATA__|/_next/'),
    ('JS Framework', 'Nuxt.js', 'body', r'__NUXT__|/_nuxt/'),
    # Analytics
    ('Analytics', 'Google Analytics', 'body', r'google-analytics\.com/ga\.js|gtag\('),
    ('Analytics', 'Google Tag Manager', 'body', r'googletagmanager\.com'),
    ('Analytics', 'Hotjar', 'body', r'hotjar\.com'),
    ('Analytics', 'Mixpanel', 'body', r'mixpanel\.com/lib'),
    # Programming Languages
    ('Language', 'PHP', 'header_value:X-Powered-By', r'PHP'),
    ('Language', 'PHP', 'body', r'\.php[\?#"\'\/]'),
    ('Language', 'Python', 'header_value:X-Powered-By', r'Python'),
    ('Language', 'Ruby', 'header_value:X-Powered-By', r'Ruby'),
]


class TechnologyEngine(BaseOSINTEngine):
    """
    Technology fingerprinting engine.

    Fetches the target's homepage and analyses HTTP headers + response body
    against a curated signature database.
    """

    name = 'TechnologyEngine'
    description = 'Technology stack detection from HTTP headers and page content'
    is_active = True  # makes an HTTP request to the target

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        results: Dict[str, Any] = {
            'domain': domain,
            'technologies': [],
            'server': None,
            'powered_by': None,
            'headers': {},
            'errors': [],
        }

        for scheme in ('https', 'http'):
            url = f'{scheme}://{domain}'
            response = self._fetch(url)
            if response is not None:
                break
        else:
            results['errors'].append('Could not connect to target')
            return results

        headers = dict(response.headers)
        body = response.text[:500_000]  # limit body size

        results['server'] = headers.get('Server') or headers.get('server')
        results['powered_by'] = headers.get('X-Powered-By')
        results['headers'] = {k: v for k, v in headers.items()}

        detected = {}
        for category, tech, match_type, pattern in SIGNATURES:
            if self._matches(match_type, pattern, headers, body):
                key = (category, tech)
                if key not in detected:
                    detected[key] = {'category': category, 'name': tech, 'confidence': 'high'}

        results['technologies'] = list(detected.values())
        return results

    # ------------------------------------------------------------------

    def _fetch(self, url: str) -> Optional[Any]:
        try:
            resp = requests.get(
                url,
                timeout=15,
                verify=False,  # noqa: S501 — intentional for security testing
                headers={'User-Agent': 'Mozilla/5.0 (OSINT-Scanner; +https://github.com)'},
                allow_redirects=True,
            )
            return resp
        except Exception as exc:
            logger.debug("TechnologyEngine fetch error for %s: %s", url, exc)
            return None

    def _matches(
        self,
        match_type: str,
        pattern: str,
        headers: Dict[str, str],
        body: str,
    ) -> bool:
        try:
            if match_type == 'body':
                return bool(re.search(pattern, body, re.IGNORECASE))
            elif match_type == 'header':
                return any(re.search(pattern, k, re.IGNORECASE) for k in headers)
            elif match_type.startswith('header_value:'):
                header_name = match_type.split(':', 1)[1]
                # Case-insensitive header name lookup
                value = next(
                    (v for k, v in headers.items() if k.lower() == header_name.lower()),
                    ''
                )
                return bool(re.search(pattern, value, re.IGNORECASE))
        except Exception:
            pass
        return False

    def _count_items(self, data: Dict[str, Any]) -> int:
        return len(data.get('technologies', []))
