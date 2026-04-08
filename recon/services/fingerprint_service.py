"""
Technology stack fingerprinting service for the Recon app.

Fetches a URL and analyses HTTP response headers and body content to
identify the technology stack in use.
"""
import logging
import re

from django.conf import settings

logger = logging.getLogger(__name__)

# (pattern, technology, category, version_group_index_or_None)
_HEADER_FINGERPRINTS = [
    (r'Apache(?:/([0-9.]+))?', 'Apache', 'server', 1),
    (r'nginx(?:/([0-9.]+))?', 'nginx', 'server', 1),
    (r'Microsoft-IIS(?:/([0-9.]+))?', 'IIS', 'server', 1),
    (r'LiteSpeed', 'LiteSpeed', 'server', None),
    (r'PHP(?:/([0-9.]+))?', 'PHP', 'language', 1),
    (r'ASP\.NET', 'ASP.NET', 'framework', None),
    (r'Express', 'Express.js', 'framework', None),
    (r'Django', 'Django', 'framework', None),
    (r'Ruby on Rails', 'Ruby on Rails', 'framework', None),
]

_BODY_FINGERPRINTS = [
    (r'wp-content|wp-includes', 'WordPress', 'cms', None),
    (r'Drupal\.settings|drupal\.js', 'Drupal', 'cms', None),
    (r'Joomla!|joomla', 'Joomla', 'cms', None),
    (r'data-reactroot|__NEXT_DATA__', 'React/Next.js', 'framework', None),
    (r'ng-version="([^"]+)"', 'Angular', 'framework', 1),
    (r'__vue', 'Vue.js', 'framework', None),
    (r'jquery(?:\.min)?\.js(?:\?ver=([0-9.]+))?', 'jQuery', 'library', 1),
    (r'bootstrap(?:\.min)?\.css(?:\?ver=([0-9.]+))?', 'Bootstrap', 'library', 1),
    (r'<meta name="generator" content="([^"]+)"', 'Generator', 'cms', 1),
]


def fingerprint_url(url: str, timeout: int = None) -> list:
    """
    Fetch *url* and return a list of detected technologies.

    Args:
        url: The URL to fingerprint.
        timeout: Request timeout in seconds.  Defaults to
                 ``settings.NETWORK_DEFAULT_TIMEOUT``.

    Returns:
        A list of dicts with keys: technology, version, category,
        evidence, confidence.
    """
    if timeout is None:
        timeout = getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)

    findings = []

    try:
        import requests
        resp = requests.get(
            url,
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0'},
            allow_redirects=True,
        )
    except Exception as exc:
        logger.error("Fingerprinting request failed for %s: %s", url, exc)
        return findings

    # ---- Header-based detection ----
    server_header = resp.headers.get('Server', '')
    powered_by = resp.headers.get('X-Powered-By', '')
    combined_headers = f"{server_header} {powered_by}"

    for pattern, tech, category, ver_group in _HEADER_FINGERPRINTS:
        m = re.search(pattern, combined_headers, re.IGNORECASE)
        if m:
            version = m.group(ver_group) if ver_group and m.lastindex and m.lastindex >= ver_group else ''
            findings.append({
                'technology': tech,
                'version': version or '',
                'category': category,
                'evidence': f"Header: {combined_headers[:200]}",
                'confidence': 90,
            })

    # Security headers worth noting
    for hdr, tech in [
        ('X-Frame-Options', 'X-Frame-Options'),
        ('Strict-Transport-Security', 'HSTS'),
        ('Content-Security-Policy', 'CSP'),
    ]:
        if hdr in resp.headers:
            findings.append({
                'technology': tech,
                'version': '',
                'category': 'security',
                'evidence': f"Header present: {resp.headers[hdr][:100]}",
                'confidence': 100,
            })

    # ---- Cookie-based detection ----
    for cookie_name in resp.cookies:
        if 'wordpress' in cookie_name.lower() or 'wp-' in cookie_name.lower():
            findings.append({
                'technology': 'WordPress',
                'version': '',
                'category': 'cms',
                'evidence': f"Cookie: {cookie_name}",
                'confidence': 75,
            })
        elif cookie_name.lower() in ('phpsessid',):
            findings.append({
                'technology': 'PHP',
                'version': '',
                'category': 'language',
                'evidence': f"Cookie: {cookie_name}",
                'confidence': 70,
            })
        elif 'asp.net' in cookie_name.lower() or cookie_name == '.ASPXAUTH':
            findings.append({
                'technology': 'ASP.NET',
                'version': '',
                'category': 'framework',
                'evidence': f"Cookie: {cookie_name}",
                'confidence': 80,
            })

    # ---- Body-based detection ----
    try:
        body = resp.text
    except Exception:
        body = ''

    for pattern, tech, category, ver_group in _BODY_FINGERPRINTS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            version = ''
            if ver_group and m.lastindex and m.lastindex >= ver_group:
                version = m.group(ver_group) or ''
            # Special case: generator meta tag
            if tech == 'Generator' and version:
                tech = version.split(' ')[0]
                version = ' '.join(version.split(' ')[1:]) if ' ' in version else ''
            findings.append({
                'technology': tech,
                'version': version,
                'category': category,
                'evidence': f"Body pattern: {pattern[:80]}",
                'confidence': 70,
            })

    # De-duplicate by technology name
    seen = set()
    unique = []
    for f in findings:
        if f['technology'] not in seen:
            seen.add(f['technology'])
            unique.append(f)

    return unique
