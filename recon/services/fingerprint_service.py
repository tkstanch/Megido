"""
Technology stack fingerprinting service for the Recon app.

Fetches a URL and analyses HTTP response headers and body content to
identify the technology stack in use.
"""
import logging
import re

from django.conf import settings

logger = logging.getLogger(__name__)

# Max characters used when embedding header values in evidence strings.
_MAX_EVIDENCE_LEN = 100

# (pattern, technology, category, version_group_index_or_None)
# Matched against the combined Server + X-Powered-By header string.
_HEADER_FINGERPRINTS = [
    (r'Apache(?:/([0-9.]+))?', 'Apache', 'server', 1),
    (r'nginx(?:/([0-9.]+))?', 'nginx', 'server', 1),
    (r'Microsoft-IIS(?:/([0-9.]+))?', 'IIS', 'server', 1),
    (r'LiteSpeed', 'LiteSpeed', 'server', None),
    (r'OpenResty(?:/([0-9.]+))?', 'OpenResty', 'server', 1),
    (r'Caddy(?:/([0-9.]+))?', 'Caddy', 'server', 1),
    (r'Tomcat(?:/([0-9.]+))?', 'Tomcat', 'server', 1),
    (r'Jetty(?:[\s/]([0-9.]+))?', 'Jetty', 'server', 1),
    (r'cloudflare', 'Cloudflare', 'cdn', None),
    (r'AmazonS3', 'Amazon S3', 'cdn', None),
    (r'CloudFront', 'AWS CloudFront', 'cdn', None),
    (r'Varnish(?:/([0-9.]+))?', 'Varnish', 'cdn', 1),
    (r'Fastly', 'Fastly', 'cdn', None),
    (r'envoy', 'Envoy', 'proxy', None),
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
    (r'shopify\.com|Shopify\.theme', 'Shopify', 'cms', None),
    (r'squarespace', 'Squarespace', 'cms', None),
    (r'wix\.com', 'Wix', 'cms', None),
    (r'gtag\(|googletagmanager\.com', 'Google Analytics/GTM', 'analytics', None),
]

# Additional individual headers to inspect beyond Server/X-Powered-By.
# Each entry: (header_name, pattern_or_None, technology, category, confidence)
# If pattern is None the mere presence of the header is the signal.
_EXTRA_HEADER_CHECKS = [
    ('X-AspNet-Version', r'([0-9.]+)', 'ASP.NET', 'framework', 90),
    ('X-AspNetMvc-Version', r'([0-9.]+)', 'ASP.NET MVC', 'framework', 90),
    ('X-Generator', None, 'X-Generator', 'cms', 80),
    ('X-Powered-CMS', None, 'X-Powered-CMS', 'cms', 80),
    ('CF-Ray', None, 'Cloudflare', 'cdn', 100),
    ('X-Cache', r'(HIT|MISS)', 'Varnish/Cache-Proxy', 'cdn', 60),
    ('Via', r'cloudfront', 'AWS CloudFront', 'cdn', 90),
    ('Via', r'varnish', 'Varnish', 'cdn', 90),
    ('X-Served-By', r'cache', 'Fastly', 'cdn', 70),
    ('X-Amz-Cf-Id', None, 'AWS CloudFront', 'cdn', 100),
    ('X-Amz-Request-Id', None, 'Amazon AWS', 'cloud', 90),
    ('X-Google-Backends', None, 'Google Cloud', 'cloud', 90),
    ('X-GFE-Request-State', None, 'Google Frontend', 'cloud', 90),
    ('Server-Timing', None, 'Server-Timing', 'performance', 80),
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

    # ---- Always record basic response metadata ----
    is_https = resp.url.startswith('https://')
    content_type = resp.headers.get('Content-Type', 'unknown').split(';')[0].strip()
    findings.append({
        'technology': f'HTTP {resp.status_code}',
        'version': '',
        'category': 'response',
        'evidence': f"Status {resp.status_code}, Content-Type: {content_type}",
        'confidence': 100,
    })
    if is_https:
        findings.append({
            'technology': 'HTTPS/TLS',
            'version': '',
            'category': 'transport',
            'evidence': f"URL uses HTTPS: {resp.url[:_MAX_EVIDENCE_LEN]}",
            'confidence': 100,
        })

    # ---- Header-based detection (Server + X-Powered-By) ----
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

    # ---- Additional individual header checks ----
    for hdr_name, pattern, tech, category, confidence in _EXTRA_HEADER_CHECKS:
        hdr_val = resp.headers.get(hdr_name, '')
        if not hdr_val:
            continue
        version = ''
        if pattern:
            m = re.search(pattern, hdr_val, re.IGNORECASE)
            if not m:
                continue
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else ''
        # Use the raw header value as the technology name when it's a
        # generic "X-Generator" / "X-Powered-CMS" style header.
        display_tech = hdr_val[:_MAX_EVIDENCE_LEN] if tech in ('X-Generator', 'X-Powered-CMS') else tech
        findings.append({
            'technology': display_tech,
            'version': version,
            'category': category,
            'evidence': f"Header {hdr_name}: {hdr_val[:_MAX_EVIDENCE_LEN]}",
            'confidence': confidence,
        })

    # ---- Security headers worth noting ----
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
                'evidence': f"Header present: {resp.headers[hdr][:_MAX_EVIDENCE_LEN]}",
                'confidence': 100,
            })

    # ---- Cookie-based detection ----
    for cookie_name in resp.cookies.keys():
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
