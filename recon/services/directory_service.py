"""
Directory brute-force service for the Recon app.
"""
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

DEFAULT_WORDLIST = [
    'admin', 'login', 'api', 'wp-admin', 'phpmyadmin', 'dashboard',
    'panel', 'console', 'portal', 'manage', 'management', 'administrator',
    'user', 'users', 'account', 'accounts', 'profile', 'settings',
    'config', 'configuration', 'backup', 'backups', 'db', 'database',
    'upload', 'uploads', 'files', 'file', 'download', 'downloads',
    'static', 'assets', 'media', 'images', 'img', 'css', 'js',
    'test', 'dev', 'staging', 'old', 'new', 'beta', 'v2',
    'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'docs',
    '.git', '.env', '.htaccess', 'robots.txt', 'sitemap.xml',
    'favicon.ico', 'crossdomain.xml', 'security.txt',
]

INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403}


def brute_force_directories(
    target_url: str,
    wordlist: list = None,
    timeout: int = None,
) -> list:
    """
    Try paths from *wordlist* against *target_url* and return HTTP responses.

    Args:
        target_url: The base URL to probe (e.g. ``https://example.com``).
        wordlist: List of path strings to try.  Defaults to
                  :data:`DEFAULT_WORDLIST`.
        timeout: Request timeout in seconds.  Defaults to
                 ``settings.NETWORK_DEFAULT_TIMEOUT``.

    Returns:
        A list of dicts with keys: path, status_code, content_length,
        content_type, redirect_url, full_url, is_interesting.
    """
    if timeout is None:
        timeout = getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)

    paths = wordlist if wordlist is not None else DEFAULT_WORDLIST
    base = target_url.rstrip('/')
    results = []

    try:
        import requests
        session = requests.Session()
        session.max_redirects = 3
    except ImportError:
        logger.error("requests library not available")
        return []

    for path in paths:
        url = f"{base}/{path.lstrip('/')}"
        try:
            resp = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'},
            )
            content_length = len(resp.content)
            content_type = resp.headers.get('Content-Type', '')
            redirect_url = resp.url if resp.url != url else ''
            code = resp.status_code
            is_interesting = code in INTERESTING_CODES
            results.append({
                'path': path,
                'full_url': url,
                'status_code': code,
                'content_length': content_length,
                'content_type': content_type[:200],
                'redirect_url': redirect_url,
                'is_interesting': is_interesting,
            })
            logger.debug("Dir brute %s -> %d", url, code)
        except Exception as exc:
            logger.debug("Request failed for %s: %s", url, exc)

    return results
