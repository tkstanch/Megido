"""
GitHub reconnaissance service for the Recon app.

Searches GitHub for repositories and sensitive code patterns belonging to
a target organisation.
"""
import logging
import time

from django.conf import settings

logger = logging.getLogger(__name__)


def _get_timeout():
    return getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)


def _get_headers(token: str = None):
    token = token or getattr(settings, 'GITHUB_TOKEN', '')
    headers = {'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f"Bearer {token}"
    return headers


def search_github_repos(org_name: str, token: str = None) -> list:
    """
    List public repositories for *org_name* via the GitHub API.

    Reads ``GITHUB_TOKEN`` from Django settings when *token* is not supplied.
    Works without a token but rate-limits apply (60 req/h unauthenticated).

    Args:
        org_name: The GitHub organisation or user name.
        token: Optional personal access token.

    Returns:
        A list of dicts with keys: name, full_name, description,
        html_url, stargazers_count, language, topics.
    """
    try:
        import requests
        url = f"https://api.github.com/orgs/{org_name}/repos"
        params = {'per_page': 100, 'type': 'public'}
        response = requests.get(
            url, headers=_get_headers(token), params=params, timeout=_get_timeout()
        )
        if response.status_code == 404:
            # Try as a user instead of org
            url = f"https://api.github.com/users/{org_name}/repos"
            response = requests.get(
                url, headers=_get_headers(token), params=params, timeout=_get_timeout()
            )
        response.raise_for_status()
        repos = []
        for r in response.json():
            repos.append({
                'name': r.get('name', ''),
                'full_name': r.get('full_name', ''),
                'description': r.get('description', '') or '',
                'html_url': r.get('html_url', ''),
                'stargazers_count': r.get('stargazers_count', 0),
                'language': r.get('language', '') or '',
                'topics': r.get('topics', []),
            })
        return repos
    except Exception as exc:
        logger.error("GitHub repo search failed for %s: %s", org_name, exc)
        return []


def search_github_code(query: str, token: str = None) -> list:
    """
    Search GitHub code for *query* using the code search API.

    Useful for finding leaked secrets, credentials, or configuration files.
    A token is strongly recommended to avoid rate-limiting.

    Args:
        query: GitHub code search query string.
        token: Optional personal access token.

    Returns:
        A list of dicts with keys: repository, file_path, url, score.
    """
    try:
        import requests
        url = "https://api.github.com/search/code"
        params = {'q': query, 'per_page': 30}
        response = requests.get(
            url, headers=_get_headers(token), params=params, timeout=_get_timeout()
        )
        response.raise_for_status()
        items = []
        for item in response.json().get('items', []):
            items.append({
                'repository': item.get('repository', {}).get('full_name', ''),
                'file_path': item.get('path', ''),
                'url': item.get('html_url', ''),
                'score': item.get('score', 0),
            })
        return items
    except Exception as exc:
        logger.error("GitHub code search failed for %r: %s", query, exc)
        return []


# ---------------------------------------------------------------------------
# Sensitive pattern definitions and rate-limit constants
# ---------------------------------------------------------------------------

# Seconds to pause between normal code-search queries (GitHub allows ~30/min)
_QUERY_INTERVAL_DELAY = 2
# Extra back-off when a 403 rate-limit response is received
_RATE_LIMIT_RETRY_DELAY = 10

_SENSITIVE_PATTERNS = [
    # Private keys – critical
    {'pattern': 'BEGIN RSA PRIVATE KEY', 'severity': 'critical'},
    {'pattern': 'BEGIN OPENSSH PRIVATE KEY', 'severity': 'critical'},
    {'pattern': 'BEGIN PGP PRIVATE KEY', 'severity': 'critical'},
    # Credential files – high
    {'pattern': 'filename:.env', 'severity': 'high'},
    {'pattern': 'filename:.npmrc', 'severity': 'high'},
    {'pattern': 'filename:.htpasswd', 'severity': 'high'},
    {'pattern': 'filename:wp-config.php', 'severity': 'high'},
    {'pattern': 'filename:credentials', 'severity': 'high'},
    {'pattern': 'filename:shadow', 'severity': 'high'},
    {'pattern': 'filename:id_rsa', 'severity': 'critical'},
    # Cloud credentials – high
    {'pattern': 'AWS_SECRET_ACCESS_KEY', 'severity': 'high'},
    {'pattern': 'AZURE_CLIENT_SECRET', 'severity': 'high'},
    {'pattern': 'GOOGLE_APPLICATION_CREDENTIALS', 'severity': 'high'},
    # API keys / tokens – high
    {'pattern': 'api_key', 'severity': 'high'},
    {'pattern': 'apikey', 'severity': 'high'},
    {'pattern': 'access_token', 'severity': 'high'},
    {'pattern': 'auth_token', 'severity': 'high'},
    {'pattern': 'private_key', 'severity': 'high'},
    {'pattern': 'password', 'severity': 'high'},
    {'pattern': 'secret', 'severity': 'high'},
    # Connection strings – medium
    {'pattern': 'jdbc:', 'severity': 'medium'},
    {'pattern': 'mongodb://', 'severity': 'medium'},
    {'pattern': 'postgres://', 'severity': 'medium'},
    {'pattern': 'mysql://', 'severity': 'medium'},
    {'pattern': 'redis://', 'severity': 'medium'},
]


def search_sensitive_data(org_name: str, token: str = None) -> list:
    """
    Search an organisation's code on GitHub for sensitive patterns.

    Each pattern from ``_SENSITIVE_PATTERNS`` is submitted as a separate
    ``org:{org_name} <pattern>`` code-search query.  A 2-second sleep is
    inserted between queries to stay within GitHub's rate limit for the
    code-search endpoint.

    Args:
        org_name: GitHub organisation or user name to scope the search.
        token: Optional personal access token (strongly recommended).

    Returns:
        A deduplicated list of dicts with keys: finding_type, repository,
        file_path, content, url, severity, pattern.
    """
    try:
        import requests
    except ImportError:
        logger.error("requests library is not installed")
        return []

    seen_urls: set = set()
    results: list = []

    for entry in _SENSITIVE_PATTERNS:
        pattern = entry['pattern']
        severity = entry['severity']
        query = f'org:{org_name} {pattern}'
        api_url = "https://api.github.com/search/code"
        params = {'q': query, 'per_page': 30}

        try:
            response = requests.get(
                api_url,
                headers=_get_headers(token),
                params=params,
                timeout=_get_timeout(),
            )
            if response.status_code == 403:
                logger.warning(
                    "GitHub code search rate-limited for pattern %r – skipping", pattern
                )
                time.sleep(_RATE_LIMIT_RETRY_DELAY)
                continue
            if response.status_code == 422:
                # Unprocessable entity – query not supported (e.g. too broad)
                logger.debug("GitHub code search 422 for pattern %r", pattern)
                time.sleep(_QUERY_INTERVAL_DELAY)
                continue
            response.raise_for_status()

            for item in response.json().get('items', []):
                url = item.get('html_url', '')
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                # Determine finding_type from severity
                if severity == 'critical':
                    finding_type = 'secret'
                else:
                    finding_type = 'leak'
                results.append({
                    'finding_type': finding_type,
                    'repository': item.get('repository', {}).get('full_name', ''),
                    'file_path': item.get('path', ''),
                    'url': url,
                    'severity': severity,
                    'pattern': pattern,
                })

        except Exception as exc:
            logger.error(
                "GitHub sensitive-data search failed for pattern %r: %s", pattern, exc
            )

        # Respect GitHub's code-search rate limit (30 req/min for authenticated)
        time.sleep(_QUERY_INTERVAL_DELAY)

    return results
