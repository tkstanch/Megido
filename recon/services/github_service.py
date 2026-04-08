"""
GitHub reconnaissance service for the Recon app.

Searches GitHub for repositories and sensitive code patterns belonging to
a target organisation.
"""
import logging

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
