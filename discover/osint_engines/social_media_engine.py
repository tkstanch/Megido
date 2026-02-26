"""
Social Media Reconnaissance Engine

  - GitHub: profile, repositories, leaked secrets in commits, gists
  - Pastebin / paste-site monitoring
  - Username enumeration across platforms (Sherlock-style)
"""
import base64
import logging
import re
from typing import Any, Dict, List, Optional

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

# Platforms to check for username presence
USERNAME_PLATFORMS = [
    ('GitHub', 'https://github.com/{username}'),
    ('Twitter/X', 'https://twitter.com/{username}'),
    ('Reddit', 'https://www.reddit.com/user/{username}'),
    ('Instagram', 'https://www.instagram.com/{username}/'),
    ('LinkedIn', 'https://www.linkedin.com/in/{username}/'),
    ('HackerNews', 'https://news.ycombinator.com/user?id={username}'),
    ('GitLab', 'https://gitlab.com/{username}'),
    ('Keybase', 'https://keybase.io/{username}'),
    ('Medium', 'https://medium.com/@{username}'),
    ('Dev.to', 'https://dev.to/{username}'),
]

# Patterns that indicate a profile page exists (not a 404 page)
PROFILE_EXISTS_PATTERNS = [
    r'og:type.*profile',
    r'<title>[^<]+</title>',
]

# Sensitive patterns to look for in GitHub repositories
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Token'),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'Private Key'),
    (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{6,}["\']', 'Password'),
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', 'API Key'),
]


class SocialMediaEngine(BaseOSINTEngine):
    """
    Social media and GitHub OSINT engine.
    """

    name = 'SocialMediaEngine'
    description = 'GitHub scanning, username enumeration, paste monitoring'
    is_active = False

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        org_name = domain.split('.')[0]  # heuristic: use first label as org name

        results: Dict[str, Any] = {
            'domain': domain,
            'github_org': {},
            'github_repos': [],
            'leaked_secrets': [],
            'username_profiles': [],
            'errors': [],
        }

        github_token = self._get_config('github_token')

        # GitHub organisation/user search
        github_data = self._search_github(org_name, github_token)
        results['github_org'] = github_data.get('org', {})
        results['github_repos'] = github_data.get('repos', [])
        if github_data.get('error'):
            results['errors'].append(f'GitHub: {github_data["error"]}')

        # Scan top repos for leaked secrets (read-only, public only)
        for repo in results['github_repos'][:5]:
            secrets = self._scan_repo_for_secrets(
                repo.get('full_name', ''), github_token
            )
            results['leaked_secrets'].extend(secrets)

        # Username presence across platforms
        profiles = self._enumerate_usernames(org_name)
        results['username_profiles'] = profiles

        return results

    # ------------------------------------------------------------------

    def _search_github(self, query: str, token: Optional[str] = None) -> Dict[str, Any]:
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if token:
            headers['Authorization'] = f'token {token}'

        result: Dict[str, Any] = {'org': {}, 'repos': [], 'error': None}

        # Try as org first, then user
        for entity_type in ('orgs', 'users'):
            url = f'https://api.github.com/{entity_type}/{query}'
            try:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    result['org'] = {
                        'login': data.get('login'),
                        'name': data.get('name'),
                        'description': data.get('description'),
                        'public_repos': data.get('public_repos'),
                        'followers': data.get('followers'),
                        'html_url': data.get('html_url'),
                        'type': data.get('type'),
                    }
                    break
            except Exception as exc:
                result['error'] = str(exc)

        # Fetch public repos
        repos_url = f'https://api.github.com/orgs/{query}/repos'
        try:
            resp = requests.get(
                repos_url, headers=headers, params={'per_page': 30}, timeout=10
            )
            if resp.status_code != 200:
                repos_url = f'https://api.github.com/users/{query}/repos'
                resp = requests.get(
                    repos_url, headers=headers, params={'per_page': 30}, timeout=10
                )
            if resp.status_code == 200:
                for repo in resp.json():
                    result['repos'].append({
                        'full_name': repo.get('full_name'),
                        'description': repo.get('description'),
                        'language': repo.get('language'),
                        'stars': repo.get('stargazers_count', 0),
                        'url': repo.get('html_url'),
                        'updated_at': repo.get('updated_at'),
                    })
        except Exception as exc:
            result['error'] = str(exc)

        return result

    def _scan_repo_for_secrets(self, full_name: str, token: Optional[str] = None) -> List[Dict]:
        if not full_name:
            return []
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if token:
            headers['Authorization'] = f'token {token}'

        found = []
        # Search the default branch README / common config files
        for filename in ('README.md', '.env.example', 'config.yml', 'settings.py'):
            url = f'https://api.github.com/repos/{full_name}/contents/{filename}'
            try:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    content = base64.b64decode(data.get('content', '')).decode('utf-8', errors='replace')
                    for pattern, label in SECRET_PATTERNS:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            found.append({
                                'repo': full_name,
                                'file': filename,
                                'type': label,
                                'match': match.group(0)[:100],
                            })
            except Exception:
                pass
        return found

    def _enumerate_usernames(self, username: str) -> List[Dict]:
        profiles = []
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (OSINT; +github.com)'})
        for platform, url_template in USERNAME_PLATFORMS:
            url = url_template.format(username=username)
            try:
                resp = session.get(url, timeout=8, allow_redirects=True, verify=False)  # noqa: S501
                if resp.status_code == 200:
                    profiles.append({'platform': platform, 'url': url, 'exists': True})
            except Exception:
                pass
        return profiles

    def _count_items(self, data: Dict[str, Any]) -> int:
        return (
            len(data.get('github_repos', []))
            + len(data.get('leaked_secrets', []))
            + len(data.get('username_profiles', []))
        )

