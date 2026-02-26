"""
Subdomain Discovery Engine

Multi-method subdomain enumeration:
  - Certificate transparency logs via crt.sh
  - Passive aggregation from multiple public APIs
  - DNS brute-force with built-in wordlist
  - Permutation/alteration generation
"""
import logging
import re
import socket
import time
from typing import Any, Dict, List, Set

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

# A compact but effective wordlist covering common subdomain prefixes.
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'webmail', 'admin',
    'secure', 'vpn', 'remote', 'blog', 'shop', 'api', 'dev', 'staging',
    'test', 'portal', 'mx', 'owa', 'autodiscover', 'exchange', 'static',
    'cdn', 'images', 'img', 'media', 'app', 'apps', 'mobile', 'beta',
    'git', 'gitlab', 'jira', 'confluence', 'jenkins', 'ci', 'build',
    'status', 'monitor', 'dashboard', 'analytics', 'support', 'help',
    'kb', 'docs', 'wiki', 'forum', 'store', 'pay', 'payments', 'checkout',
    'account', 'accounts', 'login', 'auth', 'sso', 'id', 'oauth',
    'upload', 'files', 'download', 'backup', 'old', 'new', 'v2', 'v3',
    'internal', 'intranet', 'corp', 'office', 'employees', 'hr', 'erp',
    'crm', 'db', 'database', 'mysql', 'postgres', 'redis', 'elasticsearch',
    'kibana', 'grafana', 'prometheus', 'k8s', 'kubernetes', 'docker',
    'registry', 'repo', 'nexus', 'artifactory', 'sonar', 'slack',
    'mail2', 'smtp2', 'pop3', 'imap', 'webdisk', 'cpanel', 'whm', 'plesk',
]


class SubdomainEngine(BaseOSINTEngine):
    """
    Multi-method passive and semi-active subdomain discovery.
    """

    name = 'SubdomainEngine'
    description = 'Subdomain enumeration via cert transparency, public APIs, and DNS brute-force'
    is_active = False
    rate_limit_delay = 1.0

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip().lstrip('www.') if target.startswith('www.') else target.lower().strip()
        found: Set[str] = set()
        sources: Dict[str, List[str]] = {}
        errors: List[str] = []

        # 1. Certificate transparency
        ct_subs, ct_error = self._crtsh(domain)
        if ct_error:
            errors.append(f'crt.sh: {ct_error}')
        if ct_subs:
            sources['crt.sh'] = ct_subs
            found.update(ct_subs)

        # 2. HackerTarget passive DNS
        ht_subs, ht_error = self._hackertarget(domain)
        if ht_error:
            errors.append(f'hackertarget: {ht_error}')
        if ht_subs:
            sources['hackertarget'] = ht_subs
            found.update(ht_subs)

        # 3. DNS brute-force (resolves only, no active scanning)
        bf_subs = self._dns_bruteforce(domain)
        if bf_subs:
            sources['bruteforce'] = bf_subs
            found.update(bf_subs)

        # 4. Permutation generation (no DNS resolution — passive)
        perms = self._generate_permutations(list(found), domain)
        if perms:
            sources['permutations'] = perms
            found.update(perms)

        # Deduplicate and sort
        subdomains = sorted(found)

        return {
            'domain': domain,
            'subdomains': subdomains,
            'total': len(subdomains),
            'sources': sources,
            'errors': errors,
        }

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def _crtsh(self, domain: str):
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            entries = resp.json()
            subs = set()
            for entry in entries:
                name = entry.get('name_value', '')
                for line in name.splitlines():
                    line = line.strip().lstrip('*.')
                    if line.endswith(f'.{domain}') or line == domain:
                        subs.add(line)
            return sorted(subs), None
        except Exception as exc:
            return [], str(exc)

    def _hackertarget(self, domain: str):
        url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            text = resp.text.strip()
            if 'error' in text.lower() or 'API count exceeded' in text:
                return [], text
            subs = []
            for line in text.splitlines():
                parts = line.split(',')
                if parts:
                    sub = parts[0].strip()
                    if sub.endswith(f'.{domain}') or sub == domain:
                        subs.append(sub)
            return subs, None
        except Exception as exc:
            return [], str(exc)

    def _dns_bruteforce(self, domain: str) -> List[str]:
        found = []
        for word in COMMON_SUBDOMAINS:
            candidate = f'{word}.{domain}'
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(candidate)
                found.append(candidate)
            except socket.gaierror:
                pass
            except Exception:
                pass
        return found

    def _generate_permutations(self, existing: List[str], domain: str) -> List[str]:
        """Generate subdomain permutations from existing ones (passive — no DNS)."""
        perms = set()
        prefixes = ['dev', 'test', 'staging', 'prod', 'old', 'new', 'v2', 'api', 'internal']
        for sub in existing[:20]:  # limit to avoid explosion
            base = sub.replace(f'.{domain}', '').replace(domain, '')
            if not base:
                continue
            for prefix in prefixes:
                candidate = f'{prefix}-{base}.{domain}'
                if candidate not in existing:
                    perms.add(candidate)
        return list(perms)

    def _count_items(self, data: Dict[str, Any]) -> int:
        return data.get('total', 0)
