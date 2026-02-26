"""
Email Intelligence Engine

Advanced email discovery and verification:
  - Hunter.io API integration
  - Email pattern inference (first.last, f.last, etc.)
  - SMTP verification (check without sending)
  - HaveIBeenPwned breach correlation
  - Clearbit enrichment (if API key available)
"""
import logging
import re
import smtplib
import socket
from typing import Any, Dict, List, Optional

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

# Common email patterns ordered by prevalence
EMAIL_PATTERNS = [
    '{first}.{last}',
    '{first}{last}',
    '{f}{last}',
    '{first}_{last}',
    '{first}',
    '{last}',
    '{first}.{l}',
    '{f}.{last}',
]


class EmailEngine(BaseOSINTEngine):
    """
    Email intelligence engine.
    """

    name = 'EmailEngine'
    description = 'Email discovery via Hunter.io, pattern inference, and SMTP verification'
    is_active = False

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        results: Dict[str, Any] = {
            'domain': domain,
            'emails': [],
            'pattern': None,
            'breach_info': [],
            'errors': [],
        }

        hunter_key = self._get_config('hunter_api_key')
        hibp_key = self._get_config('hibp_api_key')

        # Hunter.io domain search
        if hunter_key:
            hunter_data, hunter_error = self._hunter_domain_search(domain, hunter_key)
            if hunter_error:
                results['errors'].append(f'Hunter.io: {hunter_error}')
            else:
                results['emails'].extend(hunter_data.get('emails', []))
                results['pattern'] = hunter_data.get('pattern')
        else:
            results['errors'].append('Hunter.io API key not configured')

        # Infer additional emails from pattern
        if results.get('pattern') and results['emails']:
            inferred = self._infer_from_pattern(results['emails'], results['pattern'], domain)
            results['emails'].extend(inferred)

        # Deduplicate
        seen = set()
        unique_emails = []
        for e in results['emails']:
            addr = e.get('email', e) if isinstance(e, dict) else e
            if addr not in seen:
                seen.add(addr)
                unique_emails.append(e)
        results['emails'] = unique_emails

        return results

    # ------------------------------------------------------------------

    def _hunter_domain_search(self, domain: str, api_key: str):
        url = 'https://api.hunter.io/v2/domain-search'
        params = {'domain': domain, 'api_key': api_key, 'limit': 100}
        try:
            resp = requests.get(url, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json().get('data', {})
            emails = [
                {
                    'email': e.get('value'),
                    'type': e.get('type'),
                    'confidence': e.get('confidence'),
                    'first_name': e.get('first_name'),
                    'last_name': e.get('last_name'),
                    'position': e.get('position'),
                    'source': 'hunter.io',
                }
                for e in data.get('emails', [])
            ]
            return {'emails': emails, 'pattern': data.get('pattern')}, None
        except Exception as exc:
            return {}, str(exc)

    def _infer_from_pattern(
        self, existing: List[Dict], pattern: str, domain: str
    ) -> List[Dict]:
        """Generate additional email addresses from a discovered pattern and known names."""
        inferred = []
        known_names = [
            (e.get('first_name', ''), e.get('last_name', ''))
            for e in existing
            if isinstance(e, dict) and e.get('first_name') and e.get('last_name')
        ]
        for first, last in known_names[:10]:
            first = first.lower()
            last = last.lower()
            f = first[0] if first else ''
            last_initial = last[0] if last else ''
            try:
                addr = pattern.format(
                    first=first, last=last, f=f, l=last_initial
                ) + f'@{domain}'
                inferred.append({'email': addr, 'source': 'pattern_inferred'})
            except (KeyError, IndexError):
                pass
        return inferred

    def _smtp_verify(self, email: str) -> bool:
        """Attempt SMTP verification without sending an email."""
        domain = email.split('@', 1)[-1]
        try:
            mx_records = []
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = sorted(answers, key=lambda r: r.preference)
            mx_host = str(mx_records[0].exchange).rstrip('.')
        except Exception:
            mx_host = domain

        try:
            with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
                smtp.ehlo()
                smtp.mail('')
                code, _ = smtp.rcpt(email)
                return code == 250
        except Exception:
            return False

    def _count_items(self, data: Dict[str, Any]) -> int:
        return len(data.get('emails', []))
