"""
Hunter.io Engine

Queries the Hunter.io API to discover and enumerate email addresses associated
with a domain:
  - Domain-wide email search with confidence scores
  - Email pattern detection
  - Department and seniority breakdowns
  - Personal vs generic address classification
"""
import logging
import os
from typing import Any, Dict, List

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

HUNTER_DOMAIN_SEARCH_URL = 'https://api.hunter.io/v2/domain-search'
HUNTER_EMAIL_COUNT_URL = 'https://api.hunter.io/v2/email-count'


class HunterEngine(BaseOSINTEngine):
    """
    Hunter.io email discovery and verification: find email addresses, patterns,
    and associated people for a domain.

    Configure the API key via the ``hunter_api_key`` config key or the
    ``HUNTER_API_KEY`` environment variable.
    """

    name = 'HunterEngine'
    description = (
        'Hunter.io email discovery and verification: find email addresses, '
        'patterns, and associated people for a domain'
    )
    is_active = False
    rate_limit_delay = 1.5

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------

    def collect(self, target: str) -> Dict[str, Any]:
        api_key = self._get_config(
            'hunter_api_key',
            os.environ.get('HUNTER_API_KEY', ''),
        )

        errors: List[str] = []
        domain = target.strip().lower()

        # 1. Domain search
        search_data = self._query_domain_search(domain, api_key, errors)

        # 2. Email count (does not require an API key for basic totals)
        count_data = self._query_email_count(domain, errors)

        # Parse results
        domain_info = search_data.get('data', {})
        emails_raw: List[Dict[str, Any]] = domain_info.get('emails', [])
        emails = self._normalise_emails(emails_raw)

        department_breakdown: Dict[str, int] = {}
        seniority_breakdown: Dict[str, int] = {}
        type_breakdown: Dict[str, int] = {'personal': 0, 'generic': 0}

        for email in emails:
            dept = email.get('department') or ''
            if dept:
                department_breakdown[dept] = department_breakdown.get(dept, 0) + 1
            seniority = email.get('seniority') or ''
            if seniority:
                seniority_breakdown[seniority] = seniority_breakdown.get(seniority, 0) + 1
            etype = email.get('type') or ''
            if etype in type_breakdown:
                type_breakdown[etype] += 1

        total_emails = (
            count_data.get('data', {}).get('total', 0)
            or domain_info.get('total', 0)
            or len(emails)
        )

        return {
            'domain': domain,
            'organization': domain_info.get('organization'),
            'emails': emails,
            'email_pattern': domain_info.get('pattern'),
            'total_emails': total_emails,
            'department_breakdown': department_breakdown,
            'seniority_breakdown': seniority_breakdown,
            'type_breakdown': type_breakdown,
            'errors': errors,
        }

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def _query_domain_search(
        self, domain: str, api_key: str, errors: List[str]
    ) -> Dict[str, Any]:
        """Call Hunter.io /v2/domain-search."""
        try:
            resp = requests.get(
                HUNTER_DOMAIN_SEARCH_URL,
                params={'domain': domain, 'api_key': api_key},
                timeout=15,
            )
            if resp.status_code == 401:
                errors.append('Hunter.io: invalid API key')
                return {}
            if resp.status_code == 429:
                errors.append('Hunter.io: rate limit exceeded')
                return {}
            if resp.status_code == 404:
                errors.append(f'Hunter.io: domain {domain} not found')
                return {}
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            errors.append(f'Hunter.io domain search failed: {exc}')
            return {}

    def _query_email_count(self, domain: str, errors: List[str]) -> Dict[str, Any]:
        """Call Hunter.io /v2/email-count (no API key required)."""
        try:
            resp = requests.get(
                HUNTER_EMAIL_COUNT_URL,
                params={'domain': domain},
                timeout=10,
            )
            if resp.status_code not in (200, 201):
                return {}
            return resp.json()
        except Exception as exc:
            errors.append(f'Hunter.io email count failed: {exc}')
            return {}

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalise_emails(self, raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert Hunter.io email objects to a normalised schema."""
        emails = []
        for item in raw:
            emails.append({
                'email': item.get('value') or item.get('email', ''),
                'first_name': item.get('first_name'),
                'last_name': item.get('last_name'),
                'position': item.get('position'),
                'department': item.get('department'),
                'seniority': item.get('seniority'),
                'type': item.get('type'),
                'confidence': item.get('confidence'),
                'sources': item.get('sources', []),
            })
        return emails

    def _count_items(self, data: Dict[str, Any]) -> int:
        return len(data.get('emails', []))
