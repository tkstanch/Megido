"""
WHOIS / RDAP Engine

Retrieves registrar info, creation/expiry dates, name servers, registrant
details, and ASN / BGP routing data.
"""
import logging
import socket
from typing import Any, Dict, Optional

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed — WHOIS engine will use RDAP only")


class WHOISEngine(BaseOSINTEngine):
    """
    WHOIS and RDAP lookup engine.

    Tries python-whois first (if available) then falls back to RDAP API for
    structured registration data.  Also queries the Team Cymru IP-to-ASN API
    for ASN/BGP information.
    """

    name = 'WHOISEngine'
    description = 'WHOIS/RDAP registration data and ASN/BGP routing information'
    is_active = False

    def collect(self, target: str) -> Dict[str, Any]:
        domain = target.lower().strip()
        results: Dict[str, Any] = {
            'domain': domain,
            'whois': {},
            'rdap': {},
            'asn_info': [],
            'errors': [],
        }

        # WHOIS lookup
        if WHOIS_AVAILABLE:
            self._collect_whois(domain, results)
        else:
            results['errors'].append('python-whois not installed')

        # RDAP lookup (always attempt — structured JSON, no lib required)
        self._collect_rdap(domain, results)

        # ASN info for resolved IPs
        try:
            ips = list({info[4][0] for info in socket.getaddrinfo(domain, None)})
            for ip in ips[:3]:
                asn = self._ip_to_asn(ip)
                if asn:
                    results['asn_info'].append(asn)
        except Exception as exc:
            results['errors'].append(f'ASN lookup: {exc}')

        return results

    # ------------------------------------------------------------------

    def _collect_whois(self, domain: str, results: Dict[str, Any]) -> None:
        try:
            w = python_whois.whois(domain)
            results['whois'] = {
                'registrar': getattr(w, 'registrar', None),
                'creation_date': str(getattr(w, 'creation_date', None)),
                'expiration_date': str(getattr(w, 'expiration_date', None)),
                'updated_date': str(getattr(w, 'updated_date', None)),
                'name_servers': getattr(w, 'name_servers', []),
                'status': getattr(w, 'status', None),
                'emails': getattr(w, 'emails', []),
                'org': getattr(w, 'org', None),
                'country': getattr(w, 'country', None),
            }
        except Exception as exc:
            results['errors'].append(f'WHOIS: {exc}')

    def _collect_rdap(self, domain: str, results: Dict[str, Any]) -> None:
        url = f'https://rdap.org/domain/{domain}'
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            results['rdap'] = {
                'handle': data.get('handle'),
                'ldhName': data.get('ldhName'),
                'status': data.get('status', []),
                'entities': [
                    {
                        'roles': e.get('roles', []),
                        'handle': e.get('handle'),
                    }
                    for e in data.get('entities', [])
                ],
                'nameservers': [
                    ns.get('ldhName') for ns in data.get('nameservers', [])
                ],
                'events': data.get('events', []),
            }
        except Exception as exc:
            results['errors'].append(f'RDAP: {exc}')

    def _ip_to_asn(self, ip: str) -> Optional[Dict[str, str]]:
        """Use Team Cymru whois service for IP-to-ASN mapping."""
        try:
            parts = ip.split('.')
            reversed_ip = '.'.join(reversed(parts))
            host = f'{reversed_ip}.origin.asn.cymru.com'
            answers = socket.getaddrinfo(host, None)
            if answers:
                return {'ip': ip, 'source': 'cymru_dns'}
        except Exception:
            pass
        return None

    def _count_items(self, data: Dict[str, Any]) -> int:
        total = 0
        if data.get('whois'):
            total += 1
        if data.get('rdap'):
            total += 1
        total += len(data.get('asn_info', []))
        return total
