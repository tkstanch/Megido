"""
Shodan Engine

Queries the Shodan API to retrieve internet-wide scan data for a target:
  - Open ports and services with banners
  - OS detection
  - CVE/vulnerability information
  - Geolocation and network metadata
"""
import logging
import os
import socket
from typing import Any, Dict, List

import requests

from .base_engine import BaseOSINTEngine

logger = logging.getLogger(__name__)

SHODAN_HOST_URL = 'https://api.shodan.io/shodan/host/{ip}'
SHODAN_DNS_URL = 'https://api.shodan.io/dns/resolve'


class ShodanEngine(BaseOSINTEngine):
    """
    Shodan internet-wide scan data: open ports, services, banners, vulnerabilities,
    and OS detection.

    Uses the Shodan REST API (no shodan Python package required).  Configure the
    API key via the ``shodan_api_key`` config key or the ``SHODAN_API_KEY``
    environment variable.
    """

    name = 'ShodanEngine'
    description = (
        'Shodan internet-wide scan data: open ports, services, banners, '
        'vulnerabilities, and OS detection'
    )
    is_active = False
    rate_limit_delay = 1.0

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------

    def collect(self, target: str) -> Dict[str, Any]:
        api_key = self._get_config(
            'shodan_api_key',
            os.environ.get('SHODAN_API_KEY', ''),
        )

        errors: List[str] = []
        domain = target.strip().lower()

        # Determine whether target is a domain or an IP
        ip = self._resolve_ip(domain, errors)

        host_data: Dict[str, Any] = {}
        if ip:
            host_data = self._query_host(ip, api_key, errors)

        # Build structured response
        ports: List[int] = host_data.get('ports', [])
        services: List[Dict[str, Any]] = self._extract_services(host_data)
        vulns: List[str] = list(host_data.get('vulns', {}).keys()) if isinstance(host_data.get('vulns'), dict) else []
        location = self._extract_location(host_data)

        return {
            'ip': ip or target,
            'hostnames': host_data.get('hostnames', []),
            'ports': ports,
            'services': services,
            'os': host_data.get('os'),
            'vulns': vulns,
            'location': location,
            'last_update': host_data.get('last_update'),
            'tags': host_data.get('tags', []),
            'total_ports': len(ports),
            'errors': errors,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_ip(self, target: str, errors: List[str]) -> str:
        """Return the IPv4 address for *target*, resolving via DNS when needed."""
        # If it already looks like an IPv4 address, return it directly
        parts = target.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return target
        try:
            return socket.gethostbyname(target)
        except Exception as exc:
            errors.append(f'DNS resolution failed for {target}: {exc}')
            return ''

    def _query_host(self, ip: str, api_key: str, errors: List[str]) -> Dict[str, Any]:
        """Query the Shodan /shodan/host/{ip} endpoint."""
        url = SHODAN_HOST_URL.format(ip=ip)
        try:
            resp = requests.get(url, params={'key': api_key}, timeout=15)
            if resp.status_code == 401:
                errors.append('Shodan: invalid API key')
                return {}
            if resp.status_code == 404:
                errors.append(f'Shodan: no information available for {ip}')
                return {}
            if resp.status_code == 429:
                errors.append('Shodan: rate limit exceeded')
                return {}
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            errors.append(f'Shodan host lookup failed: {exc}')
            return {}

    def _extract_services(self, host_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build a normalised list of service dicts from Shodan host data."""
        services = []
        for item in host_data.get('data', []):
            port = item.get('port')
            transport = item.get('transport', 'tcp')
            product = item.get('product', '')
            version = item.get('version', '')
            banner = item.get('data', '')
            services.append({
                'port': port,
                'protocol': transport,
                'product': product,
                'version': version,
                'banner_snippet': banner[:200] if banner else '',
            })
        return services

    def _extract_location(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract a normalised location dict from Shodan host data."""
        loc = host_data.get('location', {})
        return {
            'country': loc.get('country_name') or host_data.get('country_name'),
            'city': loc.get('city') or host_data.get('city'),
            'latitude': loc.get('latitude') or host_data.get('latitude'),
            'longitude': loc.get('longitude') or host_data.get('longitude'),
            'isp': host_data.get('isp'),
            'org': host_data.get('org'),
        }

    def _count_items(self, data: Dict[str, Any]) -> int:
        return data.get('total_ports', 0)
