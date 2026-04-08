"""
Port scanning service for the Recon app.

Provides passive port information from Shodan and a list of common ports
for active scanning tools.
"""
import logging

from django.conf import settings

logger = logging.getLogger(__name__)


def _get_timeout():
    return getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 8888, 9200, 27017,
]


def get_common_ports() -> list:
    """
    Return a list of common TCP ports to scan.

    Returns:
        A list of integer port numbers.
    """
    return list(COMMON_PORTS)


def passive_scan_shodan(host: str, api_key: str = None) -> list:
    """
    Retrieve port and service information for *host* from the Shodan API.

    Reads ``SHODAN_API_KEY`` from Django settings when *api_key* is not
    supplied directly.

    Args:
        host: Hostname or IP address to query.
        api_key: Optional Shodan API key override.

    Returns:
        A list of dicts with keys: port, protocol, service_name,
        service_version, banner.  Returns an empty list when the API key
        is missing or the query fails.
    """
    key = api_key or getattr(settings, 'SHODAN_API_KEY', None)
    if not key:
        logger.warning("SHODAN_API_KEY not configured; Shodan scan unavailable")
        return []

    try:
        import requests
        from .dns_service import resolve_domain

        # Shodan host lookup needs an IP address
        ips = resolve_domain(host)
        if not ips:
            logger.warning("Could not resolve %s for Shodan lookup", host)
            return []
        ip = ips[0]

        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        response = requests.get(url, timeout=_get_timeout())
        response.raise_for_status()
        data = response.json()

        results = []
        for service in data.get('data', []):
            results.append({
                'port': service.get('port', 0),
                'protocol': service.get('transport', 'tcp'),
                'service_name': service.get('_shodan', {}).get('module', ''),
                'service_version': service.get('version', ''),
                'banner': service.get('data', '')[:500],
            })
        return results

    except Exception as exc:
        logger.error("Shodan scan failed for %s: %s", host, exc)
        return []
