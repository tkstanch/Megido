"""
Port scanning service for the Recon app.

Provides passive port information from Shodan and a socket-based active
fallback for when the Shodan API key is not configured.
"""
import logging
import socket
import concurrent.futures

from django.conf import settings

logger = logging.getLogger(__name__)


def _get_timeout():
    return getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 8888, 9200, 27017,
]

# Well-known service names for common ports
_PORT_SERVICE_NAMES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
    465: 'smtps', 587: 'submission', 993: 'imaps', 995: 'pop3s',
    1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 3389: 'rdp',
    5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
    8443: 'https-alt', 8888: 'http-alt', 9200: 'elasticsearch',
    27017: 'mongodb',
}

# Maximum number of concurrent socket probes during an active scan
MAX_CONCURRENT_PORT_SCANS = 50


def get_common_ports() -> list:
    """
    Return a list of common TCP ports to scan.

    Returns:
        A list of integer port numbers.
    """
    return list(COMMON_PORTS)


def _check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if *port* is open on *host*."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def active_scan_socket(host: str, ports: list = None, timeout: float = 3.0) -> list:
    """
    Perform a basic TCP connect scan on *host* for the given *ports*.

    Uses a thread pool to probe ports concurrently so the scan completes
    in a reasonable time.

    Args:
        host: Hostname or IP address to scan.
        ports: List of integer port numbers to probe.  Defaults to
               :data:`COMMON_PORTS`.
        timeout: Per-port connection timeout in seconds.

    Returns:
        A list of dicts with keys: port, protocol, service_name,
        service_version, banner.  Only open ports are returned.
    """
    ports = ports if ports is not None else COMMON_PORTS
    results = []

    def probe(port):
        if _check_port(host, port, timeout):
            return {
                'port': port,
                'protocol': 'tcp',
                'service_name': _PORT_SERVICE_NAMES.get(port, ''),
                'service_version': '',
                'banner': '',
            }
        return None

    max_workers = min(MAX_CONCURRENT_PORT_SCANS, len(ports))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception as exc:
                logger.debug("Port probe error on %s: %s", futures[future], exc)

    results.sort(key=lambda r: r['port'])
    logger.info("Socket scan of %s complete: %d open ports", host, len(results))
    return results


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
