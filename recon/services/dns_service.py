"""
DNS resolution, reverse IP lookup, and ASN data service for the Recon app.
"""
import json
import logging
import socket

from django.conf import settings

logger = logging.getLogger(__name__)


def _get_timeout():
    return getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)


def resolve_domain(domain: str) -> list:
    """
    Resolve *domain* to a list of IP address strings.

    Tries the ``dnspython`` library first for reliable resolution inside
    Docker containers, then falls back to :func:`socket.getaddrinfo`.
    Returns an empty list on failure.

    Args:
        domain: The domain name to resolve (e.g. ``example.com``).

    Returns:
        A list of unique IP address strings.
    """
    ips = []

    # Primary: use dnspython for reliable resolution inside Docker
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(_get_timeout())
        for record_type in ('A', 'AAAA'):
            try:
                answers = resolver.resolve(domain, record_type)
                for rdata in answers:
                    ip = str(rdata.address)
                    if ip not in ips:
                        ips.append(ip)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers):
                pass
        if ips:
            return ips
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("dnspython resolution failed for %s: %s", domain, exc)

    # Fallback: socket.getaddrinfo
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception as exc:
        logger.error("DNS resolution failed for %s: %s", domain, exc)
    return ips


def reverse_ip_lookup(ip_address: str) -> str:
    """
    Perform a reverse DNS lookup on *ip_address*.

    Args:
        ip_address: A dotted-decimal IPv4 or colon-separated IPv6 address.

    Returns:
        The hostname string, or an empty string on failure.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except Exception as exc:
        logger.debug("Reverse DNS failed for %s: %s", ip_address, exc)
        return ''


def get_asn_info(ip_address: str) -> dict:
    """
    Retrieve ASN and network organisation data for *ip_address* from
    ``ipinfo.io``.

    Reads ``IPINFO_TOKEN`` from Django settings (optional – unauthenticated
    requests are rate-limited by ipinfo.io).

    Args:
        ip_address: The IP address to look up.

    Returns:
        A dict with keys: asn_number, asn_org, asn_country, ip_range.
        Empty strings are used for unavailable fields.
    """
    result = {
        'asn_number': '',
        'asn_org': '',
        'asn_country': '',
        'ip_range': '',
    }

    try:
        import requests
        token = getattr(settings, 'IPINFO_TOKEN', '')
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {}
        if token:
            headers['Authorization'] = f"Bearer {token}"

        response = requests.get(url, headers=headers, timeout=_get_timeout())
        response.raise_for_status()
        data = response.json()

        org = data.get('org', '')
        if org:
            parts = org.split(' ', 1)
            if len(parts) == 2 and parts[0].startswith('AS'):
                result['asn_number'] = parts[0]
                result['asn_org'] = parts[1]
            else:
                result['asn_org'] = org

        result['asn_country'] = data.get('country', '')
        result['ip_range'] = data.get('network', '')

    except Exception as exc:
        logger.error("ASN lookup failed for %s: %s", ip_address, exc)

    return result
