"""
Subdomain enumeration service for the Recon app.

Provides brute-force enumeration and certificate-transparency-based discovery.
"""
import logging

from .cert_service import query_crt_sh
from .dns_service import resolve_domain

logger = logging.getLogger(__name__)

DEFAULT_WORDLIST = [
    'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'test', 'admin',
    'portal', 'app', 'web', 'smtp', 'vpn', 'ns1', 'ns2', 'mx', 'cdn',
    'static', 'assets', 'beta',
]


def brute_force_subdomains(domain: str, wordlist: list = None) -> list:
    """
    Try common subdomain prefixes against *domain* using DNS resolution.

    Args:
        domain: The root domain (e.g. ``example.com``).
        wordlist: Optional list of prefixes to try.  Defaults to
                  :data:`DEFAULT_WORDLIST`.

    Returns:
        A list of dicts with keys ``subdomain``, ``ip_address``, ``source``.
    """
    prefixes = wordlist if wordlist is not None else DEFAULT_WORDLIST
    results = []
    for prefix in prefixes:
        candidate = f"{prefix}.{domain}"
        ips = resolve_domain(candidate)
        if ips:
            results.append({
                'subdomain': candidate,
                'ip_address': ips[0],
                'source': 'brute-force',
            })
            logger.debug("Found subdomain %s -> %s", candidate, ips[0])
    return results


def enumerate_from_certs(domain: str) -> list:
    """
    Discover subdomains from certificate transparency logs via crt.sh.

    Args:
        domain: The root domain to query.

    Returns:
        A list of dicts with keys ``subdomain``, ``ip_address``, ``source``.
    """
    certs = query_crt_sh(f"%.{domain}")
    seen = set()
    results = []
    for cert in certs:
        name_value = cert.get('name_value', '')
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip('*.')
            if name and name.endswith(domain) and name not in seen:
                seen.add(name)
                ips = resolve_domain(name)
                results.append({
                    'subdomain': name,
                    'ip_address': ips[0] if ips else '',
                    'source': 'crt.sh',
                })
    return results
