"""
WHOIS and reverse-WHOIS service for the Recon app.

Performs WHOIS lookups using the python-whois library (optional) and
integrates with ViewDNS.info for reverse WHOIS queries.
"""
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

_TIMEOUT = None


def _get_timeout():
    global _TIMEOUT
    if _TIMEOUT is None:
        _TIMEOUT = getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)
    return _TIMEOUT


def perform_whois_lookup(domain: str) -> dict:
    """
    Perform a WHOIS lookup for *domain* and return a structured dict.

    Uses the ``python-whois`` library when available.  If the library is not
    installed or the lookup fails the function returns the raw text response
    (if any) together with empty structured fields so that the caller can still
    save partial data.

    Args:
        domain: The domain name to look up (e.g. ``example.com``).

    Returns:
        A dict with keys: registrar, registrant_name, registrant_email,
        registrant_org, registrant_phone, registrant_address,
        creation_date, expiration_date, name_servers, status, raw_data.
    """
    result = {
        'registrar': '',
        'registrant_name': '',
        'registrant_email': '',
        'registrant_org': '',
        'registrant_phone': '',
        'registrant_address': '',
        'creation_date': '',
        'expiration_date': '',
        'name_servers': '[]',
        'status': '',
        'raw_data': '',
    }

    try:
        import whois  # python-whois
    except ImportError:
        logger.warning("python-whois not installed; WHOIS lookup unavailable")
        return result

    try:
        w = whois.whois(domain)
        result['raw_data'] = str(w.text) if hasattr(w, 'text') else str(w)

        result['registrar'] = _first(w.get('registrar', ''))
        result['registrant_name'] = _first(w.get('name', ''))
        result['registrant_email'] = _first(w.get('emails', ''))
        result['registrant_org'] = _first(w.get('org', ''))

        ns = w.get('name_servers', [])
        if isinstance(ns, list):
            import json
            result['name_servers'] = json.dumps([str(n).lower() for n in ns])
        elif ns:
            import json
            result['name_servers'] = json.dumps([str(ns).lower()])

        creation = w.get('creation_date')
        if creation:
            result['creation_date'] = str(_first(creation))

        expiration = w.get('expiration_date')
        if expiration:
            result['expiration_date'] = str(_first(expiration))

        status = w.get('status', '')
        if isinstance(status, list):
            result['status'] = ', '.join(str(s) for s in status)
        elif status:
            result['status'] = str(status)

    except Exception as exc:
        logger.error("WHOIS lookup failed for %s: %s", domain, exc)

    return result


def _first(value):
    """Return the first element if *value* is a list, otherwise *value* itself."""
    if isinstance(value, list):
        return value[0] if value else ''
    return value or ''


def perform_reverse_whois(query: str, query_type: str = 'email') -> dict:
    """
    Perform a reverse WHOIS lookup via the ViewDNS.info API.

    This requires ``VIEWDNS_API_KEY`` to be set in Django settings.

    Args:
        query: The value to search for (e.g. an email address or org name).
        query_type: One of ``email``, ``name``, ``address``, ``company``
                    (as supported by ViewDNS).

    Returns:
        A dict with keys ``success`` (bool), ``domains`` (list), and
        ``error`` (str on failure).
    """
    api_key = getattr(settings, 'VIEWDNS_API_KEY', '')
    if not api_key:
        logger.warning("VIEWDNS_API_KEY not configured; reverse WHOIS unavailable")
        return {'success': False, 'domains': [], 'error': 'API key not configured'}

    try:
        import requests
        url = (
            f"https://api.viewdns.info/reversewhois/"
            f"?q={query}&apikey={api_key}&output=json"
        )
        response = requests.get(url, timeout=_get_timeout())
        response.raise_for_status()
        data = response.json()
        domains = [
            d.get('domain', '') for d in data.get('response', {}).get('domains', [])
        ]
        return {'success': True, 'domains': domains, 'error': ''}
    except Exception as exc:
        logger.error("Reverse WHOIS failed for %s: %s", query, exc)
        return {'success': False, 'domains': [], 'error': str(exc)}
