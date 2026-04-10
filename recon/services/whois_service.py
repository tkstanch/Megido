"""
WHOIS and reverse-WHOIS service for the Recon app.

Performs WHOIS lookups using the python-whois library (optional) and
integrates with ViewDNS.info for reverse WHOIS queries.  Falls back to
the RDAP API when python-whois is unavailable or the lookup fails.
"""
import json
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

    Tries the ``python-whois`` library first.  If the library is not
    installed or the lookup fails, falls back to the RDAP API
    (``https://rdap.org/domain/{domain}``) which requires no library and
    returns structured JSON.

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

    whois_ok = False
    try:
        import whois  # python-whois
        whois_ok = True
    except ImportError:
        logger.warning("python-whois not installed; falling back to RDAP")

    if whois_ok:
        try:
            w = whois.whois(domain)
            result['raw_data'] = str(w.text) if hasattr(w, 'text') else str(w)

            result['registrar'] = _first(w.get('registrar', ''))
            result['registrant_name'] = _first(w.get('name', ''))
            result['registrant_email'] = _first(w.get('emails', ''))
            result['registrant_org'] = _first(w.get('org', ''))

            ns = w.get('name_servers', [])
            if isinstance(ns, list):
                result['name_servers'] = json.dumps([str(n).lower() for n in ns])
            elif ns:
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

            # If we got at least a registrar, consider it successful
            if result['registrar'] or result['raw_data']:
                return result
            logger.warning("python-whois returned empty data for %s; trying RDAP", domain)
        except Exception as exc:
            logger.warning("python-whois lookup failed for %s: %s; falling back to RDAP", domain, exc)

    # RDAP fallback
    return _rdap_lookup(domain, result)


def _rdap_lookup(domain: str, result: dict) -> dict:
    """
    Fetch domain registration data from the RDAP API and populate *result*.

    Args:
        domain: Domain name to look up.
        result: Existing result dict to populate (modified in place).

    Returns:
        The populated result dict.
    """
    try:
        import requests
        url = f"https://rdap.org/domain/{domain}"
        response = requests.get(url, timeout=_get_timeout(), headers={'Accept': 'application/json'})
        response.raise_for_status()
        data = response.json()
        result['raw_data'] = json.dumps(data)

        # Registrar
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            vcard = entity.get('vcardArray', [])
            if 'registrar' in roles and vcard:
                for entry in vcard[1] if len(vcard) > 1 else []:
                    if entry[0] == 'fn':
                        result['registrar'] = entry[3]
                        break
            if 'registrant' in roles and vcard:
                for entry in vcard[1] if len(vcard) > 1 else []:
                    if entry[0] == 'fn' and not result['registrant_name']:
                        result['registrant_name'] = entry[3]
                    elif entry[0] == 'email' and not result['registrant_email']:
                        result['registrant_email'] = entry[3]
                    elif entry[0] == 'org' and not result['registrant_org']:
                        result['registrant_org'] = entry[3]
                    elif entry[0] == 'tel' and not result['registrant_phone']:
                        result['registrant_phone'] = entry[3]

        # Name servers
        ns_list = []
        for ns in data.get('nameservers', []):
            ldh_name = ns.get('ldhName', '')
            if ldh_name:
                ns_list.append(ldh_name.lower())
        if ns_list:
            result['name_servers'] = json.dumps(ns_list)

        # Dates
        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date = event.get('eventDate', '')
            if action == 'registration' and not result['creation_date']:
                result['creation_date'] = date
            elif action == 'expiration' and not result['expiration_date']:
                result['expiration_date'] = date

        # Status
        statuses = data.get('status', [])
        if statuses:
            result['status'] = ', '.join(statuses)

        logger.info("RDAP lookup successful for %s", domain)
    except Exception as exc:
        logger.error("RDAP lookup failed for %s: %s", domain, exc)

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
