"""
Certificate transparency log service for the Recon app.

Queries crt.sh to discover SSL certificates for a given domain.
"""
import logging

from django.conf import settings

logger = logging.getLogger(__name__)


def _get_timeout():
    return getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)


def query_crt_sh(domain: str) -> list:
    """
    Query the crt.sh certificate transparency log for *domain*.

    Args:
        domain: The domain to search (wildcards accepted, e.g. ``%.example.com``).

    Returns:
        A list of dicts, each containing:
        ``id``, ``issuer_ca_id``, ``issuer_name``, ``common_name``,
        ``name_value``, ``not_before``, ``not_after``.
        Returns an empty list on error.
    """
    try:
        import requests
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=_get_timeout())
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        logger.error("crt.sh query failed for %s: %s", domain, exc)
        return []
