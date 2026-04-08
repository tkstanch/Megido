"""
Cloud bucket discovery service for the Recon app.

Checks AWS S3 bucket existence and basic permissions; generates name
variations from keywords.
"""
import logging

from django.conf import settings

logger = logging.getLogger(__name__)


def _get_timeout():
    return getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30)


def generate_bucket_names(keyword: str) -> list:
    """
    Generate plausible S3 / cloud bucket name variations from *keyword*.

    Args:
        keyword: The seed keyword (e.g. a company name).

    Returns:
        A deduplicated list of bucket name strings.
    """
    kw = keyword.lower().replace(' ', '-').replace('_', '-')
    names = [
        kw,
        f"{kw}-backup",
        f"{kw}-backups",
        f"{kw}-data",
        f"{kw}-dev",
        f"{kw}-staging",
        f"{kw}-prod",
        f"{kw}-assets",
        f"{kw}-media",
        f"{kw}-uploads",
        f"{kw}-files",
        f"{kw}-static",
        f"{kw}-logs",
        f"{kw}-db",
        f"backup-{kw}",
        f"data-{kw}",
        f"dev-{kw}",
    ]
    return list(dict.fromkeys(names))


def check_s3_bucket(bucket_name: str) -> dict:
    """
    Check whether an AWS S3 bucket exists and probe its access level.

    The check is performed without credentials (anonymous HTTP request) so
    only public buckets can be discovered.

    Args:
        bucket_name: The S3 bucket name to check.

    Returns:
        A dict with keys: exists (bool), is_public (bool or None),
        is_listable (bool), is_writable (bool), bucket_url (str),
        error (str).
    """
    result = {
        'exists': False,
        'is_public': None,
        'is_listable': False,
        'is_writable': False,
        'bucket_url': '',
        'error': '',
    }

    try:
        import requests
        bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
        result['bucket_url'] = bucket_url

        resp = requests.get(bucket_url, timeout=_get_timeout())
        status = resp.status_code

        if status == 404:
            # Bucket does not exist
            return result

        result['exists'] = True

        if status == 200:
            result['is_public'] = True
            # A 200 on bucket root typically means listing is allowed
            result['is_listable'] = True
        elif status == 403:
            result['is_public'] = False
        elif status == 301:
            result['is_public'] = True

        # Probe writability with an OPTIONS request (non-destructive)
        try:
            opts = requests.options(bucket_url, timeout=_get_timeout())
            allow = opts.headers.get('Allow', '')
            if 'PUT' in allow or 'POST' in allow:
                result['is_writable'] = True
        except Exception:
            pass

    except Exception as exc:
        logger.error("S3 bucket check failed for %s: %s", bucket_name, exc)
        result['error'] = str(exc)

    return result
