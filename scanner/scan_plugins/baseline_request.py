"""
Shared Baseline Request Utility

Provides helpers for distinguishing genuine server-behaviour changes from
mere reflection artefacts.  Used by CRLF detector, open-redirect detector,
and any other plugin that needs to diff baseline vs. probe responses.

Public API
----------
fetch_baseline(url, verify_ssl, timeout)
    Send a clean GET request and return the response (or None on error).

diff_headers(baseline_response, probe_response)
    Return a dict of headers that are **new or changed** in the probe response
    compared to the baseline.  Headers present only in the baseline are ignored.

is_payload_reflected_in_url(response, payload)
    Return True when the only evidence of *payload* is its URL-encoded form
    inside a URL-bearing header (Location, Refresh, URI, Content-Location).
    Used to avoid false positives where the server simply reflects the
    request path back in a redirect without actually injecting a header.
"""

import logging
import urllib.parse
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Headers whose *values* often contain the request URL and therefore
# legitimately reflect URL-encoded payloads without being injected.
_URL_REFLECTION_HEADERS = {
    'location',
    'refresh',
    'uri',
    'content-location',
}

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    _HAS_REQUESTS = False


def fetch_baseline(
    url: str,
    verify_ssl: bool = False,
    timeout: int = 10,
) -> Optional['_requests.Response']:
    """
    Send a clean GET request to *url* and return the response.

    Returns None when requests is unavailable or the request fails.
    """
    if not _HAS_REQUESTS:
        return None
    try:
        return _requests.get(
            url,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
        )
    except Exception as exc:
        logger.debug("fetch_baseline(%s) failed: %s", url, exc)
        return None


def diff_headers(
    baseline_response: Optional['_requests.Response'],
    probe_response: Optional['_requests.Response'],
) -> Dict[str, str]:
    """
    Return headers that are **new or changed** in *probe_response* compared
    to *baseline_response*.

    If *baseline_response* is None every header in *probe_response* is
    considered new.  If *probe_response* is None an empty dict is returned.
    """
    if probe_response is None:
        return {}

    probe_headers: Dict[str, str] = {
        k.lower(): v for k, v in probe_response.headers.items()
    }

    if baseline_response is None:
        return dict(probe_headers)

    baseline_headers: Dict[str, str] = {
        k.lower(): v for k, v in baseline_response.headers.items()
    }

    changed: Dict[str, str] = {}
    for name, value in probe_headers.items():
        if name not in baseline_headers or baseline_headers[name] != value:
            changed[name] = value

    return changed


def is_payload_reflected_in_url(
    response: Optional['_requests.Response'],
    payload: str,
) -> bool:
    """
    Return True when *payload* (or its URL-decoded form) appears **only**
    inside URL-bearing response headers rather than as an actual injected
    header key.

    This prevents false positives where a server echoes the request path in a
    ``Location`` redirect without actually performing CRLF injection.

    The check works as follows:
    1. URL-decode the payload so that ``%0d%0aX-Megido-CRLF`` becomes
       ``\\r\\nX-Megido-CRLF``.
    2. Derive the substring we would look for (the injected header name part
       after the CRLF sequence, lower-cased).
    3. Scan every response header:
       - If the substring is found in a URL-reflection header *value*, record
         it as a URL-reflection match.
       - If the substring is found anywhere else (different header name, or a
         non-URL header), it is NOT pure URL reflection.
    4. Return True only when at least one URL-reflection match exists and no
       non-URL-reflection match was found.
    """
    if response is None or not payload:
        return False

    # Decode percent-encoding so we can search for the raw marker text
    try:
        decoded_payload = urllib.parse.unquote(payload).lower()
    except Exception:
        decoded_payload = payload.lower()

    # Extract the marker text: everything after the last \n in the payload
    # e.g. "\r\nX-Megido-CRLF: injected" → "x-megido-crlf"
    marker = decoded_payload.split('\n')[-1].split(':')[0].strip()
    if not marker:
        return False

    url_reflected = False
    non_url_reflected = False

    for header_name, header_value in response.headers.items():
        name_lower = header_name.lower()
        value_lower = header_value.lower()

        # Check if marker appears in the header value
        if marker in value_lower:
            if name_lower in _URL_REFLECTION_HEADERS:
                url_reflected = True
            else:
                non_url_reflected = True

    return url_reflected and not non_url_reflected
