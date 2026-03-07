"""Utility functions for the Repeater app."""

import base64
import binascii
import difflib
import json
import re
import urllib.parse
from typing import Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Raw HTTP request parsing / building
# ---------------------------------------------------------------------------

def parse_raw_request(raw: str) -> Dict:
    """Parse a raw HTTP request string into its components.

    Returns a dict with keys: method, url, http_version, headers, body.
    The *url* field contains only the path/query portion found in the
    request line; callers should combine it with a base URL if needed.
    """
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')

    # Split headers block from body at the first blank line
    if '\n\n' in raw:
        header_section, body = raw.split('\n\n', 1)
    else:
        header_section = raw
        body = ''

    lines = header_section.split('\n')
    request_line = lines[0].strip()

    # Parse the request line: METHOD PATH HTTP/VERSION
    parts = request_line.split(' ', 2)
    method = parts[0].upper() if len(parts) > 0 else 'GET'
    path = parts[1] if len(parts) > 1 else '/'
    http_version = parts[2] if len(parts) > 2 else 'HTTP/1.1'

    # Parse headers
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ':' in line:
            key, _, value = line.partition(':')
            headers[key.strip()] = value.strip()

    # Build a full URL from Host header if path doesn't look absolute
    host = headers.get('Host', '')
    if host and not path.startswith('http'):
        scheme = 'https' if ':443' in host else 'http'
        url = f"{scheme}://{host}{path}"
    else:
        url = path

    return {
        'method': method,
        'url': url,
        'http_version': http_version,
        'headers': headers,
        'body': body,
    }


def build_raw_request(method: str, url: str, headers: Dict[str, str], body: str = '') -> str:
    """Build a raw HTTP request string from its components."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    lines = [f"{method.upper()} {path} HTTP/1.1"]

    # Ensure Host header is present
    if 'Host' not in headers and parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")

    for key, value in headers.items():
        lines.append(f"{key}: {value}")

    lines.append('')  # blank line separating headers from body
    lines.append(body or '')

    return '\r\n'.join(lines)


# ---------------------------------------------------------------------------
# Response comparison / diff
# ---------------------------------------------------------------------------

def compare_responses(response_a: Dict, response_b: Dict) -> Dict:
    """Compare two response dicts and return a structured diff.

    Each response dict should have: status_code, headers (dict or JSON str),
    body (str).
    """
    def _parse_headers(h):
        if isinstance(h, str):
            try:
                return json.loads(h)
            except (json.JSONDecodeError, TypeError):
                return {}
        return h or {}

    headers_a = _parse_headers(response_a.get('headers', {}))
    headers_b = _parse_headers(response_b.get('headers', {}))

    body_a = (response_a.get('body') or '').splitlines(keepends=True)
    body_b = (response_b.get('body') or '').splitlines(keepends=True)

    body_diff = list(difflib.unified_diff(body_a, body_b, fromfile='Response A', tofile='Response B'))

    # Header diff
    all_header_keys = set(headers_a.keys()) | set(headers_b.keys())
    header_diff = {}
    for key in sorted(all_header_keys):
        val_a = headers_a.get(key)
        val_b = headers_b.get(key)
        if val_a != val_b:
            header_diff[key] = {'a': val_a, 'b': val_b}

    status_a = response_a.get('status_code')
    status_b = response_b.get('status_code')

    return {
        'status_code': {'a': status_a, 'b': status_b, 'changed': status_a != status_b},
        'headers': header_diff,
        'body_diff': ''.join(body_diff),
        'body_changed': body_a != body_b,
    }


# ---------------------------------------------------------------------------
# Encoding / decoding helpers
# ---------------------------------------------------------------------------

def url_encode(value: str) -> str:
    """Percent-encode a string."""
    return urllib.parse.quote(value, safe='')


def url_decode(value: str) -> str:
    """Decode a percent-encoded string."""
    return urllib.parse.unquote(value)


def base64_encode(value: str) -> str:
    """Base64-encode a UTF-8 string."""
    return base64.b64encode(value.encode('utf-8')).decode('ascii')


def base64_decode(value: str) -> str:
    """Decode a base64-encoded string to UTF-8."""
    try:
        return base64.b64decode(value).decode('utf-8')
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid base64 input: {exc}") from exc


def unicode_escape(value: str) -> str:
    """Escape a string to ASCII-safe unicode escape sequences."""
    return value.encode('unicode_escape').decode('ascii')


def unicode_unescape(value: str) -> str:
    """Unescape unicode escape sequences back to unicode."""
    return value.encode('ascii').decode('unicode_escape')


# ---------------------------------------------------------------------------
# Content-Length auto-update
# ---------------------------------------------------------------------------

def update_content_length(headers: Dict[str, str], body: str) -> Dict[str, str]:
    """Return a copy of *headers* with Content-Length set to len(body)."""
    updated = dict(headers)
    body_bytes = (body or '').encode('utf-8')
    updated['Content-Length'] = str(len(body_bytes))
    return updated


def update_content_length_in_raw(raw: str) -> str:
    """Update (or insert) the Content-Length header in a raw HTTP request."""
    parsed = parse_raw_request(raw)
    body = parsed.get('body', '')
    content_length = str(len((body or '').encode('utf-8')))

    # Replace existing Content-Length header (case-insensitive, handle CRLF line endings)
    updated = re.sub(
        r'(?im)^Content-Length:\s*\d+\r?$',
        f'Content-Length: {content_length}',
        raw,
    )

    if not re.search(r'(?im)^Content-Length:', updated):
        # Insert before the blank line that separates headers from body
        updated = re.sub(r'(\r?\n\r?\n)', f'\r\nContent-Length: {content_length}\\1', updated, count=1)

    return updated


# ---------------------------------------------------------------------------
# Hex dump helper
# ---------------------------------------------------------------------------

def hexdump(data: str, bytes_per_row: int = 16) -> str:
    """Return a hexdump representation of *data* (encoded as UTF-8)."""
    raw_bytes = data.encode('utf-8', errors='replace')
    rows = []
    for i in range(0, len(raw_bytes), bytes_per_row):
        chunk = raw_bytes[i:i + bytes_per_row]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        rows.append(f'{i:08x}  {hex_part:<{bytes_per_row * 3}}  {ascii_part}')
    return '\n'.join(rows)
