"""
Visual Proof of Concept (VPoC) – data model and shared helpers.

Provides a consistent evidence data model and utilities used by all
exploit-capable scan plugins for capturing, sanitizing, and serializing
VPoC artifacts.

Key components
--------------
VPoCEvidence
    Dataclass that stores all information needed to reproduce a finding.
    Sensitive data is redacted and large bodies are bounded.

redact_sensitive_headers(headers)
    Returns a copy of a headers dict with secrets replaced by '[REDACTED]'.

truncate_body(body, max_length)
    Truncates a string to at most *max_length* characters and appends a
    notice when shortening occurred.

build_curl_command(url, method, headers, body)
    Produces a copy-pasteable curl command for manual reproduction.

capture_request_response_evidence(response, ...)
    Convenience function that builds a VPoCEvidence object from a
    ``requests.Response`` instance.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum body size (characters) stored in evidence; larger bodies are truncated.
BODY_MAX_LENGTH = 4096

#: Suffix appended to truncated bodies.
BODY_TRUNCATION_NOTICE = '\n... [truncated] ...'

#: Replacement value for sensitive header content.
REDACTED = '[REDACTED]'

# Header names whose *values* must be redacted before storage.
_SENSITIVE_HEADER_RE = re.compile(
    r'^(authorization|cookie|set-cookie|x-auth-token|x-api-key|'
    r'proxy-authorization|www-authenticate|x-amz-security-token|'
    r'x-csrf-token|x-xsrf-token)$',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class VPoCEvidence:
    """
    Visual Proof of Concept evidence artifact.

    Stores all information required to reproduce and understand a finding
    produced by an exploit-capable scanner plugin.  Sensitive data is
    redacted and large bodies are bounded before reaching this object.

    Attributes
    ----------
    plugin_name : str
        Identifier of the plugin that produced this evidence.
    target_url : str
        The URL that was targeted (without injected payload).
    payload : str
        The payload or crafted input that triggered the vulnerability.
    confidence : float
        Confidence score in the range [0.0, 1.0].
    http_request : dict, optional
        Sanitized representation of the outgoing HTTP request::

            {
                'method': 'GET',
                'url': 'https://example.com/page?next=...',
                'headers': {'User-Agent': 'Megido/1.0', ...},
                'body': '',
            }

    http_response : dict, optional
        Sanitized representation of the HTTP response::

            {
                'status_code': 302,
                'headers': {'Location': 'https://evil.com', ...},
                'body': '',
            }

    reproduction_steps : str, optional
        Human-readable step-by-step reproduction instructions.
    redirect_chain : list of str, optional
        Sequence of redirect URLs (relevant for open-redirect findings).
    curl_command : str, optional
        Ready-to-run ``curl`` command that reproduces the request.
    screenshots : list of str, optional
        File-system paths to screenshot evidence (when available).
    timestamp : str
        ISO-8601 UTC timestamp when this evidence was captured.
    """

    plugin_name: str
    target_url: str
    payload: str
    confidence: float

    http_request: Optional[Dict[str, Any]] = None
    http_response: Optional[Dict[str, Any]] = None
    reproduction_steps: Optional[str] = None
    redirect_chain: Optional[List[str]] = None
    curl_command: Optional[str] = None
    screenshots: Optional[List[str]] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain, JSON-safe dictionary."""
        d: Dict[str, Any] = {
            'plugin_name': self.plugin_name,
            'target_url': self.target_url,
            'payload': self.payload,
            'confidence': self.confidence,
            'timestamp': self.timestamp,
        }
        if self.http_request is not None:
            d['http_request'] = self.http_request
        if self.http_response is not None:
            d['http_response'] = self.http_response
        if self.reproduction_steps:
            d['reproduction_steps'] = self.reproduction_steps
        if self.redirect_chain:
            d['redirect_chain'] = self.redirect_chain
        if self.curl_command:
            d['curl_command'] = self.curl_command
        if self.screenshots:
            d['screenshots'] = self.screenshots
        return d


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Return a copy of *headers* with sensitive values replaced by ``'[REDACTED]'``.

    The following header names are redacted (case-insensitive):
    ``Authorization``, ``Cookie``, ``Set-Cookie``, ``X-Auth-Token``,
    ``X-Api-Key``, ``Proxy-Authorization``, ``WWW-Authenticate``,
    ``X-Amz-Security-Token``, ``X-CSRF-Token``, ``X-XSRF-Token``.

    Parameters
    ----------
    headers : dict
        Mapping of header name → value.

    Returns
    -------
    dict
        Copy with sensitive values replaced.
    """
    return {
        name: REDACTED if _SENSITIVE_HEADER_RE.match(name) else value
        for name, value in headers.items()
    }


def truncate_body(body: str, max_length: int = BODY_MAX_LENGTH) -> str:
    """
    Truncate *body* to at most *max_length* characters.

    When the body is shortened a truncation notice is appended so that
    readers can tell the content is incomplete.

    Parameters
    ----------
    body : str
        Raw body string.
    max_length : int
        Maximum number of characters to retain (default: 4096).

    Returns
    -------
    str
        Truncated (or unchanged) body string.
    """
    if len(body) <= max_length:
        return body
    return body[:max_length] + BODY_TRUNCATION_NOTICE


def build_curl_command(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
) -> str:
    """
    Build a ``curl`` command string for reproducing an HTTP request.

    Sensitive header values are redacted before inclusion so that the
    command can be stored or shared safely.

    Parameters
    ----------
    url : str
        Request URL.
    method : str
        HTTP verb (default: ``'GET'``).
    headers : dict, optional
        Request headers.
    body : str, optional
        Request body (for POST/PUT requests).

    Returns
    -------
    str
        Formatted curl command.
    """
    safe_headers = redact_sensitive_headers(headers or {})
    parts = ['curl', '-X', method.upper()]

    for name, value in safe_headers.items():
        header_str = f'{name}: {value}'
        parts += ['-H', f"'{header_str}'" if ' ' in header_str else header_str]

    if body:
        parts += ['--data', f"'{body}'" if ' ' in body else body]

    parts.append(f"'{url}'" if ' ' in url else url)
    return ' '.join(parts)


def capture_request_response_evidence(
    response: Any,
    plugin_name: str,
    payload: str,
    confidence: float,
    target_url: str,
    redirect_chain: Optional[List[str]] = None,
    reproduction_steps: Optional[str] = None,
) -> 'VPoCEvidence':
    """
    Build a :class:`VPoCEvidence` instance from a ``requests.Response`` object.

    Both the request and response are sanitized (headers redacted, bodies
    truncated) before being stored in the evidence object.

    Parameters
    ----------
    response : requests.Response
        The HTTP response received during the exploit-capable check.
    plugin_name : str
        Name/ID of the calling plugin.
    payload : str
        The payload that was injected / tested.
    confidence : float
        Confidence score for this finding.
    target_url : str
        Original target URL (without injected payload).
    redirect_chain : list of str, optional
        Ordered list of redirect URLs encountered during the request.
    reproduction_steps : str, optional
        Human-readable instructions for reproducing the finding.

    Returns
    -------
    VPoCEvidence
        Populated evidence artifact.
    """
    # --- Capture outgoing request ---
    req = getattr(response, 'request', None)
    http_request: Optional[Dict[str, Any]] = None
    if req is not None:
        try:
            req_headers: Dict[str, str] = {
                str(k): str(v) for k, v in (req.headers or {}).items()
            }
        except Exception:
            req_headers = {}
        req_body = req.body or ''
        if isinstance(req_body, bytes):
            req_body = req_body.decode('utf-8', errors='replace')
        http_request = {
            'method': str(req.method or 'GET'),
            'url': str(req.url or target_url),
            'headers': redact_sensitive_headers(req_headers),
            'body': truncate_body(str(req_body)),
        }

    # --- Capture response ---
    try:
        resp_headers: Dict[str, str] = {
            str(k): str(v) for k, v in (response.headers or {}).items()
        }
    except Exception:
        resp_headers = {}
    http_response: Dict[str, Any] = {
        'status_code': int(response.status_code),
        'headers': redact_sensitive_headers(resp_headers),
        'body': truncate_body(str(response.text or '')),
    }

    # --- Build curl command ---
    curl_cmd: Optional[str] = None
    if http_request is not None:
        try:
            curl_cmd = build_curl_command(
                http_request['url'],
                method=http_request['method'],
                headers=http_request['headers'],
                body=http_request['body'] or None,
            )
        except Exception:
            pass

    return VPoCEvidence(
        plugin_name=plugin_name,
        target_url=target_url,
        payload=payload,
        confidence=confidence,
        http_request=http_request,
        http_response=http_response,
        redirect_chain=redirect_chain,
        reproduction_steps=reproduction_steps,
        curl_command=curl_cmd,
    )
