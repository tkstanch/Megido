"""
Response Normalisation Utilities
=================================
Provides helpers for cleaning HTTP response bodies so that two responses from
the same target can be compared accurately, reducing false positives caused by
dynamic content.

Pipeline (applied in order):
  1. strip_html       – remove HTML markup
  2. normalize_whitespace – collapse runs of whitespace to a single space
  3. scrub_dynamic_tokens – replace timestamps, UUIDs, CSRF-like tokens, …
                           with stable placeholders

``normalize_response_body`` applies the full pipeline.
``fingerprint``             returns a short SHA-256 hex digest of the
                            normalised text for fast equality checks.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Tuple

# ---------------------------------------------------------------------------
# HTML stripping
# ---------------------------------------------------------------------------

# Minimal, zero-dependency HTML tag stripper.  We deliberately avoid importing
# html.parser or third-party libraries so this module stays self-contained.
_HTML_TAG_RE = re.compile(r"<[^>]+>", re.DOTALL)
_HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);")


def strip_html(text: str) -> str:
    """Remove HTML tags and decode common HTML entities from *text*."""
    text = _HTML_TAG_RE.sub(" ", text)
    # Decode a small set of common entities to avoid false differences
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace(
        "&gt;", ">"
    ).replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    # Strip any remaining entities
    text = _HTML_ENTITY_RE.sub(" ", text)
    return text


# ---------------------------------------------------------------------------
# Whitespace normalisation
# ---------------------------------------------------------------------------

_MULTI_WS_RE = re.compile(r"\s+")


def normalize_whitespace(text: str) -> str:
    """Collapse consecutive whitespace characters to a single space and strip
    leading/trailing whitespace."""
    return _MULTI_WS_RE.sub(" ", text).strip()


# ---------------------------------------------------------------------------
# Dynamic token scrubbing
# ---------------------------------------------------------------------------

# Each entry is (compiled pattern, stable placeholder).
# Patterns are applied in the order listed so more specific patterns (e.g. UUID)
# are matched before generic hex strings.
_SCRUB_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # ISO-8601 / RFC-2822 timestamps
    (
        re.compile(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
            r"(?:Z|[+-]\d{2}:?\d{2})?",
        ),
        "<TIMESTAMP>",
    ),
    # UUID / GUID
    (
        re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ),
        "<UUID>",
    ),
    # Unix epoch integers (10-13 digit numbers)
    (re.compile(r"\b\d{10,13}\b"), "<EPOCH>"),
    # Request / trace / correlation IDs embedded as key=value pairs
    (
        re.compile(
            r'(?i)(x-request-id|x-trace-id|x-correlation-id|nonce|'
            r'_csrf|csrf_token|csrfmiddlewaretoken)["\s:=]+[^\s"<>&]+',
        ),
        "<REQUEST_ID>",
    ),
    # Long hexadecimal tokens (CSRF nonces, session IDs, …) — 16+ hex chars
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HEX_TOKEN>"),
    # JWT / base64 blobs (≥32 base64 chars with optional padding)
    (re.compile(r"[A-Za-z0-9+/]{32,}={0,2}"), "<B64_TOKEN>"),
]


def scrub_dynamic_tokens(text: str) -> str:
    """Replace volatile tokens in *text* with stable placeholders so that two
    responses that are semantically identical (but contain different session
    tokens / timestamps) compare as equal."""
    for pattern, placeholder in _SCRUB_PATTERNS:
        text = pattern.sub(placeholder, text)
    return text


# ---------------------------------------------------------------------------
# Full normalisation pipeline
# ---------------------------------------------------------------------------


def normalize_response_body(text: str) -> str:
    """Apply the full normalisation pipeline to an HTTP response body.

    Steps:
    1. Strip HTML markup.
    2. Normalize whitespace.
    3. Scrub dynamic tokens.
    """
    text = strip_html(text)
    text = normalize_whitespace(text)
    text = scrub_dynamic_tokens(text)
    return text


# ---------------------------------------------------------------------------
# Stable fingerprint
# ---------------------------------------------------------------------------


def fingerprint(text: str, *, normalise: bool = True) -> str:
    """Return a short (16-char) hex fingerprint of *text*.

    If *normalise* is True (default) the full normalisation pipeline is applied
    before hashing so that two semantically identical responses always produce
    the same fingerprint.
    """
    if normalise:
        text = normalize_response_body(text)
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
