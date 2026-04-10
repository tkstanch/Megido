"""
Content Encoding Detection & Decoder

Automatically detects and decodes encoded content (base64, base64url,
hexadecimal, URL-encoding) found during web application investigation.

When the scanner encounters encoded content, it tries to decode it to
discover what the website is trying to communicate.
"""

import base64
import binascii
import re
import urllib.parse
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Regex patterns for encoding detection
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
_BASE64URL_RE = re.compile(r'^[A-Za-z0-9\-_]{4,}={0,2}$')
_HEX_RE = re.compile(r'^[0-9a-fA-F]{2,}$')
_URL_ENCODED_RE = re.compile(r'%[0-9a-fA-F]{2}')

# Patterns that suggest interesting decoded content
_INTERESTING_PATTERNS = [
    re.compile(r'(password|passwd|pwd|secret|token|api[_-]?key|auth|bearer|credential)', re.IGNORECASE),
    re.compile(r'(internal|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)', re.IGNORECASE),
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),  # Long base64-like strings (potential keys)
    re.compile(r'[a-zA-Z0-9]{32,}'),  # Long alphanumeric (potential tokens/hashes)
    re.compile(r'/[a-z]+/[a-z]+'),  # Internal paths
]


class ContentEncodingDetector:
    """
    Detects and decodes encoded content encountered during web application scanning.

    Supports:
    - Base64 (standard)
    - Base64URL (URL-safe base64)
    - Hexadecimal
    - URL encoding (percent-encoding)
    - Recursive / nested decoding
    """

    def detect_encoding(self, content: str) -> List[str]:
        """
        Detect which encoding types are present in the given content string.

        Returns a list of detected encoding type names. Possible values:
        'url_encoded', 'base64', 'base64url', 'hex'.
        """
        detected = []
        if not content or not isinstance(content, str):
            return detected

        stripped = content.strip()

        # URL encoding — check for percent-encoded sequences
        if _URL_ENCODED_RE.search(stripped):
            detected.append('url_encoded')

        # Hex — entire string is hex digits (even length, min 2 chars)
        if len(stripped) >= 2 and len(stripped) % 2 == 0 and _HEX_RE.fullmatch(stripped):
            # Avoid false-positives: require at least 4 hex chars
            if len(stripped) >= 4:
                detected.append('hex')

        # Base64 vs Base64URL — check only when no spaces / percent chars
        if '%' not in stripped and ' ' not in stripped:
            # Pad to multiple of 4 for validation
            padded = stripped + '=' * ((-len(stripped)) % 4)
            if _BASE64_RE.fullmatch(stripped):
                # Distinguish base64url (has - or _) from standard base64
                if '-' in stripped or '_' in stripped:
                    if _BASE64URL_RE.fullmatch(stripped):
                        detected.append('base64url')
                else:
                    # Validate that it actually decodes without error
                    try:
                        base64.b64decode(padded, validate=True)
                        # Only report base64 if result has printable content
                        decoded_bytes = base64.b64decode(padded, validate=True)
                        if len(decoded_bytes) >= 2:
                            detected.append('base64')
                    except Exception:
                        pass

        return detected

    def decode_content(self, content: str, encoding_type: str) -> str:
        """
        Decode content using the specified encoding type.

        Args:
            content: The encoded string to decode.
            encoding_type: One of 'base64', 'base64url', 'hex', 'url_encoded'.

        Returns:
            The decoded string, or the original content if decoding fails.
        """
        if not content or not isinstance(content, str):
            return content

        try:
            if encoding_type == 'base64':
                padded = content.strip() + '=' * ((-len(content.strip())) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
                return decoded_bytes.decode('utf-8', errors='replace')

            elif encoding_type == 'base64url':
                padded = content.strip() + '=' * ((-len(content.strip())) % 4)
                decoded_bytes = base64.urlsafe_b64decode(padded)
                return decoded_bytes.decode('utf-8', errors='replace')

            elif encoding_type == 'hex':
                decoded_bytes = bytes.fromhex(content.strip())
                return decoded_bytes.decode('utf-8', errors='replace')

            elif encoding_type == 'url_encoded':
                return urllib.parse.unquote(content)

        except Exception as exc:
            logger.debug("decode_content failed for type=%s: %s", encoding_type, exc)

        return content

    def auto_decode(self, content: str) -> Dict[str, Any]:
        """
        Auto-detect and decode the given content.

        Returns a dict with keys:
            original  – the original input string
            encoding  – detected encoding type (first detected), or None
            decoded   – decoded value, or original if no encoding detected
            depth     – decoding depth (always 1 for a single auto_decode call)
            interesting – True if decoded content matches interesting patterns
        """
        result: Dict[str, Any] = {
            'original': content,
            'encoding': None,
            'decoded': content,
            'depth': 0,
            'interesting': False,
        }

        if not content:
            return result

        detected = self.detect_encoding(content)
        if not detected:
            return result

        encoding = detected[0]
        decoded = self.decode_content(content, encoding)

        result['encoding'] = encoding
        result['decoded'] = decoded
        result['depth'] = 1
        result['interesting'] = self.is_interesting(decoded)
        return result

    def url_encode_hostname(self, hostname: str) -> str:
        """
        Calculate the URL-encoded equivalent of a hostname.

        Each character in the hostname is percent-encoded.

        Example:
            url_encode_hostname('example.com') -> '%65%78%61%6D%70%6C%65%2E%63%6F%6D'
        """
        if not hostname:
            return hostname
        return ''.join(f'%{ord(c):02X}' for c in hostname)

    def url_decode(self, content: str) -> str:
        """
        URL-decode (percent-decode) the given content.

        Equivalent to ``urllib.parse.unquote(content)``.
        """
        if not content:
            return content
        return urllib.parse.unquote(content)

    def recursive_decode(self, content: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        """
        Recursively decode nested encodings up to *max_depth* levels.

        Returns a list of dicts, each describing one decoding step:
            step     – step number (1-based)
            encoding – encoding type decoded at this step
            input    – value before decoding
            output   – value after decoding
            interesting – True if the output matches interesting patterns
        """
        steps: List[Dict[str, Any]] = []
        current = content

        for depth in range(1, max_depth + 1):
            detected = self.detect_encoding(current)
            if not detected:
                break

            encoding = detected[0]
            decoded = self.decode_content(current, encoding)

            if decoded == current:
                # Decoding did not change the value; stop to avoid infinite loops
                break

            steps.append({
                'step': depth,
                'encoding': encoding,
                'input': current,
                'output': decoded,
                'interesting': self.is_interesting(decoded),
            })
            current = decoded

        return steps

    def analyze_scan_response(self, response_body: str, url: str = '') -> List[Dict[str, Any]]:
        """
        Scan a response body for encoded values and return decoded findings.

        Extracts candidate encoded tokens from the response body, attempts to
        decode each one, and returns a list of findings for encoded values that
        successfully decode to something meaningful.

        Args:
            response_body: The full HTTP response body text.
            url: The URL the response came from (for context).

        Returns:
            List of dicts, each with keys:
                encoded_value, encoding_type, decoded_value, interesting, location
        """
        findings: List[Dict[str, Any]] = []
        if not response_body:
            return findings

        # Extract candidate tokens: long alphanumeric / base64-like sequences
        # and percent-encoded sequences
        candidates = set()

        # Percent-encoded sequences (collect contiguous encoded runs)
        for match in re.finditer(r'(?:%[0-9a-fA-F]{2})+', response_body):
            candidates.add(match.group())

        # Hex strings (standalone, even length, min 8 chars)
        for match in re.finditer(r'\b([0-9a-fA-F]{8,})\b', response_body):
            val = match.group(1)
            if len(val) % 2 == 0:
                candidates.add(val)

        # Base64 / base64url candidates (standalone tokens, min 8 chars)
        for match in re.finditer(r'[A-Za-z0-9+/\-_]{8,}={0,2}', response_body):
            val = match.group()
            if len(val) >= 8:
                candidates.add(val)

        for candidate in candidates:
            result = self.auto_decode(candidate)
            if result['encoding'] and result['decoded'] != candidate:
                findings.append({
                    'encoded_value': candidate,
                    'encoding_type': result['encoding'],
                    'decoded_value': result['decoded'],
                    'interesting': result['interesting'],
                    'location': url,
                })

        return findings

    def is_interesting(self, text: str) -> bool:
        """Return True if *text* matches any interesting content pattern."""
        if not text:
            return False
        return any(p.search(text) for p in _INTERESTING_PATTERNS)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_interesting(self, text: str) -> bool:
        """Deprecated alias kept for backward compatibility; use is_interesting()."""
        return self.is_interesting(text)
