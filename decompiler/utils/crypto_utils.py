"""
Cryptographic utility functions for the decompiler app.

Provides entropy calculation, Base64/hex detection, and common
encryption pattern identification.
"""
import math
import re
import base64
from typing import List, Tuple


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Args:
        data: Input string

    Returns:
        Shannon entropy value (0.0 - 8.0 for bytes)
    """
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def calculate_bytes_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
_HEX_PATTERN = re.compile(r'[0-9a-fA-F]{16,}')
_XOR_PATTERN = re.compile(r'\bXOR\b|\^=|\bxor\b', re.IGNORECASE)
_ATOB_PATTERN = re.compile(r'\batob\s*\(|\bbtoa\s*\(')


def find_high_entropy_strings(source_code: str, threshold: float = 4.5) -> List[Tuple[str, float]]:
    """
    Find string literals with high Shannon entropy.

    Args:
        source_code: Source code to analyze
        threshold: Minimum entropy to flag

    Returns:
        List of (string, entropy) tuples
    """
    results = []
    string_pattern = re.compile(r'["\']([^"\']{10,})["\']')
    for match in string_pattern.finditer(source_code):
        s = match.group(1)
        entropy = calculate_entropy(s)
        if entropy >= threshold:
            results.append((s, entropy))
    return results


def find_base64_strings(source_code: str) -> List[str]:
    """Find potential Base64-encoded strings in source code."""
    results = []
    for match in _BASE64_PATTERN.finditer(source_code):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + '==')
            if len(decoded) > 3:
                results.append(candidate)
        except Exception:
            pass
    return results


def find_hex_encoded_strings(source_code: str) -> List[str]:
    """Find potential hex-encoded strings in source code."""
    return _HEX_PATTERN.findall(source_code)


def detect_xor_operations(source_code: str) -> bool:
    """Detect XOR operations near string constants (possible encryption)."""
    return bool(_XOR_PATTERN.search(source_code))


def detect_atob_usage(source_code: str) -> bool:
    """Detect atob()/btoa() Base64 decode/encode calls."""
    return bool(_ATOB_PATTERN.search(source_code))
