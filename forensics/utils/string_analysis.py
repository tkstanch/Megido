"""String extraction and analysis utilities."""
import re
from .ioc_extraction import extract_iocs


def extract_ascii_strings(data: bytes, min_length=4) -> list:
    """Extract ASCII printable strings from bytes."""
    pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    return [m.decode('ascii', errors='replace') for m in re.findall(pattern, data)]


def extract_unicode_strings(data: bytes, min_length=4) -> list:
    """Extract UTF-16LE strings from bytes."""
    pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    return [m.decode('utf-16-le', errors='replace') for m in re.findall(pattern, data)]


def analyze_strings(data: bytes) -> dict:
    """Full string analysis including IOC extraction."""
    ascii_strings = extract_ascii_strings(data)
    unicode_strings = extract_unicode_strings(data)
    combined_text = '\n'.join(ascii_strings + unicode_strings)
    iocs = {}
    try:
        iocs = extract_iocs(combined_text)
    except Exception:
        pass
    return {
        'ascii_count': len(ascii_strings),
        'unicode_count': len(unicode_strings),
        'ascii_sample': ascii_strings[:100],
        'unicode_sample': unicode_strings[:50],
        'iocs': iocs,
    }
