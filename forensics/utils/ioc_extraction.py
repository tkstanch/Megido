"""IOC extraction engine using regex patterns."""
import re

# IOC regex patterns
_IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_IPV6_RE = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}')
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|ru|cn|jp|br|au|info|biz|xyz|onion|top|club|site|online|tech|app|cloud|store|shop|dev|ai)\b', re.IGNORECASE)
_URL_RE = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]{3,500}', re.IGNORECASE)
_EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_WIN_PATH_RE = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
_UNIX_PATH_RE = re.compile(r'/(?:etc|var|usr|home|tmp|root|bin|sbin|lib|opt|proc|sys|dev)/[^\s\x00-\x1f]{1,200}')
_REG_KEY_RE = re.compile(r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR)\\[^\s\x00-\x1f]{3,300}', re.IGNORECASE)
_MD5_RE = re.compile(r'\b[0-9a-fA-F]{32}\b')
_SHA1_RE = re.compile(r'\b[0-9a-fA-F]{40}\b')
_SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
_BTC_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b')
_ETH_RE = re.compile(r'\b0x[0-9a-fA-F]{40}\b')

_FALSE_POS_IPS = {'0.0.0.0', '127.0.0.1', '255.255.255.255', '192.168.0.0', '10.0.0.0'}
_FALSE_POS_DOMAINS = {'localhost', 'example.com', 'test.com', 'domain.com'}


def extract_iocs(data) -> dict:
    """
    Extract all IOC types from bytes or string.

    Returns dict mapping ioc_type -> list of values.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = ''
    else:
        text = str(data)

    result = {
        'ipv4': list(set(_IPV4_RE.findall(text))),
        'ipv6': list(set(_IPV6_RE.findall(text))),
        'domain': list(set(_DOMAIN_RE.findall(text))),
        'url': list(set(_URL_RE.findall(text))),
        'email': list(set(_EMAIL_RE.findall(text))),
        'filepath': list(set(_WIN_PATH_RE.findall(text) + _UNIX_PATH_RE.findall(text))),
        'registry_key': list(set(_REG_KEY_RE.findall(text))),
        'md5': list(set(_MD5_RE.findall(text))),
        'sha1': list(set(_SHA1_RE.findall(text))),
        'sha256': list(set(_SHA256_RE.findall(text))),
        'crypto_wallet': list(set(_BTC_RE.findall(text) + _ETH_RE.findall(text))),
    }
    return filter_false_positives(result)


def extract_strings(data: bytes, min_length=4) -> dict:
    """Extract ASCII and Unicode strings from bytes."""
    ascii_strings = re.findall(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}', data)
    unicode_strings = re.findall(rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}', data)
    return {
        'ascii': [s.decode('ascii', errors='replace') for s in ascii_strings],
        'unicode': [s.decode('utf-16-le', errors='replace') for s in unicode_strings],
    }


def filter_false_positives(iocs: dict) -> dict:
    """Remove common false positives from IOC results."""
    filtered = {}
    for ioc_type, values in iocs.items():
        if ioc_type == 'ipv4':
            filtered[ioc_type] = [v for v in values if v not in _FALSE_POS_IPS]
        elif ioc_type == 'domain':
            filtered[ioc_type] = [v for v in values if v.lower() not in _FALSE_POS_DOMAINS]
        elif ioc_type in ('md5', 'sha1', 'sha256'):
            # Filter all-zero, all-f, and all-a hashes (known false positives)
            hash_lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}
            expected_len = hash_lengths.get(ioc_type, 0)
            filtered[ioc_type] = [
                v for v in values
                if len(v) == expected_len and
                v not in ('0' * expected_len, 'f' * expected_len, 'a' * expected_len)
            ]
        else:
            filtered[ioc_type] = values
    return filtered
