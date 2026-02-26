"""STIX2 export utilities."""

try:
    import stix2
    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False

from django.utils import timezone


def ioc_to_stix_indicator(ioc) -> dict:
    """Convert an IOC model instance or dict to a STIX2 indicator dict."""
    ioc_type = ioc.ioc_type if hasattr(ioc, 'ioc_type') else ioc.get('ioc_type', 'other')
    ioc_value = ioc.ioc_value if hasattr(ioc, 'ioc_value') else ioc.get('ioc_value', '')

    pattern_map = {
        'ipv4': f"[ipv4-addr:value = '{ioc_value}']",
        'ipv6': f"[ipv6-addr:value = '{ioc_value}']",
        'domain': f"[domain-name:value = '{ioc_value}']",
        'url': f"[url:value = '{ioc_value}']",
        'email': f"[email-message:from_ref.value = '{ioc_value}']",
        'md5': f"[file:hashes.MD5 = '{ioc_value}']",
        'sha1': f"[file:hashes.'SHA-1' = '{ioc_value}']",
        'sha256': f"[file:hashes.'SHA-256' = '{ioc_value}']",
        'filepath': f"[file:name = '{ioc_value}']",
    }
    pattern = pattern_map.get(ioc_type, f"[x-custom:value = '{ioc_value}']")

    return {
        'type': 'indicator',
        'spec_version': '2.1',
        'id': f'indicator--{_make_deterministic_id(ioc_type, ioc_value)}',
        'created': timezone.now().isoformat(),
        'modified': timezone.now().isoformat(),
        'name': f'{ioc_type}: {ioc_value[:50]}',
        'pattern': pattern,
        'pattern_type': 'stix',
        'valid_from': timezone.now().isoformat(),
        'indicator_types': ['malicious-activity'],
    }


def export_iocs_to_stix(iocs: list) -> dict:
    """Export a list of IOC instances/dicts as a STIX2 bundle."""
    objects = []
    for ioc in iocs:
        try:
            objects.append(ioc_to_stix_indicator(ioc))
        except Exception:
            continue
    return {
        'type': 'bundle',
        'id': f'bundle--{_make_deterministic_id("bundle", str(len(objects)))}',
        'spec_version': '2.1',
        'objects': objects,
    }


def _make_deterministic_id(type_str: str, value: str) -> str:
    """Generate a deterministic UUID-like string."""
    import hashlib
    h = hashlib.sha256(f'{type_str}:{value}'.encode()).hexdigest()
    return f'{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}'
