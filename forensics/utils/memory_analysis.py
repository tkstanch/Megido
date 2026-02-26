"""Memory forensics utilities."""
import re

try:
    import volatility3
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False


def analyze_memory_dump(file_path: str) -> dict:
    """Analyze a memory dump file."""
    result = {
        'file_path': file_path,
        'volatility_available': VOLATILITY_AVAILABLE,
        'strings': {},
        'processes': [],
        'network_artifacts': [],
        'error': None,
    }
    try:
        with open(file_path, 'rb') as f:
            data = f.read(1024 * 1024)  # Read first 1MB
        result['strings'] = extract_strings_from_memory(file_path)
        result['processes'] = find_processes_in_memory(data)
        result['network_artifacts'] = find_network_artifacts(data)
    except Exception as e:
        result['error'] = str(e)
    return result


def extract_strings_from_memory(file_path: str) -> dict:
    """Extract ASCII and Unicode strings from a memory dump."""
    ascii_strings = []
    unicode_strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4 * 1024 * 1024)  # First 4MB
        ascii_strings = [m.decode('ascii', errors='replace')
                         for m in re.findall(rb'[\x20-\x7e]{6,}', data)][:500]
        unicode_strings = [m.decode('utf-16-le', errors='replace')
                           for m in re.findall(rb'(?:[\x20-\x7e]\x00){6,}', data)][:200]
    except Exception:
        pass
    return {'ascii': ascii_strings, 'unicode': unicode_strings}


def find_processes_in_memory(data: bytes) -> list:
    """Pattern match for process structures in memory."""
    processes = []
    # Look for _EPROCESS pool tag PROC
    pattern = rb'Pro\xe3'
    for m in re.finditer(pattern, data):
        processes.append({'offset': m.start(), 'hint': 'EPROCESS pool tag'})
        if len(processes) >= 50:
            break
    return processes


def find_network_artifacts(data: bytes) -> list:
    """Find IP addresses and ports in memory."""
    ipv4_re = re.compile(rb'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)')
    artifacts = []
    for m in ipv4_re.finditer(data):
        ip = m.group().decode('ascii')
        if ip not in ('0.0.0.0', '127.0.0.1', '255.255.255.255'):
            artifacts.append({'type': 'ipv4', 'value': ip, 'offset': m.start()})
        if len(artifacts) >= 100:
            break
    return artifacts
