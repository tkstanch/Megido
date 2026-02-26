"""Windows registry hive analysis utilities."""

try:
    import regipy
    from regipy.registry import RegistryHive
    REGIPY_AVAILABLE = True
except ImportError:
    REGIPY_AVAILABLE = False


def analyze_registry_hive(file_path: str) -> dict:
    """Parse a Windows registry hive."""
    result = {
        'file_path': file_path,
        'regipy_available': REGIPY_AVAILABLE,
        'user_accounts': [],
        'usb_devices': [],
        'installed_software': [],
        'autorun_entries': [],
        'error': None,
    }
    if not REGIPY_AVAILABLE:
        result['error'] = 'regipy not installed - install for registry analysis'
        return result
    try:
        hive = RegistryHive(file_path)
        result['user_accounts'] = extract_user_accounts(hive)
        result['usb_devices'] = extract_usb_devices(hive)
        result['installed_software'] = extract_installed_software(hive)
        result['autorun_entries'] = extract_autorun_entries(hive)
    except Exception as e:
        result['error'] = str(e)
    return result


def extract_user_accounts(hive_data) -> list:
    """Extract user accounts from registry hive."""
    accounts = []
    try:
        sam_path = 'SAM\\Domains\\Account\\Users\\Names'
        key = hive_data.get_key(sam_path)
        if key:
            for subkey in key.iter_subkeys():
                accounts.append({'username': subkey.name})
    except Exception:
        pass
    return accounts


def extract_usb_devices(hive_data) -> list:
    """Extract USB device history from registry hive."""
    devices = []
    try:
        usb_path = 'SYSTEM\\CurrentControlSet\\Enum\\USBSTOR'
        key = hive_data.get_key(usb_path)
        if key:
            for subkey in key.iter_subkeys():
                devices.append({'device_class': subkey.name})
    except Exception:
        pass
    return devices


def extract_installed_software(hive_data) -> list:
    """Extract installed software from registry hive."""
    software = []
    try:
        sw_path = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        key = hive_data.get_key(sw_path)
        if key:
            for subkey in key.iter_subkeys():
                software.append({'key': subkey.name})
    except Exception:
        pass
    return software


def extract_autorun_entries(hive_data) -> list:
    """Extract autorun/startup entries from registry hive."""
    entries = []
    autorun_paths = [
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    ]
    try:
        for path in autorun_paths:
            try:
                key = hive_data.get_key(path)
                if key:
                    for val in key.get_values():
                        entries.append({'path': path, 'name': val.name, 'value': str(val.value)})
            except Exception:
                continue
    except Exception:
        pass
    return entries
