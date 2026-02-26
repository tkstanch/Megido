"""Disk image analysis utilities."""

try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False


def analyze_disk_image(file_path: str) -> dict:
    """Analyze a disk image file. Falls back gracefully if pytsk3 not available."""
    result = {
        'file_path': file_path,
        'pytsk3_available': PYTSK3_AVAILABLE,
        'partitions': [],
        'file_system': 'Unknown',
        'error': None,
    }
    if not PYTSK3_AVAILABLE:
        result['error'] = 'pytsk3 not installed - install for full disk analysis'
        return result
    try:
        img = pytsk3.Img_Info(file_path)
        try:
            volume = pytsk3.Volume_Info(img)
            for part in volume:
                result['partitions'].append({
                    'addr': part.addr,
                    'start': part.start,
                    'len': part.len,
                    'desc': part.desc.decode('utf-8', errors='replace'),
                })
        except Exception:
            pass
        try:
            fs = pytsk3.FS_Info(img)
            result['file_system'] = str(fs.info.ftype)
        except Exception:
            pass
    except Exception as e:
        result['error'] = str(e)
    return result


def detect_partitions(file_path: str) -> list:
    """Detect partitions in a disk image."""
    result = analyze_disk_image(file_path)
    return result.get('partitions', [])


def list_files(file_path: str, partition_offset=0) -> list:
    """List files in a disk image partition."""
    files = []
    if not PYTSK3_AVAILABLE:
        return files
    try:
        img = pytsk3.Img_Info(file_path)
        fs = pytsk3.FS_Info(img, offset=partition_offset)
        directory = fs.open_dir(path='/')
        for entry in directory:
            try:
                name = entry.info.name.name.decode('utf-8', errors='replace')
                if name in ('.', '..'):
                    continue
                meta = entry.info.meta
                files.append({
                    'name': name,
                    'size': meta.size if meta else 0,
                    'type': str(meta.type) if meta else 'unknown',
                })
            except Exception:
                continue
    except Exception:
        pass
    return files
