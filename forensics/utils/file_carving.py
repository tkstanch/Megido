"""File carving engine - find embedded files by scanning for magic bytes."""

CARVE_SIGNATURES = [
    {'type': 'JPEG', 'header': b'\xff\xd8\xff', 'footer': b'\xff\xd9', 'extension': '.jpg', 'max_size': 10_000_000},
    {'type': 'PNG', 'header': b'\x89PNG\r\n\x1a\n', 'footer': b'\x49\x45\x4e\x44\xae\x42\x60\x82', 'extension': '.png', 'max_size': 10_000_000},
    {'type': 'PDF', 'header': b'%PDF', 'footer': b'%%EOF', 'extension': '.pdf', 'max_size': 50_000_000},
    {'type': 'ZIP', 'header': b'PK\x03\x04', 'footer': b'PK\x05\x06', 'extension': '.zip', 'max_size': 100_000_000},
    {'type': 'ELF', 'header': b'\x7fELF', 'footer': None, 'extension': '.elf', 'max_size': 50_000_000},
    {'type': 'PE', 'header': b'MZ', 'footer': None, 'extension': '.exe', 'max_size': 50_000_000},
    {'type': 'SQLITE', 'header': b'SQLite format 3\x00', 'footer': None, 'extension': '.db', 'max_size': 100_000_000},
    {'type': 'GIF', 'header': b'GIF8', 'footer': b'\x00;', 'extension': '.gif', 'max_size': 5_000_000},
    {'type': 'MP4', 'header': b'\x00\x00\x00\x18ftyp', 'footer': None, 'extension': '.mp4', 'max_size': 500_000_000},
    {'type': 'GZIP', 'header': b'\x1f\x8b', 'footer': None, 'extension': '.gz', 'max_size': 100_000_000},
]


def carve_files(data: bytes) -> list:
    """Find and extract embedded files by scanning for headers/footers."""
    results = []
    for sig in CARVE_SIGNATURES:
        header = sig['header']
        footer = sig.get('footer')
        max_size = sig.get('max_size', 10_000_000)
        offset = 0
        while True:
            pos = data.find(header, offset)
            if pos == -1:
                break
            end = None
            if footer:
                end = data.find(footer, pos + len(header))
                if end != -1:
                    end = end + len(footer)
            if end is None:
                end = min(pos + max_size, len(data))
            size = end - pos
            if size > 0:
                results.append(carve_file_from_data(data, pos, sig, size))
            offset = pos + len(header)
    results.sort(key=lambda x: x['offset'])
    return results


def carve_file_from_data(data: bytes, offset: int, file_type_info: dict, size: int = None) -> dict:
    """Extract a single carved file from data."""
    if size is None:
        size = min(file_type_info.get('max_size', 1024), len(data) - offset)
    carved = data[offset:offset + size]
    return {
        'type': file_type_info['type'],
        'extension': file_type_info.get('extension', ''),
        'offset': offset,
        'size': size,
        'data': carved[:256],  # Truncated sample
        'confidence': 'high' if file_type_info.get('footer') else 'medium',
    }
