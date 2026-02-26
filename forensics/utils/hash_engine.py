"""Multi-algorithm hashing utilities."""
import hashlib
import binascii

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False


def calculate_hashes(file_obj) -> dict:
    """Calculate MD5, SHA1, SHA256, SHA512, CRC32 for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    crc32 = 0
    try:
        file_obj.seek(0)
        for chunk in iter(lambda: file_obj.read(65536), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
            crc32 = binascii.crc32(chunk, crc32) & 0xFFFFFFFF
        file_obj.seek(0)
    except Exception:
        pass
    result = {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'sha512': sha512.hexdigest(),
        'crc32': f'{crc32:08x}',
    }
    if SSDEEP_AVAILABLE:
        try:
            file_obj.seek(0)
            data = file_obj.read()
            file_obj.seek(0)
            result['ssdeep'] = ssdeep.hash(data)
        except Exception:
            result['ssdeep'] = ''
    return result


def calculate_block_hashes(file_obj, block_size=4096) -> list:
    """Calculate hashes for each block of the file."""
    results = []
    try:
        file_obj.seek(0)
        offset = 0
        while True:
            block = file_obj.read(block_size)
            if not block:
                break
            h = hashlib.sha256(block).hexdigest()
            results.append({'offset': offset, 'size': len(block), 'sha256': h})
            offset += len(block)
        file_obj.seek(0)
    except Exception:
        pass
    return results
