"""
File utility functions for the decompiler app.

Provides magic byte detection, checksum calculation, safe file extraction,
and archive handling.
"""
import hashlib
import zipfile
import os
import tempfile
import shutil
import struct
from typing import Dict, Optional, Tuple


# Magic byte signatures
MAGIC_BYTES = {
    'crx3': b'Cr24',
    'zip': b'PK\x03\x04',
    'java_class': b'\xca\xfe\xba\xbe',
    'swf_uncompressed': b'FWS',
    'swf_zlib': b'CWS',
    'swf_lzma': b'ZWS',
    'wasm': b'\x00asm',
    'pe': b'MZ',
    'elf': b'\x7fELF',
}


def read_magic_bytes(file_path: str, n: int = 64) -> bytes:
    """Read the first n bytes from a file."""
    try:
        with open(file_path, 'rb') as f:
            return f.read(n)
    except (IOError, OSError):
        return b''


def detect_type_from_magic(file_path: str) -> Optional[str]:
    """
    Detect file type from magic bytes.

    Returns an extension type string or None if unrecognised.
    """
    header = read_magic_bytes(file_path, 64)
    if not header:
        return None

    if header[:4] == MAGIC_BYTES['crx3']:
        return 'chrome_crx'
    if header[:4] == MAGIC_BYTES['wasm']:
        return 'wasm'
    if header[:4] == MAGIC_BYTES['java_class']:
        return 'java_applet'
    if header[:3] in (MAGIC_BYTES['swf_uncompressed'],
                      MAGIC_BYTES['swf_zlib'],
                      MAGIC_BYTES['swf_lzma']):
        return 'flash'
    if header[:2] == MAGIC_BYTES['pe']:
        return 'unknown'  # PE file — could be Edge MSIX wrapper
    if header[:4] == MAGIC_BYTES['zip']:
        # Analyse ZIP contents to distinguish types
        return _detect_zip_type(file_path)
    # Try reading as ASAR (JSON header)
    if _is_asar(file_path):
        return 'electron_asar'
    # Plain text → could be userscript or JS
    return _detect_text_type(file_path)


def _detect_zip_type(file_path: str) -> str:
    """Inspect ZIP contents to determine extension type."""
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            names = [n.lower() for n in zf.namelist()]
            name_set = set(names)

            if 'appmanifest.xaml' in name_set or any(n.endswith('.dll') for n in names):
                return 'silverlight'
            if 'manifest.json' in name_set:
                # Try to distinguish Chrome/Firefox/generic WebExtension
                try:
                    manifest_data = zf.read('manifest.json').decode('utf-8', errors='replace')
                    if '"applications"' in manifest_data or '"browser_specific_settings"' in manifest_data:
                        return 'firefox_xpi'
                    return 'chrome_crx'
                except Exception:
                    return 'webextension'
            if 'install.rdf' in name_set or 'chrome.manifest' in name_set:
                return 'firefox_xpi'
            if any(n.endswith('.jar') or n.endswith('.class') for n in names):
                return 'java_applet'
    except zipfile.BadZipFile:
        pass
    return 'unknown'


def _is_asar(file_path: str) -> bool:
    """Check if file is an Electron ASAR archive."""
    try:
        with open(file_path, 'rb') as f:
            # ASAR: 4-byte little-endian header size, then a JSON string
            size_bytes = f.read(4)
            if len(size_bytes) < 4:
                return False
            header_size = struct.unpack('<I', size_bytes)[0]
            if header_size < 4 or header_size > 1024 * 1024:
                return False
            header = f.read(header_size)
            return header.lstrip().startswith(b'{')
    except Exception:
        return False


def _detect_text_type(file_path: str) -> str:
    """Detect type from text content (userscript, JS, etc.)."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(512)
        if '==UserScript==' in content or '==UserStyle==' in content:
            return 'userscript'
        if content.strip().startswith(('{', '[')):
            return 'javascript'
    except Exception:
        pass
    return 'unknown'


def calculate_checksums(file_path: str) -> Dict[str, str]:
    """
    Calculate MD5, SHA256, and SHA512 checksums for a file.

    Returns dict with keys md5, sha256, sha512.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
    except (IOError, OSError):
        return {'md5': '', 'sha256': '', 'sha512': ''}
    return {
        'md5': md5.hexdigest(),
        'sha256': sha256.hexdigest(),
        'sha512': sha512.hexdigest(),
    }


def safe_extract_zip(zip_path: str, output_dir: str, max_size: int = 500 * 1024 * 1024) -> Tuple[bool, str]:
    """
    Safely extract a ZIP archive, guarding against zip-slip and bombs.

    Returns (success, error_message).
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            total_size = sum(info.file_size for info in zf.infolist())
            if total_size > max_size:
                return False, f"Extracted size {total_size} exceeds limit {max_size}"
            for member in zf.infolist():
                target = os.path.realpath(os.path.join(output_dir, member.filename))
                if not target.startswith(os.path.realpath(output_dir) + os.sep) and \
                        target != os.path.realpath(output_dir):
                    return False, f"Zip slip detected: {member.filename}"
            zf.extractall(output_dir)
        return True, ''
    except zipfile.BadZipFile as exc:
        return False, f"Bad ZIP file: {exc}"
    except Exception as exc:
        return False, str(exc)


def make_temp_dir(prefix: str = 'decompiler_') -> str:
    """Create and return a temporary directory path."""
    return tempfile.mkdtemp(prefix=prefix)


def cleanup_temp_dir(path: str) -> None:
    """Remove a temporary directory and all contents."""
    try:
        if path and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
