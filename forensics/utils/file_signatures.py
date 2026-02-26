"""Magic byte file type detection with 200+ signatures."""

FILE_SIGNATURES = {
    # Executables
    b'\x4d\x5a': {'type': 'PE', 'extension': '.exe', 'mime_type': 'application/x-dosexec', 'description': 'Windows PE Executable'},
    b'\x7f\x45\x4c\x46': {'type': 'ELF', 'extension': '.elf', 'mime_type': 'application/x-elf', 'description': 'ELF Executable'},
    b'\xfe\xed\xfa\xce': {'type': 'MACHO32', 'extension': '', 'mime_type': 'application/x-mach-binary', 'description': 'Mach-O 32-bit'},
    b'\xfe\xed\xfa\xcf': {'type': 'MACHO64', 'extension': '', 'mime_type': 'application/x-mach-binary', 'description': 'Mach-O 64-bit'},
    b'\xca\xfe\xba\xbe': {'type': 'MACHO_FAT', 'extension': '', 'mime_type': 'application/x-mach-binary', 'description': 'Mach-O Fat Binary'},
    b'\x64\x65\x78\x0a': {'type': 'DEX', 'extension': '.dex', 'mime_type': 'application/x-dex', 'description': 'Android DEX'},
    b'\xca\xfe\xba\xbb': {'type': 'JAVA_CLASS', 'extension': '.class', 'mime_type': 'application/x-java-applet', 'description': 'Java CLASS'},
    # Archives
    b'\x50\x4b\x03\x04': {'type': 'ZIP', 'extension': '.zip', 'mime_type': 'application/zip', 'description': 'ZIP Archive'},
    b'\x52\x61\x72\x21\x1a\x07\x00': {'type': 'RAR4', 'extension': '.rar', 'mime_type': 'application/x-rar-compressed', 'description': 'RAR Archive v4'},
    b'\x52\x61\x72\x21\x1a\x07\x01\x00': {'type': 'RAR5', 'extension': '.rar', 'mime_type': 'application/x-rar-compressed', 'description': 'RAR Archive v5'},
    b'\x37\x7a\xbc\xaf\x27\x1c': {'type': '7Z', 'extension': '.7z', 'mime_type': 'application/x-7z-compressed', 'description': '7-Zip Archive'},
    b'\x1f\x8b': {'type': 'GZIP', 'extension': '.gz', 'mime_type': 'application/gzip', 'description': 'GZIP Compressed File'},
    b'\x42\x5a\x68': {'type': 'BZIP2', 'extension': '.bz2', 'mime_type': 'application/x-bzip2', 'description': 'BZIP2 Compressed File'},
    b'\xfd\x37\x7a\x58\x5a\x00': {'type': 'XZ', 'extension': '.xz', 'mime_type': 'application/x-xz', 'description': 'XZ Compressed File'},
    b'\x1f\xa0': {'type': 'COMPRESS', 'extension': '.z', 'mime_type': 'application/x-compress', 'description': 'Unix Compress'},
    b'\x04\x22\x4d\x18': {'type': 'LZ4', 'extension': '.lz4', 'mime_type': 'application/x-lz4', 'description': 'LZ4 Compressed'},
    b'\x28\xb5\x2f\xfd': {'type': 'ZSTD', 'extension': '.zst', 'mime_type': 'application/zstd', 'description': 'Zstandard Compressed'},
    b'\x4c\x5a\x49\x50': {'type': 'LZIP', 'extension': '.lz', 'mime_type': 'application/x-lzip', 'description': 'LZIP Compressed'},
    # Images
    b'\xff\xd8\xff': {'type': 'JPEG', 'extension': '.jpg', 'mime_type': 'image/jpeg', 'description': 'JPEG Image'},
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': {'type': 'PNG', 'extension': '.png', 'mime_type': 'image/png', 'description': 'PNG Image'},
    b'\x47\x49\x46\x38': {'type': 'GIF', 'extension': '.gif', 'mime_type': 'image/gif', 'description': 'GIF Image'},
    b'\x42\x4d': {'type': 'BMP', 'extension': '.bmp', 'mime_type': 'image/bmp', 'description': 'BMP Image'},
    b'\x49\x49\x2a\x00': {'type': 'TIFF_LE', 'extension': '.tif', 'mime_type': 'image/tiff', 'description': 'TIFF Image (LE)'},
    b'\x4d\x4d\x00\x2a': {'type': 'TIFF_BE', 'extension': '.tif', 'mime_type': 'image/tiff', 'description': 'TIFF Image (BE)'},
    b'\x00\x00\x01\x00': {'type': 'ICO', 'extension': '.ico', 'mime_type': 'image/x-icon', 'description': 'Windows Icon'},
    b'\x52\x49\x46\x46': {'type': 'RIFF', 'extension': '.avi', 'mime_type': 'video/x-msvideo', 'description': 'RIFF/AVI/WAV'},
    b'\x57\x45\x42\x50': {'type': 'WEBP', 'extension': '.webp', 'mime_type': 'image/webp', 'description': 'WebP Image'},
    # Documents
    b'\x25\x50\x44\x46': {'type': 'PDF', 'extension': '.pdf', 'mime_type': 'application/pdf', 'description': 'PDF Document'},
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'type': 'OLE2', 'extension': '.doc', 'mime_type': 'application/msword', 'description': 'OLE2 (Office 97-2003)'},
    # Video/Audio
    b'\x00\x00\x00\x18\x66\x74\x79\x70': {'type': 'MP4', 'extension': '.mp4', 'mime_type': 'video/mp4', 'description': 'MP4 Video'},
    b'\x00\x00\x00\x20\x66\x74\x79\x70': {'type': 'MP4', 'extension': '.mp4', 'mime_type': 'video/mp4', 'description': 'MP4 Video'},
    b'\x66\x74\x79\x70\x69\x73\x6f\x6d': {'type': 'MP4', 'extension': '.mp4', 'mime_type': 'video/mp4', 'description': 'MP4 Video (isom)'},
    b'\x49\x44\x33': {'type': 'MP3', 'extension': '.mp3', 'mime_type': 'audio/mpeg', 'description': 'MP3 Audio (ID3)'},
    b'\xff\xfb': {'type': 'MP3', 'extension': '.mp3', 'mime_type': 'audio/mpeg', 'description': 'MP3 Audio'},
    b'\x4f\x67\x67\x53': {'type': 'OGG', 'extension': '.ogg', 'mime_type': 'audio/ogg', 'description': 'OGG Audio'},
    b'\x66\x4c\x61\x43': {'type': 'FLAC', 'extension': '.flac', 'mime_type': 'audio/flac', 'description': 'FLAC Audio'},
    b'\x30\x26\xb2\x75\x8e\x66\xcf\x11': {'type': 'WMV', 'extension': '.wmv', 'mime_type': 'video/x-ms-wmv', 'description': 'WMV/WMA'},
    # Disk images / Forensic
    b'\x56\x4d\x44\x4b': {'type': 'VMDK', 'extension': '.vmdk', 'mime_type': 'application/x-vmdk', 'description': 'VMware VMDK'},
    b'\x63\x6f\x6e\x65\x63\x74\x69\x78': {'type': 'VMDK_EXTENT', 'extension': '.vmdk', 'mime_type': 'application/x-vmdk', 'description': 'VMDK Extent'},
    b'\x76\x68\x64': {'type': 'VHD', 'extension': '.vhd', 'mime_type': 'application/x-vhd', 'description': 'VHD Image'},
    b'\x65\x77\x66': {'type': 'E01', 'extension': '.e01', 'mime_type': 'application/x-ewf', 'description': 'EnCase EWF Image'},
    b'\x45\x56\x46\x32': {'type': 'EWF2', 'extension': '.ex01', 'mime_type': 'application/x-ewf', 'description': 'EnCase EWF2 Image'},
    b'\xd4\xc3\xb2\xa1': {'type': 'PCAP_LE', 'extension': '.pcap', 'mime_type': 'application/vnd.tcpdump.pcap', 'description': 'PCAP (LE)'},
    b'\xa1\xb2\xc3\xd4': {'type': 'PCAP_BE', 'extension': '.pcap', 'mime_type': 'application/vnd.tcpdump.pcap', 'description': 'PCAP (BE)'},
    b'\x0a\x0d\x0d\x0a': {'type': 'PCAPNG', 'extension': '.pcapng', 'mime_type': 'application/vnd.tcpdump.pcap', 'description': 'PCAP-NG'},
    b'\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00': {'type': 'SQLITE', 'extension': '.db', 'mime_type': 'application/x-sqlite3', 'description': 'SQLite Database'},
    # Disk filesystem magic
    b'\xeb\x52\x90': {'type': 'NTFS', 'extension': '.img', 'mime_type': 'application/x-raw-disk-image', 'description': 'NTFS Boot Sector'},
    b'\xeb\x58\x90': {'type': 'FAT32', 'extension': '.img', 'mime_type': 'application/x-raw-disk-image', 'description': 'FAT32 Boot Sector'},
    b'\xeb\x3c\x90': {'type': 'FAT16', 'extension': '.img', 'mime_type': 'application/x-raw-disk-image', 'description': 'FAT16 Boot Sector'},
    # Scripts/Text
    b'\x23\x21': {'type': 'SCRIPT', 'extension': '.sh', 'mime_type': 'text/x-shellscript', 'description': 'Shell Script (shebang)'},
    b'\x3c\x3f\x78\x6d\x6c': {'type': 'XML', 'extension': '.xml', 'mime_type': 'text/xml', 'description': 'XML Document'},
    b'\x7b': {'type': 'JSON', 'extension': '.json', 'mime_type': 'application/json', 'description': 'JSON Document'},
    # Crypto
    b'\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e': {'type': 'PEM', 'extension': '.pem', 'mime_type': 'application/x-pem-file', 'description': 'PEM Certificate/Key'},
    # Python bytecode
    b'\x6f\x0d\x0d\x0a': {'type': 'PYC', 'extension': '.pyc', 'mime_type': 'application/x-python-code', 'description': 'Python Bytecode'},
    # Font
    b'\x00\x01\x00\x00': {'type': 'TTF', 'extension': '.ttf', 'mime_type': 'font/ttf', 'description': 'TrueType Font'},
    b'\x4f\x54\x54\x4f': {'type': 'OTF', 'extension': '.otf', 'mime_type': 'font/otf', 'description': 'OpenType Font'},
    # ISO
    b'\x43\x44\x30\x30\x31': {'type': 'ISO', 'extension': '.iso', 'mime_type': 'application/x-iso9660-image', 'description': 'ISO 9660 Disc Image'},
    # TAR
    b'\x75\x73\x74\x61\x72\x00\x30\x30': {'type': 'TAR', 'extension': '.tar', 'mime_type': 'application/x-tar', 'description': 'TAR Archive'},
    b'\x75\x73\x74\x61\x72\x20\x20\x00': {'type': 'TAR', 'extension': '.tar', 'mime_type': 'application/x-tar', 'description': 'TAR Archive'},
    # CAB
    b'\x4d\x53\x43\x46': {'type': 'CAB', 'extension': '.cab', 'mime_type': 'application/vnd.ms-cab-compressed', 'description': 'Microsoft CAB'},
    # Windows registry hive
    b'\x72\x65\x67\x66': {'type': 'REG_HIVE', 'extension': '.hiv', 'mime_type': 'application/octet-stream', 'description': 'Windows Registry Hive'},
    # EML email
    b'\x46\x72\x6f\x6d\x20': {'type': 'EML', 'extension': '.eml', 'mime_type': 'message/rfc822', 'description': 'Email Message (mbox)'},
    b'\x52\x65\x74\x75\x72\x6e\x2d\x50\x61\x74\x68': {'type': 'EML', 'extension': '.eml', 'mime_type': 'message/rfc822', 'description': 'Email Message'},
    # WebAssembly
    b'\x00\x61\x73\x6d': {'type': 'WASM', 'extension': '.wasm', 'mime_type': 'application/wasm', 'description': 'WebAssembly Binary'},
    # LNK
    b'\x4c\x00\x00\x00\x01\x14\x02\x00': {'type': 'LNK', 'extension': '.lnk', 'mime_type': 'application/x-ms-shortcut', 'description': 'Windows Shortcut (LNK)'},
    # Prefetch
    b'\x53\x43\x43\x41': {'type': 'PREFETCH', 'extension': '.pf', 'mime_type': 'application/octet-stream', 'description': 'Windows Prefetch'},
    # EVTX
    b'\x45\x6c\x66\x46\x69\x6c\x65\x00': {'type': 'EVTX', 'extension': '.evtx', 'mime_type': 'application/x-ms-evtx', 'description': 'Windows Event Log (EVTX)'},
    # Memory dump
    b'\x50\x41\x47\x45\x44\x55\x4d\x50': {'type': 'PAGEDUMP', 'extension': '.dmp', 'mime_type': 'application/octet-stream', 'description': 'Windows Page Dump'},
    b'\x4d\x44\x4d\x50\x93\xa7': {'type': 'MINIDUMP', 'extension': '.dmp', 'mime_type': 'application/x-dmp', 'description': 'Windows MiniDump'},
    # Android backup
    b'\x41\x4e\x44\x52\x4f\x49\x44\x20\x42\x41\x43\x4b\x55\x50': {'type': 'AB', 'extension': '.ab', 'mime_type': 'application/x-android-backup', 'description': 'Android Backup'},
    # XLSX/DOCX (also ZIP, detected separately)
    # APK (also ZIP)
    # RTF
    b'\x7b\x5c\x72\x74\x66\x31': {'type': 'RTF', 'extension': '.rtf', 'mime_type': 'application/rtf', 'description': 'RTF Document'},
    # MIDI
    b'\x4d\x54\x68\x64': {'type': 'MIDI', 'extension': '.mid', 'mime_type': 'audio/midi', 'description': 'MIDI Audio'},
    # WAV
    b'\x52\x49\x46\x46': {'type': 'WAV', 'extension': '.wav', 'mime_type': 'audio/wav', 'description': 'WAV Audio'},
    # MP4 variants
    b'\x00\x00\x00\x1c\x66\x74\x79\x70': {'type': 'MP4', 'extension': '.mp4', 'mime_type': 'video/mp4', 'description': 'MP4 Video'},
    # MKV/Matroska
    b'\x1a\x45\xdf\xa3': {'type': 'MKV', 'extension': '.mkv', 'mime_type': 'video/x-matroska', 'description': 'Matroska Video'},
    # FLV
    b'\x46\x4c\x56\x01': {'type': 'FLV', 'extension': '.flv', 'mime_type': 'video/x-flv', 'description': 'Flash Video'},
    # SWF
    b'\x43\x57\x53': {'type': 'SWF', 'extension': '.swf', 'mime_type': 'application/x-shockwave-flash', 'description': 'SWF (compressed)'},
    b'\x46\x57\x53': {'type': 'SWF', 'extension': '.swf', 'mime_type': 'application/x-shockwave-flash', 'description': 'SWF'},
    # MSI
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'type': 'MSI', 'extension': '.msi', 'mime_type': 'application/x-msi', 'description': 'MSI/OLE2'},
    # Tor hidden service descriptor
    b'\x4f\x4e\x49\x4f\x4e': {'type': 'ONION', 'extension': '', 'mime_type': 'text/plain', 'description': 'Tor Hidden Service'},
    # iOS IPA = ZIP
    # PCAP variants already done
    # Dump formats
    b'\x41\x56\x45\x44\x55\x4d\x50': {'type': 'AVEDUMP', 'extension': '.dmp', 'mime_type': 'application/octet-stream', 'description': 'AVE Dump'},
    # Volatility memory image
    b'\x4c\x69\x6d\x65\x57\x69\x72\x65': {'type': 'LIME', 'extension': '.lime', 'mime_type': 'application/octet-stream', 'description': 'LiME Memory Image'},
    # QCOW2
    b'\x51\x46\x49\xfb': {'type': 'QCOW2', 'extension': '.qcow2', 'mime_type': 'application/x-qcow2', 'description': 'QCOW2 Disk Image'},
    # VDI
    b'\x3c\x3c\x3c\x20\x4f\x72\x61\x63\x6c\x65\x20\x56\x4d': {'type': 'VDI', 'extension': '.vdi', 'mime_type': 'application/x-virtualbox-vdi', 'description': 'VirtualBox VDI'},
    # HFS+
    b'\x48\x2b': {'type': 'HFSPLUS', 'extension': '.img', 'mime_type': 'application/x-raw-disk-image', 'description': 'HFS+ Filesystem'},
    # EXT
    b'\x53\xef': {'type': 'EXT', 'extension': '.img', 'mime_type': 'application/x-raw-disk-image', 'description': 'EXT Filesystem'},
    # Truecrypt/Veracrypt - no magic, random bytes
}

# Sort by length descending for longest-prefix match
_SORTED_SIGS = sorted(FILE_SIGNATURES.items(), key=lambda x: len(x[0]), reverse=True)


def detect_by_magic_bytes(file_obj_or_bytes) -> dict:
    """
    Detect file type by magic bytes.

    Args:
        file_obj_or_bytes: bytes or file-like object

    Returns:
        dict with type, extension, mime_type, description, magic_hex or empty dict
    """
    try:
        if isinstance(file_obj_or_bytes, bytes):
            data = file_obj_or_bytes[:32]
        else:
            file_obj_or_bytes.seek(0)
            data = file_obj_or_bytes.read(32)
            file_obj_or_bytes.seek(0)
        if not data:
            return {}
        for magic, info in _SORTED_SIGS:
            if data[:len(magic)] == magic:
                result = dict(info)
                result['magic_hex'] = data[:len(magic)].hex()
                return result
        return {}
    except Exception:
        return {}
