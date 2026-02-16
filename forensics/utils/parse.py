"""
Utility functions for parsing and analyzing forensic files.

Provides basic file analysis including:
- Hash calculation (SHA256, MD5)
- File size and type detection
- Sample data/hex extraction
- Basic metadata extraction

Future extensions could include:
- PyTSK3 integration for disk image analysis
- YARA rule scanning
- File carving and recovery
- Timeline generation
- Artifact extraction (registry, browser history, etc.)
- Memory analysis with Volatility
"""
import hashlib
import mimetypes
import os


def calculate_file_hash(file_obj, algorithm='sha256'):
    """
    Calculate hash of a file object.
    
    Args:
        file_obj: Django UploadedFile object or file-like object
        algorithm: Hash algorithm to use ('sha256', 'md5')
    
    Returns:
        str: Hexadecimal hash string
    """
    if algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'md5':
        hasher = hashlib.md5()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    # Reset file pointer to beginning
    file_obj.seek(0)
    
    # Read file in chunks to handle large files efficiently
    for chunk in iter(lambda: file_obj.read(8192), b''):
        hasher.update(chunk)
    
    # Reset file pointer for further processing
    file_obj.seek(0)
    
    return hasher.hexdigest()


def get_hex_sample(file_obj, num_bytes=256):
    """
    Extract first N bytes from file as hex string.
    
    Args:
        file_obj: Django UploadedFile object or file-like object
        num_bytes: Number of bytes to extract (default: 256)
    
    Returns:
        str: Hex representation of first N bytes
    """
    # Reset file pointer to beginning
    file_obj.seek(0)
    
    # Read first N bytes
    sample_bytes = file_obj.read(num_bytes)
    
    # Reset file pointer for further processing
    file_obj.seek(0)
    
    # Convert to hex string with spaces for readability
    hex_string = ' '.join(f'{b:02x}' for b in sample_bytes)
    
    return hex_string


def detect_file_type(filename):
    """
    Detect file type based on filename extension.
    
    Args:
        filename: Name of the file
    
    Returns:
        tuple: (file_type_description, mime_type)
    """
    # Get MIME type
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None:
        mime_type = 'application/octet-stream'
    
    # Determine file type description
    ext = os.path.splitext(filename)[1].lower()
    
    # Common forensic file types
    forensic_types = {
        '.dd': 'Raw Disk Image',
        '.img': 'Disk Image',
        '.e01': 'EnCase Evidence File',
        '.aff': 'Advanced Forensic Format',
        '.vmdk': 'VMware Virtual Disk',
        '.vhd': 'Virtual Hard Disk',
        '.zip': 'Compressed Archive',
        '.tar': 'TAR Archive',
        '.gz': 'GZIP Compressed File',
        '.log': 'Log File',
        '.pcap': 'Packet Capture',
        '.mem': 'Memory Dump',
        '.dmp': 'Memory Dump',
        '.raw': 'Raw Data File',
        '.bin': 'Binary File',
        '.backup': 'Backup File',
        '.ab': 'Android Backup',
        '.ipa': 'iOS Application',
        '.apk': 'Android Application',
    }
    
    file_type = forensic_types.get(ext, f'Unknown ({ext})' if ext else 'Unknown')
    
    return file_type, mime_type


def analyze_file(file_obj, filename):
    """
    Perform basic analysis on uploaded file.
    
    Args:
        file_obj: Django UploadedFile object
        filename: Original filename
    
    Returns:
        dict: Analysis results containing:
            - sha256_hash: SHA256 hash
            - md5_hash: MD5 hash
            - file_size: Size in bytes
            - file_type: File type description
            - mime_type: MIME type
            - hex_sample: First 256 bytes in hex
    
    Future enhancements:
    - Extract device information from backup files
    - Parse file system metadata from disk images
    - Extract artifacts (browser history, registry keys, etc.)
    - Run YARA rules for malware detection
    - Parse log files for security events
    """
    # Calculate hashes
    sha256_hash = calculate_file_hash(file_obj, 'sha256')
    md5_hash = calculate_file_hash(file_obj, 'md5')
    
    # Get file size
    file_obj.seek(0, os.SEEK_END)
    file_size = file_obj.tell()
    file_obj.seek(0)
    
    # Get hex sample
    hex_sample = get_hex_sample(file_obj)
    
    # Detect file type
    file_type, mime_type = detect_file_type(filename)
    
    return {
        'sha256_hash': sha256_hash,
        'md5_hash': md5_hash,
        'file_size': file_size,
        'file_type': file_type,
        'mime_type': mime_type,
        'hex_sample': hex_sample,
    }


def extract_device_info(file_obj, filename):
    """
    Extract device information from backup files (placeholder).
    
    This is a placeholder for future implementation. Could extract:
    - Android backup: device model, OS version, IMEI
    - iOS backup: device model, iOS version, serial number
    - Disk images: system information, hostname, etc.
    
    Args:
        file_obj: Django UploadedFile object
        filename: Original filename
    
    Returns:
        dict: Device information (empty dict in basic implementation)
    
    Future enhancements:
    - Parse Android backup manifest
    - Parse iOS backup Info.plist
    - Extract system information from disk images
    - Parse Windows registry for system details
    """
    # Placeholder - return empty dict
    # Future implementation would parse various backup formats
    return {
        'device_model': None,
        'os_version': None,
        'serial_number': None,
    }
