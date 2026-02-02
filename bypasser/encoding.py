"""
Encoding utilities for bypassing WAF and input filters.
Provides various encoding techniques to test filter bypass capabilities.
"""

import base64
import urllib.parse
from typing import List, Dict, Tuple


class EncodingTechniques:
    """Collection of encoding techniques for bypass testing"""
    
    @staticmethod
    def url_encode_single(text: str) -> str:
        """Single URL encoding"""
        return urllib.parse.quote(text, safe='')
    
    @staticmethod
    def url_encode_double(text: str) -> str:
        """Double URL encoding"""
        encoded_once = urllib.parse.quote(text, safe='')
        return urllib.parse.quote(encoded_once, safe='')
    
    @staticmethod
    def url_encode_triple(text: str) -> str:
        """Triple URL encoding"""
        encoded_once = urllib.parse.quote(text, safe='')
        encoded_twice = urllib.parse.quote(encoded_once, safe='')
        return urllib.parse.quote(encoded_twice, safe='')
    
    @staticmethod
    def html_entity_decimal(text: str) -> str:
        """HTML entity encoding (decimal)"""
        return ''.join([f'&#{ord(c)};' for c in text])
    
    @staticmethod
    def html_entity_hex(text: str) -> str:
        """HTML entity encoding (hexadecimal)"""
        return ''.join([f'&#x{ord(c):x};' for c in text])
    
    @staticmethod
    def unicode_escape(text: str) -> str:
        """Unicode escape sequences"""
        return ''.join([f'\\u{ord(c):04x}' for c in text])
    
    @staticmethod
    def base64_encode(text: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def hex_encode(text: str) -> str:
        """Hexadecimal encoding"""
        return ''.join([f'\\x{ord(c):02x}' for c in text])
    
    @staticmethod
    def mixed_case(text: str) -> List[str]:
        """Generate mixed case variations"""
        variations = []
        # All lowercase
        variations.append(text.lower())
        # All uppercase
        variations.append(text.upper())
        # Alternating case starting with upper
        variations.append(''.join([c.upper() if i % 2 == 0 else c.lower() 
                                   for i, c in enumerate(text)]))
        # Alternating case starting with lower
        variations.append(''.join([c.lower() if i % 2 == 0 else c.upper() 
                                   for i, c in enumerate(text)]))
        return list(set(variations))  # Remove duplicates
    
    @staticmethod
    def character_concatenation(text: str) -> str:
        """Character concatenation (JavaScript style)"""
        return '+'.join([f'String.fromCharCode({ord(c)})' for c in text])
    
    @staticmethod
    def null_byte_injection(text: str) -> str:
        """Null byte injection"""
        return text + '%00'
    
    @staticmethod
    def comment_insertion_html(text: str) -> str:
        """HTML comment insertion"""
        # Insert comments between characters
        return '<!---->'.join(text)
    
    @staticmethod
    def comment_insertion_sql(text: str) -> str:
        """SQL comment insertion"""
        # Insert SQL comments between characters
        return '/**/'.join(text)
    
    @staticmethod
    def utf7_encode(text: str) -> str:
        """UTF-7 encoding (legacy)"""
        try:
            return text.encode('utf-7').decode('ascii')
        except:
            return text
    
    @staticmethod
    def utf8_overlong(char: str) -> str:
        """UTF-8 overlong encoding (for single characters)"""
        if len(char) != 1:
            return char
        
        code = ord(char)
        # Two-byte overlong for ASCII characters
        if code < 0x80:
            return f'\\xC{(code >> 6) + 1:x}\\x{0x80 | (code & 0x3F):x}'
        return char
    
    @staticmethod
    def html5_named_entities(char: str) -> str:
        """HTML5 named entities for common special characters"""
        entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&apos;',
            '&': '&amp;',
            ' ': '&nbsp;',
            '/': '&sol;',
            '\\': '&bsol;',
        }
        return entities.get(char, char)
    
    @staticmethod
    def get_all_encodings(text: str) -> Dict[str, str]:
        """
        Get all encoding variations for a given text.
        Returns a dictionary with encoding type as key and encoded string as value.
        """
        encodings = {
            'url_single': EncodingTechniques.url_encode_single(text),
            'url_double': EncodingTechniques.url_encode_double(text),
            'url_triple': EncodingTechniques.url_encode_triple(text),
            'html_decimal': EncodingTechniques.html_entity_decimal(text),
            'html_hex': EncodingTechniques.html_entity_hex(text),
            'unicode': EncodingTechniques.unicode_escape(text),
            'base64': EncodingTechniques.base64_encode(text),
            'hex': EncodingTechniques.hex_encode(text),
            'concatenation': EncodingTechniques.character_concatenation(text),
            'null_byte': EncodingTechniques.null_byte_injection(text),
            'comment_insertion': EncodingTechniques.comment_insertion_html(text),
            'utf7': EncodingTechniques.utf7_encode(text),
        }
        
        # Add single-character specific encodings
        if len(text) == 1:
            encodings['utf8_overlong'] = EncodingTechniques.utf8_overlong(text)
            encodings['html5_entities'] = EncodingTechniques.html5_named_entities(text)
        
        # Add mixed case variations
        mixed_cases = EncodingTechniques.mixed_case(text)
        for i, variant in enumerate(mixed_cases):
            encodings[f'mixed_case_{i+1}'] = variant
        
        return encodings


class SpecialCharacters:
    """Commonly tested special characters for filter bypass"""
    
    @staticmethod
    def get_common_special_chars() -> List[Tuple[str, str, str]]:
        """
        Returns list of (character, unicode_code, description) tuples
        for commonly blocked special characters.
        """
        return [
            ('<', 'U+003C', 'Less Than'),
            ('>', 'U+003E', 'Greater Than'),
            ('"', 'U+0022', 'Double Quote'),
            ("'", 'U+0027', 'Single Quote'),
            ('&', 'U+0026', 'Ampersand'),
            ('/', 'U+002F', 'Forward Slash'),
            ('\\', 'U+005C', 'Backslash'),
            ('(', 'U+0028', 'Left Parenthesis'),
            (')', 'U+0029', 'Right Parenthesis'),
            (';', 'U+003B', 'Semicolon'),
            (':', 'U+003A', 'Colon'),
            ('|', 'U+007C', 'Pipe'),
            ('`', 'U+0060', 'Backtick'),
            ('$', 'U+0024', 'Dollar Sign'),
            ('%', 'U+0025', 'Percent'),
            ('!', 'U+0021', 'Exclamation Mark'),
            ('?', 'U+003F', 'Question Mark'),
            ('=', 'U+003D', 'Equals'),
            ('+', 'U+002B', 'Plus'),
            ('-', 'U+002D', 'Hyphen'),
            ('*', 'U+002A', 'Asterisk'),
            ('^', 'U+005E', 'Caret'),
            ('~', 'U+007E', 'Tilde'),
            ('[', 'U+005B', 'Left Bracket'),
            (']', 'U+005D', 'Right Bracket'),
            ('{', 'U+007B', 'Left Brace'),
            ('}', 'U+007D', 'Right Brace'),
            ('#', 'U+0023', 'Hash'),
            ('@', 'U+0040', 'At Sign'),
            (',', 'U+002C', 'Comma'),
            ('.', 'U+002E', 'Period'),
            ('\n', 'U+000A', 'Line Feed'),
            ('\r', 'U+000D', 'Carriage Return'),
            ('\t', 'U+0009', 'Tab'),
            (' ', 'U+0020', 'Space'),
        ]
    
    @staticmethod
    def get_xss_chars() -> List[Tuple[str, str, str]]:
        """Characters commonly used in XSS attacks"""
        return [
            ('<', 'U+003C', 'Less Than (Script Tag)'),
            ('>', 'U+003E', 'Greater Than (Script Tag)'),
            ('"', 'U+0022', 'Double Quote (Attribute Breaking)'),
            ("'", 'U+0027', 'Single Quote (Attribute Breaking)'),
            ('/', 'U+002F', 'Slash (Tag Closing)'),
            ('(', 'U+0028', 'Parenthesis (Function Call)'),
            (')', 'U+0029', 'Parenthesis (Function Call)'),
            (';', 'U+003B', 'Semicolon (JavaScript)'),
            ('`', 'U+0060', 'Backtick (Template Literal)'),
        ]
    
    @staticmethod
    def get_sqli_chars() -> List[Tuple[str, str, str]]:
        """Characters commonly used in SQL injection"""
        return [
            ("'", 'U+0027', 'Single Quote (String Delimiter)'),
            ('"', 'U+0022', 'Double Quote (Identifier)'),
            (';', 'U+003B', 'Semicolon (Statement Separator)'),
            ('--', 'U+002D U+002D', 'Comment'),
            ('#', 'U+0023', 'Comment'),
            ('/*', 'U+002F U+002A', 'Multi-line Comment Start'),
            ('*/', 'U+002A U+002F', 'Multi-line Comment End'),
            ('|', 'U+007C', 'Pipe (Bitwise OR)'),
            ('&', 'U+0026', 'Ampersand (Bitwise AND)'),
            ('=', 'U+003D', 'Equals (Comparison)'),
        ]
    
    @staticmethod
    def get_command_injection_chars() -> List[Tuple[str, str, str]]:
        """Characters commonly used in command injection"""
        return [
            (';', 'U+003B', 'Semicolon (Command Separator)'),
            ('|', 'U+007C', 'Pipe (Command Chaining)'),
            ('&', 'U+0026', 'Ampersand (Background Process)'),
            ('`', 'U+0060', 'Backtick (Command Substitution)'),
            ('$', 'U+0024', 'Dollar (Variable Expansion)'),
            ('(', 'U+0028', 'Subshell Start'),
            (')', 'U+0029', 'Subshell End'),
            ('\n', 'U+000A', 'Newline (Command Separator)'),
            ('>', 'U+003E', 'Redirect Output'),
            ('<', 'U+003C', 'Redirect Input'),
        ]


def detect_blocking(baseline_response: str, test_response: str, 
                    baseline_status: int, test_status: int) -> Tuple[bool, str]:
    """
    Detect if a character was blocked by comparing baseline and test responses.
    
    Args:
        baseline_response: Response content from baseline request
        test_response: Response content from test request
        baseline_status: HTTP status code from baseline
        test_status: HTTP status code from test
    
    Returns:
        Tuple of (is_blocked, reason)
    """
    # Check for common blocking status codes
    if test_status in [403, 406, 418, 429, 500, 501, 503]:
        return (True, f"Blocking status code: {test_status}")
    
    # Check for significant status code change
    if baseline_status == 200 and test_status != 200:
        return (True, f"Status changed from {baseline_status} to {test_status}")
    
    # Check for WAF indicators in response
    waf_indicators = [
        'blocked', 'forbidden', 'not acceptable', 'security',
        'firewall', 'waf', 'access denied', 'rejected',
        'suspicious', 'malicious', 'attack', 'invalid request'
    ]
    
    test_lower = test_response.lower()
    for indicator in waf_indicators:
        if indicator in test_lower:
            return (True, f"WAF indicator found: '{indicator}'")
    
    # Check for significant content length difference
    baseline_len = len(baseline_response)
    test_len = len(test_response)
    
    if baseline_len > 0:
        diff_ratio = abs(baseline_len - test_len) / baseline_len
        if diff_ratio > 0.5:  # More than 50% difference
            return (True, f"Significant content length change: {baseline_len} -> {test_len}")
    
    # If we get here, character appears to be allowed
    return (False, "No blocking detected")
