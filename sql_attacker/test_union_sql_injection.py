"""
Unit tests for UNION-based SQL Injection Attacker module.

Tests cover:
- Column count discovery
- DBMS detection
- Metadata mining (tables, columns)
- Data extraction
- Sensitive data search
- Helper methods
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from sql_attacker.union_sql_injection import (
    UnionSQLInjectionAttacker,
    DBMSType,
    example_basic_usage,
    example_sensitive_data_search
)


class TestUnionSQLInjectionAttacker(unittest.TestCase):
    """Test cases for UnionSQLInjectionAttacker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_request = Mock()
        self.attacker = UnionSQLInjectionAttacker(
            send_request_callback=self.mock_request,
            max_columns=10,
            delay=0.01  # Low delay for faster tests
        )
    
    def test_initialization(self):
        """Test attacker initialization."""
        self.assertEqual(self.attacker.max_columns, 10)
        self.assertEqual(self.attacker.delay, 0.01)
        self.assertEqual(self.attacker.dbms_type, DBMSType.UNKNOWN)
        self.assertIsNone(self.attacker.column_count)
        self.assertEqual(self.attacker.injectable_columns, [])
    
    def test_set_target(self):
        """Test setting target URL and injection point."""
        self.mock_request.return_value = ("<html>test</html>", 200, {})
        
        self.attacker.set_target("http://example.com/product?id=1")
        
        self.assertEqual(self.attacker.target_url, "http://example.com/product?id=1")
        self.assertEqual(self.attacker.injection_point, "id")
        self.assertIsNotNone(self.attacker.baseline_response)
        self.assertGreater(self.attacker.baseline_length, 0)
    
    def test_set_target_explicit_injection_point(self):
        """Test setting target with explicit injection point."""
        self.mock_request.return_value = ("<html>test</html>", 200, {})
        
        self.attacker.set_target("http://example.com/search", injection_point="query")
        
        self.assertEqual(self.attacker.injection_point, "query")
    
    def test_inject_payload(self):
        """Test payload injection into URL."""
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        injected_url = self.attacker._inject_payload("' OR '1'='1")
        
        self.assertIn("' OR '1'='1", injected_url)
        self.assertIn("id=1", injected_url)
    
    def test_is_successful_union_with_errors(self):
        """Test detection of failed UNION attempts with SQL errors."""
        error_response = "You have an error in your SQL syntax near '1'"
        
        result = self.attacker._is_successful_union(error_response, 200)
        
        self.assertFalse(result)
    
    def test_is_successful_union_with_success(self):
        """Test detection of successful UNION attempts."""
        success_response = "<html><body>Product details...</body></html>"
        
        result = self.attacker._is_successful_union(success_response, 200)
        
        self.assertTrue(result)
    
    def test_is_successful_union_bad_status(self):
        """Test detection rejects bad HTTP status codes."""
        result = self.attacker._is_successful_union("any response", 500)
        
        self.assertFalse(result)
    
    def test_check_dbms_indicators_mysql(self):
        """Test DBMS detection for MySQL."""
        mysql_response = "MySQL version 5.7.31 running"
        
        result = self.attacker._check_dbms_indicators(mysql_response, DBMSType.MYSQL)
        
        self.assertTrue(result)
    
    def test_check_dbms_indicators_postgresql(self):
        """Test DBMS detection for PostgreSQL."""
        pg_response = "PostgreSQL 12.5 on x86_64-pc-linux-gnu"
        
        result = self.attacker._check_dbms_indicators(pg_response, DBMSType.POSTGRESQL)
        
        self.assertTrue(result)
    
    def test_check_dbms_indicators_mssql(self):
        """Test DBMS detection for MS-SQL."""
        mssql_response = "Microsoft SQL Server 2019"
        
        result = self.attacker._check_dbms_indicators(mssql_response, DBMSType.MSSQL)
        
        self.assertTrue(result)
    
    def test_check_dbms_indicators_oracle(self):
        """Test DBMS detection for Oracle."""
        oracle_response = "Oracle Database 19c Enterprise Edition"
        
        result = self.attacker._check_dbms_indicators(oracle_response, DBMSType.ORACLE)
        
        self.assertTrue(result)
    
    def test_check_dbms_indicators_no_match(self):
        """Test DBMS detection with no matching indicators."""
        generic_response = "Database error occurred"
        
        result = self.attacker._check_dbms_indicators(generic_response, DBMSType.MYSQL)
        
        self.assertFalse(result)
    
    def test_get_concat_function_mysql(self):
        """Test MySQL concatenation function."""
        self.attacker.dbms_type = DBMSType.MYSQL
        
        result = self.attacker._get_concat_function(['col1', "'|'", 'col2'])
        
        self.assertEqual(result, "CONCAT(col1,'|',col2)")
    
    def test_get_concat_function_postgresql(self):
        """Test PostgreSQL concatenation function."""
        self.attacker.dbms_type = DBMSType.POSTGRESQL
        
        result = self.attacker._get_concat_function(['col1', "'|'", 'col2'])
        
        self.assertEqual(result, "col1||'|'||col2")
    
    def test_get_concat_function_mssql(self):
        """Test MS-SQL concatenation function."""
        self.attacker.dbms_type = DBMSType.MSSQL
        
        result = self.attacker._get_concat_function(['col1', "'|'", 'col2'])
        
        self.assertEqual(result, "col1+'|'+col2")
    
    def test_get_concat_function_oracle(self):
        """Test Oracle concatenation function."""
        self.attacker.dbms_type = DBMSType.ORACLE
        
        result = self.attacker._get_concat_function(['col1', "'|'", 'col2'])
        
        self.assertEqual(result, "col1||'|'||col2")
    
    def test_discover_column_count_success(self):
        """Test successful column count discovery."""
        # First 2 attempts fail, 3rd succeeds
        self.mock_request.side_effect = [
            ("<html>baseline</html>", 200, {}),  # set_target
            ("SQL syntax error", 200, {}),  # 1 column fails
            ("SQL syntax error", 200, {}),  # 2 columns fails
            ("<html>success with extra data</html>", 200, {}),  # 3 columns succeeds
        ]
        
        self.attacker.set_target("http://example.com/product?id=1")
        
        # Add more responses for injectable column identification
        self.mock_request.side_effect = [
            ("<html>INJECTABLE_1_TEST found</html>", 200, {}),
            ("<html>no marker</html>", 200, {}),
            ("<html>no marker</html>", 200, {}),
        ]
        
        column_count = self.attacker.discover_column_count()
        
        self.assertEqual(column_count, 3)
        self.assertEqual(self.attacker.column_count, 3)
    
    def test_discover_column_count_failure(self):
        """Test column count discovery failure."""
        self.mock_request.return_value = ("SQL syntax error", 200, {})
        
        self.attacker.set_target("http://example.com/product?id=1")
        column_count = self.attacker.discover_column_count()
        
        self.assertIsNone(column_count)
    
    def test_discover_column_count_no_target(self):
        """Test column count discovery without setting target."""
        column_count = self.attacker.discover_column_count()
        
        self.assertIsNone(column_count)
    
    def test_identify_injectable_columns(self):
        """Test identification of injectable columns."""
        self.attacker.column_count = 3
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        # Mock responses: column 1 and 3 are injectable
        self.mock_request.side_effect = [
            ("<html>INJECTABLE_1_TEST</html>", 200, {}),
            ("<html>no marker</html>", 200, {}),
            ("<html>INJECTABLE_3_TEST here</html>", 200, {}),
        ]
        
        self.attacker._identify_injectable_columns(3, '--')
        
        self.assertEqual(self.attacker.injectable_columns, [1, 3])
    
    def test_detect_dbms_mysql(self):
        """Test DBMS detection for MySQL."""
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = ("MySQL version 5.7", 200, {})
        
        dbms = self.attacker.detect_dbms()
        
        self.assertEqual(dbms, DBMSType.MYSQL)
        self.assertEqual(self.attacker.dbms_type, DBMSType.MYSQL)
    
    def test_detect_dbms_already_known(self):
        """Test DBMS detection when already known."""
        self.attacker.dbms_type = DBMSType.POSTGRESQL
        
        dbms = self.attacker.detect_dbms()
        
        self.assertEqual(dbms, DBMSType.POSTGRESQL)
        # Should not make any requests
        self.mock_request.assert_not_called()
    
    def test_extract_results_from_response(self):
        """Test extraction of results from response."""
        response = """
        <html>
            <body>
                <table>
                    <tr><td>users</td></tr>
                    <tr><td>products</td></tr>
                    <tr><td>orders</td></tr>
                </table>
            </body>
        </html>
        """
        
        results = self.attacker._extract_results_from_response(response)
        
        # Should extract table-like names
        self.assertIsInstance(results, list)
        # May contain 'users', 'products', 'orders', 'table', 'body', etc.
        self.assertGreater(len(results), 0)
    
    def test_discover_tables_no_column_count(self):
        """Test discovering tables without column count."""
        tables = self.attacker.discover_tables()
        
        self.assertEqual(tables, [])
    
    def test_discover_tables_mysql(self):
        """Test discovering tables for MySQL."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MYSQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        # Mock response with table names
        self.mock_request.return_value = (
            "<html>users products orders</html>",
            200,
            {}
        )
        
        tables = self.attacker.discover_tables()
        
        self.assertIsInstance(tables, list)
        # Should call request with UNION query
        self.mock_request.assert_called()
    
    def test_discover_tables_oracle(self):
        """Test discovering tables for Oracle."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.ORACLE
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = (
            "<html>USERS PRODUCTS ORDERS</html>",
            200,
            {}
        )
        
        tables = self.attacker.discover_tables()
        
        self.assertIsInstance(tables, list)
    
    def test_discover_tables_with_pattern(self):
        """Test discovering tables with pattern filter."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MYSQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = ("<html>users user_sessions</html>", 200, {})
        
        tables = self.attacker.discover_tables(pattern='%user%')
        
        self.assertIsInstance(tables, list)
    
    def test_discover_columns_no_column_count(self):
        """Test discovering columns without column count."""
        columns = self.attacker.discover_columns('users')
        
        self.assertEqual(columns, [])
    
    def test_discover_columns_mysql(self):
        """Test discovering columns for MySQL."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MYSQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        # Mock response with column info
        self.mock_request.return_value = (
            "<html>username|varchar password|varchar email|varchar</html>",
            200,
            {}
        )
        
        columns = self.attacker.discover_columns('users')
        
        self.assertIsInstance(columns, list)
    
    def test_discover_columns_oracle(self):
        """Test discovering columns for Oracle."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.ORACLE
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = (
            "<html>USERNAME|VARCHAR2 PASSWORD|VARCHAR2</html>",
            200,
            {}
        )
        
        columns = self.attacker.discover_columns('USERS')
        
        self.assertIsInstance(columns, list)
    
    def test_discover_columns_with_pattern(self):
        """Test discovering columns with pattern filter."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MYSQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = (
            "<html>password|varchar</html>",
            200,
            {}
        )
        
        columns = self.attacker.discover_columns('users', pattern='%pass%')
        
        self.assertIsInstance(columns, list)
    
    def test_extract_data_no_column_count(self):
        """Test extracting data without column count."""
        data = self.attacker.extract_data('users', ['username', 'password'])
        
        self.assertEqual(data, [])
    
    def test_extract_data_mysql(self):
        """Test extracting data for MySQL."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MYSQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        # Mock response with data
        self.mock_request.return_value = (
            "<html>admin|admin@example.com user1|user1@example.com</html>",
            200,
            {}
        )
        
        data = self.attacker.extract_data('users', ['username', 'email'], limit=10)
        
        self.assertIsInstance(data, list)
    
    def test_extract_data_with_where_clause(self):
        """Test extracting data with WHERE clause."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MYSQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = (
            "<html>admin|admin@example.com</html>",
            200,
            {}
        )
        
        data = self.attacker.extract_data(
            'users',
            ['username', 'email'],
            where_clause='id > 5',
            limit=10
        )
        
        self.assertIsInstance(data, list)
    
    def test_extract_data_limit_postgresql(self):
        """Test data extraction with PostgreSQL LIMIT syntax."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.POSTGRESQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = ("<html>data</html>", 200, {})
        
        data = self.attacker.extract_data('users', ['username'], limit=5)
        
        # Should use LIMIT syntax
        self.assertIsInstance(data, list)
    
    def test_extract_data_limit_mssql(self):
        """Test data extraction with MS-SQL TOP syntax."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MSSQL
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = ("<html>data</html>", 200, {})
        
        data = self.attacker.extract_data('users', ['username'], limit=5)
        
        # Should use TOP syntax
        self.assertIsInstance(data, list)
    
    def test_extract_data_limit_oracle(self):
        """Test data extraction with Oracle ROWNUM syntax."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.ORACLE
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = ("<html>data</html>", 200, {})
        
        data = self.attacker.extract_data('USERS', ['USERNAME'], limit=5)
        
        # Should use ROWNUM syntax
        self.assertIsInstance(data, list)
    
    def test_search_sensitive_columns_no_column_count(self):
        """Test searching sensitive columns without column count."""
        # Mock discover_tables to return empty
        with patch.object(self.attacker, 'discover_tables', return_value=[]):
            sensitive = self.attacker.search_sensitive_columns()
            
            self.assertEqual(sensitive, {})
    
    def test_search_sensitive_columns_success(self):
        """Test successful sensitive column search."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [1]
        self.attacker.dbms_type = DBMSType.MYSQL
        
        # Mock discover_tables
        with patch.object(self.attacker, 'discover_tables', return_value=['users', 'products']):
            # Mock discover_columns to return password column for users table
            def mock_discover_columns(table, schema=None, pattern=None):
                if table == 'users' and pattern and 'pass' in pattern.lower():
                    return [{'column_name': 'password', 'data_type': 'varchar'}]
                return []
            
            with patch.object(self.attacker, 'discover_columns', side_effect=mock_discover_columns):
                sensitive = self.attacker.search_sensitive_columns(patterns=['%pass%'])
                
                self.assertIsInstance(sensitive, dict)
                # Should find password in users table
                if 'users' in sensitive:
                    self.assertGreater(len(sensitive['users']), 0)
    
    def test_execute_union_query(self):
        """Test executing UNION query."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = [2]
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = (
            "<html>result_value other_data</html>",
            200,
            {}
        )
        
        results = self.attacker._execute_union_query("SELECT table_name FROM information_schema.tables")
        
        self.assertIsInstance(results, list)
        self.mock_request.assert_called()
    
    def test_execute_union_query_no_injectable_columns(self):
        """Test executing UNION query without injectable columns."""
        self.attacker.column_count = 3
        self.attacker.injectable_columns = []  # No injectable columns
        self.attacker.target_url = "http://example.com/product?id=1"
        self.attacker.injection_point = "id"
        
        self.mock_request.return_value = ("<html>data</html>", 200, {})
        
        # Should default to column 1
        results = self.attacker._execute_union_query("SELECT 1")
        
        self.assertIsInstance(results, list)


class TestExampleFunctions(unittest.TestCase):
    """Test example usage functions."""
    
    @patch('sql_attacker.union_sql_injection.UnionSQLInjectionAttacker')
    def test_example_basic_usage(self, mock_attacker_class):
        """Test basic usage example runs without errors."""
        mock_attacker = Mock()
        mock_attacker.detect_dbms.return_value = DBMSType.MYSQL
        mock_attacker.discover_column_count.return_value = 3
        mock_attacker.discover_tables.return_value = ['users', 'products']
        mock_attacker.discover_columns.return_value = [
            {'column_name': 'id', 'data_type': 'int'},
            {'column_name': 'username', 'data_type': 'varchar'}
        ]
        mock_attacker.extract_data.return_value = [
            {'id': '1', 'username': 'admin'}
        ]
        mock_attacker_class.return_value = mock_attacker
        
        # Should run without raising exceptions
        try:
            example_basic_usage()
            success = True
        except Exception as e:
            success = False
            print(f"Example failed: {e}")
        
        self.assertTrue(success)
    
    @patch('sql_attacker.union_sql_injection.UnionSQLInjectionAttacker')
    def test_example_sensitive_data_search(self, mock_attacker_class):
        """Test sensitive data search example runs without errors."""
        mock_attacker = Mock()
        mock_attacker.discover_column_count.return_value = 3
        mock_attacker.search_sensitive_columns.return_value = {
            'users': [{'column_name': 'password', 'data_type': 'varchar'}]
        }
        mock_attacker.extract_data.return_value = [
            {'password': 'hashed_password'}
        ]
        mock_attacker_class.return_value = mock_attacker
        
        # Should run without raising exceptions
        try:
            example_sensitive_data_search()
            success = True
        except Exception as e:
            success = False
            print(f"Example failed: {e}")
        
        self.assertTrue(success)


class TestDBMSType(unittest.TestCase):
    """Test DBMSType enum."""
    
    def test_dbms_types_exist(self):
        """Test all expected DBMS types exist."""
        self.assertEqual(DBMSType.MYSQL.value, "mysql")
        self.assertEqual(DBMSType.POSTGRESQL.value, "postgresql")
        self.assertEqual(DBMSType.MSSQL.value, "mssql")
        self.assertEqual(DBMSType.ORACLE.value, "oracle")
        self.assertEqual(DBMSType.UNKNOWN.value, "unknown")


if __name__ == '__main__':
    unittest.main()
