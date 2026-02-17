# Numeric SQL Injection Prober

## Overview

The `NumericSqlInjector` class provides specialized SQL injection testing for numeric parameters. It uses arithmetic-based payloads that are less likely to trigger WAFs or input validation filters compared to traditional string-based SQL injection payloads.

## Features

- **Automatic Parameter Identification**: Identifies numeric parameters from HTTP requests (query strings, POST data, cookies, headers)
- **Arithmetic-Based Payloads**: Generates 20+ different numeric SQL injection payloads including:
  - Basic arithmetic: `5+0`, `5-0`, `5*1`, `5/1`
  - Value-changing operations: `5+1`, `5-1`, `5*2`
  - ASCII operations: `67-ASCII("A")`, `51-ASCII(1)`
  - Bitwise operations: `5|0`, `5&5`, `5^0`
  - Nested expressions: `(5+1)-1`, `(5*2)/2`
- **ORDER BY-Based SQL Injection Detection**: Specialized detection for ORDER BY clauses and column selection
  - Sequential numeric value testing (1, 2, 3, ...) to detect ordering/field control
  - Detection of ordering changes in responses
  - Detection of field/column changes when parameter value changes
  - Identification of parameters used as column names or in ORDER BY clauses
  - ORDER BY payload testing (ASC --, DESC --)
  - Advanced column selection payloads (nested SELECT, CASE expressions)
  - MS-SQL batched query detection
- **Smart URL Encoding**: Properly encodes HTTP special characters while preserving payload structure
- **Response Analysis**: Detects vulnerabilities through:
  - SQL error detection (MySQL, PostgreSQL, Oracle, MS SQL Server)
  - HTTP status code changes
  - Content similarity analysis
  - Ordering and field change detection
  - Confidence scoring
- **HTTP Method Preservation**: Maintains GET/POST methods during testing
- **Retry Logic**: Handles transient network failures
- **Configurable**: Timeout, retry count, similarity threshold, and numeric headers can be customized

## Installation

The module is part of the Megido SQL Attacker package and requires:
- Python 3.8+
- requests
- Django (for tests)

```bash
pip install requests
```

## Quick Start

### Basic Usage

```python
from sql_attacker.numeric_probe import NumericSqlInjector

# Initialize injector
injector = NumericSqlInjector()

# Probe all parameters in a URL
results = injector.probe_all_parameters(
    url='http://example.com/product?id=5&page=1',
    method='GET'
)

# Check for vulnerabilities
for result in results:
    if result.vulnerable:
        print(f"Vulnerable Parameter: {result.parameter.name}")
        print(f"Payload: {result.payload}")
        print(f"Confidence: {result.confidence:.2f}")
        print(f"Evidence: {result.evidence}")
```

### Identify Numeric Parameters

```python
# From URL query string
params = injector.identify_numeric_parameters(
    url='http://example.com/product?id=123&name=test&page=5',
    method='GET'
)

# From POST data
params = injector.identify_numeric_parameters(
    url='http://example.com/api/user',
    method='POST',
    data={'user_id': '456', 'username': 'john', 'age': '30'}
)

# From cookies
params = injector.identify_numeric_parameters(
    url='http://example.com',
    method='GET',
    cookies={'session_id': 'abc123', 'user_id': '789'}
)

# From headers
params = injector.identify_numeric_parameters(
    url='http://example.com',
    method='GET',
    headers={'X-User-ID': '123', 'X-Request-ID': '456'}
)

for param in params:
    print(f"{param.name} = {param.value} (location: {param.location})")
```

### Generate Payloads

```python
# Generate payloads for a specific value
payloads = injector.generate_payloads('5')

for payload in payloads:
    print(payload)
# Output:
# 5
# 5+0
# 5-0
# 5+1
# 67-ASCII("A")
# ...
```

### Probe a Single Parameter

```python
# Create a parameter
from sql_attacker.numeric_probe import NumericParameter

param = NumericParameter('id', '5', 'GET', 'query')

# Probe the parameter
results = injector.probe_parameter(
    url='http://example.com/product',
    parameter=param,
    method='GET',
    params={'id': '5'}
)

# Analyze results
for result in results:
    print(f"Payload: {result.payload}")
    print(f"Vulnerable: {result.vulnerable}")
    print(f"Confidence: {result.confidence}")
```

### ORDER BY-Based SQL Injection Detection

The injector can analyze parameters for ORDER BY-based SQL injection by testing sequential numeric values and detecting ordering/field changes:

```python
from sql_attacker.numeric_probe import NumericSqlInjector, NumericParameter

# Initialize injector
injector = NumericSqlInjector()

# Create a parameter suspected to be used in ORDER BY
param = NumericParameter('sort', '1', 'GET', 'query')

# Analyze for ORDER BY injection
results = injector.analyze_order_by_injection(
    url='http://example.com/products?sort=1',
    parameter=param,
    method='GET',
    params={'sort': '1'},
    max_sequential=10  # Test values 1-10
)

# Check results
for result in results:
    if result.vulnerable:
        print(f"ORDER BY Vulnerability Detected!")
        print(f"  Parameter: {result.parameter.name}")
        print(f"  Payload: {result.payload}")
        print(f"  Injection Type: {result.injection_type}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Evidence: {result.evidence}")
        
        if result.ordering_changed:
            print(f"  ✓ Ordering changes detected")
        if result.field_changed:
            print(f"  ✓ Field/column changes detected")
```

#### How ORDER BY Detection Works

1. **Sequential Value Testing**: Sends values 1, 2, 3, ... and monitors for changes
2. **Ordering Detection**: Identifies when response ordering changes (e.g., ascending to descending)
3. **Field Detection**: Identifies when response fields/columns change
4. **Column Number Detection**: Detects when a column filled with '1' values appears (indicating direct column selection)
5. **ORDER BY Payloads**: If ordering changes detected, tests `ASC --` and `DESC --` payloads
6. **Advanced Payloads**: If field changes detected, tests subqueries like `(SELECT 1)`, `(SELECT 1 WHERE 1=1)`

#### Example: Detecting Column Selection

```python
# A parameter that controls which column to display
param = NumericParameter('col', '2', 'GET', 'query')

results = injector.analyze_order_by_injection(
    url='http://example.com/data?col=2',
    parameter=param,
    method='GET',
    params={'col': '2'}
)

# Check for column selection injection
column_results = [r for r in results if r.injection_type == 'column_selection']
if column_results:
    print("Column selection vulnerability found!")
    print(f"Parameter '{param.name}' likely used as: SELECT * FROM table ORDER BY {param.name}")
```

#### Example: MS-SQL Advanced Payloads

```python
# For detected ORDER BY vulnerabilities, test advanced MS-SQL payloads
# This automatically happens when field changes are detected

results = injector.analyze_order_by_injection(
    url='http://example.com/items?orderby=1',
    parameter=NumericParameter('orderby', '1', 'GET', 'query'),
    method='GET',
    params={'orderby': '1'}
)

# Check for advanced injection types
advanced_results = [r for r in results if 'advanced' in r.injection_type]
for result in advanced_results:
    print(f"Advanced injection: {result.payload}")
    # Payloads like: (SELECT 1), (SELECT 1 WHERE 1=1), etc.
```

## Advanced Configuration

### Custom Initialization

```python
# Configure timeout, retries, and similarity threshold
injector = NumericSqlInjector(
    timeout=30,              # Request timeout in seconds
    max_retries=5,           # Number of retry attempts
    similarity_threshold=0.90  # Response similarity threshold
)

# Configure custom numeric headers to check
custom_headers = ['X-Custom-ID', 'X-Special-Number', 'X-Transaction-ID']
injector = NumericSqlInjector(numeric_headers=custom_headers)
```

### Testing POST Requests

```python
results = injector.probe_all_parameters(
    url='http://example.com/api/submit',
    method='POST',
    data={
        'user_id': '100',
        'action': 'update',
        'count': '5'
    },
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)
```

### Testing with Authentication

```python
results = injector.probe_all_parameters(
    url='http://example.com/api/data?id=10',
    method='GET',
    headers={
        'Authorization': 'Bearer your-token-here',
        'X-API-Key': 'your-api-key'
    },
    cookies={
        'session': 'your-session-cookie'
    }
)
```

## Understanding Results

### NumericInjectionResult Object

Each test returns a `NumericInjectionResult` object with the following fields:

```python
result = NumericInjectionResult(...)

# Access result fields
result.parameter        # NumericParameter that was tested
result.payload          # The payload that was sent
result.vulnerable       # Boolean: True if vulnerability detected
result.confidence       # Float 0.0-1.0: Confidence in detection
result.evidence         # String: Evidence of vulnerability
result.response_diff    # Float: Response difference from baseline
result.injection_type   # String: Type of injection ('numeric', 'order_by', 'column_selection', 'advanced_column_selection')
result.ordering_changed # Boolean: True if ordering was detected to change
result.field_changed    # Boolean: True if response fields changed
```

### Injection Types

- **numeric**: Standard numeric SQL injection (arithmetic operations)
- **order_by**: ORDER BY clause injection (ASC/DESC manipulation)
- **column_selection**: Column selection by number (e.g., ORDER BY 1, ORDER BY 2)
- **advanced_column_selection**: Advanced column manipulation (subqueries, CASE expressions)

### Confidence Levels

- **0.9+**: High confidence (SQL errors detected)
- **0.6-0.8**: Medium confidence (status code changes, large content differences)
- **0.3-0.5**: Low confidence (minor differences)
- **< 0.3**: Not considered vulnerable

### Vulnerability Detection Methods

1. **SQL Error Detection**: Scans responses for database error messages
   - MySQL: "SQL syntax error", "mysql_fetch"
   - PostgreSQL: "PostgreSQL ERROR"
   - Oracle: "ORA-XXXXX"
   - MS SQL: "Incorrect syntax near"

2. **Status Code Changes**: 200 → 500 indicates potential vulnerability

3. **Content Similarity**: Large differences in response content suggest SQL interpretation

4. **Ordering Detection** (ORDER BY): Detects when response item ordering changes
   - Reversed sequences (ascending to descending or vice versa)
   - Reordered items with same data

5. **Field Change Detection**: Detects when response fields/columns change
   - Different data structure in response
   - Different number or type of fields

6. **Column Pattern Detection**: Identifies when a column contains all '1' values
   - Indicates parameter used as column number selector
   - Pattern: SELECT * FROM table ORDER BY <parameter>

## Integration with Megido

The `NumericSqlInjector` can be integrated into Megido's attack pipelines:

```python
from sql_attacker.sqli_engine import SQLInjectionEngine
from sql_attacker.numeric_probe import NumericSqlInjector

# In your attack workflow
def test_target_with_numeric_probing(target_url):
    # Use standard SQL injection engine
    engine = SQLInjectionEngine()
    standard_results = engine.test_url(target_url)
    
    # Add numeric probing
    numeric_injector = NumericSqlInjector()
    numeric_results = numeric_injector.probe_all_parameters(
        url=target_url,
        method='GET'
    )
    
    # Combine results
    all_vulnerabilities = []
    all_vulnerabilities.extend(standard_results)
    
    for result in numeric_results:
        if result.vulnerable:
            all_vulnerabilities.append({
                'type': 'numeric_sql_injection',
                'parameter': result.parameter.name,
                'payload': result.payload,
                'confidence': result.confidence,
                'evidence': result.evidence
            })
    
    return all_vulnerabilities
```

## Testing

### Running Unit Tests

The module includes comprehensive unit tests:

```bash
# Using Django test runner
python manage.py test sql_attacker.test_numeric_probe

# View test coverage
python manage.py test sql_attacker.test_numeric_probe --verbosity=2
```

### Running the Demo

```bash
# Interactive demonstration
python demo_numeric_probe.py

# Quick functionality check
python -c "
from sql_attacker.numeric_probe import NumericSqlInjector
injector = NumericSqlInjector()
print(f'Payloads: {len(injector.generate_payloads(\"5\"))}')
"
```

## How It Works

### 1. Parameter Identification

The injector scans HTTP requests to identify parameters with numeric values:
- Query parameters: `?id=123&page=5`
- POST data: `{'user_id': '456'}`
- Cookies: `{'user_id': '789'}`
- Headers: `{'X-User-ID': '123'}`

### 2. Payload Generation

For each numeric value, generates variations like:
- `5` (baseline)
- `5+0` (should equal original)
- `5+1` (should differ from original)
- `67-ASCII("A")` (evaluates to 2 in SQL)
- `(5+1)-1` (should equal original)

### 3. Request Tampering

Sends HTTP requests with each payload, properly URL-encoded:
- `5+1` → `5%2B1` (plus sign encoded)
- `67-ASCII("A")` → `67-ASCII%28%22A%22%29`

### 4. Response Analysis

Compares test responses with baseline:
- Checks for SQL error messages
- Calculates content similarity
- Monitors status code changes
- Detects ordering changes (for ORDER BY injection)
- Detects field/column changes
- Identifies column-with-1s pattern
- Assigns confidence scores

### 5. ORDER BY Detection (Additional)

For ORDER BY-based injection:
- Tests sequential numeric values (1, 2, 3, ...)
- Monitors for ordering changes in response
- Monitors for field/column changes
- Tests ASC/DESC payloads if ordering changes detected
- Tests advanced payloads (subqueries) if field changes detected

### 6. Vulnerability Reporting

Returns structured results indicating:
- Which parameters are vulnerable
- Which payloads triggered detection
- Type of injection (numeric, order_by, column_selection)
- Evidence and confidence scores

## Why Numeric Injection?

Numeric SQL injection testing offers several advantages:

1. **WAF Evasion**: Arithmetic operations are less suspicious than quotes and keywords
2. **Input Validation Bypass**: Numeric filters often allow math operators
3. **Subtle Detection**: Differences may be less obvious but still indicate SQLi
4. **Comprehensive Coverage**: Tests parameters that might be missed by string-based tests
5. **ORDER BY Detection**: Specialized detection for ordering and column selection vulnerabilities
6. **Advanced Exploitation**: Tests subqueries and batched queries for MS-SQL and other databases

## Best Practices

1. **Start with Identification**: Always identify parameters before probing
2. **Use Baseline Comparison**: Compare responses to detect subtle changes
3. **Check Multiple Locations**: Test query, body, cookies, and headers
4. **Test ORDER BY Separately**: Use `analyze_order_by_injection()` for suspected sorting/ordering parameters
5. **Monitor for Ordering Changes**: Pay attention to ordering_changed and field_changed flags in results
6. **Respect Rate Limits**: Use appropriate timeouts and delays
7. **Verify Results**: High confidence results should be manually verified
8. **Combine Approaches**: Use alongside traditional string-based SQLi testing

## Example: Complete Workflow

```python
from sql_attacker.numeric_probe import NumericSqlInjector

# Initialize
injector = NumericSqlInjector(
    timeout=15,
    max_retries=3,
    similarity_threshold=0.95
)

# Target URL
target = 'http://example.com/product?id=5&category=electronics'

# Step 1: Identify numeric parameters
print("Step 1: Identifying numeric parameters...")
params = injector.identify_numeric_parameters(url=target, method='GET')
print(f"Found {len(params)} numeric parameter(s)")

# Step 2: Probe each parameter
print("\nStep 2: Probing for vulnerabilities...")
results = injector.probe_all_parameters(url=target, method='GET')

# Step 3: Report findings
print("\nStep 3: Analyzing results...")
vulnerable_params = []

for result in results:
    if result.vulnerable:
        vulnerable_params.append(result)
        print(f"\n🔴 VULNERABLE: {result.parameter.name}")
        print(f"   Payload: {result.payload}")
        print(f"   Confidence: {result.confidence:.2%}")
        print(f"   Evidence: {result.evidence}")

# Step 4: Summary
print(f"\n{'='*60}")
print(f"Summary: Found {len(vulnerable_params)} potential vulnerabilities")
print(f"Total tests: {len(results)}")
print(f"{'='*60}")
```

## Example: Complete ORDER BY Workflow

```python
from sql_attacker.numeric_probe import NumericSqlInjector, NumericParameter

# Initialize
injector = NumericSqlInjector(
    timeout=15,
    max_retries=3,
    similarity_threshold=0.95
)

# Target URL with suspected ORDER BY parameter
target = 'http://example.com/products?sort=1&page=1'

# Step 1: Identify numeric parameters
print("Step 1: Identifying numeric parameters...")
params = injector.identify_numeric_parameters(url=target, method='GET')
print(f"Found {len(params)} numeric parameter(s)")

# Step 2: Test for standard numeric injection
print("\nStep 2: Testing for standard numeric injection...")
standard_results = injector.probe_all_parameters(url=target, method='GET')

# Step 3: Test suspected ORDER BY parameters
print("\nStep 3: Testing for ORDER BY injection...")
order_by_params = [p for p in params if p.name in ['sort', 'orderby', 'order', 'col', 'column']]

for param in order_by_params:
    print(f"\n  Analyzing '{param.name}' for ORDER BY injection...")
    order_results = injector.analyze_order_by_injection(
        url=target,
        parameter=param,
        method='GET',
        params={p.name: p.value for p in params},
        max_sequential=10
    )
    
    # Check for ORDER BY vulnerabilities
    for result in order_results:
        if result.vulnerable:
            print(f"\n  🔴 ORDER BY VULNERABILITY FOUND!")
            print(f"     Parameter: {result.parameter.name}")
            print(f"     Injection Type: {result.injection_type}")
            print(f"     Payload: {result.payload}")
            print(f"     Confidence: {result.confidence:.2%}")
            print(f"     Evidence: {result.evidence}")
            
            if result.ordering_changed:
                print(f"     ✓ Ordering changes detected")
            if result.field_changed:
                print(f"     ✓ Field/column changes detected")

# Step 4: Summary
print(f"\n{'='*60}")
print(f"Analysis Complete")
print(f"{'='*60}")
```

## Troubleshooting

### Connection Errors
```python
# Increase timeout and retries
injector = NumericSqlInjector(timeout=30, max_retries=5)
```

### Too Many False Positives
```python
# Increase similarity threshold
injector = NumericSqlInjector(similarity_threshold=0.98)
```

### Missing Parameters
```python
# Add custom numeric headers
injector = NumericSqlInjector(
    numeric_headers=['X-User-ID', 'X-Custom-Header', 'X-ID']
)
```

## API Reference

See docstrings in `sql_attacker/numeric_probe.py` for detailed API documentation:
- `NumericSqlInjector` class
- `NumericParameter` class
- `NumericInjectionResult` class

## Contributing

To extend the numeric probe functionality:

1. Add new payload templates to `NUMERIC_PAYLOADS`
2. Add new error patterns to `_check_sql_errors()`
3. Add new analysis methods to `_analyze_response()`
4. Update tests in `test_numeric_probe.py`

## License

Part of the Megido Security Testing Framework.

## See Also

- `sql_attacker/sqli_engine.py` - Main SQL injection engine
- `sql_attacker/comprehensive_input_tester.py` - Multi-vector testing
- `demo_numeric_probe.py` - Interactive demonstration
