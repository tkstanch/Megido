# Multi-Context Injection Attack Enhancement

## Overview

The SQL Attacker module has been significantly enhanced to support injection attacks across multiple interpreted query contexts beyond SQL. This provides comprehensive coverage for modern web applications that use various backend technologies.

## Supported Injection Contexts

### 1. SQL Injection
- **Traditional SQL database injection**
- Supports: MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite
- Attack types: Error-based, Time-based blind, UNION-based, Boolean-based, Stacked queries
- 40+ specialized payloads

### 2. LDAP Injection
- **LDAP directory query injection**
- Targets: Active Directory, OpenLDAP, etc.
- Attack vectors: Filter injection, Authentication bypass, Attribute extraction
- 35+ LDAP-specific payloads

### 3. XPath Injection
- **XML XPath query injection**
- Targets: XML databases, SOAP services, etc.
- Attack vectors: Node extraction, Boolean blind, Authentication bypass
- 40+ XPath-specific payloads

### 4. Message Queue Injection
- **Message queue system injection**
- Targets: RabbitMQ, Kafka, ActiveMQ, Redis Pub/Sub
- Attack vectors: Queue manipulation, Command injection, Privilege escalation
- 30+ message queue payloads

### 5. Custom Query Language Injection
- **Modern query language injection**
- Targets: GraphQL, JSONPath, OData, MongoDB queries, ElasticSearch DSL
- Attack vectors: Schema introspection, Data exfiltration, Query manipulation
- 35+ custom query payloads

## Architecture

### Core Components

```
sql_attacker/
├── injection_contexts/          # Multi-context framework
│   ├── __init__.py
│   ├── base.py                  # Abstract base classes
│   ├── sql_context.py           # SQL injection context
│   ├── ldap_context.py          # LDAP injection context
│   ├── xpath_context.py         # XPath injection context
│   ├── message_queue_context.py # Message queue context
│   └── custom_query_context.py  # Custom query context
├── multi_context_orchestrator.py # Attack coordinator
└── models.py                    # Extended data models
```

### Key Classes

#### `InjectionContext` (Abstract Base Class)
Defines the interface for all injection contexts:
- `test_injection()` - Test a single payload
- `analyze_response()` - Analyze response for success indicators
- `attempt_exploitation()` - Attempt data extraction
- `_load_payloads()` - Load context-specific payloads
- `_load_detection_patterns()` - Load success detection patterns

#### `MultiContextAttackOrchestrator`
Coordinates attacks across multiple contexts:
- Parallel context testing
- Result aggregation
- Attack report generation
- Context-specific exploitation

## Usage Examples

### Basic Multi-Context Attack

```python
from sql_attacker.multi_context_orchestrator import MultiContextAttackOrchestrator
from sql_attacker.injection_contexts import InjectionContextType

# Initialize orchestrator
orchestrator = MultiContextAttackOrchestrator({
    'enabled_contexts': [
        InjectionContextType.SQL,
        InjectionContextType.LDAP,
        InjectionContextType.XPATH,
    ],
    'parallel_execution': True,
    'enable_exploitation': True,
})

# Test all contexts against a target
results = orchestrator.test_all_contexts(
    target_url="https://example.com/login",
    parameter_name="username",
    parameter_type="POST",
    parameter_value="test",
)

# Review successful attacks
for result in results:
    if result.success:
        print(f"✓ {result.context_type.value} injection found!")
        print(f"  Confidence: {result.confidence_score:.2%}")
        print(f"  Payload: {result.attack_vector.payload}")
        if result.exploited:
            print(f"  Extracted data: {result.extracted_data}")
```

### Testing Specific Contexts

```python
from sql_attacker.injection_contexts.ldap_context import LDAPInjectionContext

# Test only LDAP injection
ldap_context = LDAPInjectionContext()

result = ldap_context.test_injection(
    target_url="https://example.com/search",
    parameter_name="user",
    parameter_type="GET",
    parameter_value="",
    payload="*)(uid=*)",
)

if result.success:
    print(f"LDAP injection detected!")
    print(f"Evidence: {result.evidence}")
```

### Custom Configuration

```python
# Configure with custom settings
config = {
    'enabled_contexts': [InjectionContextType.CUSTOM_QUERY],
    'parallel_execution': False,  # Sequential testing
    'max_workers': 3,
    'timeout': 15,
    'enable_exploitation': True,
}

orchestrator = MultiContextAttackOrchestrator(config)

# Get context statistics
stats = orchestrator.get_context_statistics()
print(f"Total payloads: {stats['total_payloads']}")
for context_name, info in stats['contexts'].items():
    print(f"  {context_name}: {info['payload_count']} payloads")
```

## Dashboard UI

### Multi-Context Results Tab

The dashboard now includes a dedicated "Multi-Context Results" tab that displays:

1. **Context Filtering** - Quick filters for each injection type
2. **Result Cards** - Detailed cards for each successful attack showing:
   - Injection context type (SQL, LDAP, XPath, etc.)
   - Verification status (Verified/Detected)
   - Confidence score
   - Severity level
   - Attack vector description
   - Payload used
   - Detection evidence
   - Proof of impact
   - Visual proof (screenshots/GIFs)
   - Exploitation results

3. **Visual Proof Display** - Following the vulnerability scanner pattern:
   - Inline preview images
   - Click to view fullscreen
   - Download option
   - Support for screenshots and animated GIFs

### Features

- **Color-coded severity**: Critical (red), High (yellow), Medium (blue), Low (gray)
- **Verification badges**: Green checkmark for verified, Yellow warning for detected
- **Evidence panels**: Styled panels for detection evidence, proof of impact, and exploitation results
- **Copy functionality**: One-click copy of payloads
- **Download options**: Export exploitation data

## Data Model Extensions

### SQLInjectionResult Model

Enhanced fields:
- `injection_context` - Type of injection (sql, ldap, xpath, message_queue, custom_query)
- `verified` - Boolean indicating if attack was verified through exploitation
- `proof_of_impact` - Text evidence of real-world impact
- `visual_proof_path` - Path to screenshot/GIF proof
- `visual_proof_type` - Type of visual proof (screenshot, gif, video)
- `visual_proof_size` - File size in bytes

These fields mirror the vulnerability scanner's proof reporting pattern for consistency.

## Attack Workflow

1. **Parameter Discovery** - Identify testable parameters
2. **Context Detection** - Test all enabled injection contexts in parallel
3. **Success Analysis** - Analyze responses for injection indicators
4. **Verification** - Attempt exploitation to verify findings
5. **Proof Collection** - Capture visual and textual proof
6. **Result Storage** - Store in database with full evidence
7. **Dashboard Display** - Present results in organized UI

## Response Analysis

Each context implements custom response analysis:

### SQL Context
- Database error patterns (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Time-based delay detection
- Boolean-based behavior changes

### LDAP Context
- LDAP error messages
- Authentication bypass indicators
- Directory attribute extraction

### XPath Context
- XML parser errors
- XPath syntax errors
- Node extraction success

### Message Queue Context
- Queue system errors (RabbitMQ, Kafka, Redis, ActiveMQ)
- Privilege escalation indicators
- Queue manipulation success

### Custom Query Context
- GraphQL introspection responses
- API error messages
- Schema extraction success

## Extensibility

The framework is designed for easy extension:

### Adding New Contexts

1. Create a new context class in `injection_contexts/`
2. Inherit from `InjectionContext`
3. Implement required methods:
   - `get_context_type()`
   - `_load_payloads()`
   - `_load_detection_patterns()`
   - `analyze_response()`
   - `attempt_exploitation()`
4. Add to `InjectionContextType` enum
5. Register in orchestrator's context classes

Example:
```python
from .base import InjectionContext, InjectionContextType

class NoSQLInjectionContext(InjectionContext):
    def get_context_type(self):
        return InjectionContextType.NOSQL
    
    def _load_payloads(self):
        return [
            '{"$gt": ""}',
            '{"$ne": null}',
            # ... more payloads
        ]
    
    # Implement other required methods...
```

## Security Considerations

⚠️ **Important**: This tool is for authorized security testing only.

- Only test systems you own or have explicit permission to test
- Be aware of rate limiting and blocking
- Some payloads may trigger IDS/IPS alerts
- Visual proof capture may include sensitive data
- Follow responsible disclosure practices

## Performance

- **Parallel Execution**: Tests multiple contexts simultaneously
- **Configurable Workers**: Adjust parallelism with `max_workers`
- **Request Timeout**: Configurable per-context
- **Smart Detection**: Early termination on successful detection

## Best Practices

1. **Start with Specific Contexts**: Enable only relevant contexts based on target technology
2. **Review Results Manually**: Automated detection may have false positives
3. **Verify Exploitation**: Always verify detected vulnerabilities
4. **Collect Visual Proof**: Enable proof capture for documentation
5. **Rate Limiting**: Use delays to avoid overwhelming targets
6. **Log Everything**: Maintain detailed logs for analysis

## Troubleshooting

### No Results Found
- Check target URL accessibility
- Verify parameter names and types
- Review detection patterns (may need customization)
- Enable verbose logging

### False Positives
- Increase confidence threshold
- Review detection evidence manually
- Add custom detection patterns
- Implement baseline comparison

### Performance Issues
- Reduce number of enabled contexts
- Decrease max_workers
- Increase request timeout
- Disable parallel execution for debugging

## Future Enhancements

Planned additions:
- NoSQL injection context (MongoDB, CouchDB, Redis)
- Command injection context
- Template injection context (Jinja2, Twig, etc.)
- Server-Side Request Forgery (SSRF) context
- AI-powered payload generation
- Automated exploit development
- Integration with external tools (Burp Suite, OWASP ZAP)

## References

- OWASP Testing Guide
- SQL Injection Prevention Cheat Sheet
- LDAP Injection Guide
- XPath Injection Tutorial
- GraphQL Security Best Practices

## Contributing

To contribute new injection contexts:
1. Follow the established patterns in existing contexts
2. Include comprehensive payload library
3. Implement robust detection patterns
4. Add unit tests
5. Document usage examples
6. Submit pull request with description

## License

Same as parent project.
