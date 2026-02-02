# Custom Bypass Techniques - Advanced Crafting Guide

## Overview

The Custom Bypass Techniques feature allows security professionals to create, test, and reuse their own custom bypass patterns for filters, WAFs, IPS, IDS, and Firewalls. This powerful feature enables you to craft sophisticated multi-layer bypass techniques using template-based transformations.

## Key Features

### 🔧 Technique Crafting
- **Template-based System**: Use variables and transformation functions
- **16+ Built-in Transformations**: URL encoding, HTML entities, Unicode, Base64, and more
- **Chaining Support**: Combine multiple transformations in sequence
- **Variable Substitution**: Use payload, char, target, and param variables

### 📊 Usage Tracking
- **Automatic Statistics**: Track times used and success rate
- **Success Rate Calculation**: Automatically updated after each use
- **Execution History**: Full audit trail of technique usage

### 🔒 Security
- **Template Validation**: Prevents code injection attacks
- **Dangerous Pattern Blocking**: Blocks __import__, eval, exec, etc.
- **Safe Transformations Only**: Only whitelisted transformations allowed
- **Input Sanitization**: All user input is validated

### 🏷️ Organization
- **Categories**: WAF, Firewall, IPS, IDS, Filter, Mixed
- **Tags**: Add custom tags for easy searching
- **Author Tracking**: Record who created each technique
- **Active/Inactive Status**: Enable/disable techniques

## Template Syntax

### Variables

Use double curly braces with variable names:

- `{{payload}}` - The main payload to transform
- `{{char}}` - A single character to test
- `{{target}}` - The target URL
- `{{param}}` - The parameter name being tested

### Transformations

Apply transformations using the pipe (`|`) operator:

```
{{variable|transformation}}
{{variable|transform1|transform2|transform3}}
```

### Available Transformations

#### URL Encoding
- `url_encode` - Single URL encoding (`<` → `%3C`)
- `url_encode_double` - Double URL encoding (`<` → `%253C`)
- `url_encode_triple` - Triple URL encoding (`<` → `%25253C`)

#### HTML Encoding
- `html_decimal` - HTML decimal entities (`<` → `&#60;`)
- `html_hex` - HTML hexadecimal entities (`<` → `&#x3c;`)
- `html5_entity` - HTML5 named entities (`<` → `&lt;`)

#### Character Encoding
- `unicode` - Unicode escape sequences (`<` → `\u003c`)
- `base64` - Base64 encoding
- `hex` - Hexadecimal encoding (`<` → `\x3c`)
- `utf7` - UTF-7 encoding (legacy)

#### Obfuscation
- `upper` - Convert to uppercase
- `lower` - Convert to lowercase
- `reverse` - Reverse the string
- `null_byte` - Append null byte (`test` → `test%00`)
- `html_comment` - Insert HTML comments between chars (`script` → `s<!---->c<!---->r<!---->i<!---->p<!---->t`)
- `sql_comment` - Insert SQL comments between chars (`script` → `s/**/c/**/r/**/i/**/p/**/t`)

## Examples

### Basic Templates

#### Single Transformation
```
{{payload|url_encode}}
```
Input: `<script>`  
Output: `%3Cscript%3E`

#### Chained Transformations
```
{{payload|html_hex|url_encode}}
```
Input: `<script>`  
Output: `%26%23x3c%3Bscript%26%23x3e%3B`

#### Multiple Variables
```
test{{payload|url_encode_double}}value{{char|html_hex}}
```
Input: payload=`<`, char=`>`  
Output: `test%253Cvalue&#x3e;`

### Advanced Techniques

#### WAF Bypass - Triple Encoding Mix
```json
{
  "name": "Triple Encoding WAF Bypass",
  "category": "waf",
  "technique_template": "{{payload|url_encode_triple}}",
  "description": "Bypasses WAFs that only decode twice"
}
```

#### IDS Evasion - Case + Comments
```json
{
  "name": "IDS Evasion - Mixed Case Comments",
  "category": "ids",
  "technique_template": "{{payload|upper|html_comment}}",
  "description": "Uppercase with HTML comment insertion"
}
```

#### Firewall Bypass - Encoding Chain
```json
{
  "name": "Multi-Layer Firewall Bypass",
  "category": "firewall",
  "technique_template": "{{payload|base64|url_encode|html_hex}}",
  "description": "Three-layer encoding: Base64 → URL → HTML"
}
```

#### Filter Bypass - SQL Injection
```json
{
  "name": "SQL Injection Filter Bypass",
  "category": "filter",
  "technique_template": "{{payload|sql_comment}}",
  "description": "Inserts SQL comments between characters"
}
```

## API Usage

### Create a Technique

```bash
curl -X POST http://localhost:8000/bypasser/api/custom-techniques/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Custom Bypass",
    "category": "waf",
    "description": "Combines multiple encoding techniques",
    "technique_template": "{{payload|url_encode_double|html_hex}}",
    "example_input": "<script>alert(1)</script>",
    "tags": "waf,encoding,advanced",
    "author": "Security Team"
  }'
```

Response:
```json
{
  "id": 1,
  "message": "Custom technique created successfully",
  "name": "My Custom Bypass"
}
```

### List All Techniques

```bash
curl http://localhost:8000/bypasser/api/custom-techniques/
```

### Filter by Category

```bash
curl http://localhost:8000/bypasser/api/custom-techniques/?category=waf
```

### Get Technique Details

```bash
curl http://localhost:8000/bypasser/api/custom-techniques/1/
```

### Update a Technique

```bash
curl -X PUT http://localhost:8000/bypasser/api/custom-techniques/1/ \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "is_active": true
  }'
```

### Test a Technique

```bash
curl -X POST http://localhost:8000/bypasser/api/custom-techniques/1/test/ \
  -H "Content-Type: application/json" \
  -d '{"payload": "<script>alert(1)</script>"}'
```

Response:
```json
{
  "technique_name": "My Custom Bypass",
  "technique_template": "{{payload|url_encode_double|html_hex}}",
  "test_payload": "<script>alert(1)</script>",
  "success": true,
  "result": "%2526%2523x3c%253B..."
}
```

### Delete a Technique

```bash
curl -X DELETE http://localhost:8000/bypasser/api/custom-techniques/1/
```

### Use Custom Techniques in a Session

After running character probing and identifying blocked characters:

```bash
curl -X POST http://localhost:8000/bypasser/api/sessions/1/use-custom/
```

Response:
```json
{
  "message": "Custom technique testing completed",
  "techniques_tested": 5,
  "successful_bypasses": 2,
  "results": [
    {
      "technique_id": 1,
      "technique_name": "My Custom Bypass",
      "character": "<",
      "transformed_payload": "%253C...",
      "success": true,
      "reflection_found": true
    }
  ]
}
```

### Get Available Transformations

```bash
curl http://localhost:8000/bypasser/api/transformations/
```

Response includes:
- List of all available transformations with descriptions
- List of all available variables
- Template syntax examples
- Complete usage examples

## Best Practices

### 1. Start Simple
Begin with single transformations and test them before chaining:
```
{{payload|url_encode}}  // Test this first
{{payload|url_encode|html_hex}}  // Then add complexity
```

### 2. Test Thoroughly
Always test your technique with the built-in test function before using it in production:
```bash
curl -X POST /bypasser/api/custom-techniques/1/test/ \
  -d '{"payload": "YOUR_TEST_PAYLOAD"}'
```

### 3. Document Your Techniques
Use descriptive names and detailed descriptions:
```json
{
  "name": "Triple URL + HTML Hex Mix",
  "description": "First applies triple URL encoding, then HTML hex entities. Effective against WAFs that decode twice but don't handle hex entities."
}
```

### 4. Tag Appropriately
Use tags for organization and searching:
```json
{
  "tags": "waf,encoding,url,html,advanced,tested"
}
```

### 5. Track Success Rates
Monitor which techniques work best for your targets. The system automatically tracks:
- `times_used` - How many times the technique has been used
- `times_successful` - How many successful bypasses
- `success_rate` - Percentage of successful attempts

### 6. Build a Library
Create a library of techniques for different scenarios:
- WAF bypasses
- IDS/IPS evasion
- Firewall traversal
- Filter bypasses
- Protocol-specific techniques

## Security Considerations

### What's Protected

✅ **Code Injection Prevention**
- All templates are validated before execution
- Dangerous patterns are blocked
- Only whitelisted transformations are allowed

✅ **Input Validation**
- Variable names must be from approved list
- Transformation names must be from approved list
- No arbitrary code execution

✅ **Safe Execution**
- Templates execute in a sandboxed context
- No access to system functions
- No file system access

### What to Watch For

⚠️ **Authorization**
- Only use on authorized targets
- Document your testing authorization
- Follow responsible disclosure practices

⚠️ **Data Sensitivity**
- Don't include sensitive data in example payloads
- Be careful with author information
- Review techniques before making them public

⚠️ **Rate Limiting**
- Custom techniques test real systems
- Implement delays between tests
- Respect target system resources

## Troubleshooting

### Template Validation Errors

**Error: "Template must contain at least one placeholder"**
```
❌ This is invalid text with no variables
✅ {{payload}}
✅ test{{payload|url_encode}}value
```

**Error: "Invalid variable name"**
```
❌ {{invalid_var|url_encode}}
✅ {{payload|url_encode}}
✅ {{char|url_encode}}
```

**Error: "Unknown transformation function"**
```
❌ {{payload|nonexistent_function}}
✅ {{payload|url_encode}}
✅ {{payload|html_hex}}
```

**Error: "Contains potentially dangerous pattern"**
```
❌ {{payload}}__import__("os")
❌ {{payload}}eval(...)
✅ {{payload|url_encode}}
```

### Execution Errors

**Error: "Transformation failed"**
- Check that your input is compatible with the transformation
- Some transformations only work with specific input types

**No Bypasses Found**
- Try different transformation combinations
- Test with different payloads
- Combine with built-in bypass techniques

## Integration

### With Character Probing
1. Run character probing to identify blocked characters
2. Create custom techniques for those specific characters
3. Test custom techniques against blocked characters
4. Refine techniques based on results

### With Built-in Techniques
- Custom techniques complement built-in techniques
- Use both in the same session
- Custom techniques run after built-in ones
- Statistics are tracked separately

### With Bypass Results
- Successful custom bypasses are recorded
- Includes risk assessment
- Provides remediation recommendations
- Full audit trail maintained

## Example Workflow

```bash
# 1. Create target
curl -X POST /bypasser/api/targets/ -d '{
  "url": "https://target.com/search",
  "http_method": "GET",
  "test_parameter": "q"
}'

# 2. Start character probing
curl -X POST /bypasser/api/targets/1/probe/

# 3. Get results
curl /bypasser/api/sessions/1/results/

# 4. Create custom technique for blocked characters
curl -X POST /bypasser/api/custom-techniques/ -d '{
  "name": "Custom WAF Bypass",
  "category": "waf",
  "technique_template": "{{payload|url_encode_double|html_hex}}"
}'

# 5. Test the technique
curl -X POST /bypasser/api/custom-techniques/1/test/ -d '{
  "payload": "<script>"
}'

# 6. Use in session
curl -X POST /bypasser/api/sessions/1/use-custom/

# 7. Review results
curl /bypasser/api/sessions/1/bypasses/
```

## Advanced Topics

### Creating Technique Libraries

Organize techniques by purpose:

**XSS Bypass Library**
```json
[
  {"name": "XSS - Double URL", "template": "{{payload|url_encode_double}}"},
  {"name": "XSS - HTML Hex", "template": "{{payload|html_hex}}"},
  {"name": "XSS - Mixed Case", "template": "{{payload|upper|html_comment}}"}
]
```

**SQL Injection Library**
```json
[
  {"name": "SQLi - Comment Insertion", "template": "{{payload|sql_comment}}"},
  {"name": "SQLi - Case Variation", "template": "{{payload|upper}}"},
  {"name": "SQLi - Unicode Escape", "template": "{{payload|unicode}}"}
]
```

### Chaining Strategies

**Escalating Complexity**
```
Level 1: {{payload|url_encode}}
Level 2: {{payload|url_encode|html_hex}}
Level 3: {{payload|url_encode|html_hex|base64}}
```

**Multi-Path Encoding**
```
{{payload|url_encode_double}}{{payload|html_hex}}{{payload|unicode}}
```

**Context-Specific**
```
Before: test{{payload|url_encode}}
After: {{payload|html_hex}}end
Both: pre{{payload|base64}}post
```

## Contributing

To add new transformation functions:

1. Add the function to `bypasser/encoding.py`
2. Register it in `TechniqueParser.TRANSFORMATIONS` in `technique_parser.py`
3. Add tests in `tests.py`
4. Update documentation

Example:
```python
# In encoding.py
@staticmethod
def rot13_encode(text: str) -> str:
    """ROT13 encoding"""
    return text.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    ))

# In technique_parser.py
TRANSFORMATIONS = {
    # ... existing transformations ...
    'rot13': EncodingTechniques.rot13_encode,
}
```

## Support

For issues, questions, or feature requests related to custom bypass techniques, please refer to the main Megido documentation or open an issue in the repository.

---

**Remember**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system.
