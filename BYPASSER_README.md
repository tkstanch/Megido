# Bypasser - Character Probing & Filter Bypass Testing Tool

## Overview

The Bypasser module is a comprehensive security testing tool designed to identify input filtering weaknesses in web applications. It probes for special character restrictions and tests various encoding techniques to discover potential bypass methods.

## ⚠️ Security Notice

**IMPORTANT:** This tool is designed for authorized security testing only. Users must have explicit written permission from the target application owner before conducting any tests. Unauthorized testing may be illegal in your jurisdiction.

## Features

### 1. Character Probing
- Tests **35+ special characters** commonly blocked by WAFs and input filters
- Detects blocked vs. allowed characters
- Identifies WAF/filter behavior patterns
- Tracks HTTP status codes and response characteristics
- Supports both GET and POST methods

### 2. Encoding Bypass Techniques

The tool implements **15+ encoding methods** to test bypass capabilities:

- **URL Encoding**
  - Single encoding (`%3C`)
  - Double encoding (`%253C`)
  - Triple encoding (`%25253C`)

- **HTML Entity Encoding**
  - Decimal entities (`&#60;`)
  - Hexadecimal entities (`&#x3c;`)
  - HTML5 named entities (`&lt;`)

- **Unicode & Character Encoding**
  - Unicode escape sequences (`\u003c`)
  - Hexadecimal encoding (`\x3c`)
  - Base64 encoding
  - UTF-7 encoding
  - UTF-8 overlong encoding

- **Obfuscation Techniques**
  - Mixed case variations
  - Character concatenation (JavaScript style)
  - Null byte injection (`%00`)
  - HTML comment insertion (`<!---->`between characters)
  - SQL comment insertion (`/**/` between characters)

### 3. WAF Detection

Automatically detects Web Application Firewall blocking through:
- HTTP status code analysis (403, 406, 418, 429, 500, etc.)
- Response content analysis
- Common WAF indicator keywords detection
- Response length comparison

### 4. Interactive Dashboard

A user-friendly web interface with:
- **Overview Tab**: Session statistics and all tested characters
- **Blocked Characters Tab**: Characters blocked by the filter
- **Allowed Characters Tab**: Characters that passed through
- **Bypass Techniques Tab**: Successful encoding bypasses with risk assessment

## Installation

The Bypasser app is already integrated into the Megido security toolkit. No additional installation required.

## Usage

### Via Web Interface

1. Navigate to `/bypasser/` in your browser
2. Enter the target URL (e.g., `https://example.com/search`)
3. Select HTTP method (GET or POST)
4. Specify the parameter name to test (e.g., `q`, `search`, `query`)
5. Click "Start Probing"
6. Review results in the tabbed interface
7. For blocked characters, click "Test Encoding Bypasses" to attempt bypasses

### Via API

#### Create a Target
```bash
curl -X POST http://localhost:8000/bypasser/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/search",
    "name": "Example Search",
    "http_method": "GET",
    "test_parameter": "q"
  }'
```

#### Start Character Probing
```bash
curl -X POST http://localhost:8000/bypasser/api/targets/1/probe/
```

#### Get Session Results
```bash
curl http://localhost:8000/bypasser/api/sessions/1/results/
```

#### Test Encoding Bypasses
```bash
curl -X POST http://localhost:8000/bypasser/api/sessions/1/test-bypass/
```

#### Get Bypass Results
```bash
curl http://localhost:8000/bypasser/api/sessions/1/bypasses/
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/bypasser/api/targets/` | List all targets |
| POST | `/bypasser/api/targets/` | Create new target |
| POST | `/bypasser/api/targets/<id>/probe/` | Start character probing |
| GET | `/bypasser/api/sessions/<id>/results/` | Get probing results |
| POST | `/bypasser/api/sessions/<id>/test-bypass/` | Test encoding bypasses |
| GET | `/bypasser/api/sessions/<id>/bypasses/` | Get successful bypasses |

## Configuration

### Environment Variables

- `MEGIDO_VERIFY_SSL` - Set to `True` to verify SSL certificates (default: `False`)
- `MEGIDO_ALLOW_INTERNAL_TESTING` - Set to `True` to allow testing of internal/private networks (default: `False`)

### SSL Certificate Verification

By default, SSL certificate verification is disabled for security testing purposes. To enable:

```bash
export MEGIDO_VERIFY_SSL=True
```

### Internal Network Testing

By default, testing internal/private networks is blocked to prevent SSRF attacks. To enable for controlled testing:

```bash
export MEGIDO_ALLOW_INTERNAL_TESTING=True
```

**Warning:** Only enable this in controlled environments where SSRF testing is authorized.

## Security Features

### SSRF Prevention

The tool includes built-in protection against Server-Side Request Forgery (SSRF):

- Blocks testing of `localhost` and `127.0.0.1`
- Blocks private network ranges:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- Blocks link-local addresses (`169.254.0.0/16`)
- Blocks cloud metadata endpoints
- Only allows HTTP and HTTPS protocols

These protections help prevent accidental testing of internal infrastructure but can be overridden when necessary with proper authorization.

## Character Sets

The tool tests various character sets relevant to different attack vectors:

### Common Special Characters (35+)
`< > " ' & / \ ( ) ; : | \` $ % ! ? = + - * ^ ~ [ ] { } # @ , . \n \r \t` and space

### XSS Characters
Characters commonly used in Cross-Site Scripting attacks

### SQL Injection Characters
Characters commonly used in SQL injection attacks

### Command Injection Characters
Characters commonly used in OS command injection

## Results Interpretation

### Character Status

- **Allowed (Green)**: Character passed through without being blocked
- **Blocked (Red)**: Character was blocked by the filter/WAF
- **Error (Yellow)**: Error occurred during testing
- **Uncertain**: Unable to determine if blocked or allowed

### Bypass Risk Levels

- **Critical**: Bypass allows execution of malicious code
- **High**: Bypass significantly weakens security controls
- **Medium**: Bypass may enable certain attacks
- **Low**: Minor bypass with limited impact
- **Info**: Informational finding

## Examples

### Example 1: Testing a Search Function

Target: `https://example.com/search?q=test`

Results:
- Characters blocked: `<`, `>`, `'`, `"`
- Successful bypass: URL double encoding of `<` as `%253C`
- Risk: High - XSS filter can be bypassed

### Example 2: Testing a Form Parameter

Target: `https://example.com/contact` (POST method)
Parameter: `message`

Results:
- Characters blocked: `<script>`, `javascript:`
- Successful bypass: HTML entity encoding `&#60;script&#62;`
- Risk: High - Script injection possible

## Best Practices

1. **Always get authorization** before testing any application
2. **Document your findings** thoroughly
3. **Test in non-production environments** when possible
4. **Rate limit your tests** to avoid overwhelming the target
5. **Use responsible disclosure** when reporting vulnerabilities
6. **Follow local laws** regarding security testing

## Troubleshooting

### Error: "Testing internal/private networks is not allowed"

This is a security feature. If you need to test internal applications:
1. Ensure you have proper authorization
2. Set `MEGIDO_ALLOW_INTERNAL_TESTING=True`
3. Use only in controlled environments

### Error: "SSL Certificate Verification Failed"

For self-signed certificates or testing environments:
```bash
export MEGIDO_VERIFY_SSL=False
```

### No Blocked Characters Found

This could mean:
- The application has no input filtering
- The filter operates on a different layer
- The test parameter is not being validated

Try:
- Testing different parameters
- Using different HTTP methods
- Testing with longer payloads

## Contributing

To add new encoding techniques:

1. Add the encoding method to `bypasser/encoding.py`
2. Add it to the `ENCODING_TYPE_CHOICES` in `models.py`
3. Update `get_all_encodings()` to include the new technique
4. Add tests in `tests.py`

## License

Part of the Megido Security Testing Toolkit.

## Support

For issues or questions, please refer to the main Megido documentation.

---

**Remember:** With great power comes great responsibility. Use this tool ethically and legally.
