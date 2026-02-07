# Payload Rules Guide

Payload rules enable automatic payload injection into HTTP requests based on URL patterns and injection types. This guide covers creating, managing, and using payload rules in Megido.

## Table of Contents

- [Overview](#overview)
- [Rule Structure](#rule-structure)
- [Injection Types](#injection-types)
- [Creating Rules](#creating-rules)
- [URL Pattern Matching](#url-pattern-matching)
- [App Targeting](#app-targeting)
- [Example Rules](#example-rules)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

Payload rules allow you to:
- Automatically inject payloads into requests matching specific URL patterns
- Test different injection types (headers, parameters, cookies, body)
- Target specific apps or apply rules globally
- Enable/disable rules without deleting them
- Manage rules via Django admin or API

## Rule Structure

Each payload rule consists of:

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Descriptive name for the rule |
| `target_url_pattern` | String | Regex pattern to match URLs |
| `injection_type` | Choice | Where to inject (header, param, cookie, body) |
| `injection_point` | String | Header name, parameter name, etc. |
| `payload_content` | Text | The payload to inject |
| `active` | Boolean | Whether the rule is active |
| `target_apps` | JSON Array | Apps this rule applies to (empty = all) |
| `created_by` | User | User who created the rule |

## Injection Types

### 1. Header Injection

Inject custom HTTP headers into requests.

**Example:**
```json
{
    "injection_type": "header",
    "injection_point": "X-Custom-Header",
    "payload_content": "custom-value"
}
```

**Use Cases:**
- Testing header-based vulnerabilities
- Adding authentication headers
- Bypassing WAF rules
- Testing CORS policies

### 2. URL Parameter Injection

Add or modify URL query parameters.

**Example:**
```json
{
    "injection_type": "param",
    "injection_point": "id",
    "payload_content": "1' OR '1'='1"
}
```

**Use Cases:**
- SQL injection testing
- XSS payload testing
- Parameter pollution attacks
- IDOR testing

### 3. Cookie Injection

Add or modify cookies in requests.

**Example:**
```json
{
    "injection_type": "cookie",
    "injection_point": "session_id",
    "payload_content": "modified-session-value"
}
```

**Use Cases:**
- Session hijacking tests
- Cookie manipulation
- Authentication bypass
- Cookie injection attacks

### 4. Body Injection

Modify request body content.

**Example (JSON):**
```json
{
    "injection_type": "body",
    "injection_point": "username",
    "payload_content": "admin' OR '1'='1"
}
```

**Example (Form Data):**
```json
{
    "injection_type": "body",
    "injection_point": "email",
    "payload_content": "test@example.com<script>alert(1)</script>"
}
```

**Use Cases:**
- Testing POST request vulnerabilities
- JSON injection attacks
- Form data manipulation
- File upload testing

## Creating Rules

### Via Django Admin

1. Navigate to `/admin/interceptor/payloadrule/`
2. Click "Add Payload Rule"
3. Fill in the form:
   - **Name**: "SQL Injection - Login Form"
   - **Target URL Pattern**: `.*login.*`
   - **Injection Type**: "URL Parameter"
   - **Injection Point**: `username`
   - **Payload Content**: `admin' OR '1'='1--`
   - **Active**: ✓ Checked
   - **Created By**: Select user
   - **Target Apps**: `["sql_attacker"]` (or leave empty for all)
4. Save

### Via API

```python
import requests

url = "http://localhost:8000/interceptor/api/payload-rules/"
headers = {"Authorization": "Token YOUR_TOKEN"}

rule_data = {
    "name": "XSS Test - Search Parameter",
    "target_url_pattern": ".*search.*",
    "injection_type": "param",
    "injection_point": "q",
    "payload_content": "<script>alert('XSS')</script>",
    "active": True,
    "target_apps": ["scanner"]
}

response = requests.post(url, json=rule_data, headers=headers)
print(response.json())
```

### Programmatically

```python
from interceptor.models import PayloadRule
from django.contrib.auth.models import User

user = User.objects.first()

rule = PayloadRule.objects.create(
    name="CSRF Token Bypass",
    target_url_pattern=".*api/v1.*",
    injection_type="header",
    injection_point="X-CSRF-Token",
    payload_content="bypassed",
    active=True,
    created_by=user,
    target_apps=["bypasser"]
)
```

## URL Pattern Matching

URL patterns use Python regex. Common patterns:

### Match All URLs
```regex
.*
```

### Match Specific Domain
```regex
https://example\.com/.*
```

### Match Path Pattern
```regex
.*/api/users/.*
```

### Match Query Parameter
```regex
.*\?.*id=.*
```

### Match File Extension
```regex
.*\.php$
```

### Complex Pattern
```regex
^https?://(www\.)?example\.com/(api|admin)/.*
```

## App Targeting

Control which apps can use each rule:

### Apply to All Apps
```json
{
    "target_apps": []
}
```
Empty list = applies to all apps.

### Apply to Specific Apps
```json
{
    "target_apps": ["scanner", "spider", "sql_attacker"]
}
```

### Available Apps
- `browser` - Desktop browser traffic
- `scanner` - Security scanner
- `spider` - Web spider/crawler
- `sql_attacker` - SQL injection tester
- `repeater` - Request repeater
- `mapper` - Application mapper
- `bypasser` - WAF/filter bypass
- `malware_analyser` - Malware analysis
- `response_analyser` - Response analyzer
- `data_tracer` - Data flow tracer
- `discover` - Parameter discovery
- `manipulator` - Request manipulator
- `proxy` - Proxy server
- `collaborator` - OAST collaborator

## Example Rules

### 1. SQL Injection - Union Attack
```json
{
    "name": "SQL - UNION SELECT",
    "target_url_pattern": ".*/api/.*",
    "injection_type": "param",
    "injection_point": "id",
    "payload_content": "1' UNION SELECT NULL, username, password FROM users--",
    "active": true,
    "target_apps": ["sql_attacker"]
}
```

### 2. XSS - Reflected in Search
```json
{
    "name": "XSS - Search Parameter",
    "target_url_pattern": ".*search.*",
    "injection_type": "param",
    "injection_point": "q",
    "payload_content": "\"><script>alert(document.domain)</script>",
    "active": true,
    "target_apps": ["scanner"]
}
```

### 3. Header Injection - User-Agent
```json
{
    "name": "Custom User-Agent",
    "target_url_pattern": ".*",
    "injection_type": "header",
    "injection_point": "User-Agent",
    "payload_content": "MegidoScanner/1.0 (Security Testing)",
    "active": true,
    "target_apps": []
}
```

### 4. Cookie Manipulation
```json
{
    "name": "Admin Cookie Injection",
    "target_url_pattern": ".*/admin/.*",
    "injection_type": "cookie",
    "injection_point": "role",
    "payload_content": "admin",
    "active": true,
    "target_apps": ["bypasser"]
}
```

### 5. JSON Body Injection
```json
{
    "name": "JSON - NoSQL Injection",
    "target_url_pattern": ".*/api/login.*",
    "injection_type": "body",
    "injection_point": "password",
    "payload_content": "{\"$ne\": null}",
    "active": true,
    "target_apps": ["sql_attacker"]
}
```

### 6. SSRF Test
```json
{
    "name": "SSRF - Internal IP",
    "target_url_pattern": ".*/fetch.*",
    "injection_type": "param",
    "injection_point": "url",
    "payload_content": "http://127.0.0.1:8000/admin",
    "active": true,
    "target_apps": ["scanner"]
}
```

## Best Practices

### 1. Use Descriptive Names
- Good: "SQL Injection - Login Username"
- Bad: "Test1"

### 2. Test URL Patterns
Verify patterns match intended URLs:
```python
import re

pattern = ".*login.*"
test_urls = [
    "https://example.com/login",
    "https://example.com/api/login",
    "https://example.com/user/profile"
]

for url in test_urls:
    match = re.search(pattern, url)
    print(f"{url}: {'✓' if match else '✗'}")
```

### 3. Start with Inactive Rules
Create rules as inactive, test them, then activate.

### 4. Use Specific Target Apps
Don't apply all rules to all apps. Target appropriately.

### 5. Clean Up Old Rules
Regularly delete or deactivate unused rules.

### 6. Document Complex Payloads
Use clear names and consider adding comments in documentation.

### 7. Monitor Performance
Too many active rules can slow down traffic processing.

### 8. Test Before Production
Always test rules in a safe environment first.

## Troubleshooting

### Rule Not Applied

**Check:**
1. Rule is `active = True`
2. URL pattern matches target URL
3. `target_apps` includes current app or is empty
4. mitmproxy addon is running and loaded rules
5. Rule cache hasn't expired (wait for cache_ttl)

**Debug:**
```python
from interceptor.models import PayloadRule
import re

# Get active rules
rules = PayloadRule.objects.filter(active=True)

# Test URL matching
test_url = "https://example.com/login"
for rule in rules:
    match = re.search(rule.target_url_pattern, test_url)
    print(f"{rule.name}: {'✓' if match else '✗'}")
```

### Payload Not Working

**Check:**
1. Injection type matches target (e.g., can't inject into URL params on POST body)
2. Injection point exists (e.g., header name is correct)
3. Payload content is properly formatted
4. Target application properly handles the payload

### Performance Issues

**Solutions:**
1. Reduce number of active rules
2. Make URL patterns more specific
3. Increase mitmproxy cache TTL
4. Use target_apps to limit scope

### Regex Pattern Errors

Common mistakes:
- Forgetting to escape special characters: `.` should be `\.`
- Not anchoring: Use `^` for start, `$` for end
- Overly broad: `.*` matches everything

**Test patterns:**
```python
import re

# Good
pattern = r"https://example\.com/api/.*"

# Bad - doesn't escape dot
pattern = r"https://example.com/api/.*"
```

## Advanced Usage

### Dynamic Payloads

For dynamic payloads (e.g., timestamps), use the API to create/update rules:

```python
from datetime import datetime
from interceptor.models import PayloadRule

# Update payload with current timestamp
rule = PayloadRule.objects.get(name="Timestamp Injection")
rule.payload_content = f"test-{datetime.now().timestamp()}"
rule.save()
```

### Chaining Rules

Multiple rules can apply to the same request:

```python
# Rule 1: Add auth header
rule1 = PayloadRule.objects.create(
    name="Auth Header",
    target_url_pattern=".*api.*",
    injection_type="header",
    injection_point="Authorization",
    payload_content="Bearer test-token",
    ...
)

# Rule 2: Add tracking param
rule2 = PayloadRule.objects.create(
    name="Tracking Parameter",
    target_url_pattern=".*api.*",
    injection_type="param",
    injection_point="tracking_id",
    payload_content="test-123",
    ...
)
```

### Conditional Rules

Use Python to conditionally activate rules:

```python
from interceptor.models import PayloadRule

# Activate SQL injection rules only during testing
test_mode = True

sql_rules = PayloadRule.objects.filter(name__contains="SQL")
for rule in sql_rules:
    rule.active = test_mode
    rule.save()
```

## Rule Templates

Save these as starting points:

### Basic Authentication Test
```json
{
    "name": "Auth - Basic Test",
    "target_url_pattern": ".*/api/.*",
    "injection_type": "header",
    "injection_point": "Authorization",
    "payload_content": "Basic YWRtaW46YWRtaW4=",
    "active": false,
    "target_apps": []
}
```

### IDOR Test
```json
{
    "name": "IDOR - User ID",
    "target_url_pattern": ".*/user/.*",
    "injection_type": "param",
    "injection_point": "id",
    "payload_content": "1",
    "active": false,
    "target_apps": ["scanner"]
}
```

### Path Traversal
```json
{
    "name": "Path Traversal",
    "target_url_pattern": ".*/file.*",
    "injection_type": "param",
    "injection_point": "path",
    "payload_content": "../../../../etc/passwd",
    "active": false,
    "target_apps": ["scanner"]
}
```

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## Support

For questions or issues:
- GitHub Issues: https://github.com/tkstanch/Megido/issues
- API Documentation: docs/interceptor_api.md
