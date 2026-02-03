# Response Analyser

A Django app for automatically analyzing HTTP responses from attack routines, collecting positive vulnerability results, and storing detailed evidence for inspection.

## Overview

Response Analyser integrates with Megido's attack workflows to automatically detect, record, and categorize security vulnerabilities. It captures full HTTP request/response details including HTML evidence, which can be inspected in a sandboxed environment similar to browser developer tools.

## Features

- **Automatic Vulnerability Detection**: Helper functions to detect XSS, SQL injection, command injection, and more
- **Comprehensive Evidence Storage**: Stores full request/response details including headers, body, and HTML
- **Django Admin Integration**: Rich admin interface with filtering, searching, and HTML preview
- **User-Friendly UI**: Dashboard and list views for vulnerability management
- **Sandboxed HTML Viewing**: Safely inspect captured HTML responses in sandboxed iframes
- **Grouping and Analytics**: Group vulnerabilities by attack type, endpoint, and payload
- **Severity Classification**: Categorize findings by severity (critical, high, medium, low, info)

## Installation

The app is already integrated into the Megido project. After merging this PR:

1. **Run migrations** to create the database tables:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

2. **Access the app**:
   - Dashboard: http://localhost:8000/response-analyser/
   - Vulnerability List: http://localhost:8000/response-analyser/vulnerabilities/
   - Admin Panel: http://localhost:8000/admin/response_analyser/vulnerability/

## Usage

### Integrating with Attack Logic

Import the analysis functions in your attack code:

```python
from response_analyser.analyse import (
    analyze_xss_response,
    analyze_sqli_response,
    analyze_command_injection_response,
    save_vulnerability
)
```

### Example: XSS Detection

```python
import requests
from response_analyser.analyse import analyze_xss_response

# Make an attack request
target_url = "https://example.com/search"
payload = "<script>alert('XSS')</script>"

response = requests.get(target_url, params={'q': payload})

# Analyze the response
vuln = analyze_xss_response(
    target_url=target_url,
    payload=payload,
    response=response,
    request_method='GET',
    request_params={'q': payload},
    notes='Reflected XSS in search parameter'
)

if vuln:
    print(f"[+] XSS vulnerability detected and saved (ID: {vuln.id})")
else:
    print("[-] No XSS detected")
```

### Example: SQL Injection Detection

```python
from response_analyser.analyse import analyze_sqli_response

# Test for SQL injection
payload = "' OR '1'='1"
response = requests.get(target_url, params={'id': payload})

# Baseline response for comparison
baseline_response = requests.get(target_url, params={'id': '1'})

vuln = analyze_sqli_response(
    target_url=target_url,
    payload=payload,
    response=response,
    baseline_response=baseline_response,
    request_method='GET',
    request_params={'id': payload}
)
```

### Example: Custom Vulnerability Recording

```python
from response_analyser.analyse import save_vulnerability

# When you've confirmed a vulnerability through custom logic
response = requests.post(target_url, data=exploit_data)

vuln = save_vulnerability(
    attack_type='csrf',  # See Vulnerability.ATTACK_TYPES for options
    target_url=target_url,
    payload=str(exploit_data),
    response=response,
    severity='high',
    request_method='POST',
    request_params=exploit_data,
    notes='CSRF token not validated on sensitive action'
)
```

## Model Fields

The `Vulnerability` model stores:

- **attack_type**: Type of vulnerability (XSS, SQLi, CSRF, etc.)
- **severity**: Critical, High, Medium, Low, or Informational
- **target_url**: The URL where the vulnerability was found
- **payload**: The payload that triggered the vulnerability
- **request_method**: HTTP method (GET, POST, etc.)
- **request_headers**: Request headers (JSON format)
- **request_body**: Request body/parameters
- **response_status_code**: HTTP status code
- **response_headers**: Response headers (JSON format)
- **response_body**: Response body text
- **evidence_html**: Full HTML response for iframe inspection
- **endpoint**: Normalized endpoint path for grouping
- **detected_at**: Timestamp of detection
- **notes**: Additional analysis notes
- **is_confirmed**: Manual confirmation flag
- **false_positive**: False positive flag

## Admin Interface

The Django admin provides:

1. **Filtering**: By attack type, severity, confirmation status, date
2. **Search**: Search across URLs, payloads, endpoints, and notes
3. **HTML Preview**: View captured HTML in sandboxed iframes
4. **Bulk Actions**: Mark multiple vulnerabilities as confirmed or false positive
5. **Date Hierarchy**: Navigate vulnerabilities by detection date

## Security Considerations

- **Sandboxed Iframes**: All HTML evidence is displayed in fully sandboxed iframes with no JavaScript execution
- **CSP Headers**: Content Security Policy headers prevent script execution
- **XFrame Protection**: Appropriate headers to prevent clickjacking
- **No Inline Execution**: Raw HTML is never executed outside of sandboxed contexts

## API Reference

### Analysis Functions

#### `analyze_xss_response(target_url, payload, response, ...)`
Detects reflected XSS by checking if payload appears in response without encoding.

#### `analyze_sqli_response(target_url, payload, response, baseline_response=None, ...)`
Detects SQL injection via error messages or response behavior changes.

#### `analyze_command_injection_response(target_url, payload, response, ...)`
Detects command injection by looking for command output indicators.

#### `save_vulnerability(attack_type, target_url, payload, response, ...)`
Generic function to save any vulnerability finding.

#### `extract_endpoint(url)`
Normalizes URLs to endpoints for grouping (e.g., `/api/users/123` → `/api/users/{id}`).

## Views

- **dashboard**: Overview with statistics and recent vulnerabilities
- **vulnerability_list**: Filterable list of all vulnerabilities
- **vulnerability_detail**: Detailed view of a specific vulnerability
- **render_evidence_html**: Serves raw HTML evidence with security headers

## URL Routes

- `/` - Dashboard
- `/vulnerabilities/` - List view
- `/vulnerabilities/<id>/` - Detail view
- `/vulnerabilities/<id>/html/` - Raw HTML evidence

## Tips

1. **False Positives**: Use the admin interface to mark false positives
2. **Confirmation**: Review and confirm real vulnerabilities in the admin
3. **Grouping**: Use the endpoint field to group similar vulnerabilities
4. **Performance**: For large datasets, use admin filters to narrow results
5. **Integration**: Call analysis functions after every attack request for automatic recording

## Future Enhancements

Potential improvements:
- Export functionality (CSV, JSON, PDF reports)
- Integration with issue trackers (Jira, GitHub Issues)
- Automated severity assessment
- Duplicate detection and grouping
- Timeline visualization
- Attack replay functionality

## Support

For issues or questions:
1. Check the Django admin logs
2. Review the model definitions in `models.py`
3. Examine the analysis logic in `analyse.py`
4. Consult the main Megido documentation

## License

Part of the Megido security testing platform.
