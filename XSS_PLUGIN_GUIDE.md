# Advanced XSS Exploit Plugin - Professional Guide

## Overview

The Advanced XSS (Cross-Site Scripting) Exploit Plugin is a professional-grade security testing tool designed for automated vulnerability exploitation in professional, SaaS, and red-team scenarios. This plugin provides comprehensive XSS testing capabilities with advanced features for evidence collection, reporting, and stealth operation.

**NEW: Real Impact Evidence Collection** - The plugin now automatically collects and displays real impact evidence after successful exploitation, matching professional bug bounty standards and improving client value.

## Real Impact Evidence Collection (NEW)

When XSS exploitation is successful, the plugin automatically collects comprehensive evidence to prove the **real business and security impact** of the vulnerability, not just payload execution:

### Evidence Automatically Collected

1. **Session Data**
   - **Cookies**: All accessible cookies with security flags (HTTPOnly, Secure, SameSite)
   - **localStorage**: Complete key-value pairs stored in localStorage
   - **sessionStorage**: Complete key-value pairs stored in sessionStorage
   - **Document Domain**: The domain accessible to the JavaScript code

2. **Proof of Execution**
   - **Screenshots**: Visual proof of XSS execution in browser
   - **Console Logs**: JavaScript console messages and errors
   - **HTML DOM Sample**: Page source at injection point
   - **Alert Dialogs**: Text of any triggered alert boxes

3. **Actions Performed**
   - Cookie access detection
   - Non-HTTPOnly cookie identification
   - Sensitive data detection (tokens, credentials, API keys)
   - Storage access tracking
   - DOM manipulation detection

4. **Business Impact Narrative**
   - Automatic generation of security/business impact description
   - Risk assessment based on collected evidence
   - Specific threats identified (session hijacking, credential theft, etc.)
   - Business consequences outlined (compliance, reputation, financial)

### Verified vs Unverified Vulnerabilities

- **VERIFIED** ✓: Marked only when real impact evidence is successfully collected
- **Unverified**: Detection only, no actual exploitation proof

**Important**: Only vulnerabilities with real impact evidence are marked as VERIFIED. This ensures high confidence in findings and reduces false positives.

### Example Real Impact Report

See [real_xss_bug_report_example.md](./real_xss_bug_report_example.md) for a complete example of a professional bug report with real impact evidence.

## Key Features

### 1. Smart Crawling
- **Configurable Depth**: Control how deep the crawler explores the site (default: 2 levels)
- **Form Discovery**: Automatically discovers and tests all forms on crawled pages
- **Link Discovery**: Identifies and follows links within the same domain
- **Maximum Page Limit**: Configurable limit to prevent excessive crawling (default: 50 pages)

### 2. Network Throttling
- **Stealth Operation**: Configurable delays between requests to avoid detection
- **Rate Limiting**: Prevents overwhelming target servers
- **Random Delays**: Optional randomization for more natural traffic patterns

### 3. Session Management
- **Custom Cookies**: Support for authenticated testing with session cookies
- **Custom Headers**: Add custom HTTP headers for specific requirements
- **Proxy Support**: Full proxy configuration support for anonymity
- **SSL Verification**: Configurable SSL/TLS verification for testing environments

### 4. Selenium-Powered DOM Simulation
- **Browser Automation**: Uses real browsers (Chrome/Firefox) for accurate DOM testing
- **Headless Mode**: Run tests without visible browser windows
- **JavaScript Execution**: Tests JavaScript-based XSS vulnerabilities
- **Alert Detection**: Automatically detects XSS-triggered alert dialogs
- **Event Simulation**: Simulates clicks, form submissions, and user interactions

### 5. Browser Fingerprint Randomization
- **User Agent Rotation**: Randomizes user agent strings for each request
- **Automation Detection Bypass**: Disables automation indicators
- **Anti-Fingerprinting**: Makes automated testing harder to detect

### 6. Real Impact Evidence Collection (Enhanced)
- **Screenshots**: Captures screenshots when XSS is triggered
- **Cookies Extraction**: Collects all accessible cookies with security flags
- **localStorage/sessionStorage**: Extracts all browser storage data
- **Document Domain**: Records the document.domain accessible to attacker
- **DOM Context**: Saves HTML context around injection points
- **Console Logs**: Collects JavaScript console logs and errors
- **HTML Samples**: Preserves HTML samples showing reflected payloads
- **Actions Detection**: Identifies what actions were performed (data access, manipulation)
- **Business Impact**: Generates narrative describing security and business consequences
- **Injection Analysis**: Identifies injection context (HTML, attribute, JavaScript, etc.)

### 7. JavaScript Injection Context Analysis
The plugin automatically analyzes where payloads are reflected and identifies:
- **HTML Context**: Direct injection into HTML content
- **Attribute Context**: Injection into HTML attributes
- **JavaScript Context**: Injection within `<script>` tags
- **CSS Context**: Injection within `<style>` tags
- **URL Context**: Injection into href/src attributes

### 8. Enhanced Report Generation with Real Impact Evidence
- **JSON Reports**: Machine-readable format for automation and SaaS integration
- **HTML Reports**: Human-readable format with visual presentation and screenshots
- **Markdown Reports**: Professional bug bounty style reports (NEW)
- **All Formats**: Generate JSON, HTML, and Markdown simultaneously with `output_format: 'all'`
- **Verified Badge**: Visual indicator for vulnerabilities with real impact proof
- **Detailed Findings**: Each finding includes URL, parameter, payload, context, and evidence
- **Real Impact Display**: Shows extracted cookies, storage data, actions, and screenshots
- **Business Impact Section**: Narrative explaining security and business consequences
- **Severity Classification**: Automatically classifies findings by severity (high/medium/low)
- **Remediation Advice**: Includes comprehensive remediation guidance

### 9. Configurable Scan Parameters
Extensive configuration options for customizing scan behavior:
- Crawl depth and page limits
- Network throttling settings
- Browser configuration
- Evidence collection preferences
- Output format and location
- Timeout settings
- And more...

### 10. Extensible Architecture
- **Modular Design**: Easy to extend with new features
- **Plugin Interface**: Follows standard exploit plugin interface
- **Custom Payloads**: Support for adding custom XSS payloads
- **Payload Encoding**: Built-in encoding support (URL, HTML, Base64, Unicode)

## Installation

### Dependencies

Add the following dependencies to your `requirements.txt`:

```txt
selenium>=4.15.0
webdriver-manager>=4.0.1
fake-useragent>=1.4.0
Pillow>=10.0.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Browser Drivers

For Selenium to work, you need browser drivers:

#### Chrome (Recommended)
```bash
# ChromeDriver is automatically managed by webdriver-manager
# No manual installation needed
```

#### Firefox
```bash
# GeckoDriver installation (if using Firefox)
# Linux:
wget https://github.com/mozilla/geckodriver/releases/latest/download/geckodriver-linux64.tar.gz
tar -xvzf geckodriver-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/

# macOS:
brew install geckodriver

# Windows:
# Download from https://github.com/mozilla/geckodriver/releases
```

## Usage

### Basic Usage

```python
from scanner.plugins import get_registry

# Get the plugin registry
registry = get_registry()

# Get the XSS plugin
xss_plugin = registry.get_plugin('xss')

# Execute attack against a target
result = xss_plugin.execute_attack(
    target_url='http://example.com/search',
    vulnerability_data={
        'parameter': 'q',
        'method': 'GET',
    },
    config={
        'crawl_depth': 2,
        'enable_dom_testing': True,
    }
)

# Check results
if result['success']:
    print(f"Found {len(result['findings'])} vulnerabilities")
    for finding in result['findings']:
        print(f"  - {finding['type']} XSS in parameter: {finding['parameter']}")
```

### Advanced Configuration

```python
# Advanced configuration example
config = {
    # Crawling Configuration
    'enable_crawler': True,
    'crawl_depth': 3,
    'max_pages': 100,
    
    # Network Configuration
    'network_throttle': 1.0,  # 1 second delay between requests
    'timeout': 30,
    'verify_ssl': False,
    
    # Proxy Configuration
    'proxy': {
        'http': 'http://proxy.example.com:8080',
        'https': 'https://proxy.example.com:8080',
    },
    
    # Session Configuration
    'custom_headers': {
        'Authorization': 'Bearer token123',
        'X-Custom-Header': 'value',
    },
    'custom_cookies': {
        'session': 'abc123',
        'auth_token': 'xyz789',
    },
    
    # Browser Configuration
    'enable_dom_testing': True,
    'browser_type': 'chrome',  # or 'firefox'
    'headless': True,
    'randomize_fingerprint': True,
    
    # Evidence Collection
    'collect_evidence': True,
    
    # Report Configuration
    'output_format': 'both',  # 'json', 'html', or 'both'
    'output_dir': './xss_reports',
}

result = xss_plugin.execute_attack(
    target_url='http://example.com',
    vulnerability_data={},
    config=config
)
```

### Testing Specific Parameters

```python
# Test a specific GET parameter
result = xss_plugin.execute_attack(
    target_url='http://example.com/page',
    vulnerability_data={
        'parameter': 'user_input',
        'method': 'GET',
        'params': {'user_input': 'test'},
    },
    config={'enable_crawler': False}
)
```

```python
# Test a specific POST parameter
result = xss_plugin.execute_attack(
    target_url='http://example.com/submit',
    vulnerability_data={
        'parameter': 'comment',
        'method': 'POST',
        'data': {
            'comment': 'test comment',
            'author': 'test user',
        },
    },
    config={'enable_crawler': False}
)
```

### Generating Custom Payloads

```python
# Generate basic payloads
payloads = xss_plugin.generate_payloads({'payload_type': 'basic'})

# Generate attribute-based payloads
payloads = xss_plugin.generate_payloads({'payload_type': 'attribute'})

# Generate all payload types
payloads = xss_plugin.generate_payloads({'payload_type': 'all'})

# Generate encoded payloads
payloads = xss_plugin.generate_payloads({
    'payload_type': 'basic',
    'encoding': 'url'
})

# Add custom payloads
payloads = xss_plugin.generate_payloads({
    'payload_type': 'basic',
    'custom_payloads': [
        '<custom>payload</custom>',
        'javascript:customAlert(1)',
    ]
})
```

## Configuration Options

### Crawling Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_crawler` | bool | True | Enable smart crawling |
| `crawl_depth` | int | 2 | Maximum crawl depth |
| `max_pages` | int | 50 | Maximum pages to crawl |

### Network Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `network_throttle` | float | 0.5 | Delay between requests (seconds) |
| `timeout` | int | 30 | Request timeout (seconds) |
| `verify_ssl` | bool | False | Verify SSL certificates |
| `proxy` | dict | None | Proxy configuration |
| `custom_headers` | dict | {} | Custom HTTP headers |
| `custom_cookies` | dict | {} | Custom cookies |

### Browser Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_dom_testing` | bool | True | Enable Selenium DOM testing |
| `browser_type` | str | 'chrome' | Browser type ('chrome' or 'firefox') |
| `headless` | bool | True | Run browser in headless mode |
| `randomize_fingerprint` | bool | True | Randomize browser fingerprint |

### Evidence Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `collect_evidence` | bool | True | Collect screenshots and DOM evidence |

### Report Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output_format` | str | 'json' | Output format: 'json', 'html', 'markdown' (or 'md'), 'both', or 'all' |
| `output_dir` | str | './xss_reports' | Output directory for reports |

**Note**: Use `'all'` to generate JSON, HTML, and Markdown reports simultaneously.

## Payload Types

The plugin supports multiple payload types for different injection contexts:

### Basic Payloads
- Standard `<script>alert(1)</script>`
- Image-based: `<img src=x onerror=alert(1)>`
- SVG-based: `<svg/onload=alert(1)>`
- IFrame-based: `<iframe src="javascript:alert(1)">`

### Attribute Payloads
- Event handler injection: `" onmouseover="alert(1)`
- Breaking out of attributes: `"><script>alert(1)</script>`

### JavaScript Context Payloads
- String escape: `'-alert(1)-'`
- Script tag injection: `</script><script>alert(1)</script>`

### DOM Payloads
- Hash-based: `#"><script>alert(1)</script>`
- JavaScript protocol: `javascript:alert(1)`
- Data URI: `data:text/html,<script>alert(1)</script>`

### Advanced Payloads
- Details element: `<details open ontoggle=alert(1)>`
- Marquee element: `<marquee onstart=alert(1)>`
- Input autofocus: `<input onfocus=alert(1) autofocus>`

## Report Structure

### JSON Report Format (Enhanced with Real Impact Evidence)

```json
{
  "scan_info": {
    "target_url": "http://example.com",
    "timestamp": "2024-02-12T22:00:00Z",
    "scanner": "Advanced XSS Exploit Plugin",
    "version": "1.0.0"
  },
  "summary": {
    "total_vulnerabilities": 3,
    "severity_breakdown": {
      "high": 2,
      "medium": 1,
      "low": 0
    },
    "vulnerability_types": ["reflected", "dom"]
  },
  "findings": [
    {
      "type": "dom",
      "url": "http://example.com/search",
      "parameter": "q",
      "method": "GET",
      "payload": "<script>alert(document.cookie)</script>",
      "context": "dom",
      "evidence": "XSS triggered alert dialog: [cookies content]",
      "severity": "high",
      "timestamp": "2024-02-12T22:00:15Z",
      "verified": true,
      "proof_of_impact": "Evidence: JavaScript successfully executed...\n\nExtracted Data:\n- Cookies: 3 accessible\n- localStorage: 5 items\n...",
      "business_impact": "**IMPACT LEVEL: CRITICAL**\n\n**Session Hijacking Risk:**...",
      "evidence_data": {
        "cookies": {
          "session": {
            "value": "abc123...",
            "httpOnly": false,
            "secure": true,
            "sameSite": "None"
          }
        },
        "local_storage": {
          "auth_token": "eyJhbG...",
          "user_data": "{...}"
        },
        "session_storage": {
          "csrf_token": "xyz789"
        },
        "document_domain": "example.com",
        "actions_performed": [
          "Cookies accessed",
          "Non-HTTPOnly cookies exposed: session",
          "localStorage accessed (5 items)",
          "Sensitive data in localStorage: auth_token, user_data"
        ],
        "console_logs": [
          "[XSS] Exploitation successful",
          "[XSS] Data exfiltrated"
        ],
        "screenshot": "iVBORw0KGgoAAAANSUhEUgAAAA...",
        "html_sample": "<!DOCTYPE html><html>...",
        "current_url": "http://example.com/search?q=...",
        "page_title": "Search Results"
      }
    }
  ]
}
```

### HTML Report (Enhanced with Real Impact Evidence)

The HTML report includes:
- Header with scan information and timestamp
- Summary section with:
  - Total vulnerabilities found
  - **Verified count** (vulnerabilities with real impact proof)
  - Severity breakdown (high/medium/low)
- Detailed findings with:
  - **✓ VERIFIED badge** for exploited vulnerabilities
  - Vulnerability type (Reflected/DOM XSS)
  - Affected URL and parameter
  - HTTP method
  - Injection context
  - Payload used
  - Evidence collected
  - **Proof of Impact section** (for verified findings):
    - Alert dialog text
    - Extracted data summary
    - Actions performed
    - Business impact narrative
  - **Extracted Data section**:
    - Cookies with security flags (HTTPOnly, Secure, SameSite)
    - localStorage items
    - sessionStorage items
    - Document domain
    - Actions performed
    - Console logs
    - **Screenshot** of exploitation (embedded as base64 image)
  - **Business/Security Impact section**:
    - Impact level (Critical/High/Medium/Low)
    - Security risks identified
    - Business consequences
    - Attack scenarios
  - Severity level
- Remediation advice section

### Markdown Report (NEW)

The Markdown report provides a professional bug bounty style format:
- Complete vulnerability summary with verified count
- Each finding includes:
  - Verified badge for real impact
  - Complete technical details
  - Proof of impact section
  - Extracted data with formatting
  - Business impact narrative
  - Code blocks for payloads and logs
- Professional formatting for bug bounty submissions
- Easy to read and share with security teams
  - HTTP method
  - Injection context
  - Payload used
  - Evidence collected
  - Severity level
- Remediation advice section

## Security Best Practices

### 1. Authorization
**Always obtain explicit written permission** before testing any system you don't own.

### 2. Scope Management
- Stay within the defined scope
- Respect robots.txt and security.txt
- Avoid testing production systems during business hours

### 3. Rate Limiting
- Use network throttling to avoid overwhelming target servers
- Monitor for rate limiting responses
- Adjust crawl depth and page limits appropriately

### 4. Data Handling
- Don't exfiltrate sensitive data
- Store evidence securely
- Delete evidence after testing is complete

### 5. Legal Compliance
- Comply with all applicable laws and regulations
- Maintain proper documentation
- Follow responsible disclosure practices

## Troubleshooting

### Selenium Not Available

If you see "Selenium not available" warning:

```bash
pip install selenium webdriver-manager
```

### Browser Driver Issues

If browser tests fail:

```python
# Try Firefox instead of Chrome
config = {'browser_type': 'firefox'}
```

### Network Errors

If experiencing connection issues:

```python
# Increase timeout and disable SSL verification
config = {
    'timeout': 60,
    'verify_ssl': False,
    'network_throttle': 2.0,
}
```

### Crawling Issues

If crawler is not finding pages:

```python
# Increase crawl depth and page limit
config = {
    'crawl_depth': 3,
    'max_pages': 100,
}
```

## Integration with SaaS Platforms

The plugin is designed for easy integration with SaaS security scanning platforms:

### API Integration Example

```python
def scan_target(target_url: str, api_key: str) -> dict:
    """Scan target and return results for API."""
    registry = get_registry()
    xss_plugin = registry.get_plugin('xss')
    
    result = xss_plugin.execute_attack(
        target_url=target_url,
        vulnerability_data={},
        config={
            'output_format': 'json',
            'custom_headers': {'X-API-Key': api_key},
        }
    )
    
    return {
        'status': 'completed',
        'vulnerabilities_found': result['success'],
        'findings_count': len(result['findings']),
        'report_path': result['report_path'],
        'data': result['data'],
    }
```

### Webhook Integration

```python
import requests

def scan_and_notify(target_url: str, webhook_url: str):
    """Scan and send results to webhook."""
    registry = get_registry()
    xss_plugin = registry.get_plugin('xss')
    
    result = xss_plugin.execute_attack(
        target_url=target_url,
        vulnerability_data={},
        config={'output_format': 'json'}
    )
    
    # Send results to webhook
    requests.post(webhook_url, json={
        'target': target_url,
        'success': result['success'],
        'findings': result['findings'],
    })
```

## Performance Considerations

### Memory Usage
- The plugin stores visited URLs and discovered forms in memory
- For large sites, limit `max_pages` to prevent excessive memory usage
- Evidence collection (screenshots) can consume significant memory

### Scan Duration
- Crawling and DOM testing can be time-consuming
- Use `network_throttle` to balance speed and stealth
- Disable DOM testing if only reflected XSS is needed
- Limit payload count for faster scanning

### Optimization Tips

```python
# Fast scan (reflected XSS only)
config = {
    'enable_crawler': False,
    'enable_dom_testing': False,
    'network_throttle': 0.1,
}

# Thorough scan (all features)
config = {
    'enable_crawler': True,
    'crawl_depth': 3,
    'enable_dom_testing': True,
    'collect_evidence': True,
}

# Balanced scan
config = {
    'enable_crawler': True,
    'crawl_depth': 2,
    'max_pages': 30,
    'enable_dom_testing': True,
    'collect_evidence': False,  # Skip evidence for speed
}
```

## Remediation Advice

The plugin provides comprehensive remediation advice for XSS vulnerabilities:

1. **Input Validation**: Validate all user inputs on the server side
2. **Output Encoding**: Always encode output before rendering in HTML
3. **Content Security Policy (CSP)**: Implement strict CSP headers
4. **HTTPOnly Cookies**: Set HTTPOnly flag on sensitive cookies
5. **Framework Security**: Use framework security features and auto-escaping
6. **DOM Security**: Avoid dangerous JavaScript functions
7. **WAF Deployment**: Deploy Web Application Firewall
8. **Security Headers**: Implement security headers
9. **Regular Testing**: Perform regular security assessments

For detailed remediation advice, see the full output from:

```python
print(xss_plugin.get_remediation_advice())
```

## Support

For issues, questions, or contributions, please refer to the main Megido repository.

## License

The Advanced XSS Exploit Plugin is part of the Megido Security Testing Platform.

---

**Note**: This plugin is for authorized security testing only. Unauthorized testing of systems you don't own is illegal and unethical.
