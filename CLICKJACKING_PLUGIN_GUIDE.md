# Clickjacking Exploit Plugin Guide

## Overview

The Clickjacking Exploit Plugin is an advanced, production-quality plugin for Megido's vulnerability scanning system that provides comprehensive clickjacking detection and exploitation capabilities. This plugin automates the detection of clickjacking vulnerabilities through security header analysis and browser-based frameability testing, generates interactive HTML proof-of-concept payloads, and provides detailed remediation guidance.

## Features

### Core Capabilities

1. **HTML Proof-of-Concept Generation**
   - Interactive overlay attack demonstrations
   - Multiple overlay styles (transparent, opaque, partial)
   - Customizable appearance and behavior
   - Ready-to-deploy attack scenarios

2. **Automated Frameability Detection**
   - Security header analysis (X-Frame-Options, CSP frame-ancestors)
   - Headless browser testing with Selenium/WebDriver
   - Support for Chrome and Firefox browsers
   - Intelligent fallback to header-only analysis

3. **Evidence Collection**
   - Screenshot capture with automatic annotation
   - Detailed header analysis reports
   - Browser test results and logs
   - HTML PoC file generation

4. **Advanced Configuration**
   - Overlay appearance customization
   - Test mode for quick assessment
   - Browser type selection
   - Headless/headed operation
   - Evidence collection control

5. **Professional Quality**
   - Comprehensive error handling
   - Resource cleanup (browser sessions, temp files)
   - Type annotations and documentation
   - Detailed logging for debugging
   - Security best practices

## Installation

The clickjacking plugin is automatically discovered when the Megido plugin system loads. Ensure all dependencies are installed:

```bash
pip install selenium webdriver-manager Pillow requests
```

## Quick Start

### Basic Usage

```python
from scanner.plugins import get_registry

# Get the plugin registry
registry = get_registry()

# Get the clickjacking plugin
clickjacking_plugin = registry.get_plugin('clickjacking')

# Test a target URL
result = clickjacking_plugin.execute_attack(
    target_url='http://example.com',
    vulnerability_data={'action_description': 'user login'},
    config={'test_mode': False, 'browser_type': 'chrome'}
)

# Check results
if result['vulnerable']:
    print(f"Vulnerability found! Severity: {result['severity']}")
    print(f"PoC saved to: {result['data']['poc_path']}")
    print(f"Evidence: {result['evidence']}")
else:
    print("No clickjacking vulnerability detected")
```

### Generating Payloads

```python
# Generate HTML PoC payloads
payloads = clickjacking_plugin.generate_payloads({
    'target_url': 'http://example.com/transfer',
    'overlay_style': 'transparent',
    'overlay_text': 'Claim Your Prize',
    'overlay_opacity': 0.3,
    'action_description': 'money transfer'
})

# Save payload to file
with open('clickjacking_poc.html', 'w') as f:
    f.write(payloads[0])
```

## Configuration Options

The plugin supports extensive configuration through the `config` parameter:

### Overlay Appearance

- **overlay_style**: Style of the overlay
  - `'transparent'`: Semi-transparent overlay showing both decoy and target (default)
  - `'opaque'`: Fully opaque decoy page with hidden iframe
  - `'partial'`: Partial overlay with gradient effect

- **overlay_text**: Custom text for the overlay button (default: 'Click here to continue')

- **overlay_opacity**: Opacity level for the iframe
  - Range: 0.0 (invisible) to 1.0 (fully visible)
  - Default: 0.3
  - Used with transparent and partial styles

### Testing Options

- **test_mode**: Skip browser testing, use header analysis only
  - `True`: Fast assessment using only HTTP headers
  - `False`: Full browser-based frameability test (default)

- **browser_type**: Browser to use for testing
  - `'chrome'`: Google Chrome (default)
  - `'firefox'`: Mozilla Firefox

- **headless**: Run browser in headless mode
  - `True`: No visible browser window (default)
  - `False`: Show browser window (useful for debugging)

- **timeout**: Browser operation timeout in seconds (default: 30)

### Evidence Collection

- **collect_evidence**: Capture screenshots and save reports
  - `True`: Save all evidence (default)
  - `False`: Run test without saving files

- **output_dir**: Directory for evidence and reports (default: './clickjacking_reports')

- **enable_annotations**: Add text annotations to screenshots
  - `True`: Annotate screenshots with target URL (default)
  - `False`: Save raw screenshots

### Network Options

- **verify_ssl**: Verify SSL certificates
  - `True`: Strict SSL verification
  - `False`: Accept self-signed certificates (default, for testing)

## Usage Examples

### Example 1: Quick Assessment (Test Mode)

Fast assessment using only HTTP header analysis:

```python
config = {
    'test_mode': True,  # Skip browser test
    'collect_evidence': False,  # No file output
}

result = clickjacking_plugin.execute_attack(
    target_url='http://example.com',
    vulnerability_data={},
    config=config
)

print(f"Headers allow framing: {result['data']['headers_allow_framing']}")
print(f"X-Frame-Options: {result['data']['headers']['x_frame_options']}")
```

### Example 2: Full Browser Test

Complete assessment with browser-based frameability testing:

```python
config = {
    'test_mode': False,
    'browser_type': 'chrome',
    'headless': True,
    'collect_evidence': True,
    'output_dir': './reports',
}

result = clickjacking_plugin.execute_attack(
    target_url='http://example.com/admin',
    vulnerability_data={'action_description': 'admin panel access'},
    config=config
)

if result['vulnerable']:
    print(f"Vulnerability confirmed via browser test")
    print(f"Screenshot: {result['data']['frameability']['screenshot_path']}")
    print(f"PoC HTML: {result['data']['poc_path']}")
```

### Example 3: Custom Overlay Design

Generate a PoC with custom overlay appearance:

```python
config = {
    'overlay_style': 'opaque',
    'overlay_text': 'Win $1000!',
    'test_mode': True,
}

payloads = clickjacking_plugin.generate_payloads({
    'target_url': 'http://example.com/delete-account',
    'overlay_style': 'opaque',
    'overlay_text': 'Claim Prize',
    'action_description': 'account deletion'
})

# This generates a convincing phishing page that hides the real action
```

### Example 4: Testing Multiple Targets

Scan multiple pages efficiently:

```python
targets = [
    'http://example.com/login',
    'http://example.com/settings',
    'http://example.com/payment',
]

results = {}
for target in targets:
    result = clickjacking_plugin.execute_attack(
        target_url=target,
        vulnerability_data={},
        config={'test_mode': True}
    )
    results[target] = result['vulnerable']

# Print summary
vulnerable_targets = [url for url, vuln in results.items() if vuln]
print(f"Found {len(vulnerable_targets)} vulnerable targets:")
for url in vulnerable_targets:
    print(f"  - {url}")
```

### Example 5: Automated Reporting

Generate detailed reports for multiple findings:

```python
import json
from datetime import datetime

findings = []

for target in targets:
    result = clickjacking_plugin.execute_attack(
        target_url=target,
        vulnerability_data={'action_description': 'sensitive operation'},
        config={
            'test_mode': False,
            'collect_evidence': True,
            'output_dir': './clickjacking_scan_results',
        }
    )
    
    if result['vulnerable']:
        findings.append({
            'target': target,
            'severity': result['severity'],
            'evidence': result['evidence'],
            'poc_path': result['data'].get('poc_path'),
            'timestamp': datetime.now().isoformat(),
        })

# Save report
with open('clickjacking_report.json', 'w') as f:
    json.dump(findings, f, indent=2)

print(f"Report saved: {len(findings)} vulnerabilities found")
```

## Understanding Results

### Result Structure

The `execute_attack` method returns a dictionary with the following structure:

```python
{
    'success': bool,          # True if scan completed successfully
    'vulnerable': bool,       # True if clickjacking vulnerability found
    'findings': [             # List of finding dictionaries
        {
            'type': 'clickjacking',
            'target': 'http://example.com',
            'severity': 'medium',  # or 'high' for sensitive actions
            'description': 'Target is vulnerable to clickjacking attacks',
            'evidence': 'No X-Frame-Options header present; ...',
            'poc_available': True
        }
    ],
    'data': {                 # Additional data
        'headers': {},        # Security headers analysis
        'headers_allow_framing': True,
        'frameability': {     # Browser test results
            'frameable': True,
            'method': 'browser_test',
            'screenshot_path': '/path/to/screenshot.png'
        },
        'poc_path': '/path/to/poc.html',
        'poc_html': '<html>...</html>'
    },
    'evidence': 'No X-Frame-Options header present; ...',
    'error': None,            # Error message if scan failed
    'severity': 'medium',     # Overall severity
    'remediation': '...'      # Remediation advice
}
```

### Security Header Analysis

The plugin analyzes the following security headers:

1. **X-Frame-Options**
   - `DENY`: Prevents all framing (good protection)
   - `SAMEORIGIN`: Allows only same-origin framing (good protection)
   - Missing: Allows all framing (vulnerable)

2. **Content-Security-Policy (frame-ancestors)**
   - `frame-ancestors 'none'`: Prevents all framing (excellent protection)
   - `frame-ancestors 'self'`: Allows only same-origin framing (good protection)
   - Missing or permissive: Allows framing (vulnerable)

### Protection Levels

- **excellent**: CSP frame-ancestors 'none'
- **good**: X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors 'self'
- **none**: No protection headers present

### Severity Classification

The plugin assigns severity based on context:

- **medium**: Basic pages without sensitive actions
- **high**: Pages with sensitive actions (payment, transfer, delete, admin, password, etc.)

## HTML Proof-of-Concept Payloads

The plugin generates three types of PoC HTML files:

### 1. Transparent Overlay

A semi-transparent iframe overlaid with a visible decoy button. The user sees both the target page and the decoy, but the decoy is positioned to intercept clicks.

**Use case**: Demonstrating basic clickjacking technique

**Key features**:
- Adjustable opacity
- Clear visual demonstration
- Security warning banner

### 2. Opaque Overlay

A fully opaque decoy page with a nearly invisible iframe positioned over interactive elements. The user only sees the decoy page.

**Use case**: Demonstrating advanced social engineering attacks

**Key features**:
- Convincing fake content (prize claims, surveys, etc.)
- Hidden iframe with minimal opacity
- Precise positioning over target buttons

### 3. Partial Overlay

A partially visible iframe with gradient overlay, showing some of the target page while maintaining the deception.

**Use case**: Demonstrating button hijacking

**Key features**:
- Semi-transparent gradient
- Visible target page context
- Strategic overlay positioning

All PoC files include:
- Security warning banner (to prevent accidental misuse)
- Inline CSS styling (no external dependencies)
- Console logging for demonstration
- Explanatory comments

## Best Practices

### 1. Ethical Use

**Always obtain explicit written permission before testing any system you do not own.**

The clickjacking plugin is intended for:
- Authorized security testing
- Vulnerability assessments with permission
- Educational and research purposes
- Security awareness demonstrations

**Never use this tool for:**
- Unauthorized testing
- Malicious attacks
- Exploiting vulnerabilities without permission

### 2. Test Mode for Reconnaissance

Use test mode for initial reconnaissance:

```python
config = {'test_mode': True}
```

This provides fast results using only HTTP requests, reducing load on target systems and avoiding browser fingerprinting.

### 3. Resource Management

The plugin automatically cleans up resources, but you can help by:
- Using context managers when possible
- Avoiding long-running test sessions
- Cleaning up output directories periodically

### 4. Rate Limiting

When scanning multiple targets:
- Add delays between requests
- Limit concurrent scans
- Respect robots.txt and rate limits

### 5. Evidence Handling

Handle evidence securely:
- Store reports in secure locations
- Encrypt sensitive findings
- Delete PoC files after demonstration
- Follow data protection regulations

### 6. False Positives

Browser-based tests are more reliable than header-only analysis. If headers suggest protection but you need confirmation:

```python
config = {'test_mode': False, 'browser_type': 'chrome'}
```

### 7. SSL/TLS Testing

For production systems with valid certificates:

```python
config = {'verify_ssl': True}
```

For testing environments with self-signed certificates:

```python
config = {'verify_ssl': False}
```

## Remediation Guidance

The plugin provides comprehensive remediation advice. Key recommendations:

### 1. Implement Frame Protection Headers

**Best Practice**: Use both X-Frame-Options AND CSP frame-ancestors

```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

### 2. Header Configuration by Platform

**Apache**:
```apache
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'none'"
```

**Nginx**:
```nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none'" always;
```

**Express.js (Node.js)**:
```javascript
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
app.use(helmet.contentSecurityPolicy({
    directives: {
        frameAncestors: ["'none'"]
    }
}));
```

**Django (Python)**:
```python
# settings.py
X_FRAME_OPTIONS = 'DENY'
CSP_FRAME_ANCESTORS = ["'none'"]
```

### 3. Defense in Depth

In addition to headers:
- Implement CSRF tokens for all state-changing operations
- Use user interaction confirmations for sensitive actions
- Consider frame-busting JavaScript (as additional layer, not primary defense)
- Educate users about phishing and social engineering

### 4. Testing After Implementation

After applying fixes, verify with the plugin:

```python
result = clickjacking_plugin.execute_attack(
    target_url='http://your-site.com',
    vulnerability_data={},
    config={'test_mode': False}
)

assert not result['vulnerable'], "Protection headers not working!"
```

## Troubleshooting

### Browser Not Found

If you get "browser not found" errors:

```bash
# Install Chrome/Chromium
sudo apt-get install chromium-browser

# Install Firefox
sudo apt-get install firefox

# Or use webdriver-manager
pip install webdriver-manager
```

### Selenium Errors

If browser tests fail:

1. Check browser is installed: `which chromium-browser` or `which firefox`
2. Try different browser: `config = {'browser_type': 'firefox'}`
3. Run in headed mode for debugging: `config = {'headless': False}`
4. Fall back to test mode: `config = {'test_mode': True}`

### Screenshot Issues

If screenshot annotation fails:

1. Check Pillow is installed: `pip install Pillow`
2. Disable annotations: `config = {'enable_annotations': False}`

### Permission Errors

If file writing fails:

1. Check output directory permissions
2. Specify writable directory: `config = {'output_dir': '/tmp/clickjacking'}`

## Integration Examples

### Integration with Megido Scanner

```python
from scanner.plugins import get_registry
from scanner.models import Vulnerability

def test_clickjacking_vulnerability(vulnerability: Vulnerability):
    """Test a discovered URL for clickjacking."""
    registry = get_registry()
    plugin = registry.get_plugin('clickjacking')
    
    result = plugin.execute_attack(
        target_url=vulnerability.url,
        vulnerability_data={
            'action_description': vulnerability.description
        },
        config={'test_mode': False}
    )
    
    if result['vulnerable']:
        # Update vulnerability record
        vulnerability.confirmed = True
        vulnerability.severity = result['severity']
        vulnerability.evidence = result['evidence']
        vulnerability.save()
        
        return result['data']['poc_path']
    
    return None
```

### Integration with CI/CD Pipeline

```python
import sys

def check_clickjacking_protection(urls):
    """Check URLs for clickjacking protection in CI/CD."""
    registry = get_registry()
    plugin = registry.get_plugin('clickjacking')
    
    vulnerable = []
    
    for url in urls:
        result = plugin.execute_attack(
            target_url=url,
            vulnerability_data={},
            config={'test_mode': True}
        )
        
        if result['vulnerable']:
            vulnerable.append(url)
    
    if vulnerable:
        print(f"ERROR: {len(vulnerable)} URLs lack clickjacking protection:")
        for url in vulnerable:
            print(f"  - {url}")
        sys.exit(1)
    
    print("SUCCESS: All URLs have clickjacking protection")
    return 0
```

## Advanced Topics

### Custom Payload Templates

You can customize the HTML template by modifying the private methods or extending the plugin:

```python
class CustomClickjackingPlugin(ClickjackingPlugin):
    def _generate_transparent_overlay_poc(self, target_url, overlay_text, 
                                         opacity, action_description):
        # Custom implementation
        custom_html = f"""
        <!DOCTYPE html>
        <html>
        <!-- Your custom template -->
        </html>
        """
        return custom_html
```

### Batch Processing

Process multiple targets efficiently:

```python
from concurrent.futures import ThreadPoolExecutor

def test_clickjacking_batch(urls, max_workers=5):
    """Test multiple URLs in parallel."""
    plugin = get_registry().get_plugin('clickjacking')
    
    def test_single(url):
        return plugin.execute_attack(
            target_url=url,
            vulnerability_data={},
            config={'test_mode': True}
        )
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(test_single, urls)
    
    return list(results)
```

## API Reference

### ClickjackingPlugin Class

#### Properties

- `vulnerability_type` → `'clickjacking'`
- `name` → `'Advanced Clickjacking Exploit'`
- `description` → Plugin description
- `version` → `'1.0.0'`

#### Methods

##### `generate_payloads(context=None) -> List[str]`

Generate HTML PoC payloads.

**Parameters**:
- `context` (dict, optional): Configuration including target_url, overlay_style, etc.

**Returns**: List of HTML payload strings

##### `execute_attack(target_url, vulnerability_data, config=None) -> Dict`

Execute clickjacking test.

**Parameters**:
- `target_url` (str): Target URL to test
- `vulnerability_data` (dict): Context including action_description
- `config` (dict, optional): Test configuration

**Returns**: Result dictionary with vulnerability status and evidence

##### `get_remediation_advice() -> str`

Get remediation guidance.

**Returns**: Detailed remediation advice string

##### `get_severity_level() -> str`

Get typical severity level.

**Returns**: `'medium'`

##### `validate_config(config) -> bool`

Validate configuration.

**Parameters**:
- `config` (dict): Configuration to validate

**Returns**: True if valid, False otherwise

## Support and Contributing

For issues, questions, or contributions:

1. Check existing documentation
2. Review test cases in `scanner/tests_clickjacking.py`
3. Refer to the main EXPLOIT_PLUGINS_GUIDE.md
4. Submit issues or pull requests to the Megido repository

## License

Part of the Megido Security Testing Platform.

## Security Notice

This tool is provided for legitimate security testing purposes only. Users are responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Using the tool ethically and responsibly
- Protecting any sensitive data discovered

Unauthorized access to computer systems is illegal.
