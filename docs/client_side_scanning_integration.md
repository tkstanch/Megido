# Client-Side Scanning Integration

## Overview

The Client-Side Scanning Integration extends the SQL Attacker module with comprehensive client-side security testing capabilities. This includes browser automation for HTML5 storage testing, static JavaScript analysis, HTTP Parameter Pollution detection, and privacy/storage risk analysis.

## Architecture

The client-side scanning system is designed as a modular, orchestrated architecture:

```
sql_attacker/client_side/
├── __init__.py                 # Module exports
├── browser_automation.py       # Browser automation worker (Playwright/Selenium)
├── static_scanner.py          # JavaScript static analysis
├── hpp_detector.py            # HTTP Parameter Pollution detection
├── privacy_analyzer.py        # Privacy and storage risk analysis
└── orchestrator.py            # Scan orchestration and coordination
```

### Components

#### 1. Browser Automation Worker (`browser_automation.py`)

Uses Playwright (with Selenium fallback) to:
- Inject SQL injection payloads into HTML5 storage-backed forms
- Monitor JavaScript console for SQL/database errors
- Detect payload reflection in localStorage, sessionStorage, and indexedDB
- Identify storage corruption and data leakage
- Track persistent storage changes over time

**Key Features:**
- Dual browser support (Playwright preferred, Selenium fallback)
- Real-time console and page error monitoring
- Storage state comparison before/after injection
- Sensitive data leakage detection

#### 2. Static JavaScript Scanner (`static_scanner.py`)

Performs static code analysis on JavaScript files to detect:
- Unsafe usage of `openDatabase()` with tainted input
- Insecure `localStorage` operations with concatenation
- Vulnerable `indexedDB` usage patterns
- Web SQL injection via string concatenation in `executeSql()`
- Tainted input sources (location, URL, referrer, etc.)

**Key Features:**
- Pattern-based vulnerability detection
- Confidence scoring for findings
- Multi-file and directory scanning
- HTML report generation

#### 3. HTTP Parameter Pollution Detector (`hpp_detector.py`)

Detects HTTP Parameter Pollution vulnerabilities through:
- Duplicate parameter testing
- Parameter encoding variations
- Mixed case parameter names
- Array notation (`param[]`)
- Semicolon separators
- Encoded ampersand testing

**Key Features:**
- Multiple HPP technique coverage
- Response difference detection
- Baseline comparison
- Error keyword detection

#### 4. Privacy Storage Analyzer (`privacy_analyzer.py`)

Analyzes client-side storage for privacy risks:
- Cookie security attribute validation (HttpOnly, Secure, SameSite)
- Sensitive data detection in storage (passwords, tokens, SSNs, credit cards)
- JWT token exposure in localStorage
- Cached URL analysis for sensitive data
- Flash LSO detection (optional)

**Key Features:**
- Multi-pattern sensitive data detection
- Risk level classification
- Storage location categorization
- Security best practice validation

#### 5. Scan Orchestrator (`orchestrator.py`)

Coordinates all client-side scans:
- Manages scan lifecycle
- Aggregates findings from all scanners
- Generates comprehensive reports (JSON, HTML)
- Provides summary statistics

**Key Features:**
- Independent or combined scan execution
- Unified reporting format
- Error handling and status tracking
- Multi-format export

## Usage

### Basic Usage

```python
from sql_attacker.client_side import ClientSideScanOrchestrator, ScanConfiguration, ScanType

# Create orchestrator
orchestrator = ClientSideScanOrchestrator()

# Configure scan
config = ScanConfiguration(
    scan_types=[ScanType.ALL.value],
    target_url="https://example.com",
    javascript_code="""
        var db = openDatabase('test', '1.0', 'Test', 1024);
        var input = window.location.hash;
        db.transaction(function(tx) {
            tx.executeSql('SELECT * FROM users WHERE id = ' + input);
        });
    """,
    use_playwright=True,
    headless=True,
    timeout=30000
)

# Execute scan
results = orchestrator.scan(config)

# Export results
orchestrator.export_results(results, "scan_report.json", format="json")
orchestrator.export_results(results, "scan_report.html", format="html")
```

### Individual Scanner Usage

#### Browser Automation

```python
from sql_attacker.client_side import BrowserAutomationWorker

worker = BrowserAutomationWorker(use_playwright=True, headless=True)

# Scan forms on a page
findings = worker.scan_form("https://example.com/login", form_selector="form#login")

# Monitor storage changes
findings = worker.monitor_storage_changes("https://example.com", duration=10)

# Get report
report = worker.get_findings_report()
print(f"Total findings: {report['total_findings']}")
```

#### Static JavaScript Analysis

```python
from sql_attacker.client_side import JavaScriptStaticScanner

scanner = JavaScriptStaticScanner()

# Scan a file
findings = scanner.scan_file("/path/to/app.js")

# Scan code snippet
code = """
var token = localStorage.getItem('auth_token');
var query = 'SELECT * FROM users WHERE token = "' + token + '"';
"""
findings = scanner.scan_code(code, "inline.js")

# Generate HTML report
scanner.generate_html_report(findings, "static_report.html")
```

#### HTTP Parameter Pollution Detection

```python
from sql_attacker.client_side import HTTPParameterPollutionDetector

detector = HTTPParameterPollutionDetector(timeout=10, verify_ssl=True)

# Scan URL
findings = detector.scan_url("https://example.com/search?q=test&page=1")

# Generate test URLs
test_urls = detector.generate_test_urls(
    "https://example.com/api",
    {"id": "123", "user": "admin"}
)

print("Duplicate parameter test URLs:")
for url in test_urls['duplicate']:
    print(f"  {url}")
```

#### Privacy Storage Analysis

```python
from sql_attacker.client_side import PrivacyStorageAnalyzer

analyzer = PrivacyStorageAnalyzer()

# Analyze storage from browser
storage_data = {
    'cookies': [
        {
            'name': 'session_token',
            'value': 'abc123...',
            'httpOnly': False,
            'secure': False,
            'sameSite': None
        }
    ],
    'localStorage': {
        'jwt_token': 'eyJhbGci...',
        'user_password': 'secret123'
    },
    'sessionStorage': {
        'user_email': 'user@example.com'
    }
}

findings = analyzer.analyze_all(storage_data)

# Get report
report = analyzer.get_report(findings)
print(f"Critical: {report['by_risk_level']['CRITICAL']}")
print(f"High: {report['by_risk_level']['HIGH']}")
```

## Configuration Options

### ScanConfiguration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_types` | List[str] | Required | Types of scans to run (browser_automation, static_javascript, hpp_detection, privacy_analysis, all) |
| `target_url` | str | None | Target URL for browser-based scans |
| `javascript_files` | List[str] | None | JavaScript files for static analysis |
| `javascript_code` | str | None | Inline JavaScript code for static analysis |
| `use_playwright` | bool | True | Use Playwright (True) or Selenium (False) |
| `headless` | bool | True | Run browser in headless mode |
| `timeout` | int | 30000 | Request timeout in milliseconds |
| `verify_ssl` | bool | True | Verify SSL certificates |
| `follow_redirects` | bool | True | Follow HTTP redirects |
| `scan_flash_lso` | bool | False | Scan for Flash Local Shared Objects |
| `form_selector` | str | None | CSS selector for specific form |
| `test_params` | Dict | None | Parameters for HPP testing |

## Output Format

### JSON Output Structure

```json
{
  "scan_id": "cs_20240101_120000",
  "start_time": "2024-01-01T12:00:00",
  "end_time": "2024-01-01T12:05:00",
  "status": "completed",
  "configuration": {
    "scan_types": ["all"],
    "target_url": "https://example.com",
    "use_playwright": true,
    "headless": true
  },
  "browser_findings": [
    {
      "finding_type": "SQL_ERROR_IN_CONSOLE",
      "severity": "HIGH",
      "url": "https://example.com/app",
      "payload": "' OR '1'='1",
      "error_message": "SQLite error: syntax error"
    }
  ],
  "static_findings": [
    {
      "vulnerability_type": "unsafe_webSQL",
      "severity": "CRITICAL",
      "file_path": "app.js",
      "line_number": 42,
      "code_snippet": "tx.executeSql('SELECT * FROM users WHERE id = ' + userInput)",
      "description": "Web SQL executeSql() with string concatenation",
      "recommendation": "Use parameterized queries with '?' placeholder"
    }
  ],
  "hpp_findings": [
    {
      "technique": "duplicate_parameter",
      "severity": "MEDIUM",
      "url": "https://example.com/search",
      "behavior": "Parameter duplication changed response"
    }
  ],
  "privacy_findings": [
    {
      "risk_type": "JWT_IN_LOCALSTORAGE",
      "risk_level": "HIGH",
      "storage_location": "localStorage",
      "key": "auth_token",
      "description": "JWT token stored in localStorage",
      "recommendation": "Store JWT in httpOnly cookies"
    }
  ],
  "summary": {
    "total_findings": 15,
    "by_scan_type": {
      "browser_automation": 3,
      "static_javascript": 7,
      "hpp_detection": 2,
      "privacy_analysis": 3
    },
    "by_severity": {
      "CRITICAL": 2,
      "HIGH": 5,
      "MEDIUM": 6,
      "LOW": 2
    },
    "scan_duration": "0:05:00"
  }
}
```

### Finding Types and Severity Levels

#### Browser Automation Findings

| Finding Type | Severity | Description |
|-------------|----------|-------------|
| SQL_ERROR_IN_CONSOLE | HIGH | SQL errors detected in browser console |
| SQL_ERROR_IN_PAGE | HIGH | SQL errors in page error events |
| PAYLOAD_IN_STORAGE | MEDIUM | Injected payload found in storage |
| STORAGE_CORRUPTION | HIGH | Corrupted data detected in storage |
| SENSITIVE_DATA_LEAKAGE | CRITICAL | Sensitive data leaked to storage |

#### Static JavaScript Findings

| Finding Type | Severity | Description |
|-------------|----------|-------------|
| unsafe_openDatabase | HIGH | Unsafe openDatabase usage with tainted input |
| unsafe_localStorage | MEDIUM | Unsafe localStorage with concatenation |
| unsafe_indexedDB | HIGH | Unsafe indexedDB operations |
| unsafe_webSQL | CRITICAL | SQL injection in Web SQL |
| sql_concatenation | CRITICAL | SQL query with string concatenation |

#### HPP Findings

| Technique | Severity | Description |
|-----------|----------|-------------|
| duplicate_parameter | MEDIUM | Duplicate parameters cause behavior change |
| encoded_parameter | LOW | Encoded parameters cause behavior change |
| mixed_case | LOW | Case variation causes behavior change |
| array_notation | MEDIUM | Array notation causes behavior change |
| semicolon_separator | LOW | Semicolon separator causes behavior change |
| ampersand_encoded | LOW | Encoded ampersand causes behavior change |

#### Privacy Findings

| Risk Type | Risk Level | Description |
|-----------|------------|-------------|
| SENSITIVE_DATA_IN_COOKIE_* | CRITICAL/HIGH | Sensitive data in cookies |
| COOKIE_MISSING_HTTPONLY | MEDIUM | Missing HttpOnly flag |
| COOKIE_MISSING_SECURE | MEDIUM | Missing Secure flag |
| COOKIE_MISSING_SAMESITE | MEDIUM | Missing SameSite attribute |
| JWT_IN_LOCALSTORAGE | HIGH | JWT token in localStorage |
| SENSITIVE_DATA_IN_LOCALSTORAGE_* | CRITICAL/HIGH | Sensitive data in localStorage |
| SENSITIVE_DATA_IN_CACHE_URL_* | HIGH | Sensitive data in cached URLs |

## Django Integration

### Views

Add to `sql_attacker/views.py`:

```python
from .client_side import ClientSideScanOrchestrator, ScanConfiguration, ScanType

@api_view(['POST'])
def api_client_side_scan(request):
    """API endpoint for client-side scans"""
    try:
        data = request.data
        
        config = ScanConfiguration(
            scan_types=data.get('scan_types', [ScanType.ALL.value]),
            target_url=data.get('target_url'),
            javascript_code=data.get('javascript_code'),
            use_playwright=data.get('use_playwright', True),
            headless=data.get('headless', True)
        )
        
        orchestrator = ClientSideScanOrchestrator()
        results = orchestrator.scan(config)
        
        return Response(results.to_dict(), status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
```

### URL Configuration

Add to `sql_attacker/urls.py`:

```python
urlpatterns = [
    # ... existing patterns ...
    path('api/client-side/scan/', views.api_client_side_scan, name='api_client_side_scan'),
    path('client-side/', views.client_side_dashboard, name='client_side_dashboard'),
]
```

## Testing

Run the test suite:

```bash
# Run all client-side tests
python -m unittest discover sql_attacker -p "test_*.py"

# Run specific test modules
python -m unittest sql_attacker.test_browser_automation
python -m unittest sql_attacker.test_static_scanner
python -m unittest sql_attacker.test_hpp_detector
python -m unittest sql_attacker.test_privacy_analyzer
python -m unittest sql_attacker.test_orchestrator
```

## Best Practices

### Security Considerations

1. **Isolation**: Run browser automation in isolated environments (containers, VMs)
2. **Rate Limiting**: Implement rate limiting for HPP detection to avoid DoS
3. **SSL Verification**: Always verify SSL certificates in production
4. **Sensitive Data**: Mask or redact sensitive data in reports
5. **Access Control**: Restrict client-side scanning features to authorized users

### Performance Optimization

1. **Headless Mode**: Use headless browsers for faster execution
2. **Timeout Configuration**: Set appropriate timeouts based on target responsiveness
3. **Parallel Execution**: Run independent scans in parallel when possible
4. **Selective Scanning**: Choose specific scan types based on needs
5. **Cache Results**: Cache static analysis results for unchanged files

### Error Handling

All scanners implement comprehensive error handling:
- Network errors are logged and don't crash the scan
- Browser initialization failures fall back to alternative methods
- Invalid input is validated before processing
- Partial results are returned on non-critical failures

## Example Scenarios

### Scenario 1: Pentesting a Web Application

```python
# Complete security assessment
config = ScanConfiguration(
    scan_types=[ScanType.ALL.value],
    target_url="https://target-app.com",
    javascript_files=[
        "static/js/app.js",
        "static/js/auth.js"
    ],
    use_playwright=True,
    headless=True,
    verify_ssl=True
)

orchestrator = ClientSideScanOrchestrator()
results = orchestrator.scan(config)

# Generate reports
orchestrator.export_results(results, "pentest_report.json", "json")
orchestrator.export_results(results, "pentest_report.html", "html")
```

### Scenario 2: Code Review

```python
# Static analysis only
config = ScanConfiguration(
    scan_types=[ScanType.STATIC_JAVASCRIPT.value],
    javascript_files=[
        "src/database.js",
        "src/storage.js"
    ]
)

orchestrator = ClientSideScanOrchestrator()
results = orchestrator.scan(config)

# Check for critical findings
critical = [f for f in results.static_findings if f.severity == "CRITICAL"]
if critical:
    print(f"Found {len(critical)} CRITICAL vulnerabilities!")
    for finding in critical:
        print(f"  {finding.file_path}:{finding.line_number} - {finding.description}")
```

### Scenario 3: Privacy Audit

```python
# Privacy analysis only
config = ScanConfiguration(
    scan_types=[ScanType.PRIVACY_ANALYSIS.value],
    target_url="https://app.com",
    scan_flash_lso=True
)

orchestrator = ClientSideScanOrchestrator()
results = orchestrator.scan(config)

# Generate privacy report
report = {
    'cookies_analyzed': len(results.privacy_findings),
    'critical_issues': len([f for f in results.privacy_findings if f.risk_level == "CRITICAL"]),
    'recommendations': [f.recommendation for f in results.privacy_findings[:5]]
}
```

## Troubleshooting

### Common Issues

**Issue**: Browser fails to initialize
```
Solution: Install browser drivers
- Playwright: python -m playwright install chromium
- Selenium: pip install webdriver-manager
```

**Issue**: SSL certificate errors
```
Solution: Set verify_ssl=False for testing (not recommended for production)
config = ScanConfiguration(verify_ssl=False, ...)
```

**Issue**: Timeout errors
```
Solution: Increase timeout value
config = ScanConfiguration(timeout=60000, ...)  # 60 seconds
```

**Issue**: Permission errors accessing Flash LSO
```
Solution: Run with appropriate permissions or disable Flash LSO scanning
config = ScanConfiguration(scan_flash_lso=False, ...)
```

## API Reference

See inline documentation in each module for detailed API reference:
- `browser_automation.py`: Browser automation API
- `static_scanner.py`: Static analysis API
- `hpp_detector.py`: HPP detection API
- `privacy_analyzer.py`: Privacy analysis API
- `orchestrator.py`: Orchestration API

## Future Enhancements

- WebSocket injection testing
- Service Worker analysis
- IndexedDB query injection detection
- CORS misconfiguration detection
- CSP bypass techniques
- DOM-based XSS with storage interaction
- Automated remediation suggestions
- Integration with CI/CD pipelines
- Real-time monitoring capabilities

## Contributing

When contributing to client-side scanning:
1. Follow the existing modular architecture
2. Add comprehensive tests for new features
3. Update this documentation
4. Ensure backward compatibility
5. Add example usage in docstrings

## License

See main project LICENSE file.
