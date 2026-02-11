# Scanner Plugin Development Guide

## Overview

Megido's vulnerability scanner now uses a **modular plugin-based architecture** for vulnerability detection. This guide explains how to create new scan plugins, understand the architecture, and contribute to the scanning system.

## Architecture

### Separation of Concerns

The Megido scanner has TWO distinct plugin systems:

1. **Scan Plugins** (`scanner/scan_plugins/`) - **DETECTION**
   - Purpose: Identify potential vulnerabilities
   - Location: `scanner/scan_plugins/detectors/`
   - Base Class: `BaseScanPlugin`
   - Focus: Finding security issues

2. **Exploit Plugins** (`scanner/plugins/`) - **EXPLOITATION**
   - Purpose: Exploit confirmed vulnerabilities
   - Location: `scanner/plugins/exploits/`
   - Base Class: `ExploitPlugin`
   - Focus: Proving exploitability

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Scanner Application                      │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │   REST API   │  │  Scan Views  │  │   Web UI        │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘  │
│         │                 │                    │            │
│         └─────────────────┼────────────────────┘            │
│                           │                                 │
│                   ┌───────▼──────┐                          │
│                   │ Scan Engine  │                          │
│                   │              │                          │
│                   └───────┬──────┘                          │
│                           │                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │
                ┌───────────┼───────────┐
                │           │           │
        ┌───────▼────┐ ┌────▼─────┐ ┌──▼──────┐
        │   Plugin   │ │  Plugin  │ │ Plugin  │
        │  Registry  │ │Discovery │ │ Loader  │
        └───────┬────┘ └────┬─────┘ └────┬────┘
                │           │            │
                └───────────┼────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
      ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
      │    XSS    │  │  Headers  │  │    SSL    │
      │  Scanner  │  │  Scanner  │  │  Scanner  │
      └───────────┘  └───────────┘  └───────────┘
```

## Creating a Scan Plugin

### Step 1: Create Plugin File

Create a new Python file in `scanner/scan_plugins/detectors/`:

```bash
touch scanner/scan_plugins/detectors/my_scanner.py
```

### Step 2: Import Base Classes

```python
"""
My Custom Scanner Plugin

Description of what this plugin detects.
"""

import logging
from typing import Dict, List, Any, Optional

from scanner.scan_plugins.base_scan_plugin import (
    BaseScanPlugin,
    VulnerabilityFinding,
    ScanSeverity
)

logger = logging.getLogger(__name__)
```

### Step 3: Implement Plugin Class

```python
class MyCustomScannerPlugin(BaseScanPlugin):
    """
    Custom vulnerability scanner plugin.
    
    This plugin detects [describe what it detects].
    """
    
    @property
    def plugin_id(self) -> str:
        """Unique identifier for this plugin."""
        return 'my_custom_scanner'
    
    @property
    def name(self) -> str:
        """Human-readable name."""
        return 'My Custom Scanner'
    
    @property
    def description(self) -> str:
        """Brief description of the plugin."""
        return 'Detects custom security issues in web applications'
    
    @property
    def version(self) -> str:
        """Plugin version."""
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        """List of vulnerability types this plugin detects."""
        return ['custom_vuln_type']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Main scanning logic.
        
        Args:
            url: Target URL to scan
            config: Optional configuration dictionary
        
        Returns:
            List of vulnerability findings
        """
        config = config or self.get_default_config()
        findings = []
        
        try:
            # Your scanning logic here
            # Example: Make HTTP requests, parse responses, analyze content
            
            # If vulnerability found, create a finding
            finding = VulnerabilityFinding(
                vulnerability_type='custom_vuln_type',
                severity='medium',  # low, medium, high, critical
                url=url,
                description='Description of the vulnerability',
                evidence='Proof/evidence of the vulnerability',
                remediation='How to fix this issue',
                parameter='vulnerable_param',  # Optional
                confidence=0.8,  # 0.0 to 1.0
                cwe_id='CWE-XXX'  # Optional CWE ID
            )
            findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            # Add custom config options here
        }
```

### Step 4: Test Your Plugin

The plugin is automatically discovered! Test it:

```python
from scanner.scan_plugins import get_scan_registry

# Get the registry (auto-discovers all plugins)
registry = get_scan_registry()

# Get your plugin
plugin = registry.get_plugin('my_custom_scanner')

# Run a scan
findings = plugin.scan('https://example.com')

for finding in findings:
    print(f"{finding.severity.upper()}: {finding.description}")
```

## Using the Scan Engine

### Basic Usage

```python
from scanner.scan_engine import get_scan_engine
from scanner.models import Scan

# Get the engine
engine = get_scan_engine()

# Configure the scan
config = {
    'verify_ssl': False,
    'timeout': 10,
}

# Run scan with all plugins
findings = engine.scan('https://example.com', config)

# Save to database
scan = Scan.objects.get(id=1)
engine.save_findings_to_db(scan, findings)
```

### Targeted Scanning

```python
# Run specific plugins only
findings = engine.scan_with_plugins(
    url='https://example.com',
    plugin_ids=['xss_scanner', 'ssl_scanner'],
    config=config
)
```

### List Available Plugins

```python
plugins = engine.list_available_plugins()
for plugin in plugins:
    print(f"{plugin['name']}: {plugin['description']}")
```

## VulnerabilityFinding Structure

```python
@dataclass
class VulnerabilityFinding:
    vulnerability_type: str      # e.g., 'xss', 'sqli', 'csrf'
    severity: str               # 'low', 'medium', 'high', 'critical'
    url: str                    # Target URL
    description: str            # What was found
    evidence: str              # Proof of vulnerability
    remediation: str           # How to fix
    parameter: Optional[str]   # Vulnerable parameter (if applicable)
    confidence: float          # 0.0 to 1.0
    cwe_id: Optional[str]     # CWE identifier (e.g., 'CWE-79')
```

## Available Scan Plugins

### XSS Scanner (`xss_scanner`)
- **Purpose**: Detects potential XSS vulnerabilities
- **Method**: Finds forms with user input fields
- **Vulnerability Types**: `xss`

### Security Headers Scanner (`security_headers_scanner`)
- **Purpose**: Checks for missing security headers
- **Headers Checked**:
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security
  - Content-Security-Policy
- **Vulnerability Types**: `other`, `info_disclosure`

### SSL/TLS Scanner (`ssl_scanner`)
- **Purpose**: Checks SSL/TLS configuration
- **Checks**: HTTP vs HTTPS usage
- **Vulnerability Types**: `info_disclosure`, `other`

## Integration with REST API

The scan engine is integrated into the existing REST API:

```bash
# Start a scan (uses plugin engine automatically)
curl -X POST http://localhost:8000/scanner/api/targets/1/scan/

# Get results
curl http://localhost:8000/scanner/api/scans/1/results/
```

## Future Enhancements (TODO)

### Phase 2: Async Scanning
```python
# TODO: Implement async scanning
async def async_scan(self, url: str, config: Optional[Dict[str, Any]] = None):
    """Async version of scan method"""
    # Use asyncio for concurrent plugin execution
    # Integrate with Celery for background tasks
    # Add progress tracking
    pass
```

### Phase 3: Advanced Features
- [ ] Plugin configuration UI
- [ ] Scan scheduling
- [ ] Incremental scanning
- [ ] Scan result caching
- [ ] Plugin marketplace
- [ ] Real-time scan progress via WebSocket
- [ ] Scan templates and profiles

### Phase 4: More Detectors
- [ ] SQL Injection detection plugin
- [ ] CSRF detection plugin
- [ ] Authentication bypass checks
- [ ] Session management checks
- [ ] Information disclosure checks
- [ ] Business logic vulnerability checks

## Best Practices

### 1. Error Handling
Always wrap scanning logic in try-except:
```python
try:
    # Scanning logic
    pass
except requests.RequestException as e:
    logger.error(f"Network error: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}")
```

### 2. Logging
Use appropriate log levels:
```python
logger.debug("Detailed debugging info")
logger.info("Normal operation info")
logger.warning("Warning about potential issues")
logger.error("Error during scan")
```

### 3. Configuration
Provide sensible defaults:
```python
def get_default_config(self) -> Dict[str, Any]:
    return {
        'verify_ssl': False,  # For testing environments
        'timeout': 10,        # Reasonable timeout
        'max_retries': 3,     # Retry failed requests
    }
```

### 4. Evidence Collection
Provide clear evidence:
```python
evidence = f"Header 'X-Frame-Options' not found in response headers. " \
          f"Response status: {response.status_code}"
```

### 5. Confidence Scores
Be realistic about confidence:
- 0.9-1.0: Very high confidence (easily verified)
- 0.7-0.9: High confidence (strong indicators)
- 0.5-0.7: Medium confidence (potential issue)
- 0.3-0.5: Low confidence (requires verification)
- 0.0-0.3: Very low confidence (might be false positive)

## Testing

### Unit Testing
```python
import unittest
from scanner.scan_plugins import get_scan_registry

class TestMyScanner(unittest.TestCase):
    def setUp(self):
        self.registry = get_scan_registry()
        self.plugin = self.registry.get_plugin('my_custom_scanner')
    
    def test_plugin_loaded(self):
        self.assertIsNotNone(self.plugin)
    
    def test_scan_returns_findings(self):
        findings = self.plugin.scan('https://example.com')
        self.assertIsInstance(findings, list)
```

### Integration Testing
```python
def test_scan_engine_integration():
    from scanner.scan_engine import get_scan_engine
    
    engine = get_scan_engine()
    findings = engine.scan('https://example.com')
    
    assert len(findings) >= 0
    for finding in findings:
        assert finding.url
        assert finding.severity in ['low', 'medium', 'high', 'critical']
```

## Migration from Old Scanner

The old `perform_basic_scan` function has been refactored to use the plugin engine. The migration is transparent:

**Before:**
```python
# Hardcoded checks in perform_basic_scan()
if 'X-Frame-Options' not in headers:
    Vulnerability.objects.create(...)
```

**After:**
```python
# Plugin-based approach
engine = get_scan_engine()
findings = engine.scan(url, config)
engine.save_findings_to_db(scan, findings)
```

## Contributing

To contribute a new scan plugin:

1. Create plugin file in `scanner/scan_plugins/detectors/`
2. Inherit from `BaseScanPlugin`
3. Implement all required methods
4. Test thoroughly
5. Add documentation
6. Submit pull request

## Security Notice

⚠️ **Important**: Scan plugins should only perform detection, not exploitation. For exploitation capabilities, create an exploit plugin in `scanner/plugins/exploits/`.

## Support

For questions or issues:
- Check existing plugins for examples
- Review the base class documentation
- Open an issue on GitHub
- Consult the main [USAGE_GUIDE.md](../USAGE_GUIDE.md)

## License

Part of the Megido Security Testing Platform.
