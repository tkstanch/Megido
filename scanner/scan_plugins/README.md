# Scan Plugin System

## Overview

This directory contains the **vulnerability detection plugin system** for Megido's scanner. These plugins focus on **finding security issues**, not exploiting them.

## Directory Structure

```
scanner/scan_plugins/
├── __init__.py                     # Package initialization
├── base_scan_plugin.py            # Base plugin interface
├── scan_plugin_registry.py        # Plugin discovery and registry
└── detectors/                     # Individual scan plugins
    ├── __init__.py
    ├── xss_scanner.py            # XSS detection
    ├── security_headers_scanner.py # Security headers checks
    └── ssl_scanner.py            # SSL/TLS configuration checks
```

## Quick Start

### Using the Scan Engine

```python
from scanner.scan_engine import get_scan_engine

# Get scan engine (automatically loads all plugins)
engine = get_scan_engine()

# Run scan
findings = engine.scan('https://example.com')

# Print findings
for finding in findings:
    print(f"{finding.severity}: {finding.description}")
```

### Using Individual Plugins

```python
from scanner.scan_plugins import get_scan_registry

# Get the plugin registry
registry = get_scan_registry()

# List all available plugins
plugins = registry.list_plugins()
for plugin in plugins:
    print(f"{plugin['name']}: {plugin['description']}")

# Get a specific plugin
xss_scanner = registry.get_plugin('xss_scanner')

# Run the plugin
findings = xss_scanner.scan('https://example.com')
```

## Available Plugins

### 1. XSS Scanner (`xss_scanner`)
**Purpose**: Detect potential Cross-Site Scripting vulnerabilities

**What it does**:
- Finds forms with user input fields
- Identifies potential injection points
- Reports forms as potential XSS targets

**Vulnerability Type**: `xss`  
**Severity**: Medium

### 2. Security Headers Scanner (`security_headers_scanner`)
**Purpose**: Check for missing security headers

**What it checks**:
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)

**Vulnerability Types**: `other`, `info_disclosure`  
**Severity**: Low to Medium

### 3. SSL/TLS Scanner (`ssl_scanner`)
**Purpose**: Check SSL/TLS configuration

**What it checks**:
- HTTP vs HTTPS usage
- (Future: Certificate validation, cipher suites, protocol versions)

**Vulnerability Types**: `info_disclosure`, `other`  
**Severity**: Medium

## Creating New Plugins

See [SCANNER_PLUGIN_GUIDE.md](../../SCANNER_PLUGIN_GUIDE.md) for complete documentation.

### Quick Example

```python
from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

class MyScanner(BaseScanPlugin):
    @property
    def plugin_id(self) -> str:
        return 'my_scanner'
    
    @property
    def name(self) -> str:
        return 'My Custom Scanner'
    
    @property
    def description(self) -> str:
        return 'Detects custom vulnerabilities'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['custom_type']
    
    def scan(self, url: str, config=None) -> List[VulnerabilityFinding]:
        findings = []
        # Your scanning logic here
        return findings
```

Save to `detectors/my_scanner.py` and it's automatically discovered!

## Architecture

### Plugin Lifecycle

```
1. Application Startup
   ↓
2. ScanPluginRegistry.discover_plugins()
   ↓
3. Scan Python files in detectors/
   ↓
4. Import modules and find BaseScanPlugin subclasses
   ↓
5. Instantiate and register plugins
   ↓
6. Plugins ready for use
```

### Scan Flow

```
User triggers scan
   ↓
start_scan() in views.py
   ↓
perform_basic_scan()
   ↓
ScanEngine.scan()
   ↓
Execute all registered plugins
   ↓
Aggregate findings
   ↓
Save to database
   ↓
Return results to user
```

## Key Classes

### BaseScanPlugin
Base interface that all plugins must implement.

**Required Properties**:
- `plugin_id`: Unique identifier
- `name`: Human-readable name
- `description`: Brief description
- `vulnerability_types`: List of vuln types detected

**Required Methods**:
- `scan(url, config)`: Main scanning logic

### VulnerabilityFinding
Standardized data class for vulnerability findings.

**Fields**:
- `vulnerability_type`: Type of vulnerability
- `severity`: low, medium, high, critical
- `url`: Target URL
- `description`: What was found
- `evidence`: Proof
- `remediation`: How to fix
- `confidence`: 0.0 to 1.0
- `cwe_id`: CWE identifier (optional)

### ScanPluginRegistry
Manages plugin discovery and lifecycle.

**Methods**:
- `discover_plugins()`: Auto-discover plugins
- `get_plugin(plugin_id)`: Get specific plugin
- `get_all_plugins()`: Get all plugins
- `list_plugins()`: List plugin metadata

## Integration with Scanner

The plugin system is integrated into the existing scanner flow:

1. **REST API**: `/scanner/api/targets/{id}/scan/` uses plugin engine
2. **Web UI**: Scan button triggers plugin-based scan
3. **Database**: Findings saved to `Vulnerability` model
4. **Advanced Features**: Applied after plugin scan completes

## Future Enhancements (Roadmap)

### Phase 2: Async Scanning
- [ ] Implement `async_scan()` methods
- [ ] Integrate with Celery for background tasks
- [ ] Add progress tracking via WebSocket
- [ ] Enable concurrent plugin execution

### Phase 3: More Detectors
- [ ] SQL Injection detection plugin
- [ ] CSRF detection plugin
- [ ] Authentication bypass checks
- [ ] Session management scanner
- [ ] Information disclosure scanner
- [ ] Business logic vulnerability checks
- [ ] API security scanner

### Phase 4: Advanced Features
- [ ] Plugin configuration UI
- [ ] Scan scheduling and automation
- [ ] Scan templates and profiles
- [ ] Incremental scanning
- [ ] Result caching and deduplication
- [ ] Plugin marketplace
- [ ] Custom plugin parameters via UI

## Comparison with Exploit Plugins

| Feature | Scan Plugins | Exploit Plugins |
|---------|-------------|----------------|
| **Purpose** | Detection | Exploitation |
| **Location** | `scanner/scan_plugins/` | `scanner/plugins/` |
| **Base Class** | `BaseScanPlugin` | `ExploitPlugin` |
| **Focus** | Finding issues | Proving exploitability |
| **Risk** | Read-only scanning | Active exploitation |
| **When Used** | Initial scan | After confirmation |

## Best Practices

1. **Error Handling**: Always wrap in try-except
2. **Logging**: Use appropriate log levels
3. **Configuration**: Provide sensible defaults
4. **Evidence**: Collect clear proof
5. **Confidence**: Be realistic about scores
6. **Documentation**: Document what you check
7. **Testing**: Write unit tests for plugins

## Testing

```python
import unittest
from scanner.scan_plugins import get_scan_registry

class TestScanPlugins(unittest.TestCase):
    def test_plugins_loaded(self):
        registry = get_scan_registry()
        self.assertGreater(registry.get_plugin_count(), 0)
    
    def test_xss_scanner(self):
        registry = get_scan_registry()
        plugin = registry.get_plugin('xss_scanner')
        self.assertIsNotNone(plugin)
        
        findings = plugin.scan('https://example.com')
        self.assertIsInstance(findings, list)
```

## Security Considerations

⚠️ **Important**:
- Scan plugins should be **read-only**
- Do NOT modify target systems
- Handle sensitive data appropriately
- Respect rate limits and robots.txt
- Always get authorization before scanning

## Contributing

1. Create plugin in `detectors/`
2. Inherit from `BaseScanPlugin`
3. Implement required methods
4. Add tests
5. Update documentation
6. Submit pull request

## Support

- Full guide: [SCANNER_PLUGIN_GUIDE.md](../../SCANNER_PLUGIN_GUIDE.md)
- Usage guide: [USAGE_GUIDE.md](../../USAGE_GUIDE.md)
- Issues: GitHub issues
- Examples: Look at existing plugins

## License

Part of the Megido Security Testing Platform.
