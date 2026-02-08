# Exploit Plugin System

This directory contains the plugin-based exploit registry and payload generator system for Megido.

## Directory Structure

```
scanner/plugins/
├── __init__.py                 # Package initialization and exports
├── exploit_plugin.py          # Base ExploitPlugin interface
├── plugin_registry.py         # Plugin discovery and registry system
├── payload_generator.py       # Centralized payload library
└── exploits/                  # Directory containing exploit plugin implementations
    ├── __init__.py
    └── sqli_plugin.py         # SQL Injection exploit plugin
```

## Quick Start

### Using the Plugin System

```python
from scanner.plugins import get_registry

# Get the global plugin registry (auto-discovers plugins)
registry = get_registry()

# List all available plugins
plugins = registry.list_plugins()
for plugin in plugins:
    print(f"{plugin['name']}: {plugin['description']}")

# Get a specific plugin by vulnerability type
sqli_plugin = registry.get_plugin('sqli')

# Generate payloads
payloads = sqli_plugin.generate_payloads({'database_type': 'mysql'})

# Execute an attack (requires proper authorization!)
result = sqli_plugin.execute_attack(
    target_url='http://example.com/page?id=1',
    vulnerability_data={'parameter': 'id', 'method': 'GET'},
    config={'verify_ssl': False}
)
```

### Using the Payload Generator

```python
from scanner.plugins import get_payload_generator

generator = get_payload_generator()

# Get XSS payloads
xss_payloads = generator.get_payloads('xss')

# Get SQL injection payloads for MySQL
sqli_payloads = generator.get_payloads('sqli', {'database_type': 'mysql'})

# Encode a payload
encoded = generator.encode_payload('<script>alert(1)</script>', 'url')
```

## Creating a New Plugin

1. Create a new Python file in `exploits/` directory (e.g., `xss_plugin.py`)
2. Import the base class:
   ```python
   from scanner.plugins.exploit_plugin import ExploitPlugin
   ```
3. Create a class that inherits from `ExploitPlugin`
4. Implement all required methods
5. The plugin will be automatically discovered on the next import

### Minimal Plugin Example

```python
from scanner.plugins.exploit_plugin import ExploitPlugin
from scanner.plugins.payload_generator import get_payload_generator

class XSSPlugin(ExploitPlugin):
    @property
    def vulnerability_type(self) -> str:
        return 'xss'
    
    @property
    def name(self) -> str:
        return 'XSS Exploit Plugin'
    
    @property
    def description(self) -> str:
        return 'Cross-Site Scripting exploit plugin'
    
    def generate_payloads(self, context=None):
        generator = get_payload_generator()
        return generator.get_payloads('xss', context)
    
    def execute_attack(self, target_url, vulnerability_data, config=None):
        # Your implementation here
        return {
            'success': False,
            'findings': [],
            'data': {},
            'evidence': '',
            'error': None,
        }
```

## Available Plugins

### SQL Injection Plugin (`sqli_plugin.py`)

**Type**: `sqli`  
**Severity**: Critical

Comprehensive SQL injection exploit plugin supporting:
- Error-based SQL injection
- Time-based blind SQL injection
- Union-based SQL injection
- Multiple database types (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Integration with Megido's SQLInjectionEngine

## Integration with Scanner

The plugin system can be integrated with the scanner using the helper functions in `scanner/exploit_integration.py`:

```python
from scanner.exploit_integration import exploit_vulnerability
from scanner.models import Vulnerability

# Get a vulnerability
vuln = Vulnerability.objects.get(id=1)

# Exploit it
result = exploit_vulnerability(vuln)

if result['success']:
    print(f"Exploited: {result['evidence']}")
```

## Testing

Run the plugin system tests:

```bash
python -m unittest scanner.tests_plugins
```

Run the demo:

```bash
python demo_exploit_plugins.py
```

## Security Notice

⚠️ **IMPORTANT**: Only use these exploit plugins against systems you have **explicit written permission** to test. Unauthorized use of these tools may be illegal and unethical.

## Documentation

For complete documentation, see:
- [EXPLOIT_PLUGINS_GUIDE.md](../../EXPLOIT_PLUGINS_GUIDE.md) - Comprehensive guide
- [scanner/exploit_integration.py](../exploit_integration.py) - Integration examples
- [demo_exploit_plugins.py](../../demo_exploit_plugins.py) - Working demo

## Contributing

To contribute a new plugin:

1. Follow the plugin creation guide above
2. Add comprehensive tests to `scanner/tests_plugins.py`
3. Update documentation
4. Submit a pull request

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Scanner Application                      │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Vulnerability│  │  Scan Engine │  │  Web Interface  │  │
│  │   Scanner    │  │              │  │                 │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘  │
│         │                 │                    │            │
│         └─────────────────┼────────────────────┘            │
│                           │                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │
                    ┌───────▼──────┐
                    │ Integration  │
                    │   Layer      │
                    └───────┬──────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────────┐  ┌───────▼────────┐  ┌──────▼───────┐
│ Plugin Registry│  │    Payload     │  │   Exploit    │
│                │  │   Generator    │  │   Plugins    │
│ - Discovery    │  │                │  │              │
│ - Registration │  │ - XSS Payloads │  │ - SQLi       │
│ - Retrieval    │  │ - SQLi Payloads│  │ - XSS (TBD)  │
│                │  │ - RCE Payloads │  │ - RCE (TBD)  │
└────────────────┘  │ - etc.         │  │ - etc.       │
                    └────────────────┘  └──────────────┘
```

## License

Part of the Megido Security Testing Platform.
