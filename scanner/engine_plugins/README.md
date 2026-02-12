# Engine Plugins Directory

This directory contains the multi-engine plugin architecture for Megido's vulnerability scanner.

## 📁 Structure

```
engine_plugins/
├── __init__.py                  # Package exports
├── base_engine.py               # Base interface for all engines
├── engine_registry.py           # Auto-discovery and registration
├── engine_orchestrator.py       # Multi-engine execution
├── config_manager.py            # Configuration management
├── engines_config.yaml          # Default configuration
├── test_engine_plugins.py       # Unit tests
└── engines/                     # Engine implementations
    ├── __init__.py
    ├── bandit_engine.py         # Bandit SAST scanner
    ├── gitleaks_engine.py       # GitLeaks secrets scanner
    └── dummy_scanner.py         # Demo/test engine
```

## 🚀 Quick Start

```python
from scanner.engine_plugins import EngineOrchestrator

# Create orchestrator
orchestrator = EngineOrchestrator()

# Run multi-engine scan
results = orchestrator.run_scan('/path/to/scan')

# Access results
print(f"Found {results['summary'].total_findings} issues")
for finding in results['findings']:
    print(f"[{finding.severity}] {finding.title}")
```

## 🔌 Adding New Engines

1. Create a new file in `engines/` directory (e.g., `my_engine.py`)
2. Inherit from `BaseEngine`
3. Implement required methods:

```python
from scanner.engine_plugins.base_engine import BaseEngine, EngineResult

class MyEngine(BaseEngine):
    @property
    def engine_id(self) -> str:
        return 'my_engine'
    
    @property
    def name(self) -> str:
        return 'My Security Scanner'
    
    @property
    def description(self) -> str:
        return 'Scans for XYZ vulnerabilities'
    
    @property
    def category(self) -> str:
        return 'sast'  # or 'dast', 'sca', 'secrets', etc.
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None):
        # Your scanning logic here
        findings = []
        # ... perform scan ...
        return findings
```

4. Engine is automatically discovered and loaded!

## ⚙️ Configuration

Edit `engines_config.yaml`:

```yaml
engines:
  my_engine:
    enabled: true
    config:
      timeout: 300
      custom_setting: value
```

## 🧪 Testing

Run the test suite:

```bash
python test_engine_plugins.py
```

Run the demo:

```bash
python ../../demo_multi_engine_scanner.py /path/to/scan
```

## 📚 Documentation

See [MULTI_ENGINE_PLUGIN_GUIDE.md](../../MULTI_ENGINE_PLUGIN_GUIDE.md) for comprehensive documentation.

## 🎯 Engine Categories

- **sast** - Static Application Security Testing (code analysis)
- **dast** - Dynamic Application Security Testing (runtime testing)
- **sca** - Software Composition Analysis (dependency checking)
- **secrets** - Secrets Detection (credential scanning)
- **container** - Container Security (image scanning)
- **cloud** - Cloud Security (infrastructure checks)
- **custom** - Custom Analyzers (anything else)

## 💡 Examples

### List All Engines

```python
from scanner.engine_plugins import get_engine_registry

registry = get_engine_registry()
for engine in registry.list_engines():
    print(f"{engine['name']} - {engine['category']}")
```

### Run Specific Engines

```python
orchestrator = EngineOrchestrator()
results = orchestrator.run_scan(
    target='/path/to/code',
    engine_ids=['bandit', 'gitleaks']  # Only run these
)
```

### Filter by Category

```python
results = orchestrator.run_scan(
    target='/path/to/code',
    categories=['sast', 'secrets']  # Only SAST and secrets engines
)
```

### Sequential Execution

```python
results = orchestrator.run_scan(
    target='/path/to/code',
    parallel=False  # Run one at a time
)
```

## 🔒 Security

- All engines run in isolated execution contexts
- Timeouts prevent runaway scans
- Input validation on all parameters
- Safe subprocess execution
- No hardcoded credentials

## 🚀 Performance

- Parallel execution (default: 4 workers)
- Lightweight architecture
- Efficient registry caching
- Minimal overhead

## 📊 Architecture

```
Application
    ↓
EngineOrchestrator
    ↓
EngineRegistry → ConfigManager
    ↓
BaseEngine (Interface)
    ↓
Concrete Engines (Bandit, GitLeaks, etc.)
```

## ✅ Status

- ✅ Core architecture implemented
- ✅ 3 example engines (Bandit, GitLeaks, Dummy)
- ✅ Full test coverage (15 tests)
- ✅ Comprehensive documentation
- ✅ Demo script
- ✅ Code review completed
- ✅ Security scan passed (0 vulnerabilities)

## 🔮 Future Enhancements

- Async/await support
- Distributed execution
- AI-powered deduplication
- Incremental scanning
- Result caching
- More engine implementations
