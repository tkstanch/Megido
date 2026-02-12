# Multi-Engine Plugin Architecture Guide

## 🎯 Overview

The Megido Multi-Engine Plugin Architecture enables running multiple analysis modules—SAST, DAST, SCA, secrets scanners, and custom analyzers—side by side. This future-proof architecture allows the project to scale and support all scan types with a consistent interface.

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                  Application Layer                          │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Demo CLI   │  │ Django Views │  │  REST API        │   │
│  └──────┬─────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │               │                    │              │
│         └───────────────┼────────────────────┘              │
└─────────────────────────┼─────────────────────────────────-─┘
                          │
           ┌──────────────▼────────────────┐
           │   Engine Orchestrator         │
           │  - Config Management          │
           │  - Parallel Execution         │
           │  - Result Aggregation         │
           └──────────────┬────────────────┘
                          │
           ┌──────────────▼────────────────┐
           │    Engine Registry            │
           │  - Auto-Discovery             │
           │  - Engine Lifecycle           │
           │  - Category Management        │
           └──────────────┬────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
    ┌────▼────┐      ┌───▼────┐      ┌───▼────┐
    │  SAST   │      │  DAST  │      │  SCA   │
    │ Bandit  │      │ Custom │      │ Trivy  │
    └─────────┘      └────────┘      └────────┘
         │                │                │
    ┌────▼────┐      ┌───▼────┐      ┌───▼────┐
    │ Secrets │      │ Custom │      │ Custom │
    │GitLeaks │      │ Plugin │      │ Plugin │
    └─────────┘      └────────┘      └────────┘
```

### Design Principles

1. **Pluggable**: Add new engines by dropping a Python file
2. **Consistent**: All engines implement the same interface
3. **Configurable**: YAML/JSON config for enable/disable
4. **Observable**: Comprehensive logging throughout
5. **Scalable**: Parallel execution with configurable workers
6. **Extensible**: Support for any scan type (SAST, DAST, SCA, etc.)

## 📁 File Structure

```
scanner/engine_plugins/
├── __init__.py                 # Package initialization
├── base_engine.py              # Base interface for all engines
├── engine_registry.py          # Auto-discovery and registration
├── engine_orchestrator.py      # Execution orchestration
├── config_manager.py           # Configuration management
├── engines_config.yaml         # Default configuration
├── test_engine_plugins.py      # Unit tests
└── engines/                    # Engine implementations
    ├── __init__.py
    ├── bandit_engine.py        # Bandit SAST scanner
    ├── gitleaks_engine.py      # GitLeaks secrets scanner
    └── dummy_scanner.py        # Demo/test engine
```

## 🚀 Quick Start

### 1. Basic Usage

```python
from scanner.engine_plugins import get_engine_registry, EngineOrchestrator

# Create orchestrator (loads config automatically)
orchestrator = EngineOrchestrator()

# Run scan on target
results = orchestrator.run_scan(
    target='/path/to/code',
    parallel=True,
    max_workers=4
)

# Access results
print(f"Found {results['summary'].total_findings} issues")
for finding in results['findings']:
    print(f"[{finding.severity}] {finding.title}")
```

### 2. Run Demo Script

```bash
# Scan current directory
python demo_multi_engine_scanner.py

# Scan specific path
python demo_multi_engine_scanner.py /path/to/project

# Results are saved to scan_results.json
```

### 3. List Available Engines

```python
from scanner.engine_plugins import get_engine_registry

registry = get_engine_registry()
engines = registry.list_engines()

for engine in engines:
    print(f"{engine['name']} - {engine['category']} - Available: {engine['available']}")
```

## 🔧 Configuration

### Configuration File Format

Create `scanner/engine_plugins/engines_config.yaml`:

```yaml
# Global settings
global:
  max_workers: 4
  default_timeout: 300
  severity_threshold: low

# Engine-specific settings
engines:
  bandit:
    enabled: true
    config:
      severity_threshold: medium
      exclude_patterns:
        - "*/tests/*"
        - "*/venv/*"
  
  gitleaks:
    enabled: true
    config:
      timeout: 300
  
  trivy:
    enabled: false  # Requires trivy binary
  
  dummy_scanner:
    enabled: true
```

### Configuration Options

**Global Settings:**
- `max_workers`: Maximum parallel workers (default: 4)
- `default_timeout`: Default timeout per engine in seconds (default: 300)
- `severity_threshold`: Minimum severity to report (info, low, medium, high, critical)

**Engine Settings:**
- `enabled`: Whether engine is enabled (default: true)
- `config`: Engine-specific configuration dictionary

## 🔌 Creating Custom Engines

### Step 1: Create Engine File

Create `scanner/engine_plugins/engines/my_engine.py`:

```python
from scanner.engine_plugins.base_engine import BaseEngine, EngineResult

class MyCustomEngine(BaseEngine):
    """My custom security scanner"""
    
    @property
    def engine_id(self) -> str:
        return 'my_scanner'
    
    @property
    def name(self) -> str:
        return 'My Custom Scanner'
    
    @property
    def description(self) -> str:
        return 'Scans for custom security issues'
    
    @property
    def category(self) -> str:
        return 'custom'  # or 'sast', 'dast', 'sca', 'secrets', etc.
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """Implement your scanning logic here"""
        findings = []
        
        # Your scanning logic
        # ...
        
        # Create findings
        finding = EngineResult(
            engine_id=self.engine_id,
            engine_name=self.name,
            title='Security Issue Found',
            description='Detailed description',
            severity='medium',
            confidence=0.8,
            file_path='/path/to/file.py',
            line_number=42,
            remediation='How to fix it'
        )
        findings.append(finding)
        
        return findings
```

### Step 2: Engine Auto-Discovery

That's it! The engine registry automatically discovers and loads your engine on startup.

### Step 3: Configure Your Engine

Add to `engines_config.yaml`:

```yaml
engines:
  my_scanner:
    enabled: true
    config:
      custom_option: value
```

## 🎭 Engine Categories

The architecture supports these engine categories:

| Category | Purpose | Examples |
|----------|---------|----------|
| **sast** | Static Application Security Testing | Bandit, Semgrep, SonarQube |
| **dast** | Dynamic Application Security Testing | OWASP ZAP, Burp Scanner |
| **sca** | Software Composition Analysis | Trivy, OWASP Dependency-Check |
| **secrets** | Secrets Detection | GitLeaks, TruffleHog |
| **container** | Container Security | Trivy, Clair |
| **cloud** | Cloud Security | ScoutSuite, Prowler |
| **custom** | Custom Analyzers | Your own scanners |

## 📊 Result Format

All engines return results in a standardized `EngineResult` format:

```python
@dataclass
class EngineResult:
    # Identification
    engine_id: str
    engine_name: str
    
    # Finding details
    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    
    # Location
    file_path: Optional[str]
    line_number: Optional[int]
    url: Optional[str]
    
    # Classification
    category: Optional[str]
    cwe_id: Optional[str]
    cve_id: Optional[str]
    owasp_category: Optional[str]
    
    # Remediation
    evidence: Optional[str]
    remediation: Optional[str]
    references: List[str]
    
    # Metadata
    timestamp: datetime
    raw_output: Optional[Dict]
```

## 🧪 Testing

### Run Unit Tests

```bash
cd scanner/engine_plugins
python test_engine_plugins.py
```

### Run Integration Demo

```bash
python demo_multi_engine_scanner.py /path/to/scan
```

## 📈 Advanced Usage

### Filter by Category

```python
# Run only SAST engines
results = orchestrator.run_scan(
    target='/path/to/code',
    categories=['sast']
)
```

### Filter by Engine IDs

```python
# Run specific engines only
results = orchestrator.run_scan(
    target='/path/to/code',
    engine_ids=['bandit', 'gitleaks']
)
```

### Sequential Execution

```python
# Run engines one by one (useful for debugging)
results = orchestrator.run_scan(
    target='/path/to/code',
    parallel=False
)
```

### Custom Configuration

```python
# Use custom config file
orchestrator = EngineOrchestrator(
    config_path='/path/to/custom_config.yaml'
)
```

## 🔍 Example Engines

### 1. Bandit (SAST)

Python static security analyzer. Finds common security issues in Python code.

**Requires:** `pip install bandit`

**Config:**
```yaml
bandit:
  enabled: true
  config:
    severity_threshold: medium
    exclude_patterns:
      - "*/tests/*"
```

### 2. GitLeaks (Secrets)

Detects hardcoded secrets, API keys, passwords in code and git history.

**Requires:** GitLeaks binary (https://github.com/gitleaks/gitleaks)

**Config:**
```yaml
gitleaks:
  enabled: true
  config:
    timeout: 300
```

### 3. Dummy Scanner (Demo)

Demonstration engine that generates sample findings for testing.

**Requires:** Nothing (always available)

**Config:**
```yaml
dummy_scanner:
  enabled: true
  config:
    num_findings: 3
```

## 🚀 Future Enhancements

The architecture is designed to support:

1. **Async/Await Execution**: Non-blocking engine execution
2. **Distributed Scanning**: Run engines across multiple machines
3. **AI/ML Integration**: Smart finding deduplication and prioritization
4. **Real-time Streaming**: Stream results as engines complete
5. **Incremental Scanning**: Only scan changed files
6. **Result Caching**: Cache and reuse scan results
7. **Custom Reporters**: Generate reports in various formats

## 📚 API Reference

### BaseEngine

Base class for all engines. Implement these abstract methods:

- `engine_id` (property): Unique identifier
- `name` (property): Human-readable name
- `description` (property): Brief description
- `category` (property): Engine category (sast, dast, etc.)
- `scan(target, config)`: Main scanning method

Optional methods:
- `is_available()`: Check if engine is usable
- `get_health_status()`: Get detailed health info
- `get_default_config()`: Return default config

### EngineRegistry

Manages engine discovery and lifecycle:

- `discover_engines()`: Auto-discover engines
- `register_engine(engine)`: Manually register
- `get_engine(engine_id)`: Get specific engine
- `get_engines_by_category(category)`: Filter by category
- `list_engines()`: List all engines

### EngineOrchestrator

Orchestrates multi-engine scans:

- `run_scan(target, categories, engine_ids, parallel, max_workers)`: Run scan
- `get_enabled_engines()`: Get enabled engine IDs
- `list_available_engines()`: List all available engines

### ConfigManager

Manages configuration:

- `is_engine_enabled(engine_id)`: Check if enabled
- `get_engine_config(engine_id)`: Get engine config
- `update_engine_config(engine_id, enabled, config)`: Update config
- `save_config(filepath)`: Save config to file

## 🤝 Contributing

To add a new engine:

1. Create engine class inheriting from `BaseEngine`
2. Implement required abstract methods
3. Place in `scanner/engine_plugins/engines/`
4. Add configuration to `engines_config.yaml`
5. Test with demo script
6. Submit pull request!

## 📝 License

This architecture is part of the Megido Security Testing Platform.

## 🙏 Credits

Inspired by industry-leading security tools and plugin architectures.
