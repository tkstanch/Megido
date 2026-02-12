# 🚀 Quick Start - Advanced Multi-Engine Scanner

## 5-Minute Getting Started

### 1. List Available Engines
```bash
python advanced_scanner_cli.py list-engines
```

### 2. Run Your First Scan
```bash
python advanced_scanner_cli.py scan /path/to/code
```

### 3. View Results
```bash
python advanced_scanner_cli.py show-scan 1 --severity high
```

### 4. Export Report
```bash
python advanced_scanner_cli.py export-report 1 --format html
```

## Python API
```python
from scanner.engine_plugins.engine_service import EngineService

service = EngineService()
scan = service.create_scan(target_path='/path', categories=['sast'])
result = service.execute_scan(scan)
findings = service.get_scan_findings(scan.id, severity='high')
```

## REST API
```bash
curl -X POST http://localhost:8000/api/engine-scans/ \
  -d '{"target_path": "/path", "execute_immediately": true}'
```

## Documentation
- Complete features: `FEATURE_SHOWCASE.md`
- Implementation: `FINAL_ACHIEVEMENT_SUMMARY.md`
- User guide: `MULTI_ENGINE_PLUGIN_GUIDE.md`

**Ready to scan!** 🚀
