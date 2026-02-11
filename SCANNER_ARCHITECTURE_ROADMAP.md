# Scanner Architecture Migration & Roadmap

## Overview

This document describes the migration from the old hardcoded vulnerability scanner to the new plugin-based architecture, and outlines the roadmap for future enhancements.

## Phase 1: Initial Refactor and Scaffolding ✅ COMPLETE

### What Was Implemented

#### 1. Core Architecture ✅
- **Plugin System**: Created `scanner/scan_plugins/` with modular plugin architecture
- **Base Classes**: Implemented `BaseScanPlugin` interface for detection plugins
- **Registry System**: Auto-discovery of plugins from `detectors/` directory
- **Scan Engine**: Orchestration layer that executes all plugins
- **Integration**: Updated `perform_basic_scan()` to use plugin engine

#### 2. Detection Plugins ✅
Migrated existing hardcoded checks into three plugins:

| Plugin | Purpose | Vulnerability Types | Status |
|--------|---------|-------------------|--------|
| `xss_scanner` | Detect XSS vulnerabilities | `xss` | ✅ Complete |
| `security_headers_scanner` | Check security headers | `other`, `info_disclosure` | ✅ Complete |
| `ssl_scanner` | Check SSL/TLS config | `info_disclosure`, `other` | ✅ Complete |

#### 3. Documentation ✅
- **SCANNER_PLUGIN_GUIDE.md**: Comprehensive plugin development guide
- **scanner/scan_plugins/README.md**: Quick reference for plugin system
- **USAGE_GUIDE.md**: Updated with new architecture info
- **Inline Documentation**: Extensive code comments and TODOs
- **Demo Scripts**: Two demo scripts showcasing the system

#### 4. Testing ✅
- **tests_scan_plugins.py**: Comprehensive test suite for plugin system
- **Demo Scripts**: Verified plugin discovery and execution
- **Manual Testing**: Tested individual plugins and scan engine

### Architecture Before vs After

**Before (Phase 0):**
```python
def perform_basic_scan(scan, url):
    # Hardcoded XSS checks
    forms = soup.find_all('form')
    for form in forms:
        # Create vulnerability...
    
    # Hardcoded header checks
    if 'X-Frame-Options' not in headers:
        # Create vulnerability...
    
    # Hardcoded SSL checks
    if urlparse(url).scheme == 'http':
        # Create vulnerability...
```

**After (Phase 1):**
```python
def perform_basic_scan(scan, url):
    # Use plugin-based engine
    engine = get_scan_engine()
    findings = engine.scan(url, config)
    engine.save_findings_to_db(scan, findings)
```

### Backward Compatibility ✅

**100% backward compatible** with existing:
- REST API endpoints (`/scanner/api/targets/{id}/scan/`)
- Web UI scan interface
- Database models
- Scan results format
- Advanced features integration

## Phase 2: Async Scanning & More Detectors (PLANNED)

### Timeline: Q1 2026

### Goals
1. Implement async scanning capabilities
2. Add more vulnerability detection plugins
3. Enhance scanning performance

### Async Scanning Implementation

#### 2.1 Async Plugin Support
```python
class BaseScanPlugin:
    @property
    def supports_async(self) -> bool:
        """Override to return True if plugin supports async"""
        return True
    
    async def async_scan(self, url: str, config: Optional[Dict[str, Any]] = None):
        """Async version of scan method"""
        # Implement async scanning logic
        pass
```

#### 2.2 Async Scan Engine
```python
class ScanEngine:
    async def async_scan(self, url: str, config: Optional[Dict[str, Any]] = None):
        """Execute all plugins concurrently"""
        tasks = []
        for plugin in self.registry.get_all_plugins():
            if plugin.supports_async:
                tasks.append(plugin.async_scan(url, config))
            else:
                # Fall back to sync in executor
                tasks.append(asyncio.to_thread(plugin.scan, url, config))
        
        results = await asyncio.gather(*tasks)
        return [f for findings in results for f in findings]
```

#### 2.3 Celery Integration
```python
@shared_task
def async_plugin_scan(scan_id, url, config):
    """Celery task for background scanning"""
    engine = get_scan_engine()
    findings = engine.scan(url, config)
    
    scan = Scan.objects.get(id=scan_id)
    engine.save_findings_to_db(scan, findings)
    
    return {
        'scan_id': scan_id,
        'findings_count': len(findings),
    }
```

#### 2.4 WebSocket Progress Updates
```python
async def scan_with_progress(scan_id, url):
    """Scan with real-time progress updates via WebSocket"""
    channel_layer = get_channel_layer()
    
    async def update_progress(plugin_name, status):
        await channel_layer.group_send(
            f'scan_{scan_id}',
            {
                'type': 'scan_progress',
                'plugin': plugin_name,
                'status': status,
            }
        )
    
    # Execute scan with progress callbacks
    # ...
```

### Additional Detection Plugins

#### 2.5 SQL Injection Detection Plugin
```python
class SQLInjectionScannerPlugin(BaseScanPlugin):
    """
    Detect SQL injection vulnerabilities.
    
    Integration with existing sql_attacker/sqli_engine.py
    """
    
    @property
    def plugin_id(self) -> str:
        return 'sqli_scanner'
    
    def scan(self, url: str, config=None):
        # Use existing SQLInjectionEngine
        # Test common SQLi patterns
        # Return findings
        pass
```

#### 2.6 CSRF Detection Plugin
```python
class CSRFScannerPlugin(BaseScanPlugin):
    """Detect missing CSRF protection"""
    
    def scan(self, url: str, config=None):
        # Check for CSRF tokens in forms
        # Verify CSRF headers
        # Test CSRF protection
        pass
```

#### 2.7 Authentication Bypass Plugin
```python
class AuthBypassScannerPlugin(BaseScanPlugin):
    """Detect authentication bypass vulnerabilities"""
    
    def scan(self, url: str, config=None):
        # Test common bypass techniques
        # Check for exposed admin panels
        # Verify authentication mechanisms
        pass
```

### Performance Enhancements

- **Caching**: Cache scan results for duplicate URLs
- **Rate Limiting**: Respect target rate limits
- **Connection Pooling**: Reuse HTTP connections
- **Parallel Execution**: Run plugins concurrently

## Phase 3: Advanced Features & UI (PLANNED)

### Timeline: Q2 2026

### 3.1 Plugin Configuration UI
```
┌─────────────────────────────────────────┐
│ Scanner Configuration                   │
├─────────────────────────────────────────┤
│ Available Plugins:                      │
│                                         │
│ ☑ XSS Scanner                          │
│   └─ ☑ Check forms                     │
│   └─ ☑ Check reflections              │
│   └─ Depth: [2 ▼]                     │
│                                         │
│ ☑ Security Headers Scanner             │
│   └─ ☑ X-Frame-Options                │
│   └─ ☑ CSP                            │
│                                         │
│ ☑ SSL Scanner                          │
│   └─ ☑ Certificate validation          │
│                                         │
│ [Start Scan] [Save Template]            │
└─────────────────────────────────────────┘
```

### 3.2 Scan Templates
```python
class ScanTemplate(models.Model):
    """Predefined scan configurations"""
    name = models.CharField(max_length=255)
    description = models.TextField()
    enabled_plugins = models.JSONField()
    plugin_config = models.JSONField()
    
    # Predefined templates
    # - Quick Scan (fast, basic checks)
    # - Deep Scan (all plugins, thorough)
    # - Compliance Scan (OWASP Top 10, etc.)
    # - Custom templates...
```

### 3.3 Scan Scheduling
```python
class ScheduledScan(models.Model):
    """Scheduled recurring scans"""
    target = models.ForeignKey(ScanTarget)
    template = models.ForeignKey(ScanTemplate)
    schedule = models.CharField()  # Cron expression
    enabled = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True)
    next_run = models.DateTimeField()
```

### 3.4 Incremental Scanning
```python
class IncrementalScanner:
    """Only scan changed content"""
    
    def scan_incremental(self, url, previous_scan_id):
        # Compare with previous scan
        # Only scan modified pages
        # Merge with previous results
        pass
```

### 3.5 Result Deduplication
```python
class VulnerabilityDeduplicator:
    """Identify and merge duplicate findings"""
    
    def deduplicate(self, findings):
        # Group by similarity
        # Merge duplicates
        # Track across multiple scans
        pass
```

## Phase 4: Ecosystem & Marketplace (FUTURE)

### Timeline: Q3-Q4 2026

### 4.1 Plugin Marketplace
- Community-contributed plugins
- Plugin ratings and reviews
- Automated testing and validation
- Versioning and updates

### 4.2 Plugin SDK
```bash
# CLI tool for plugin development
megido-sdk create-plugin my_scanner
megido-sdk test my_scanner
megido-sdk publish my_scanner
```

### 4.3 Plugin Packaging
```python
# setup.py for plugin distribution
from setuptools import setup

setup(
    name='megido-plugin-my-scanner',
    version='1.0.0',
    entry_points={
        'megido.scan_plugins': [
            'my_scanner = my_plugin:MyScannerPlugin',
        ],
    },
)
```

### 4.4 Advanced Integrations
- **CI/CD Integration**: GitHub Actions, GitLab CI
- **Issue Trackers**: Jira, GitHub Issues
- **Notifications**: Slack, Email, PagerDuty
- **Reporting**: PDF, HTML, JSON exports
- **API Extensions**: GraphQL API

## Migration Guide for Developers

### Adding a New Detection Plugin

1. **Create plugin file**: `scanner/scan_plugins/detectors/my_plugin.py`
2. **Implement plugin class**:
```python
from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

class MyPlugin(BaseScanPlugin):
    @property
    def plugin_id(self) -> str:
        return 'my_plugin'
    
    # Implement other required methods...
```
3. **Plugin is auto-discovered** on next import
4. **Test your plugin**: Use `demo_plugin_scanner_standalone.py`

### Converting Existing Checks to Plugins

**Before:**
```python
# In perform_basic_scan()
if some_condition:
    Vulnerability.objects.create(
        scan=scan,
        vulnerability_type='some_type',
        # ...
    )
```

**After:**
```python
# In your plugin
def scan(self, url, config):
    findings = []
    if some_condition:
        finding = VulnerabilityFinding(
            vulnerability_type='some_type',
            # ...
        )
        findings.append(finding)
    return findings
```

## Breaking Changes

**None** - Phase 1 is fully backward compatible.

Future phases will maintain compatibility or provide migration paths.

## Performance Impact

### Phase 1
- **Negligible impact**: Plugin overhead is minimal
- **Same functionality**: Performs identical checks
- **Better structure**: Easier to maintain and extend

### Phase 2 (Expected)
- **Faster**: Async execution reduces total scan time
- **Scalable**: Can handle concurrent scans
- **Efficient**: Better resource utilization

## Testing Strategy

### Phase 1 ✅
- [x] Unit tests for each plugin
- [x] Integration tests for scan engine
- [x] Backward compatibility tests
- [x] Demo scripts validation

### Phase 2 (Planned)
- [ ] Async operation tests
- [ ] Performance benchmarks
- [ ] Load testing
- [ ] Concurrency tests

### Phase 3 (Planned)
- [ ] UI/UX testing
- [ ] Template functionality tests
- [ ] Scheduling system tests
- [ ] End-to-end workflows

## Rollback Plan

If issues arise, rollback is simple:

1. **Revert views.py**: Restore old `perform_basic_scan()` implementation
2. **Remove imports**: Remove `scan_engine` imports
3. **Keep plugins**: Plugin system can remain for future use

## Success Metrics

### Phase 1 ✅
- [x] 3+ plugins implemented
- [x] 100% backward compatibility
- [x] Comprehensive documentation
- [x] Working demos

### Phase 2 (Targets)
- [ ] 8+ total plugins
- [ ] 2x faster scan time (via async)
- [ ] Real-time progress tracking
- [ ] Background scan capability

### Phase 3 (Targets)
- [ ] Plugin configuration UI
- [ ] Scan templates system
- [ ] Scheduled scans
- [ ] 95%+ user satisfaction

## Support & Questions

- **Documentation**: See SCANNER_PLUGIN_GUIDE.md
- **Examples**: Check existing plugins in `detectors/`
- **Issues**: Open GitHub issue
- **Contributing**: See contribution guidelines

## Conclusion

Phase 1 successfully modernizes the scanner architecture with:
- ✅ Modular, extensible plugin system
- ✅ Clean separation of concerns
- ✅ Future-ready for async operations
- ✅ 100% backward compatible
- ✅ Comprehensive documentation

The foundation is set for future enhancements while maintaining stability and compatibility.
