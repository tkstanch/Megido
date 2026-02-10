# Advanced Vulnerability Scanner - Complete Guide

## Overview

The Advanced Vulnerability Scanner extends the enhanced scanner with enterprise-grade features for production security scanning. It provides risk-based prioritization, incremental scanning, compliance mapping, automated remediation, and comprehensive reporting.

## Architecture

```
Vulnerability Scanner Evolution:
├── sensitive_scanner.py (Original)          # Basic pattern matching
├── sensitive_scanner_enhanced.py (Enhanced) # Pluggable patterns, heuristics, ML templates
└── sensitive_scanner_advanced.py (Advanced) # Enterprise features
```

## Enterprise Features

### 1. Risk Scoring & Prioritization

**Purpose**: Calculate composite risk scores to prioritize critical findings.

**Algorithm**:
```
Risk Score = base_severity × (1 + context + exposure) × (1 + entropy) × age
- Base Severity: critical=10, high=7.5, medium=5, low=2.5
- Context Factor: Config files=2.0, URLs=1.5, Regular files=1.0
- Exposure Factor: high=1.5, medium=1.0, low=0.5
- Entropy Factor: 0.0-1.0 (normalized Shannon entropy)
- Age Factor: 1.0 (newer) to 0.5 (older)
- Final Score: 0-100
```

**Risk Levels**:
- Critical: 80-100
- High: 60-79
- Medium: 40-59
- Low: 20-39
- Info: 0-19

**Usage**:
```python
from discover.sensitive_scanner_advanced import RiskScoringEngine

engine = RiskScoringEngine(exposure_level='high')

finding = {
    'type': 'AWS Access Key',
    'severity': 'critical',
    'source_type': 'file',
    'file_context': {'is_config_file': True}
}

risk_score = engine.calculate_risk_score(finding)
print(f"Risk: {risk_score.risk_level} ({risk_score.composite_score:.1f}/100)")

# Prioritize multiple findings
findings = [...]  # List of findings
prioritized = engine.prioritize_findings(findings)
# Returns findings sorted by risk score (highest first)
```

### 2. Incremental Scanning

**Purpose**: Track file changes and only scan modified files for speed.

**Features**:
- MD5 checksum-based change detection
- Scan history persistence
- State file management
- 10x+ faster on unchanged files

**Usage**:
```python
from discover.sensitive_scanner_advanced import IncrementalScanner

scanner = IncrementalScanner(state_file='.scan_state.pkl')

files = ['file1.py', 'file2.py', 'file3.py']

# Get only changed files
changed_files = scanner.get_changed_files(files)
print(f"Changed: {len(changed_files)}/{len(files)}")

# After scanning, update state
for file in changed_files:
    findings_count = scan_file(file)  # Your scan logic
    scanner.update_file_state(file, findings_count)

scanner.save()  # Persist state to disk

# Statistics
stats = scanner.get_scan_statistics()
print(f"Files tracked: {stats['total_files_tracked']}")
print(f"With findings: {stats['files_with_findings']}")
```

### 3. False Positive Management

**Purpose**: Learn from user feedback to reduce false positives.

**Features**:
- Finding classification (true positive, false positive, acceptable risk)
- Allowlist persistence
- Pattern ignore list
- Automatic filtering

**Usage**:
```python
from discover.sensitive_scanner_advanced import FalsePositiveManager

manager = FalsePositiveManager(allowlist_file='.allowlist.json')

finding = {
    'type': 'AWS Key',
    'value': 'AKIATEST12345',
    'source': 'test.py'
}

# Classify finding
manager.classify_finding(
    finding,
    classification='false_positive',
    reason='This is a test key used in documentation',
    classified_by='security_team'
)

# Check if false positive
if manager.is_false_positive(finding):
    print("Skipping false positive")

# Filter findings list
clean_findings = manager.filter_findings(all_findings)

# Statistics
stats = manager.get_statistics()
print(f"False positives: {stats['false_positives']}")
print(f"True positives: {stats['true_positives']}")
```

### 4. Compliance Framework Mapping

**Purpose**: Map findings to compliance requirements (GDPR, PCI-DSS, OWASP, HIPAA, SOC2).

**Supported Frameworks**:
- **GDPR**: Article 32 (Security of Processing)
- **PCI-DSS**: Requirement 3.4 (Protect Cardholder Data)
- **OWASP Top 10**: A02:2021 (Cryptographic Failures)
- **HIPAA**: 164.312(a)(2)(iv) (Encryption and Decryption)
- **SOC2**: Security controls

**Usage**:
```python
from discover.sensitive_scanner_advanced import ComplianceMapper, ComplianceFramework

mapper = ComplianceMapper()

finding = {
    'type': 'Credit Card Number',
    'value': '4532015112830366'
}

# Get compliance mappings
mappings = mapper.get_compliance_mappings(finding)
for mapping in mappings:
    print(f"{mapping.framework.value}: {mapping.requirement_name}")

# Generate compliance report
findings = [...]  # List of findings
report = mapper.generate_compliance_report(findings)

print(f"Total violations: {report['total_violations']}")
print(f"Affected frameworks: {report['affected_frameworks']}")

# Framework-specific report
gdpr_report = mapper.generate_compliance_report(
    findings,
    framework=ComplianceFramework.GDPR
)
```

### 5. Remediation Engine

**Purpose**: Provide automated fix suggestions with code examples.

**Features**:
- Action recommendations
- Code snippet examples
- Effort estimation (low/medium/high)
- Priority-based sorting
- Reference documentation

**Supported Findings**:
- AWS Access Keys
- API Keys
- Passwords
- Private Keys
- Database Connections
- JWT Tokens
- And more...

**Usage**:
```python
from discover.sensitive_scanner_advanced import RemediationEngine

engine = RemediationEngine()

finding = {
    'type': 'AWS Access Key',
    'value': 'AKIAIOSFODNN7EXAMPLE'
}

# Get remediation suggestion
remediation = engine.get_remediation(finding)
print(f"Action: {remediation.action}")
print(f"Effort: {remediation.effort_estimate}")
print(f"Priority: {remediation.priority}/5")
print(f"\nCode example:\n{remediation.code_snippet}")

# Generate report for all findings
findings = [...]
report = engine.generate_remediation_report(findings)

print(f"Total items: {report['total_items']}")
print(f"Effort: {report['estimated_total_effort']}")
print("\nEffort distribution:")
for level, count in report['effort_distribution'].items():
    print(f"  {level}: {count}")
```

### 6. Performance Profiling

**Purpose**: Track and optimize scanner performance.

**Metrics**:
- Scan duration
- Files/URLs scanned
- Patterns matched
- Findings count
- Cache hits/misses
- Memory usage

**Usage**:
```python
from discover.sensitive_scanner_advanced import PerformanceProfiler

profiler = PerformanceProfiler()

# Start profiling
profiler.start_scan('scan_20260210')

# ... perform scan ...

# End profiling
metrics = profiler.end_scan(
    files_scanned=100,
    urls_scanned=50,
    patterns_matched=25,
    findings_count=15,
    cache_hits=80,
    cache_misses=20
)

print(f"Duration: {metrics.duration_seconds:.2f}s")
print(f"Memory: {metrics.memory_usage_mb:.1f} MB")
print(f"Throughput: {metrics.files_scanned/metrics.duration_seconds:.1f} files/sec")

# Statistics across multiple scans
stats = profiler.get_statistics()
print(f"Average duration: {stats['average_duration_seconds']:.2f}s")
print(f"Cache efficiency: {stats['cache_efficiency_percent']:.1f}%")

# Save metrics to file
profiler.save_metrics('scan_metrics.json')
```

### 7. Plugin System

**Purpose**: Extend scanner with custom functionality.

**Plugin Interface**:
```python
from discover.sensitive_scanner_advanced import PluginInterface

class MyPlugin(PluginInterface):
    def get_name(self) -> str:
        return "MyCustomPlugin"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: dict):
        # Initialize plugin with configuration
        pass
    
    def pre_scan(self, targets: list) -> list:
        # Modify targets before scanning
        # Example: filter out certain files
        return [t for t in targets if not t.endswith('.ignore')]
    
    def post_scan(self, findings: list) -> list:
        # Modify findings after scanning
        # Example: add metadata
        for finding in findings:
            finding['plugin_metadata'] = {'reviewed': False}
        return findings
    
    def analyze_finding(self, finding: dict) -> dict:
        # Analyze individual finding
        # Example: add risk context
        if finding['type'] == 'AWS Key':
            finding['aws_metadata'] = {'needs_rotation': True}
        return finding
```

**Usage**:
```python
from discover.sensitive_scanner_advanced import PluginManager

manager = PluginManager(plugin_dir='plugins')

# Discover plugins from directory
manager.discover_plugins()

# Or register manually
plugin = MyPlugin()
manager.register_plugin(plugin)

# Get plugin info
for info in manager.get_plugin_info():
    print(f"{info['name']} v{info['version']}")

# Plugins are automatically executed during scanning
```

### 8. Advanced Scanner Integration

**Purpose**: Unified interface for all enterprise features.

**Complete Example**:
```python
from discover.sensitive_scanner_advanced import AdvancedVulnerabilityScanner

# Initialize with all features
scanner = AdvancedVulnerabilityScanner(
    # Base scanner options
    timeout=10,
    max_workers=10,
    enable_heuristics=True,
    enable_ml=False,
    cache_ttl=3600,
    log_level='INFO',
    
    # Advanced features
    enable_risk_scoring=True,
    enable_incremental_scan=True,
    enable_false_positive_mgmt=True,
    enable_compliance_mapping=True,
    enable_remediation=True,
    enable_profiling=True,
    enable_plugins=True,
    
    # Configuration
    exposure_level='high',  # low/medium/high
    state_file='.scan_state.pkl',
    allowlist_file='.allowlist.json'
)

# Comprehensive scan
result = scanner.scan_with_advanced_features(
    targets=['file1.py', 'file2.py', 'dir/'],
    target_type='file',  # or 'url'
    incremental=True     # Use incremental scanning
)

# Access results
print(f"Findings: {result['findings_count']}")
print(f"Targets scanned: {result['targets_scanned']}")

# Risk scores
for finding in result['findings'][:5]:  # Top 5
    risk = finding['risk_score']
    print(f"{finding['type']}: {risk['risk_level']} ({risk['composite_score']:.1f}/100)")

# Compliance report
if result['compliance_report']:
    report = result['compliance_report']
    print(f"Compliance violations: {report['total_violations']}")
    for framework, findings in report['frameworks'].items():
        print(f"  {framework}: {len(findings)}")

# Remediation suggestions
if result['remediation_report']:
    report = result['remediation_report']
    print(f"Remediation items: {report['total_items']}")
    print(f"Estimated effort: {report['estimated_total_effort']}")

# Performance metrics
if result['performance_metrics']:
    metrics = result['performance_metrics']
    print(f"Scan duration: {metrics['duration_seconds']:.2f}s")
    print(f"Memory usage: {metrics['memory_usage_mb']:.1f} MB")
```

## Workflow Examples

### CI/CD Integration

```python
#!/usr/bin/env python3
"""CI/CD security scan script."""

from discover.sensitive_scanner_advanced import AdvancedVulnerabilityScanner
import sys
import json

def main():
    scanner = AdvancedVulnerabilityScanner(
        enable_risk_scoring=True,
        enable_incremental_scan=True,  # Fast on unchanged code
        enable_false_positive_mgmt=True,
        exposure_level='high'
    )
    
    # Scan changed files only
    changed_files = get_changed_files_from_git()  # Your git logic
    
    result = scanner.scan_with_advanced_features(
        changed_files,
        target_type='file',
        incremental=True
    )
    
    # Filter by risk level
    critical_findings = [
        f for f in result['findings']
        if f['risk_score']['risk_level'] == 'critical'
    ]
    
    if critical_findings:
        print(f"❌ Found {len(critical_findings)} critical issues!")
        for finding in critical_findings:
            print(f"  - {finding['type']} in {finding['source']}")
        sys.exit(1)
    else:
        print("✅ No critical security issues found")
        sys.exit(0)

if __name__ == '__main__':
    main()
```

### Security Audit Workflow

```python
#!/usr/bin/env python3
"""Security audit with compliance reporting."""

from discover.sensitive_scanner_advanced import AdvancedVulnerabilityScanner
from datetime import datetime
import json

def run_security_audit(project_path):
    scanner = AdvancedVulnerabilityScanner(
        enable_risk_scoring=True,
        enable_compliance_mapping=True,
        enable_remediation=True,
        enable_profiling=True,
        exposure_level='high'
    )
    
    # Scan entire project
    files = list_all_files(project_path)  # Your file discovery logic
    
    result = scanner.scan_with_advanced_features(
        files,
        target_type='file',
        incremental=False
    )
    
    # Generate comprehensive report
    report = {
        'timestamp': datetime.now().isoformat(),
        'project': project_path,
        'summary': {
            'files_scanned': result['targets_scanned'],
            'findings_count': result['findings_count'],
            'scan_duration': result['performance_metrics']['duration_seconds']
        },
        'findings_by_risk': {},
        'compliance': result['compliance_report'],
        'remediation': result['remediation_report']
    }
    
    # Group by risk level
    for finding in result['findings']:
        risk_level = finding['risk_score']['risk_level']
        if risk_level not in report['findings_by_risk']:
            report['findings_by_risk'][risk_level] = []
        report['findings_by_risk'][risk_level].append({
            'type': finding['type'],
            'source': finding['source'],
            'risk_score': finding['risk_score']['composite_score']
        })
    
    # Save report
    with open(f'security_audit_{datetime.now().strftime("%Y%m%d")}.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

if __name__ == '__main__':
    report = run_security_audit('/path/to/project')
    print(f"Audit complete: {report['summary']['findings_count']} findings")
```

## Performance Optimization

### Recommended Settings

**Fast Scans (CI/CD)**:
```python
scanner = AdvancedVulnerabilityScanner(
    max_workers=15,              # High concurrency
    cache_ttl=7200,              # Long cache
    enable_heuristics=False,     # Disable for speed
    enable_incremental_scan=True # Only scan changes
)
```

**Comprehensive Scans (Security Audit)**:
```python
scanner = AdvancedVulnerabilityScanner(
    max_workers=10,
    cache_ttl=3600,
    enable_heuristics=True,      # Full detection
    enable_risk_scoring=True,
    enable_compliance_mapping=True,
    enable_remediation=True,
    enable_incremental_scan=False  # Scan everything
)
```

**Low Resource Scans**:
```python
scanner = AdvancedVulnerabilityScanner(
    max_workers=3,               # Low concurrency
    cache_ttl=1800,
    enable_profiling=False       # Minimize overhead
)
```

## Best Practices

1. **Incremental Scanning**: Use for regular/CI builds to minimize scan time
2. **Risk Prioritization**: Focus on critical/high findings first
3. **False Positive Management**: Review and classify findings to improve accuracy
4. **Compliance Tracking**: Generate regular compliance reports for audits
5. **Performance Monitoring**: Track metrics to optimize scan performance
6. **Plugin Development**: Extend with custom logic for your environment

## Troubleshooting

### Slow Scans
- Enable incremental scanning
- Increase `max_workers`
- Disable heuristics if not needed
- Check cache configuration

### High False Positives
- Use false positive management
- Review and classify findings
- Adjust pattern sensitivity
- Add custom ignore patterns

### Memory Issues
- Reduce `max_workers`
- Clear cache periodically
- Process files in batches
- Disable profiling if not needed

## Migration Guide

### From Enhanced Scanner

```python
# Old (Enhanced Scanner)
from discover.sensitive_scanner_enhanced import EnhancedSensitiveInfoScanner

scanner = EnhancedSensitiveInfoScanner()
results = scanner.scan_files(files)

# New (Advanced Scanner)
from discover.sensitive_scanner_advanced import AdvancedVulnerabilityScanner

scanner = AdvancedVulnerabilityScanner(
    enable_risk_scoring=True,
    enable_incremental_scan=True
)
result = scanner.scan_with_advanced_features(files, target_type='file')

# Same findings accessible, plus additional features
findings = result['findings']  # Risk scores added automatically
compliance = result['compliance_report']
remediation = result['remediation_report']
```

## API Reference

See inline documentation in `sensitive_scanner_advanced.py` for complete API details.

## Testing

Run tests:
```bash
python -m unittest discover.test_sensitive_scanner_advanced -v
```

Run demonstrations:
```bash
python demo_advanced_scanner.py
```

## Support

For issues or questions, refer to the main repository documentation or create an issue.

---

**Version**: 2.0.0  
**Status**: Production Ready  
**Last Updated**: February 2026
