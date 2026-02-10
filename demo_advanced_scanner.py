#!/usr/bin/env python3
"""
Demo script for Advanced Vulnerability Scanner

This script demonstrates enterprise-grade features including:
- Risk scoring and prioritization
- Incremental scanning with change tracking
- False positive management
- Compliance framework mapping
- Automated remediation suggestions
- Performance profiling
- Plugin system
"""

import tempfile
import os
import json
from discover.sensitive_scanner_advanced import (
    AdvancedVulnerabilityScanner,
    RiskScoringEngine,
    IncrementalScanner,
    FalsePositiveManager,
    ComplianceMapper,
    ComplianceFramework,
    RemediationEngine,
    PerformanceProfiler,
    PluginManager,
    GitSecretsScannerPlugin
)


def demo_risk_scoring():
    """Demonstrate risk scoring and prioritization."""
    print("=" * 70)
    print("DEMO 1: Risk Scoring and Prioritization")
    print("=" * 70)
    
    # Create test files with different risk levels
    files = []
    test_data = [
        ("critical_secret.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE", True),
        ("low_risk.txt", "support@example.com", False),
        ("api_config.yaml", "api_key: my-secret-api-key", True)
    ]
    
    with tempfile.TemporaryDirectory() as temp_dir:
        for filename, content, is_config in test_data:
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            files.append(filepath)
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=False,
            enable_risk_scoring=True,
            enable_incremental_scan=False,
            enable_false_positive_mgmt=False,
            exposure_level='high'
        )
        
        result = scanner.scan_with_advanced_features(
            files,
            target_type='file',
            incremental=False
        )
        
        print(f"\nFiles scanned: {result['targets_scanned']}")
        print(f"Findings: {result['findings_count']}")
        
        if result['findings']:
            print("\nFindings by Risk Score (highest first):")
            for i, finding in enumerate(result['findings'][:5], 1):
                risk = finding['risk_score']
                print(f"\n{i}. {finding['type']}")
                print(f"   Risk Level: {risk['risk_level'].upper()}")
                print(f"   Composite Score: {risk['composite_score']:.1f}/100")
                print(f"   Source: {os.path.basename(finding['source'])}")


def demo_incremental_scanning():
    """Demonstrate incremental scanning."""
    print("\n" + "=" * 70)
    print("DEMO 2: Incremental Scanning")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test files
        files = []
        for i in range(3):
            filepath = os.path.join(temp_dir, f"file{i}.py")
            with open(filepath, 'w') as f:
                f.write(f"api_key = 'secret-key-{i}'")
            files.append(filepath)
        
        state_file = os.path.join(temp_dir, 'scan_state.pkl')
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=False,
            enable_risk_scoring=False,
            enable_incremental_scan=True,
            state_file=state_file
        )
        
        # First scan
        print("\n--- First Scan (All files) ---")
        result1 = scanner.scan_with_advanced_features(
            files,
            target_type='file',
            incremental=True
        )
        print(f"Files scanned: {result1['targets_scanned']}")
        
        # Second scan (no changes)
        print("\n--- Second Scan (No changes) ---")
        result2 = scanner.scan_with_advanced_features(
            files,
            target_type='file',
            incremental=True
        )
        print(f"Files scanned: {result2['targets_scanned']} (cached)")
        
        # Modify one file
        with open(files[1], 'w') as f:
            f.write("api_key = 'new-secret-key'")
        
        # Third scan (one changed file)
        print("\n--- Third Scan (1 file modified) ---")
        result3 = scanner.scan_with_advanced_features(
            files,
            target_type='file',
            incremental=True
        )
        print(f"Files scanned: {result3['targets_scanned']} (1 changed)")


def demo_false_positive_management():
    """Demonstrate false positive management."""
    print("\n" + "=" * 70)
    print("DEMO 3: False Positive Management")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, 'w') as f:
            f.write("""
api_key = 'test-key-for-demo'
email = 'test@example.com'
aws_key = 'AKIAIOSFODNN7EXAMPLE'
            """)
        
        allowlist_file = os.path.join(temp_dir, 'allowlist.json')
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=False,
            enable_risk_scoring=False,
            enable_false_positive_mgmt=True,
            allowlist_file=allowlist_file
        )
        
        # First scan
        result1 = scanner.scan_with_advanced_features(
            [test_file],
            target_type='file',
            incremental=False
        )
        
        print(f"\nInitial scan findings: {len(result1['findings'])}")
        
        # Classify one as false positive
        if result1['findings']:
            finding_to_ignore = result1['findings'][0]
            print(f"\nClassifying as false positive: {finding_to_ignore['type']}")
            scanner.fp_manager.classify_finding(
                finding_to_ignore,
                'false_positive',
                'This is a test key used for demos',
                'security_team'
            )
        
        # Second scan with filtering
        result2 = scanner.scan_with_advanced_features(
            [test_file],
            target_type='file',
            incremental=False
        )
        
        print(f"After filtering: {len(result2['findings'])} findings")
        print(f"False positives filtered: {len(result1['findings']) - len(result2['findings'])}")


def demo_compliance_mapping():
    """Demonstrate compliance framework mapping."""
    print("\n" + "=" * 70)
    print("DEMO 4: Compliance Framework Mapping")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file with various sensitive data
        test_file = os.path.join(temp_dir, "config.env")
        with open(test_file, 'w') as f:
            f.write("""
AWS_KEY=AKIAIOSFODNN7EXAMPLE
DB_PASSWORD=secret_password_123
CREDIT_CARD=4532015112830366
            """)
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=False,
            enable_risk_scoring=False,
            enable_compliance_mapping=True
        )
        
        result = scanner.scan_with_advanced_features(
            [test_file],
            target_type='file',
            incremental=False
        )
        
        print(f"\nFindings: {len(result['findings'])}")
        
        if result['compliance_report']:
            report = result['compliance_report']
            print(f"\nCompliance Violations: {report['total_violations']}")
            print(f"Affected Frameworks: {', '.join(report['affected_frameworks'])}")
            
            print("\nViolations by Framework:")
            for framework, findings in report['frameworks'].items():
                print(f"  {framework.upper()}: {len(findings)} violation(s)")


def demo_remediation_suggestions():
    """Demonstrate automated remediation suggestions."""
    print("\n" + "=" * 70)
    print("DEMO 5: Automated Remediation Suggestions")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test file with security issues
        test_file = os.path.join(temp_dir, "insecure_code.py")
        with open(test_file, 'w') as f:
            f.write("""
# Insecure code examples
aws_key = "AKIAIOSFODNN7EXAMPLE"
password = "mypassword123"
api_key = "sk-test-1234567890"
            """)
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=False,
            enable_risk_scoring=False,
            enable_remediation=True
        )
        
        result = scanner.scan_with_advanced_features(
            [test_file],
            target_type='file',
            incremental=False
        )
        
        if result['remediation_report']:
            report = result['remediation_report']
            print(f"\nTotal remediation items: {report['total_items']}")
            print(f"Effort distribution:")
            for level, count in report['effort_distribution'].items():
                if count > 0:
                    print(f"  {level.capitalize()}: {count}")
            print(f"Estimated total effort: {report['estimated_total_effort']}")
            
            print("\nTop Remediation Suggestions:")
            for i, item in enumerate(report['remediations'][:3], 1):
                rem = item['remediation']
                print(f"\n{i}. {rem['finding_type']}")
                print(f"   Action: {rem['action']}")
                print(f"   Effort: {rem['effort_estimate']}")
                print(f"   Priority: {'★' * rem['priority']}")


def demo_performance_profiling():
    """Demonstrate performance profiling."""
    print("\n" + "=" * 70)
    print("DEMO 6: Performance Profiling")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create multiple test files
        files = []
        for i in range(10):
            filepath = os.path.join(temp_dir, f"file{i}.py")
            with open(filepath, 'w') as f:
                f.write(f"api_key = 'key-{i}'\npassword = 'pass-{i}'")
            files.append(filepath)
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=True,
            enable_risk_scoring=True,
            enable_profiling=True
        )
        
        # Run scan
        result = scanner.scan_with_advanced_features(
            files,
            target_type='file',
            incremental=False
        )
        
        if result['performance_metrics']:
            metrics = result['performance_metrics']
            print(f"\nScan Performance:")
            print(f"  Duration: {metrics['duration_seconds']:.3f} seconds")
            print(f"  Files scanned: {metrics['files_scanned']}")
            print(f"  Patterns matched: {metrics['patterns_matched']}")
            print(f"  Findings: {metrics['findings_count']}")
            print(f"  Memory usage: {metrics['memory_usage_mb']:.1f} MB")
            print(f"  Throughput: {metrics['files_scanned']/metrics['duration_seconds']:.1f} files/sec")


def demo_plugin_system():
    """Demonstrate plugin system."""
    print("\n" + "=" * 70)
    print("DEMO 7: Plugin System")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test files
        files = [
            os.path.join(temp_dir, "code.py"),
            os.path.join(temp_dir, ".gitignore"),
            os.path.join(temp_dir, "config.yaml")
        ]
        
        for filepath in files:
            with open(filepath, 'w') as f:
                f.write("api_key = 'test-key'")
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=False,
            enable_plugins=True
        )
        
        # Register plugin
        plugin = GitSecretsScannerPlugin()
        scanner.plugin_manager.register_plugin(plugin)
        
        print(f"\nLoaded plugins:")
        for info in scanner.plugin_manager.get_plugin_info():
            print(f"  - {info['name']} v{info['version']}")
        
        # Scan with plugin
        result = scanner.scan_with_advanced_features(
            files,
            target_type='file',
            incremental=False
        )
        
        print(f"\nFiles requested: {len(files)}")
        print(f"Files scanned: {result['targets_scanned']}")
        print("(Plugin filtered .gitignore)")
        
        if result['findings']:
            finding = result['findings'][0]
            if 'git_metadata' in finding:
                print("\nPlugin added metadata:")
                print(f"  Git metadata: {finding['git_metadata']}")


def demo_comprehensive_scan():
    """Demonstrate all features together."""
    print("\n" + "=" * 70)
    print("DEMO 8: Comprehensive Scan (All Features)")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create realistic test files
        files_content = {
            ".env": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=secret123",
            "config.py": "API_KEY = 'my-api-key-12345'",
            "app.py": "email = 'user@example.com'"
        }
        
        files = []
        for filename, content in files_content.items():
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            files.append(filepath)
        
        # Initialize scanner with all features
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=True,
            enable_risk_scoring=True,
            enable_incremental_scan=False,
            enable_false_positive_mgmt=True,
            enable_compliance_mapping=True,
            enable_remediation=True,
            enable_profiling=True,
            enable_plugins=False,
            exposure_level='high'
        )
        
        # Run comprehensive scan
        result = scanner.scan_with_advanced_features(
            files,
            target_type='file',
            incremental=False
        )
        
        print("\n📊 SCAN SUMMARY")
        print("─" * 70)
        print(f"Files scanned: {result['targets_scanned']}")
        print(f"Findings: {result['findings_count']}")
        
        if result['findings']:
            # Risk distribution
            risk_levels = {}
            for finding in result['findings']:
                level = finding['risk_score']['risk_level']
                risk_levels[level] = risk_levels.get(level, 0) + 1
            
            print(f"\nRisk Distribution:")
            for level in ['critical', 'high', 'medium', 'low']:
                if level in risk_levels:
                    print(f"  {level.capitalize()}: {risk_levels[level]}")
        
        if result['compliance_report']:
            report = result['compliance_report']
            print(f"\nCompliance:")
            print(f"  Total violations: {report['total_violations']}")
            print(f"  Frameworks affected: {len(report['affected_frameworks'])}")
        
        if result['remediation_report']:
            report = result['remediation_report']
            print(f"\nRemediation:")
            print(f"  Items to fix: {report['total_items']}")
            print(f"  Estimated effort: {report['estimated_total_effort']}")
        
        if result['performance_metrics']:
            metrics = result['performance_metrics']
            print(f"\nPerformance:")
            print(f"  Scan time: {metrics['duration_seconds']:.3f}s")
            print(f"  Memory: {metrics['memory_usage_mb']:.1f} MB")


def main():
    """Run all demonstrations."""
    print("\n" + "=" * 70)
    print("Advanced Vulnerability Scanner - Feature Demonstrations")
    print("Enterprise-Grade Security Scanning")
    print("=" * 70)
    
    demos = [
        demo_risk_scoring,
        demo_incremental_scanning,
        demo_false_positive_management,
        demo_compliance_mapping,
        demo_remediation_suggestions,
        demo_performance_profiling,
        demo_plugin_system,
        demo_comprehensive_scan
    ]
    
    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"\nError in {demo.__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("All demonstrations completed!")
    print("=" * 70)
    print("\nFor more information, see ADVANCED_SCANNER_GUIDE.md")


if __name__ == '__main__':
    main()
