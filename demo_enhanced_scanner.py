#!/usr/bin/env python3
"""
Demo script for the Enhanced Vulnerability Scanner

This script demonstrates the various features of the enhanced scanner including:
- Basic URL and file scanning
- Pattern-based detection
- Heuristic detection
- External pattern loading
- Caching
- Context awareness
"""

import tempfile
import os
import json
from discover.sensitive_scanner_enhanced import (
    EnhancedSensitiveInfoScanner,
    SensitivePatterns,
    ExternalPatternProvider,
    HeuristicScanner,
    ContextAnalyzer,
    scan_discovered_urls_enhanced
)


def demo_basic_scanning():
    """Demonstrate basic scanning capabilities."""
    print("=" * 70)
    print("DEMO 1: Basic Pattern Detection")
    print("=" * 70)
    
    # Create a test file with sensitive data (using safe test patterns)
    test_content = """
    # Configuration File
    AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"
    database_url = "postgres://user:password@localhost/mydb"
    secret_key = "my-secret-key-value-here-1234567890"
    JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write(test_content)
        temp_file = f.name
    
    try:
        scanner = EnhancedSensitiveInfoScanner(
            enable_heuristics=False,
            log_level='WARNING'
        )
        
        result = scanner.scan_file(temp_file)
        
        print(f"\nScanned file: {temp_file}")
        print(f"Success: {result['success']}")
        print(f"Findings: {len(result['findings'])}")
        
        # Group by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for finding in result['findings']:
            severity = finding.get('severity', 'medium')
            by_severity[severity].append(finding)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if by_severity[severity]:
                print(f"\n{severity.upper()} severity findings: {len(by_severity[severity])}")
                for finding in by_severity[severity][:3]:  # Show first 3
                    print(f"  - {finding['type']}: {finding['value'][:50]}...")
    finally:
        os.unlink(temp_file)


def demo_heuristic_detection():
    """Demonstrate heuristic detection."""
    print("\n" + "=" * 70)
    print("DEMO 2: Heuristic Detection (Entropy Analysis)")
    print("=" * 70)
    
    # Content with high-entropy strings
    test_content = """
    # Some configuration
    normal_text = "hello world"
    suspicious_token = "aB3xK9mN2pQ7vY1zL4wR6sT8uH5jF0dG2eI9wX"
    another_key = "mQpL8kJ4nH7gF2dS9aZ6xC1vB5nM3wR0"
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(test_content)
        temp_file = f.name
    
    try:
        scanner = EnhancedSensitiveInfoScanner(
            enable_heuristics=True,
            log_level='WARNING'
        )
        
        result = scanner.scan_file(temp_file)
        
        print(f"\nScanned file: {temp_file}")
        print(f"Total findings: {len(result['findings'])}")
        
        # Show heuristic findings
        heuristic_findings = [f for f in result['findings'] 
                            if f.get('detection_method') == 'heuristic']
        
        print(f"\nHeuristic findings: {len(heuristic_findings)}")
        for finding in heuristic_findings:
            print(f"\n  Type: {finding['type']}")
            print(f"  Value: {finding['value'][:50]}...")
            if 'entropy' in finding:
                print(f"  Entropy: {finding['entropy']}")
    finally:
        os.unlink(temp_file)


def demo_external_patterns():
    """Demonstrate loading external patterns."""
    print("\n" + "=" * 70)
    print("DEMO 3: External Pattern Provider")
    print("=" * 70)
    
    # Create custom pattern file
    custom_patterns = {
        "patterns": {
            "Custom API Key": r"custom_[0-9a-f]{32}",
            "Service Token": r"srv_tok_[A-Za-z0-9]{40}"
        },
        "severity": {
            "Custom API Key": "high",
            "Service Token": "critical"
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(custom_patterns, f)
        pattern_file = f.name
    
    # Create test content with custom patterns
    test_content = """
    custom_key = "custom_abc123def456789012345678901234"
    service_token = "srv_tok_abcdefghijklmnopqrstuvwxyz1234567890"
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(test_content)
        test_file = f.name
    
    try:
        # Create external provider
        external_provider = ExternalPatternProvider(source_file=pattern_file)
        
        # Create scanner with both built-in and external patterns
        scanner = EnhancedSensitiveInfoScanner(
            pattern_providers=[
                SensitivePatterns(),
                external_provider
            ],
            enable_heuristics=False,
            log_level='WARNING'
        )
        
        result = scanner.scan_file(test_file)
        
        print(f"\nScanned file with custom patterns: {test_file}")
        print(f"Total patterns loaded: {len(scanner.patterns)}")
        print(f"Findings: {len(result['findings'])}")
        
        for finding in result['findings']:
            print(f"\n  Type: {finding['type']}")
            print(f"  Severity: {finding['severity']}")
            print(f"  Value: {finding['value'][:50]}")
    finally:
        os.unlink(pattern_file)
        os.unlink(test_file)


def demo_directory_scanning():
    """Demonstrate directory scanning."""
    print("\n" + "=" * 70)
    print("DEMO 4: Directory Scanning with File Patterns")
    print("=" * 70)
    
    # Create temporary directory with multiple files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create various config files
        files = {
            '.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASS=secretpass123',
            'config.yaml': 'api_key: ghp_123456789012345678901234567890123456',
            'settings.py': 'SECRET_KEY = "django-secret-key-12345"',
            'readme.txt': 'This is just documentation',
        }
        
        for filename, content in files.items():
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
        
        scanner = EnhancedSensitiveInfoScanner(
            enable_heuristics=False,
            log_level='WARNING'
        )
        
        # Scan only config files
        results = scanner.scan_directory(
            temp_dir,
            recursive=False,
            file_patterns=['*.env', '*.yaml', '*.yml', '*.config']
        )
        
        print(f"\nScanned directory: {temp_dir}")
        print(f"Files scanned: {len(results)}")
        
        total_findings = sum(len(r['findings']) for r in results if r['success'])
        print(f"Total findings: {total_findings}")
        
        for result in results:
            if result['success'] and result['findings']:
                filename = os.path.basename(result['source'])
                print(f"\n  File: {filename}")
                print(f"  Findings: {len(result['findings'])}")
                for finding in result['findings'][:2]:  # Show first 2
                    print(f"    - {finding['type']}: {finding['severity']}")


def demo_context_analysis():
    """Demonstrate context awareness."""
    print("\n" + "=" * 70)
    print("DEMO 5: Context Analysis")
    print("=" * 70)
    
    # Set a test environment variable
    os.environ['DEMO_API_KEY'] = 'test_key_12345'
    
    try:
        # Test environment correlation
        result = ContextAnalyzer.check_environment_correlation('test_key_12345')
        
        print("\nEnvironment Variable Correlation:")
        print(f"Has correlation: {result['has_correlation']}")
        if result['correlations']:
            for corr in result['correlations']:
                print(f"  - Variable: {corr['name']}")
                print(f"    Match type: {corr['match']}")
        
        # Test config file detection
        config_files = [
            '/path/to/.env',
            '/path/to/config.yaml',
            '/path/to/script.py',
            '/path/to/readme.txt'
        ]
        
        print("\nConfiguration File Detection:")
        for filepath in config_files:
            result = ContextAnalyzer.detect_config_file_context(filepath)
            print(f"\n  File: {os.path.basename(filepath)}")
            print(f"  Is config: {result['is_config_file']}")
            print(f"  Risk level: {result['risk_level']}")
    finally:
        del os.environ['DEMO_API_KEY']


def demo_caching():
    """Demonstrate caching functionality."""
    print("\n" + "=" * 70)
    print("DEMO 6: Result Caching")
    print("=" * 70)
    
    test_content = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(test_content)
        temp_file = f.name
    
    try:
        scanner = EnhancedSensitiveInfoScanner(
            enable_heuristics=False,
            cache_ttl=60,  # 1 minute cache
            log_level='WARNING'
        )
        
        import time
        
        # First scan
        start1 = time.time()
        result1 = scanner.scan_file(temp_file)
        time1 = time.time() - start1
        
        # Second scan (cached)
        start2 = time.time()
        result2 = scanner.scan_file(temp_file)
        time2 = time.time() - start2
        
        print(f"\nFirst scan time: {time1*1000:.2f}ms")
        print(f"Second scan time (cached): {time2*1000:.2f}ms")
        print(f"Speedup: {time1/time2:.1f}x faster")
        print(f"\nResults identical: {result1 == result2}")
        
        # Show cache statistics
        print(f"\nCache entries: {len(scanner.cache._cache)}")
    finally:
        os.unlink(temp_file)


def demo_severity_classification():
    """Demonstrate severity-based classification."""
    print("\n" + "=" * 70)
    print("DEMO 7: Severity Classification and Prioritization")
    print("=" * 70)
    
    test_content = """
    # Mix of different severity findings
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"                    # Critical
    email = "user@example.com"                          # Low
    bearer_token = "Bearer abc123def456"                # High
    private_ip = "192.168.1.100"                        # Low
    postgres_url = "postgres://user:pass@host/db"      # Critical
    slack_webhook = "https://hooks.slack.com/services/T12345/B67890/abcdef"  # High
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(test_content)
        temp_file = f.name
    
    try:
        scanner = EnhancedSensitiveInfoScanner(
            enable_heuristics=False,
            log_level='WARNING'
        )
        
        result = scanner.scan_file(temp_file)
        
        # Group by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for finding in result['findings']:
            severity = finding.get('severity', 'medium')
            by_severity[severity].append(finding)
        
        print(f"\nTotal findings: {len(result['findings'])}")
        print("\nFindings by Severity:")
        
        for severity in ['critical', 'high', 'medium', 'low']:
            count = len(by_severity[severity])
            if count > 0:
                print(f"\n{severity.upper()}: {count} finding(s)")
                for finding in by_severity[severity]:
                    print(f"  - {finding['type']}")
    finally:
        os.unlink(temp_file)


def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print("Enhanced Vulnerability Scanner - Feature Demonstrations")
    print("=" * 70)
    
    demos = [
        demo_basic_scanning,
        demo_heuristic_detection,
        demo_external_patterns,
        demo_directory_scanning,
        demo_context_analysis,
        demo_caching,
        demo_severity_classification,
    ]
    
    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"\nError in {demo.__name__}: {e}")
    
    print("\n" + "=" * 70)
    print("All demos completed!")
    print("=" * 70)
    print("\nFor more information, see VULNERABILITY_SCANNER_ENHANCEMENT.md")


if __name__ == '__main__':
    main()
