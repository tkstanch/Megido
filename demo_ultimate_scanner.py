#!/usr/bin/env python3
"""
Demo for the Most Advanced Ultimate Vulnerability Scanner

This demonstrates cutting-edge features:
- Real AI/ML integration
- Interactive HTML dashboards
- SARIF format for IDE integration
- Advanced visualization
"""

import tempfile
import os
from discover.sensitive_scanner_ultimate import (
    UltimateVulnerabilityScanner,
    quick_scan
)


def demo_ultimate_scanner():
    """Demonstrate the ultimate scanner with all features."""
    print("=" * 70)
    print("ULTIMATE VULNERABILITY SCANNER DEMONSTRATION")
    print("Cutting-Edge AI-Powered Security Scanning")
    print("=" * 70)
    
    # Create test files with various issues
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create realistic test files
        test_files = {
            "config.env": """
# Production Configuration
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://user:pass@prod.example.com:5432/maindb
API_KEY=test_api_key_for_demo_purposes_only
            """,
            
            "api_keys.py": """
# API Configuration
OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz12345"
GITHUB_TOKEN = "******"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T123/B456/abc"
JWT_SECRET = "super-secret-jwt-key-12345"
            """,
            
            "credentials.yaml": """
services:
  database:
    host: localhost
    username: admin
    password: MySecretP@ssw0rd123
  
  redis:
    url: redis://:secretpass@localhost:6379/0
    
  smtp:
    username: alerts@company.com
    password: EmailP@ss123
            """,
            
            "app.js": """
// Application Configuration
const config = {
    apiKey: 'prod_api_key_abcdef123456',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----',
    sessionSecret: 'my-session-secret-key',
    creditCard: '4532015112830366'  // Test card
};
            """
        }
        
        # Write test files
        for filename, content in test_files.items():
            with open(os.path.join(temp_dir, filename), 'w') as f:
                f.write(content)
        
        print(f"\n📁 Created {len(test_files)} test files with security issues")
        
        # Initialize ultimate scanner with all features
        print("\n🚀 Initializing Ultimate Scanner...")
        scanner = UltimateVulnerabilityScanner(
            enable_ai_ml=True,              # AI/ML detection
            enable_dashboard_generation=True,  # HTML dashboard
            enable_sarif_output=True,       # SARIF for IDEs
            enable_risk_scoring=True,       # Risk prioritization
            enable_incremental_scan=False,  # Full scan
            enable_compliance_mapping=True, # Compliance frameworks
            enable_remediation=True,        # Fix suggestions
            enable_profiling=True,          # Performance metrics
            enable_heuristics=True,         # Pattern-independent detection
            exposure_level='high'           # High risk environment
        )
        
        # Collect files
        files = [os.path.join(temp_dir, f) for f in test_files.keys()]
        
        # Create output directory
        output_dir = os.path.join(temp_dir, 'scan_results')
        
        print("\n🔍 Starting comprehensive security scan...")
        print("   - AI/ML anomaly detection")
        print("   - Risk-based prioritization")
        print("   - Compliance framework mapping")
        print("   - Interactive dashboard generation")
        print("   - SARIF format for IDE integration")
        
        # Perform scan
        result = scanner.scan_with_ultimate_features(
            files,
            target_type='file',
            incremental=False,
            output_dir=output_dir
        )
        
        # Display results
        print("\n" + "=" * 70)
        print("SCAN RESULTS")
        print("=" * 70)
        
        print(f"\n📊 Statistics:")
        print(f"   Files scanned: {result['targets_scanned']}")
        print(f"   Total findings: {result['findings_count']}")
        
        # Risk distribution
        if result['findings']:
            risk_dist = {}
            for finding in result['findings']:
                risk = finding.get('risk_score', {}).get('risk_level', 'medium')
                risk_dist[risk] = risk_dist.get(risk, 0) + 1
            
            print(f"\n⚠️  Risk Distribution:")
            for level in ['critical', 'high', 'medium', 'low']:
                if level in risk_dist:
                    emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[level]
                    print(f"   {emoji} {level.upper()}: {risk_dist[level]}")
        
        # ML Analysis
        if 'ml_enabled' in result and result.get('ml_enabled'):
            ml_analyzed = sum(1 for f in result['findings'] if 'ml_analysis' in f)
            print(f"\n🤖 AI/ML Analysis:")
            print(f"   ML-analyzed findings: {ml_analyzed}")
        
        # Compliance
        if result.get('compliance_report'):
            comp = result['compliance_report']
            print(f"\n📋 Compliance:")
            print(f"   Total violations: {comp['total_violations']}")
            print(f"   Affected frameworks: {len(comp['affected_frameworks'])}")
            for fw in comp['affected_frameworks']:
                count = len(comp['frameworks'].get(fw, []))
                print(f"      - {fw.upper()}: {count} violations")
        
        # Remediation
        if result.get('remediation_report'):
            rem = result['remediation_report']
            print(f"\n🔧 Remediation:")
            print(f"   Items to fix: {rem['total_items']}")
            print(f"   Estimated effort: {rem['estimated_total_effort']}")
            effort = rem['effort_distribution']
            print(f"   Effort breakdown: Low={effort.get('low', 0)}, Medium={effort.get('medium', 0)}, High={effort.get('high', 0)}")
        
        # Performance
        if result.get('performance_metrics'):
            perf = result['performance_metrics']
            print(f"\n⚡ Performance:")
            print(f"   Scan duration: {perf['duration_seconds']:.3f}s")
            print(f"   Memory usage: {perf['memory_usage_mb']:.1f} MB")
            print(f"   Throughput: {perf['files_scanned']/perf['duration_seconds']:.1f} files/sec")
        
        # Output files
        print(f"\n📄 Generated Reports:")
        if 'dashboard_path' in result:
            print(f"   ✅ Interactive Dashboard: {result['dashboard_path']}")
        if 'sarif_path' in result:
            print(f"   ✅ SARIF Report: {result['sarif_path']}")
        
        # Sample findings
        print(f"\n🔍 Sample Findings (Top 5):")
        for i, finding in enumerate(result['findings'][:5], 1):
            risk = finding.get('risk_score', {}).get('risk_level', 'medium')
            score = finding.get('risk_score', {}).get('composite_score', 0)
            ftype = finding.get('type', 'Unknown')
            source = os.path.basename(finding.get('source', 'Unknown'))
            
            print(f"\n   {i}. {ftype}")
            print(f"      Risk: {risk.upper()} (Score: {score:.1f}/100)")
            print(f"      Location: {source}")
            
            # Show ML analysis if available
            if 'ml_analysis' in finding:
                ml = finding['ml_analysis']
                if ml['is_secret_ml']:
                    print(f"      🤖 ML: Confirmed secret (confidence: {ml['ml_confidence']:.2f})")
        
        print("\n" + "=" * 70)
        print("✅ SCAN COMPLETE!")
        print("=" * 70)
        print("\nThe ultimate scanner has analyzed your code with:")
        print("  ✓ AI-powered anomaly detection")
        print("  ✓ Risk-based prioritization")
        print("  ✓ Compliance framework mapping")
        print("  ✓ Automated remediation suggestions")
        print("  ✓ Performance profiling")
        print("  ✓ Interactive dashboard")
        print("  ✓ IDE-compatible SARIF format")
        
        # Wait for user to view dashboard
        if 'dashboard_path' in result:
            print(f"\n💡 Open the dashboard to view results:")
            print(f"   file://{result['dashboard_path']}")


def demo_quick_scan():
    """Demonstrate quick scan helper."""
    print("\n" + "=" * 70)
    print("QUICK SCAN DEMONSTRATION")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a test file
        test_file = os.path.join(temp_dir, 'secrets.py')
        with open(test_file, 'w') as f:
            f.write("""
# Configuration
API_KEY = "sk-test-1234567890abcdefghijklmnop"
DB_URL = "postgres://user:pass@localhost/db"
            """)
        
        print(f"\n📁 Created test file: {test_file}")
        print("\n🚀 Running quick scan...")
        
        # Use quick_scan helper
        dashboard_path = quick_scan(test_file, output_dir=os.path.join(temp_dir, 'results'))
        
        print(f"\n✅ Quick scan complete!")
        print(f"   Dashboard: {dashboard_path}")


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🔒 ULTIMATE VULNERABILITY SCANNER")
    print("The Most Advanced Security Scanning Platform")
    print("=" * 70)
    
    # Run demonstrations
    demo_ultimate_scanner()
    demo_quick_scan()
    
    print("\n" + "=" * 70)
    print("🎉 All demonstrations complete!")
    print("=" * 70)
    print("\nThe Ultimate Scanner provides:")
    print("  • AI/ML-powered detection")
    print("  • Interactive visualizations")
    print("  • IDE integration (SARIF)")
    print("  • Compliance frameworks")
    print("  • Automated remediation")
    print("  • Enterprise-grade performance")
    print("\n" + "=" * 70)
