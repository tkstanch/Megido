#!/usr/bin/env python3
"""
Enterprise Vulnerability Scanner Demo

Demonstrates all enterprise features:
1. Real-time CVE feed integration
2. Advanced ML/AI vulnerability detection
3. Automated remediation with PR generation
4. Container and runtime scanning
5. Distributed scanning
6. Comprehensive reporting
"""

import os
import sys
import tempfile
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from discover.sensitive_scanner_enterprise import (
    EnterpriseVulnerabilityScanner,
    CVEFeedManager,
    TransformerVulnerabilityDetector,
    RemediationCodeGenerator,
    ContainerScanner,
    DistributedScanCoordinator,
    quick_enterprise_scan
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)


def print_section(title):
    """Print a section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print('=' * 80)


def demo_1_cve_integration():
    """Demo 1: Real-time CVE feed integration."""
    print_section("Demo 1: Real-Time CVE Feed Integration")
    
    print("\n📡 Initializing CVE feed manager...")
    cve_manager = CVEFeedManager()
    
    print("\n🔍 Fetching recent CVEs (last 7 days)...")
    cves = cve_manager.fetch_recent_cves(days=7)
    
    print(f"\n✅ Fetched {len(cves)} CVEs")
    print("\nTop 3 CVEs:")
    for i, cve in enumerate(cves[:3], 1):
        print(f"\n{i}. {cve['id']}")
        print(f"   Severity: {cve['severity']} (Score: {cve['score']})")
        print(f"   Description: {cve['description'][:100]}...")
    
    # Enrich a finding
    print("\n🔬 Enriching finding with CVE intelligence...")
    finding = {
        'type': 'AWS Access Key',
        'value': 'AKIATEST123',
        'context': 'aws_key = "AKIATEST123"',
        'risk_score': {'composite_score': 75, 'risk_level': 'high'}
    }
    
    enriched = cve_manager.enrich_finding_with_cve(finding)
    
    if 'threat_intelligence' in enriched:
        ti = enriched['threat_intelligence']
        print(f"\n✅ Finding enriched with {ti['cve_count']} related CVEs")
        if ti['related_cves']:
            print(f"   Top CVE: {ti['related_cves'][0]['cve_id']}")
            print(f"   Severity: {ti['max_severity']} (Score: {ti['max_score']})")


def demo_2_advanced_ml():
    """Demo 2: Advanced ML/AI vulnerability detection."""
    print_section("Demo 2: Advanced ML/AI Vulnerability Detection")
    
    print("\n🤖 Initializing transformer-based detector...")
    detector = TransformerVulnerabilityDetector()
    
    print(f"   Model trained: {detector.is_trained}")
    print(f"   Features: {len(detector.feature_weights)}")
    
    # Test with different strings
    test_cases = [
        ("sk_live_abc123xyz", 'api_key = "sk_live_abc123xyz"', "API Key"),
        ("AKIAIOSFODNN7EXAMPLE", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', "AWS Key"),
        ("password123", 'password = "password123"', "Password"),
        ("hello world", "message = 'hello world'", "Normal Text")
    ]
    
    print("\n🔬 Analyzing vulnerability patterns...")
    for text, context, finding_type in test_cases:
        risk_score, explanation, features = detector.predict_vulnerability(
            text, context, finding_type
        )
        
        print(f"\n📊 {finding_type}:")
        print(f"   Text: {text[:30]}...")
        print(f"   Risk Score: {risk_score:.3f}")
        print(f"   Explanation: {explanation}")


def demo_3_automated_remediation():
    """Demo 3: Automated remediation generation."""
    print_section("Demo 3: Automated Remediation with Code Generation")
    
    print("\n🔧 Initializing remediation generator...")
    generator = RemediationCodeGenerator()
    
    # Test remediation for different vulnerability types
    vulnerabilities = [
        {
            'type': 'AWS Access Key',
            'value': 'AKIATEST123',
            'context': 'aws_key = "AKIATEST123"',
            'source': 'config.py',
            'position': 42,
            'risk_score': {'risk_level': 'critical'}
        },
        {
            'type': 'Password Field',
            'value': 'supersecret',
            'source': 'database.py',
            'position': 15,
            'risk_score': {'risk_level': 'high'}
        }
    ]
    
    print("\n🔍 Generating automated remediations...")
    remediations = []
    
    for vuln in vulnerabilities:
        remediation = generator.generate_remediation(
            vuln,
            file_path=vuln.get('source'),
            line_number=vuln.get('position')
        )
        remediations.append(remediation)
        
        print(f"\n📝 {vuln['type']}:")
        print(f"   Priority: {remediation['priority']}/5")
        print(f"   Effort: {remediation['effort']}")
        print(f"   Action: {remediation['action']}")
        print(f"\n   Code Patch:")
        print(f"   Before: {remediation['code_patch']['before']}")
        print(f"   After:  {remediation['code_patch']['after']}")
    
    # Generate PR description
    print("\n📄 Generating Pull Request description...")
    pr_desc = generator.generate_pr_description(vulnerabilities, remediations)
    print("\nPR Description Preview:")
    print(pr_desc[:400] + "...")


def demo_4_container_scanning():
    """Demo 4: Container and runtime scanning."""
    print_section("Demo 4: Container & Runtime Scanning")
    
    print("\n🐳 Initializing container scanner...")
    scanner = ContainerScanner()
    
    # Check if Docker is available
    print("\n🔍 Checking Docker availability...")
    result = scanner.scan_docker_container('test-container')
    
    print(f"   Status: {result['status']}")
    if result['status'] == 'error':
        print(f"   Message: {result['message']}")
    else:
        print(f"   Findings: {len(result.get('findings', []))}")
    
    # Scan running processes
    print("\n🔍 Scanning running processes...")
    process_findings = scanner.scan_running_processes()
    
    print(f"   Process findings: {len(process_findings)}")
    if process_findings:
        print("\n   Sample findings:")
        for finding in process_findings[:3]:
            print(f"   - {finding['type']}: {finding['message']}")


def demo_5_distributed_scanning():
    """Demo 5: Distributed scanning."""
    print_section("Demo 5: Distributed Scanning")
    
    print("\n⚡ Initializing distributed coordinator...")
    coordinator = DistributedScanCoordinator()
    
    # Create temporary test files
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"\n📁 Creating test files in {temp_dir}...")
        
        test_files = []
        for i in range(20):
            file_path = os.path.join(temp_dir, f'test_{i}.py')
            with open(file_path, 'w') as f:
                f.write(f'# Test file {i}\n')
                f.write(f'api_key_{i} = "test_key_{i}"\n')
            test_files.append(file_path)
        
        print(f"   Created {len(test_files)} test files")
        
        print("\n🚀 Distributing scan across 4 workers...")
        results = coordinator.distribute_scan(test_files, num_workers=4)
        
        print(f"\n✅ Distributed scan complete:")
        print(f"   Workers used: {results['num_workers']}")
        print(f"   Chunks processed: {results['chunks_processed']}")
        print(f"   Total findings: {results['total_findings']}")


def demo_6_full_enterprise_scan():
    """Demo 6: Full enterprise scan with all features."""
    print_section("Demo 6: Full Enterprise Scan")
    
    # Create test file with vulnerabilities
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"\n📝 Creating vulnerable test file...")
        
        test_file = os.path.join(temp_dir, 'vulnerable_app.py')
        with open(test_file, 'w') as f:
            f.write('''#!/usr/bin/env python3
"""
Sample application with vulnerabilities for testing
"""

# AWS credentials (CRITICAL)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database credentials (HIGH)
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASSWORD = "supersecret123"

# API keys (HIGH)
stripe_api_key = "sk_live_abc123xyz"
github_token = "ghp_test123456789"

# JWT token (MEDIUM)
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"

def connect_database():
    """Connect to database with hardcoded credentials."""
    connection_string = f"postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/mydb"
    return connection_string

def make_api_call():
    """Make API call with hardcoded key."""
    headers = {
        "Authorization": f"Bearer {stripe_api_key}",
        "X-GitHub-Token": github_token
    }
    return headers
''')
        
        output_dir = os.path.join(temp_dir, 'enterprise_results')
        
        print("\n🚀 Initializing enterprise scanner...")
        scanner = EnterpriseVulnerabilityScanner(
            enable_cve_integration=True,
            enable_advanced_ml=True,
            enable_auto_remediation=True,
            enable_risk_scoring=True,
            enable_compliance_mapping=True,
            enable_dashboard_generation=True,
            enable_sarif_output=True
        )
        
        print("\n🔍 Running comprehensive enterprise scan...")
        results = scanner.scan_with_enterprise_features(
            [test_file],
            target_type='file',
            output_dir=output_dir
        )
        
        print(f"\n✅ Scan completed in {results['scan_duration']:.2f}s")
        print(f"\n📊 Results:")
        print(f"   Total findings: {results['findings_count']}")
        print(f"   Scanner version: {results['scanner_version']}")
        
        # Enterprise features
        if 'enterprise_features' in results:
            features = results['enterprise_features']
            print(f"\n🎯 Enterprise Features:")
            
            if 'cve_enrichment' in features:
                cve = features['cve_enrichment']
                print(f"   CVE Enrichment: {'✅' if cve['enabled'] else '❌'}")
                if cve.get('findings_enriched'):
                    print(f"   - Findings enriched: {cve['findings_enriched']}")
            
            if 'advanced_ml' in features:
                ml = features['advanced_ml']
                print(f"   Advanced ML: {'✅' if ml['enabled'] else '❌'}")
                if ml.get('findings_analyzed'):
                    print(f"   - Findings analyzed: {ml['findings_analyzed']}")
            
            if 'auto_remediation' in features:
                remediation = features['auto_remediation']
                print(f"   Auto Remediation: {'✅' if remediation['enabled'] else '❌'}")
                if remediation.get('remediations_generated'):
                    print(f"   - Remediations generated: {remediation['remediations_generated']}")
        
        # Show sample findings
        if results.get('findings'):
            print(f"\n🔍 Sample Findings (top 3):")
            for i, finding in enumerate(results['findings'][:3], 1):
                print(f"\n{i}. {finding['type']}")
                print(f"   Value: {finding['value'][:50]}...")
                if 'risk_score' in finding:
                    risk = finding['risk_score']
                    print(f"   Risk Level: {risk['risk_level']} ({risk['composite_score']:.1f}/100)")
                if 'ml_advanced' in finding:
                    ml = finding['ml_advanced']
                    print(f"   ML Risk Score: {ml['risk_score']:.3f}")
        
        # Show output files
        print(f"\n📁 Output Files:")
        if os.path.exists(output_dir):
            for filename in os.listdir(output_dir):
                file_path = os.path.join(output_dir, filename)
                size = os.path.getsize(file_path)
                print(f"   - {filename} ({size:,} bytes)")
        
        # Show remediation sample
        if results.get('automated_remediations'):
            print(f"\n🔧 Sample Remediation:")
            remediation = results['automated_remediations'][0]
            print(f"   Type: {remediation['finding_type']}")
            print(f"   Priority: {remediation['priority']}/5")
            print(f"   Action: {remediation['action']}")


def demo_7_quick_scan():
    """Demo 7: Quick enterprise scan."""
    print_section("Demo 7: Quick Enterprise Scan")
    
    print("\n⚡ Running quick enterprise scan...")
    
    # Create simple test file
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, 'quick_test.py')
        with open(test_file, 'w') as f:
            f.write('api_key = "sk_live_quick_test_123"\n')
        
        output_dir = os.path.join(temp_dir, 'quick_results')
        
        # Run quick scan
        results = quick_enterprise_scan([test_file], output_dir)
        
        print(f"\n✅ Quick scan completed:")
        print(f"   Findings: {results.get('findings_count', 0)}")
        print(f"   Duration: {results.get('scan_duration', 0):.2f}s")
        print(f"   Version: {results.get('scanner_version', 'unknown')}")


def main():
    """Run all demos."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║            Enterprise Vulnerability Scanner Demo v5.0                        ║
║                                                                              ║
║  Demonstrating the most advanced security scanning platform:                ║
║  • Real-time CVE feed integration                                           ║
║  • Advanced ML/AI with transformer-based detection                          ║
║  • Automated remediation with PR generation                                 ║
║  • Container and runtime scanning                                           ║
║  • Distributed scanning architecture                                        ║
║  • Comprehensive reporting and dashboards                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    demos = [
        ("CVE Integration", demo_1_cve_integration),
        ("Advanced ML/AI", demo_2_advanced_ml),
        ("Automated Remediation", demo_3_automated_remediation),
        ("Container Scanning", demo_4_container_scanning),
        ("Distributed Scanning", demo_5_distributed_scanning),
        ("Full Enterprise Scan", demo_6_full_enterprise_scan),
        ("Quick Scan", demo_7_quick_scan),
    ]
    
    print("\nAvailable demos:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  {len(demos) + 1}. Run all demos")
    print("  0. Exit")
    
    try:
        choice = input("\nSelect demo (0-8): ").strip()
        
        if choice == '0':
            print("\n👋 Goodbye!")
            return
        elif choice == str(len(demos) + 1):
            # Run all demos
            for name, demo_func in demos:
                try:
                    demo_func()
                except KeyboardInterrupt:
                    print("\n\n⚠️  Demo interrupted by user")
                    break
                except Exception as e:
                    print(f"\n❌ Error in {name}: {e}")
                    import traceback
                    traceback.print_exc()
        elif choice.isdigit() and 1 <= int(choice) <= len(demos):
            # Run selected demo
            name, demo_func = demos[int(choice) - 1]
            try:
                demo_func()
            except Exception as e:
                print(f"\n❌ Error in {name}: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("\n❌ Invalid choice")
    
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    
    print("\n" + "=" * 80)
    print("Demo completed! See documentation for more details.")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    main()
