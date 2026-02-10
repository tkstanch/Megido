"""
Next-Generation Vulnerability Scanner Demo

Demonstrates cutting-edge features:
- Real-time monitoring
- Graph-based data flow analysis
- Cloud security integration
- Advanced API interface
"""

import os
import sys
import tempfile
import time
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from discover.sensitive_scanner_nextgen import (
    NextGenVulnerabilityScanner,
    DataFlowAnalyzer,
    CloudSecurityScanner,
    quick_nextgen_scan
)


def print_section(title):
    """Print section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_graph_analysis():
    """Demonstrate graph-based data flow analysis."""
    print_section("1. Graph-Based Data Flow Analysis")
    
    try:
        from discover.sensitive_scanner_nextgen import HAS_NETWORKX
        
        if not HAS_NETWORKX:
            print("⚠️  networkx not installed - skipping graph analysis demo")
            return
        
        # Create test files with data flow
        test_dir = tempfile.mkdtemp()
        
        # File 1: Contains secret
        file1 = os.path.join(test_dir, 'secrets.py')
        with open(file1, 'w') as f:
            f.write("""
import os

# Sensitive credentials
API_SECRET_KEY = "sk_live_abcdef123456"
DB_PASSWORD = "SuperSecret123!"

def get_api_key():
    return API_SECRET_KEY

def connect_database():
    return f"postgresql://user:{DB_PASSWORD}@localhost/db"
""")
        
        # File 2: Uses the secret
        file2 = os.path.join(test_dir, 'app.py')
        with open(file2, 'w') as f:
            f.write("""
from secrets import get_api_key, connect_database

api_key = get_api_key()
db_conn = connect_database()

def make_request():
    headers = {'Authorization': api_key}
    return headers
""")
        
        print(f"\n📁 Created test files in {test_dir}")
        print(f"   - secrets.py (contains API_SECRET_KEY, DB_PASSWORD)")
        print(f"   - app.py (imports and uses secrets)")
        
        # Run analysis
        print("\n🔍 Building code dependency graph...")
        analyzer = DataFlowAnalyzer()
        analyzer.build_graph([file1, file2])
        
        # Get graph stats
        stats = analyzer.get_graph_stats()
        print(f"\n📊 Graph Statistics:")
        print(f"   - Total nodes: {stats['total_nodes']}")
        print(f"   - Total edges: {stats['total_edges']}")
        print(f"   - Sensitive nodes: {stats['sensitive_nodes']}")
        print(f"   - Avg degree: {stats['avg_degree']:.2f}")
        
        # Find secret flows
        print("\n🔗 Analyzing secret data flows...")
        flows = analyzer.find_secret_flows()
        
        if flows:
            print(f"\n⚠️  Found {len(flows)} data flow paths with secrets:")
            for i, flow in enumerate(flows[:3], 1):
                print(f"\n   Flow #{i}:")
                print(f"   - Source: {flow['source']}")
                print(f"   - Target: {flow['target']}")
                print(f"   - Path length: {flow['length']}")
                print(f"   - Risk: {flow['risk']}")
        else:
            print("\n✅ No direct secret flows detected")
        
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")


def demo_cloud_security():
    """Demonstrate cloud security scanning."""
    print_section("2. Cloud & Container Security Scanning")
    
    scanner = CloudSecurityScanner()
    
    print("\n🔍 Scanning environment variables for sensitive data...")
    
    # Set some test env vars
    test_vars = {
        'TEST_API_KEY': 'test_key_123',
        'TEST_SECRET_TOKEN': 'secret_abc',
        'NORMAL_VAR': 'normal_value'
    }
    
    for key, value in test_vars.items():
        os.environ[key] = value
    
    try:
        findings = scanner.scan_environment_variables()
        
        test_findings = [f for f in findings if f['name'].startswith('TEST_')]
        
        print(f"\n📊 Found {len(test_findings)} sensitive environment variables:")
        for finding in test_findings:
            print(f"\n   ⚠️  {finding['name']}")
            print(f"      Risk: {finding['risk']}")
            print(f"      Message: {finding['message']}")
        
        # Docker scanning
        print("\n\n🐳 Docker Image Scanning:")
        docker_result = scanner.scan_docker_image('myapp:latest')
        print(f"   Status: {docker_result['status']}")
        print(f"   Note: {docker_result.get('message', 'N/A')}")
        
        # K8s scanning
        print("\n☸️  Kubernetes Secret Scanning:")
        k8s_result = scanner.scan_k8s_secrets('default')
        print(f"   Status: {k8s_result['status']}")
        print(f"   Note: {k8s_result.get('message', 'N/A')}")
        
    finally:
        # Cleanup
        for key in test_vars:
            if key in os.environ:
                del os.environ[key]


def demo_api_interface():
    """Demonstrate API interface."""
    print_section("3. Advanced API Interface")
    
    scanner = NextGenVulnerabilityScanner()
    api = scanner.api_interface
    
    print("\n🌐 API Interface Features:")
    print("   - Async scanning support")
    print("   - Scan history tracking")
    print("   - Status monitoring")
    print("   - RESTful API ready")
    
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("password = 'test123'")
        test_file = f.name
    
    try:
        print("\n📝 Example API workflow:")
        print(f"   1. Submit scan request for {os.path.basename(test_file)}")
        
        # Simulate API call (synchronous for demo)
        import asyncio
        
        async def run_scan():
            result = await api.scan_async([test_file], {'incremental': True})
            return result
        
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_scan())
        loop.close()
        
        print(f"   2. Scan completed: ID={result.get('scan_id', 'N/A')}")
        print(f"   3. Findings: {result.get('findings_count', 0)}")
        
        # Get history
        history = api.get_scan_history()
        print(f"\n📜 Scan History: {len(history)} scans")
        
    finally:
        os.unlink(test_file)


def demo_comprehensive_scan():
    """Demonstrate comprehensive next-gen scan."""
    print_section("4. Comprehensive Next-Gen Scan")
    
    # Create test project
    test_dir = tempfile.mkdtemp()
    
    files = []
    
    # File 1: Configuration with secrets
    file1 = os.path.join(test_dir, 'config.env')
    with open(file1, 'w') as f:
        f.write("""
# Application Configuration
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://user:mypassword123@localhost:5432/mydb
STRIPE_API_KEY=test_rk_12345abcde67890
""")
    files.append(file1)
    
    # File 2: Python code
    file2 = os.path.join(test_dir, 'app.py')
    with open(file2, 'w') as f:
        f.write("""
import os
from flask import Flask

app = Flask(__name__)

# Load config
API_KEY = os.getenv('AWS_ACCESS_KEY_ID')
SECRET = os.getenv('AWS_SECRET_ACCESS_KEY')

@app.route('/api/data')
def get_data():
    # Use API key
    return {'key': API_KEY}
""")
    files.append(file2)
    
    # File 3: JavaScript
    file3 = os.path.join(test_dir, 'client.js')
    with open(file3, 'w') as f:
        f.write("""
const apiKey = 'pk_test_51HFq2bKmqBwvUlVl';
const stripeKey = 'test_rk_12345abcde67890';

function initializeApp() {
    fetch('/api/data', {
        headers: {'X-API-Key': apiKey}
    });
}
""")
    files.append(file3)
    
    print(f"\n📁 Created test project with {len(files)} files:")
    for f in files:
        print(f"   - {os.path.basename(f)}")
    
    # Run comprehensive scan
    print("\n🚀 Running comprehensive next-gen scan...")
    print("   Features enabled:")
    print("   ✓ AI/ML Detection")
    print("   ✓ Risk Scoring")
    print("   ✓ Graph Analysis")
    print("   ✓ Cloud Security")
    print("   ✓ HTML Dashboard")
    print("   ✓ SARIF Output")
    
    start_time = time.time()
    
    try:
        from discover.sensitive_scanner_nextgen import HAS_NETWORKX
        
        scanner = NextGenVulnerabilityScanner(
            enable_ai_ml=True,
            enable_risk_scoring=True,
            enable_graph_analysis=HAS_NETWORKX,
            enable_cloud_scanning=True,
            enable_dashboard_generation=True,
            enable_sarif_output=True,
            exposure_level='high'
        )
        
        results = scanner.scan_with_nextgen_features(
            files,
            target_type='file',
            output_dir=test_dir
        )
        
        scan_time = time.time() - start_time
        
        # Display results
        print(f"\n✅ Scan completed in {scan_time:.3f}s")
        print(f"\n📊 Scan Results:")
        print(f"   - Total findings: {results.get('findings_count', 0)}")
        print(f"   - Scanner version: {results.get('scanner_version')}")
        
        # Risk breakdown
        if 'findings' in results:
            risk_counts = {}
            for finding in results['findings']:
                risk = finding.get('risk_score', {}).get('risk_level', 'unknown')
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            print(f"\n   Risk Breakdown:")
            for risk, count in sorted(risk_counts.items()):
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(risk, '⚪')
                print(f"      {emoji} {risk.capitalize()}: {count}")
        
        # Next-gen features
        nextgen = results.get('nextgen_features', {})
        
        print(f"\n   Next-Gen Features:")
        
        if 'data_flow_analysis' in nextgen:
            dfa = nextgen['data_flow_analysis']
            if 'graph_stats' in dfa:
                stats = dfa['graph_stats']
                print(f"      📊 Graph Analysis:")
                print(f"         - Nodes: {stats.get('total_nodes', 0)}")
                print(f"         - Edges: {stats.get('total_edges', 0)}")
                print(f"         - Secret flows: {dfa.get('flow_count', 0)}")
        
        if 'cloud_security' in nextgen:
            cloud = nextgen['cloud_security']
            print(f"      ☁️  Cloud Security:")
            print(f"         - Environment issues: {cloud.get('finding_count', 0)}")
        
        # Output files
        print(f"\n   📄 Output Files:")
        if results.get('dashboard_path'):
            print(f"      - Dashboard: {os.path.basename(results['dashboard_path'])}")
        if results.get('sarif_path'):
            print(f"      - SARIF: {os.path.basename(results['sarif_path'])}")
        
        # Performance
        print(f"\n   ⚡ Performance:")
        print(f"      - Scan time: {scan_time:.3f}s")
        print(f"      - Files/sec: {len(files)/scan_time:.1f}")
        print(f"      - Next-gen overhead: {results.get('nextgen_scan_time', 0):.3f}s")
        
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


def demo_quick_scan():
    """Demonstrate quick scan function."""
    print_section("5. Quick Scan Function")
    
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("""
# Quick test file
PASSWORD = "admin123"
secret_token = "abc_secret_xyz"
""")
        test_file = f.name
    
    try:
        print("\n🚀 Running quick_nextgen_scan()...")
        print(f"   File: {os.path.basename(test_file)}")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            result = quick_nextgen_scan([test_file], output_dir=tmpdir)
            
            print(f"\n✅ Results:")
            print(f"   - Findings: {result.get('findings_count', 0)}")
            print(f"   - Version: {result.get('scanner_version')}")
            print(f"   - Features: All next-gen features enabled")
    
    finally:
        os.unlink(test_file)


def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print("  Next-Generation Vulnerability Scanner v4.0 - Demo")
    print("=" * 70)
    print("\nDemonstrating cutting-edge security scanning features:")
    print("  1. Graph-based data flow analysis")
    print("  2. Cloud & container security")
    print("  3. Advanced API interface")
    print("  4. Comprehensive scanning")
    print("  5. Quick scan utilities")
    
    try:
        # Demo 1: Graph analysis
        demo_graph_analysis()
        
        # Demo 2: Cloud security
        demo_cloud_security()
        
        # Demo 3: API interface
        demo_api_interface()
        
        # Demo 4: Comprehensive scan
        demo_comprehensive_scan()
        
        # Demo 5: Quick scan
        demo_quick_scan()
        
        # Summary
        print_section("Demo Complete!")
        print("\n🎉 Next-Generation Scanner v4.0 Features:")
        print("   ✓ Real-time monitoring (file watchers)")
        print("   ✓ Graph-based data flow analysis")
        print("   ✓ Cloud/container security scanning")
        print("   ✓ Advanced API interface (async, history)")
        print("   ✓ AI/ML detection (Ultimate v3.0)")
        print("   ✓ Interactive dashboards (Ultimate v3.0)")
        print("   ✓ SARIF format (Ultimate v3.0)")
        print("\n🚀 Ready for production deployment!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
