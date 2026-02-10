"""
Tests for Next-Generation Vulnerability Scanner
"""

import unittest
import os
import tempfile
import time
import json
from pathlib import Path

from discover.sensitive_scanner_nextgen import (
    NextGenVulnerabilityScanner,
    DataFlowAnalyzer,
    CloudSecurityScanner,
    ScanAPIInterface,
    quick_nextgen_scan
)

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    from watchdog.observers import Observer
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


class TestDataFlowAnalyzer(unittest.TestCase):
    """Test graph-based data flow analysis."""
    
    @unittest.skipUnless(HAS_NETWORKX, "networkx not available")
    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = DataFlowAnalyzer()
        self.assertIsNotNone(analyzer.graph)
        self.assertEqual(len(analyzer.sensitive_nodes), 0)
    
    @unittest.skipUnless(HAS_NETWORKX, "networkx not available")
    def test_file_analysis(self):
        """Test file analysis."""
        analyzer = DataFlowAnalyzer()
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
import os
API_KEY = "test_key"
password = "secret123"

def get_config():
    return API_KEY
""")
            test_file = f.name
        
        try:
            analyzer.build_graph([test_file])
            
            # Check graph was built
            self.assertGreater(analyzer.graph.number_of_nodes(), 0)
            self.assertGreater(len(analyzer.sensitive_nodes), 0)
            
            # Get stats
            stats = analyzer.get_graph_stats()
            self.assertIn('total_nodes', stats)
            self.assertIn('sensitive_nodes', stats)
        
        finally:
            os.unlink(test_file)
    
    @unittest.skipUnless(HAS_NETWORKX, "networkx not available")
    def test_secret_flow_detection(self):
        """Test secret flow detection."""
        analyzer = DataFlowAnalyzer()
        
        # Create test file with secret flow
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
API_KEY = "sk_test_123"
config = API_KEY
""")
            test_file = f.name
        
        try:
            analyzer.build_graph([test_file])
            flows = analyzer.find_secret_flows()
            
            # Should detect some flows
            self.assertIsInstance(flows, list)
        
        finally:
            os.unlink(test_file)


class TestCloudSecurityScanner(unittest.TestCase):
    """Test cloud security scanning."""
    
    def test_initialization(self):
        """Test scanner initialization."""
        scanner = CloudSecurityScanner()
        self.assertIsNotNone(scanner.patterns)
        self.assertIn('aws_access_key', scanner.patterns)
    
    def test_environment_variable_scan(self):
        """Test environment variable scanning."""
        scanner = CloudSecurityScanner()
        
        # Set test env var
        os.environ['TEST_API_KEY'] = 'test_value'
        
        try:
            findings = scanner.scan_environment_variables()
            
            # Should find our test var
            self.assertIsInstance(findings, list)
            found = any(f['name'] == 'TEST_API_KEY' for f in findings)
            self.assertTrue(found)
        
        finally:
            del os.environ['TEST_API_KEY']
    
    def test_docker_scan_placeholder(self):
        """Test Docker scan placeholder."""
        scanner = CloudSecurityScanner()
        result = scanner.scan_docker_image('test:latest')
        
        self.assertIn('status', result)
        self.assertEqual(result['status'], 'not_implemented')
    
    def test_k8s_scan_placeholder(self):
        """Test K8s scan placeholder."""
        scanner = CloudSecurityScanner()
        result = scanner.scan_k8s_secrets('default')
        
        self.assertIn('status', result)
        self.assertEqual(result['status'], 'not_implemented')


class TestScanAPIInterface(unittest.TestCase):
    """Test API interface."""
    
    def test_initialization(self):
        """Test API initialization."""
        scanner = NextGenVulnerabilityScanner()
        api = ScanAPIInterface(scanner)
        
        self.assertIsNotNone(api.scanner)
        self.assertEqual(len(api.scan_history), 0)
    
    def test_scan_history(self):
        """Test scan history."""
        scanner = NextGenVulnerabilityScanner()
        api = ScanAPIInterface(scanner)
        
        # Add some history
        api.scan_history.append({
            'scan_id': 'test1',
            'findings_count': 5
        })
        
        history = api.get_scan_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['scan_id'], 'test1')
    
    def test_scan_status(self):
        """Test scan status retrieval."""
        scanner = NextGenVulnerabilityScanner()
        api = ScanAPIInterface(scanner)
        
        # Add to history
        api.scan_history.append({
            'scan_id': 'test_scan',
            'status': 'completed'
        })
        
        status = api.get_scan_status('test_scan')
        self.assertEqual(status['status'], 'completed')
        
        # Test not found
        status = api.get_scan_status('nonexistent')
        self.assertIn('error', status)


class TestNextGenScanner(unittest.TestCase):
    """Test next-generation scanner."""
    
    def test_initialization(self):
        """Test scanner initialization."""
        scanner = NextGenVulnerabilityScanner(
            enable_graph_analysis=True,
            enable_cloud_scanning=True
        )
        
        self.assertIsNotNone(scanner)
        self.assertTrue(scanner.enable_cloud_scanning)
    
    def test_nextgen_scan(self):
        """Test next-gen scanning."""
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
API_KEY = "test_api_key_12345"
password = "secret123"
""")
            test_file = f.name
        
        try:
            scanner = NextGenVulnerabilityScanner(
                enable_cloud_scanning=True,
                enable_risk_scoring=True
            )
            
            results = scanner.scan_with_nextgen_features(
                [test_file],
                target_type='file'
            )
            
            # Check results structure
            self.assertIn('findings_count', results)
            self.assertIn('nextgen_features', results)
            self.assertIn('scanner_version', results)
            self.assertEqual(results['scanner_version'], '4.0-nextgen')
            
            # Check next-gen features
            nextgen = results['nextgen_features']
            self.assertIn('cloud_security', nextgen)
        
        finally:
            os.unlink(test_file)
    
    @unittest.skipUnless(HAS_NETWORKX, "networkx not available")
    def test_graph_analysis_integration(self):
        """Test graph analysis integration."""
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
import requests
API_KEY = "sk_test_123"
""")
            test_file = f.name
        
        try:
            scanner = NextGenVulnerabilityScanner(
                enable_graph_analysis=True
            )
            
            results = scanner.scan_with_nextgen_features(
                [test_file],
                target_type='file'
            )
            
            # Check graph analysis results
            self.assertIn('nextgen_features', results)
            nextgen = results['nextgen_features']
            
            if 'data_flow_analysis' in nextgen:
                analysis = nextgen['data_flow_analysis']
                self.assertIn('graph_stats', analysis)
        
        finally:
            os.unlink(test_file)
    
    def test_api_interface_integration(self):
        """Test API interface integration."""
        scanner = NextGenVulnerabilityScanner()
        
        self.assertIsNotNone(scanner.api_interface)
        self.assertIsInstance(scanner.api_interface, ScanAPIInterface)
    
    def test_quick_nextgen_scan(self):
        """Test quick scan function."""
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("password = 'test123'")
            test_file = f.name
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                results = quick_nextgen_scan([test_file], output_dir=tmpdir)
                
                self.assertIn('findings_count', results)
                self.assertIn('scanner_version', results)
        
        finally:
            os.unlink(test_file)


class TestIntegration(unittest.TestCase):
    """Integration tests for next-gen scanner."""
    
    def test_full_scan_pipeline(self):
        """Test full scanning pipeline."""
        # Create test files
        test_dir = tempfile.mkdtemp()
        
        try:
            # File 1: Python with secrets
            file1 = os.path.join(test_dir, 'config.py')
            with open(file1, 'w') as f:
                f.write("""
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "supersecret123"
""")
            
            # File 2: Normal code
            file2 = os.path.join(test_dir, 'utils.py')
            with open(file2, 'w') as f:
                f.write("""
def get_data():
    return "hello world"
""")
            
            # Run comprehensive scan
            scanner = NextGenVulnerabilityScanner(
                enable_risk_scoring=True,
                enable_cloud_scanning=True,
                enable_graph_analysis=HAS_NETWORKX
            )
            
            results = scanner.scan_with_nextgen_features(
                [file1, file2],
                target_type='file'
            )
            
            # Verify results
            self.assertGreater(results['findings_count'], 0)
            self.assertIn('nextgen_features', results)
            self.assertIn('cloud_security', results['nextgen_features'])
            
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
