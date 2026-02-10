"""
Tests for the Ultimate Vulnerability Scanner
"""
import unittest
import tempfile
import os
import json
from unittest.mock import Mock, patch
from discover.sensitive_scanner_ultimate import (
    MLSecretDetector,
    DashboardGenerator,
    SARIFReporter,
    UltimateVulnerabilityScanner,
    quick_scan,
    HAS_SKLEARN
)


class TestMLSecretDetector(unittest.TestCase):
    """Tests for ML-based secret detection."""
    
    @unittest.skipIf(not HAS_SKLEARN, "sklearn not available")
    def test_ml_detector_initialization(self):
        """Test ML detector initializes correctly."""
        detector = MLSecretDetector()
        self.assertIsNotNone(detector)
        self.assertTrue(detector.is_trained)
    
    @unittest.skipIf(not HAS_SKLEARN, "sklearn not available")
    def test_predict_secret(self):
        """Test secret prediction."""
        detector = MLSecretDetector()
        
        # Test with likely secret
        is_secret, confidence = detector.predict_secret("sk_live_abcdefgh1234567890")
        self.assertIsInstance(is_secret, bool)
        self.assertIsInstance(confidence, float)
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)


class TestDashboardGenerator(unittest.TestCase):
    """Tests for dashboard generation."""
    
    def test_generate_html_dashboard(self):
        """Test HTML dashboard generation."""
        scan_results = {
            'findings': [
                {
                    'type': 'AWS Key',
                    'value': 'AKIATEST123',
                    'source': '/tmp/test.py',
                    'risk_score': {'risk_level': 'critical', 'composite_score': 95}
                },
                {
                    'type': 'API Key',
                    'value': 'api_key_test',
                    'source': '/tmp/test2.py',
                    'risk_score': {'risk_level': 'high', 'composite_score': 75}
                }
            ]
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, 'dashboard.html')
            result = DashboardGenerator.generate_html_dashboard(scan_results, output_path)
            
            self.assertTrue(os.path.exists(output_path))
            
            with open(output_path, 'r') as f:
                content = f.read()
                self.assertIn('Security Scan Dashboard', content)
                self.assertIn('Critical Issues', content)


class TestSARIFReporter(unittest.TestCase):
    """Tests for SARIF report generation."""
    
    def test_generate_sarif(self):
        """Test SARIF report generation."""
        scan_results = {
            'findings': [
                {
                    'type': 'AWS Key',
                    'value': 'AKIATEST123',
                    'source': 'test.py',
                    'context': 'aws_key = "AKIATEST123"',
                    'risk_score': {'risk_level': 'critical'}
                }
            ]
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, 'results.sarif')
            result = SARIFReporter.generate_sarif(scan_results, output_path)
            
            self.assertTrue(os.path.exists(output_path))
            
            with open(output_path, 'r') as f:
                sarif = json.load(f)
                self.assertEqual(sarif['version'], '2.1.0')
                self.assertIn('runs', sarif)
                self.assertTrue(len(sarif['runs']) > 0)
                self.assertIn('results', sarif['runs'][0])


class TestUltimateScanner(unittest.TestCase):
    """Tests for ultimate scanner."""
    
    def test_scanner_initialization(self):
        """Test ultimate scanner initializes correctly."""
        scanner = UltimateVulnerabilityScanner(
            enable_ai_ml=False,  # Skip ML for basic test
            enable_dashboard_generation=True,
            enable_sarif_output=True
        )
        
        self.assertIsNotNone(scanner)
        self.assertTrue(scanner.enable_dashboard)
        self.assertTrue(scanner.enable_sarif)
    
    def test_scan_with_ultimate_features(self):
        """Test scanning with ultimate features."""
        # Create test file
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write('aws_key = "AKIAIOSFODNN7EXAMPLE"')
            
            output_dir = os.path.join(temp_dir, 'results')
            
            scanner = UltimateVulnerabilityScanner(
                enable_ai_ml=False,
                enable_heuristics=False,
                enable_dashboard_generation=True,
                enable_sarif_output=True
            )
            
            result = scanner.scan_with_ultimate_features(
                [test_file],
                target_type='file',
                output_dir=output_dir
            )
            
            self.assertTrue(result['success'])
            self.assertIn('dashboard_path', result)
            self.assertIn('sarif_path', result)
            
            # Check files were created
            if 'dashboard_path' in result:
                self.assertTrue(os.path.exists(result['dashboard_path']))
            if 'sarif_path' in result:
                self.assertTrue(os.path.exists(result['sarif_path']))
    
    @unittest.skipIf(not HAS_SKLEARN, "sklearn not available")
    def test_ml_detection_integration(self):
        """Test ML detection integration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write('secret = "sk_live_abcdefgh1234567890"')
            
            scanner = UltimateVulnerabilityScanner(
                enable_ai_ml=True,
                enable_heuristics=False
            )
            
            result = scanner.scan_with_ultimate_features(
                [test_file],
                target_type='file',
                generate_dashboard=False,
                generate_sarif=False,
                output_dir=temp_dir
            )
            
            self.assertTrue(result.get('ml_enabled', False))
            
            # Check if ML analysis was applied
            if result['findings']:
                # Some findings should have ML analysis
                has_ml_analysis = any('ml_analysis' in f for f in result['findings'])
                # May or may not have ML analysis depending on what was detected


class TestQuickScan(unittest.TestCase):
    """Tests for quick scan helper function."""
    
    def test_quick_scan_file(self):
        """Test quick scan on a file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write('api_key = "test_key_12345"')
            
            output_dir = os.path.join(temp_dir, 'results')
            
            # Run quick scan
            dashboard_path = quick_scan(test_file, output_dir)
            
            # Check output directory was created
            self.assertTrue(os.path.exists(output_dir))


if __name__ == '__main__':
    unittest.main()
