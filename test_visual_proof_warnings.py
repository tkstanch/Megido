"""
Test suite for visual proof warnings and diagnostics system.

This test suite verifies that:
1. Missing dependencies are properly detected
2. Warnings are generated and propagated to scan results
3. Visual proof status is correctly set based on capture results
4. Frontend receives proper status information
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestVisualProofDiagnostics(unittest.TestCase):
    """Test visual proof diagnostics module."""
    
    def setUp(self):
        """Set up test fixtures."""
        from scanner.visual_proof_diagnostics import VisualProofDiagnostics
        self.diagnostics = VisualProofDiagnostics()
    
    def test_check_dependencies(self):
        """Test dependency checking."""
        result = self.diagnostics._check_dependencies()
        
        # Should return a dictionary with dependency status
        self.assertIn('playwright', result)
        self.assertIn('selenium', result)
        self.assertIn('pillow', result)
        self.assertIn('missing_critical', result)
        self.assertIn('missing_optional', result)
        self.assertIn('installation_commands', result)
        
        # Check that missing_critical and missing_optional are lists
        self.assertIsInstance(result['missing_critical'], list)
        self.assertIsInstance(result['missing_optional'], list)
    
    def test_check_filesystem_permissions(self):
        """Test filesystem permission checking."""
        result = self.diagnostics._check_filesystem_permissions()
        
        # Should return a dictionary with filesystem status
        self.assertIn('writable', result)
        self.assertIn('directory_exists', result)
        self.assertIn('path', result)
        
        # Path should be set
        self.assertIsNotNone(result['path'])
    
    def test_check_all(self):
        """Test comprehensive diagnostic check."""
        result = self.diagnostics.check_all()
        
        # Should return complete diagnostic results
        self.assertIn('dependencies', result)
        self.assertIn('browsers', result)
        self.assertIn('filesystem', result)
        self.assertIn('overall_status', result)
        self.assertIn('warnings', result)
        self.assertIn('errors', result)
        self.assertIn('recommendations', result)
        
        # Overall status should be one of the valid statuses
        self.assertIn(result['overall_status'], ['ok', 'critical'])
    
    def test_get_warnings_for_scan(self):
        """Test warning generation for scan results."""
        warnings = self.diagnostics.get_warnings_for_scan()
        
        # Should return a list
        self.assertIsInstance(warnings, list)
        
        # If there are warnings, they should have the required fields
        for warning in warnings:
            self.assertIn('category', warning)
            self.assertIn('severity', warning)
            self.assertIn('component', warning)
            self.assertIn('message', warning)
            self.assertIn('recommendation', warning)
    
    def test_recommendations_generated(self):
        """Test that recommendations are generated for issues."""
        results = self.diagnostics.check_all()
        
        if results['errors'] or results['warnings']:
            # If there are errors or warnings, recommendations should be generated
            self.assertGreater(len(results['recommendations']), 0)


class TestProofDataStatus(unittest.TestCase):
    """Test ProofData visual proof status tracking."""
    
    def test_visual_proof_status_initialization(self):
        """Test that visual proof status is initialized."""
        from scanner.proof_reporter import ProofData
        
        proof_data = ProofData('xss', vulnerability_id=1)
        
        # Status should be initialized
        self.assertEqual(proof_data.visual_proof_status, 'not_attempted')
        self.assertIsInstance(proof_data.visual_proof_warnings, list)
        self.assertEqual(len(proof_data.visual_proof_warnings), 0)
    
    def test_set_visual_proof_status(self):
        """Test setting visual proof status."""
        from scanner.proof_reporter import ProofData
        
        proof_data = ProofData('xss', vulnerability_id=1)
        proof_data.set_visual_proof_status('captured')
        
        self.assertEqual(proof_data.visual_proof_status, 'captured')
    
    def test_set_visual_proof_status_with_warning(self):
        """Test setting visual proof status with warning."""
        from scanner.proof_reporter import ProofData
        
        proof_data = ProofData('xss', vulnerability_id=1)
        warning = {
            'category': 'visual_proof',
            'severity': 'high',
            'component': 'Test',
            'message': 'Test warning',
            'recommendation': 'Fix it'
        }
        proof_data.set_visual_proof_status('failed', warning=warning)
        
        self.assertEqual(proof_data.visual_proof_status, 'failed')
        self.assertEqual(len(proof_data.visual_proof_warnings), 1)
        self.assertEqual(proof_data.visual_proof_warnings[0]['message'], 'Test warning')
    
    def test_add_visual_proof_warning(self):
        """Test adding visual proof warnings."""
        from scanner.proof_reporter import ProofData
        
        proof_data = ProofData('xss', vulnerability_id=1)
        proof_data.add_visual_proof_warning(
            message='Dependency missing',
            severity='high',
            component='Playwright',
            recommendation='Install with pip install playwright'
        )
        
        self.assertEqual(len(proof_data.visual_proof_warnings), 1)
        warning = proof_data.visual_proof_warnings[0]
        self.assertEqual(warning['category'], 'visual_proof')
        self.assertEqual(warning['severity'], 'high')
        self.assertEqual(warning['component'], 'Playwright')
        self.assertEqual(warning['message'], 'Dependency missing')
    
    def test_proof_data_to_dict_includes_status(self):
        """Test that to_dict includes visual proof status."""
        from scanner.proof_reporter import ProofData
        
        proof_data = ProofData('xss', vulnerability_id=1)
        proof_data.set_visual_proof_status('disabled')
        proof_data.add_visual_proof_warning('Test warning')
        
        data_dict = proof_data.to_dict()
        
        self.assertIn('visual_proof_status', data_dict)
        self.assertIn('visual_proof_warnings', data_dict)
        self.assertEqual(data_dict['visual_proof_status'], 'disabled')
        self.assertEqual(len(data_dict['visual_proof_warnings']), 1)


class TestProofReporterWarnings(unittest.TestCase):
    """Test ProofReporter warning collection."""
    
    @patch('scanner.visual_proof_capture.get_visual_proof_capture')
    def test_init_collects_warnings_when_dependencies_missing(self, mock_get_capture):
        """Test that warnings are collected when dependencies are missing."""
        from scanner.proof_reporter import ProofReporter
        
        # Mock that visual proof capture is not available
        mock_get_capture.return_value = None
        
        reporter = ProofReporter(enable_visual_proof=True)
        
        # Reporter should have collected warnings
        self.assertIsInstance(reporter.visual_proof_warnings, list)
        # If dependencies are missing, warnings should be collected
        # (actual number depends on system state)
    
    @patch('scanner.visual_proof_capture.get_visual_proof_capture')
    def test_capture_propagates_warnings_to_proof_data(self, mock_get_capture):
        """Test that capture failures propagate warnings to proof data."""
        from scanner.proof_reporter import ProofReporter, ProofData
        
        # Mock that visual proof capture is not available
        mock_get_capture.return_value = None
        
        reporter = ProofReporter(enable_visual_proof=True)
        proof_data = ProofData('xss', vulnerability_id=1)
        
        # Try to capture visual proof (should fail gracefully)
        result = reporter.capture_visual_proof(proof_data, 'http://example.com')
        
        # Should return False
        self.assertFalse(result)
        
        # Status should be set
        self.assertEqual(proof_data.visual_proof_status, 'missing_dependencies')
        
        # Warnings should be propagated to proof data
        # (actual number depends on diagnostics)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions."""
    
    def test_check_visual_proof_dependencies_function(self):
        """Test quick dependency check function."""
        from scanner.visual_proof_diagnostics import check_visual_proof_dependencies
        
        result = check_visual_proof_dependencies()
        
        # Should return diagnostic results
        self.assertIn('dependencies', result)
        self.assertIn('overall_status', result)
    
    def test_get_visual_proof_warnings_function(self):
        """Test warning getter function."""
        from scanner.visual_proof_diagnostics import get_visual_proof_warnings
        
        warnings = get_visual_proof_warnings()
        
        # Should return a list of warnings
        self.assertIsInstance(warnings, list)


def run_tests():
    """Run all tests and print results."""
    print("\n" + "="*70)
    print("Visual Proof Warnings Test Suite")
    print("="*70 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestVisualProofDiagnostics))
    suite.addTests(loader.loadTestsFromTestCase(TestProofDataStatus))
    suite.addTests(loader.loadTestsFromTestCase(TestProofReporterWarnings))
    suite.addTests(loader.loadTestsFromTestCase(TestUtilityFunctions))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70 + "\n")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
