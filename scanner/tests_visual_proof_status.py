"""
Tests for visual proof status propagation
"""

from django.test import TestCase
from scanner.models import ScanTarget, Scan, Vulnerability
from scanner.exploit_integration import _capture_visual_proof
from unittest.mock import patch, MagicMock


class VisualProofStatusTestCase(TestCase):
    """Test cases for visual proof status propagation"""

    def setUp(self):
        """Set up test data"""
        # Create test scan target and scan
        self.target = ScanTarget.objects.create(
            url='https://example.com',
            name='Test Target'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='completed'
        )

        # Create test vulnerability
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='high',
            url='https://example.com/page1',
            parameter='search',
            description='XSS vulnerability',
            evidence='Script tag reflected'
        )

    @patch('scanner.exploit_integration.get_visual_proof_capture')
    def test_visual_proof_status_missing_dependencies(self, mock_get_capture):
        """Test that status is set to 'missing_dependencies' when dependencies are missing"""
        # Mock get_visual_proof_capture to return None (simulating missing dependencies)
        mock_get_capture.return_value = None
        
        # Call _capture_visual_proof
        result = {'success': True, 'evidence': 'XSS triggered'}
        _capture_visual_proof(self.vuln, result, {})
        
        # Refresh from database
        self.vuln.refresh_from_db()
        
        # Verify status is set correctly
        self.assertEqual(self.vuln.visual_proof_status, 'missing_dependencies')
        self.assertIsNone(self.vuln.visual_proof_path)

    @patch('scanner.exploit_integration.get_visual_proof_capture')
    def test_visual_proof_status_capture_failed(self, mock_get_capture):
        """Test that status is set to 'failed' when capture returns None"""
        # Mock capture instance that returns None (capture failed)
        mock_capture = MagicMock()
        mock_capture.capture_exploit_proof.return_value = None
        mock_get_capture.return_value = mock_capture
        
        # Call _capture_visual_proof
        result = {'success': True, 'evidence': 'XSS triggered'}
        _capture_visual_proof(self.vuln, result, {})
        
        # Refresh from database
        self.vuln.refresh_from_db()
        
        # Verify status is set correctly
        self.assertEqual(self.vuln.visual_proof_status, 'failed')
        self.assertIsNone(self.vuln.visual_proof_path)

    @patch('scanner.exploit_integration.get_visual_proof_capture')
    def test_visual_proof_status_captured_success(self, mock_get_capture):
        """Test that status is set to 'captured' on successful capture"""
        # Mock successful capture
        mock_capture = MagicMock()
        mock_capture.capture_exploit_proof.return_value = {
            'path': 'media/exploit_proofs/xss_1_test.png',
            'type': 'screenshot',
            'size': 12345,
            'url': 'https://example.com/page1'
        }
        mock_get_capture.return_value = mock_capture
        
        # Call _capture_visual_proof
        result = {'success': True, 'evidence': 'XSS triggered'}
        _capture_visual_proof(self.vuln, result, {})
        
        # Refresh from database
        self.vuln.refresh_from_db()
        
        # Verify status and data are set correctly
        self.assertEqual(self.vuln.visual_proof_status, 'captured')
        self.assertEqual(self.vuln.visual_proof_path, 'media/exploit_proofs/xss_1_test.png')
        self.assertEqual(self.vuln.visual_proof_type, 'screenshot')
        self.assertEqual(self.vuln.visual_proof_size, 12345)

    @patch('scanner.exploit_integration.get_visual_proof_capture')
    def test_visual_proof_status_exception_handling(self, mock_get_capture):
        """Test that status is set to 'failed' when exception occurs"""
        # Mock capture that raises an exception
        mock_capture = MagicMock()
        mock_capture.capture_exploit_proof.side_effect = Exception("Test error")
        mock_get_capture.return_value = mock_capture
        
        # Call _capture_visual_proof
        result = {'success': True, 'evidence': 'XSS triggered'}
        _capture_visual_proof(self.vuln, result, {})
        
        # Refresh from database
        self.vuln.refresh_from_db()
        
        # Verify status is set correctly
        self.assertEqual(self.vuln.visual_proof_status, 'failed')
        self.assertIsNone(self.vuln.visual_proof_path)

    def test_visual_proof_status_default_value(self):
        """Test that visual_proof_status has correct default value"""
        # Create new vulnerability
        new_vuln = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='sqli',
            severity='critical',
            url='https://example.com/page2',
            parameter='id',
            description='SQL Injection',
            evidence='SQL error'
        )
        
        # Verify default status
        self.assertEqual(new_vuln.visual_proof_status, 'not_attempted')
