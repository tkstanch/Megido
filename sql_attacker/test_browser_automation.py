"""
Unit tests for Browser Automation Worker

Tests browser automation with mocked browser interactions.
"""

import unittest
from unittest.mock import Mock, MagicMock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.client_side.browser_automation import (
    BrowserAutomationWorker,
    BrowserFinding,
    StorageType
)


class TestBrowserAutomationWorker(unittest.TestCase):
    """Test cases for BrowserAutomationWorker"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.worker = BrowserAutomationWorker(headless=True)
    
    def test_initialization(self):
        """Test worker initialization"""
        self.assertTrue(self.worker.use_playwright)
        self.assertTrue(self.worker.headless)
        self.assertEqual(self.worker.timeout, 30000)
        self.assertEqual(len(self.worker.findings), 0)
    
    def test_browser_finding_creation(self):
        """Test BrowserFinding dataclass"""
        finding = BrowserFinding(
            finding_type="SQL_ERROR_IN_CONSOLE",
            severity="HIGH",
            url="https://example.com",
            payload="' OR '1'='1",
            error_message="SQL syntax error"
        )
        
        self.assertEqual(finding.finding_type, "SQL_ERROR_IN_CONSOLE")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIsNotNone(finding.to_dict())
    
    def test_init_playwright(self):
        """Test Playwright initialization"""
        # Test that initialization method exists and can be called
        worker = BrowserAutomationWorker(use_playwright=True, headless=True)
        
        # This will fail to initialize if playwright is not installed, 
        # but should not raise an exception
        try:
            result = worker._init_playwright()
            # Result should be boolean
            self.assertIsInstance(result, bool)
        except ImportError:
            # Expected if Playwright is not installed
            self.assertTrue(True)
    
    def test_payload_in_storage_detection(self):
        """Test detection of payloads in storage"""
        storage_before = {'localStorage': {}}
        storage_after = {'localStorage': {'test_key': "' OR '1'='1"}}
        
        self.worker._check_storage_corruption(
            "https://example.com",
            "' OR '1'='1",
            storage_before,
            storage_after
        )
        
        # Should detect payload in storage
        self.assertGreater(len(self.worker.findings), 0)
        finding = self.worker.findings[0]
        self.assertEqual(finding.finding_type, "PAYLOAD_IN_STORAGE")
    
    def test_corrupted_data_detection(self):
        """Test detection of corrupted data"""
        self.assertTrue(self.worker._is_corrupted_data("null"))
        self.assertTrue(self.worker._is_corrupted_data("undefined"))
        self.assertTrue(self.worker._is_corrupted_data("NaN"))  # Should work now with case-insensitive check
        self.assertTrue(self.worker._is_corrupted_data("syntax error"))
        self.assertFalse(self.worker._is_corrupted_data("normal value"))
    
    def test_storage_leakage_detection(self):
        """Test detection of storage leakage"""
        initial = {'localStorage': {}}
        current = {'localStorage': {'user_password': 'secret123'}}
        
        self.worker._detect_storage_leakage("https://example.com", initial, current)
        
        # Should detect sensitive data
        self.assertGreater(len(self.worker.findings), 0)
        finding = self.worker.findings[0]
        self.assertEqual(finding.finding_type, "SENSITIVE_DATA_LEAKAGE")
        self.assertEqual(finding.severity, "CRITICAL")
    
    def test_findings_report(self):
        """Test report generation"""
        # Add some findings
        self.worker.findings = [
            BrowserFinding(
                finding_type="SQL_ERROR_IN_CONSOLE",
                severity="HIGH",
                url="https://example.com",
                payload="test"
            ),
            BrowserFinding(
                finding_type="PAYLOAD_IN_STORAGE",
                severity="MEDIUM",
                url="https://example.com",
                payload="test2"
            ),
        ]
        
        report = self.worker.get_findings_report()
        
        self.assertEqual(report['total_findings'], 2)
        self.assertEqual(report['by_severity']['HIGH'], 1)
        self.assertEqual(report['by_severity']['MEDIUM'], 1)
        self.assertEqual(report['by_type']['SQL_ERROR_IN_CONSOLE'], 1)
        self.assertEqual(report['by_type']['PAYLOAD_IN_STORAGE'], 1)
    
    def test_cleanup(self):
        """Test browser cleanup"""
        # Should not raise an exception even if browser is not initialized
        self.worker.cleanup()
    
    def test_html5_storage_payloads(self):
        """Test that HTML5 storage payloads are defined"""
        self.assertGreater(len(BrowserAutomationWorker.HTML5_STORAGE_PAYLOADS), 0)
        self.assertIn("' OR '1'='1", BrowserAutomationWorker.HTML5_STORAGE_PAYLOADS)


class TestBrowserFinding(unittest.TestCase):
    """Test cases for BrowserFinding dataclass"""
    
    def test_finding_to_dict(self):
        """Test conversion to dictionary"""
        finding = BrowserFinding(
            finding_type="TEST",
            severity="HIGH",
            url="https://test.com",
            payload="test_payload",
            storage_type="localStorage",
            error_message="test error",
            evidence={'key': 'value'}
        )
        
        result = finding.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['finding_type'], "TEST")
        self.assertEqual(result['severity'], "HIGH")
        self.assertEqual(result['url'], "https://test.com")
        self.assertEqual(result['payload'], "test_payload")


if __name__ == '__main__':
    unittest.main()
