"""
Unit tests for Client-Side Scan Orchestrator

Tests integration of all client-side scanners.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import tempfile
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_side.orchestrator import (
    ClientSideScanOrchestrator,
    ScanConfiguration,
    ScanResults,
    ScanType
)
from client_side.browser_automation import BrowserFinding
from client_side.static_scanner import StaticFinding
from client_side.hpp_detector import HPPFinding
from client_side.privacy_analyzer import PrivacyFinding, RiskLevel, StorageLocation


class TestClientSideScanOrchestrator(unittest.TestCase):
    """Test cases for ClientSideScanOrchestrator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.orchestrator = ClientSideScanOrchestrator()
    
    def test_initialization(self):
        """Test orchestrator initialization"""
        self.assertIsNone(self.orchestrator.current_scan)
    
    def test_scan_configuration_creation(self):
        """Test ScanConfiguration creation"""
        config = ScanConfiguration(
            scan_types=[ScanType.STATIC_JAVASCRIPT.value],
            javascript_code="var x = 1;",
            use_playwright=True,
            headless=True
        )
        
        self.assertEqual(config.scan_types, [ScanType.STATIC_JAVASCRIPT.value])
        self.assertEqual(config.javascript_code, "var x = 1;")
        self.assertTrue(config.use_playwright)
    
    def test_scan_configuration_to_dict(self):
        """Test ScanConfiguration to_dict"""
        config = ScanConfiguration(
            scan_types=[ScanType.ALL.value],
            target_url="https://example.com"
        )
        
        result = config.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['scan_types'], [ScanType.ALL.value])
        self.assertEqual(result['target_url'], "https://example.com")
    
    @patch('client_side.orchestrator.JavaScriptStaticScanner')
    def test_run_static_analysis(self, mock_scanner_class):
        """Test running static JavaScript analysis"""
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner.scan_code.return_value = [
            StaticFinding(
                vulnerability_type="TEST",
                severity="HIGH",
                file_path="test.js",
                line_number=1,
                code_snippet="code",
                description="desc",
                recommendation="rec"
            )
        ]
        mock_scanner_class.return_value = mock_scanner
        
        config = ScanConfiguration(
            scan_types=[ScanType.STATIC_JAVASCRIPT.value],
            javascript_code="var x = 1;"
        )
        
        findings = self.orchestrator._run_static_analysis(config)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "TEST")
    
    @patch('client_side.orchestrator.HTTPParameterPollutionDetector')
    def test_run_hpp_detection(self, mock_detector_class):
        """Test running HPP detection"""
        # Mock detector
        mock_detector = Mock()
        mock_detector.scan_url.return_value = [
            HPPFinding(
                technique="duplicate_parameter",
                severity="MEDIUM",
                url="https://example.com",
                original_params={'id': '1'},
                polluted_params="id=1&id=2",
                response_code=200
            )
        ]
        mock_detector_class.return_value = mock_detector
        
        config = ScanConfiguration(
            scan_types=[ScanType.HPP_DETECTION.value],
            target_url="https://example.com?id=1"
        )
        
        findings = self.orchestrator._run_hpp_detection(config)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "duplicate_parameter")
    
    def test_generate_summary(self):
        """Test summary generation"""
        # Create mock results
        results = ScanResults(
            scan_id="test_123",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            configuration=ScanConfiguration(scan_types=[ScanType.ALL.value]),
            browser_findings=[
                BrowserFinding(
                    finding_type="SQL_ERROR",
                    severity="HIGH",
                    url="https://example.com",
                    payload="test"
                )
            ],
            static_findings=[
                StaticFinding(
                    vulnerability_type="UNSAFE_SQL",
                    severity="CRITICAL",
                    file_path="test.js",
                    line_number=1,
                    code_snippet="code",
                    description="desc",
                    recommendation="rec"
                )
            ],
            hpp_findings=[],
            privacy_findings=[
                PrivacyFinding(
                    risk_type="SENSITIVE_DATA",
                    risk_level=RiskLevel.MEDIUM.value,
                    storage_location=StorageLocation.COOKIES.value,
                    key="test",
                    description="desc",
                    recommendation="rec"
                )
            ],
            summary={}
        )
        
        summary = self.orchestrator._generate_summary(results)
        
        self.assertEqual(summary['total_findings'], 3)
        self.assertEqual(summary['by_scan_type']['browser_automation'], 1)
        self.assertEqual(summary['by_scan_type']['static_javascript'], 1)
        self.assertEqual(summary['by_scan_type']['privacy_analysis'], 1)
        self.assertEqual(summary['by_severity']['HIGH'], 1)
        self.assertEqual(summary['by_severity']['CRITICAL'], 1)
        self.assertEqual(summary['by_severity']['MEDIUM'], 1)
    
    def test_export_results_json(self):
        """Test exporting results to JSON"""
        results = ScanResults(
            scan_id="test_123",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            configuration=ScanConfiguration(scan_types=[ScanType.ALL.value]),
            browser_findings=[],
            static_findings=[],
            hpp_findings=[],
            privacy_findings=[],
            summary={'total_findings': 0},
            status="completed"
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            result_path = self.orchestrator.export_results(results, output_file, format="json")
            
            self.assertTrue(os.path.exists(result_path))
            
            # Verify JSON content
            with open(result_path, 'r') as f:
                data = json.load(f)
                self.assertEqual(data['scan_id'], "test_123")
                self.assertEqual(data['status'], "completed")
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_export_results_html(self):
        """Test exporting results to HTML"""
        results = ScanResults(
            scan_id="test_123",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            configuration=ScanConfiguration(scan_types=[ScanType.ALL.value]),
            browser_findings=[],
            static_findings=[],
            hpp_findings=[],
            privacy_findings=[],
            summary={'total_findings': 0, 'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}, 'scan_duration': '1 minute'},
            status="completed"
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            output_file = f.name
        
        try:
            result_path = self.orchestrator.export_results(results, output_file, format="html")
            
            self.assertTrue(os.path.exists(result_path))
            
            # Verify HTML content
            with open(result_path, 'r') as f:
                content = f.read()
                self.assertIn('<html>', content)
                self.assertIn('test_123', content)
                self.assertIn('completed', content)
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_html_section_generation(self):
        """Test HTML section generation for different finding types"""
        # Test browser findings section
        browser_findings = [
            BrowserFinding(
                finding_type="TEST",
                severity="HIGH",
                url="https://example.com",
                payload="test_payload"
            )
        ]
        
        html = self.orchestrator._html_section_browser(browser_findings)
        self.assertIn('Browser Automation Findings', html)
        self.assertIn('TEST', html)
        self.assertIn('HIGH', html)
        
        # Test static findings section
        static_findings = [
            StaticFinding(
                vulnerability_type="UNSAFE_SQL",
                severity="CRITICAL",
                file_path="test.js",
                line_number=10,
                code_snippet="SELECT * FROM users",
                description="SQL injection",
                recommendation="Use parameterized queries"
            )
        ]
        
        html = self.orchestrator._html_section_static(static_findings)
        self.assertIn('Static JavaScript Analysis', html)
        self.assertIn('UNSAFE_SQL', html)
        self.assertIn('CRITICAL', html)
    
    def test_scan_with_all_types(self):
        """Test scan with ALL scan types"""
        config = ScanConfiguration(
            scan_types=[ScanType.ALL.value],
            target_url="https://example.com",
            javascript_code="var x = 1;"
        )
        
        # Mock all scanner methods to avoid actual execution
        with patch.object(self.orchestrator, '_run_browser_automation', return_value=[]), \
             patch.object(self.orchestrator, '_run_static_analysis', return_value=[]), \
             patch.object(self.orchestrator, '_run_hpp_detection', return_value=[]), \
             patch.object(self.orchestrator, '_run_privacy_analysis', return_value=[]):
            
            results = self.orchestrator.scan(config)
            
            self.assertEqual(results.status, "completed")
            self.assertIsNotNone(results.scan_id)
            self.assertIsNotNone(results.summary)
    
    def test_scan_with_error_handling(self):
        """Test scan error handling"""
        config = ScanConfiguration(
            scan_types=[ScanType.STATIC_JAVASCRIPT.value],
            javascript_code="var x = 1;"
        )
        
        # Mock to raise an exception
        with patch.object(self.orchestrator, '_run_static_analysis', side_effect=Exception("Test error")):
            results = self.orchestrator.scan(config)
            
            self.assertEqual(results.status, "failed")
            self.assertIsNotNone(results.error)
            self.assertIn("Test error", results.error)


class TestScanResults(unittest.TestCase):
    """Test cases for ScanResults dataclass"""
    
    def test_scan_results_creation(self):
        """Test ScanResults creation"""
        results = ScanResults(
            scan_id="test_123",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            configuration=ScanConfiguration(scan_types=[ScanType.ALL.value]),
            browser_findings=[],
            static_findings=[],
            hpp_findings=[],
            privacy_findings=[],
            summary={},
            status="completed"
        )
        
        self.assertEqual(results.scan_id, "test_123")
        self.assertEqual(results.status, "completed")
        self.assertEqual(len(results.browser_findings), 0)
    
    def test_scan_results_to_dict(self):
        """Test ScanResults to_dict"""
        results = ScanResults(
            scan_id="test_123",
            start_time="2024-01-01T00:00:00",
            end_time=None,
            configuration=ScanConfiguration(scan_types=[ScanType.ALL.value]),
            browser_findings=[],
            static_findings=[],
            hpp_findings=[],
            privacy_findings=[],
            summary={},
            status="running"
        )
        
        result_dict = results.to_dict()
        
        self.assertIsInstance(result_dict, dict)
        self.assertEqual(result_dict['scan_id'], "test_123")
        self.assertEqual(result_dict['status'], "running")
        self.assertIsNone(result_dict['end_time'])


class TestScanType(unittest.TestCase):
    """Test cases for ScanType enum"""
    
    def test_scan_type_values(self):
        """Test that all scan types are defined"""
        self.assertEqual(ScanType.BROWSER_AUTOMATION.value, "browser_automation")
        self.assertEqual(ScanType.STATIC_JAVASCRIPT.value, "static_javascript")
        self.assertEqual(ScanType.HPP_DETECTION.value, "hpp_detection")
        self.assertEqual(ScanType.PRIVACY_ANALYSIS.value, "privacy_analysis")
        self.assertEqual(ScanType.ALL.value, "all")


if __name__ == '__main__':
    unittest.main()
