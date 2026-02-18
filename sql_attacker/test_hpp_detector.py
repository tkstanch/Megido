"""
Unit tests for HTTP Parameter Pollution Detector

Tests HPP detection with URL generation and response analysis.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.client_side.hpp_detector import (
    HTTPParameterPollutionDetector,
    HPPFinding,
    HPPTechnique
)


class TestHTTPParameterPollutionDetector(unittest.TestCase):
    """Test cases for HTTPParameterPollutionDetector"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = HTTPParameterPollutionDetector(timeout=10, verify_ssl=False)
    
    def test_initialization(self):
        """Test detector initialization"""
        self.assertEqual(self.detector.timeout, 10)
        self.assertFalse(self.detector.verify_ssl)
        self.assertTrue(self.detector.follow_redirects)
        self.assertEqual(len(self.detector.findings), 0)
    
    def test_generate_test_urls(self):
        """Test generation of test URLs"""
        base_url = "https://example.com/search"
        params = {'q': 'test', 'page': '1'}
        
        test_urls = self.detector.generate_test_urls(base_url, params)
        
        self.assertIsInstance(test_urls, dict)
        self.assertIn('duplicate', test_urls)
        self.assertIn('array', test_urls)
        self.assertGreater(len(test_urls['duplicate']), 0)
        
        # Check duplicate parameter format
        duplicate_url = test_urls['duplicate'][0]
        self.assertIn('q=test', duplicate_url)
        self.assertIn('q=test2', duplicate_url)
    
    def test_array_notation_url_generation(self):
        """Test array notation URL generation"""
        base_url = "https://example.com/api"
        params = {'id': '123'}
        
        test_urls = self.detector.generate_test_urls(base_url, params)
        
        # Check array notation
        array_url = test_urls['array'][0]
        self.assertIn('id[]', array_url)
    
    @patch('sql_attacker.client_side.hpp_detector.requests.Session.get')
    def test_scan_url_with_mocked_response(self, mock_get):
        """Test URL scanning with mocked responses"""
        # Mock baseline response
        baseline_response = Mock()
        baseline_response.status_code = 200
        baseline_response.content = b"Baseline content"
        
        # Mock different response
        different_response = Mock()
        different_response.status_code = 200
        different_response.content = b"Different content with more data"
        
        mock_get.side_effect = [baseline_response, different_response]
        
        url = "https://example.com/test?param=value"
        findings = self.detector.scan_url(url)
        
        # Should have made requests
        self.assertGreater(mock_get.call_count, 0)
    
    def test_has_significant_difference_status_code(self):
        """Test detection of status code differences"""
        response1 = Mock()
        response1.status_code = 200
        response1.content = b"content"
        
        response2 = Mock()
        response2.status_code = 404
        response2.content = b"content"
        
        self.assertTrue(self.detector._has_significant_difference(response1, response2))
    
    def test_has_significant_difference_content_length(self):
        """Test detection of content length differences"""
        response1 = Mock()
        response1.status_code = 200
        response1.content = b"a" * 100
        
        response2 = Mock()
        response2.status_code = 200
        response2.content = b"a" * 200  # 100% difference
        
        self.assertTrue(self.detector._has_significant_difference(response1, response2))
    
    def test_has_significant_difference_error_keywords(self):
        """Test detection of error keywords"""
        response1 = Mock()
        response1.status_code = 200
        response1.content = b"Normal content"
        
        response2 = Mock()
        response2.status_code = 200
        response2.content = b"SQL error: syntax exception"
        
        self.assertTrue(self.detector._has_significant_difference(response1, response2))
    
    def test_no_significant_difference(self):
        """Test when responses are similar"""
        response1 = Mock()
        response1.status_code = 200
        response1.content = b"Same content"
        
        response2 = Mock()
        response2.status_code = 200
        response2.content = b"Same content"
        
        self.assertFalse(self.detector._has_significant_difference(response1, response2))
    
    def test_report_generation(self):
        """Test report generation"""
        # Add some findings
        self.detector.findings = [
            HPPFinding(
                technique=HPPTechnique.DUPLICATE_PARAM.value,
                severity="MEDIUM",
                url="https://example.com",
                original_params={'id': '1'},
                polluted_params="id=1&id=2",
                response_code=200,
                behavior="Changed response"
            ),
            HPPFinding(
                technique=HPPTechnique.ARRAY_NOTATION.value,
                severity="MEDIUM",
                url="https://example.com",
                original_params={'id': '1'},
                polluted_params="id[]=1",
                response_code=200,
                behavior="Array handling"
            ),
        ]
        
        report = self.detector.get_report()
        
        self.assertEqual(report['total_findings'], 2)
        self.assertEqual(report['by_severity']['MEDIUM'], 2)
        self.assertEqual(report['by_technique'][HPPTechnique.DUPLICATE_PARAM.value], 1)
        self.assertEqual(report['by_technique'][HPPTechnique.ARRAY_NOTATION.value], 1)
    
    def test_empty_params_warning(self):
        """Test handling of URL without parameters"""
        url = "https://example.com/page"
        findings = self.detector.scan_url(url)
        
        # Should return empty findings for URL without params
        self.assertEqual(len(findings), 0)


class TestHPPFinding(unittest.TestCase):
    """Test cases for HPPFinding dataclass"""
    
    def test_finding_creation(self):
        """Test HPPFinding creation"""
        finding = HPPFinding(
            technique=HPPTechnique.DUPLICATE_PARAM.value,
            severity="MEDIUM",
            url="https://test.com",
            original_params={'id': '1'},
            polluted_params="id=1&id=2",
            response_code=200,
            behavior="Test behavior"
        )
        
        self.assertEqual(finding.technique, HPPTechnique.DUPLICATE_PARAM.value)
        self.assertEqual(finding.severity, "MEDIUM")
        self.assertEqual(finding.response_code, 200)
    
    def test_finding_to_dict(self):
        """Test conversion to dictionary"""
        finding = HPPFinding(
            technique="test",
            severity="HIGH",
            url="https://test.com",
            original_params={},
            polluted_params="test",
            response_code=200
        )
        
        result = finding.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['technique'], "test")
        self.assertEqual(result['severity'], "HIGH")


class TestHPPTechnique(unittest.TestCase):
    """Test cases for HPPTechnique enum"""
    
    def test_technique_values(self):
        """Test that all techniques are defined"""
        self.assertEqual(HPPTechnique.DUPLICATE_PARAM.value, "duplicate_parameter")
        self.assertEqual(HPPTechnique.ENCODED_PARAM.value, "encoded_parameter")
        self.assertEqual(HPPTechnique.MIXED_CASE.value, "mixed_case")
        self.assertEqual(HPPTechnique.ARRAY_NOTATION.value, "array_notation")
        self.assertEqual(HPPTechnique.SEMICOLON_SEPARATOR.value, "semicolon_separator")
        self.assertEqual(HPPTechnique.AMPERSAND_ENCODED.value, "ampersand_encoded")


if __name__ == '__main__':
    unittest.main()
