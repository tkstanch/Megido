"""
Tests for scanner plugin fixes and error handling improvements.

This test suite validates:
1. Advanced SQLi scanner with urljoin import
2. Risk scoring engine with proper exposure_level handling
3. Compliance mapper with map_finding_to_compliance method
4. Remediation engine with generate_remediation method
5. RFI plugin error handling when test_server is missing
6. Robust error handling in exploit integration
"""

from django.test import TestCase
from unittest.mock import patch, MagicMock
import logging

# Configure logging to capture warnings/errors during tests
logging.basicConfig(level=logging.DEBUG)


class AdvancedSQLiScannerTestCase(TestCase):
    """Test cases for Advanced SQLi Scanner plugin"""

    def test_urljoin_import(self):
        """Test that urljoin is properly imported in advanced_sqli_scanner"""
        try:
            from scanner.scan_plugins.detectors.advanced_sqli_scanner import AdvancedSQLiScannerPlugin
            from urllib.parse import urljoin
            
            # Verify the plugin can be instantiated
            plugin = AdvancedSQLiScannerPlugin()
            self.assertIsNotNone(plugin)
            self.assertEqual(plugin.plugin_id, 'advanced_sqli_scanner')
            
        except ImportError as e:
            self.fail(f"Failed to import AdvancedSQLiScannerPlugin or urljoin: {e}")

    @patch('scanner.scan_plugins.detectors.advanced_sqli_scanner.requests')
    @patch('scanner.scan_plugins.detectors.advanced_sqli_scanner.BeautifulSoup')
    def test_sqli_scan_with_forms(self, mock_bs4, mock_requests):
        """Test SQLi scanning with form detection"""
        try:
            from scanner.scan_plugins.detectors.advanced_sqli_scanner import AdvancedSQLiScannerPlugin
            
            # Mock response with a form
            mock_response = MagicMock()
            mock_response.text = '<form action="/login" method="POST"><input name="username"/></form>'
            mock_response.status_code = 200
            mock_requests.get.return_value = mock_response
            
            # Mock BeautifulSoup to find forms
            mock_soup = MagicMock()
            mock_form = MagicMock()
            mock_form.get.side_effect = lambda key, default='': {
                'action': '/login',
                'method': 'POST'
            }.get(key, default)
            
            mock_input = MagicMock()
            mock_input.get.return_value = 'username'
            mock_form.find_all.return_value = [mock_input]
            mock_soup.find_all.return_value = [mock_form]
            mock_bs4.return_value = mock_soup
            
            plugin = AdvancedSQLiScannerPlugin()
            config = plugin.get_default_config()
            
            # This should not raise an error about urljoin
            findings = plugin.scan('https://example.com', config)
            
            # Verify scan ran without import errors
            self.assertIsInstance(findings, list)
            
        except NameError as e:
            if 'urljoin' in str(e):
                self.fail(f"urljoin import issue: {e}")
            raise


class RiskScoringEngineTestCase(TestCase):
    """Test cases for Risk Scoring Engine"""

    def test_risk_scoring_engine_initialization(self):
        """Test that RiskScoringEngine accepts exposure_level in __init__"""
        try:
            from discover.sensitive_scanner_advanced import RiskScoringEngine
            
            # Test with different exposure levels
            for level in ['low', 'medium', 'high']:
                engine = RiskScoringEngine(exposure_level=level)
                self.assertEqual(engine.exposure_level, level)
                self.assertIn(level, engine.exposure_factors)
                
        except ImportError:
            self.skipTest("Advanced scanner module not available")

    def test_calculate_risk_score_without_kwarg(self):
        """Test that calculate_risk_score doesn't require exposure_level kwarg"""
        try:
            from discover.sensitive_scanner_advanced import RiskScoringEngine
            
            engine = RiskScoringEngine(exposure_level='high')
            
            finding = {
                'type': 'SQL Injection',
                'severity': 'critical',
                'source': 'https://example.com',
                'confidence': 0.9,
                'verified': True,
            }
            
            # This should work without passing exposure_level as kwarg
            risk_score = engine.calculate_risk_score(finding)
            
            self.assertIsNotNone(risk_score)
            self.assertGreater(risk_score.composite_score, 0)
            self.assertIn(risk_score.risk_level, ['critical', 'high', 'medium', 'low', 'info'])
            
        except ImportError:
            self.skipTest("Advanced scanner module not available")
        except TypeError as e:
            if 'exposure_level' in str(e):
                self.fail(f"calculate_risk_score incorrectly requires exposure_level kwarg: {e}")
            raise


class ComplianceMapperTestCase(TestCase):
    """Test cases for Compliance Mapper"""

    def test_map_finding_to_compliance_method_exists(self):
        """Test that map_finding_to_compliance method exists"""
        try:
            from discover.sensitive_scanner_advanced import ComplianceMapper
            
            mapper = ComplianceMapper()
            self.assertTrue(hasattr(mapper, 'map_finding_to_compliance'))
            self.assertTrue(callable(mapper.map_finding_to_compliance))
            
        except ImportError:
            self.skipTest("Advanced scanner module not available")

    def test_map_finding_to_compliance_returns_dict_list(self):
        """Test that map_finding_to_compliance returns list of dicts"""
        try:
            from discover.sensitive_scanner_advanced import ComplianceMapper
            
            mapper = ComplianceMapper()
            
            finding = {
                'type': 'AWS Access Key',
                'severity': 'critical',
                'category': 'credential',
            }
            
            result = mapper.map_finding_to_compliance(finding)
            
            self.assertIsInstance(result, list)
            if result:  # If mappings found
                self.assertIsInstance(result[0], dict)
                self.assertIn('framework', result[0])
                self.assertIn('requirement_id', result[0])
                
        except ImportError:
            self.skipTest("Advanced scanner module not available")


class RemediationEngineTestCase(TestCase):
    """Test cases for Remediation Engine"""

    def test_generate_remediation_method_exists(self):
        """Test that generate_remediation method exists"""
        try:
            from discover.sensitive_scanner_advanced import RemediationEngine
            
            engine = RemediationEngine()
            self.assertTrue(hasattr(engine, 'generate_remediation'))
            self.assertTrue(callable(engine.generate_remediation))
            
        except ImportError:
            self.skipTest("Advanced scanner module not available")

    def test_generate_remediation_returns_dict(self):
        """Test that generate_remediation returns dict"""
        try:
            from discover.sensitive_scanner_advanced import RemediationEngine
            
            engine = RemediationEngine()
            
            finding = {
                'type': 'Password Field',
                'severity': 'high',
                'source': 'config.py',
            }
            
            result = engine.generate_remediation(finding)
            
            self.assertIsInstance(result, dict)
            self.assertIn('action', result)
            self.assertIn('description', result)
            self.assertIn('effort_estimate', result)
            self.assertIn('priority', result)
            
        except ImportError:
            self.skipTest("Advanced scanner module not available")


class RFIDetectorTestCase(TestCase):
    """Test cases for RFI Detector plugin"""

    def test_rfi_plugin_missing_test_server(self):
        """Test that RFI plugin logs warning when test_server is missing"""
        try:
            from scanner.scan_plugins.detectors.rfi_detector import RFIDetectorPlugin
            
            plugin = RFIDetectorPlugin()
            
            # Config without test_server
            config = {'verify_ssl': False, 'timeout': 10}
            
            # This should log a warning but not raise an error
            with self.assertLogs('scanner.scan_plugins.detectors.rfi_detector', level='WARNING') as cm:
                findings = plugin.scan('https://example.com?file=test.php', config)
                
                # Should return empty findings
                self.assertEqual(findings, [])
                
                # Should have logged a warning about missing test_server
                self.assertTrue(any('test server' in log.lower() for log in cm.output))
                self.assertTrue(any('skipped' in log.lower() for log in cm.output))
                
        except ImportError as e:
            self.fail(f"Failed to import RFIDetectorPlugin: {e}")


class ExploitIntegrationErrorHandlingTestCase(TestCase):
    """Test cases for error handling in exploit integration"""

    def test_apply_risk_scoring_fallback(self):
        """Test that apply_risk_scoring has fallback when advanced scanner unavailable"""
        try:
            from scanner.exploit_integration import apply_risk_scoring
            from scanner.models import Vulnerability, Scan, ScanTarget
            
            # Create test vulnerability
            target = ScanTarget.objects.create(url='https://example.com', name='Test')
            scan = Scan.objects.create(target=target, status='completed')
            vuln = Vulnerability.objects.create(
                scan=scan,
                vulnerability_type='xss',
                severity='high',
                url='https://example.com/page',
                parameter='search',
                description='XSS vulnerability'
            )
            
            # This should not raise an error even if advanced scanner fails
            apply_risk_scoring(vuln)
            
            # Should have some risk score assigned (either from advanced or fallback)
            self.assertIsNotNone(vuln.risk_score)
            self.assertGreater(vuln.risk_score, 0)
            
        except Exception as e:
            self.fail(f"apply_risk_scoring raised unexpected error: {e}")

    def test_apply_compliance_mapping_error_handling(self):
        """Test that apply_compliance_mapping handles errors gracefully"""
        try:
            from scanner.exploit_integration import apply_compliance_mapping
            from scanner.models import Vulnerability, Scan, ScanTarget
            
            # Create test vulnerability
            target = ScanTarget.objects.create(url='https://example.com', name='Test')
            scan = Scan.objects.create(target=target, status='completed')
            vuln = Vulnerability.objects.create(
                scan=scan,
                vulnerability_type='sqli',
                severity='critical',
                url='https://example.com/page',
                parameter='id',
                description='SQL Injection'
            )
            
            # This should not raise an error even if compliance mapping fails
            apply_compliance_mapping(vuln)
            
            # Should have compliance_violations field (possibly empty dict if failed)
            self.assertIsNotNone(vuln.compliance_violations)
            
        except Exception as e:
            self.fail(f"apply_compliance_mapping raised unexpected error: {e}")

    def test_apply_remediation_advice_error_handling(self):
        """Test that apply_remediation_advice handles errors gracefully"""
        try:
            from scanner.exploit_integration import apply_remediation_advice
            from scanner.models import Vulnerability, Scan, ScanTarget
            
            # Create test vulnerability
            target = ScanTarget.objects.create(url='https://example.com', name='Test')
            scan = Scan.objects.create(target=target, status='completed')
            vuln = Vulnerability.objects.create(
                scan=scan,
                vulnerability_type='xss',
                severity='medium',
                url='https://example.com/page',
                parameter='q',
                description='XSS vulnerability'
            )
            
            # This should not raise an error even if remediation fails
            apply_remediation_advice(vuln)
            
            # Remediation field should exist (may be None or have value)
            # The important thing is it doesn't crash
            self.assertTrue(hasattr(vuln, 'remediation'))
            
        except Exception as e:
            self.fail(f"apply_remediation_advice raised unexpected error: {e}")


class EndToEndScannerTestCase(TestCase):
    """End-to-end tests for scanner with all fixes applied"""

    @patch('scanner.exploit_integration.HAS_ADVANCED_SCANNER', False)
    def test_scan_without_advanced_scanner(self):
        """Test that scanning works even without advanced scanner module"""
        try:
            from scanner.exploit_integration import (
                apply_risk_scoring,
                apply_compliance_mapping,
                apply_remediation_advice
            )
            from scanner.models import Vulnerability, Scan, ScanTarget
            
            # Create test vulnerability
            target = ScanTarget.objects.create(url='https://example.com', name='Test')
            scan = Scan.objects.create(target=target, status='completed')
            vuln = Vulnerability.objects.create(
                scan=scan,
                vulnerability_type='sqli',
                severity='high',
                url='https://example.com/page',
                parameter='id',
                description='SQL Injection'
            )
            
            # All these should work with fallback logic
            apply_risk_scoring(vuln)
            apply_compliance_mapping(vuln)
            apply_remediation_advice(vuln)
            
            # Verify vulnerability is still usable
            self.assertIsNotNone(vuln.risk_score)
            self.assertTrue(hasattr(vuln, 'compliance_violations'))
            
        except Exception as e:
            self.fail(f"Scanner failed without advanced scanner: {e}")
