"""
Tests for Scan Plugin System

This module tests the plugin-based vulnerability scanning architecture.
"""

from django.test import TestCase
from unittest.mock import Mock, patch, MagicMock
from scanner.scan_plugins import (
    get_scan_registry,
    BaseScanPlugin,
    VulnerabilityFinding,
    ScanSeverity,
)
from scanner.scan_plugins.scan_plugin_registry import reset_scan_registry
from scanner.scan_engine import get_scan_engine, ScanEngine
from scanner.models import Scan, ScanTarget, Vulnerability


class TestScanPluginRegistry(TestCase):
    """Test the scan plugin registry"""
    
    def setUp(self):
        """Reset registry before each test"""
        reset_scan_registry()
    
    def test_registry_singleton(self):
        """Test that registry returns the same instance"""
        registry1 = get_scan_registry()
        registry2 = get_scan_registry()
        self.assertIs(registry1, registry2)
    
    def test_plugin_discovery(self):
        """Test that plugins are discovered automatically"""
        registry = get_scan_registry()
        plugin_count = registry.get_plugin_count()
        
        # Should find at least 3 plugins (xss, headers, ssl)
        self.assertGreaterEqual(plugin_count, 3)
    
    def test_get_plugin_by_id(self):
        """Test retrieving a plugin by its ID"""
        registry = get_scan_registry()
        
        xss_plugin = registry.get_plugin('xss_scanner')
        self.assertIsNotNone(xss_plugin)
        self.assertEqual(xss_plugin.plugin_id, 'xss_scanner')
    
    def test_list_plugins(self):
        """Test listing all plugins"""
        registry = get_scan_registry()
        plugins = registry.list_plugins()
        
        self.assertIsInstance(plugins, list)
        self.assertGreater(len(plugins), 0)
        
        # Check structure of plugin info
        for plugin_info in plugins:
            self.assertIn('plugin_id', plugin_info)
            self.assertIn('name', plugin_info)
            self.assertIn('description', plugin_info)
            self.assertIn('version', plugin_info)
            self.assertIn('vulnerability_types', plugin_info)
    
    def test_has_plugin(self):
        """Test checking if plugin exists"""
        registry = get_scan_registry()
        
        self.assertTrue(registry.has_plugin('xss_scanner'))
        self.assertFalse(registry.has_plugin('nonexistent_plugin'))


class TestXSSScannerPlugin(TestCase):
    """Test the XSS scanner plugin"""
    
    def setUp(self):
        """Get the XSS plugin"""
        registry = get_scan_registry()
        self.plugin = registry.get_plugin('xss_scanner')
    
    def test_plugin_exists(self):
        """Test that XSS plugin is loaded"""
        self.assertIsNotNone(self.plugin)
    
    def test_plugin_properties(self):
        """Test plugin properties"""
        self.assertEqual(self.plugin.plugin_id, 'xss_scanner')
        self.assertEqual(self.plugin.name, 'XSS Vulnerability Scanner')
        self.assertIn('xss', self.plugin.vulnerability_types)
    
    @patch('scanner.scan_plugins.detectors.xss_scanner.requests')
    @patch('scanner.scan_plugins.detectors.xss_scanner.BeautifulSoup')
    def test_scan_finds_form(self, mock_bs4, mock_requests):
        """Test that plugin detects forms with inputs"""
        # Mock response
        mock_response = Mock()
        mock_response.text = '<html><form action="/test"><input name="q"></form></html>'
        mock_requests.get.return_value = mock_response
        
        # Mock BeautifulSoup
        mock_form = Mock()
        mock_form.get.return_value = '/test'
        mock_input = Mock()
        mock_input.get.return_value = 'q'
        mock_form.find_all.return_value = [mock_input]
        
        mock_soup = Mock()
        mock_soup.find_all.return_value = [mock_form]
        mock_bs4.return_value = mock_soup
        
        # Run scan
        findings = self.plugin.scan('http://example.com')
        
        # Should find at least one potential XSS vulnerability
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].vulnerability_type, 'xss')


class TestSecurityHeadersScannerPlugin(TestCase):
    """Test the security headers scanner plugin"""
    
    def setUp(self):
        """Get the security headers plugin"""
        registry = get_scan_registry()
        self.plugin = registry.get_plugin('security_headers_scanner')
    
    def test_plugin_exists(self):
        """Test that security headers plugin is loaded"""
        self.assertIsNotNone(self.plugin)
    
    def test_plugin_properties(self):
        """Test plugin properties"""
        self.assertEqual(self.plugin.plugin_id, 'security_headers_scanner')
        self.assertIn('Security Headers', self.plugin.name)
    
    @patch('scanner.scan_plugins.detectors.security_headers_scanner.requests')
    def test_scan_finds_missing_headers(self, mock_requests):
        """Test that plugin detects missing security headers"""
        # Mock response with no security headers
        mock_response = Mock()
        mock_response.headers = {}
        mock_requests.get.return_value = mock_response
        
        # Run scan
        findings = self.plugin.scan('http://example.com')
        
        # Should find missing headers (4 headers checked)
        self.assertGreaterEqual(len(findings), 4)
        
        # Check that findings are for missing headers
        header_names = ['X-Frame-Options', 'X-Content-Type-Options', 
                       'Strict-Transport-Security', 'Content-Security-Policy']
        for finding in findings:
            self.assertIn(finding.description, [f'Missing {h} header' for h in header_names])


class TestSSLScannerPlugin(TestCase):
    """Test the SSL/TLS scanner plugin"""
    
    def setUp(self):
        """Get the SSL scanner plugin"""
        registry = get_scan_registry()
        self.plugin = registry.get_plugin('ssl_scanner')
    
    def test_plugin_exists(self):
        """Test that SSL plugin is loaded"""
        self.assertIsNotNone(self.plugin)
    
    def test_plugin_properties(self):
        """Test plugin properties"""
        self.assertEqual(self.plugin.plugin_id, 'ssl_scanner')
        self.assertIn('SSL', self.plugin.name)
    
    def test_scan_detects_http(self):
        """Test that plugin detects HTTP usage"""
        # Run scan on HTTP URL
        findings = self.plugin.scan('http://example.com')
        
        # Should find that HTTP is insecure
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, 'info_disclosure')
        self.assertIn('insecure HTTP', findings[0].description)
    
    def test_scan_accepts_https(self):
        """Test that plugin doesn't flag HTTPS"""
        # Run scan on HTTPS URL
        findings = self.plugin.scan('https://example.com')
        
        # Should not find issues with HTTPS
        self.assertEqual(len(findings), 0)


class TestVulnerabilityFinding(TestCase):
    """Test the VulnerabilityFinding data class"""
    
    def test_create_finding(self):
        """Test creating a vulnerability finding"""
        finding = VulnerabilityFinding(
            vulnerability_type='xss',
            severity='high',
            url='http://example.com',
            description='Test vulnerability',
            evidence='Test evidence',
            remediation='Test remediation',
            parameter='test_param',
            confidence=0.9,
            cwe_id='CWE-79'
        )
        
        self.assertEqual(finding.vulnerability_type, 'xss')
        self.assertEqual(finding.severity, 'high')
        self.assertEqual(finding.confidence, 0.9)
    
    def test_finding_to_dict(self):
        """Test converting finding to dictionary"""
        finding = VulnerabilityFinding(
            vulnerability_type='xss',
            severity='medium',
            url='http://example.com',
            description='Test',
            evidence='Evidence',
            remediation='Fix it'
        )
        
        finding_dict = finding.to_dict()
        
        self.assertIsInstance(finding_dict, dict)
        self.assertEqual(finding_dict['vulnerability_type'], 'xss')
        self.assertEqual(finding_dict['severity'], 'medium')


class TestScanEngine(TestCase):
    """Test the scan engine"""
    
    def setUp(self):
        """Create scan target and scan for testing"""
        self.target = ScanTarget.objects.create(
            url='http://example.com',
            name='Test Target'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='running'
        )
    
    def test_engine_initialization(self):
        """Test that scan engine initializes correctly"""
        engine = get_scan_engine()
        self.assertIsInstance(engine, ScanEngine)
        self.assertGreater(engine.registry.get_plugin_count(), 0)
    
    def test_list_available_plugins(self):
        """Test listing available plugins"""
        engine = get_scan_engine()
        plugins = engine.list_available_plugins()
        
        self.assertIsInstance(plugins, list)
        self.assertGreater(len(plugins), 0)
    
    @patch('scanner.scan_plugins.detectors.ssl_scanner.SSLScannerPlugin.scan')
    def test_scan_with_specific_plugins(self, mock_scan):
        """Test scanning with specific plugins only"""
        # Mock the scan method
        mock_scan.return_value = [
            VulnerabilityFinding(
                vulnerability_type='info_disclosure',
                severity='medium',
                url='http://example.com',
                description='Test finding',
                evidence='Test evidence',
                remediation='Test remediation'
            )
        ]
        
        engine = get_scan_engine()
        findings = engine.scan_with_plugins(
            url='http://example.com',
            plugin_ids=['ssl_scanner']
        )
        
        self.assertGreater(len(findings), 0)
        mock_scan.assert_called_once()
    
    def test_save_findings_to_db(self):
        """Test saving findings to database"""
        engine = get_scan_engine()
        
        findings = [
            VulnerabilityFinding(
                vulnerability_type='xss',
                severity='high',
                url='http://example.com',
                description='Test XSS',
                evidence='Evidence',
                remediation='Fix it',
                parameter='q',
                confidence=0.8,
                cwe_id='CWE-79'
            ),
            VulnerabilityFinding(
                vulnerability_type='other',
                severity='low',
                url='http://example.com',
                description='Missing header',
                evidence='Header not found',
                remediation='Add header',
                confidence=0.9
            )
        ]
        
        vulnerabilities = engine.save_findings_to_db(self.scan, findings)
        
        # Check that vulnerabilities were saved
        self.assertEqual(len(vulnerabilities), 2)
        self.assertEqual(vulnerabilities[0].vulnerability_type, 'xss')
        self.assertEqual(vulnerabilities[1].vulnerability_type, 'other')
        
        # Check database
        db_vulns = Vulnerability.objects.filter(scan=self.scan)
        self.assertEqual(db_vulns.count(), 2)


class TestScannerIntegration(TestCase):
    """Integration tests for the scanner with plugin system"""
    
    def setUp(self):
        """Create test data"""
        self.target = ScanTarget.objects.create(
            url='http://example.com',
            name='Test Target'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='running'
        )
    
    @patch('scanner.scan_plugins.detectors.ssl_scanner.SSLScannerPlugin.scan')
    def test_perform_basic_scan_uses_plugins(self, mock_ssl_scan):
        """Test that perform_basic_scan uses the plugin engine"""
        from scanner.views import perform_basic_scan
        
        # Mock SSL scanner to return a finding
        mock_ssl_scan.return_value = [
            VulnerabilityFinding(
                vulnerability_type='info_disclosure',
                severity='medium',
                url='http://example.com',
                description='Insecure HTTP',
                evidence='Using HTTP',
                remediation='Use HTTPS'
            )
        ]
        
        # Run the scan
        perform_basic_scan(self.scan, 'http://example.com')
        
        # Check that vulnerabilities were created
        vulns = Vulnerability.objects.filter(scan=self.scan)
        self.assertGreater(vulns.count(), 0)
