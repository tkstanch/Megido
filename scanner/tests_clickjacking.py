"""
Tests for the Clickjacking Exploit Plugin

This module contains comprehensive tests for the clickjacking plugin including:
- Plugin registration and discovery
- Payload generation
- Security header analysis
- Frameability detection
- HTML PoC generation
- Evidence collection
- Configuration validation
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent.parent))

from scanner.plugins.exploit_plugin import ExploitPlugin
from scanner.plugins.plugin_registry import PluginRegistry, get_registry, reset_registry
from scanner.plugins.payload_generator import PayloadGenerator, get_payload_generator


class TestClickjackingPlugin(unittest.TestCase):
    """Test cases for ClickjackingPlugin."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Import the plugin
        from scanner.plugins.exploits.clickjacking_plugin import ClickjackingPlugin
        self.plugin = ClickjackingPlugin()
        self.test_url = 'http://example.com/test'
    
    def test_plugin_properties(self):
        """Test that plugin properties are correctly set."""
        self.assertEqual(self.plugin.vulnerability_type, 'clickjacking')
        self.assertEqual(self.plugin.name, 'Advanced Clickjacking Exploit')
        self.assertIn('clickjacking', self.plugin.description.lower())
        self.assertEqual(self.plugin.version, '1.0.0')
    
    def test_severity_level(self):
        """Test severity level."""
        self.assertEqual(self.plugin.get_severity_level(), 'medium')
    
    def test_remediation_advice(self):
        """Test that remediation advice is provided."""
        advice = self.plugin.get_remediation_advice()
        self.assertIsInstance(advice, str)
        self.assertGreater(len(advice), 0)
        self.assertIn('X-Frame-Options', advice)
        self.assertIn('Content-Security-Policy', advice)
        self.assertIn('frame-ancestors', advice)
    
    def test_config_validation_valid(self):
        """Test config validation with valid configuration."""
        valid_config = {
            'overlay_opacity': 0.5,
            'browser_type': 'chrome',
            'timeout': 30,
        }
        self.assertTrue(self.plugin.validate_config(valid_config))
    
    def test_config_validation_invalid_opacity(self):
        """Test config validation with invalid opacity."""
        invalid_config = {
            'overlay_opacity': 1.5,  # Out of range
        }
        self.assertFalse(self.plugin.validate_config(invalid_config))
        
        invalid_config = {
            'overlay_opacity': -0.1,  # Out of range
        }
        self.assertFalse(self.plugin.validate_config(invalid_config))
    
    def test_config_validation_invalid_browser(self):
        """Test config validation with invalid browser type."""
        invalid_config = {
            'browser_type': 'safari',  # Not supported
        }
        self.assertFalse(self.plugin.validate_config(invalid_config))
    
    def test_config_validation_invalid_timeout(self):
        """Test config validation with invalid timeout."""
        invalid_config = {
            'timeout': -10,  # Negative timeout
        }
        self.assertFalse(self.plugin.validate_config(invalid_config))
    
    def test_required_config_keys(self):
        """Test that no config keys are required."""
        required = self.plugin.get_required_config_keys()
        self.assertEqual(len(required), 0)
    
    def test_generate_payloads_basic(self):
        """Test basic payload generation."""
        payloads = self.plugin.generate_payloads()
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # Check that payloads contain HTML
        for payload in payloads[:3]:  # Check first 3 custom payloads
            self.assertIn('<!DOCTYPE html>', payload)
            self.assertIn('iframe', payload.lower())
    
    def test_generate_payloads_with_context(self):
        """Test payload generation with context."""
        context = {
            'target_url': self.test_url,
            'overlay_style': 'transparent',
            'overlay_text': 'Test Button',
            'overlay_opacity': 0.5,
        }
        payloads = self.plugin.generate_payloads(context)
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # Check that context is used
        self.assertTrue(any(self.test_url in p for p in payloads))
        self.assertTrue(any('Test Button' in p for p in payloads))
    
    def test_generate_transparent_overlay(self):
        """Test transparent overlay PoC generation."""
        poc = self.plugin._generate_transparent_overlay_poc(
            target_url=self.test_url,
            overlay_text='Click Me',
            opacity=0.3,
            action_description='delete account'
        )
        
        self.assertIn('<!DOCTYPE html>', poc)
        self.assertIn(self.test_url, poc)
        self.assertIn('Click Me', poc)
        self.assertIn('opacity: 0.3', poc)
        self.assertIn('delete account', poc)
    
    def test_generate_opaque_overlay(self):
        """Test opaque overlay PoC generation."""
        poc = self.plugin._generate_opaque_overlay_poc(
            target_url=self.test_url,
            overlay_text='Claim Prize',
            action_description='transfer money'
        )
        
        self.assertIn('<!DOCTYPE html>', poc)
        self.assertIn(self.test_url, poc)
        self.assertIn('Claim Prize', poc)
        self.assertIn('opacity: 0.01', poc)  # Nearly invisible iframe
    
    def test_generate_partial_overlay(self):
        """Test partial overlay PoC generation."""
        poc = self.plugin._generate_partial_overlay_poc(
            target_url=self.test_url,
            overlay_text='Continue',
            opacity=0.5,
            action_description='submit form'
        )
        
        self.assertIn('<!DOCTYPE html>', poc)
        self.assertIn(self.test_url, poc)
        self.assertIn('Continue', poc)
        self.assertIn('opacity: 0.5', poc)
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_analyze_security_headers_no_protection(self, mock_get):
        """Test header analysis with no protection."""
        # Mock response with no security headers
        mock_response = Mock()
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        config = {'timeout': 30, 'verify_ssl': False}
        analysis = self.plugin._analyze_security_headers(self.test_url, config)
        
        self.assertIsNone(analysis['x_frame_options'])
        self.assertIsNone(analysis['csp_frame_ancestors'])
        self.assertTrue(analysis['allows_framing'])
        self.assertEqual(analysis['protection_level'], 'none')
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_analyze_security_headers_with_xfo_deny(self, mock_get):
        """Test header analysis with X-Frame-Options: DENY."""
        # Mock response with X-Frame-Options
        mock_response = Mock()
        mock_response.headers = {'X-Frame-Options': 'DENY'}
        mock_get.return_value = mock_response
        
        config = {'timeout': 30, 'verify_ssl': False}
        analysis = self.plugin._analyze_security_headers(self.test_url, config)
        
        self.assertEqual(analysis['x_frame_options'], 'DENY')
        self.assertFalse(analysis['allows_framing'])
        self.assertEqual(analysis['protection_level'], 'good')
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_analyze_security_headers_with_xfo_sameorigin(self, mock_get):
        """Test header analysis with X-Frame-Options: SAMEORIGIN."""
        # Mock response with X-Frame-Options
        mock_response = Mock()
        mock_response.headers = {'X-Frame-Options': 'SAMEORIGIN'}
        mock_get.return_value = mock_response
        
        config = {'timeout': 30, 'verify_ssl': False}
        analysis = self.plugin._analyze_security_headers(self.test_url, config)
        
        self.assertEqual(analysis['x_frame_options'], 'SAMEORIGIN')
        self.assertFalse(analysis['allows_framing'])
        self.assertEqual(analysis['protection_level'], 'good')
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_analyze_security_headers_with_csp_none(self, mock_get):
        """Test header analysis with CSP frame-ancestors 'none'."""
        # Mock response with CSP
        mock_response = Mock()
        mock_response.headers = {
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"
        }
        mock_get.return_value = mock_response
        
        config = {'timeout': 30, 'verify_ssl': False}
        analysis = self.plugin._analyze_security_headers(self.test_url, config)
        
        self.assertIsNotNone(analysis['csp_frame_ancestors'])
        self.assertIn("'none'", analysis['csp_frame_ancestors'])
        self.assertFalse(analysis['allows_framing'])
        self.assertEqual(analysis['protection_level'], 'excellent')
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_analyze_security_headers_with_csp_self(self, mock_get):
        """Test header analysis with CSP frame-ancestors 'self'."""
        # Mock response with CSP
        mock_response = Mock()
        mock_response.headers = {
            'Content-Security-Policy': "frame-ancestors 'self'"
        }
        mock_get.return_value = mock_response
        
        config = {'timeout': 30, 'verify_ssl': False}
        analysis = self.plugin._analyze_security_headers(self.test_url, config)
        
        self.assertIn("'self'", analysis['csp_frame_ancestors'])
        self.assertFalse(analysis['allows_framing'])
        self.assertEqual(analysis['protection_level'], 'good')
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_execute_attack_vulnerable(self, mock_get):
        """Test execute_attack with vulnerable target."""
        # Mock vulnerable response (no security headers)
        mock_response = Mock()
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        config = {
            'test_mode': True,  # Skip browser test
            'collect_evidence': False,  # Skip evidence collection
        }
        
        result = self.plugin.execute_attack(
            target_url=self.test_url,
            vulnerability_data={'action_description': 'test action'},
            config=config
        )
        
        self.assertTrue(result['success'])
        self.assertTrue(result['vulnerable'])
        self.assertGreater(len(result['findings']), 0)
        self.assertIn('headers', result['data'])
        self.assertIsNotNone(result['remediation'])
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_execute_attack_protected(self, mock_get):
        """Test execute_attack with protected target."""
        # Mock protected response
        mock_response = Mock()
        mock_response.headers = {'X-Frame-Options': 'DENY'}
        mock_get.return_value = mock_response
        
        config = {
            'test_mode': True,  # Skip browser test
        }
        
        result = self.plugin.execute_attack(
            target_url=self.test_url,
            vulnerability_data={},
            config=config
        )
        
        self.assertTrue(result['success'])  # Scan succeeded
        self.assertFalse(result['vulnerable'])  # But not vulnerable
        self.assertEqual(len(result['findings']), 0)
    
    def test_determine_severity_basic(self):
        """Test severity determination for basic pages."""
        header_analysis = {'protection_level': 'none'}
        vulnerability_data = {'action_description': 'view page'}
        
        severity = self.plugin._determine_severity(header_analysis, vulnerability_data)
        self.assertEqual(severity, 'medium')
    
    def test_determine_severity_sensitive_action(self):
        """Test severity determination for sensitive actions."""
        header_analysis = {'protection_level': 'none'}
        vulnerability_data = {'action_description': 'transfer money'}
        
        severity = self.plugin._determine_severity(header_analysis, vulnerability_data)
        self.assertEqual(severity, 'high')
        
        # Test with other sensitive keywords
        for keyword in ['payment', 'delete', 'admin', 'password']:
            vulnerability_data = {'action_description': f'perform {keyword} action'}
            severity = self.plugin._determine_severity(header_analysis, vulnerability_data)
            self.assertEqual(severity, 'high')
    
    def test_build_evidence_description(self):
        """Test evidence description building."""
        header_analysis = {
            'x_frame_options': None,
            'csp_frame_ancestors': None,
        }
        frameability_result = {
            'frameable': True,
            'screenshot_path': '/tmp/screenshot.png',
        }
        
        evidence = self.plugin._build_evidence_description(
            header_analysis, frameability_result
        )
        
        self.assertIn('X-Frame-Options', evidence)
        self.assertIn('frame-ancestors', evidence)
        self.assertIn('frameable', evidence)
        self.assertIn('screenshot.png', evidence)
    
    def test_save_poc(self):
        """Test PoC file saving."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {'output_dir': temp_dir}
            poc_html = '<html><body>Test PoC</body></html>'
            
            poc_path = self.plugin._save_poc(poc_html, self.test_url, config)
            
            self.assertTrue(os.path.exists(poc_path))
            self.assertTrue(poc_path.startswith(temp_dir))
            
            # Verify content
            with open(poc_path, 'r') as f:
                content = f.read()
            self.assertEqual(content, poc_html)
    
    def test_cleanup(self):
        """Test resource cleanup."""
        # Create some temporary resources
        temp_dir = tempfile.mkdtemp(prefix='test_clickjacking_')
        self.plugin._temp_dirs.append(temp_dir)
        
        # Add mock driver
        mock_driver = Mock()
        self.plugin._drivers.append(mock_driver)
        
        # Call cleanup
        self.plugin._cleanup()
        
        # Verify cleanup
        self.assertEqual(len(self.plugin._temp_dirs), 0)
        self.assertEqual(len(self.plugin._drivers), 0)
        mock_driver.quit.assert_called_once()
        self.assertFalse(os.path.exists(temp_dir))


class TestClickjackingPluginRegistry(unittest.TestCase):
    """Test plugin registration and discovery."""
    
    def setUp(self):
        """Set up test fixtures."""
        reset_registry()
    
    def test_plugin_discovery(self):
        """Test that clickjacking plugin is discovered."""
        registry = get_registry()
        
        # Check if clickjacking plugin is loaded
        self.assertTrue(registry.has_plugin('clickjacking'))
        
        # Get the plugin
        plugin = registry.get_plugin('clickjacking')
        self.assertIsNotNone(plugin)
        self.assertEqual(plugin.vulnerability_type, 'clickjacking')
    
    def test_plugin_in_list(self):
        """Test that clickjacking plugin appears in plugin list."""
        registry = get_registry()
        plugins = registry.list_plugins()
        
        # Find clickjacking plugin
        clickjacking_plugin = None
        for plugin_info in plugins:
            if plugin_info['vulnerability_type'] == 'clickjacking':
                clickjacking_plugin = plugin_info
                break
        
        self.assertIsNotNone(clickjacking_plugin)
        self.assertEqual(clickjacking_plugin['name'], 'Advanced Clickjacking Exploit')
        self.assertIn('clickjacking', clickjacking_plugin['description'].lower())


class TestClickjackingPayloads(unittest.TestCase):
    """Test clickjacking payloads in PayloadGenerator."""
    
    def test_clickjacking_payloads_available(self):
        """Test that clickjacking payloads are available in generator."""
        generator = get_payload_generator()
        payloads = generator.get_payloads('clickjacking')
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # Check that payloads contain iframe tags
        for payload in payloads:
            self.assertIn('iframe', payload.lower())
    
    def test_clickjacking_in_vulnerability_types(self):
        """Test that clickjacking is listed in vulnerability types."""
        generator = get_payload_generator()
        vuln_types = generator.get_all_vulnerability_types()
        
        self.assertIn('clickjacking', vuln_types)


class TestClickjackingIntegration(unittest.TestCase):
    """Integration tests for clickjacking plugin."""
    
    @patch('scanner.plugins.exploits.clickjacking_plugin.requests.get')
    def test_full_workflow_vulnerable_target(self, mock_get):
        """Test complete workflow with vulnerable target."""
        # Mock vulnerable response
        mock_response = Mock()
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        # Get plugin from registry
        reset_registry()
        registry = get_registry()
        plugin = registry.get_plugin('clickjacking')
        
        self.assertIsNotNone(plugin)
        
        # Generate payloads
        payloads = plugin.generate_payloads({
            'target_url': 'http://vulnerable.example.com'
        })
        self.assertGreater(len(payloads), 0)
        
        # Execute attack
        with tempfile.TemporaryDirectory() as temp_dir:
            result = plugin.execute_attack(
                target_url='http://vulnerable.example.com',
                vulnerability_data={'action_description': 'sensitive action'},
                config={
                    'test_mode': True,
                    'output_dir': temp_dir,
                    'collect_evidence': True,
                }
            )
            
            # Verify results
            self.assertTrue(result['success'])
            self.assertTrue(result['vulnerable'])
            self.assertGreater(len(result['findings']), 0)
            self.assertIn('poc_html', result['data'])
            self.assertIn('poc_path', result['data'])
            
            # Verify PoC file was created
            poc_path = result['data']['poc_path']
            self.assertTrue(os.path.exists(poc_path))


if __name__ == '__main__':
    unittest.main()
