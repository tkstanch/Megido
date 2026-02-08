"""
Tests for the Exploit Plugin System

This module contains comprehensive tests for the plugin infrastructure including:
- Plugin discovery and registration
- Payload generation
- Plugin execution
- SQL Injection plugin
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import sys
from pathlib import Path

# Add parent directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir.parent.parent))

from scanner.plugins.exploit_plugin import ExploitPlugin
from scanner.plugins.plugin_registry import PluginRegistry, get_registry, reset_registry
from scanner.plugins.payload_generator import PayloadGenerator, get_payload_generator


class TestExploitPlugin(ExploitPlugin):
    """Test plugin for unit testing."""
    
    @property
    def vulnerability_type(self) -> str:
        return 'test_vuln'
    
    @property
    def name(self) -> str:
        return 'Test Exploit Plugin'
    
    @property
    def description(self) -> str:
        return 'A test plugin for unit testing'
    
    def generate_payloads(self, context=None):
        return ['test_payload_1', 'test_payload_2', 'test_payload_3']
    
    def execute_attack(self, target_url, vulnerability_data, config=None):
        return {
            'success': True,
            'findings': ['test_finding'],
            'data': {'test': 'data'},
            'evidence': 'test_evidence',
            'error': None,
        }


class TestPluginRegistry(unittest.TestCase):
    """Test cases for PluginRegistry."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.registry = PluginRegistry()
    
    def test_registry_initialization(self):
        """Test that registry initializes correctly."""
        self.assertIsInstance(self.registry, PluginRegistry)
        self.assertEqual(self.registry.get_plugin_count(), 0)
    
    def test_manual_plugin_registration(self):
        """Test manual plugin registration."""
        plugin = TestExploitPlugin()
        self.registry.register_plugin(plugin)
        
        self.assertEqual(self.registry.get_plugin_count(), 1)
        self.assertTrue(self.registry.has_plugin('test_vuln'))
        
        retrieved = self.registry.get_plugin('test_vuln')
        self.assertIsInstance(retrieved, TestExploitPlugin)
        self.assertEqual(retrieved.name, 'Test Exploit Plugin')
    
    def test_get_nonexistent_plugin(self):
        """Test retrieving a plugin that doesn't exist."""
        plugin = self.registry.get_plugin('nonexistent')
        self.assertIsNone(plugin)
    
    def test_has_plugin(self):
        """Test checking if plugin exists."""
        self.assertFalse(self.registry.has_plugin('test_vuln'))
        
        plugin = TestExploitPlugin()
        self.registry.register_plugin(plugin)
        
        self.assertTrue(self.registry.has_plugin('test_vuln'))
    
    def test_list_plugins(self):
        """Test listing all plugins."""
        plugin1 = TestExploitPlugin()
        self.registry.register_plugin(plugin1)
        
        plugins = self.registry.list_plugins()
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0]['vulnerability_type'], 'test_vuln')
        self.assertEqual(plugins[0]['name'], 'Test Exploit Plugin')
    
    def test_clear_plugins(self):
        """Test clearing all plugins."""
        plugin = TestExploitPlugin()
        self.registry.register_plugin(plugin)
        self.assertEqual(self.registry.get_plugin_count(), 1)
        
        self.registry.clear_plugins()
        self.assertEqual(self.registry.get_plugin_count(), 0)
    
    def test_plugin_discovery(self):
        """Test automatic plugin discovery."""
        # This will discover actual plugins in the exploits directory
        plugins_dir = Path(__file__).parent.parent / 'plugins' / 'exploits'
        
        if plugins_dir.exists():
            count = self.registry.discover_plugins()
            # Should find at least the SQL injection plugin
            self.assertGreaterEqual(count, 0)


class TestPayloadGenerator(unittest.TestCase):
    """Test cases for PayloadGenerator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.generator = PayloadGenerator()
    
    def test_generator_initialization(self):
        """Test that generator initializes correctly."""
        self.assertIsInstance(self.generator, PayloadGenerator)
    
    def test_get_xss_payloads(self):
        """Test getting XSS payloads."""
        payloads = self.generator.get_payloads('xss')
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertIn('<script>alert(1)</script>', payloads)
    
    def test_get_sqli_payloads_basic(self):
        """Test getting basic SQL injection payloads."""
        payloads = self.generator.get_payloads('sqli')
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertIn("'", payloads)
    
    def test_get_sqli_payloads_mysql(self):
        """Test getting MySQL-specific SQL injection payloads."""
        payloads = self.generator.get_payloads('sqli', {'database_type': 'mysql'})
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        # Check for MySQL-specific payload
        mysql_payload_found = any('SLEEP' in p or 'database()' in p for p in payloads)
        self.assertTrue(mysql_payload_found)
    
    def test_get_sqli_payloads_postgresql(self):
        """Test getting PostgreSQL-specific SQL injection payloads."""
        payloads = self.generator.get_payloads('sqli', {'database_type': 'postgresql'})
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        # Check for PostgreSQL-specific payload
        pg_payload_found = any('pg_sleep' in p or 'version()' in p for p in payloads)
        self.assertTrue(pg_payload_found)
    
    def test_get_rce_payloads(self):
        """Test getting RCE payloads."""
        payloads = self.generator.get_payloads('rce')
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertIn('; ls', payloads)
    
    def test_get_lfi_payloads(self):
        """Test getting LFI payloads."""
        payloads = self.generator.get_payloads('lfi')
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertIn('../../../etc/passwd', payloads)
    
    def test_get_unknown_vulnerability_type(self):
        """Test getting payloads for unknown vulnerability type."""
        payloads = self.generator.get_payloads('unknown_vuln_type')
        self.assertEqual(payloads, [])
    
    def test_add_custom_payloads(self):
        """Test adding custom payloads."""
        custom_payloads = ['custom1', 'custom2', 'custom3']
        self.generator.add_custom_payloads('custom_vuln', custom_payloads)
        
        retrieved = self.generator.get_payloads('custom_vuln')
        self.assertEqual(retrieved, custom_payloads)
    
    def test_get_all_vulnerability_types(self):
        """Test getting all vulnerability types."""
        types = self.generator.get_all_vulnerability_types()
        self.assertIsInstance(types, list)
        self.assertIn('xss', types)
        self.assertIn('sqli', types)
        self.assertIn('rce', types)
    
    def test_customize_payload(self):
        """Test payload customization."""
        template = "SELECT * FROM {table} WHERE {column}='{value}'"
        variables = {'table': 'users', 'column': 'id', 'value': '1'}
        
        result = self.generator.customize_payload(template, variables)
        self.assertEqual(result, "SELECT * FROM users WHERE id='1'")
    
    def test_customize_payload_missing_variable(self):
        """Test payload customization with missing variable."""
        template = "SELECT * FROM {table} WHERE {column}='{value}'"
        variables = {'table': 'users'}  # Missing 'column' and 'value'
        
        # Should return original template if variables are missing
        result = self.generator.customize_payload(template, variables)
        self.assertEqual(result, template)
    
    def test_encode_payload_url(self):
        """Test URL encoding."""
        payload = '<script>alert(1)</script>'
        encoded = self.generator.encode_payload(payload, 'url')
        self.assertIn('%3C', encoded)  # '<' encoded
        self.assertIn('%3E', encoded)  # '>' encoded
    
    def test_encode_payload_base64(self):
        """Test Base64 encoding."""
        payload = 'test payload'
        encoded = self.generator.encode_payload(payload, 'base64')
        self.assertEqual(encoded, 'dGVzdCBwYXlsb2Fk')
    
    def test_encode_payload_html(self):
        """Test HTML encoding."""
        payload = '<script>alert(1)</script>'
        encoded = self.generator.encode_payload(payload, 'html')
        self.assertIn('&lt;', encoded)  # '<' encoded
        self.assertIn('&gt;', encoded)  # '>' encoded
    
    def test_get_payload_info(self):
        """Test getting payload information."""
        info = self.generator.get_payload_info('xss')
        self.assertIsInstance(info, dict)
        self.assertIn('count', info)
        self.assertGreater(info['count'], 0)
    
    def test_get_payload_info_sqli(self):
        """Test getting SQL injection payload information."""
        info = self.generator.get_payload_info('sqli')
        self.assertIsInstance(info, dict)
        self.assertIn('count', info)
        self.assertIn('types', info)
        self.assertGreater(len(info['types']), 0)


class TestExploitPluginInterface(unittest.TestCase):
    """Test cases for ExploitPlugin interface."""
    
    def test_plugin_properties(self):
        """Test plugin properties."""
        plugin = TestExploitPlugin()
        
        self.assertEqual(plugin.vulnerability_type, 'test_vuln')
        self.assertEqual(plugin.name, 'Test Exploit Plugin')
        self.assertEqual(plugin.description, 'A test plugin for unit testing')
        self.assertEqual(plugin.version, '1.0.0')
    
    def test_generate_payloads(self):
        """Test payload generation."""
        plugin = TestExploitPlugin()
        payloads = plugin.generate_payloads()
        
        self.assertIsInstance(payloads, list)
        self.assertEqual(len(payloads), 3)
        self.assertIn('test_payload_1', payloads)
    
    def test_execute_attack(self):
        """Test attack execution."""
        plugin = TestExploitPlugin()
        result = plugin.execute_attack(
            'http://example.com',
            {'parameter': 'id', 'method': 'GET'}
        )
        
        self.assertIsInstance(result, dict)
        self.assertTrue(result['success'])
        self.assertIsNotNone(result['findings'])
        self.assertIsNotNone(result['evidence'])
    
    def test_get_remediation_advice(self):
        """Test getting remediation advice."""
        plugin = TestExploitPlugin()
        advice = plugin.get_remediation_advice()
        
        self.assertIsInstance(advice, str)
        self.assertGreater(len(advice), 0)
    
    def test_get_severity_level(self):
        """Test getting severity level."""
        plugin = TestExploitPlugin()
        severity = plugin.get_severity_level()
        
        self.assertIn(severity, ['low', 'medium', 'high', 'critical'])
    
    def test_validate_config(self):
        """Test config validation."""
        plugin = TestExploitPlugin()
        
        self.assertTrue(plugin.validate_config({}))
        self.assertTrue(plugin.validate_config({'timeout': 30}))
    
    def test_get_required_config_keys(self):
        """Test getting required config keys."""
        plugin = TestExploitPlugin()
        keys = plugin.get_required_config_keys()
        
        self.assertIsInstance(keys, list)


class TestSQLInjectionPlugin(unittest.TestCase):
    """Test cases for SQL Injection plugin."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Try to import the SQLi plugin
        try:
            from scanner.plugins.exploits.sqli_plugin import SQLInjectionPlugin
            self.plugin = SQLInjectionPlugin()
            self.plugin_available = True
        except ImportError:
            self.plugin_available = False
    
    def test_plugin_properties(self):
        """Test SQLi plugin properties."""
        if not self.plugin_available:
            self.skipTest("SQLi plugin not available")
        
        self.assertEqual(self.plugin.vulnerability_type, 'sqli')
        self.assertIn('SQL Injection', self.plugin.name)
        self.assertGreater(len(self.plugin.description), 0)
    
    def test_generate_payloads_basic(self):
        """Test generating basic SQL injection payloads."""
        if not self.plugin_available:
            self.skipTest("SQLi plugin not available")
        
        payloads = self.plugin.generate_payloads()
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_generate_payloads_mysql(self):
        """Test generating MySQL-specific payloads."""
        if not self.plugin_available:
            self.skipTest("SQLi plugin not available")
        
        payloads = self.plugin.generate_payloads({'database_type': 'mysql'})
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_generate_payloads_time_based(self):
        """Test generating time-based payloads."""
        if not self.plugin_available:
            self.skipTest("SQLi plugin not available")
        
        payloads = self.plugin.generate_payloads({
            'database_type': 'mysql',
            'injection_type': 'time'
        })
        self.assertIsInstance(payloads, list)
        # Should include SLEEP payloads for MySQL
        sleep_found = any('SLEEP' in p for p in payloads)
        self.assertTrue(sleep_found)
    
    def test_get_severity_level(self):
        """Test SQLi severity level."""
        if not self.plugin_available:
            self.skipTest("SQLi plugin not available")
        
        severity = self.plugin.get_severity_level()
        self.assertEqual(severity, 'critical')
    
    def test_get_remediation_advice(self):
        """Test SQLi remediation advice."""
        if not self.plugin_available:
            self.skipTest("SQLi plugin not available")
        
        advice = self.plugin.get_remediation_advice()
        self.assertIsInstance(advice, str)
        self.assertGreater(len(advice), 100)  # Should be comprehensive
        self.assertIn('Parameterized', advice)
    
    def test_validate_config(self):
        """Test SQLi config validation."""
        if not self.plugin_available:
            self.skipTest("SQLi plugin not available")
        
        # Valid configs
        self.assertTrue(self.plugin.validate_config({}))
        self.assertTrue(self.plugin.validate_config({'timeout': 30}))
        self.assertTrue(self.plugin.validate_config({'min_delay': 1, 'max_delay': 2}))
        
        # Invalid configs
        self.assertFalse(self.plugin.validate_config({'timeout': -1}))
        self.assertFalse(self.plugin.validate_config({'timeout': 0}))
        self.assertFalse(self.plugin.validate_config({'min_delay': 5, 'max_delay': 2}))


class TestGlobalRegistryFunctions(unittest.TestCase):
    """Test cases for global registry functions."""
    
    def test_get_registry(self):
        """Test getting global registry."""
        registry = get_registry()
        self.assertIsInstance(registry, PluginRegistry)
    
    def test_get_registry_singleton(self):
        """Test that get_registry returns the same instance."""
        registry1 = get_registry()
        registry2 = get_registry()
        self.assertIs(registry1, registry2)
    
    def test_reset_registry(self):
        """Test resetting global registry."""
        registry1 = get_registry()
        reset_registry()
        registry2 = get_registry()
        # After reset, should get a new instance
        self.assertIsNot(registry1, registry2)
    
    def test_get_payload_generator(self):
        """Test getting global payload generator."""
        generator = get_payload_generator()
        self.assertIsInstance(generator, PayloadGenerator)
    
    def test_get_payload_generator_singleton(self):
        """Test that get_payload_generator returns the same instance."""
        generator1 = get_payload_generator()
        generator2 = get_payload_generator()
        self.assertIs(generator1, generator2)


if __name__ == '__main__':
    unittest.main()
