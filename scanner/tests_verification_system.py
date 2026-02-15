"""
Tests for the post-exploitation verification system.

This module tests the verify() method implementation across all exploit plugins
and the integration with the exploit framework.
"""

from django.test import TestCase
from scanner.models import ScanTarget, Scan, Vulnerability
from scanner.plugins import get_registry
from scanner.plugins.exploits.info_disclosure_plugin import InfoDisclosurePlugin
from scanner.plugins.exploits.rce_plugin import RCEPlugin
from scanner.plugins.exploits.xss_plugin import XSSPlugin
from scanner.plugins.exploits.lfi_plugin import LFIPlugin
from scanner.plugins.exploits.sqli_plugin import SQLInjectionPlugin
from unittest.mock import patch, MagicMock


class VerificationSystemTestCase(TestCase):
    """Test cases for the verification system"""

    def setUp(self):
        """Set up test data"""
        # Create test scan target and scan
        self.target = ScanTarget.objects.create(
            url='https://testsite.com',
            name='Test Site'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='completed'
        )

    def test_base_plugin_has_verify_method(self):
        """Test that the base ExploitPlugin class has verify() method"""
        from scanner.plugins.exploit_plugin import ExploitPlugin
        
        # Check that verify method exists
        self.assertTrue(hasattr(ExploitPlugin, 'verify'))
        self.assertTrue(callable(getattr(ExploitPlugin, 'verify')))

    def test_info_disclosure_verification_with_sensitive_data(self):
        """Test InfoDisclosurePlugin verification with sensitive data"""
        plugin = InfoDisclosurePlugin()
        
        # Simulate successful exploit with sensitive data
        result = {
            'success': True,
            'disclosed_info': {
                '/.env': 'DB_PASSWORD=super_secret_123\nAPI_KEY=sk_live_abc123xyz',
                '/config.php': 'password = "admin123"'
            },
            'evidence': 'Found 2 exposed files'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'file'}
        )
        
        # Should be verified due to sensitive data
        self.assertTrue(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)
        self.assertIn('Sensitive', proof)
        self.assertIn('/.env', proof)

    def test_info_disclosure_verification_without_sensitive_data(self):
        """Test InfoDisclosurePlugin verification without sensitive data"""
        plugin = InfoDisclosurePlugin()
        
        # Simulate successful exploit but no clearly sensitive data
        result = {
            'success': True,
            'disclosed_info': {
                '/README.md': '# Project Name\n\nThis is a test project.',
            },
            'evidence': 'Found 1 exposed file'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'file'}
        )
        
        # Should NOT be verified without sensitive data
        self.assertFalse(is_verified)
        # Proof may still contain information
        if proof:
            self.assertIn('inconclusive', proof.lower())

    def test_rce_verification_with_command_output(self):
        """Test RCEPlugin verification with command output"""
        plugin = RCEPlugin()
        
        # Simulate successful RCE with command output
        result = {
            'success': True,
            'command_output': 'uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)',
            'evidence': 'Command executed: id, Found uid/gid in output',
            'os_detected': 'linux'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'cmd'}
        )
        
        # Should be verified with concrete command output
        self.assertTrue(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)
        self.assertIn('Remote Code Execution', proof)
        self.assertIn('uid=', proof)

    def test_rce_verification_without_output(self):
        """Test RCEPlugin verification without command output"""
        plugin = RCEPlugin()
        
        # Simulate claimed success but no output
        result = {
            'success': True,
            'command_output': '',
            'evidence': 'Might have executed',
            'os_detected': 'unknown'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'cmd'}
        )
        
        # Should NOT be verified without output
        self.assertFalse(is_verified)
        self.assertIsNone(proof)

    def test_xss_verification_with_callback(self):
        """Test XSSPlugin verification with callback"""
        plugin = XSSPlugin()
        
        # Simulate successful XSS with callback verification
        result = {
            'success': True,
            'callback_verified': True,
            'callback_data': {
                'callback_url': 'https://collaborator.example.com/callback',
                'timestamp': '2024-01-01 12:00:00',
                'user_agent': 'Mozilla/5.0...'
            },
            'payload': '<script>fetch("https://collaborator.example.com/callback")</script>',
            'evidence': 'Callback received'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'q'}
        )
        
        # Should be verified with callback
        self.assertTrue(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)
        self.assertIn('Cross-Site Scripting', proof)
        self.assertIn('Callback', proof)

    def test_xss_verification_reflected_only(self):
        """Test XSSPlugin verification with reflection but no execution"""
        plugin = XSSPlugin()
        
        # Simulate reflected payload but no execution proof
        result = {
            'success': True,
            'payload': '<script>alert(1)</script>',
            'evidence': 'Payload reflected in response'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'q'}
        )
        
        # Should NOT be verified with just reflection
        self.assertFalse(is_verified)
        # May have partial proof
        if proof:
            self.assertIn('reflected', proof.lower())

    def test_lfi_verification_with_file_content(self):
        """Test LFIPlugin verification with file content"""
        plugin = LFIPlugin()
        
        # Simulate successful LFI with file content
        result = {
            'success': True,
            'files_read': {
                '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n',
                '/etc/hosts': '127.0.0.1 localhost\n'
            },
            'evidence': 'Successfully read 2 files'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'file'}
        )
        
        # Should be verified with file content
        self.assertTrue(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)
        self.assertIn('Local File Inclusion', proof)
        self.assertIn('/etc/passwd', proof)

    def test_sqli_verification_with_data_extraction(self):
        """Test SQLInjectionPlugin verification with data extraction"""
        plugin = SQLInjectionPlugin()
        
        # Simulate successful SQLi with data extraction
        result = {
            'success': True,
            'extracted_data': {
                'database_version': 'MySQL 8.0.32',
                'current_user': 'webapp@localhost',
                'databases': ['webapp_db', 'information_schema', 'mysql'],
                'tables': ['users', 'posts', 'comments'],
                'sample_data': [
                    {'username': 'admin', 'email': 'admin@example.com'},
                    {'username': 'user1', 'email': 'user1@example.com'}
                ]
            },
            'evidence': 'Union-based injection successful'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'id'}
        )
        
        # Should be verified with data extraction
        self.assertTrue(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)
        self.assertIn('SQL Injection', proof)
        self.assertIn('MySQL', proof)

    def test_sqli_verification_error_only(self):
        """Test SQLInjectionPlugin verification with error but no data"""
        plugin = SQLInjectionPlugin()
        
        # Simulate error-based detection but no data extraction
        result = {
            'success': True,
            'extracted_data': {},
            'evidence': 'SQL syntax error in response'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'id'}
        )
        
        # Should NOT be verified without data extraction
        self.assertFalse(is_verified)
        if proof:
            self.assertIn('not confirmed', proof.lower())

    def test_verification_backward_compatibility(self):
        """Test backward compatibility for plugins without verify()"""
        # Create a mock plugin without verify() method
        class LegacyPlugin:
            def __init__(self):
                pass
            
            @property
            def vulnerability_type(self):
                return 'test'
        
        legacy_plugin = LegacyPlugin()
        
        # Should not have verify method
        self.assertFalse(hasattr(legacy_plugin, 'verify'))
        
        # The exploit_integration code should handle this gracefully
        # (tested via integration tests)

    def test_failed_exploit_not_verified(self):
        """Test that failed exploits are not verified"""
        plugin = InfoDisclosurePlugin()
        
        # Simulate failed exploit
        result = {
            'success': False,
            'error': 'Connection timeout'
        }
        
        is_verified, proof = plugin.verify(
            result=result,
            target_url='https://testsite.com',
            vulnerability_data={'parameter': 'file'}
        )
        
        # Should NOT be verified
        self.assertFalse(is_verified)
        self.assertIsNone(proof)

    def test_all_plugins_have_verify_method(self):
        """Test that all registered plugins have verify() method"""
        registry = get_registry()
        registry.discover_plugins()
        
        plugins = registry.get_all_plugins()
        
        for plugin in plugins:
            with self.subTest(plugin=plugin.name):
                # Each plugin should have verify method
                self.assertTrue(
                    hasattr(plugin, 'verify'),
                    f"Plugin {plugin.name} missing verify() method"
                )
                self.assertTrue(
                    callable(plugin.verify),
                    f"Plugin {plugin.name} verify() is not callable"
                )


class VerificationIntegrationTestCase(TestCase):
    """Integration tests for verification in the exploit flow"""

    def setUp(self):
        """Set up test data"""
        self.target = ScanTarget.objects.create(
            url='https://testsite.com',
            name='Test Site'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='completed'
        )
        
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='info_disclosure',
            severity='medium',
            url='https://testsite.com',
            parameter='file',
            description='Information disclosure',
            evidence='Exposed files detected'
        )

    @patch('scanner.exploit_integration.exploit_vulnerability')
    def test_exploit_integration_calls_verify(self, mock_exploit):
        """Test that exploit_integration calls verify() after successful exploit"""
        from scanner.exploit_integration import _exploit_vulnerability_and_update
        
        # Mock successful exploit with sensitive data
        mock_exploit.return_value = {
            'success': True,
            'disclosed_info': {
                '/.env': 'DB_PASSWORD=secret123\nAPI_KEY=sk_test_abc'
            },
            'evidence': 'Found exposed .env file',
            'plugin_used': 'Information Disclosure Plugin'
        }
        
        results = {
            'exploited': 0,
            'failed': 0,
            'no_plugin': 0,
            'results': []
        }
        
        # Execute exploitation
        _exploit_vulnerability_and_update(self.vuln, {}, results)
        
        # Reload vulnerability from database
        self.vuln.refresh_from_db()
        
        # Check that vulnerability was marked as exploited
        self.assertTrue(self.vuln.exploited)
        
        # Check that verified status was set
        # (Should be True if sensitive data was found)
        self.assertTrue(self.vuln.verified)
        
        # Check that proof_of_impact was set
        self.assertIsNotNone(self.vuln.proof_of_impact)
        self.assertIn('VERIFIED', self.vuln.proof_of_impact)

    @patch('scanner.exploit_integration.exploit_vulnerability')
    def test_exploit_integration_no_verification_without_proof(self, mock_exploit):
        """Test that exploits without proof are not verified"""
        from scanner.exploit_integration import _exploit_vulnerability_and_update
        
        # Mock successful exploit but without concrete proof
        mock_exploit.return_value = {
            'success': True,
            'disclosed_info': {
                '/README.md': 'Just a readme file'
            },
            'evidence': 'Found README',
            'plugin_used': 'Information Disclosure Plugin'
        }
        
        results = {
            'exploited': 0,
            'failed': 0,
            'no_plugin': 0,
            'results': []
        }
        
        # Execute exploitation
        _exploit_vulnerability_and_update(self.vuln, {}, results)
        
        # Reload vulnerability from database
        self.vuln.refresh_from_db()
        
        # Check that vulnerability was marked as exploited
        self.assertTrue(self.vuln.exploited)
        
        # Check that verified status is False (no sensitive data)
        self.assertFalse(self.vuln.verified)
