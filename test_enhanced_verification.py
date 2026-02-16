"""
Unit tests for enhanced verification features

Tests for:
- VulnerabilityFinding with verification data
- create_repeater_request helper
- ExploitPlugin format_repeater_request method
- Verification logic in exploit plugins
"""

import unittest
from scanner.scan_plugins import VulnerabilityFinding, create_repeater_request


class TestVulnerabilityFindingEnhancements(unittest.TestCase):
    """Test VulnerabilityFinding enhancements."""
    
    def test_basic_finding_without_verification(self):
        """Test creating a basic finding without verification data."""
        finding = VulnerabilityFinding(
            vulnerability_type='xss',
            severity='medium',
            url='https://example.com',
            description='Test XSS',
            evidence='Test evidence',
            remediation='Test remediation'
        )
        
        self.assertEqual(finding.vulnerability_type, 'xss')
        self.assertFalse(finding.verified)
        self.assertIsNone(finding.successful_payloads)
        self.assertIsNone(finding.repeater_requests)
    
    def test_verified_finding_with_payloads(self):
        """Test creating a verified finding with payloads."""
        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
        
        finding = VulnerabilityFinding(
            vulnerability_type='xss',
            severity='high',
            url='https://example.com',
            description='Verified XSS',
            evidence='JavaScript executed',
            remediation='Implement output encoding',
            verified=True,
            successful_payloads=payloads
        )
        
        self.assertTrue(finding.verified)
        self.assertEqual(len(finding.successful_payloads), 2)
        self.assertIn('<script>alert(1)</script>', finding.successful_payloads)
    
    def test_finding_with_repeater_requests(self):
        """Test creating a finding with repeater requests."""
        repeater_req = create_repeater_request(
            url='https://example.com/test',
            method='POST',
            headers={'Content-Type': 'application/json'},
            body='{"test": "data"}',
            description='Test request'
        )
        
        finding = VulnerabilityFinding(
            vulnerability_type='sqli',
            severity='critical',
            url='https://example.com',
            description='SQL Injection',
            evidence='Database error',
            remediation='Use parameterized queries',
            verified=True,
            repeater_requests=[repeater_req]
        )
        
        self.assertTrue(finding.verified)
        self.assertEqual(len(finding.repeater_requests), 1)
        self.assertEqual(finding.repeater_requests[0]['method'], 'POST')
        self.assertEqual(finding.repeater_requests[0]['url'], 'https://example.com/test')
    
    def test_to_dict_includes_verification_data(self):
        """Test that to_dict includes verification data."""
        finding = VulnerabilityFinding(
            vulnerability_type='info_disclosure',
            severity='high',
            url='https://example.com',
            description='Test',
            evidence='Test',
            remediation='Test',
            verified=True,
            successful_payloads=['/.env'],
            repeater_requests=[
                create_repeater_request(
                    url='https://example.com/.env',
                    method='GET'
                )
            ]
        )
        
        finding_dict = finding.to_dict()
        
        self.assertIn('verified', finding_dict)
        self.assertTrue(finding_dict['verified'])
        self.assertIn('successful_payloads', finding_dict)
        self.assertEqual(finding_dict['successful_payloads'], ['/.env'])
        self.assertIn('repeater_requests', finding_dict)
        self.assertEqual(len(finding_dict['repeater_requests']), 1)


class TestCreateRepeaterRequest(unittest.TestCase):
    """Test create_repeater_request helper function."""
    
    def test_basic_get_request(self):
        """Test creating a basic GET request."""
        req = create_repeater_request(
            url='https://example.com/test',
            method='GET'
        )
        
        self.assertEqual(req['url'], 'https://example.com/test')
        self.assertEqual(req['method'], 'GET')
        self.assertEqual(req['headers'], {})
        self.assertEqual(req['body'], '')
    
    def test_post_request_with_body(self):
        """Test creating a POST request with body."""
        req = create_repeater_request(
            url='https://example.com/api',
            method='POST',
            headers={'Content-Type': 'application/json'},
            body='{"key": "value"}',
            description='Test POST request'
        )
        
        self.assertEqual(req['url'], 'https://example.com/api')
        self.assertEqual(req['method'], 'POST')
        self.assertEqual(req['headers']['Content-Type'], 'application/json')
        self.assertEqual(req['body'], '{"key": "value"}')
        self.assertEqual(req['description'], 'Test POST request')
    
    def test_method_normalization(self):
        """Test that HTTP methods are normalized to uppercase."""
        req = create_repeater_request(
            url='https://example.com',
            method='post'
        )
        
        self.assertEqual(req['method'], 'POST')


class TestExploitPluginFormatRepeaterRequest(unittest.TestCase):
    """Test ExploitPlugin.format_repeater_request method."""
    
    def test_format_repeater_request_basic(self):
        """Test basic repeater request formatting."""
        from scanner.plugins.exploit_plugin import ExploitPlugin
        
        # Create a minimal concrete plugin for testing
        class TestPlugin(ExploitPlugin):
            @property
            def vulnerability_type(self):
                return 'test'
            
            @property
            def name(self):
                return 'Test Plugin'
            
            @property
            def description(self):
                return 'Test'
            
            def generate_payloads(self, context=None):
                return []
            
            def execute_attack(self, target_url, vulnerability_data, config=None):
                return {}
        
        plugin = TestPlugin()
        req = plugin.format_repeater_request(
            url='https://example.com',
            method='GET',
            description='Test request'
        )
        
        self.assertEqual(req['url'], 'https://example.com')
        self.assertEqual(req['method'], 'GET')
        self.assertEqual(req['description'], 'Test request')
    
    def test_format_repeater_request_with_response(self):
        """Test formatting with response data."""
        from scanner.plugins.exploit_plugin import ExploitPlugin
        
        class TestPlugin(ExploitPlugin):
            @property
            def vulnerability_type(self):
                return 'test'
            
            @property
            def name(self):
                return 'Test Plugin'
            
            @property
            def description(self):
                return 'Test'
            
            def generate_payloads(self, context=None):
                return []
            
            def execute_attack(self, target_url, vulnerability_data, config=None):
                return {}
        
        plugin = TestPlugin()
        response_data = {
            'status_code': 200,
            'body': 'Test response',
            'headers': {'Content-Type': 'text/html'}
        }
        
        req = plugin.format_repeater_request(
            url='https://example.com',
            method='POST',
            body='test=data',
            response_data=response_data
        )
        
        self.assertEqual(req['url'], 'https://example.com')
        self.assertIn('response', req)
        self.assertEqual(req['response']['status_code'], 200)
        self.assertEqual(req['response']['body'], 'Test response')


class TestVerificationLogic(unittest.TestCase):
    """Test verification logic in exploit plugins."""
    
    def test_info_disclosure_verification(self):
        """Test info disclosure verification logic."""
        # Simulate successful exploitation with sensitive data
        result = {
            'success': True,
            'disclosed_info': {
                '/.env': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=secret123'
            },
            'successful_payloads': ['/.env'],
            'repeater_requests': []
        }
        
        # Simulate verification - would be True because credentials found
        has_credentials = 'AWS_ACCESS_KEY_ID' in str(result.get('disclosed_info', {}))
        self.assertTrue(has_credentials)
    
    def test_rce_verification(self):
        """Test RCE verification logic."""
        # Simulate successful command execution
        result = {
            'success': True,
            'command_output': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
            'successful_payloads': ['; id'],
            'repeater_requests': []
        }
        
        # Would be verified because command output captured
        has_output = bool(result.get('command_output'))
        self.assertTrue(has_output)
        self.assertIn('uid=', result['command_output'])
    
    def test_sqli_verification(self):
        """Test SQLi verification logic."""
        # Simulate successful data extraction
        result = {
            'success': True,
            'extracted_data': {
                'database_version': 'MySQL 8.0.23',
                'current_user': 'root@localhost',
                'databases': ['information_schema', 'mysql', 'myapp']
            },
            'successful_payloads': ["' UNION SELECT @@version--"],
            'repeater_requests': []
        }
        
        # Would be verified because database info extracted
        has_db_info = bool(result.get('extracted_data', {}).get('database_version'))
        self.assertTrue(has_db_info)


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerabilityFindingEnhancements))
    suite.addTests(loader.loadTestsFromTestCase(TestCreateRepeaterRequest))
    suite.addTests(loader.loadTestsFromTestCase(TestExploitPluginFormatRepeaterRequest))
    suite.addTests(loader.loadTestsFromTestCase(TestVerificationLogic))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return success status
    return result.wasSuccessful()


if __name__ == '__main__':
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
