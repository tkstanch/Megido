"""
Tests for ProofReporter system.

This test suite validates the unified proof reporting system across all exploit plugins.
"""

import unittest
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from scanner.proof_reporter import (
    ProofData,
    ProofReporter,
    get_proof_reporter
)


class TestProofData(unittest.TestCase):
    """Test ProofData container class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.proof_data = ProofData('xss', vulnerability_id=123)
    
    def test_initialization(self):
        """Test ProofData initialization."""
        self.assertEqual(self.proof_data.vulnerability_type, 'xss')
        self.assertEqual(self.proof_data.vulnerability_id, 123)
        self.assertFalse(self.proof_data.success)
        self.assertFalse(self.proof_data.verified)
        self.assertEqual(self.proof_data.confidence_score, 0.0)
    
    def test_add_http_request(self):
        """Test adding HTTP requests."""
        self.proof_data.add_http_request(
            method='POST',
            url='http://example.com/test',
            headers={'Content-Type': 'application/json'},
            body='{"data": "test"}'
        )
        
        self.assertEqual(len(self.proof_data.http_requests), 1)
        req = self.proof_data.http_requests[0]
        self.assertEqual(req['method'], 'POST')
        self.assertEqual(req['url'], 'http://example.com/test')
        self.assertIn('Content-Type', req['headers'])
    
    def test_add_http_response(self):
        """Test adding HTTP responses."""
        self.proof_data.add_http_response(
            status_code=200,
            headers={'Server': 'nginx'},
            body='<html>Response</html>'
        )
        
        self.assertEqual(len(self.proof_data.http_responses), 1)
        resp = self.proof_data.http_responses[0]
        self.assertEqual(resp['status_code'], 200)
        self.assertIn('Server', resp['headers'])
    
    def test_add_log(self):
        """Test adding log messages."""
        self.proof_data.add_log('Test message', 'info')
        self.proof_data.add_log('Warning message', 'warning')
        
        self.assertEqual(len(self.proof_data.logs), 2)
        self.assertIn('INFO', self.proof_data.logs[0])
        self.assertIn('WARNING', self.proof_data.logs[1])
    
    def test_set_command_output(self):
        """Test setting command output."""
        output = 'uid=0(root) gid=0(root) groups=0(root)'
        self.proof_data.set_command_output(output)
        self.assertEqual(self.proof_data.command_output, output)
    
    def test_set_extracted_data(self):
        """Test setting extracted data."""
        data = {'users': ['admin', 'user1'], 'db': 'production'}
        self.proof_data.set_extracted_data(data)
        self.assertEqual(self.proof_data.extracted_data, data)
    
    def test_add_screenshot(self):
        """Test adding screenshot."""
        self.proof_data.add_screenshot(
            path='/media/exploit_proofs/xss_123.png',
            screenshot_type='screenshot',
            size=1024,
            url='http://example.com'
        )
        
        self.assertEqual(len(self.proof_data.screenshots), 1)
        screenshot = self.proof_data.screenshots[0]
        self.assertEqual(screenshot['path'], '/media/exploit_proofs/xss_123.png')
        self.assertEqual(screenshot['type'], 'screenshot')
    
    def test_set_visual_proof(self):
        """Test setting visual proof."""
        self.proof_data.set_visual_proof('/path/to/proof.png', 'screenshot')
        self.assertEqual(self.proof_data.visual_proof_path, '/path/to/proof.png')
        self.assertEqual(self.proof_data.visual_proof_type, 'screenshot')
    
    def test_add_callback_evidence(self):
        """Test adding callback evidence."""
        callback_data = {
            'callback_id': 'abc123',
            'callback_received': True,
            'data': 'test'
        }
        self.proof_data.add_callback_evidence(callback_data)
        
        self.assertEqual(len(self.proof_data.callback_evidence), 1)
        self.assertIn('callback_id', self.proof_data.callback_evidence[0])
    
    def test_set_success(self):
        """Test setting success status."""
        self.proof_data.set_success(True, True, 0.95)
        self.assertTrue(self.proof_data.success)
        self.assertTrue(self.proof_data.verified)
        self.assertEqual(self.proof_data.confidence_score, 0.95)
    
    def test_add_metadata(self):
        """Test adding metadata."""
        self.proof_data.add_metadata('target_url', 'http://example.com')
        self.proof_data.add_metadata('plugin_version', '1.0.0')
        
        self.assertEqual(self.proof_data.metadata['target_url'], 'http://example.com')
        self.assertEqual(self.proof_data.metadata['plugin_version'], '1.0.0')
    
    def test_to_dict(self):
        """Test converting to dictionary."""
        self.proof_data.set_success(True, True, 0.9)
        self.proof_data.add_log('Test log')
        self.proof_data.add_metadata('key', 'value')
        
        data_dict = self.proof_data.to_dict()
        
        self.assertIsInstance(data_dict, dict)
        self.assertEqual(data_dict['vulnerability_type'], 'xss')
        self.assertTrue(data_dict['success'])
        self.assertTrue(data_dict['verified'])
        self.assertEqual(data_dict['confidence_score'], 0.9)
        self.assertEqual(len(data_dict['logs']), 1)
        self.assertIn('key', data_dict['metadata'])
    
    def test_to_json(self):
        """Test converting to JSON."""
        self.proof_data.set_success(True, True, 0.8)
        json_str = self.proof_data.to_json()
        
        self.assertIsInstance(json_str, str)
        data = json.loads(json_str)
        self.assertEqual(data['vulnerability_type'], 'xss')
        self.assertTrue(data['success'])


class TestProofReporter(unittest.TestCase):
    """Test ProofReporter class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for tests
        self.temp_dir = tempfile.mkdtemp()
        self.reporter = ProofReporter(
            output_dir=self.temp_dir,
            enable_visual_proof=False  # Disable for unit tests
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test ProofReporter initialization."""
        self.assertTrue(Path(self.temp_dir).exists())
        self.assertTrue(self.reporter.enable_http_capture)
        self.assertTrue(self.reporter.enable_callback_verification)
        self.assertFalse(self.reporter.enable_visual_proof)
    
    def test_create_proof_data(self):
        """Test creating proof data container."""
        proof_data = self.reporter.create_proof_data('rce', 456)
        
        self.assertIsInstance(proof_data, ProofData)
        self.assertEqual(proof_data.vulnerability_type, 'rce')
        self.assertEqual(proof_data.vulnerability_id, 456)
    
    def test_save_proof_json(self):
        """Test saving proof data to JSON."""
        proof_data = self.reporter.create_proof_data('sqli', 789)
        proof_data.set_success(True, True, 0.85)
        proof_data.add_log('SQL injection successful')
        
        json_path = self.reporter.save_proof_json(proof_data)
        
        self.assertIsNotNone(json_path)
        self.assertTrue(Path(json_path).exists())
        
        # Verify content
        with open(json_path, 'r') as f:
            data = json.load(f)
            self.assertEqual(data['vulnerability_type'], 'sqli')
            self.assertTrue(data['success'])
    
    def test_save_proof_html(self):
        """Test saving proof data to HTML."""
        proof_data = self.reporter.create_proof_data('xss', 123)
        proof_data.set_success(True, True, 0.9)
        proof_data.add_log('XSS payload executed')
        proof_data.add_http_request('GET', 'http://example.com', {}, '')
        
        html_path = self.reporter.save_proof_html(proof_data)
        
        self.assertIsNotNone(html_path)
        self.assertTrue(Path(html_path).exists())
        
        # Verify it's HTML
        with open(html_path, 'r') as f:
            content = f.read()
            self.assertIn('<!DOCTYPE html>', content)
            self.assertIn('XSS', content.upper())
            self.assertIn('SUCCESS', content.upper())
    
    def test_html_report_structure(self):
        """Test HTML report structure and content."""
        proof_data = self.reporter.create_proof_data('rce', 999)
        proof_data.set_success(True, True, 0.95)
        proof_data.add_log('Command executed: whoami')
        proof_data.set_command_output('root')
        proof_data.add_http_request('POST', 'http://example.com/api', 
                                    {'Content-Type': 'application/json'}, '{"cmd":"whoami"}')
        proof_data.add_http_response(200, {'Server': 'nginx'}, 'root')
        proof_data.add_metadata('target', 'example.com')
        
        html_path = self.reporter.save_proof_html(proof_data)
        
        with open(html_path, 'r') as f:
            content = f.read()
            # Check for key sections
            self.assertIn('Summary', content)
            self.assertIn('HTTP Traffic', content)
            self.assertIn('Exploitation Output', content)
            self.assertIn('Command Output', content)
            self.assertIn('Logs', content)
            self.assertIn('VERIFIED', content)
            self.assertIn('root', content)
    
    @patch('scanner.models.Vulnerability')
    def test_store_in_database(self, mock_vuln_model):
        """Test storing proof data in database."""
        # Create mock vulnerability
        mock_vuln = Mock()
        mock_vuln.id = 123
        mock_vuln_model.objects.get.return_value = mock_vuln
        
        proof_data = self.reporter.create_proof_data('xss', 123)
        proof_data.set_success(True, True, 0.9)
        proof_data.add_http_request('GET', 'http://test.com', {}, '')
        
        result = self.reporter.store_in_database(proof_data)
        
        self.assertTrue(result)
        mock_vuln.save.assert_called_once()
        self.assertTrue(mock_vuln.verified)
        self.assertEqual(mock_vuln.confidence_score, 0.9)
    
    def test_report_proof_all_outputs(self):
        """Test complete proof reporting with all outputs."""
        proof_data = self.reporter.create_proof_data('ssrf', 555)
        proof_data.set_success(True, True, 0.88)
        proof_data.add_log('SSRF confirmed')
        proof_data.set_extracted_data({'metadata': 'aws-credentials'})
        
        results = self.reporter.report_proof(
            proof_data,
            save_json=True,
            save_html=True,
            store_db=False  # Disable DB for unit test
        )
        
        self.assertTrue(results['success'])
        self.assertIsNotNone(results['json_path'])
        self.assertIsNotNone(results['html_path'])
        self.assertTrue(Path(results['json_path']).exists())
        self.assertTrue(Path(results['html_path']).exists())


class TestProofReporterIntegration(unittest.TestCase):
    """Integration tests for ProofReporter with exploit plugins."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_xss_proof_reporting(self):
        """Test proof reporting for XSS exploit."""
        reporter = ProofReporter(output_dir=self.temp_dir, enable_visual_proof=False)
        
        # Simulate XSS exploitation result
        proof_data = reporter.create_proof_data('xss', 101)
        proof_data.set_success(True, True, 0.92)
        proof_data.add_http_request('GET', 'http://victim.com/search?q=<script>alert(1)</script>', 
                                    {'User-Agent': 'Megido'}, '')
        proof_data.add_http_response(200, {}, '<html><script>alert(1)</script></html>')
        proof_data.add_log('XSS payload reflected in response')
        proof_data.add_callback_evidence({'callback_id': 'xss123', 'verified': True})
        proof_data.add_metadata('payload', '<script>alert(1)</script>')
        
        results = reporter.report_proof(proof_data, save_json=True, save_html=True, store_db=False)
        
        self.assertTrue(results['success'])
        self.assertIsNotNone(results['json_path'])
        self.assertIsNotNone(results['html_path'])
    
    def test_rce_proof_reporting(self):
        """Test proof reporting for RCE exploit."""
        reporter = ProofReporter(output_dir=self.temp_dir, enable_visual_proof=False)
        
        # Simulate RCE exploitation result
        proof_data = reporter.create_proof_data('rce', 202)
        proof_data.set_success(True, True, 0.98)
        proof_data.add_http_request('POST', 'http://victim.com/exec', 
                                    {'Content-Type': 'application/x-www-form-urlencoded'},
                                    'cmd=whoami')
        proof_data.add_http_response(200, {}, 'root')
        proof_data.set_command_output('root')
        proof_data.add_log('Command execution successful')
        proof_data.add_metadata('command', 'whoami')
        proof_data.add_metadata('os', 'linux')
        
        results = reporter.report_proof(proof_data, save_json=True, save_html=True, store_db=False)
        
        self.assertTrue(results['success'])
        
        # Verify JSON content
        with open(results['json_path'], 'r') as f:
            data = json.load(f)
            self.assertEqual(data['vulnerability_type'], 'rce')
            self.assertEqual(data['command_output'], 'root')
            self.assertTrue(data['verified'])
    
    def test_ssrf_proof_reporting(self):
        """Test proof reporting for SSRF exploit."""
        reporter = ProofReporter(output_dir=self.temp_dir, enable_visual_proof=False)
        
        # Simulate SSRF exploitation result
        proof_data = reporter.create_proof_data('ssrf', 303)
        proof_data.set_success(True, True, 0.87)
        proof_data.add_http_request('GET', 'http://victim.com/fetch?url=http://169.254.169.254/latest/meta-data/', 
                                    {}, '')
        proof_data.add_http_response(200, {}, 'ami-id\ninstance-type\n...')
        proof_data.set_extracted_data({'aws_metadata': 'ami-12345', 'instance_type': 't2.micro'})
        proof_data.add_log('AWS metadata extracted via SSRF')
        proof_data.add_oob_interaction({'type': 'http', 'url': 'http://attacker.com/ssrf', 'verified': True})
        proof_data.add_metadata('cloud_provider', 'aws')
        
        results = reporter.report_proof(proof_data, save_json=True, save_html=True, store_db=False)
        
        self.assertTrue(results['success'])
        
        # Verify HTML content
        with open(results['html_path'], 'r') as f:
            content = f.read()
            self.assertIn('SSRF', content.upper())
            self.assertIn('aws', content.lower())


class TestGlobalProofReporter(unittest.TestCase):
    """Test global proof reporter singleton."""
    
    def test_get_proof_reporter(self):
        """Test getting global proof reporter instance."""
        reporter1 = get_proof_reporter()
        reporter2 = get_proof_reporter()
        
        # Should return same instance
        self.assertIs(reporter1, reporter2)
        self.assertIsInstance(reporter1, ProofReporter)


if __name__ == '__main__':
    unittest.main()
