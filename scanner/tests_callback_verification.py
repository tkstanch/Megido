"""
Tests for XSS Callback Verification System

This test suite verifies the functionality of the callback-based XSS verification system.
"""

import unittest
import time
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the callback verifier
try:
    from scanner.plugins.xss_callback_verifier import (
        XSSCallbackVerifier, 
        get_default_callback_payloads
    )
    HAS_CALLBACK_VERIFIER = True
except ImportError:
    HAS_CALLBACK_VERIFIER = False


class TestXSSCallbackVerifier(unittest.TestCase):
    """Test cases for XSS callback verifier."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not HAS_CALLBACK_VERIFIER:
            self.skipTest("Callback verifier not available")
        
        # Create verifier with test endpoint
        self.verifier = XSSCallbackVerifier(
            callback_endpoint='https://test-callback.example.com',
            timeout=5,
            poll_interval=1,
            use_internal_collaborator=False
        )
    
    def test_initialization(self):
        """Test verifier initialization."""
        self.assertEqual(self.verifier.callback_endpoint, 'https://test-callback.example.com')
        self.assertEqual(self.verifier.timeout, 5)
        self.assertEqual(self.verifier.poll_interval, 1)
        self.assertEqual(len(self.verifier.pending_verifications), 0)
    
    def test_generate_payload_id(self):
        """Test payload ID generation."""
        payload_id1 = self.verifier._generate_payload_id()
        payload_id2 = self.verifier._generate_payload_id()
        
        # Should generate unique IDs
        self.assertNotEqual(payload_id1, payload_id2)
        
        # Should be 16 characters (MD5 hash truncated)
        self.assertEqual(len(payload_id1), 16)
        self.assertEqual(len(payload_id2), 16)
    
    def test_build_callback_url(self):
        """Test callback URL building."""
        payload_id = 'test123abc456def'
        callback_url = self.verifier._build_callback_url(payload_id)
        
        # Should contain the payload ID
        self.assertIn(payload_id, callback_url)
        
        # Should contain the base endpoint
        self.assertIn('test-callback.example.com', callback_url)
    
    def test_generate_callback_javascript(self):
        """Test JavaScript callback code generation."""
        callback_url = 'https://test-callback.example.com/abc123'
        js_code = self.verifier._generate_callback_javascript(callback_url)
        
        # Should contain the callback URL
        self.assertIn(callback_url, js_code)
        
        # Should use multiple methods (XMLHttpRequest, fetch, Image)
        self.assertIn('XMLHttpRequest', js_code)
        self.assertIn('fetch', js_code)
        self.assertIn('Image', js_code)
        
        # Should be minified (no newlines)
        self.assertNotIn('\n', js_code)
    
    def test_generate_callback_payload_basic(self):
        """Test basic callback payload generation."""
        payload, payload_id = self.verifier.generate_callback_payload(
            base_payload='<script>CALLBACK</script>',
            context='html'
        )
        
        # Should return both payload and ID
        self.assertIsInstance(payload, str)
        self.assertIsInstance(payload_id, str)
        self.assertEqual(len(payload_id), 16)
        
        # Payload should contain callback code
        self.assertIn('<script>', payload)
        self.assertIn('XMLHttpRequest', payload)
        self.assertIn('test-callback.example.com', payload)
        
        # Should track the payload
        self.assertIn(payload_id, self.verifier.pending_verifications)
        
        verification = self.verifier.pending_verifications[payload_id]
        self.assertEqual(verification['context'], 'html')
        self.assertEqual(verification['payload'], payload)
        self.assertFalse(verification['verified'])
    
    def test_generate_callback_payload_img_tag(self):
        """Test callback payload generation with img tag."""
        payload, payload_id = self.verifier.generate_callback_payload(
            base_payload='<img src=x onerror="CALLBACK">',
            context='attribute'
        )
        
        # Should replace CALLBACK placeholder
        self.assertNotIn('CALLBACK', payload)
        self.assertIn('onerror', payload)
        self.assertIn('XMLHttpRequest', payload)
    
    def test_generate_multiple_payloads(self):
        """Test generating multiple callback payloads."""
        templates = [
            '<script>CALLBACK</script>',
            '<img src=x onerror="CALLBACK">',
            '<svg/onload="CALLBACK">'
        ]
        
        results = self.verifier.generate_multiple_payloads(templates, context='html')
        
        # Should generate payload for each template
        self.assertEqual(len(results), 3)
        
        # Each should have unique payload ID
        payload_ids = [pid for _, pid in results]
        self.assertEqual(len(set(payload_ids)), 3)
        
        # Should track all payloads
        for _, payload_id in results:
            self.assertIn(payload_id, self.verifier.pending_verifications)
    
    def test_verify_callback_no_interaction(self):
        """Test verification when no callback is received."""
        payload, payload_id = self.verifier.generate_callback_payload(
            base_payload='<script>CALLBACK</script>'
        )
        
        # Mock the interaction check to return empty
        self.verifier._check_for_interactions = Mock(return_value=[])
        
        # Verify without waiting
        is_verified, interactions = self.verifier.verify_callback(payload_id, wait=False)
        
        self.assertFalse(is_verified)
        self.assertEqual(len(interactions), 0)
        
        # Should still be tracked but not verified
        verification = self.verifier.get_verification_status(payload_id)
        self.assertFalse(verification['verified'])
    
    def test_verify_callback_with_interaction(self):
        """Test verification when callback is received."""
        payload, payload_id = self.verifier.generate_callback_payload(
            base_payload='<script>CALLBACK</script>'
        )
        
        # Mock the interaction check to return a callback
        mock_interaction = {
            'id': 1,
            'type': 'http',
            'source_ip': '203.0.113.42',
            'timestamp': datetime.now().isoformat(),
            'http_method': 'GET',
            'http_path': f'/callback/{payload_id}',
            'raw_data': 'GET request data'
        }
        
        self.verifier._check_for_interactions = Mock(return_value=[mock_interaction])
        
        # Verify without waiting
        is_verified, interactions = self.verifier.verify_callback(payload_id, wait=False)
        
        self.assertTrue(is_verified)
        self.assertEqual(len(interactions), 1)
        self.assertEqual(interactions[0]['source_ip'], '203.0.113.42')
        
        # Should be marked as verified
        verification = self.verifier.get_verification_status(payload_id)
        self.assertTrue(verification['verified'])
        self.assertIn('verified_at', verification)
    
    def test_verify_callback_unknown_id(self):
        """Test verification with unknown payload ID."""
        is_verified, interactions = self.verifier.verify_callback('unknown_id', wait=False)
        
        self.assertFalse(is_verified)
        self.assertEqual(len(interactions), 0)
    
    def test_get_verification_status(self):
        """Test getting verification status."""
        payload, payload_id = self.verifier.generate_callback_payload('<script>CALLBACK</script>')
        
        status = self.verifier.get_verification_status(payload_id)
        
        self.assertIsNotNone(status)
        self.assertIn('payload', status)
        self.assertIn('context', status)
        self.assertIn('callback_url', status)
        self.assertIn('created_at', status)
        self.assertIn('verified', status)
    
    def test_get_all_verifications(self):
        """Test getting all verifications."""
        # Generate multiple payloads
        templates = ['<script>CALLBACK</script>', '<img src=x onerror="CALLBACK">']
        results = self.verifier.generate_multiple_payloads(templates)
        
        all_verifications = self.verifier.get_all_verifications()
        
        self.assertEqual(len(all_verifications), 2)
        for _, payload_id in results:
            self.assertIn(payload_id, all_verifications)
    
    def test_clear_verification(self):
        """Test clearing a specific verification."""
        payload, payload_id = self.verifier.generate_callback_payload('<script>CALLBACK</script>')
        
        self.assertIn(payload_id, self.verifier.pending_verifications)
        
        self.verifier.clear_verification(payload_id)
        
        self.assertNotIn(payload_id, self.verifier.pending_verifications)
    
    def test_clear_all_verifications(self):
        """Test clearing all verifications."""
        # Generate multiple payloads
        templates = ['<script>CALLBACK</script>', '<img src=x onerror="CALLBACK">']
        self.verifier.generate_multiple_payloads(templates)
        
        self.assertGreater(len(self.verifier.pending_verifications), 0)
        
        self.verifier.clear_all_verifications()
        
        self.assertEqual(len(self.verifier.pending_verifications), 0)
    
    def test_generate_report(self):
        """Test report generation."""
        payload, payload_id = self.verifier.generate_callback_payload('<script>CALLBACK</script>')
        
        # Generate report for unverified
        report = self.verifier.generate_report(payload_id)
        
        self.assertIn(payload_id, report)
        self.assertIn('NOT VERIFIED', report)
        self.assertIn(payload, report)
        
        # Mock verification
        self.verifier.pending_verifications[payload_id]['verified'] = True
        self.verifier.pending_verifications[payload_id]['verified_at'] = datetime.now().isoformat()
        self.verifier.pending_verifications[payload_id]['interactions'] = [{
            'type': 'http',
            'source_ip': '203.0.113.42',
            'timestamp': datetime.now().isoformat(),
            'http_method': 'GET',
            'http_path': f'/callback/{payload_id}'
        }]
        
        # Generate report for verified
        report = self.verifier.generate_report(payload_id)
        
        self.assertIn(payload_id, report)
        self.assertIn('VERIFIED', report)
        self.assertIn('203.0.113.42', report)
        self.assertIn('INTERACTIONS', report)
    
    def test_generate_report_unknown_id(self):
        """Test report generation for unknown ID."""
        report = self.verifier.generate_report('unknown_id')
        
        self.assertIn('No verification found', report)


class TestGetDefaultCallbackPayloads(unittest.TestCase):
    """Test cases for default callback payloads."""
    
    def test_get_default_payloads(self):
        """Test getting default callback payloads."""
        if not HAS_CALLBACK_VERIFIER:
            self.skipTest("Callback verifier not available")
        
        payloads = get_default_callback_payloads()
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # All should contain CALLBACK placeholder
        for payload in payloads:
            self.assertIn('CALLBACK', payload)
    
    def test_payload_variety(self):
        """Test that payloads include various XSS vectors."""
        if not HAS_CALLBACK_VERIFIER:
            self.skipTest("Callback verifier not available")
        
        payloads = get_default_callback_payloads()
        payload_text = ' '.join(payloads)
        
        # Should include various injection methods
        self.assertIn('<script>', payload_text)
        self.assertIn('onerror', payload_text)
        self.assertIn('onload', payload_text)
        self.assertIn('<svg', payload_text)
        self.assertIn('<img', payload_text)


class TestXSSPluginCallbackIntegration(unittest.TestCase):
    """Test XSS plugin integration with callback verification."""
    
    def setUp(self):
        """Set up test fixtures."""
        try:
            from scanner.plugins.exploits.xss_plugin import XSSPlugin
            self.plugin = XSSPlugin()
            self.plugin_available = True
        except ImportError:
            self.plugin_available = False
    
    def test_plugin_initialization_with_callback(self):
        """Test plugin initializes with callback verifier."""
        if not self.plugin_available or not HAS_CALLBACK_VERIFIER:
            self.skipTest("Plugin or callback verifier not available")
        
        # Plugin should not have callback verifier until execute_attack is called
        self.assertIsNone(self.plugin.callback_verifier)
    
    def test_plugin_config_callback_disabled(self):
        """Test plugin with callback verification disabled."""
        if not self.plugin_available:
            self.skipTest("Plugin not available")
        
        # This should not raise an error even if callback is disabled
        config = {
            'callback_verification_enabled': False,
            'enable_crawler': False,
            'enable_dom_testing': False
        }
        
        # Should be able to execute (though it won't do much without DOM testing)
        # This is more of a config validation test
        valid = self.plugin.validate_config(config)
        self.assertTrue(valid)


if __name__ == '__main__':
    unittest.main()
