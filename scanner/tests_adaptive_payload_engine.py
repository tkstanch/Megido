"""
Tests for Adaptive Payload Engine

Basic tests to validate adaptive payload engine functionality.
"""

import unittest
from scanner.adaptive_payload_engine import AdaptivePayloadEngine, get_adaptive_payload_engine


class TestAdaptivePayloadEngine(unittest.TestCase):
    """Test cases for AdaptivePayloadEngine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = AdaptivePayloadEngine()
    
    def test_initialization(self):
        """Test engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertIsInstance(self.engine.context_cache, dict)
    
    def test_xss_payload_generation(self):
        """Test XSS payload generation."""
        payloads = self.engine.generate_adaptive_payloads('xss', context='html')
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # Should contain XSS patterns
        has_script = any('<script>' in p for p in payloads)
        has_img = any('<img' in p for p in payloads)
        has_svg = any('<svg' in p for p in payloads)
        
        self.assertTrue(has_script or has_img or has_svg)
    
    def test_sqli_payload_generation(self):
        """Test SQL injection payload generation."""
        payloads = self.engine.generate_adaptive_payloads('sqli', context='mysql')
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # Should contain SQL patterns
        has_or = any("OR" in p for p in payloads)
        has_union = any("UNION" in p for p in payloads)
        
        self.assertTrue(has_or or has_union)
    
    def test_rce_payload_generation(self):
        """Test RCE payload generation."""
        payloads = self.engine.generate_adaptive_payloads('rce', context='unix')
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        
        # Should contain command patterns
        has_whoami = any('whoami' in p for p in payloads)
        has_id = any('id' in p for p in payloads)
        
        self.assertTrue(has_whoami or has_id)
    
    def test_xss_context_variations(self):
        """Test XSS payloads for different contexts."""
        contexts = ['html', 'attribute', 'javascript', 'json', 'svg']
        
        for context in contexts:
            payloads = self.engine.generate_adaptive_payloads('xss', context=context)
            self.assertGreater(len(payloads), 0, f"No payloads for {context} context")
    
    def test_callback_payload_generation(self):
        """Test payload generation with callback URL."""
        callback_url = 'https://callback.example.com/test123'
        
        payloads = self.engine.generate_adaptive_payloads(
            'xss',
            context='html',
            callback_url=callback_url
        )
        
        # Should include callback-based payloads
        has_callback = any(callback_url in p for p in payloads)
        self.assertTrue(has_callback)
    
    def test_context_detection(self):
        """Test injection context detection."""
        # HTML context
        html_response = '<div>User input: <script>test</script></div>'
        context = self.engine.detect_context(html_response, 'test')
        self.assertIn(context, ['html', 'javascript'])
        
        # JSON context
        json_response = '{"data": "test"}'
        context = self.engine.detect_context(json_response, 'test')
        self.assertEqual(context, 'json')
        
        # Attribute context
        attr_response = '<input value="test" />'
        context = self.engine.detect_context(attr_response, 'test')
        self.assertEqual(context, 'attribute')
    
    def test_reflection_analysis(self):
        """Test reflection analysis."""
        test_payload = '<script>TEST123</script>'
        
        # Test direct reflection
        response_reflected = f'<div>User said: {test_payload}</div>'
        analysis = self.engine.analyze_reflection(response_reflected, test_payload)
        
        self.assertTrue(analysis['reflected'])
        self.assertIsInstance(analysis['context'], str)
        self.assertFalse(analysis['encoded'])
        
        # Test non-reflection
        response_not_reflected = '<div>Hello world</div>'
        analysis = self.engine.analyze_reflection(response_not_reflected, test_payload)
        
        self.assertFalse(analysis['reflected'])
    
    def test_reflection_encoded(self):
        """Test encoded reflection detection."""
        test_payload = '<script>alert(1)</script>'
        
        # HTML entity encoded
        response_encoded = '&lt;script&gt;alert(1)&lt;/script&gt;'
        analysis = self.engine.analyze_reflection(response_encoded, test_payload)
        
        self.assertTrue(analysis['reflected'])
        self.assertTrue(analysis['encoded'])
    
    def test_filter_bypass_suggestions(self):
        """Test filter bypass suggestions."""
        payload = '<script>alert(1)</script>'
        response = 'alert(1)'  # 'script' tag filtered
        
        analysis = self.engine.analyze_reflection(response, payload)
        
        if analysis['filtered']:
            bypasses = analysis['filter_bypasses']
            self.assertIsInstance(bypasses, list)
            self.assertGreater(len(bypasses), 0)
    
    def test_payload_encoding(self):
        """Test payload encoding."""
        payload = '<script>test</script>'
        
        # URL encoding
        url_encoded = self.engine.encode_payload(payload, 'url')
        self.assertNotEqual(url_encoded, payload)
        
        # HTML encoding
        html_encoded = self.engine.encode_payload(payload, 'html')
        self.assertNotEqual(html_encoded, payload)
        self.assertIn('&lt;', html_encoded)
        
        # Base64 encoding
        base64_encoded = self.engine.encode_payload(payload, 'base64')
        self.assertNotEqual(base64_encoded, payload)
        
        # Unicode encoding
        unicode_encoded = self.engine.encode_payload(payload, 'unicode')
        self.assertNotEqual(unicode_encoded, payload)
        self.assertIn('\\u', unicode_encoded)
    
    def test_multi_encoded_payloads(self):
        """Test multi-encoded payload generation."""
        payload = '<script>alert(1)</script>'
        
        variants = self.engine.generate_multi_encoded_payloads(payload)
        
        self.assertIsInstance(variants, list)
        self.assertGreater(len(variants), 1)  # At least original + 1 encoded
        
        # Original should be included
        self.assertIn(payload, variants)
    
    def test_waf_detection(self):
        """Test WAF detection."""
        # Cloudflare WAF
        headers_cf = {'cf-ray': '12345-LAX'}
        waf = self.engine.detect_waf_signature('Access denied', 403, headers_cf)
        self.assertEqual(waf, 'cloudflare')
        
        # No WAF
        headers_none = {'server': 'nginx'}
        waf = self.engine.detect_waf_signature('Normal response', 200, headers_none)
        self.assertIsNone(waf)
    
    def test_select_best_payloads(self):
        """Test best payload selection."""
        payloads = self.engine.select_best_payloads('xss', 'html', max_payloads=5)
        
        self.assertIsInstance(payloads, list)
        self.assertLessEqual(len(payloads), 5)
        self.assertGreater(len(payloads), 0)
    
    def test_select_best_payloads_with_analysis(self):
        """Test payload selection with reflection analysis."""
        reflection_analysis = {
            'reflected': True,
            'filtered': True,
            'filter_bypasses': ['Use alternative tags: <img>, <svg>']
        }
        
        payloads = self.engine.select_best_payloads(
            'xss',
            'html',
            reflection_analysis=reflection_analysis,
            max_payloads=10
        )
        
        # Should prioritize img/svg tags based on bypass suggestions
        has_img_or_svg = any('<img' in p or '<svg' in p for p in payloads[:3])
        self.assertTrue(has_img_or_svg)
    
    def test_factory_function(self):
        """Test factory function."""
        engine = get_adaptive_payload_engine()
        self.assertIsNotNone(engine)
        self.assertIsInstance(engine, AdaptivePayloadEngine)


if __name__ == '__main__':
    unittest.main()
