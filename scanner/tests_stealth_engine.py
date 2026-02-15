"""
Tests for Stealth Engine

Basic tests to validate stealth engine functionality.
"""

import unittest
import time
from scanner.stealth_engine import StealthEngine, get_stealth_engine


class TestStealthEngine(unittest.TestCase):
    """Test cases for StealthEngine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = StealthEngine(
            min_delay=0.1,
            max_delay=0.3,
            jitter_range=0.05,
            enable_session_rotation=True
        )
    
    def test_initialization(self):
        """Test engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.min_delay, 0.1)
        self.assertEqual(self.engine.max_delay, 0.3)
        self.assertTrue(self.engine.enable_session_rotation)
    
    def test_randomized_headers(self):
        """Test header randomization."""
        headers1 = self.engine.get_randomized_headers()
        headers2 = self.engine.get_randomized_headers()
        
        # Should have required headers
        self.assertIn('User-Agent', headers1)
        self.assertIn('Accept', headers1)
        self.assertIn('Accept-Language', headers1)
        self.assertIn('Accept-Encoding', headers1)
        
        # Headers should vary between calls (at least User-Agent might)
        # Note: Due to randomness, this could occasionally fail but very unlikely
        self.assertIsInstance(headers1['User-Agent'], str)
        self.assertIsInstance(headers2['User-Agent'], str)
    
    def test_request_delay(self):
        """Test request delay calculation."""
        delay = self.engine.get_request_delay()
        
        # Should be within configured range (with jitter)
        min_possible = self.engine.min_delay - self.engine.jitter_range
        max_possible = self.engine.max_delay + self.engine.jitter_range
        
        self.assertGreaterEqual(delay, 0.1)  # Always at least 0.1s
        self.assertLessEqual(delay, max_possible)
    
    def test_wait_before_request(self):
        """Test actual waiting."""
        start = time.time()
        self.engine.wait_before_request(force_delay=True)
        elapsed = time.time() - start
        
        # Should have waited at least min_delay - jitter
        min_wait = self.engine.min_delay - self.engine.jitter_range
        self.assertGreaterEqual(elapsed, 0.05)  # Some wait occurred
    
    def test_parameter_randomization(self):
        """Test parameter order randomization."""
        params = {'a': '1', 'b': '2', 'c': '3', 'd': '4', 'e': '5'}
        
        # Try multiple times to ensure randomization
        results = []
        for _ in range(10):
            randomized = self.engine.randomize_parameter_order(params)
            results.append(list(randomized.keys()))
        
        # Should have same keys
        for result in results:
            self.assertEqual(set(result), set(params.keys()))
        
        # At least one should be different order (very high probability)
        original_order = list(params.keys())
        different_orders = [r for r in results if r != original_order]
        self.assertGreater(len(different_orders), 0)
    
    def test_url_parameter_randomization(self):
        """Test URL parameter randomization."""
        url = 'https://example.com/page?a=1&b=2&c=3'
        
        randomized = self.engine.randomize_url_parameters(url)
        
        # Should still be a valid URL
        self.assertIn('example.com/page', randomized)
        self.assertIn('a=1', randomized)
        self.assertIn('b=2', randomized)
        self.assertIn('c=3', randomized)
    
    def test_session_rotation(self):
        """Test session rotation."""
        session1 = self.engine.current_session_id
        self.engine.rotate_session()
        session2 = self.engine.current_session_id
        
        # Should be different after rotation
        self.assertNotEqual(session1, session2)
    
    def test_session_cookies(self):
        """Test session cookie generation."""
        cookies = self.engine.get_session_cookies('example.com')
        
        # Should have session cookie
        self.assertIsInstance(cookies, dict)
        self.assertGreater(len(cookies), 0)
        
        # Check for common session cookie names
        common_names = ['PHPSESSID', 'JSESSIONID', 'sessionid', 'session', '_session_id']
        has_session_cookie = any(name in cookies for name in common_names)
        self.assertTrue(has_session_cookie)
    
    def test_payload_encoding(self):
        """Test payload encoding."""
        payload = '<script>alert(1)</script>'
        
        # Test different encodings
        url_encoded = self.engine.encode_payload(payload, 'url')
        self.assertNotEqual(url_encoded, payload)
        self.assertIn('%', url_encoded)  # Should have URL encoding
        
        html_encoded = self.engine.encode_payload(payload, 'html')
        self.assertNotEqual(html_encoded, payload)
        self.assertIn('&#', html_encoded)  # Should have HTML entities
        
        # None encoding should return original
        none_encoded = self.engine.encode_payload(payload, 'none')
        self.assertEqual(none_encoded, payload)
    
    def test_referer_header(self):
        """Test referer header generation."""
        url = 'https://example.com/page'
        
        referer = self.engine.get_referer_header(url)
        self.assertIsInstance(referer, str)
        self.assertIn('example.com', referer)
        
        # Test with previous URL
        prev = 'https://example.com/previous'
        referer_with_prev = self.engine.get_referer_header(url, prev)
        self.assertEqual(referer_with_prev, prev)
    
    def test_factory_function(self):
        """Test factory function."""
        config = {
            'min_delay': 0.2,
            'max_delay': 0.5,
            'jitter_range': 0.1,
            'enable_session_rotation': False,
        }
        
        engine = get_stealth_engine(config)
        self.assertIsNotNone(engine)
        self.assertEqual(engine.min_delay, 0.2)
        self.assertEqual(engine.max_delay, 0.5)
        self.assertFalse(engine.enable_session_rotation)


if __name__ == '__main__':
    unittest.main()
