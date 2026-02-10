"""
Tests for the Enhanced Sensitive Information Scanner Module
"""
import unittest
import tempfile
import os
import json
from unittest.mock import Mock, patch, MagicMock
from discover.sensitive_scanner_enhanced import (
    PatternProvider,
    SensitivePatterns,
    ExternalPatternProvider,
    HeuristicScanner,
    MLIntegrationTemplate,
    ContextAnalyzer,
    ScanResultCache,
    EnhancedSensitiveInfoScanner,
    scan_discovered_urls_enhanced
)


class TestPatternProvider(unittest.TestCase):
    """Tests for PatternProvider base class and implementations."""
    
    def test_sensitive_patterns_get_patterns(self):
        """Test SensitivePatterns returns patterns correctly."""
        provider = SensitivePatterns()
        patterns = provider.get_patterns()
        
        self.assertIsInstance(patterns, dict)
        self.assertIn('AWS Access Key', patterns)
        self.assertIn('GitHub Personal Access Token', patterns)
        self.assertTrue(len(patterns) > 0)
    
    def test_sensitive_patterns_get_severity(self):
        """Test SensitivePatterns returns correct severity levels."""
        provider = SensitivePatterns()
        
        self.assertEqual(provider.get_pattern_severity('AWS Access Key'), 'critical')
        self.assertEqual(provider.get_pattern_severity('Email Address'), 'low')
        self.assertEqual(provider.get_pattern_severity('Generic API Key'), 'high')
        self.assertEqual(provider.get_pattern_severity('Unknown Pattern'), 'medium')
    
    def test_external_pattern_provider_from_file(self):
        """Test ExternalPatternProvider loads patterns from file."""
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config = {
                'patterns': {
                    'Custom API Key': r'custom_[0-9a-f]{32}',
                    'Test Secret': r'test_secret_\w+'
                },
                'severity': {
                    'Custom API Key': 'high',
                    'Test Secret': 'medium'
                }
            }
            json.dump(config, f)
            temp_file = f.name
        
        try:
            provider = ExternalPatternProvider(source_file=temp_file)
            patterns = provider.get_patterns()
            
            self.assertEqual(len(patterns), 2)
            self.assertIn('Custom API Key', patterns)
            self.assertEqual(provider.get_pattern_severity('Custom API Key'), 'high')
        finally:
            os.unlink(temp_file)
    
    def test_external_pattern_provider_cache(self):
        """Test ExternalPatternProvider caching mechanism."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config = {'patterns': {'Test': r'test'}, 'severity': {'Test': 'low'}}
            json.dump(config, f)
            temp_file = f.name
        
        try:
            provider = ExternalPatternProvider(source_file=temp_file, cache_ttl=60)
            
            # First call - loads from file
            patterns1 = provider.get_patterns()
            
            # Second call - uses cache
            patterns2 = provider.get_patterns()
            
            self.assertEqual(patterns1, patterns2)
            self.assertTrue(provider._is_cache_valid())
        finally:
            os.unlink(temp_file)


class TestHeuristicScanner(unittest.TestCase):
    """Tests for HeuristicScanner class."""
    
    def test_calculate_entropy(self):
        """Test entropy calculation."""
        # High entropy string (random-looking)
        high_entropy = "aB3xK9mN2pQ7vY1zL4wR6sT8"
        entropy_high = HeuristicScanner.calculate_entropy(high_entropy)
        
        # Low entropy string (repetitive)
        low_entropy = "aaaaaaaaaaaaaaaa"
        entropy_low = HeuristicScanner.calculate_entropy(low_entropy)
        
        # High entropy should be greater than low entropy
        self.assertGreater(entropy_high, entropy_low)
        self.assertGreater(entropy_high, 4.0)
        self.assertLess(entropy_low, 1.0)
    
    def test_detect_high_entropy_strings(self):
        """Test detection of high entropy strings."""
        content = """
        This is a test with a suspicious token: aB3xK9mN2pQ7vY1zL4wR6sT8uH5jF0
        And a normal word: hello
        """
        
        findings = HeuristicScanner.detect_high_entropy_strings(content)
        
        # Should detect at least the high entropy string
        self.assertTrue(len(findings) > 0)
        self.assertTrue(any('aB3xK9mN2pQ7vY1zL4wR6sT8uH5jF0' in f['value'] for f in findings))
    
    def test_detect_suspicious_assignments(self):
        """Test detection of suspicious variable assignments."""
        content = """
        api_key = "sk_live_abcdef123456789"
        secret_token = "very_secret_value_here"
        password = "test_password"
        """
        
        findings = HeuristicScanner.detect_suspicious_assignments(content)
        
        # Should detect the suspicious assignments
        self.assertTrue(len(findings) > 0)
        types = [f['type'] for f in findings]
        self.assertTrue(any('key' in t.lower() or 'secret' in t.lower() or 'token' in t.lower() for t in types))
    
    def test_detect_suspicious_assignments_skips_placeholders(self):
        """Test that placeholder values are skipped."""
        content = """
        api_key = "your_api_key_here"
        secret = "example_secret"
        password = "placeholder_password"
        """
        
        findings = HeuristicScanner.detect_suspicious_assignments(content)
        
        # Should not detect placeholder values
        self.assertEqual(len(findings), 0)


class TestMLIntegrationTemplate(unittest.TestCase):
    """Tests for ML integration template."""
    
    def test_ml_template_initialization(self):
        """Test ML template initializes correctly."""
        ml = MLIntegrationTemplate()
        self.assertIsNone(ml.model)
        self.assertIsNone(ml.model_path)
    
    def test_ml_template_predict_no_model(self):
        """Test prediction returns False when no model is loaded."""
        ml = MLIntegrationTemplate()
        is_sensitive, confidence = ml.predict_sensitive("test content")
        
        self.assertFalse(is_sensitive)
        self.assertEqual(confidence, 0.0)


class TestContextAnalyzer(unittest.TestCase):
    """Tests for ContextAnalyzer class."""
    
    def test_check_environment_correlation(self):
        """Test environment variable correlation check."""
        # Set a test environment variable
        os.environ['TEST_API_KEY'] = 'test_value_12345'
        
        try:
            result = ContextAnalyzer.check_environment_correlation('test_value_12345')
            
            self.assertTrue(result['has_correlation'])
            self.assertTrue(len(result['correlations']) > 0)
            self.assertEqual(result['correlations'][0]['name'], 'TEST_API_KEY')
            self.assertEqual(result['correlations'][0]['match'], 'exact')
        finally:
            del os.environ['TEST_API_KEY']
    
    def test_detect_config_file_context(self):
        """Test configuration file detection."""
        # Test config file
        result = ContextAnalyzer.detect_config_file_context('/path/to/.env')
        self.assertTrue(result['is_config_file'])
        self.assertEqual(result['risk_level'], 'high')
        
        # Test non-config file
        result = ContextAnalyzer.detect_config_file_context('/path/to/script.py')
        self.assertFalse(result['is_config_file'])
        self.assertEqual(result['risk_level'], 'medium')


class TestScanResultCache(unittest.TestCase):
    """Tests for ScanResultCache class."""
    
    def test_cache_set_and_get(self):
        """Test cache storage and retrieval."""
        cache = ScanResultCache(ttl=60)
        
        result = {'findings': ['test']}
        cache.set('http://example.com', result)
        
        cached = cache.get('http://example.com')
        self.assertEqual(cached, result)
    
    def test_cache_expiration(self):
        """Test cache expiration."""
        cache = ScanResultCache(ttl=0)  # Immediate expiration
        
        result = {'findings': ['test']}
        cache.set('http://example.com', result)
        
        import time
        time.sleep(0.1)  # Short sleep sufficient for TTL=0
        
        cached = cache.get('http://example.com')
        self.assertIsNone(cached)
    
    def test_cache_clear(self):
        """Test cache clearing."""
        cache = ScanResultCache(ttl=60)
        
        cache.set('http://example.com', {'findings': ['test']})
        cache.clear()
        
        cached = cache.get('http://example.com')
        self.assertIsNone(cached)


class TestEnhancedSensitiveInfoScanner(unittest.TestCase):
    """Tests for EnhancedSensitiveInfoScanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner initializes with correct defaults."""
        scanner = EnhancedSensitiveInfoScanner()
        
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.max_workers, 5)
        self.assertTrue(scanner.enable_heuristics)
        self.assertFalse(scanner.enable_ml)
        self.assertIsNotNone(scanner.patterns)
        self.assertTrue(len(scanner.patterns) > 0)
    
    def test_scanner_with_custom_providers(self):
        """Test scanner with custom pattern providers."""
        custom_provider = SensitivePatterns()
        scanner = EnhancedSensitiveInfoScanner(pattern_providers=[custom_provider])
        
        self.assertTrue(len(scanner.patterns) > 0)
    
    def test_luhn_check_valid_card(self):
        """Test Luhn algorithm with valid credit card."""
        # Valid test card number
        valid_card = "4532015112830366"
        self.assertTrue(EnhancedSensitiveInfoScanner.luhn_check(valid_card))
    
    def test_luhn_check_invalid_card(self):
        """Test Luhn algorithm with invalid credit card."""
        invalid_card = "4532015112830367"  # Changed last digit
        self.assertFalse(EnhancedSensitiveInfoScanner.luhn_check(invalid_card))
    
    def test_scan_content_detects_aws_key(self):
        """Test scanning content detects AWS keys."""
        scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False)
        content = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        
        findings = scanner.scan_content_for_sensitive_data(content, 'test', 'url')
        
        self.assertTrue(len(findings) > 0)
        self.assertTrue(any('AWS' in f['type'] for f in findings))
    
    def test_scan_content_detects_github_token(self):
        """Test scanning content detects GitHub tokens."""
        scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False)
        # GitHub token pattern requires exactly 36 chars after ghp_
        content = "Token: ghp_123456789012345678901234567890123456"
        
        findings = scanner.scan_content_for_sensitive_data(content, 'test', 'url')
        
        self.assertTrue(len(findings) > 0)
        self.assertTrue(any('GitHub' in f['type'] for f in findings))
    
    def test_scan_content_with_heuristics(self):
        """Test scanning with heuristic detection enabled."""
        scanner = EnhancedSensitiveInfoScanner(enable_heuristics=True)
        content = """
        Some content with high entropy: aB3xK9mN2pQ7vY1zL4wR6sT8uH5jF0dG2eI9
        """
        
        findings = scanner.scan_content_for_sensitive_data(content, 'test', 'url')
        
        # Should have heuristic findings
        self.assertTrue(any(f.get('detection_method') == 'heuristic' for f in findings))
    
    def test_scan_file_success(self):
        """Test scanning a file successfully."""
        # Create temporary file with sensitive content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("API Key: AKIAIOSFODNN7EXAMPLE")
            temp_file = f.name
        
        try:
            scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False)
            result = scanner.scan_file(temp_file)
            
            self.assertTrue(result['success'])
            self.assertEqual(result['source_type'], 'file')
            self.assertTrue(len(result['findings']) > 0)
        finally:
            os.unlink(temp_file)
    
    @patch('discover.sensitive_scanner_enhanced.requests.get')
    def test_scan_url_success(self, mock_get):
        """Test scanning a URL successfully."""
        mock_response = Mock()
        mock_response.text = "API Key: AKIAIOSFODNN7EXAMPLE"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False)
        result = scanner.scan_url('http://example.com')
        
        self.assertTrue(result['success'])
        self.assertEqual(result['source_type'], 'url')
        self.assertTrue(len(result['findings']) > 0)
    
    @patch('discover.sensitive_scanner_enhanced.requests.get')
    def test_scan_url_timeout(self, mock_get):
        """Test handling of URL timeout."""
        mock_get.side_effect = Exception("Timeout")
        
        scanner = EnhancedSensitiveInfoScanner()
        result = scanner.scan_url('http://example.com')
        
        self.assertFalse(result['success'])
        self.assertEqual(len(result['findings']), 0)
    
    def test_scan_urls_multiple(self):
        """Test scanning multiple URLs."""
        scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False)
        
        with patch('discover.sensitive_scanner_enhanced.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = "API Key: AKIAIOSFODNN7EXAMPLE"
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response
            
            urls = ['http://example1.com', 'http://example2.com']
            results = scanner.scan_urls(urls)
            
            self.assertEqual(len(results), 2)
            self.assertTrue(all(r['success'] for r in results))
    
    def test_scan_files_multiple(self):
        """Test scanning multiple files."""
        # Create temporary files
        files = []
        for i in range(2):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(f"API Key: AKIAIOSFODNN7EXAMPL{i}")
                files.append(f.name)
        
        try:
            scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False)
            results = scanner.scan_files(files)
            
            self.assertEqual(len(results), 2)
            self.assertTrue(all(r['success'] for r in results))
        finally:
            for f in files:
                os.unlink(f)
    
    def test_scan_directory(self):
        """Test scanning a directory."""
        # Create temporary directory with files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_file1 = os.path.join(temp_dir, 'test1.txt')
            test_file2 = os.path.join(temp_dir, 'test2.py')
            
            with open(test_file1, 'w') as f:
                f.write("API Key: AKIAIOSFODNN7EXAMPLE")
            
            with open(test_file2, 'w') as f:
                # GitHub token pattern requires exactly 36 chars after ghp_
                f.write("Token: ghp_123456789012345678901234567890123456")
            
            scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False)
            results = scanner.scan_directory(temp_dir, recursive=False)
            
            self.assertEqual(len(results), 2)
            self.assertTrue(all(r['success'] for r in results))
    
    def test_cache_integration(self):
        """Test that caching works in scanner."""
        scanner = EnhancedSensitiveInfoScanner(enable_heuristics=False, cache_ttl=60)
        
        with patch('discover.sensitive_scanner_enhanced.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = "API Key: AKIAIOSFODNN7EXAMPLE"
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response
            
            # First scan
            result1 = scanner.scan_url('http://example.com')
            call_count_1 = mock_get.call_count
            
            # Second scan (should use cache)
            result2 = scanner.scan_url('http://example.com')
            call_count_2 = mock_get.call_count
            
            # Should not have made additional HTTP call
            self.assertEqual(call_count_1, call_count_2)
            self.assertEqual(result1, result2)


class TestScanDiscoveredUrlsEnhanced(unittest.TestCase):
    """Tests for scan_discovered_urls_enhanced function."""
    
    @patch('discover.sensitive_scanner_enhanced.requests.get')
    def test_scan_discovered_urls_enhanced_success(self, mock_get):
        """Test enhanced URL scanning function."""
        mock_response = Mock()
        mock_response.text = "API Key: AKIAIOSFODNN7EXAMPLE"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        urls = ['http://example1.com', 'http://example2.com']
        result = scan_discovered_urls_enhanced(urls, max_urls=10, enable_heuristics=False)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['total_urls_scanned'], 2)
        self.assertTrue(result['total_findings'] > 0)
        self.assertIn('findings_by_severity', result)
    
    @patch('discover.sensitive_scanner_enhanced.requests.get')
    def test_scan_discovered_urls_enhanced_max_limit(self, mock_get):
        """Test max URL limit in enhanced scanning."""
        mock_response = Mock()
        mock_response.text = "test content"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        urls = [f'http://example{i}.com' for i in range(100)]
        result = scan_discovered_urls_enhanced(urls, max_urls=5)
        
        # Should only scan 5 URLs
        self.assertTrue(result['total_urls_scanned'] <= 5)


if __name__ == '__main__':
    unittest.main()
