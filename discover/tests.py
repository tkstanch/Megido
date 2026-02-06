"""
Tests for the Discover app's Google Dorks search functionality.
"""
from django.test import TestCase, override_settings
from unittest.mock import patch, MagicMock
from discover.google_search import is_api_configured, search_google, search_dorks
from discover.utils import search_google_dorks
from discover.models import Scan


class GoogleSearchConfigurationTests(TestCase):
    """Tests for Google Search API configuration checks."""
    
    @override_settings(GOOGLE_SEARCH_API_KEY=None, GOOGLE_SEARCH_ENGINE_ID=None)
    def test_is_api_configured_returns_false_when_not_configured(self):
        """Test that is_api_configured returns False when API keys are not set."""
        self.assertFalse(is_api_configured())
    
    @override_settings(GOOGLE_SEARCH_API_KEY='test-key', GOOGLE_SEARCH_ENGINE_ID=None)
    def test_is_api_configured_returns_false_when_only_api_key_set(self):
        """Test that is_api_configured returns False when only API key is set."""
        self.assertFalse(is_api_configured())
    
    @override_settings(GOOGLE_SEARCH_API_KEY=None, GOOGLE_SEARCH_ENGINE_ID='test-cx')
    def test_is_api_configured_returns_false_when_only_engine_id_set(self):
        """Test that is_api_configured returns False when only engine ID is set."""
        self.assertFalse(is_api_configured())
    
    @override_settings(GOOGLE_SEARCH_API_KEY='test-key', GOOGLE_SEARCH_ENGINE_ID='test-cx')
    def test_is_api_configured_returns_true_when_both_configured(self):
        """Test that is_api_configured returns True when both keys are set."""
        self.assertTrue(is_api_configured())


class GoogleSearchAPITests(TestCase):
    """Tests for Google Custom Search API integration."""
    
    @override_settings(GOOGLE_SEARCH_API_KEY=None, GOOGLE_SEARCH_ENGINE_ID=None)
    def test_search_google_returns_error_when_not_configured(self):
        """Test that search_google returns error when API is not configured."""
        result = search_google('test query')
        
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'API not configured')
        self.assertEqual(result['result_count'], 0)
        self.assertEqual(len(result['results']), 0)
    
    @override_settings(GOOGLE_SEARCH_API_KEY='test-key', GOOGLE_SEARCH_ENGINE_ID='test-cx')
    @patch('discover.google_search.requests.get')
    def test_search_google_successful_with_results(self, mock_get):
        """Test successful search with results."""
        # Mock API response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'items': [
                {
                    'title': 'Test Result 1',
                    'link': 'https://example.com/1',
                    'snippet': 'This is a test result'
                },
                {
                    'title': 'Test Result 2',
                    'link': 'https://example.com/2',
                    'snippet': 'Another test result'
                }
            ]
        }
        mock_get.return_value = mock_response
        
        result = search_google('test query', num_results=5)
        
        self.assertTrue(result['success'])
        self.assertIsNone(result['error'])
        self.assertEqual(result['result_count'], 2)
        self.assertEqual(len(result['results']), 2)
        self.assertEqual(result['results'][0]['title'], 'Test Result 1')
        self.assertEqual(result['results'][0]['url'], 'https://example.com/1')
    
    @override_settings(GOOGLE_SEARCH_API_KEY='test-key', GOOGLE_SEARCH_ENGINE_ID='test-cx')
    @patch('discover.google_search.requests.get')
    def test_search_google_handles_no_results(self, mock_get):
        """Test handling of searches with no results."""
        # Mock API response with no items
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response
        
        result = search_google('test query')
        
        self.assertTrue(result['success'])
        self.assertIsNone(result['error'])
        self.assertEqual(result['result_count'], 0)
        self.assertEqual(len(result['results']), 0)
    
    @override_settings(GOOGLE_SEARCH_API_KEY='test-key', GOOGLE_SEARCH_ENGINE_ID='test-cx')
    @patch('discover.google_search.requests.get')
    def test_search_google_handles_quota_exceeded(self, mock_get):
        """Test handling of API quota exceeded error."""
        # Mock 429 response
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response
        mock_get.return_value.raise_for_status.side_effect = \
            __import__('requests').exceptions.HTTPError(response=mock_response)
        
        result = search_google('test query')
        
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'API daily quota exceeded. Try again tomorrow or upgrade your Google API quota.')
        self.assertEqual(result['result_count'], 0)


class SearchDorksTests(TestCase):
    """Tests for search_dorks function."""
    
    @override_settings(GOOGLE_SEARCH_API_KEY=None, GOOGLE_SEARCH_ENGINE_ID=None)
    def test_search_dorks_returns_early_when_not_configured(self):
        """Test that search_dorks returns early when API is not configured."""
        dork_queries = {
            'test_category': {
                'name': 'Test Category',
                'description': 'Test description',
                'dorks': [
                    {'query': 'test query', 'description': 'test'}
                ]
            }
        }
        
        result = search_dorks(dork_queries)
        
        self.assertTrue(result['search_enabled'])
        self.assertFalse(result['api_configured'])
        self.assertEqual(len(result['categories']), 0)
    
    @override_settings(GOOGLE_SEARCH_API_KEY='test-key', GOOGLE_SEARCH_ENGINE_ID='test-cx')
    @patch('discover.google_search.search_google')
    def test_search_dorks_processes_queries(self, mock_search):
        """Test that search_dorks processes queries correctly."""
        mock_search.return_value = {
            'success': True,
            'results': [{'title': 'Test', 'url': 'https://test.com', 'snippet': 'test'}],
            'result_count': 1,
            'error': None
        }
        
        dork_queries = {
            'test_category': {
                'name': 'Test Category',
                'description': 'Test description',
                'dorks': [
                    {'query': 'test query', 'description': 'test dork'}
                ]
            }
        }
        
        result = search_dorks(dork_queries, max_dorks=1, results_per_dork=5, delay=0)
        
        self.assertTrue(result['search_enabled'])
        self.assertTrue(result['api_configured'])
        self.assertIn('test_category', result['categories'])
        self.assertEqual(len(result['categories']['test_category']['dorks']), 1)
        self.assertEqual(result['categories']['test_category']['dorks'][0]['query'], 'test query')
        self.assertEqual(result['categories']['test_category']['dorks'][0]['result_count'], 1)


class SearchGoogleDorksUtilityTests(TestCase):
    """Tests for search_google_dorks utility function."""
    
    @override_settings(GOOGLE_SEARCH_API_KEY=None, GOOGLE_SEARCH_ENGINE_ID=None)
    def test_search_google_dorks_returns_disabled_when_not_configured(self):
        """Test that search_google_dorks indicates search disabled when not configured."""
        dork_queries = {}
        result = search_google_dorks('example.com', dork_queries)
        
        self.assertFalse(result['search_enabled'])
        self.assertFalse(result['api_configured'])
    
    @override_settings(GOOGLE_SEARCH_API_KEY='test-key', GOOGLE_SEARCH_ENGINE_ID='test-cx')
    @patch('discover.google_search.search_dorks')
    def test_search_google_dorks_calls_search_dorks(self, mock_search_dorks):
        """Test that search_google_dorks calls search_dorks when configured."""
        mock_search_dorks.return_value = {
            'search_enabled': True,
            'api_configured': True,
            'categories': {}
        }
        
        dork_queries = {'test': {'dorks': []}}
        result = search_google_dorks('example.com', dork_queries)
        
        mock_search_dorks.assert_called_once()
        self.assertTrue(result['search_enabled'])
        self.assertTrue(result['api_configured'])


class ScanModelTests(TestCase):
    """Tests for Scan model with dork_results field."""
    
    def test_scan_model_has_dork_results_field(self):
        """Test that Scan model has dork_results field."""
        scan = Scan(target='example.com')
        self.assertTrue(hasattr(scan, 'dork_results'))
    
    def test_scan_model_dork_results_defaults_to_empty(self):
        """Test that dork_results defaults to empty string."""
        scan = Scan(target='example.com')
        scan.save()
        self.assertEqual(scan.dork_results, '')


class WaybackMachineConfigurationTests(TestCase):
    """Tests for Wayback Machine configuration."""
    
    @override_settings(ENABLE_WAYBACK_MACHINE=False)
    def test_collect_wayback_urls_returns_error_when_disabled(self):
        """Test that collect_wayback_urls returns error when disabled."""
        from discover.utils import collect_wayback_urls
        
        result = collect_wayback_urls('example.com')
        
        self.assertFalse(result['success'])
        self.assertIn('disabled', result['error'].lower())
        self.assertEqual(len(result['urls']), 0)
    
    @override_settings(ENABLE_WAYBACK_MACHINE=True, WAYBACK_MACHINE_TIMEOUT=10, WAYBACK_MACHINE_MAX_RETRIES=2)
    @patch('discover.utils.requests.get')
    def test_collect_wayback_urls_handles_connection_error(self, mock_get):
        """Test that collect_wayback_urls handles connection errors gracefully."""
        from discover.utils import collect_wayback_urls
        
        # Mock waybackpy to raise ImportError, so it falls back to CDX API
        with patch.dict('sys.modules', {'waybackpy': None}):
            # Mock connection error
            mock_get.side_effect = __import__('requests').exceptions.ConnectionError("Connection failed")
            
            result = collect_wayback_urls('example.com')
            
            self.assertFalse(result['success'])
            self.assertIn('Unable to connect', result['error'])
            self.assertEqual(len(result['urls']), 0)
    
    @override_settings(ENABLE_WAYBACK_MACHINE=True, WAYBACK_MACHINE_TIMEOUT=5, WAYBACK_MACHINE_MAX_RETRIES=2)
    @patch('discover.utils.requests.get')
    def test_collect_wayback_urls_handles_timeout_error(self, mock_get):
        """Test that collect_wayback_urls handles timeout errors gracefully."""
        from discover.utils import collect_wayback_urls
        
        # Mock waybackpy to raise ImportError, so it falls back to CDX API
        with patch.dict('sys.modules', {'waybackpy': None}):
            # Mock timeout error
            mock_get.side_effect = __import__('requests').exceptions.Timeout("Request timed out")
            
            result = collect_wayback_urls('example.com')
            
            self.assertFalse(result['success'])
            self.assertIn('timed out', result['error'])
            self.assertIn('5 seconds', result['error'])
            self.assertEqual(len(result['urls']), 0)
    
    @override_settings(ENABLE_WAYBACK_MACHINE=True, WAYBACK_MACHINE_TIMEOUT=10, WAYBACK_MACHINE_MAX_RETRIES=2)
    @patch('discover.utils.requests.get')
    def test_collect_wayback_urls_successful_with_cdx_api(self, mock_get):
        """Test successful Wayback Machine request using CDX API fallback."""
        from discover.utils import collect_wayback_urls
        
        # Mock waybackpy to raise ImportError, so it falls back to CDX API
        with patch.dict('sys.modules', {'waybackpy': None}):
            # Mock successful CDX API response
            # CDX API format: [urlkey, timestamp, original, mimetype, statuscode, digest, length]
            mock_response = MagicMock()
            mock_response.json.return_value = [
                ['urlkey', 'timestamp', 'original', 'mimetype', 'statuscode', 'digest', 'length'],
                ['com,example)/', '20200101000000', 'http://example.com/page1', 'text/html', '200', 'ABC123', '1000'],
                ['com,example)/', '20200201000000', 'http://example.com/page2', 'text/html', '200', 'DEF456', '2000'],
            ]
            mock_get.return_value = mock_response
            
            result = collect_wayback_urls('example.com', limit=10)
            
            self.assertTrue(result['success'])
            self.assertEqual(len(result['urls']), 2)
            self.assertIn('http://web.archive.org/web/', result['urls'][0]['url'])
            self.assertEqual(result['urls'][0]['timestamp'], '20200101000000')


class SensitiveInfoScannerTests(TestCase):
    """Tests for sensitive information scanner with credit card validation."""
    
    def test_luhn_check_valid_visa_card(self):
        """Test Luhn check with valid Visa test card number."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        # Valid Visa test card: 4532015112830366
        self.assertTrue(SensitiveInfoScanner.luhn_check('4532015112830366'))
    
    def test_luhn_check_valid_mastercard(self):
        """Test Luhn check with valid MasterCard test card number."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        # Valid MasterCard test card: 5425233430109903
        self.assertTrue(SensitiveInfoScanner.luhn_check('5425233430109903'))
    
    def test_luhn_check_invalid_card(self):
        """Test Luhn check with invalid card number (false positive from issue)."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        # Invalid card number from issue: 4114481056395
        self.assertFalse(SensitiveInfoScanner.luhn_check('4114481056395'))
    
    def test_luhn_check_empty_string(self):
        """Test Luhn check with empty string."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        self.assertFalse(SensitiveInfoScanner.luhn_check(''))
    
    def test_verify_context_not_numeric_field_with_usd(self):
        """Test context verification rejects USD price fields."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        context = 'tionRollingStats","sales":30,"volume":{"usd":6743.4114481056395,"native":{"symbol":"ETH","unit":3.566585019,"__ty'
        value = '4114481056395'
        
        # Should return False (indicating it's a false positive)
        self.assertFalse(SensitiveInfoScanner.verify_context_not_numeric_field(context, value))
    
    def test_verify_context_not_numeric_field_with_price(self):
        """Test context verification rejects price fields."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        context = 'The total price is 4532015112830366 for this item'
        value = '4532015112830366'
        
        # Should return False (indicating it's a false positive)
        self.assertFalse(SensitiveInfoScanner.verify_context_not_numeric_field(context, value))
    
    def test_verify_context_not_numeric_field_with_volume(self):
        """Test context verification rejects volume fields."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        context = '{"volume":4532015112830366,"sales":100}'
        value = '4532015112830366'
        
        # Should return False (indicating it's a false positive)
        self.assertFalse(SensitiveInfoScanner.verify_context_not_numeric_field(context, value))
    
    def test_verify_context_not_numeric_field_clean_context(self):
        """Test context verification accepts clean context."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        context = 'Card number: 4532015112830366 for payment'
        value = '4532015112830366'
        
        # Should return True (indicating it's NOT a false positive)
        # But wait, "payment" is in the false_positive_indicators!
        # Let me check the context more carefully...
        # Actually, for a real credit card in proper context, we want to avoid "payment" too
        # Let me use a cleaner example
        context = 'Credit card verification: 4532015112830366 entered'
        
        # Should return True (safe context)
        self.assertTrue(SensitiveInfoScanner.verify_context_not_numeric_field(context, value))
    
    def test_scan_content_filters_invalid_credit_cards(self):
        """Test that scanning filters out invalid credit card numbers."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        scanner = SensitiveInfoScanner()
        
        # Content with invalid credit card (from the issue)
        content = 'tionRollingStats","sales":30,"volume":{"usd":6743.4114481056395,"native":{"symbol":"ETH","unit":3.566585019,"__ty'
        
        findings = scanner.scan_content_for_sensitive_data(content, 'http://example.com')
        
        # Should not find any credit card (filtered by Luhn check)
        credit_card_findings = [f for f in findings if f['type'] == 'Credit Card Number']
        self.assertEqual(len(credit_card_findings), 0)
    
    def test_scan_content_filters_price_context(self):
        """Test that scanning filters out credit cards in price context."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        scanner = SensitiveInfoScanner()
        
        # Content with valid credit card but in price/USD context
        # Using a valid test card: 4532015112830366
        content = '{"price": 4532015112830366, "currency": "USD"}'
        
        findings = scanner.scan_content_for_sensitive_data(content, 'http://example.com')
        
        # Should not find any credit card (filtered by context check)
        credit_card_findings = [f for f in findings if f['type'] == 'Credit Card Number']
        self.assertEqual(len(credit_card_findings), 0)
    
    def test_scan_content_accepts_valid_credit_card_in_safe_context(self):
        """Test that scanning accepts valid credit cards in safe context."""
        from discover.sensitive_scanner import SensitiveInfoScanner
        
        scanner = SensitiveInfoScanner()
        
        # Content with valid credit card in safe context
        content = 'Customer card: 4532015112830366 was entered for verification.'
        
        findings = scanner.scan_content_for_sensitive_data(content, 'http://example.com')
        
        # Should find the credit card
        credit_card_findings = [f for f in findings if f['type'] == 'Credit Card Number']
        self.assertEqual(len(credit_card_findings), 1)
        self.assertEqual(credit_card_findings[0]['value'], '4532015112830366')
            self.assertEqual(result['urls'][0]['original'], 'http://example.com/page1')