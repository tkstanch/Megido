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
        self.assertEqual(result['error'], 'API quota exceeded')
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