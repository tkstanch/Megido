"""
Unit tests for network utilities (retry, error classification, logging)
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import time
from requests.exceptions import (
    Timeout, ConnectionError, HTTPError, SSLError, ProxyError,
    ChunkedEncodingError, TooManyRedirects
)
from scanner.utils.network_retry import NetworkRetryClient, retry_with_backoff
from scanner.utils.error_classifier import ErrorClassifier, ErrorCategory
from scanner.utils.network_logger import NetworkLogger
from scanner.config.network_config import NetworkConfig


class TestNetworkRetryClient(unittest.TestCase):
    """Test NetworkRetryClient functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = NetworkConfig(
            max_retries=2,
            base_delay=0.1,  # Short delays for testing
            max_delay=1.0,
            jitter_max=0.05
        )
        self.client = NetworkRetryClient(config=self.config)
    
    def test_successful_request(self):
        """Test successful request without retries."""
        mock_response = Mock()
        mock_response.status_code = 200
        
        with patch.object(self.client.session, 'request', return_value=mock_response) as mock_request:
            response = self.client.get('https://example.com')
            
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(mock_request.call_count, 1)
    
    @patch('scanner.utils.network_retry.time.sleep')
    def test_retry_on_timeout(self, mock_sleep):
        """Test retry logic on timeout errors."""
        # First two calls raise Timeout, third succeeds
        mock_response = Mock()
        mock_response.status_code = 200
        
        with patch.object(self.client.session, 'request', side_effect=[
            Timeout('Read timeout'),
            Timeout('Read timeout'),
            mock_response
        ]) as mock_request:
            response = self.client.get('https://example.com')
            
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(mock_request.call_count, 3)
            self.assertEqual(mock_sleep.call_count, 2)  # Slept before retry 2 and 3
    
    @patch('scanner.utils.network_retry.time.sleep')
    def test_retry_exhausted(self, mock_sleep):
        """Test behavior when all retries are exhausted."""
        with patch.object(self.client.session, 'request', side_effect=Timeout('Read timeout')) as mock_request:
            response = self.client.get('https://example.com')
            
            self.assertIsNone(response)
            # max_retries=2 means 3 total attempts (initial + 2 retries)
            self.assertEqual(mock_request.call_count, 3)
            self.assertEqual(mock_sleep.call_count, 2)
    
    def test_ssl_error_no_retry(self):
        """Test that SSL errors are not retried."""
        with patch.object(self.client.session, 'request', side_effect=SSLError('Certificate verify failed')) as mock_request:
            response = self.client.get('https://example.com')
            
            self.assertIsNone(response)
            self.assertEqual(mock_request.call_count, 1)  # No retries
    
    @patch('scanner.utils.network_retry.time.sleep')
    def test_connection_error_retry(self, mock_sleep):
        """Test retry on connection errors."""
        mock_response = Mock()
        mock_response.status_code = 200
        
        with patch.object(self.client.session, 'request', side_effect=[
            ConnectionError('Connection refused'),
            mock_response
        ]) as mock_request:
            response = self.client.get('https://example.com')
            
            self.assertIsNotNone(response)
            self.assertEqual(mock_request.call_count, 2)
            self.assertEqual(mock_sleep.call_count, 1)
    
    def test_exponential_backoff_calculation(self):
        """Test exponential backoff calculation."""
        backoff_0 = self.client._calculate_backoff(0)
        backoff_1 = self.client._calculate_backoff(1)
        backoff_2 = self.client._calculate_backoff(2)
        
        # Backoff should increase exponentially
        # attempt 0: 0.1 * 2^0 = 0.1 (+ jitter)
        # attempt 1: 0.1 * 2^1 = 0.2 (+ jitter)
        # attempt 2: 0.1 * 2^2 = 0.4 (+ jitter)
        self.assertGreater(backoff_1, backoff_0)
        self.assertGreater(backoff_2, backoff_1)
        
        # Should not exceed max_delay
        self.assertLessEqual(backoff_2, self.config.max_delay)
    
    @patch('scanner.utils.network_retry.time.sleep')
    def test_retryable_status_codes(self, mock_sleep):
        """Test retry on specific HTTP status codes."""
        mock_response_503 = Mock()
        mock_response_503.status_code = 503
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        
        with patch.object(self.client.session, 'request', side_effect=[mock_response_503, mock_response_200]) as mock_request:
            response = self.client.get('https://example.com')
            
            self.assertIsNotNone(response)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(mock_request.call_count, 2)


class TestErrorClassifier(unittest.TestCase):
    """Test ErrorClassifier functionality."""
    
    def test_classify_timeout(self):
        """Test classification of timeout errors."""
        error = Timeout('Read timeout')
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['category'], ErrorCategory.RECOVERABLE)
        self.assertEqual(result['type'], 'timeout')
        self.assertTrue(result['retryable'])
        self.assertIn('timed out', result['user_message'].lower())
    
    def test_classify_dns_failure(self):
        """Test classification of DNS resolution failures."""
        error = ConnectionError('[Errno -2] Name or service not known: nodename nor servname')
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['type'], 'dns_failure')
        self.assertTrue(result['retryable'])
        self.assertIn('dns', result['user_message'].lower())
    
    def test_classify_connection_refused(self):
        """Test classification of connection refused errors."""
        error = ConnectionError('Connection refused')
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['type'], 'connection_refused')
        self.assertTrue(result['retryable'])
    
    def test_classify_connection_reset(self):
        """Test classification of connection reset errors."""
        error = ConnectionError('Connection reset by peer')
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['type'], 'connection_reset')
        self.assertTrue(result['retryable'])
    
    def test_classify_ssl_error(self):
        """Test classification of SSL errors."""
        error = SSLError('Certificate verify failed')
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['type'], 'ssl_error')
        self.assertFalse(result['retryable'])  # SSL errors are fatal but still classified
    
    def test_classify_http_500(self):
        """Test classification of 500 server errors."""
        mock_response = Mock()
        mock_response.status_code = 500
        error = HTTPError(response=mock_response)
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['category'], ErrorCategory.RECOVERABLE)
        self.assertEqual(result['type'], 'server_error_500')
        self.assertTrue(result['retryable'])
    
    def test_classify_http_429(self):
        """Test classification of rate limit errors."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {'Retry-After': '60'}
        error = HTTPError(response=mock_response)
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['type'], 'rate_limit')
        self.assertTrue(result['retryable'])
    
    def test_classify_http_404(self):
        """Test classification of 404 client errors."""
        mock_response = Mock()
        mock_response.status_code = 404
        error = HTTPError(response=mock_response)
        result = ErrorClassifier.classify(error)
        
        self.assertEqual(result['category'], ErrorCategory.FATAL)
        self.assertFalse(result['retryable'])
    
    def test_is_retryable(self):
        """Test is_retryable helper method."""
        self.assertTrue(ErrorClassifier.is_retryable(Timeout('timeout')))
        self.assertTrue(ErrorClassifier.is_retryable(ConnectionError('reset')))
        # Note: Our implementation considers SSL retryable in network_retry.py for the actual retry decision
        # but ErrorClassifier considers it non-retryable. This is intentional.


class TestNetworkLogger(unittest.TestCase):
    """Test NetworkLogger functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.logger = NetworkLogger()
    
    def test_redact_url_with_credentials(self):
        """Test URL redaction with credentials."""
        url = 'https://user:password@example.com/api'
        redacted = NetworkLogger._redact_url(url)
        
        self.assertNotIn('password', redacted)
        self.assertIn('***', redacted)
    
    def test_redact_url_with_sensitive_params(self):
        """Test URL redaction with sensitive query parameters."""
        url = 'https://example.com/api?token=secret123&user=john'
        redacted = NetworkLogger._redact_url(url)
        
        self.assertNotIn('secret123', redacted)
        self.assertIn('token=***', redacted)
        self.assertIn('user=john', redacted)  # Non-sensitive param preserved
    
    def test_redact_headers(self):
        """Test header redaction."""
        headers = {
            'Authorization': 'Bearer secret_token_12345678',
            'Content-Type': 'application/json',
            'Cookie': 'session_id=abc123def456',
            'User-Agent': 'Megido Scanner'
        }
        
        redacted = NetworkLogger._redact_headers(headers)
        
        self.assertIn('***', redacted['Authorization'])
        self.assertNotIn('secret_token', redacted['Authorization'])
        self.assertEqual(redacted['Content-Type'], 'application/json')
        self.assertIn('***', redacted['Cookie'])
        self.assertEqual(redacted['User-Agent'], 'Megido Scanner')
    
    @patch('logging.Logger.warning')
    def test_log_retry(self, mock_logger_warning):
        """Test retry logging."""
        self.logger.log_retry(
            url='https://example.com/api',
            method='GET',
            attempt=2,
            max_attempts=3,
            error_type='timeout',
            backoff_delay=2.5
        )
        
        mock_logger_warning.assert_called_once()
        call_args = mock_logger_warning.call_args[0][0]
        self.assertIn('Retry', call_args)
        self.assertIn('2/3', call_args)
    
    @patch('logging.Logger.info')
    def test_log_success(self, mock_logger_info):
        """Test success logging."""
        self.logger.log_success(
            url='https://example.com/api',
            method='GET',
            status_code=200,
            attempt=1
        )
        
        mock_logger_info.assert_called_once()
        call_args = mock_logger_info.call_args[0][0]
        self.assertIn('Success', call_args)
        self.assertIn('200', call_args)


class TestRetryDecorator(unittest.TestCase):
    """Test retry_with_backoff decorator."""
    
    @patch('scanner.utils.network_retry.time.sleep')
    def test_decorator_success(self, mock_sleep):
        """Test decorator on successful function."""
        @retry_with_backoff(max_retries=2, base_delay=0.1)
        def successful_function():
            return 'success'
        
        result = successful_function()
        
        self.assertEqual(result, 'success')
        mock_sleep.assert_not_called()
    
    @patch('scanner.utils.network_retry.time.sleep')
    def test_decorator_retry(self, mock_sleep):
        """Test decorator with retries."""
        call_count = [0]
        
        @retry_with_backoff(max_retries=2, base_delay=0.1)
        def flaky_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ConnectionError('Connection failed')
            return 'success'
        
        result = flaky_function()
        
        self.assertEqual(result, 'success')
        self.assertEqual(call_count[0], 3)
        self.assertEqual(mock_sleep.call_count, 2)
    
    @patch('scanner.utils.network_retry.time.sleep')
    def test_decorator_max_retries(self, mock_sleep):
        """Test decorator when max retries exceeded."""
        @retry_with_backoff(max_retries=2, base_delay=0.1)
        def always_failing():
            raise ConnectionError('Connection failed')
        
        with self.assertRaises(ConnectionError):
            always_failing()
        
        self.assertEqual(mock_sleep.call_count, 2)


class TestNetworkConfig(unittest.TestCase):
    """Test NetworkConfig functionality."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = NetworkConfig()
        
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.base_delay, 1.0)
        self.assertEqual(config.default_timeout, 30)
        self.assertTrue(config.enable_degraded_mode)
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = NetworkConfig(
            max_retries=5,
            base_delay=2.0,
            default_timeout=60
        )
        
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.base_delay, 2.0)
        self.assertEqual(config.default_timeout, 60)
    
    def test_to_dict(self):
        """Test configuration to dictionary conversion."""
        config = NetworkConfig(max_retries=5)
        config_dict = config.to_dict()
        
        self.assertIsInstance(config_dict, dict)
        self.assertEqual(config_dict['max_retries'], 5)
        self.assertIn('base_delay', config_dict)
    
    def test_from_dict(self):
        """Test configuration from dictionary."""
        config_dict = {'max_retries': 5, 'base_delay': 2.0}
        config = NetworkConfig.from_dict(config_dict)
        
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.base_delay, 2.0)
    
    def test_get_service_timeout(self):
        """Test service-specific timeout retrieval."""
        config = NetworkConfig()
        
        fireblocks_timeout = config.get_service_timeout('fireblocks_api')
        unknown_timeout = config.get_service_timeout('unknown_service')
        
        self.assertEqual(fireblocks_timeout, 30)
        self.assertEqual(unknown_timeout, config.default_timeout)
    
    @patch.dict('os.environ', {
        'MEGIDO_MAX_RETRIES': '5',
        'MEGIDO_BASE_DELAY': '2.0',
        'MEGIDO_DEFAULT_TIMEOUT': '60'
    })
    def test_from_env(self):
        """Test configuration from environment variables."""
        config = NetworkConfig.from_env()
        
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.base_delay, 2.0)
        self.assertEqual(config.default_timeout, 60)


if __name__ == '__main__':
    unittest.main()
