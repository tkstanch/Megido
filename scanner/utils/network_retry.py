"""
Network Retry Utility with Exponential Backoff and Jitter

Provides robust retry logic for HTTP requests with:
- Exponential backoff with jitter
- Configurable retry behavior
- Error classification
- Detailed logging
"""

import time
import random
import logging
from typing import Optional, Callable, Any, Dict, Tuple
from functools import wraps
import requests
from requests.exceptions import (
    Timeout, ConnectionError, HTTPError, RequestException, 
    SSLError, ProxyError, ChunkedEncodingError, ContentDecodingError,
    TooManyRedirects
)
from ..config.network_config import NetworkConfig

logger = logging.getLogger(__name__)


class NetworkRetryClient:
    """
    HTTP client with built-in retry logic and exponential backoff.
    
    Features:
    - Exponential backoff with jitter to prevent thundering herd
    - Configurable retry behavior per error type
    - Automatic session management
    - Detailed error logging with sensitive data redaction
    
    Example:
        client = NetworkRetryClient(config=NetworkConfig())
        response = client.get('https://api.example.com/data')
    """
    
    def __init__(self, config: Optional[NetworkConfig] = None):
        """
        Initialize the retry client.
        
        Args:
            config: Network configuration object. If None, uses default config.
        """
        self.config = config or NetworkConfig()
        self.session = requests.Session()
        
        # Set default timeout if not specified in requests
        self.session.request = self._wrap_request(self.session.request)
        
    def _wrap_request(self, original_request: Callable) -> Callable:
        """Wrap the session request to add default timeout."""
        @wraps(original_request)
        def wrapper(*args, **kwargs):
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.config.default_timeout
            return original_request(*args, **kwargs)
        return wrapper
    
    def _calculate_backoff(self, attempt: int) -> float:
        """
        Calculate backoff time with exponential backoff and jitter.
        
        Formula: min(base_delay * (2 ^ attempt) + jitter, max_delay)
        
        Args:
            attempt: Current attempt number (0-indexed)
            
        Returns:
            Delay in seconds
        """
        exponential_delay = self.config.base_delay * (2 ** attempt)
        
        # Add jitter (random value between 0 and jitter_max)
        jitter = random.uniform(0, self.config.jitter_max)
        
        total_delay = exponential_delay + jitter
        
        # Cap at max_delay
        return min(total_delay, self.config.max_delay)
    
    def _is_retryable_error(self, error: Exception) -> bool:
        """
        Determine if an error is retryable.
        
        Args:
            error: Exception that occurred
            
        Returns:
            True if the error should be retried
        """
        # Connection errors are retryable (network issues, DNS failures, etc.)
        if isinstance(error, (ConnectionError, Timeout)):
            return True
        
        # Some HTTP errors are retryable (5xx server errors, 429 rate limit)
        if isinstance(error, HTTPError):
            if error.response is not None:
                status_code = error.response.status_code
                return status_code in self.config.retryable_status_codes
        
        # Proxy errors might be retryable
        if isinstance(error, ProxyError):
            return True
        
        # Encoding/chunking errors might be transient
        if isinstance(error, (ChunkedEncodingError, ContentDecodingError)):
            return True
        
        # SSL errors, redirect loops, and other issues are not retryable
        if isinstance(error, (SSLError, TooManyRedirects)):
            return False
        
        # Other RequestException types - don't retry by default
        return False
    
    def _classify_error(self, error: Exception) -> Tuple[str, str]:
        """
        Classify error type and category.
        
        Args:
            error: Exception that occurred
            
        Returns:
            Tuple of (error_type, category) where category is 'recoverable' or 'fatal'
        """
        if isinstance(error, Timeout):
            return ('timeout', 'recoverable')
        elif isinstance(error, ConnectionError):
            # Check if it's DNS resolution failure
            error_str = str(error).lower()
            if 'name resolution' in error_str or 'nodename nor servname' in error_str:
                return ('dns_failure', 'recoverable')
            elif 'connection reset' in error_str or 'connection refused' in error_str:
                return ('connection_reset', 'recoverable')
            else:
                return ('connection_error', 'recoverable')
        elif isinstance(error, SSLError):
            return ('ssl_error', 'fatal')
        elif isinstance(error, ProxyError):
            return ('proxy_error', 'recoverable')
        elif isinstance(error, HTTPError):
            status_code = error.response.status_code if error.response else 0
            if status_code >= 500:
                return (f'server_error_{status_code}', 'recoverable')
            elif status_code == 429:
                return ('rate_limit', 'recoverable')
            else:
                return (f'client_error_{status_code}', 'fatal')
        elif isinstance(error, (ChunkedEncodingError, ContentDecodingError)):
            return ('encoding_error', 'recoverable')
        elif isinstance(error, TooManyRedirects):
            return ('redirect_loop', 'fatal')
        else:
            return ('unknown_error', 'fatal')
    
    def _make_request_with_retry(
        self, 
        method: str, 
        url: str, 
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Make HTTP request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object or None if all retries failed
        """
        from .network_logger import NetworkLogger
        net_logger = NetworkLogger()
        
        max_retries = kwargs.pop('max_retries', self.config.max_retries)
        
        for attempt in range(max_retries + 1):
            try:
                # Make the request
                response = self.session.request(method, url, **kwargs)
                
                # Check if response indicates retryable error
                if response.status_code in self.config.retryable_status_codes:
                    if attempt < max_retries:
                        backoff = self._calculate_backoff(attempt)
                        net_logger.log_retry(
                            url=url,
                            method=method,
                            attempt=attempt + 1,
                            max_attempts=max_retries + 1,
                            error_type=f'http_{response.status_code}',
                            backoff_delay=backoff
                        )
                        time.sleep(backoff)
                        continue
                    else:
                        net_logger.log_final_failure(
                            url=url,
                            method=method,
                            error_type=f'http_{response.status_code}',
                            attempts=max_retries + 1
                        )
                        return response  # Return response even if status code is bad
                
                # Success!
                net_logger.log_success(
                    url=url,
                    method=method,
                    status_code=response.status_code,
                    attempt=attempt + 1
                )
                return response
                
            except Exception as error:
                error_type, category = self._classify_error(error)
                
                # Check if error is retryable
                if not self._is_retryable_error(error):
                    net_logger.log_fatal_error(
                        url=url,
                        method=method,
                        error_type=error_type,
                        error_message=str(error)
                    )
                    return None
                
                # If we have retries left, wait and retry
                if attempt < max_retries:
                    backoff = self._calculate_backoff(attempt)
                    net_logger.log_retry(
                        url=url,
                        method=method,
                        attempt=attempt + 1,
                        max_attempts=max_retries + 1,
                        error_type=error_type,
                        backoff_delay=backoff
                    )
                    time.sleep(backoff)
                else:
                    # All retries exhausted
                    net_logger.log_final_failure(
                        url=url,
                        method=method,
                        error_type=error_type,
                        attempts=max_retries + 1
                    )
                    return None
        
        return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make GET request with retry logic."""
        return self._make_request_with_retry('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make POST request with retry logic."""
        return self._make_request_with_retry('POST', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make PUT request with retry logic."""
        return self._make_request_with_retry('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make DELETE request with retry logic."""
        return self._make_request_with_retry('DELETE', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make OPTIONS request with retry logic."""
        return self._make_request_with_retry('OPTIONS', url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HEAD request with retry logic."""
        return self._make_request_with_retry('HEAD', url, **kwargs)
    
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make request with any HTTP method with retry logic."""
        return self._make_request_with_retry(method, url, **kwargs)


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter_max: float = 1.0,
    retryable_exceptions: Tuple = (ConnectionError, Timeout)
):
    """
    Decorator for adding retry logic with exponential backoff to any function.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds for backoff calculation
        max_delay: Maximum delay in seconds
        jitter_max: Maximum jitter to add (in seconds)
        retryable_exceptions: Tuple of exception types that should trigger retry
        
    Example:
        @retry_with_backoff(max_retries=3, base_delay=1.0)
        def fetch_data(url):
            return requests.get(url)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as error:
                    if attempt < max_retries:
                        # Calculate backoff with jitter
                        exponential_delay = base_delay * (2 ** attempt)
                        jitter = random.uniform(0, jitter_max)
                        delay = min(exponential_delay + jitter, max_delay)
                        
                        logger.warning(
                            f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}), "
                            f"retrying in {delay:.2f}s: {error}"
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_retries + 1} attempts: {error}"
                        )
                        raise
            return None
        return wrapper
    return decorator
