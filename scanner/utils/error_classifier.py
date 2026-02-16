"""
Error Classification Utility

Classifies network and HTTP errors into categories for better handling
and reporting.
"""

from enum import Enum
from typing import Optional, Dict, Any
import requests
from requests.exceptions import (
    Timeout, ConnectionError, HTTPError, RequestException,
    SSLError, ProxyError, ChunkedEncodingError, ContentDecodingError,
    TooManyRedirects
)


class ErrorCategory(Enum):
    """Error category classification."""
    RECOVERABLE = "recoverable"  # Can be retried
    FATAL = "fatal"              # Should not be retried
    DEGRADED = "degraded"        # Service available but degraded


class ErrorClassifier:
    """
    Utility class for classifying network and HTTP errors.
    
    Provides detailed error categorization to help determine:
    - Whether an error should be retried
    - How to present the error to users
    - What remediation steps to suggest
    """
    
    @staticmethod
    def classify(error: Exception) -> Dict[str, Any]:
        """
        Classify an error and return detailed information.
        
        Args:
            error: Exception to classify
            
        Returns:
            Dictionary with error details:
            {
                'category': ErrorCategory enum value,
                'type': str (specific error type),
                'retryable': bool,
                'user_message': str (user-friendly message),
                'technical_details': str (for logging),
                'remediation': str (suggested fix)
            }
        """
        # Timeout errors
        if isinstance(error, Timeout):
            return {
                'category': ErrorCategory.RECOVERABLE,
                'type': 'timeout',
                'retryable': True,
                'user_message': 'Request timed out. The server may be slow or unresponsive.',
                'technical_details': f'Timeout error: {str(error)}',
                'remediation': 'The request will be automatically retried. If this persists, '
                              'consider increasing the timeout value in configuration.'
            }
        
        # Connection errors
        if isinstance(error, ConnectionError):
            error_str = str(error).lower()
            
            # DNS resolution failure
            if 'name resolution' in error_str or 'nodename nor servname' in error_str or 'getaddrinfo failed' in error_str:
                return {
                    'category': ErrorCategory.FATAL,
                    'type': 'dns_failure',
                    'retryable': True,  # Might be transient DNS issue
                    'user_message': 'Could not resolve domain name. The hostname may be incorrect or DNS server may be unavailable.',
                    'technical_details': f'DNS resolution failed: {str(error)}',
                    'remediation': 'Verify the URL is correct. Check DNS server configuration. '
                                  'The request will be retried in case of transient DNS issues.'
                }
            
            # Connection refused
            if 'connection refused' in error_str:
                return {
                    'category': ErrorCategory.RECOVERABLE,
                    'type': 'connection_refused',
                    'retryable': True,
                    'user_message': 'Connection refused. The server may be down or not accepting connections.',
                    'technical_details': f'Connection refused: {str(error)}',
                    'remediation': 'Verify the server is running and the port is correct. '
                                  'Check firewall rules.'
                }
            
            # Connection reset
            if 'connection reset' in error_str or 'connection aborted' in error_str:
                return {
                    'category': ErrorCategory.RECOVERABLE,
                    'type': 'connection_reset',
                    'retryable': True,
                    'user_message': 'Connection was reset by the server. This may be a temporary network issue.',
                    'technical_details': f'Connection reset: {str(error)}',
                    'remediation': 'The request will be automatically retried. If this persists, '
                                  'the server may be rejecting connections intentionally.'
                }
            
            # Generic connection error
            return {
                'category': ErrorCategory.RECOVERABLE,
                'type': 'connection_error',
                'retryable': True,
                'user_message': 'Network connection error occurred.',
                'technical_details': f'Connection error: {str(error)}',
                'remediation': 'Check network connectivity. The request will be automatically retried.'
            }
        
        # SSL/TLS errors
        if isinstance(error, SSLError):
            return {
                'category': ErrorCategory.FATAL,
                'type': 'ssl_error',
                'retryable': False,
                'user_message': 'SSL/TLS certificate validation failed. The connection is not secure.',
                'technical_details': f'SSL error: {str(error)}',
                'remediation': 'Verify the certificate is valid. For testing purposes, you can '
                              'disable SSL verification (not recommended for production).'
            }
        
        # Proxy errors
        if isinstance(error, ProxyError):
            return {
                'category': ErrorCategory.RECOVERABLE,
                'type': 'proxy_error',
                'retryable': True,
                'user_message': 'Proxy connection failed.',
                'technical_details': f'Proxy error: {str(error)}',
                'remediation': 'Check proxy configuration and connectivity. The request will be retried.'
            }
        
        # HTTP errors
        if isinstance(error, HTTPError):
            status_code = error.response.status_code if error.response else 0
            
            # Server errors (5xx) - recoverable
            if 500 <= status_code < 600:
                return {
                    'category': ErrorCategory.RECOVERABLE,
                    'type': f'server_error_{status_code}',
                    'retryable': True,
                    'user_message': f'Server error ({status_code}). The server encountered an internal error.',
                    'technical_details': f'HTTP {status_code}: {str(error)}',
                    'remediation': 'The request will be automatically retried. The server may be '
                                  'temporarily overloaded or experiencing issues.'
                }
            
            # Rate limiting (429) - recoverable
            if status_code == 429:
                retry_after = error.response.headers.get('Retry-After', 'unknown')
                return {
                    'category': ErrorCategory.RECOVERABLE,
                    'type': 'rate_limit',
                    'retryable': True,
                    'user_message': f'Rate limit exceeded. Server requests to slow down.',
                    'technical_details': f'HTTP 429 (Retry-After: {retry_after}): {str(error)}',
                    'remediation': 'The request will be retried with exponential backoff. '
                                  'Consider reducing request frequency.'
                }
            
            # Client errors (4xx) - generally not retryable
            if 400 <= status_code < 500:
                return {
                    'category': ErrorCategory.FATAL,
                    'type': f'client_error_{status_code}',
                    'retryable': False,
                    'user_message': f'Client error ({status_code}). The request was rejected by the server.',
                    'technical_details': f'HTTP {status_code}: {str(error)}',
                    'remediation': 'Check request parameters, authentication, and permissions. '
                                  'This error will not be retried automatically.'
                }
        
        # Encoding errors
        if isinstance(error, (ChunkedEncodingError, ContentDecodingError)):
            return {
                'category': ErrorCategory.RECOVERABLE,
                'type': 'encoding_error',
                'retryable': True,
                'user_message': 'Response encoding error. The server sent malformed data.',
                'technical_details': f'Encoding error: {str(error)}',
                'remediation': 'The request will be retried. This may be a transient issue.'
            }
        
        # Redirect loop
        if isinstance(error, TooManyRedirects):
            return {
                'category': ErrorCategory.FATAL,
                'type': 'redirect_loop',
                'retryable': False,
                'user_message': 'Too many redirects. The server may have a redirect loop.',
                'technical_details': f'Redirect loop: {str(error)}',
                'remediation': 'Check the URL for redirect loops. This error will not be retried.'
            }
        
        # Generic request exception
        if isinstance(error, RequestException):
            return {
                'category': ErrorCategory.FATAL,
                'type': 'request_error',
                'retryable': False,
                'user_message': 'Request failed with an unknown error.',
                'technical_details': f'Request error: {str(error)}',
                'remediation': 'Check logs for more details. This error will not be retried.'
            }
        
        # Unknown error
        return {
            'category': ErrorCategory.FATAL,
            'type': 'unknown',
            'retryable': False,
            'user_message': 'An unexpected error occurred.',
            'technical_details': f'Unknown error: {type(error).__name__}: {str(error)}',
            'remediation': 'Check logs for more details.'
        }
    
    @staticmethod
    def get_user_friendly_message(error: Exception) -> str:
        """
        Get a user-friendly error message.
        
        Args:
            error: Exception to get message for
            
        Returns:
            User-friendly error message
        """
        classification = ErrorClassifier.classify(error)
        return classification['user_message']
    
    @staticmethod
    def is_retryable(error: Exception) -> bool:
        """
        Check if an error is retryable.
        
        Args:
            error: Exception to check
            
        Returns:
            True if error should be retried
        """
        classification = ErrorClassifier.classify(error)
        return classification['retryable']
    
    @staticmethod
    def get_remediation(error: Exception) -> str:
        """
        Get remediation steps for an error.
        
        Args:
            error: Exception to get remediation for
            
        Returns:
            Suggested remediation steps
        """
        classification = ErrorClassifier.classify(error)
        return classification['remediation']
