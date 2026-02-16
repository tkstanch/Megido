"""
Secure Network Logger

Provides logging for network operations with automatic sensitive data redaction.
"""

import re
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class NetworkLogger:
    """
    Logger for network operations that automatically redacts sensitive data.
    
    Features:
    - Automatic redaction of credentials in URLs
    - Redaction of sensitive headers (Authorization, Cookie, etc.)
    - Structured logging for easy parsing
    - Performance metrics logging
    """
    
    # Sensitive headers that should be redacted
    SENSITIVE_HEADERS = {
        'authorization', 'cookie', 'set-cookie', 'x-api-key',
        'api-key', 'apikey', 'x-auth-token', 'x-csrf-token',
        'proxy-authorization', 'www-authenticate'
    }
    
    # Sensitive query parameters that should be redacted
    SENSITIVE_PARAMS = {
        'password', 'pwd', 'passwd', 'pass', 'token', 'api_key',
        'apikey', 'secret', 'auth', 'key', 'access_token',
        'refresh_token', 'session', 'sessionid', 'csrf'
    }
    
    def __init__(self, logger_name: Optional[str] = None):
        """
        Initialize the network logger.
        
        Args:
            logger_name: Optional custom logger name
        """
        self.logger = logging.getLogger(logger_name or __name__)
    
    @staticmethod
    def _redact_url(url: str) -> str:
        """
        Redact sensitive information from URLs.
        
        Args:
            url: URL to redact
            
        Returns:
            Redacted URL with credentials and sensitive params removed
        """
        try:
            parsed = urlparse(url)
            
            # Redact username/password in URL
            if parsed.username or parsed.password:
                netloc = parsed.hostname or ''
                if parsed.port:
                    netloc = f"{netloc}:{parsed.port}"
                parsed = parsed._replace(netloc=f"***:***@{netloc}")
            
            # Redact sensitive query parameters
            if parsed.query:
                params = parse_qs(parsed.query)
                redacted_params = []
                for key, values in params.items():
                    if key.lower() in NetworkLogger.SENSITIVE_PARAMS:
                        redacted_params.append(f"{key}=***")
                    else:
                        for value in values:
                            redacted_params.append(f"{key}={value}")
                parsed = parsed._replace(query='&'.join(redacted_params))
            
            return parsed.geturl()
        except Exception:
            # If parsing fails, try basic redaction
            # Redact anything that looks like user:pass@host
            redacted = re.sub(r'://[^:]+:[^@]+@', '://***:***@', url)
            return redacted
    
    @staticmethod
    def _redact_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive headers.
        
        Args:
            headers: Headers dictionary
            
        Returns:
            Headers with sensitive values redacted
        """
        if not headers:
            return {}
        
        redacted = {}
        for key, value in headers.items():
            if key.lower() in NetworkLogger.SENSITIVE_HEADERS:
                # Show first few characters for debugging
                if isinstance(value, str) and len(value) > 8:
                    redacted[key] = f"{value[:4]}***{value[-4:]}"
                else:
                    redacted[key] = "***"
            else:
                redacted[key] = value
        
        return redacted
    
    def log_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Log an outgoing HTTP request.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            **kwargs: Additional context
        """
        redacted_url = self._redact_url(url)
        redacted_headers = self._redact_headers(headers or {})
        
        self.logger.debug(
            f"HTTP Request: {method} {redacted_url}",
            extra={
                'method': method,
                'url': redacted_url,
                'headers': redacted_headers,
                **kwargs
            }
        )
    
    def log_response(
        self,
        url: str,
        method: str,
        status_code: int,
        duration_ms: Optional[float] = None,
        **kwargs
    ):
        """
        Log an HTTP response.
        
        Args:
            url: Request URL
            method: HTTP method
            status_code: Response status code
            duration_ms: Request duration in milliseconds
            **kwargs: Additional context
        """
        redacted_url = self._redact_url(url)
        
        duration_str = f" ({duration_ms:.2f}ms)" if duration_ms else ""
        
        self.logger.info(
            f"HTTP Response: {method} {redacted_url} -> {status_code}{duration_str}",
            extra={
                'method': method,
                'url': redacted_url,
                'status_code': status_code,
                'duration_ms': duration_ms,
                **kwargs
            }
        )
    
    def log_retry(
        self,
        url: str,
        method: str,
        attempt: int,
        max_attempts: int,
        error_type: str,
        backoff_delay: float,
        **kwargs
    ):
        """
        Log a retry attempt.
        
        Args:
            url: Request URL
            method: HTTP method
            attempt: Current attempt number
            max_attempts: Maximum attempts
            error_type: Type of error that triggered retry
            backoff_delay: Delay before next retry (seconds)
            **kwargs: Additional context
        """
        redacted_url = self._redact_url(url)
        
        self.logger.warning(
            f"Retry {attempt}/{max_attempts}: {method} {redacted_url} "
            f"(error: {error_type}, backoff: {backoff_delay:.2f}s)",
            extra={
                'method': method,
                'url': redacted_url,
                'attempt': attempt,
                'max_attempts': max_attempts,
                'error_type': error_type,
                'backoff_delay': backoff_delay,
                **kwargs
            }
        )
    
    def log_success(
        self,
        url: str,
        method: str,
        status_code: int,
        attempt: int = 1,
        **kwargs
    ):
        """
        Log a successful request.
        
        Args:
            url: Request URL
            method: HTTP method
            status_code: Response status code
            attempt: Number of attempts taken
            **kwargs: Additional context
        """
        redacted_url = self._redact_url(url)
        
        attempt_str = f" (after {attempt} attempts)" if attempt > 1 else ""
        
        self.logger.info(
            f"Success: {method} {redacted_url} -> {status_code}{attempt_str}",
            extra={
                'method': method,
                'url': redacted_url,
                'status_code': status_code,
                'attempt': attempt,
                **kwargs
            }
        )
    
    def log_fatal_error(
        self,
        url: str,
        method: str,
        error_type: str,
        error_message: str,
        **kwargs
    ):
        """
        Log a fatal (non-retryable) error.
        
        Args:
            url: Request URL
            method: HTTP method
            error_type: Type of error
            error_message: Error message
            **kwargs: Additional context
        """
        redacted_url = self._redact_url(url)
        
        self.logger.error(
            f"Fatal Error: {method} {redacted_url} - {error_type}: {error_message}",
            extra={
                'method': method,
                'url': redacted_url,
                'error_type': error_type,
                'error_message': error_message,
                **kwargs
            }
        )
    
    def log_final_failure(
        self,
        url: str,
        method: str,
        error_type: str,
        attempts: int,
        **kwargs
    ):
        """
        Log final failure after all retries exhausted.
        
        Args:
            url: Request URL
            method: HTTP method
            error_type: Type of error
            attempts: Total attempts made
            **kwargs: Additional context
        """
        redacted_url = self._redact_url(url)
        
        self.logger.error(
            f"Failed after {attempts} attempts: {method} {redacted_url} - {error_type}",
            extra={
                'method': method,
                'url': redacted_url,
                'error_type': error_type,
                'attempts': attempts,
                **kwargs
            }
        )
    
    def log_degraded_mode(
        self,
        service_name: str,
        reason: str,
        **kwargs
    ):
        """
        Log when a service enters degraded mode.
        
        Args:
            service_name: Name of the service
            reason: Reason for degraded mode
            **kwargs: Additional context
        """
        self.logger.warning(
            f"Service degraded: {service_name} - {reason}",
            extra={
                'service_name': service_name,
                'reason': reason,
                'mode': 'degraded',
                **kwargs
            }
        )
