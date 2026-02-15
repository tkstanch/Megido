"""
Stealth Scan Mixin

This mixin provides stealth capabilities to scan plugins, allowing them to
evade detection and mimic real browser traffic.

Usage:
    from scanner.scan_plugins.stealth_scan_mixin import StealthScanMixin
    from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin
    
    class MyStealthScanner(StealthScanMixin, BaseScanPlugin):
        def scan(self, url, config=None):
            # Use stealth features
            headers = self.get_stealth_headers(config)
            response = requests.get(url, headers=headers)
            self.apply_stealth_delay(config)
            # ... rest of scan logic
"""

import logging
import time
import requests
from typing import Dict, Any, Optional
from scanner.stealth_engine import get_stealth_engine
from scanner.adaptive_payload_engine import get_adaptive_payload_engine
from scanner.callback_manager import get_callback_manager

logger = logging.getLogger(__name__)


class StealthScanMixin:
    """
    Mixin that provides stealth capabilities to scan plugins.
    
    This mixin can be added to any scan plugin to enable:
    - Randomized headers and User-Agents
    - Request timing with jitter
    - Session rotation
    - Adaptive payloads
    - Callback verification
    """
    
    def __init__(self):
        """Initialize stealth components."""
        super().__init__()
        self._stealth_engine = None
        self._payload_engine = None
        self._callback_manager = None
        self._stealth_enabled = True
    
    def get_stealth_engine(self, config: Optional[Dict[str, Any]] = None):
        """Get or create stealth engine instance."""
        if not self._stealth_engine:
            stealth_config = self._extract_stealth_config(config)
            self._stealth_engine = get_stealth_engine(stealth_config)
        return self._stealth_engine
    
    def get_payload_engine(self):
        """Get or create adaptive payload engine instance."""
        if not self._payload_engine:
            self._payload_engine = get_adaptive_payload_engine()
        return self._payload_engine
    
    def get_callback_manager(self, config: Optional[Dict[str, Any]] = None):
        """Get or create callback manager instance."""
        if not self._callback_manager:
            callback_config = self._extract_callback_config(config)
            self._callback_manager = get_callback_manager(callback_config)
        return self._callback_manager
    
    def _extract_stealth_config(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Extract stealth-related config from plugin config."""
        if not config:
            return {}
        
        return {
            'min_delay': config.get('stealth_min_delay', 0.5),
            'max_delay': config.get('stealth_max_delay', 3.0),
            'jitter_range': config.get('stealth_jitter', 0.5),
            'enable_session_rotation': config.get('stealth_session_rotation', True),
        }
    
    def _extract_callback_config(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Extract callback-related config from plugin config."""
        if not config:
            return {}
        
        return {
            'port': config.get('callback_port', 8888),
            'external_endpoint': config.get('callback_endpoint'),
            'use_ngrok': config.get('callback_use_ngrok', False),
            'ngrok_auth_token': config.get('callback_ngrok_token'),
        }
    
    def get_stealth_headers(self, config: Optional[Dict[str, Any]] = None,
                           base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Get randomized headers for stealth scanning.
        
        Args:
            config: Plugin configuration
            base_headers: Base headers to merge with stealth headers
        
        Returns:
            Dictionary of HTTP headers
        """
        if not self._is_stealth_enabled(config):
            return base_headers or {}
        
        stealth = self.get_stealth_engine(config)
        return stealth.get_randomized_headers(base_headers)
    
    def apply_stealth_delay(self, config: Optional[Dict[str, Any]] = None):
        """
        Apply stealth delay before next request.
        
        Args:
            config: Plugin configuration
        """
        if not self._is_stealth_enabled(config):
            return
        
        stealth = self.get_stealth_engine(config)
        stealth.wait_before_request()
    
    def get_adaptive_payloads(self, vuln_type: str, context: Optional[str] = None,
                             config: Optional[Dict[str, Any]] = None) -> list:
        """
        Get adaptive payloads for vulnerability testing.
        
        Args:
            vuln_type: Vulnerability type ('xss', 'sqli', etc.)
            context: Injection context
            config: Plugin configuration
        
        Returns:
            List of adaptive payloads
        """
        payload_engine = self.get_payload_engine()
        
        # Get callback URL if callback verification is enabled
        callback_url = None
        if self._is_callback_enabled(config):
            try:
                callback_mgr = self.get_callback_manager(config)
                callback_url = callback_mgr.get_callback_url()
            except Exception as e:
                logger.warning(f"Failed to get callback URL: {e}")
        
        return payload_engine.generate_adaptive_payloads(
            vuln_type=vuln_type,
            context=context,
            callback_url=callback_url
        )
    
    def analyze_response_reflection(self, response_text: str, test_payload: str) -> Dict[str, Any]:
        """
        Analyze how a payload is reflected in response.
        
        Args:
            response_text: HTTP response body
            test_payload: The payload that was injected
        
        Returns:
            Reflection analysis dictionary
        """
        payload_engine = self.get_payload_engine()
        return payload_engine.analyze_reflection(response_text, test_payload)
    
    def randomize_url_parameters(self, url: str, config: Optional[Dict[str, Any]] = None) -> str:
        """
        Randomize URL parameter order for stealth.
        
        Args:
            url: URL with parameters
            config: Plugin configuration
        
        Returns:
            URL with randomized parameter order
        """
        if not self._is_stealth_enabled(config):
            return url
        
        stealth = self.get_stealth_engine(config)
        return stealth.randomize_url_parameters(url)
    
    def encode_payload(self, payload: str, encoding: str = 'auto') -> str:
        """
        Encode payload for evasion.
        
        Args:
            payload: Original payload
            encoding: Encoding type
        
        Returns:
            Encoded payload
        """
        stealth = self.get_stealth_engine()
        return stealth.encode_payload(payload, encoding)
    
    def make_stealth_request(self, url: str, method: str = 'GET',
                            config: Optional[Dict[str, Any]] = None,
                            **kwargs) -> requests.Response:
        """
        Make an HTTP request with stealth features.
        
        Args:
            url: Target URL
            method: HTTP method
            config: Plugin configuration
            **kwargs: Additional arguments for requests
        
        Returns:
            Response object
        """
        # Apply stealth delay before request
        self.apply_stealth_delay(config)
        
        # Get stealth headers
        base_headers = kwargs.pop('headers', {})
        headers = self.get_stealth_headers(config, base_headers)
        
        # Randomize URL parameters if enabled
        url = self.randomize_url_parameters(url, config)
        
        # Add session cookies if enabled
        if self._is_stealth_enabled(config):
            stealth = self.get_stealth_engine(config)
            cookies = kwargs.pop('cookies', {})
            session_cookies = stealth.get_session_cookies()
            cookies.update(session_cookies)
            kwargs['cookies'] = cookies
        
        # Make request
        timeout = config.get('timeout', 10) if config else 10
        verify_ssl = config.get('verify_ssl', False) if config else False
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                **kwargs
            )
            return response
        except requests.RequestException as e:
            logger.error(f"Stealth request failed: {e}")
            raise
    
    def verify_callback(self, payload_id: str, timeout: int = 30,
                       config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Verify that a callback was received for payload.
        
        Args:
            payload_id: Unique payload identifier
            timeout: Maximum wait time
            config: Plugin configuration
        
        Returns:
            Verification result dictionary
        """
        if not self._is_callback_enabled(config):
            return {'verified': False, 'reason': 'callback_disabled'}
        
        try:
            callback_mgr = self.get_callback_manager(config)
            return callback_mgr.verify_callback(payload_id, timeout)
        except Exception as e:
            logger.error(f"Callback verification failed: {e}")
            return {'verified': False, 'reason': str(e)}
    
    def _is_stealth_enabled(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Check if stealth features are enabled."""
        if not config:
            return self._stealth_enabled
        return config.get('enable_stealth', True)
    
    def _is_callback_enabled(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Check if callback verification is enabled."""
        if not config:
            return False
        return config.get('enable_callback_verification', False)
    
    def get_stealth_config_defaults(self) -> Dict[str, Any]:
        """
        Get default configuration for stealth features.
        
        Returns:
            Default stealth configuration
        """
        return {
            'enable_stealth': True,
            'stealth_min_delay': 0.5,
            'stealth_max_delay': 3.0,
            'stealth_jitter': 0.5,
            'stealth_session_rotation': True,
            'enable_callback_verification': False,
            'callback_endpoint': None,
            'callback_use_ngrok': False,
            'callback_port': 8888,
        }
