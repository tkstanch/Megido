"""
Request replay functionality for the proxy app.
Allows replaying of logged HTTP requests to original or test endpoints.
"""

import json
import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urlunparse


class RequestReplayer:
    """Service for replaying captured HTTP requests"""
    
    def __init__(self, verify_ssl: bool = True, timeout: int = 30):
        """
        Initialize request replayer
        
        Args:
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
    
    def replay_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        target_url: Optional[str] = None,
        follow_redirects: bool = True
    ) -> Dict[str, Any]:
        """
        Replay a single HTTP request
        
        Args:
            url: Original URL
            method: HTTP method
            headers: Request headers
            body: Request body (if any)
            target_url: Alternative target URL (for testing)
            follow_redirects: Whether to follow redirects
            
        Returns:
            Dictionary containing replay results
        """
        # Use target URL if provided, otherwise use original
        request_url = target_url or url
        
        # Filter out headers that shouldn't be replayed
        filtered_headers = self._filter_headers(headers)
        
        # Prepare request data
        request_kwargs = {
            'url': request_url,
            'method': method,
            'headers': filtered_headers,
            'verify': self.verify_ssl,
            'timeout': self.timeout,
            'allow_redirects': follow_redirects
        }
        
        # Add body if present
        if body:
            request_kwargs['data'] = body
        
        # Execute request and measure time
        start_time = time.time()
        error_message = None
        response_data = {}
        
        try:
            response = self.session.request(**request_kwargs)
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Capture response data
            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:10000],  # Limit body size
                'response_time': response_time,
                'success': True
            }
            
        except requests.exceptions.Timeout:
            error_message = f"Request timed out after {self.timeout} seconds"
            response_data = {'success': False, 'error': error_message}
            
        except requests.exceptions.SSLError as e:
            error_message = f"SSL Error: {str(e)}"
            response_data = {'success': False, 'error': error_message}
            
        except requests.exceptions.ConnectionError as e:
            error_message = f"Connection Error: {str(e)}"
            response_data = {'success': False, 'error': error_message}
            
        except Exception as e:
            error_message = f"Unexpected error: {str(e)}"
            response_data = {'success': False, 'error': error_message}
        
        # Return comprehensive replay result
        return {
            'request': {
                'url': request_url,
                'original_url': url,
                'method': method,
                'headers': filtered_headers,
                'body': body[:1000] if body else None  # Limit logged body
            },
            'response': response_data,
            'timestamp': time.time(),
            'error_message': error_message
        }
    
    def replay_from_dict(
        self,
        request_data: Dict[str, Any],
        target_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Replay request from a dictionary (e.g., from database)
        
        Args:
            request_data: Dictionary with url, method, headers, body fields
            target_url: Alternative target URL
            
        Returns:
            Replay results
        """
        # Parse headers if stored as JSON string
        headers = request_data.get('headers', {})
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except json.JSONDecodeError:
                headers = {}
        
        return self.replay_request(
            url=request_data['url'],
            method=request_data['method'],
            headers=headers,
            body=request_data.get('body'),
            target_url=target_url
        )
    
    def replay_multiple(
        self,
        requests_list: List[Dict[str, Any]],
        delay_between: float = 0.5,
        target_url: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Replay multiple requests in sequence
        
        Args:
            requests_list: List of request dictionaries
            delay_between: Delay between requests in seconds
            target_url: Alternative target URL for all requests
            
        Returns:
            List of replay results
        """
        results = []
        
        for i, request_data in enumerate(requests_list):
            result = self.replay_from_dict(request_data, target_url)
            results.append(result)
            
            # Add delay between requests (except after the last one)
            if i < len(requests_list) - 1 and delay_between > 0:
                time.sleep(delay_between)
        
        return results
    
    def _filter_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Filter headers that shouldn't be replayed
        
        Args:
            headers: Original headers dictionary
            
        Returns:
            Filtered headers
        """
        # Headers to exclude from replay
        exclude_headers = {
            'host',  # Will be set automatically
            'content-length',  # Will be set automatically
            'connection',  # Connection-specific
            'keep-alive',  # Connection-specific
            'proxy-authenticate',
            'proxy-authorization',
            'te',
            'trailers',
            'transfer-encoding',
            'upgrade',
        }
        
        filtered = {}
        for key, value in headers.items():
            if key.lower() not in exclude_headers:
                filtered[key] = value
        
        return filtered
    
    def modify_url_for_testing(
        self,
        original_url: str,
        test_host: str,
        test_port: Optional[int] = None,
        use_https: bool = False
    ) -> str:
        """
        Modify URL to point to a test server
        
        Args:
            original_url: Original URL
            test_host: Test server hostname
            test_port: Test server port
            use_https: Whether to use HTTPS
            
        Returns:
            Modified URL
        """
        parsed = urlparse(original_url)
        
        # Build new netloc
        if test_port:
            netloc = f"{test_host}:{test_port}"
        else:
            netloc = test_host
        
        # Determine scheme
        scheme = 'https' if use_https else 'http'
        
        # Reconstruct URL
        return urlunparse((
            scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))


def replay_from_database(request_id: int, target_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to replay a request from database
    
    Args:
        request_id: ID of ProxyRequest to replay
        target_url: Alternative target URL
        
    Returns:
        Replay results
    """
    from .models import ProxyRequest
    
    try:
        request = ProxyRequest.objects.get(id=request_id)
        
        replayer = RequestReplayer()
        result = replayer.replay_from_dict(
            {
                'url': request.url,
                'method': request.method,
                'headers': request.headers,
                'body': request.body
            },
            target_url=target_url
        )
        
        # Mark as replay in database
        replayed_request = ProxyRequest.objects.create(
            url=target_url or request.url,
            method=request.method,
            headers=request.headers,
            body=request.body,
            host=request.host,
            port=request.port,
            is_replay=True,
            original_request=request,
            protocol=request.protocol,
            source_ip=request.source_ip,
            user_agent=request.user_agent
        )
        
        result['replayed_request_id'] = replayed_request.id
        return result
        
    except ProxyRequest.DoesNotExist:
        return {
            'success': False,
            'error': f'Request with ID {request_id} not found'
        }
