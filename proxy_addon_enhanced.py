#!/usr/bin/env python3
"""
Enhanced mitmproxy addon for Megido Security Platform
Supports HTTP/HTTPS, WebSocket, authentication, enhanced logging, and error handling

Usage:
    mitmdump -s proxy_addon_enhanced.py --set api_url=http://localhost:8000
    mitmproxy -s proxy_addon_enhanced.py --set api_url=http://localhost:8000 --set auth_required=true
    mitmweb -s proxy_addon_enhanced.py --set api_url=http://localhost:8000
    
Configuration Options:
    --set api_url=<url>              Django API base URL
    --set source_app=<name>          Source app identifier  
    --set auth_required=<bool>       Enable proxy authentication
    --set auth_token=<token>         Authentication token
    --set max_body_size=<bytes>      Maximum body size to log (default: 1MB)
    --set websocket_enabled=<bool>   Enable WebSocket logging (default: true)
"""

import json
import time
import re
import traceback
from typing import Optional, Dict, List
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import requests
from mitmproxy import http, ctx, websocket


class MegidoInterceptorEnhanced:
    """
    Enhanced mitmproxy addon with comprehensive features:
    - HTTP/HTTPS request/response logging with detailed metadata
    - WebSocket message capture
    - Authentication support
    - IP filtering
    - Enhanced error handling and recovery
    - Performance controls
    """
    
    def __init__(self):
        # API settings
        self.api_url = "http://localhost:8000"
        self.source_app = "browser"
        
        # Payload rule caching
        self.payload_rules = []
        self.rules_cache_time = 0
        self.cache_ttl = 60
        
        # Request tracking
        self.request_map = {}  # Map flow IDs to request IDs
        self.ws_connections = {}  # Track WebSocket connections
        
        # Authentication
        self.auth_required = False
        self.auth_token = None
        
        # Performance settings
        self.max_body_size = 1024 * 1024  # 1MB default
        self.connection_timeout = 30
        self.max_retries = 3
        
        # Feature flags
        self.websocket_enabled = True
        self.logging_enabled = True
        
        # Statistics
        self.stats = {
            'requests_processed': 0,
            'responses_processed': 0,
            'websocket_messages': 0,
            'errors': 0,
            'auth_attempts': 0,
            'auth_failures': 0
        }
        
    def load(self, loader):
        """Load addon configuration options"""
        loader.add_option(
            name="api_url",
            typespec=str,
            default="http://localhost:8000",
            help="Django API base URL"
        )
        loader.add_option(
            name="source_app",
            typespec=str,
            default="browser",
            help="Source app identifier (browser, scanner, spider, etc.)"
        )
        loader.add_option(
            name="cache_ttl",
            typespec=int,
            default=60,
            help="Payload rules cache TTL in seconds"
        )
        loader.add_option(
            name="auth_required",
            typespec=bool,
            default=False,
            help="Enable proxy authentication"
        )
        loader.add_option(
            name="auth_token",
            typespec=str,
            default="",
            help="Authentication token for proxy access"
        )
        loader.add_option(
            name="max_body_size",
            typespec=int,
            default=1024*1024,
            help="Maximum body size to log in bytes"
        )
        loader.add_option(
            name="websocket_enabled",
            typespec=bool,
            default=True,
            help="Enable WebSocket message logging"
        )
        loader.add_option(
            name="connection_timeout",
            typespec=int,
            default=30,
            help="Connection timeout in seconds"
        )
    
    def configure(self, updates):
        """Update configuration when options change"""
        if "api_url" in updates:
            self.api_url = ctx.options.api_url
            ctx.log.info(f"API URL set to: {self.api_url}")
        
        if "source_app" in updates:
            self.source_app = ctx.options.source_app
            ctx.log.info(f"Source app set to: {self.source_app}")
        
        if "cache_ttl" in updates:
            self.cache_ttl = ctx.options.cache_ttl
        
        if "auth_required" in updates:
            self.auth_required = ctx.options.auth_required
            ctx.log.info(f"Authentication required: {self.auth_required}")
        
        if "auth_token" in updates:
            self.auth_token = ctx.options.auth_token
        
        if "max_body_size" in updates:
            self.max_body_size = ctx.options.max_body_size
        
        if "websocket_enabled" in updates:
            self.websocket_enabled = ctx.options.websocket_enabled
        
        if "connection_timeout" in updates:
            self.connection_timeout = ctx.options.connection_timeout
    
    def running(self):
        """Called when mitmproxy starts"""
        ctx.log.info("=" * 70)
        ctx.log.info("Megido Enhanced Interceptor Addon Started")
        ctx.log.info("=" * 70)
        ctx.log.info(f"API URL:              {self.api_url}")
        ctx.log.info(f"Source App:           {self.source_app}")
        ctx.log.info(f"Authentication:       {'Enabled' if self.auth_required else 'Disabled'}")
        ctx.log.info(f"WebSocket Logging:    {'Enabled' if self.websocket_enabled else 'Disabled'}")
        ctx.log.info(f"Max Body Size:        {self.max_body_size / 1024:.0f} KB")
        ctx.log.info(f"Connection Timeout:   {self.connection_timeout}s")
        ctx.log.info("=" * 70)
        self.load_payload_rules()
    
    def done(self):
        """Called when mitmproxy shuts down"""
        ctx.log.info("=" * 70)
        ctx.log.info("Megido Interceptor Statistics")
        ctx.log.info("=" * 70)
        ctx.log.info(f"Requests Processed:   {self.stats['requests_processed']}")
        ctx.log.info(f"Responses Processed:  {self.stats['responses_processed']}")
        ctx.log.info(f"WebSocket Messages:   {self.stats['websocket_messages']}")
        ctx.log.info(f"Errors Encountered:   {self.stats['errors']}")
        ctx.log.info(f"Auth Attempts:        {self.stats['auth_attempts']}")
        ctx.log.info(f"Auth Failures:        {self.stats['auth_failures']}")
        ctx.log.info("=" * 70)
    
    def check_authentication(self, flow: http.HTTPFlow) -> bool:
        """
        Check if request is authenticated
        
        Returns:
            True if authenticated or auth not required, False otherwise
        """
        if not self.auth_required:
            return True
        
        self.stats['auth_attempts'] += 1
        
        # Check for Proxy-Authorization header
        auth_header = flow.request.headers.get("Proxy-Authorization", "")
        
        if self.auth_token:
            # Token-based authentication
            expected = f"Bearer {self.auth_token}"
            if auth_header == expected:
                return True
        
        # Authentication failed
        self.stats['auth_failures'] += 1
        self.log_auth_attempt(flow, False)
        
        # Send 407 Proxy Authentication Required
        flow.response = http.Response.make(
            407,
            b"Proxy Authentication Required",
            {"Proxy-Authenticate": "Bearer"}
        )
        
        return False
    
    def log_auth_attempt(self, flow: http.HTTPFlow, success: bool):
        """Log authentication attempt"""
        try:
            source_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
            
            data = {
                'source_ip': source_ip,
                'success': success,
                'timestamp': time.time()
            }
            
            url = f"{self.api_url}/proxy/api/auth-attempt/"
            requests.post(url, json=data, timeout=5)
            
        except Exception as e:
            ctx.log.warn(f"Failed to log auth attempt: {e}")
    
    def load_payload_rules(self) -> bool:
        """Load active payload rules from Django API"""
        current_time = time.time()
        
        # Check if cache is still valid
        if current_time - self.rules_cache_time < self.cache_ttl:
            return True
        
        try:
            url = f"{self.api_url}/interceptor/api/payload-rules/active/"
            params = {'source_app': self.source_app}
            
            response = requests.get(url, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.payload_rules = data.get('rules', [])
                self.rules_cache_time = current_time
                ctx.log.info(f"Loaded {len(self.payload_rules)} active payload rules")
                return True
            else:
                ctx.log.warn(f"Failed to load payload rules: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            ctx.log.warn(f"Error loading payload rules: {e}")
            return False
    
    def send_request_to_api(self, flow: http.HTTPFlow) -> Optional[int]:
        """Send intercepted request to Django API with enhanced metadata"""
        try:
            # Get client info
            source_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
            
            # Prepare headers
            headers = dict(flow.request.headers)
            
            # Prepare body (with size limit)
            body = ""
            request_size = 0
            if flow.request.content:
                request_size = len(flow.request.content)
                if request_size <= self.max_body_size:
                    try:
                        body = flow.request.content.decode('utf-8', errors='ignore')
                    except Exception:
                        body = flow.request.content.hex()
                else:
                    body = f"[Body too large: {request_size} bytes]"
            
            # Determine protocol
            protocol = 'HTTPS' if flow.request.scheme == 'https' else 'HTTP'
            
            # Extract host and port
            host = flow.request.host
            port = flow.request.port
            
            # Prepare data
            data = {
                'url': flow.request.pretty_url,
                'method': flow.request.method,
                'headers': json.dumps(headers),
                'body': body,
                'source_app': self.source_app,
                'source_ip': source_ip,
                'protocol': protocol,
                'host': host,
                'port': port,
                'request_size': request_size,
                'user_agent': headers.get('User-Agent', ''),
                'timestamp': time.time()
            }
            
            # Send to API with retry
            url = f"{self.api_url}/proxy/api/requests/"
            for attempt in range(self.max_retries):
                try:
                    response = requests.post(url, json=data, timeout=self.connection_timeout)
                    
                    if response.status_code in [200, 201]:
                        result = response.json()
                        request_id = result.get('id')
                        ctx.log.info(f"✓ Logged request: {flow.request.method} {flow.request.pretty_url[:60]} (ID: {request_id})")
                        self.stats['requests_processed'] += 1
                        return request_id
                    
                except requests.exceptions.Timeout:
                    if attempt < self.max_retries - 1:
                        ctx.log.warn(f"Request logging timeout, retry {attempt + 1}/{self.max_retries}")
                        continue
                    else:
                        raise
            
            ctx.log.error(f"Failed to log request after {self.max_retries} attempts")
            return None
                
        except Exception as e:
            self.log_error(flow, 'REQUEST_LOGGING_ERROR', str(e))
            return None
    
    def send_response_to_api(self, flow: http.HTTPFlow, request_id: int, response_time: float):
        """Send intercepted response to Django API with enhanced metadata"""
        try:
            # Prepare headers
            headers = dict(flow.response.headers)
            
            # Prepare body (with size limit)
            body = ""
            response_size = 0
            if flow.response.content:
                response_size = len(flow.response.content)
                if response_size <= self.max_body_size:
                    try:
                        body = flow.response.content.decode('utf-8', errors='ignore')
                    except Exception:
                        body = flow.response.content.hex()
                else:
                    body = f"[Body too large: {response_size} bytes]"
            
            # Prepare data
            data = {
                'request': request_id,
                'status_code': flow.response.status_code,
                'headers': json.dumps(headers),
                'body': body,
                'response_time': response_time * 1000,  # Convert to milliseconds
                'response_size': response_size,
                'cached': False,
                'timestamp': time.time()
            }
            
            # Send to API
            url = f"{self.api_url}/proxy/api/responses/"
            response = requests.post(url, json=data, timeout=self.connection_timeout)
            
            if response.status_code in [200, 201]:
                ctx.log.info(f"✓ Logged response: {flow.response.status_code} for request {request_id}")
                self.stats['responses_processed'] += 1
            else:
                ctx.log.warn(f"Failed to log response: HTTP {response.status_code}")
                
        except Exception as e:
            self.log_error(flow, 'RESPONSE_LOGGING_ERROR', str(e))
    
    def log_error(self, flow: http.HTTPFlow, error_type: str, error_message: str):
        """Log error to API"""
        try:
            self.stats['errors'] += 1
            
            source_ip = None
            if flow and flow.client_conn and flow.client_conn.peername:
                source_ip = flow.client_conn.peername[0]
            
            url_val = None
            if flow and flow.request:
                url_val = flow.request.pretty_url
            
            data = {
                'error_type': error_type,
                'error_message': error_message,
                'stack_trace': traceback.format_exc(),
                'url': url_val,
                'source_ip': source_ip,
                'timestamp': time.time()
            }
            
            url = f"{self.api_url}/proxy/api/errors/"
            requests.post(url, json=data, timeout=5)
            
            ctx.log.error(f"✗ Error logged: {error_type} - {error_message}")
            
        except Exception as e:
            ctx.log.error(f"Failed to log error to API: {e}")
    
    def apply_payload_rules(self, flow: http.HTTPFlow):
        """Apply payload rules to the request"""
        # Reload rules if needed
        self.load_payload_rules()
        
        if not self.payload_rules:
            return
        
        for rule in self.payload_rules:
            try:
                # Check if URL matches pattern
                pattern = rule.get('target_url_pattern', '')
                if not re.search(pattern, flow.request.pretty_url):
                    continue
                
                # Check if rule applies to this source app
                target_apps = rule.get('target_apps', [])
                if target_apps and self.source_app not in target_apps:
                    continue
                
                # Apply injection based on type
                injection_type = rule.get('injection_type')
                injection_point = rule.get('injection_point')
                payload_content = rule.get('payload_content')
                
                if injection_type == 'header':
                    flow.request.headers[injection_point] = payload_content
                    ctx.log.info(f"Applied rule '{rule['name']}': Added header {injection_point}")
                
                elif injection_type == 'param':
                    parsed = urlparse(flow.request.pretty_url)
                    params = parse_qs(parsed.query)
                    params[injection_point] = [payload_content]
                    new_query = urlencode(params, doseq=True)
                    flow.request.url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))
                    ctx.log.info(f"Applied rule '{rule['name']}': Added parameter {injection_point}")
                
                elif injection_type == 'cookie':
                    cookies = flow.request.cookies
                    cookies[injection_point] = payload_content
                    flow.request.cookies = cookies
                    ctx.log.info(f"Applied rule '{rule['name']}': Added cookie {injection_point}")
                
                elif injection_type == 'body':
                    if flow.request.content:
                        try:
                            body = json.loads(flow.request.content)
                            body[injection_point] = payload_content
                            flow.request.content = json.dumps(body).encode()
                            ctx.log.info(f"Applied rule '{rule['name']}': Modified JSON body")
                        except json.JSONDecodeError:
                            if flow.request.method == "POST":
                                content = flow.request.content.decode('utf-8', errors='ignore')
                                params = parse_qs(content)
                                params[injection_point] = [payload_content]
                                flow.request.content = urlencode(params, doseq=True).encode()
                                ctx.log.info(f"Applied rule '{rule['name']}': Modified form data")
                
            except Exception as e:
                ctx.log.error(f"Error applying rule '{rule.get('name', 'unknown')}': {e}")
    
    def request(self, flow: http.HTTPFlow):
        """Called when a request is received"""
        try:
            # Don't intercept requests to our own API
            if self.api_url in flow.request.pretty_url:
                return
            
            # Check authentication
            if not self.check_authentication(flow):
                return
            
            # Apply payload rules
            self.apply_payload_rules(flow)
            
            # Send request to API and store request ID
            if self.logging_enabled:
                request_id = self.send_request_to_api(flow)
                if request_id:
                    self.request_map[id(flow)] = {
                        'request_id': request_id,
                        'start_time': time.time()
                    }
                    
        except Exception as e:
            self.log_error(flow, 'REQUEST_PROCESSING_ERROR', str(e))
    
    def response(self, flow: http.HTTPFlow):
        """Called when a response is received"""
        try:
            # Don't intercept responses from our own API
            if self.api_url in flow.request.pretty_url:
                return
            
            # Get request ID from map
            flow_id = id(flow)
            if flow_id in self.request_map and self.logging_enabled:
                request_data = self.request_map[flow_id]
                request_id = request_data['request_id']
                response_time = time.time() - request_data['start_time']
                
                # Send response to API
                self.send_response_to_api(flow, request_id, response_time)
                
                # Clean up map
                del self.request_map[flow_id]
                
        except Exception as e:
            self.log_error(flow, 'RESPONSE_PROCESSING_ERROR', str(e))
    
    def error(self, flow: http.HTTPFlow):
        """Called when an error occurs during request/response processing"""
        try:
            error_msg = str(flow.error) if flow.error else "Unknown error"
            
            # Determine error type
            error_type = 'OTHER'
            if 'timeout' in error_msg.lower():
                error_type = 'TIMEOUT'
            elif 'connection' in error_msg.lower():
                error_type = 'CONNECTION_RESET'
            elif 'ssl' in error_msg.lower() or 'tls' in error_msg.lower():
                error_type = 'SSL_ERROR'
            elif 'dns' in error_msg.lower():
                error_type = 'DNS_ERROR'
            
            self.log_error(flow, error_type, error_msg)
            
            # Clean up map if request exists
            flow_id = id(flow)
            if flow_id in self.request_map:
                del self.request_map[flow_id]
                
        except Exception as e:
            ctx.log.error(f"Error in error handler: {e}")
    
    # WebSocket handlers
    def websocket_start(self, flow: http.HTTPFlow):
        """Called when a WebSocket connection is established"""
        if not self.websocket_enabled:
            return
        
        try:
            conn_id = f"ws_{id(flow)}_{int(time.time())}"
            self.ws_connections[id(flow)] = {
                'connection_id': conn_id,
                'url': flow.request.pretty_url,
                'start_time': time.time()
            }
            
            ctx.log.info(f"✓ WebSocket connection started: {conn_id} - {flow.request.pretty_url}")
            
        except Exception as e:
            ctx.log.error(f"Error in websocket_start: {e}")
    
    def websocket_message(self, flow: http.HTTPFlow):
        """Called when a WebSocket message is sent or received"""
        if not self.websocket_enabled:
            return
        
        try:
            flow_id = id(flow)
            if flow_id not in self.ws_connections:
                return
            
            ws_info = self.ws_connections[flow_id]
            
            # Get the last message
            if flow.websocket and flow.websocket.messages:
                message = flow.websocket.messages[-1]
                
                # Determine direction
                direction = 'SEND' if message.from_client else 'RECEIVE'
                
                # Determine message type
                msg_type = 'TEXT' if message.type.name == 'TEXT' else 'BINARY'
                
                # Get payload
                try:
                    if message.type.name == 'TEXT':
                        payload = message.content
                    else:
                        payload = message.content.hex()[:1000]  # Limit binary data
                except:
                    payload = '[Unable to decode]'
                
                # Get source IP
                source_ip = None
                if flow.client_conn and flow.client_conn.peername:
                    source_ip = flow.client_conn.peername[0]
                
                # Send to API
                data = {
                    'connection_id': ws_info['connection_id'],
                    'url': ws_info['url'],
                    'direction': direction,
                    'message_type': msg_type,
                    'payload': str(payload),
                    'payload_size': len(message.content) if message.content else 0,
                    'source_ip': source_ip,
                    'timestamp': time.time()
                }
                
                url = f"{self.api_url}/proxy/api/websocket-messages/"
                response = requests.post(url, json=data, timeout=5)
                
                if response.status_code in [200, 201]:
                    self.stats['websocket_messages'] += 1
                    ctx.log.info(f"✓ Logged WebSocket {direction} message on {ws_info['connection_id']}")
                    
        except Exception as e:
            ctx.log.error(f"Error logging WebSocket message: {e}")
    
    def websocket_end(self, flow: http.HTTPFlow):
        """Called when a WebSocket connection is closed"""
        if not self.websocket_enabled:
            return
        
        try:
            flow_id = id(flow)
            if flow_id in self.ws_connections:
                ws_info = self.ws_connections[flow_id]
                duration = time.time() - ws_info['start_time']
                ctx.log.info(f"✓ WebSocket connection closed: {ws_info['connection_id']} (Duration: {duration:.2f}s)")
                del self.ws_connections[flow_id]
                
        except Exception as e:
            ctx.log.error(f"Error in websocket_end: {e}")


# Create addon instance
addons = [MegidoInterceptorEnhanced()]
