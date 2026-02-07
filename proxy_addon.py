#!/usr/bin/env python3
"""
mitmproxy addon for Megido Security Platform
Intercepts HTTP/HTTPS traffic and sends to Django backend

Usage:
    mitmdump -s proxy_addon.py --set api_url=http://localhost:8000
    mitmproxy -s proxy_addon.py --set api_url=http://localhost:8000
    mitmweb -s proxy_addon.py --set api_url=http://localhost:8000
"""

import json
import time
import re
from typing import Optional, Dict, List
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import requests
from mitmproxy import http, ctx


class MegidoInterceptor:
    """
    mitmproxy addon for intercepting requests and applying payload rules
    """
    
    def __init__(self):
        self.api_url = "http://localhost:8000"
        self.payload_rules = []
        self.rules_cache_time = 0
        self.cache_ttl = 60  # Cache rules for 60 seconds
        self.source_app = "browser"  # Default source app
        self.request_map = {}  # Map flow IDs to request IDs
        
    def load(self, loader):
        """Load addon configuration"""
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
            ctx.log.info(f"Cache TTL set to: {self.cache_ttl} seconds")
    
    def running(self):
        """Called when mitmproxy starts"""
        ctx.log.info("=" * 60)
        ctx.log.info("Megido Interceptor Addon Started")
        ctx.log.info(f"API URL: {self.api_url}")
        ctx.log.info(f"Source App: {self.source_app}")
        ctx.log.info("=" * 60)
        self.load_payload_rules()
    
    def load_payload_rules(self) -> bool:
        """
        Load active payload rules from Django API
        Returns True if successful, False otherwise
        """
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
                ctx.log.error(f"Failed to load payload rules: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            ctx.log.error(f"Error loading payload rules: {e}")
            return False
    
    def send_request_to_api(self, flow: http.HTTPFlow) -> Optional[int]:
        """
        Send intercepted request to Django API
        Returns the request ID if successful, None otherwise
        """
        try:
            # Prepare headers
            headers = dict(flow.request.headers)
            
            # Prepare body
            body = ""
            if flow.request.content:
                try:
                    body = flow.request.content.decode('utf-8', errors='ignore')
                except Exception:
                    body = flow.request.content.hex()
            
            # Prepare data
            data = {
                'url': flow.request.pretty_url,
                'method': flow.request.method,
                'headers': headers,
                'body': body,
                'source_app': self.source_app
            }
            
            # Send to API
            url = f"{self.api_url}/interceptor/api/request/"
            response = requests.post(url, json=data, timeout=5)
            
            if response.status_code == 201:
                result = response.json()
                request_id = result.get('request_id')
                ctx.log.info(f"Logged request: {flow.request.method} {flow.request.pretty_url} (ID: {request_id})")
                return request_id
            else:
                ctx.log.error(f"Failed to log request: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            ctx.log.error(f"Error sending request to API: {e}")
            return None
    
    def send_response_to_api(self, flow: http.HTTPFlow, request_id: int, response_time: float):
        """
        Send intercepted response to Django API
        """
        try:
            # Prepare headers
            headers = dict(flow.response.headers)
            
            # Prepare body
            body = ""
            if flow.response.content:
                try:
                    body = flow.response.content.decode('utf-8', errors='ignore')
                except Exception:
                    body = flow.response.content.hex()
            
            # Prepare data
            data = {
                'request_id': request_id,
                'status_code': flow.response.status_code,
                'headers': headers,
                'body': body,
                'response_time': response_time * 1000  # Convert to milliseconds
            }
            
            # Send to API
            url = f"{self.api_url}/interceptor/api/response/"
            response = requests.post(url, json=data, timeout=5)
            
            if response.status_code == 201:
                ctx.log.info(f"Logged response: {flow.response.status_code} for request {request_id}")
            else:
                ctx.log.error(f"Failed to log response: HTTP {response.status_code}")
                
        except Exception as e:
            ctx.log.error(f"Error sending response to API: {e}")
    
    def apply_payload_rules(self, flow: http.HTTPFlow):
        """
        Apply payload rules to the request
        """
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
                    # Reconstruct URL with new query string
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
                        # For JSON bodies
                        try:
                            body = json.loads(flow.request.content)
                            body[injection_point] = payload_content
                            flow.request.content = json.dumps(body).encode()
                            ctx.log.info(f"Applied rule '{rule['name']}': Modified JSON body")
                        except json.JSONDecodeError:
                            # For form data
                            if flow.request.method == "POST":
                                content = flow.request.content.decode('utf-8', errors='ignore')
                                params = parse_qs(content)
                                params[injection_point] = [payload_content]
                                flow.request.content = urlencode(params, doseq=True).encode()
                                ctx.log.info(f"Applied rule '{rule['name']}': Modified form data")
                
            except Exception as e:
                ctx.log.error(f"Error applying rule '{rule.get('name', 'unknown')}': {e}")
    
    def request(self, flow: http.HTTPFlow):
        """
        Called when a request is received
        """
        # Don't intercept requests to our own API
        if self.api_url in flow.request.pretty_url:
            return
        
        # Apply payload rules
        self.apply_payload_rules(flow)
        
        # Send request to API and store request ID
        request_id = self.send_request_to_api(flow)
        if request_id:
            self.request_map[id(flow)] = {
                'request_id': request_id,
                'start_time': time.time()
            }
    
    def response(self, flow: http.HTTPFlow):
        """
        Called when a response is received
        """
        # Don't intercept responses from our own API
        if self.api_url in flow.request.pretty_url:
            return
        
        # Get request ID from map
        flow_id = id(flow)
        if flow_id in self.request_map:
            request_data = self.request_map[flow_id]
            request_id = request_data['request_id']
            response_time = time.time() - request_data['start_time']
            
            # Send response to API
            self.send_response_to_api(flow, request_id, response_time)
            
            # Clean up map
            del self.request_map[flow_id]
    
    def error(self, flow: http.HTTPFlow):
        """
        Called when an error occurs
        """
        ctx.log.error(f"Flow error: {flow.error}")
        
        # Clean up map if request exists
        flow_id = id(flow)
        if flow_id in self.request_map:
            del self.request_map[flow_id]


# Create addon instance
addons = [MegidoInterceptor()]
