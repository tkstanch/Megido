"""
Request Handler - CEF request interception and handling

This module intercepts HTTP requests in the CEF browser and integrates with
the Django interceptor app when enabled.
"""

try:
    from cefpython3 import cefpython as cef
except ImportError:
    # CEF Python not installed - provide mock for development
    cef = None

import json
from typing import Optional, Dict, Any
from .django_bridge import DjangoBridge


class RequestHandler:
    """
    Custom request handler for CEF browser to intercept HTTP requests
    """
    
    def __init__(self, django_bridge: DjangoBridge):
        """
        Initialize request handler
        
        Args:
            django_bridge: DjangoBridge instance for API communication
        """
        self.bridge = django_bridge
        self.interceptor_enabled = False
        self.update_interceptor_status()
    
    def update_interceptor_status(self):
        """Update interceptor status from Django"""
        status = self.bridge.get_interceptor_status()
        self.interceptor_enabled = status.get('is_enabled', False)
    
    def on_before_resource_load(self, browser, frame, request, **kwargs):
        """
        Called before a resource is loaded
        
        This is where we can intercept and modify requests
        
        Args:
            browser: CEF browser instance
            frame: CEF frame
            request: CEF request object
            
        Returns:
            RV_CONTINUE to continue loading, RV_CANCEL to cancel
        """
        if not cef:
            return
        
        # Update interceptor status
        self.update_interceptor_status()
        
        if self.interceptor_enabled:
            # Log that request is being intercepted
            url = request.GetUrl() if hasattr(request, 'GetUrl') else ''
            method = request.GetMethod() if hasattr(request, 'GetMethod') else 'GET'
            
            print(f"[Interceptor] Intercepting: {method} {url}")
            
            # In a full implementation, this would:
            # 1. Extract request details (headers, body, etc.)
            # 2. Send to Django interceptor for inspection
            # 3. Wait for user to forward/modify/drop
            # 4. Apply modifications if any
            # 5. Continue or cancel based on user action
            
            # For now, we just log and continue
            return cef.RV_CONTINUE if cef else None
        
        return cef.RV_CONTINUE if cef else None
    
    def on_resource_response(self, browser, frame, request, response, **kwargs):
        """
        Called when a resource response is received
        
        Args:
            browser: CEF browser instance
            frame: CEF frame
            request: CEF request object
            response: CEF response object
        """
        if not cef:
            return
        
        # This is where we could capture responses for analysis
        if self.interceptor_enabled:
            url = request.GetUrl() if hasattr(request, 'GetUrl') else ''
            status = response.GetStatus() if hasattr(response, 'GetStatus') else 0
            print(f"[Interceptor] Response: {status} for {url}")


class ResourceHandler:
    """
    Custom resource handler for more advanced request interception
    
    This allows complete control over request/response cycle
    """
    
    def __init__(self, django_bridge: DjangoBridge):
        """
        Initialize resource handler
        
        Args:
            django_bridge: DjangoBridge instance
        """
        self.bridge = django_bridge
        self.interceptor_enabled = False
    
    def GetResponseHeaders(self, response, response_length_out, redirect_url_out):
        """
        Called to get response headers
        
        Args:
            response: Response object
            response_length_out: Output parameter for response length
            redirect_url_out: Output parameter for redirect URL
        """
        # Set default headers
        response.SetMimeType("text/html")
        response.SetStatus(200)
    
    def ReadResponse(self, data_out, bytes_to_read, bytes_read_out, callback):
        """
        Called to read response data
        
        Args:
            data_out: Buffer to write response data
            bytes_to_read: Number of bytes to read
            bytes_read_out: Output parameter for bytes actually read
            callback: Callback to continue reading
            
        Returns:
            True if reading is complete, False otherwise
        """
        # This would be implemented for full request/response control
        return True
    
    def CanGetCookie(self, cookie):
        """
        Called to check if a cookie can be read
        
        Args:
            cookie: Cookie to check
            
        Returns:
            True to allow, False to deny
        """
        return True
    
    def CanSetCookie(self, cookie):
        """
        Called to check if a cookie can be set
        
        Args:
            cookie: Cookie to check
            
        Returns:
            True to allow, False to deny
        """
        return True
