"""
Callback Endpoint Manager

This module manages callback endpoints for out-of-band (OOB) vulnerability verification.
Supports local servers, ngrok tunnels, and other public callback services.

Features:
- Start/stop local callback servers
- Integrate with ngrok for public URL exposure
- Support for Burp Collaborator, Interactsh, and custom endpoints
- Automatic tunnel management
- Callback verification and logging

Usage:
    from scanner.callback_manager import CallbackManager
    
    # Start local server with ngrok
    manager = CallbackManager()
    callback_url = manager.start_callback_server(use_ngrok=True)
    
    # Use callback_url in payloads
    # ...
    
    # Check for callbacks
    interactions = manager.get_interactions()
    
    # Cleanup
    manager.stop_callback_server()
"""

import os
import subprocess
import threading
import logging
import time
import json
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class CallbackRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for callback server."""
    
    interactions = []  # Class variable to store interactions
    
    def log_message(self, format, *args):
        """Override to use logger instead of stderr."""
        logger.info(f"Callback: {format % args}")
    
    def do_GET(self):
        """Handle GET requests."""
        self._handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        self._handle_request('POST')
    
    def _handle_request(self, method: str):
        """Handle any HTTP request."""
        # Extract request info
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)
        
        # Get headers
        headers = dict(self.headers)
        
        # Get body for POST
        body = None
        if method == 'POST':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        # Log interaction
        interaction = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'path': self.path,
            'query_params': query_params,
            'headers': headers,
            'body': body,
            'client_ip': self.client_address[0],
        }
        
        self.interactions.append(interaction)
        
        logger.info(f"Callback received: {method} {self.path} from {self.client_address[0]}")
        
        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')


class CallbackManager:
    """
    Manages callback endpoints for OOB vulnerability verification.
    
    Handles local callback servers, ngrok integration, and external services.
    """
    
    def __init__(self, port: int = 8888):
        """
        Initialize the callback manager.
        
        Args:
            port: Port for local callback server
        """
        self.port = port
        self.server = None
        self.server_thread = None
        self.ngrok_process = None
        self.ngrok_url = None
        self.callback_url = None
        self.is_running = False
        
        # External service settings
        self.external_endpoint = None
        
        logger.debug(f"CallbackManager initialized (port: {port})")
    
    def start_callback_server(self, use_ngrok: bool = False, 
                             ngrok_auth_token: Optional[str] = None) -> str:
        """
        Start the local callback server.
        
        Args:
            use_ngrok: Whether to expose via ngrok
            ngrok_auth_token: Optional ngrok auth token
        
        Returns:
            Public callback URL
        """
        if self.is_running:
            logger.warning("Callback server already running")
            return self.callback_url
        
        # Start local HTTP server
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), CallbackRequestHandler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            self.is_running = True
            
            logger.info(f"Callback server started on port {self.port}")
            
            # Setup callback URL
            if use_ngrok:
                self.callback_url = self._start_ngrok(ngrok_auth_token)
            else:
                self.callback_url = f"http://localhost:{self.port}"
            
            logger.info(f"Callback URL: {self.callback_url}")
            return self.callback_url
            
        except Exception as e:
            logger.error(f"Failed to start callback server: {e}")
            raise
    
    def _start_ngrok(self, auth_token: Optional[str] = None) -> str:
        """
        Start ngrok tunnel to expose local server.
        
        Args:
            auth_token: Optional ngrok auth token
        
        Returns:
            Public ngrok URL
        """
        # Check if ngrok is installed
        try:
            subprocess.run(['ngrok', 'version'], 
                         capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            logger.error("ngrok not found. Please install ngrok: https://ngrok.com/download")
            raise RuntimeError("ngrok not installed")
        
        # Set auth token if provided
        if auth_token:
            try:
                subprocess.run(['ngrok', 'config', 'add-authtoken', auth_token],
                             capture_output=True, check=True, timeout=10)
                logger.info("ngrok auth token configured")
            except Exception as e:
                logger.warning(f"Failed to set ngrok auth token: {e}")
        
        # Start ngrok
        try:
            self.ngrok_process = subprocess.Popen(
                ['ngrok', 'http', str(self.port), '--log=stdout'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for ngrok to start and get public URL
            time.sleep(3)  # Give ngrok time to start
            
            # Get ngrok URL from API
            try:
                response = requests.get('http://localhost:4040/api/tunnels', timeout=5)
                if response.status_code == 200:
                    tunnels = response.json().get('tunnels', [])
                    for tunnel in tunnels:
                        if tunnel.get('proto') == 'https':
                            self.ngrok_url = tunnel.get('public_url')
                            logger.info(f"ngrok tunnel established: {self.ngrok_url}")
                            return self.ngrok_url
            except Exception as e:
                logger.warning(f"Failed to get ngrok URL from API: {e}")
            
            # Fallback: try to parse from output
            logger.warning("Could not get ngrok URL from API, ngrok may not be running properly")
            raise RuntimeError("Failed to get ngrok URL")
            
        except Exception as e:
            logger.error(f"Failed to start ngrok: {e}")
            raise
    
    def stop_callback_server(self):
        """Stop the callback server and ngrok tunnel."""
        if not self.is_running:
            return
        
        # Stop HTTP server
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.server_thread = None
        
        # Stop ngrok
        if self.ngrok_process:
            self.ngrok_process.terminate()
            try:
                self.ngrok_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.ngrok_process.kill()
            self.ngrok_process = None
            self.ngrok_url = None
        
        self.is_running = False
        logger.info("Callback server stopped")
    
    def get_interactions(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get logged callback interactions.
        
        Args:
            since: Optional datetime to filter interactions after
        
        Returns:
            List of interaction dictionaries
        """
        interactions = CallbackRequestHandler.interactions
        
        if since:
            interactions = [
                i for i in interactions
                if datetime.fromisoformat(i['timestamp']) > since
            ]
        
        return interactions
    
    def clear_interactions(self):
        """Clear all logged interactions."""
        CallbackRequestHandler.interactions.clear()
        logger.debug("Cleared callback interactions")
    
    def verify_callback(self, payload_id: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Wait for and verify a callback with specific payload ID.
        
        Args:
            payload_id: Unique payload identifier to look for
            timeout: Maximum time to wait (seconds)
        
        Returns:
            Verification result dictionary
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check interactions for payload_id
            interactions = self.get_interactions()
            
            for interaction in interactions:
                # Check if payload_id is in path or query params
                if payload_id in interaction['path']:
                    return {
                        'verified': True,
                        'interaction': interaction,
                        'time_elapsed': time.time() - start_time,
                    }
            
            time.sleep(1)  # Poll interval
        
        return {
            'verified': False,
            'interaction': None,
            'time_elapsed': timeout,
        }
    
    def set_external_endpoint(self, endpoint_url: str):
        """
        Set an external callback endpoint (e.g., Burp Collaborator, Interactsh).
        
        Args:
            endpoint_url: URL of external callback service
        """
        self.external_endpoint = endpoint_url
        self.callback_url = endpoint_url
        logger.info(f"Using external callback endpoint: {endpoint_url}")
    
    def get_callback_url(self) -> Optional[str]:
        """
        Get the current callback URL.
        
        Returns:
            Callback URL or None if not configured
        """
        if self.external_endpoint:
            return self.external_endpoint
        
        if self.is_running:
            return self.callback_url
        
        return None
    
    @staticmethod
    def check_ngrok_installed() -> bool:
        """
        Check if ngrok is installed and available.
        
        Returns:
            True if ngrok is installed
        """
        try:
            result = subprocess.run(['ngrok', 'version'],
                                  capture_output=True,
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    @staticmethod
    def get_ngrok_installation_instructions() -> str:
        """
        Get instructions for installing ngrok.
        
        Returns:
            Installation instructions string
        """
        return """
ngrok Installation Instructions:

1. Download ngrok from https://ngrok.com/download
2. Extract the binary and move it to your PATH:
   
   Linux/macOS:
   $ unzip ngrok-*.zip
   $ sudo mv ngrok /usr/local/bin/
   
   Windows:
   - Extract ngrok.exe to C:\\Windows\\System32\\
   
3. Sign up for a free account at https://dashboard.ngrok.com/signup
4. Get your auth token from https://dashboard.ngrok.com/get-started/your-authtoken
5. Configure ngrok with your token:
   $ ngrok config add-authtoken <your_token>

6. Test ngrok:
   $ ngrok http 8888

For more information, visit: https://ngrok.com/docs/getting-started
"""
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_callback_server()


def get_callback_manager(config: Optional[Dict[str, Any]] = None) -> CallbackManager:
    """
    Factory function to get a configured CallbackManager instance.
    
    Args:
        config: Optional configuration dictionary with keys:
               - port: Port for local server
               - external_endpoint: External callback endpoint URL
               - use_ngrok: Whether to use ngrok
               - ngrok_auth_token: ngrok auth token
    
    Returns:
        Configured CallbackManager instance
    """
    config = config or {}
    
    manager = CallbackManager(port=config.get('port', 8888))
    
    # Set external endpoint if provided
    if config.get('external_endpoint'):
        manager.set_external_endpoint(config['external_endpoint'])
    
    # Start server if requested
    if config.get('auto_start', False):
        manager.start_callback_server(
            use_ngrok=config.get('use_ngrok', False),
            ngrok_auth_token=config.get('ngrok_auth_token')
        )
    
    return manager
