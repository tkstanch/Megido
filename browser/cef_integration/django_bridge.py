"""
Django Bridge - Communication layer between CEF browser and Django backend

This module handles all HTTP communication between the CEF browser and Django API endpoints.
"""

import requests
import json
from typing import Dict, List, Optional, Any


class DjangoBridge:
    """
    Bridge class to communicate with Django REST API from CEF browser
    """
    
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        """
        Initialize Django bridge
        
        Args:
            base_url: Base URL of Django server (default: http://127.0.0.1:8000)
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'Megido-CEF-Browser/1.0'
        })
    
    def get_enabled_apps(self) -> List[Dict[str, Any]]:
        """
        Fetch list of enabled apps from Django
        
        Returns:
            List of enabled app configurations
        """
        try:
            response = self.session.get(f"{self.base_url}/browser/api/enabled-apps/")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching enabled apps: {e}")
            return []
    
    def get_interceptor_status(self) -> Dict[str, Any]:
        """
        Get current interceptor status from Django
        
        Returns:
            Dictionary with interceptor status
        """
        try:
            response = self.session.get(f"{self.base_url}/browser/api/interceptor-status/")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching interceptor status: {e}")
            return {'is_enabled': False}
    
    def toggle_interceptor(self, enabled: bool) -> Dict[str, Any]:
        """
        Toggle interceptor status
        
        Args:
            enabled: True to enable, False to disable
            
        Returns:
            Response from Django API
        """
        try:
            response = self.session.post(
                f"{self.base_url}/browser/api/interceptor-status/",
                json={'is_enabled': enabled}
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error toggling interceptor: {e}")
            return {'success': False, 'error': str(e)}
    
    def add_history(self, session_id: int, url: str, title: str = "") -> Dict[str, Any]:
        """
        Add browser history entry to Django
        
        Args:
            session_id: Browser session ID
            url: Visited URL
            title: Page title
            
        Returns:
            Response from Django API
        """
        try:
            response = self.session.post(
                f"{self.base_url}/browser/api/history/",
                json={
                    'session_id': session_id,
                    'url': url,
                    'title': title
                }
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error adding history: {e}")
            return {'success': False, 'error': str(e)}
    
    def log_app_interaction(self, session_id: int, app_name: str, 
                           action: str, target_url: str = "", 
                           result: str = "") -> Dict[str, Any]:
        """
        Log app interaction to Django
        
        Args:
            session_id: Browser session ID
            app_name: Name of the app
            action: Action performed
            target_url: Target URL
            result: Result of the action
            
        Returns:
            Response from Django API
        """
        try:
            response = self.session.post(
                f"{self.base_url}/browser/api/interaction/",
                json={
                    'session_id': session_id,
                    'app_name': app_name,
                    'action': action,
                    'target_url': target_url,
                    'result': result
                }
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error logging app interaction: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_session(self, session_name: str = "CEF Browser Session") -> Optional[int]:
        """
        Create a new browser session in Django
        
        Args:
            session_name: Name for the session
            
        Returns:
            Session ID or None on error
        """
        try:
            # For now, we'll use the direct Django models through HTTP
            # In a real implementation, you'd have an API endpoint for this
            # This is a placeholder - actual implementation would need an endpoint
            return 1  # Default session ID for now
        except Exception as e:
            print(f"Error creating session: {e}")
            return None
    
    def check_server_status(self) -> bool:
        """
        Check if Django server is running and accessible
        
        Returns:
            True if server is accessible, False otherwise
        """
        try:
            response = self.session.get(f"{self.base_url}/", timeout=2)
            return response.status_code in [200, 301, 302]
        except requests.RequestException:
            return False
