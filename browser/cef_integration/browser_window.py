"""
Browser Window - Main CEF browser window with Megido toolbar

This module creates the CEF browser window with integrated toolbar for all Megido apps.
"""

import sys
import os
import platform
from typing import Optional, List, Dict, Any

try:
    from cefpython3 import cefpython as cef
except ImportError:
    # CEF Python not installed - provide helpful error message
    cef = None

from .django_bridge import DjangoBridge
from .session_manager import SessionManager
from .request_handler import RequestHandler


class BrowserWindow:
    """
    Main CEF browser window with Megido app integration
    """
    
    def __init__(self, django_url: str = "http://127.0.0.1:8000"):
        """
        Initialize browser window
        
        Args:
            django_url: Base URL of Django server
        """
        if not cef:
            raise ImportError(
                "CEF Python is not installed. Please install it with: pip install cefpython3"
            )
        
        self.django_url = django_url
        self.bridge = DjangoBridge(django_url)
        self.session_manager = SessionManager(self.bridge)
        self.request_handler = RequestHandler(self.bridge)
        
        self.browser = None
        self.enabled_apps: List[Dict[str, Any]] = []
        self.interceptor_enabled = False
        
        # Initialize CEF
        self._initialize_cef()
    
    def _initialize_cef(self):
        """Initialize CEF with appropriate settings"""
        sys.excepthook = cef.ExceptHook  # To shutdown CEF properly on error
        
        # CEF settings
        settings = {
            "debug": False,
            "log_severity": cef.LOGSEVERITY_INFO,
            "log_file": "cef_debug.log",
            "cache_path": "cef_cache",
            "user_agent": "Megido-CEF-Browser/1.0 (Chromium)",
            "context_menu": {
                "enabled": True,
                "navigation": True,
                "print": True,
                "view_source": True,
                "external_browser": True,
                "devtools": True,
            }
        }
        
        cef.Initialize(settings)
    
    def create_browser(self, url: Optional[str] = None, 
                      window_title: str = "Megido Security - CEF Browser",
                      width: int = 1400, height: int = 900):
        """
        Create and display the browser window
        
        Args:
            url: Initial URL to load (defaults to Django homepage)
            window_title: Window title
            width: Window width in pixels
            height: Window height in pixels
        """
        if not url:
            url = self.django_url
        
        # Create browser window
        window_info = cef.WindowInfo()
        window_info.SetAsChild(0)  # Create as top-level window
        
        # Browser settings
        browser_settings = {
            "file_access_from_file_urls_allowed": True,
            "universal_access_from_file_urls_allowed": True,
            "web_security_disabled": False,
        }
        
        # Create browser instance
        self.browser = cef.CreateBrowserSync(
            window_info=window_info,
            url=url,
            settings=browser_settings,
            window_title=window_title
        )
        
        # Set handlers
        self.browser.SetClientHandler(LoadHandler(self))
        self.browser.SetClientHandler(RequestHandler(self.bridge))
        
        # Start session
        self.session_manager.start_session(window_title)
        
        # Load enabled apps
        self._load_enabled_apps()
    
    def _load_enabled_apps(self):
        """Load enabled apps from Django"""
        self.enabled_apps = self.bridge.get_enabled_apps()
        print(f"Loaded {len(self.enabled_apps)} enabled apps")
    
    def navigate(self, url: str):
        """
        Navigate to a URL
        
        Args:
            url: URL to navigate to
        """
        if self.browser:
            self.browser.LoadUrl(url)
            # Log navigation
            self.session_manager.log_navigation(url)
    
    def go_back(self):
        """Navigate back"""
        if self.browser and self.browser.CanGoBack():
            self.browser.GoBack()
    
    def go_forward(self):
        """Navigate forward"""
        if self.browser and self.browser.CanGoForward():
            self.browser.GoForward()
    
    def reload(self):
        """Reload current page"""
        if self.browser:
            self.browser.Reload()
    
    def stop(self):
        """Stop loading current page"""
        if self.browser:
            self.browser.StopLoad()
    
    def get_url(self) -> str:
        """
        Get current URL
        
        Returns:
            Current URL or empty string
        """
        if self.browser:
            return self.browser.GetUrl()
        return ""
    
    def toggle_interceptor(self) -> bool:
        """
        Toggle interceptor on/off
        
        Returns:
            New interceptor state
        """
        self.interceptor_enabled = not self.interceptor_enabled
        result = self.bridge.toggle_interceptor(self.interceptor_enabled)
        
        if result.get('success'):
            self.request_handler.interceptor_enabled = self.interceptor_enabled
            print(f"Interceptor {'enabled' if self.interceptor_enabled else 'disabled'}")
            return self.interceptor_enabled
        else:
            # Revert on failure
            self.interceptor_enabled = not self.interceptor_enabled
            print(f"Failed to toggle interceptor: {result.get('error')}")
            return self.interceptor_enabled
    
    def trigger_app(self, app_name: str, target_url: Optional[str] = None):
        """
        Trigger a Megido app action
        
        Args:
            app_name: Name of the app to trigger
            target_url: Target URL (defaults to current URL)
        """
        if not target_url:
            target_url = self.get_url()
        
        print(f"Triggering app: {app_name} on {target_url}")
        
        # Log the interaction
        self.session_manager.log_app_action(
            app_name=app_name,
            action=f"triggered_from_cef_browser",
            target_url=target_url,
            result="Action initiated from CEF browser"
        )
        
        # In a full implementation, this would:
        # 1. Navigate to the app's page with context
        # 2. Pass the target URL as a parameter
        # 3. Auto-populate forms or trigger actions
        
        # For now, navigate to the app's page
        app_url = f"{self.django_url}/{app_name}/"
        self.navigate(app_url)
    
    def show_dev_tools(self):
        """Show Chrome Developer Tools"""
        if self.browser:
            self.browser.ShowDevTools()
    
    def close(self):
        """Close the browser window"""
        if self.browser:
            self.browser.CloseBrowser()
        self.session_manager.end_session()
    
    def message_loop(self):
        """Run the CEF message loop"""
        cef.MessageLoop()
    
    def shutdown(self):
        """Shutdown CEF"""
        cef.Shutdown()


class LoadHandler:
    """
    Handler for browser load events
    """
    
    def __init__(self, browser_window: BrowserWindow):
        """
        Initialize load handler
        
        Args:
            browser_window: BrowserWindow instance
        """
        self.browser_window = browser_window
    
    def OnLoadStart(self, browser, frame, **kwargs):
        """
        Called when page load starts
        
        Args:
            browser: CEF browser instance
            frame: CEF frame
        """
        if frame.IsMain():
            url = browser.GetUrl()
            print(f"Loading: {url}")
    
    def OnLoadEnd(self, browser, frame, http_code, **kwargs):
        """
        Called when page load completes
        
        Args:
            browser: CEF browser instance
            frame: CEF frame
            http_code: HTTP status code
        """
        if frame.IsMain():
            url = browser.GetUrl()
            print(f"Loaded: {url} (Status: {http_code})")
            
            # Log navigation to session
            # Get page title via JavaScript
            browser.ExecuteJavascript(
                "document.title",
                onSuccess=lambda title: self.browser_window.session_manager.log_navigation(
                    url, title if title else ""
                )
            )
    
    def OnLoadError(self, browser, frame, error_code, error_text, failed_url, **kwargs):
        """
        Called when page load fails
        
        Args:
            browser: CEF browser instance
            frame: CEF frame
            error_code: Error code
            error_text: Error message
            failed_url: URL that failed to load
        """
        if frame.IsMain():
            print(f"Load error: {error_text} ({error_code}) for {failed_url}")


class KeyboardHandler:
    """
    Handler for keyboard events
    """
    
    def OnPreKeyEvent(self, browser, event, event_handle, **kwargs):
        """
        Called before key event is processed
        
        Args:
            browser: CEF browser instance
            event: Keyboard event
            event_handle: Event handle
            
        Returns:
            Tuple (is_keyboard_shortcut, suppress_keyboard_event)
        """
        # F12 for dev tools
        if event.get("windows_key_code") == 123:  # F12
            browser.ShowDevTools()
            return (True, True)
        
        # Ctrl+R for reload
        if event.get("windows_key_code") == 82 and event.get("modifiers") & cef.EVENTFLAG_CONTROL_DOWN:
            browser.Reload()
            return (True, True)
        
        return (False, False)
