# CEF Browser Configuration
# 
# This file contains example configuration settings for the CEF browser.
# Copy this to `cef_config.py` and customize as needed.

# Django Backend Configuration
DJANGO_URL = "http://127.0.0.1:8000"
DJANGO_HOST = "127.0.0.1"
DJANGO_PORT = 8000

# Browser Window Configuration
BROWSER_WINDOW_TITLE = "Megido Security - CEF Browser"
BROWSER_WINDOW_WIDTH = 1400
BROWSER_WINDOW_HEIGHT = 900

# CEF Engine Settings
CEF_SETTINGS = {
    # Debug mode (enables verbose logging)
    "debug": False,
    
    # Log severity level
    # Options: LOGSEVERITY_DEFAULT, LOGSEVERITY_VERBOSE, LOGSEVERITY_INFO, 
    #          LOGSEVERITY_WARNING, LOGSEVERITY_ERROR, LOGSEVERITY_DISABLE
    "log_severity": "LOGSEVERITY_INFO",
    
    # Log file path (set to empty string to disable file logging)
    "log_file": "cef_debug.log",
    
    # Browser cache directory
    "cache_path": "cef_cache",
    
    # User agent string (leave empty for default Chromium UA)
    "user_agent": "Megido-CEF-Browser/1.0 (Chromium)",
    
    # Browser locale
    "locale": "en-US",
    
    # Enable remote debugging port (0 to disable)
    "remote_debugging_port": 0,
}

# Browser Settings
BROWSER_SETTINGS = {
    # Allow file access from file URLs
    "file_access_from_file_urls_allowed": True,
    
    # Allow universal access from file URLs
    "universal_access_from_file_urls_allowed": True,
    
    # Disable web security (use with caution!)
    "web_security_disabled": False,
    
    # Enable JavaScript
    "javascript_enabled": True,
    
    # Enable plugins
    "plugins_enabled": False,
    
    # Background color (RGB)
    "background_color": 0xFFFFFF,
}

# Context Menu Configuration
CONTEXT_MENU = {
    # Enable context menu
    "enabled": True,
    
    # Show navigation items (back, forward, reload)
    "navigation": True,
    
    # Show print option
    "print": True,
    
    # Show view source option
    "view_source": True,
    
    # Show external browser option
    "external_browser": True,
    
    # Show DevTools option
    "devtools": True,
}

# Request Interception Configuration
INTERCEPTOR = {
    # Enable request interception by default
    "enabled_by_default": False,
    
    # Intercept all requests (including images, CSS, etc.)
    "intercept_all_resources": False,
    
    # Only intercept main frame requests
    "main_frame_only": True,
    
    # Automatically forward requests after timeout (seconds)
    # Set to 0 to require manual forwarding
    "auto_forward_timeout": 0,
}

# Session Configuration
SESSION = {
    # Default session name
    "default_name": "CEF Browser Session",
    
    # Auto-save session on exit
    "auto_save": True,
    
    # Sync cookies with Django
    "sync_cookies": True,
    
    # Sync local storage with Django
    "sync_local_storage": False,
}

# Keyboard Shortcuts
KEYBOARD_SHORTCUTS = {
    # F12: Open DevTools
    "devtools": "F12",
    
    # Ctrl+R: Reload
    "reload": "Ctrl+R",
    
    # Alt+Left: Go back
    "back": "Alt+Left",
    
    # Alt+Right: Go forward
    "forward": "Alt+Right",
    
    # Ctrl+F: Find in page
    "find": "Ctrl+F",
}

# Advanced Options
ADVANCED = {
    # Enable GPU acceleration
    "gpu_acceleration": True,
    
    # Enable smooth scrolling
    "smooth_scrolling": True,
    
    # Maximum memory cache size (MB)
    "max_cache_size_mb": 100,
    
    # Persist session on crash
    "persist_session_on_crash": True,
    
    # Auto-update check (requires network)
    "check_for_updates": False,
}

# Developer Options (for debugging)
DEVELOPER = {
    # Show console messages in terminal
    "show_console": False,
    
    # Log JavaScript errors
    "log_js_errors": True,
    
    # Log network requests
    "log_requests": False,
    
    # Enable performance profiling
    "enable_profiling": False,
}
