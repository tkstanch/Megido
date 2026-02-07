#!/usr/bin/env python3
"""
CEF Browser Example - Simple demonstration of CEF integration

This script demonstrates basic usage of the CEF browser integration.
It can be used as a reference for implementing custom CEF browser features.

Usage:
    python browser/cef_example.py
    python browser/cef_example.py --url https://example.com
"""

import sys
import os
import argparse

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Check if CEF is available
try:
    from cefpython3 import cefpython as cef
    CEF_AVAILABLE = True
except ImportError:
    CEF_AVAILABLE = False
    print("ERROR: CEF Python is not installed")
    print("Install with: pip install cefpython3")
    sys.exit(1)

from browser.cef_integration.browser_window import BrowserWindow
from browser.cef_integration.django_bridge import DjangoBridge


def simple_example(url="http://127.0.0.1:8000"):
    """
    Simple example: Create a basic CEF browser window
    
    Args:
        url: URL to load
    """
    print("=" * 70)
    print("CEF Browser - Simple Example")
    print("=" * 70)
    print(f"Loading: {url}")
    print()
    print("Instructions:")
    print("  - Navigate normally in the browser")
    print("  - Press F12 for Developer Tools")
    print("  - Press Ctrl+R to reload")
    print("  - Close window or Ctrl+C to exit")
    print("=" * 70)
    print()
    
    try:
        # Create browser window
        browser = BrowserWindow(url)
        browser.create_browser(
            url=url,
            window_title="Megido CEF Browser - Simple Example",
            width=1200,
            height=800
        )
        
        # Run browser message loop
        browser.message_loop()
        
        # Cleanup
        browser.shutdown()
        
        print("\nBrowser closed successfully")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


def bridge_example():
    """
    Bridge example: Demonstrate Django API communication
    """
    print("=" * 70)
    print("Django Bridge - API Communication Example")
    print("=" * 70)
    print()
    
    # Create bridge
    bridge = DjangoBridge("http://127.0.0.1:8000")
    
    # Check if Django server is running
    print("Checking Django server status...")
    if bridge.check_server_status():
        print("✓ Django server is running")
    else:
        print("✗ Django server is not accessible")
        print("  Start it with: python manage.py runserver")
        return 1
    
    # Get enabled apps
    print("\nFetching enabled apps...")
    apps = bridge.get_enabled_apps()
    if apps:
        print(f"✓ Found {len(apps)} enabled apps:")
        for app in apps:
            print(f"  - {app.get('display_name', app.get('app_name', 'Unknown'))}")
    else:
        print("  No apps found or error occurred")
    
    # Get interceptor status
    print("\nChecking interceptor status...")
    status = bridge.get_interceptor_status()
    if status:
        is_enabled = status.get('is_enabled', False)
        print(f"✓ Interceptor is {'ENABLED' if is_enabled else 'DISABLED'}")
    else:
        print("  Could not get interceptor status")
    
    print("\n" + "=" * 70)
    print("Bridge example completed")
    print("=" * 70)
    
    return 0


def session_example():
    """
    Session example: Demonstrate session management
    """
    print("=" * 70)
    print("Session Manager - Example")
    print("=" * 70)
    print()
    
    from browser.cef_integration.session_manager import SessionManager
    
    # Create bridge and session manager
    bridge = DjangoBridge("http://127.0.0.1:8000")
    session_manager = SessionManager(bridge)
    
    # Start session
    print("Starting browser session...")
    session_id = session_manager.start_session("Example Session")
    print(f"✓ Session started with ID: {session_id}")
    
    # Log some navigation
    print("\nLogging navigation events...")
    session_manager.log_navigation("https://example.com", "Example Domain")
    print("✓ Logged: https://example.com")
    
    session_manager.log_navigation("https://github.com", "GitHub")
    print("✓ Logged: https://github.com")
    
    # Log app interaction
    print("\nLogging app interaction...")
    session_manager.log_app_action(
        app_name="scanner",
        action="scan_page",
        target_url="https://example.com",
        result="Scan completed successfully"
    )
    print("✓ Logged scanner interaction")
    
    # End session
    print("\nEnding session...")
    session_manager.end_session()
    print("✓ Session ended")
    
    print("\n" + "=" * 70)
    print("Session example completed")
    print("=" * 70)
    
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="CEF Browser Integration Examples"
    )
    parser.add_argument(
        '--example',
        choices=['simple', 'bridge', 'session'],
        default='simple',
        help='Which example to run (default: simple)'
    )
    parser.add_argument(
        '--url',
        default='http://127.0.0.1:8000',
        help='URL to load (for simple example)'
    )
    
    args = parser.parse_args()
    
    if args.example == 'simple':
        return simple_example(args.url)
    elif args.example == 'bridge':
        return bridge_example()
    elif args.example == 'session':
        return session_example()
    else:
        print(f"Unknown example: {args.example}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
