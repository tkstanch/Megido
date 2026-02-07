#!/usr/bin/env python3
"""
Desktop Launcher for CEF Browser

This script launches the Megido security platform with a full CEF browser.
It can work in two modes:
1. Launch Django server and CEF browser together
2. Connect to an existing Django server

Usage:
    python browser/desktop_launcher.py                    # Launch both
    python browser/desktop_launcher.py --server-only      # Launch Django only
    python browser/desktop_launcher.py --browser-only     # Launch CEF only (expects Django running)
    python browser/desktop_launcher.py --django-url http://localhost:8000  # Custom Django URL
"""

import sys
import os
import argparse
import time
import threading
import subprocess
import signal

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from browser.cef_integration.browser_window import BrowserWindow
    CEF_AVAILABLE = True
except ImportError:
    CEF_AVAILABLE = False
    print("WARNING: CEF Python is not installed. Install with: pip install cefpython3")

try:
    import django
    from django.core.management import execute_from_command_line
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    print("WARNING: Django is not installed")


class DjangoServerLauncher:
    """
    Manages Django development server
    """
    
    def __init__(self, port: int = 8000, host: str = "127.0.0.1"):
        """
        Initialize Django server launcher
        
        Args:
            port: Port to run Django on
            host: Host to bind to
        """
        self.port = port
        self.host = host
        self.process = None
        self.thread = None
    
    def start(self):
        """Start Django development server"""
        if not DJANGO_AVAILABLE:
            print("ERROR: Django is not available. Cannot start server.")
            return False
        
        def run_server():
            """Run Django server in thread"""
            try:
                # Set up Django
                os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
                django.setup()
                
                print(f"Starting Django server on {self.host}:{self.port}")
                
                # Run migrations
                from django.core.management import call_command
                print("Running database migrations...")
                call_command('migrate', '--noinput', verbosity=0)
                
                # Start server
                from django.core.management.commands.runserver import Command as RunserverCommand
                server = RunserverCommand()
                server.handle(
                    addrport=f'{self.host}:{self.port}',
                    use_reloader=False,
                    verbosity=1
                )
            except Exception as e:
                print(f"Error starting Django server: {e}")
        
        self.thread = threading.Thread(target=run_server, daemon=True)
        self.thread.start()
        
        # Wait for server to start
        print("Waiting for Django server to start...")
        time.sleep(3)
        
        # Verify server is running
        try:
            import requests
            response = requests.get(f"http://{self.host}:{self.port}/", timeout=2)
            print(f"Django server is running (status: {response.status_code})")
            return True
        except Exception as e:
            print(f"Warning: Could not verify Django server: {e}")
            return False
    
    def stop(self):
        """Stop Django server"""
        if self.process:
            self.process.terminate()
            self.process.wait()


class CEFBrowserLauncher:
    """
    Manages CEF browser
    """
    
    def __init__(self, django_url: str = "http://127.0.0.1:8000"):
        """
        Initialize CEF browser launcher
        
        Args:
            django_url: URL of Django server
        """
        self.django_url = django_url
        self.browser_window = None
    
    def start(self):
        """Start CEF browser"""
        if not CEF_AVAILABLE:
            print("ERROR: CEF Python is not available. Cannot start browser.")
            print("Install with: pip install cefpython3")
            return False
        
        try:
            print(f"Starting CEF browser connected to {self.django_url}")
            
            # Create browser window
            self.browser_window = BrowserWindow(self.django_url)
            self.browser_window.create_browser(
                url=self.django_url,
                window_title="Megido Security - Desktop Browser",
                width=1400,
                height=900
            )
            
            print("CEF browser started successfully")
            print("Press Ctrl+C to exit")
            
            # Run message loop
            self.browser_window.message_loop()
            
            # Cleanup
            self.browser_window.shutdown()
            
            return True
        except Exception as e:
            print(f"Error starting CEF browser: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def stop(self):
        """Stop CEF browser"""
        if self.browser_window:
            self.browser_window.close()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Megido Security - Desktop Browser Launcher"
    )
    parser.add_argument(
        '--mode',
        choices=['both', 'server-only', 'browser-only'],
        default='both',
        help='Launch mode (default: both)'
    )
    parser.add_argument(
        '--django-url',
        default='http://127.0.0.1:8000',
        help='Django server URL (default: http://127.0.0.1:8000)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Django server port (default: 8000)'
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Django server host (default: 127.0.0.1)'
    )
    
    args = parser.parse_args()
    
    # Parse django-url to get host and port if needed
    if args.mode != 'browser-only':
        # Use provided host/port for server
        django_url = f"http://{args.host}:{args.port}"
    else:
        django_url = args.django_url
    
    print("=" * 70)
    print("Megido Security - Desktop Browser Launcher")
    print("=" * 70)
    print(f"Mode: {args.mode}")
    print(f"Django URL: {django_url}")
    print("=" * 70)
    
    django_launcher = None
    cef_launcher = None
    
    try:
        # Launch Django server if needed
        if args.mode in ['both', 'server-only']:
            django_launcher = DjangoServerLauncher(args.port, args.host)
            if not django_launcher.start():
                print("ERROR: Failed to start Django server")
                return 1
        
        # Launch CEF browser if needed
        if args.mode in ['both', 'browser-only']:
            if not CEF_AVAILABLE:
                print("\n" + "=" * 70)
                print("CEF Python is not installed!")
                print("=" * 70)
                print("To use the CEF desktop browser, install it with:")
                print("    pip install cefpython3")
                print("\nAlternatively, use the web-based iframe browser at:")
                print(f"    {django_url}/browser/")
                print("=" * 70)
                return 1
            
            cef_launcher = CEFBrowserLauncher(django_url)
            if not cef_launcher.start():
                print("ERROR: Failed to start CEF browser")
                return 1
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Cleanup
        if cef_launcher:
            cef_launcher.stop()
        if django_launcher:
            django_launcher.stop()
    
    print("Goodbye!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
