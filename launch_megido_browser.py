#!/usr/bin/env python3
"""
Launch Megido Browser with mitmproxy Integration

This script launches all components needed for the Megido desktop browser:
1. Django development server (if not running)
2. mitmproxy with the Megido addon
3. PyQt6 desktop browser

Usage:
    python launch_megido_browser.py
    python launch_megido_browser.py --django-port 8000 --proxy-port 8080
    python launch_megido_browser.py --external-django --django-url http://localhost:8000
"""

import sys
import os
import time
import signal
import subprocess
import argparse
import socket
from pathlib import Path


class MegidoLauncher:
    """
    Launcher for Megido desktop browser with all components
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.absolute()
        self.django_process = None
        self.proxy_process = None
        self.browser_process = None
    
    def print_header(self, title):
        """Print formatted header"""
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70 + "\n")
    
    def print_status(self, message, status="info"):
        """Print status message"""
        symbols = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌'
        }
        symbol = symbols.get(status, 'ℹ️')
        print(f"{symbol} {message}")
    
    def check_port(self, host, port):
        """Check if a port is already in use"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    
    def check_dependencies(self):
        """Check if required dependencies are installed"""
        self.print_header("Checking Dependencies")
        
        dependencies = {
            'django': 'Django',
            'mitmproxy': 'mitmproxy',
            'PyQt6': 'PyQt6'
        }
        
        all_ok = True
        for module, name in dependencies.items():
            try:
                __import__(module)
                self.print_status(f"{name} is installed", "success")
            except ImportError:
                self.print_status(f"{name} is NOT installed", "error")
                all_ok = False
        
        return all_ok
    
    def start_django(self, host, port):
        """Start Django development server"""
        self.print_header("Starting Django Server")
        
        # Check if port is in use
        if self.check_port(host, port):
            self.print_status(
                f"Port {port} is already in use. Assuming Django is running.",
                "warning"
            )
            return True
        
        try:
            # Set environment
            env = os.environ.copy()
            env['DJANGO_SETTINGS_MODULE'] = 'megido_security.settings'
            env['USE_SQLITE'] = 'true'  # Use SQLite for simplicity
            
            # Start Django
            self.print_status(f"Starting Django on {host}:{port}...", "info")
            
            self.django_process = subprocess.Popen(
                [sys.executable, 'manage.py', 'runserver', f'{host}:{port}'],
                cwd=str(self.base_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for Django to start
            self.print_status("Waiting for Django to start...", "info")
            time.sleep(3)
            
            # Verify
            if self.check_port(host, port):
                self.print_status(f"Django server started on http://{host}:{port}", "success")
                return True
            else:
                self.print_status("Django server may not have started properly", "warning")
                return False
                
        except Exception as e:
            self.print_status(f"Failed to start Django: {e}", "error")
            return False
    
    def start_mitmproxy(self, port, django_url):
        """Start mitmproxy with Megido addon"""
        self.print_header("Starting mitmproxy")
        
        # Check if port is in use
        if self.check_port('localhost', port):
            self.print_status(
                f"Port {port} is already in use. Assuming mitmproxy is running.",
                "warning"
            )
            return True
        
        try:
            addon_path = self.base_dir / 'proxy_addon.py'
            
            if not addon_path.exists():
                self.print_status(f"Addon not found: {addon_path}", "error")
                return False
            
            self.print_status(f"Starting mitmproxy on port {port}...", "info")
            
            # Start mitmproxy in headless mode (mitmdump)
            self.proxy_process = subprocess.Popen(
                [
                    'mitmdump',
                    '-s', str(addon_path),
                    '--set', f'api_url={django_url}',
                    '--set', 'source_app=browser',
                    '--listen-port', str(port),
                    '--ssl-insecure'  # For testing
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Wait for mitmproxy to start
            self.print_status("Waiting for mitmproxy to start...", "info")
            time.sleep(2)
            
            self.print_status(f"mitmproxy started on port {port}", "success")
            self.print_status("To intercept HTTPS, install certificate from http://mitm.it", "info")
            return True
            
        except Exception as e:
            self.print_status(f"Failed to start mitmproxy: {e}", "error")
            return False
    
    def start_browser(self, django_url, proxy_port):
        """Start PyQt6 browser"""
        self.print_header("Starting Megido Browser")
        
        try:
            browser_script = self.base_dir / 'desktop_browser' / 'megido_browser.py'
            
            if not browser_script.exists():
                self.print_status(f"Browser script not found: {browser_script}", "error")
                return False
            
            self.print_status("Launching browser...", "info")
            
            # Build command
            cmd = [
                sys.executable,
                str(browser_script),
                '--django-url', django_url
            ]
            
            # Add proxy configuration if enabled
            if proxy_port is not None:
                cmd.extend(['--proxy-port', str(proxy_port)])
            
            # Start browser
            self.browser_process = subprocess.Popen(
                cmd,
                cwd=str(self.base_dir)
            )
            
            self.print_status("Browser launched", "success")
            if proxy_port is not None:
                self.print_status(f"Browser configured to use proxy on port {proxy_port}", "info")
            else:
                self.print_status("Browser running without proxy", "info")
            return True
            
        except Exception as e:
            self.print_status(f"Failed to start browser: {e}", "error")
            return False
    
    def wait_for_browser(self):
        """Wait for browser to close"""
        if self.browser_process:
            try:
                self.print_status("Browser is running. Close the browser window to exit.", "info")
                self.browser_process.wait()
            except KeyboardInterrupt:
                self.print_status("Shutdown requested...", "info")
    
    def cleanup(self):
        """Stop all processes"""
        self.print_header("Shutting Down")
        
        # Stop browser
        if self.browser_process and self.browser_process.poll() is None:
            self.print_status("Stopping browser...", "info")
            self.browser_process.terminate()
            try:
                self.browser_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.browser_process.kill()
        
        # Stop mitmproxy
        if self.proxy_process and self.proxy_process.poll() is None:
            self.print_status("Stopping mitmproxy...", "info")
            self.proxy_process.terminate()
            try:
                self.proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
        
        # Stop Django
        if self.django_process and self.django_process.poll() is None:
            self.print_status("Stopping Django...", "info")
            self.django_process.terminate()
            try:
                self.django_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.django_process.kill()
        
        self.print_status("All processes stopped", "success")
    
    def run(self, args):
        """Main execution"""
        try:
            self.print_header("Megido Security - Desktop Browser Launcher")
            
            # Check dependencies
            if not self.check_dependencies():
                self.print_status("Missing dependencies. Install them first:", "error")
                self.print_status("pip install -r requirements.txt", "info")
                return 1
            
            django_url = args.django_url if args.external_django else f"http://{args.django_host}:{args.django_port}"
            
            # Start Django (if needed)
            if not args.external_django:
                if not self.start_django(args.django_host, args.django_port):
                    return 1
            else:
                self.print_status(f"Using external Django at {django_url}", "info")
            
            # Start mitmproxy (if enabled)
            if not args.no_proxy:
                if not self.start_mitmproxy(args.proxy_port, django_url):
                    return 1
                proxy_port = args.proxy_port
            else:
                self.print_status("mitmproxy disabled", "info")
                proxy_port = None
            
            # Start browser
            if not self.start_browser(django_url, proxy_port):
                return 1
            
            # Wait for browser to close
            self.wait_for_browser()
            
            return 0
            
        except KeyboardInterrupt:
            self.print_status("Interrupted by user", "info")
            return 0
        except Exception as e:
            self.print_status(f"Unexpected error: {e}", "error")
            import traceback
            traceback.print_exc()
            return 1
        finally:
            self.cleanup()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Launch Megido Browser with mitmproxy Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--django-host',
        default='127.0.0.1',
        help='Django server host (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--django-port',
        type=int,
        default=8000,
        help='Django server port (default: 8000)'
    )
    parser.add_argument(
        '--django-url',
        default='http://localhost:8000',
        help='Django server URL (for external Django, default: http://localhost:8000)'
    )
    parser.add_argument(
        '--proxy-port',
        type=int,
        default=8080,
        help='mitmproxy port (default: 8080)'
    )
    parser.add_argument(
        '--no-proxy',
        action='store_true',
        help='Disable mitmproxy (launch browser without proxy)'
    )
    parser.add_argument(
        '--external-django',
        action='store_true',
        help='Connect to external Django server (do not start one)'
    )
    
    args = parser.parse_args()
    
    # Create and run launcher
    launcher = MegidoLauncher()
    sys.exit(launcher.run(args))


if __name__ == '__main__':
    main()
