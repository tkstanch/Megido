#!/usr/bin/env python3
"""
Automated setup and launcher for CEF browser integration
Megido Security Testing Platform

This script automates the complete setup and launch process for the CEF browser integration.
It handles dependency installation, environment verification, Django server management,
and CEF browser launching.

Usage:
    python setup_cef_browser.py                    # Full setup + launch
    python setup_cef_browser.py --setup-only       # Only setup, don't launch
    python setup_cef_browser.py --launch-only      # Only launch (skip setup)
    python setup_cef_browser.py --check            # Check installation status
    python setup_cef_browser.py --port 8000        # Specify Django port
    python setup_cef_browser.py --debug            # Enable debug mode
"""

import sys
import os
import subprocess
import platform
import argparse
import time
import logging
from pathlib import Path
from typing import Optional, Tuple


class CEFSetup:
    """
    Automated setup and launcher for CEF browser integration
    """
    
    def __init__(self, debug: bool = False):
        """
        Initialize CEF setup
        
        Args:
            debug: Enable debug logging
        """
        self.os_name = platform.system()
        self.python_version = sys.version_info
        self.debug = debug
        self.base_dir = Path(__file__).parent.absolute()
        self.logs_dir = self.base_dir / "logs"
        
        # Setup logging
        self._setup_logging()
        
        # Track Django server process
        self.django_process = None
        
    def _setup_logging(self):
        """Setup logging configuration"""
        # Create logs directory if it doesn't exist
        self.logs_dir.mkdir(exist_ok=True)
        
        log_file = self.logs_dir / "cef_setup.log"
        log_level = logging.DEBUG if self.debug else logging.INFO
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"CEF Setup initialized - OS: {self.os_name}, Python: {self.python_version.major}.{self.python_version.minor}")
    
    def print_header(self, title: str):
        """Print formatted header"""
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70 + "\n")
    
    def print_status(self, message: str, status: str = "info"):
        """
        Print status message with appropriate symbol
        
        Args:
            message: Status message
            status: One of 'info', 'success', 'warning', 'error'
        """
        symbols = {
            'info': 'ℹ️ ',
            'success': '✅',
            'warning': '⚠️ ',
            'error': '❌'
        }
        symbol = symbols.get(status, 'ℹ️ ')
        print(f"{symbol} {message}")
        self.logger.info(f"[{status.upper()}] {message}")
    
    def check_prerequisites(self) -> bool:
        """
        Check Python version, pip, and other prerequisites
        
        Returns:
            True if all prerequisites are met, False otherwise
        """
        self.print_header("Checking Prerequisites")
        
        # Check Python version (3.7+)
        if self.python_version < (3, 7):
            self.print_status(
                f"Python 3.7+ is required. Current version: {self.python_version.major}.{self.python_version.minor}",
                "error"
            )
            return False
        
        self.print_status(
            f"Python version: {self.python_version.major}.{self.python_version.minor}.{self.python_version.micro}",
            "success"
        )
        
        # Check pip
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "--version"],
                check=True,
                capture_output=True,
                text=True
            )
            self.print_status("pip is available", "success")
        except subprocess.CalledProcessError:
            self.print_status("pip is not available or not working properly", "error")
            return False
        
        # Check operating system
        self.print_status(f"Operating System: {self.os_name}", "info")
        
        # Check if we're in a virtual environment (recommended)
        in_venv = hasattr(sys, 'real_prefix') or (
            hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
        )
        
        if in_venv:
            self.print_status("Running in virtual environment", "success")
        else:
            self.print_status(
                "Not running in virtual environment (recommended but not required)",
                "warning"
            )
        
        return True
    
    def install_dependencies(self) -> bool:
        """
        Install required dependencies
        
        Returns:
            True if installation succeeded, False otherwise
        """
        self.print_header("Installing Dependencies")
        
        dependencies = [
            "cefpython3",
            "requests",
            "Django>=6.0.0",
            "djangorestframework>=3.14.0"
        ]
        
        for dep in dependencies:
            self.print_status(f"Installing {dep}...", "info")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", dep],
                    check=True,
                    capture_output=True,
                    text=True
                )
                self.print_status(f"{dep} installed successfully", "success")
            except subprocess.CalledProcessError as e:
                self.print_status(f"Failed to install {dep}", "error")
                if self.debug:
                    self.logger.error(f"Error details: {e.stderr}")
                return False
        
        return True
    
    def verify_cef_files(self) -> bool:
        """
        Check if CEF integration files exist
        
        Returns:
            True if CEF files exist, False otherwise
        """
        self.print_header("Verifying CEF Integration Files")
        
        required_files = [
            self.base_dir / "browser" / "cef_integration" / "__init__.py",
            self.base_dir / "browser" / "cef_integration" / "browser_window.py",
            self.base_dir / "browser" / "cef_integration" / "django_bridge.py",
            self.base_dir / "browser" / "desktop_launcher.py"
        ]
        
        all_exist = True
        for file_path in required_files:
            if file_path.exists():
                self.print_status(f"Found: {file_path.relative_to(self.base_dir)}", "success")
            else:
                self.print_status(f"Missing: {file_path.relative_to(self.base_dir)}", "error")
                all_exist = False
        
        if not all_exist:
            self.print_status("Some CEF integration files are missing", "error")
            return False
        
        self.print_status("All CEF integration files are present", "success")
        return True
    
    def verify_django(self) -> bool:
        """
        Verify Django is installed and configured
        
        Returns:
            True if Django is configured properly, False otherwise
        """
        self.print_header("Verifying Django Configuration")
        
        # Check if Django is installed
        try:
            import django
            self.print_status(f"Django version: {django.get_version()}", "success")
        except ImportError:
            self.print_status("Django is not installed", "error")
            return False
        
        # Check if manage.py exists
        manage_py = self.base_dir / "manage.py"
        if not manage_py.exists():
            self.print_status("manage.py not found", "error")
            return False
        
        self.print_status("manage.py found", "success")
        
        # Check migrations
        self.print_status("Checking database migrations...", "info")
        try:
            result = subprocess.run(
                [sys.executable, "manage.py", "migrate", "--check"],
                cwd=str(self.base_dir),
                check=False,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.print_status("Database migrations are up to date", "success")
            else:
                self.print_status("Database migrations need to be run", "warning")
                self.print_status("Running migrations...", "info")
                subprocess.run(
                    [sys.executable, "manage.py", "migrate"],
                    cwd=str(self.base_dir),
                    check=True
                )
                self.print_status("Migrations completed", "success")
        except subprocess.CalledProcessError as e:
            self.print_status("Failed to run migrations", "error")
            if self.debug:
                self.logger.error(f"Error details: {e.stderr}")
            return False
        
        return True
    
    def check_cef_installed(self) -> bool:
        """
        Check if cefpython3 is installed and working
        
        Returns:
            True if CEF is installed, False otherwise
        """
        try:
            import cefpython3
            return True
        except ImportError:
            return False
    
    def start_django_server(self, port: int = 8000, host: str = "127.0.0.1") -> Optional[subprocess.Popen]:
        """
        Start Django development server
        
        Args:
            port: Port to run Django on
            host: Host to bind to
            
        Returns:
            Process object if successful, None otherwise
        """
        self.print_header("Starting Django Server")
        
        # Check if port is already in use
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            self.print_status(
                f"Port {port} is already in use. Django server might already be running.",
                "warning"
            )
            
            # Try to verify it's Django
            try:
                import requests
                response = requests.get(f"http://{host}:{port}/", timeout=2)
                self.print_status("Django server is already running", "success")
                return None  # Don't start a new one
            except:
                self.print_status(
                    f"Port {port} is in use by another application. Try a different port with --port",
                    "error"
                )
                return None
        
        self.print_status(f"Starting Django server on {host}:{port}...", "info")
        
        try:
            # Start Django server as a subprocess
            process = subprocess.Popen(
                [sys.executable, "manage.py", "runserver", f"{host}:{port}"],
                cwd=str(self.base_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to start
            self.print_status("Waiting for Django server to start...", "info")
            time.sleep(3)
            
            # Verify server is running
            try:
                import requests
                response = requests.get(f"http://{host}:{port}/", timeout=5)
                self.print_status(
                    f"Django server started successfully (status: {response.status_code})",
                    "success"
                )
                self.print_status(f"Access at: http://{host}:{port}/", "info")
                self.django_process = process
                return process
            except Exception as e:
                self.print_status(f"Warning: Could not verify Django server: {e}", "warning")
                self.django_process = process
                return process
                
        except Exception as e:
            self.print_status(f"Failed to start Django server: {e}", "error")
            return None
    
    def launch_cef_browser(self, django_url: str = "http://127.0.0.1:8000") -> bool:
        """
        Launch CEF browser window
        
        Args:
            django_url: URL of Django server
            
        Returns:
            True if browser launched successfully, False otherwise
        """
        self.print_header("Launching CEF Browser")
        
        if not self.check_cef_installed():
            self.print_status("CEF Python is not installed", "error")
            self.print_status("Install with: pip install cefpython3", "info")
            return False
        
        self.print_status(f"Launching CEF browser connected to {django_url}...", "info")
        
        try:
            # Import and launch browser
            from browser.desktop_launcher import CEFBrowserLauncher
            
            launcher = CEFBrowserLauncher(django_url)
            launcher.start()
            
            return True
            
        except KeyboardInterrupt:
            self.print_status("Browser closed by user", "info")
            return True
        except Exception as e:
            self.print_status(f"Failed to launch CEF browser: {e}", "error")
            if self.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def check_installation_status(self) -> dict:
        """
        Check current installation status
        
        Returns:
            Dictionary with status information
        """
        self.print_header("Installation Status Check")
        
        status = {
            'python_version_ok': self.python_version >= (3, 7),
            'cef_installed': self.check_cef_installed(),
            'cef_files_exist': False,
            'django_installed': False,
            'migrations_ok': False
        }
        
        # Check CEF files
        try:
            status['cef_files_exist'] = self.verify_cef_files()
        except:
            pass
        
        # Check Django
        try:
            import django
            status['django_installed'] = True
        except ImportError:
            pass
        
        # Print status
        self.print_status(
            f"Python {self.python_version.major}.{self.python_version.minor}.{self.python_version.micro}",
            "success" if status['python_version_ok'] else "error"
        )
        self.print_status(
            f"CEF Python {'installed' if status['cef_installed'] else 'NOT installed'}",
            "success" if status['cef_installed'] else "error"
        )
        self.print_status(
            f"Django {'installed' if status['django_installed'] else 'NOT installed'}",
            "success" if status['django_installed'] else "error"
        )
        self.print_status(
            f"CEF integration files {'exist' if status['cef_files_exist'] else 'NOT found'}",
            "success" if status['cef_files_exist'] else "error"
        )
        
        # Overall status
        all_ok = all(status.values())
        print("\n" + "=" * 70)
        if all_ok:
            self.print_status("✅ All checks passed! Ready to launch CEF browser.", "success")
        else:
            self.print_status("⚠️  Some checks failed. Run setup to fix issues.", "warning")
        print("=" * 70 + "\n")
        
        return status
    
    def run_setup(self) -> bool:
        """
        Run complete setup process
        
        Returns:
            True if setup succeeded, False otherwise
        """
        self.print_header("CEF Browser - Automated Setup")
        
        # Check prerequisites
        if not self.check_prerequisites():
            self.print_status("Prerequisites check failed", "error")
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            self.print_status("Dependency installation failed", "error")
            return False
        
        # Verify CEF files
        if not self.verify_cef_files():
            self.print_status("CEF files verification failed", "error")
            return False
        
        # Verify Django
        if not self.verify_django():
            self.print_status("Django verification failed", "error")
            return False
        
        self.print_header("Setup Complete!")
        self.print_status("CEF browser environment is ready", "success")
        return True
    
    def run(self, args: argparse.Namespace) -> int:
        """
        Main execution flow
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Check installation status only
            if args.check:
                self.check_installation_status()
                return 0
            
            # Setup only (no launch)
            if args.setup_only:
                if self.run_setup():
                    return 0
                else:
                    return 1
            
            # Launch only (skip setup)
            if args.launch_only:
                django_url = f"http://{args.host}:{args.port}"
                
                # Start Django if not running
                if not args.external_django:
                    self.start_django_server(args.port, args.host)
                
                # Launch browser
                if self.launch_cef_browser(django_url):
                    return 0
                else:
                    return 1
            
            # Full setup + launch
            if not self.run_setup():
                return 1
            
            django_url = f"http://{args.host}:{args.port}"
            self.start_django_server(args.port, args.host)
            
            if self.launch_cef_browser(django_url):
                return 0
            else:
                return 1
                
        except KeyboardInterrupt:
            self.print_status("\nShutdown requested...", "info")
            return 0
        except Exception as e:
            self.print_status(f"Unexpected error: {e}", "error")
            if self.debug:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            # Cleanup Django process
            if self.django_process:
                self.print_status("Stopping Django server...", "info")
                self.django_process.terminate()
                try:
                    self.django_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.django_process.kill()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Automated setup and launcher for CEF browser integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_cef_browser.py                    # Full setup + launch
  python setup_cef_browser.py --setup-only       # Only setup, don't launch
  python setup_cef_browser.py --launch-only      # Only launch (skip setup)
  python setup_cef_browser.py --check            # Check installation status
  python setup_cef_browser.py --port 8001        # Use different port
  python setup_cef_browser.py --debug            # Enable debug logging
        """
    )
    
    parser.add_argument(
        '--setup-only',
        action='store_true',
        help='Only run setup, do not launch browser'
    )
    parser.add_argument(
        '--launch-only',
        action='store_true',
        help='Only launch browser, skip setup checks'
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check installation status without making changes'
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
    parser.add_argument(
        '--external-django',
        action='store_true',
        help='Connect to external Django server (do not start one)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    args = parser.parse_args()
    
    # Validate conflicting options
    if args.setup_only and args.launch_only:
        print("Error: Cannot use --setup-only and --launch-only together")
        return 1
    
    if args.check and (args.setup_only or args.launch_only):
        print("Error: --check cannot be used with --setup-only or --launch-only")
        return 1
    
    # Create and run setup
    setup = CEFSetup(debug=args.debug)
    return setup.run(args)


if __name__ == "__main__":
    sys.exit(main())
