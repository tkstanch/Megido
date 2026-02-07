"""
Helper functions for automated CEF browser setup

This module provides utility functions used by the setup_cef_browser.py script.
"""

import sys
import subprocess
import platform
from pathlib import Path
from typing import Tuple, Optional


def check_python_version(min_version: Tuple[int, int] = (3, 7)) -> bool:
    """
    Check if Python version meets minimum requirements
    
    Args:
        min_version: Minimum required Python version as (major, minor)
        
    Returns:
        True if version is sufficient, False otherwise
    """
    current = sys.version_info
    return (current.major, current.minor) >= min_version


def get_os_info() -> dict:
    """
    Get operating system information
    
    Returns:
        Dictionary with OS name, version, and platform details
    """
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'platform': sys.platform
    }


def check_pip_installed() -> bool:
    """
    Check if pip is installed and working
    
    Returns:
        True if pip is available, False otherwise
    """
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def install_package(package_name: str, version: Optional[str] = None) -> bool:
    """
    Install a Python package using pip
    
    Args:
        package_name: Name of the package to install
        version: Optional version specifier (e.g., ">=6.0.0")
        
    Returns:
        True if installation succeeded, False otherwise
    """
    package_spec = package_name
    if version:
        package_spec = f"{package_name}{version}"
    
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package_spec],
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def check_package_installed(package_name: str) -> bool:
    """
    Check if a Python package is installed
    
    Args:
        package_name: Name of the package to check
        
    Returns:
        True if package is installed, False otherwise
    """
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False


def check_port_available(host: str, port: int) -> bool:
    """
    Check if a port is available for use
    
    Args:
        host: Host address to check
        port: Port number to check
        
    Returns:
        True if port is available, False if in use
    """
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result != 0
    except:
        return False


def verify_django_server(url: str, timeout: int = 5) -> bool:
    """
    Verify Django server is running and responding
    
    Args:
        url: URL of Django server to check
        timeout: Request timeout in seconds
        
    Returns:
        True if server is responding, False otherwise
    """
    try:
        import requests
        response = requests.get(url, timeout=timeout)
        return response.status_code in [200, 301, 302, 404]
    except:
        return False


def in_virtual_environment() -> bool:
    """
    Check if running in a virtual environment
    
    Returns:
        True if in a virtual environment, False otherwise
    """
    return hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )


def get_project_root() -> Path:
    """
    Get the project root directory
    
    Returns:
        Path to project root
    """
    # This file is in browser/cef_integration/
    return Path(__file__).parent.parent.parent


def verify_file_exists(file_path: Path) -> bool:
    """
    Verify a file exists
    
    Args:
        file_path: Path to file to check
        
    Returns:
        True if file exists, False otherwise
    """
    return file_path.exists() and file_path.is_file()


def verify_directory_exists(dir_path: Path) -> bool:
    """
    Verify a directory exists
    
    Args:
        dir_path: Path to directory to check
        
    Returns:
        True if directory exists, False otherwise
    """
    return dir_path.exists() and dir_path.is_dir()


def create_directory(dir_path: Path) -> bool:
    """
    Create a directory if it doesn't exist
    
    Args:
        dir_path: Path to directory to create
        
    Returns:
        True if directory was created or already exists, False on error
    """
    try:
        dir_path.mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def run_django_command(command: list, cwd: Optional[Path] = None) -> Tuple[bool, str, str]:
    """
    Run a Django management command
    
    Args:
        command: List of command arguments (e.g., ['migrate', '--noinput'])
        cwd: Working directory (defaults to project root)
        
    Returns:
        Tuple of (success, stdout, stderr)
    """
    if cwd is None:
        cwd = get_project_root()
    
    try:
        result = subprocess.run(
            [sys.executable, "manage.py"] + command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=True
        )
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr


def check_cef_available() -> bool:
    """
    Check if CEF Python is available
    
    Returns:
        True if cefpython3 can be imported, False otherwise
    """
    try:
        import cefpython3
        return True
    except ImportError:
        return False
