#!/usr/bin/env python3
"""
Megido Security - Launcher Script
Intelligent launcher that detects the environment and runs the appropriate mode
"""

import sys
import os
import subprocess


def is_display_available():
    """Check if a display is available (for GUI)"""
    if sys.platform == 'win32':
        return True  # Windows always has display
    elif sys.platform == 'darwin':
        return True  # macOS always has display
    else:
        # Linux/Unix - check for DISPLAY or Wayland
        return bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))


def check_pyside6():
    """Check if PySide6 is properly installed"""
    try:
        import PySide6
        return True
    except ImportError:
        return False


def run_desktop_app():
    """Launch the desktop application"""
    print("🚀 Starting Megido Security in Desktop Mode...")
    subprocess.run([sys.executable, 'desktop_app.py'])


def run_web_app():
    """Launch the web application"""
    print("🌐 Starting Megido Security in Web Mode...")
    print("=" * 60)
    print("  Access the application at: http://localhost:8000")
    print("  Press Ctrl+C to stop the server")
    print("=" * 60)
    print()
    subprocess.run([sys.executable, 'manage.py', 'runserver'])


def main():
    """Main launcher logic"""
    print("=" * 60)
    print("  Megido Security Testing Platform")
    print("=" * 60)
    print()
    
    # Check for command line argument
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        if mode in ['web', '--web', '-w']:
            run_web_app()
            return
        elif mode in ['desktop', '--desktop', '-d']:
            if not check_pyside6():
                print("❌ Error: PySide6 is not installed or not working properly.")
                print("   Install it with: pip install PySide6")
                sys.exit(1)
            if not is_display_available():
                print("❌ Error: No display detected. Desktop mode requires a GUI environment.")
                print("   Use 'python launch.py web' to run in web mode instead.")
                sys.exit(1)
            run_desktop_app()
            return
    
    # Auto-detect best mode
    if is_display_available() and check_pyside6():
        print("✅ Display detected and PySide6 available")
        print("   Launching in Desktop Mode...")
        print()
        run_desktop_app()
    else:
        if not is_display_available():
            print("ℹ️  No display detected - running in Web Mode")
        elif not check_pyside6():
            print("ℹ️  PySide6 not available - running in Web Mode")
        print()
        run_web_app()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✋ Shutting down Megido Security...")
        sys.exit(0)
