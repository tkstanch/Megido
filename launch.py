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
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Megido Security Testing Platform Launcher',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'mode',
        nargs='?',
        choices=['web', 'desktop'],
        help='Launch mode: web or desktop'
    )
    parser.add_argument(
        '--web', '-w',
        action='store_true',
        help='Launch in web mode'
    )
    parser.add_argument(
        '--desktop', '-d',
        action='store_true',
        help='Launch in desktop mode (requires PySide6)'
    )
    parser.add_argument(
        '--cef',
        action='store_true',
        help='Launch with CEF desktop browser'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  Megido Security Testing Platform")
    print("=" * 60)
    print()
    
    # Handle CEF mode
    if args.cef:
        print("🚀 Launching Megido Security with CEF Desktop Browser...")
        print()
        try:
            # Import and launch CEF browser
            from browser.desktop_launcher import main as launch_cef
            sys.exit(launch_cef())
        except ImportError as e:
            print("❌ Error: CEF browser integration not available.")
            print(f"   {e}")
            print()
            print("To set up CEF browser, run:")
            print("   python setup_cef_browser.py")
            print()
            print("Or use the quick launcher:")
            print("   ./launch_cef_browser.sh  (Linux/macOS)")
            print("   launch_cef_browser.bat   (Windows)")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error launching CEF browser: {e}")
            sys.exit(1)
    
    # Handle explicit mode arguments
    if args.web or (args.mode and args.mode == 'web'):
        run_web_app()
        return
    elif args.desktop or (args.mode and args.mode == 'desktop'):
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
