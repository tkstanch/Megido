#!/bin/bash
# Quick launcher for CEF browser - Linux/macOS
# Megido Security Testing Platform

set -e

echo ""
echo "================================================"
echo "  Megido Security - CEF Browser Launcher"
echo "================================================"
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
elif [ -d "env" ]; then
    echo "Activating virtual environment..."
    source env/bin/activate
else
    echo "⚠️  Virtual environment not found (venv/ or env/)"
    echo "   It's recommended to use a virtual environment"
    echo "   Create one with: python3 -m venv venv"
    echo ""
    read -p "Continue without virtual environment? [y/N]: " answer
    answer=${answer:-N}
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        echo "Exiting..."
        exit 0
    fi
fi

# Check if Python is available
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "❌ Error: Python is not installed"
    echo "   Please install Python 3.7 or higher"
    exit 1
fi

# Determine Python command
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
else
    PYTHON_CMD="python"
fi

echo "Using Python: $($PYTHON_CMD --version)"
echo ""

# Run the setup script
echo "Launching CEF browser..."
echo ""

if [ ! -f "setup_cef_browser.py" ]; then
    echo "❌ Error: setup_cef_browser.py not found"
    echo "   Please run this script from the project root directory"
    exit 1
fi

# Handle errors gracefully
if $PYTHON_CMD setup_cef_browser.py "$@"; then
    echo ""
    echo "✅ CEF browser closed successfully"
else
    EXIT_CODE=$?
    echo ""
    echo "❌ CEF browser exited with error code: $EXIT_CODE"
    echo ""
    echo "Troubleshooting tips:"
    echo "  1. Check if all dependencies are installed: $PYTHON_CMD setup_cef_browser.py --check"
    echo "  2. Run setup only: $PYTHON_CMD setup_cef_browser.py --setup-only"
    echo "  3. Try with debug mode: $PYTHON_CMD setup_cef_browser.py --debug"
    echo "  4. Check the logs at: logs/cef_setup.log"
    echo ""
    echo "If CEF browser fails, you can use the web-based iframe browser:"
    echo "  python manage.py runserver"
    echo "  Then open: http://localhost:8000/browser/"
    echo ""
    exit $EXIT_CODE
fi
