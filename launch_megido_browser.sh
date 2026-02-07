#!/bin/bash
# Launch Megido Browser on Linux/Mac
# This script starts Django, mitmproxy, and the PyQt6 browser

set -e

echo "========================================================================"
echo "  Megido Security - Desktop Browser Launcher"
echo "========================================================================"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
elif [ -d ".venv" ]; then
    echo "📦 Activating virtual environment..."
    source .venv/bin/activate
else
    echo "⚠️  No virtual environment found (venv or .venv)"
    echo "   It's recommended to use a virtual environment"
fi

# Install/update dependencies
echo ""
echo "📥 Checking dependencies..."
pip install -q -r requirements.txt

# Run migrations
echo ""
echo "🗄️  Running database migrations..."
# Use SQLite for simplicity in development/testing environments
# This can be overridden by setting USE_SQLITE=false before running this script
export USE_SQLITE=true
python3 manage.py migrate --noinput

# Launch browser
echo ""
echo "🚀 Launching Megido Browser..."
echo ""
python3 launch_megido_browser.py "$@"

echo ""
echo "👋 Goodbye!"
