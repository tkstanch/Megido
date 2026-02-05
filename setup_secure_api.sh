#!/bin/bash
# setup_secure_api.sh - Setup script for secure API access with token authentication

set -e

echo "========================================================================"
echo "  Megido Security - Secure API Setup"
echo "========================================================================"
echo ""

# Check if we're in the correct directory
if [ ! -f "manage.py" ]; then
    echo "Error: This script must be run from the project root directory"
    echo "Current directory: $(pwd)"
    exit 1
fi

# Step 1: Install dependencies
echo "Step 1: Installing dependencies..."
echo "--------------------------------------------------------------------"
pip install -r requirements.txt
echo "✓ Dependencies installed"
echo ""

# Step 2: Run migrations
echo "Step 2: Running database migrations..."
echo "--------------------------------------------------------------------"
python manage.py migrate
echo "✓ Migrations completed"
echo ""

# Step 3: Create authtoken table
echo "Step 3: Creating authentication token tables..."
echo "--------------------------------------------------------------------"
python manage.py migrate authtoken
echo "✓ Token authentication tables created"
echo ""

echo "========================================================================"
echo "  Setup Complete!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Create a superuser if you haven't already:"
echo "   python manage.py createsuperuser"
echo ""
echo "2. Generate an API token for your user:"
echo "   python manage.py create_scanner_token --username <your-username>"
echo ""
echo "3. Use the token in your API requests:"
echo "   - Set the MEGIDO_API_TOKEN environment variable:"
echo "     export MEGIDO_API_TOKEN=<your-token>"
echo ""
echo "   - Or update demo.py with your token"
echo ""
echo "4. Run the demo script:"
echo "   python demo.py"
echo ""
echo "For more information, see docs/API_TOKEN_SETUP.md"
echo ""
