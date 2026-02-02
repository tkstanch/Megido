#!/bin/bash

# Megido Security Setup Script
# This script sets up the Megido Security Testing Platform

echo "================================================"
echo "  Megido Security Testing Platform - Setup"
echo "================================================"
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version

if [ $? -ne 0 ]; then
    echo "Error: Python 3 is not installed. Please install Python 3.12 or higher."
    exit 1
fi

# Install dependencies
echo ""
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "Error: Failed to install dependencies."
    exit 1
fi

# Run migrations
echo ""
echo "Setting up database..."
python3 manage.py migrate

if [ $? -ne 0 ]; then
    echo "Error: Failed to run database migrations."
    exit 1
fi

# Create superuser (optional)
echo ""
echo "Do you want to create an admin user? (y/n)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    python3 manage.py createsuperuser
fi

echo ""
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo ""
echo "To start the desktop application, run:"
echo "  python3 desktop_app.py"
echo ""
echo "Or to start the web server, run:"
echo "  python3 manage.py runserver"
echo ""
echo "Then open your browser to http://localhost:8000"
echo ""
