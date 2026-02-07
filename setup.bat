@echo off
REM Megido Security Setup Script for Windows
REM This script sets up the Megido Security Testing Platform

echo ================================================
echo   Megido Security Testing Platform - Setup
echo ================================================
echo.

REM Check Python version
echo Checking Python version...
python --version

if errorlevel 1 (
    echo Error: Python is not installed. Please install Python 3.12 or higher.
    pause
    exit /b 1
)

REM Install dependencies
echo.
echo Installing Python dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

REM Run migrations
echo.
echo Setting up database...
python manage.py migrate

if errorlevel 1 (
    echo Error: Failed to run database migrations.
    pause
    exit /b 1
)

REM Create superuser (optional)
echo.
set /p create_user="Do you want to create an admin user? (y/n): "
if /i "%create_user%"=="y" (
    python manage.py createsuperuser
)

REM CEF Browser Setup (optional)
echo.
set /p setup_cef="Do you want to set up CEF desktop browser integration? (y/n): "
if /i "%setup_cef%"=="y" (
    echo.
    echo Setting up CEF browser integration...
    python setup_cef_browser.py --setup-only
    
    if errorlevel 1 (
        echo Warning: CEF browser setup failed, but you can still use the web interface
    ) else (
        echo CEF browser setup completed successfully!
        echo You can launch it anytime with: launch_cef_browser.bat
    )
)

echo.
echo ================================================
echo   Setup Complete!
echo ================================================
echo.
echo To start the desktop application, run:
echo   python desktop_app.py
echo.
echo Or to start the web server, run:
echo   python manage.py runserver
echo.
echo Then open your browser to http://localhost:8000
echo.
pause
