@echo off
REM Launch Megido Browser on Windows
REM This script starts Django, mitmproxy, and the PyQt6 browser

echo ========================================================================
echo   Megido Security - Desktop Browser Launcher
echo ========================================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo Python found: 
python --version

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo Warning: No virtual environment found (venv or .venv^)
    echo It's recommended to use a virtual environment
)

REM Install/update dependencies
echo.
echo Checking dependencies...
pip install -q -r requirements.txt

REM Run migrations
echo.
echo Running database migrations...
set USE_SQLITE=true
python manage.py migrate --noinput

REM Launch browser
echo.
echo Launching Megido Browser...
echo.
python launch_megido_browser.py %*

echo.
echo Goodbye!
pause
