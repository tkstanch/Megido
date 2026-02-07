@echo off
REM Quick launcher for CEF browser - Windows
REM Megido Security Testing Platform

echo.
echo ================================================
echo   Megido Security - CEF Browser Launcher
echo ================================================
echo.

REM Get the directory where this script is located
cd /d "%~dp0"

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else if exist "env\Scripts\activate.bat" (
    echo Activating virtual environment...
    call env\Scripts\activate.bat
) else (
    echo WARNING: Virtual environment not found (venv\ or env\)
    echo    It's recommended to use a virtual environment
    echo    Create one with: python -m venv venv
    echo.
    set /p answer="Continue without virtual environment? [y/N]: "
    if /i not "%answer%"=="y" (
        echo Exiting...
        exit /b 0
    )
)

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed
    echo    Please install Python 3.7 or higher
    pause
    exit /b 1
)

echo Using Python:
python --version
echo.

REM Run the setup script
echo Launching CEF browser...
echo.

if not exist "setup_cef_browser.py" (
    echo ERROR: setup_cef_browser.py not found
    echo    Please run this script from the project root directory
    pause
    exit /b 1
)

REM Handle errors gracefully
python setup_cef_browser.py %*

if errorlevel 1 (
    echo.
    echo ERROR: CEF browser exited with an error
    echo.
    echo Troubleshooting tips:
    echo   1. Check if all dependencies are installed: python setup_cef_browser.py --check
    echo   2. Run setup only: python setup_cef_browser.py --setup-only
    echo   3. Try with debug mode: python setup_cef_browser.py --debug
    echo   4. Check the logs at: logs\cef_setup.log
    echo.
    echo If CEF browser fails, you can use the web-based iframe browser:
    echo   python manage.py runserver
    echo   Then open: http://localhost:8000/browser/
    echo.
    pause
    exit /b 1
)

echo.
echo CEF browser closed successfully
pause
