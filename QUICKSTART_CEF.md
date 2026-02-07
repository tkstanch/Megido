# Quick Start - CEF Browser

This guide will help you quickly set up and launch the CEF (Chromium Embedded Framework) browser integration for Megido Security Testing Platform.

## What is CEF Browser?

The CEF browser integration provides a native desktop browser experience with Megido, offering:
- Full Chromium browser capabilities
- Direct integration with all Megido security tools
- Better performance than iframe-based browsers
- Session management and history tracking
- Request interception and modification

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)
- Operating System: Windows, Linux, or macOS

## One-Command Setup & Launch

### Linux/macOS

```bash
./launch_cef_browser.sh
```

### Windows

```batch
launch_cef_browser.bat
```

### Manual (All Platforms)

```bash
python setup_cef_browser.py
```

## Installation Options

### Full Setup and Launch (Default)

Installs all dependencies, verifies configuration, and launches the browser:

```bash
python setup_cef_browser.py
```

### Setup Only (No Launch)

Only installs dependencies and verifies configuration:

```bash
python setup_cef_browser.py --setup-only
```

### Launch Only (Skip Setup)

Assumes everything is already installed and configured:

```bash
python setup_cef_browser.py --launch-only
```

### Check Installation Status

Verify your current installation without making changes:

```bash
python setup_cef_browser.py --check
```

## Advanced Usage

### Custom Port

Run Django on a different port:

```bash
python setup_cef_browser.py --port 8001
```

### Custom Host

Bind Django to a specific host:

```bash
python setup_cef_browser.py --host 0.0.0.0 --port 8080
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
python setup_cef_browser.py --debug
```

### Connect to External Django Server

If you already have Django running elsewhere:

```bash
python setup_cef_browser.py --launch-only --external-django --port 8000
```

## What Gets Installed?

The setup script automatically installs:
- `cefpython3` - Chromium Embedded Framework for Python
- `requests` - HTTP library for Django communication
- `Django` (if not already installed)
- `djangorestframework` (if not already installed)

## Troubleshooting

### CEF Installation Fails

If `cefpython3` installation fails, try:

```bash
pip install --upgrade pip
pip install cefpython3
```

### Port Already in Use

If port 8000 is already taken:

```bash
python setup_cef_browser.py --port 8001
```

### Virtual Environment Issues

It's recommended to use a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Run setup
python setup_cef_browser.py
```

### CEF Browser Won't Launch

1. Check installation status:
   ```bash
   python setup_cef_browser.py --check
   ```

2. Run setup only:
   ```bash
   python setup_cef_browser.py --setup-only
   ```

3. Check logs:
   ```bash
   cat logs/cef_setup.log
   ```

4. Try debug mode:
   ```bash
   python setup_cef_browser.py --debug
   ```

### Fallback to Web Browser

If CEF browser doesn't work, you can always use the web-based iframe browser:

```bash
python manage.py runserver
```

Then open your web browser and navigate to:
```
http://localhost:8000/browser/
```

## Integration with Existing Setup Scripts

The automated setup is also integrated into the existing setup scripts:

### Linux/macOS

```bash
./setup.sh
# When prompted, select CEF setup option
```

### Windows (Batch)

```batch
setup.bat
# Follow the prompts to set up CEF
```

### Windows (PowerShell)

```powershell
.\setup.ps1
# Follow the prompts to set up CEF
```

## Usage from launch.py

The main launcher script now supports CEF browser:

```bash
python launch.py --cef
```

## Features

### Automatic Features

- ✅ Dependency installation
- ✅ Environment verification
- ✅ Django server management
- ✅ Database migrations
- ✅ Port conflict detection
- ✅ Graceful error handling
- ✅ Comprehensive logging

### Browser Features

- 🌐 Full Chromium browser
- 🔧 DevTools (F12)
- 🔄 Page refresh (Ctrl+R)
- 📜 Session history
- 🛠️ Integration with all Megido tools
- 🚦 Request interception
- 📊 Traffic analysis

## Logging

All setup and browser activities are logged to:
```
logs/cef_setup.log
```

This log includes:
- Setup steps and status
- Dependency installation results
- Django server status
- Browser launch attempts
- Error messages and stack traces (in debug mode)

## File Structure

```
Megido/
├── setup_cef_browser.py          # Main automation script
├── launch_cef_browser.sh          # Unix launcher
├── launch_cef_browser.bat         # Windows launcher
├── QUICKSTART_CEF.md              # This file
├── logs/
│   └── cef_setup.log              # Setup and runtime logs
└── browser/
    └── cef_integration/
        ├── auto_setup.py          # Helper functions
        ├── browser_window.py       # CEF browser implementation
        ├── django_bridge.py        # Django API communication
        ├── session_manager.py      # Session management
        └── request_handler.py      # Request interception
```

## Getting Help

If you encounter issues:

1. Check the [main documentation](README.md)
2. Review the [browser integration guide](BROWSER_README.md)
3. Check the [CEF implementation summary](browser/CEF_IMPLEMENTATION_SUMMARY.md)
4. Look at example code in `browser/cef_example.py`

## Next Steps

After launching the CEF browser:

1. **Browse securely** - Navigate to any website you want to test
2. **Use Megido tools** - Access the integrated security tools from the browser interface
3. **Intercept requests** - Enable the interceptor to modify requests in real-time
4. **Analyze traffic** - Review all HTTP traffic and responses
5. **Run scans** - Use the scanner to find vulnerabilities
6. **Test payloads** - Try SQL injection, XSS, and other attack vectors

Enjoy using Megido Security with CEF Browser! 🚀
