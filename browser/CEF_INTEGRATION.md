# CEF Integration Documentation

## Overview

This document describes the **CEF (Chromium Embedded Framework)** integration in the Megido Security platform. The CEF integration provides a full-featured desktop browser with complete Chromium rendering capabilities, eliminating the limitations of the iframe-based browser.

## Table of Contents

1. [What is CEF?](#what-is-cef)
2. [Why CEF Integration?](#why-cef-integration)
3. [Architecture](#architecture)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Features](#features)
7. [Configuration](#configuration)
8. [Troubleshooting](#troubleshooting)
9. [Comparison: iframe vs CEF](#comparison-iframe-vs-cef)
10. [Advanced Topics](#advanced-topics)

---

## What is CEF?

**CEF (Chromium Embedded Framework)** is an open-source framework for embedding a full Chromium browser in applications. It provides:

- Full Chromium rendering engine
- Complete JavaScript support
- Modern web standards (HTML5, CSS3, WebGL)
- DevTools integration
- Native performance

**CEF Python** (`cefpython3`) provides Python bindings for CEF, making it easy to integrate into Python applications like Megido.

## Why CEF Integration?

### Limitations of iframe Browser

The original iframe-based browser has several limitations:

- ❌ **X-Frame-Options blocking**: Many sites (Google, Facebook, etc.) block iframe embedding
- ❌ **Limited JavaScript support**: Restricted execution context
- ❌ **CSP restrictions**: Content Security Policy blocks many modern sites
- ❌ **No plugin support**: Flash, PDF viewers, etc. don't work
- ❌ **Performance issues**: Nested rendering contexts
- ❌ **Limited network control**: Can't intercept all requests

### Benefits of CEF Browser

- ✅ **Full browser engine**: Complete Chromium with all features
- ✅ **No embedding restrictions**: Works with all websites
- ✅ **Complete JavaScript support**: All modern web features
- ✅ **Developer tools**: Built-in Chrome DevTools (F12)
- ✅ **Request interception**: Full control over network layer
- ✅ **Native performance**: Direct rendering, no nested contexts
- ✅ **Plugin support**: Extensions, PDF viewer, etc.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Desktop Application                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          CEF Browser Window (Chromium)               │   │
│  │  ┌───────────────────────────────────────────────┐  │   │
│  │  │         Megido App Toolbar                     │  │   │
│  │  │  [Proxy] [Spider] [Scanner] [...] [Tools]     │  │   │
│  │  └───────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────┐  │   │
│  │  │                                                │  │   │
│  │  │        Full Chromium Browser View             │  │   │
│  │  │        (Renders any web content)              │  │   │
│  │  │                                                │  │   │
│  │  └───────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                           ▲                                  │
│                           │                                  │
│                           ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         CEF Integration Layer                        │   │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────────┐   │   │
│  │  │  Request  │  │  Django   │  │   Session    │   │   │
│  │  │  Handler  │  │  Bridge   │  │   Manager    │   │   │
│  │  └───────────┘  └───────────┘  └──────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │ HTTP/REST API
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Django Backend                            │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐  │
│  │ Browser  │  │Interceptor│  │ App       │  │  Other   │  │
│  │ Models   │  │ Models    │  │ Manager   │  │  Apps    │  │
│  └──────────┘  └──────────┘  └───────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Component Breakdown

#### 1. **BrowserWindow** (`browser_window.py`)
- Creates and manages the CEF browser window
- Handles navigation (back, forward, reload)
- Manages app toolbar integration
- Controls window lifecycle

#### 2. **RequestHandler** (`request_handler.py`)
- Intercepts HTTP requests before they're sent
- Integrates with Django interceptor when enabled
- Captures responses for analysis
- Provides hooks for request modification

#### 3. **DjangoBridge** (`django_bridge.py`)
- HTTP client for Django REST API
- Manages communication with backend
- Handles authentication and sessions
- Provides methods for all API endpoints

#### 4. **SessionManager** (`session_manager.py`)
- Synchronizes CEF sessions with Django BrowserSession model
- Logs navigation history
- Tracks app interactions
- Manages cookies and local storage (future)

#### 5. **DesktopLauncher** (`desktop_launcher.py`)
- Entry point for desktop application
- Launches Django server (optional)
- Initializes and runs CEF browser
- Handles graceful shutdown

## Installation

### Prerequisites

- Python 3.8 or higher
- Django 6.0+
- Operating System: Windows, Linux, or macOS

### Step 1: Install CEF Python

```bash
pip install cefpython3
```

**Platform-Specific Notes:**

#### Windows
- CEF Python includes all necessary binaries
- No additional setup required
- Works on Windows 7+ (64-bit)

#### Linux
- Requires GTK 3.0+
- Install dependencies:
  ```bash
  sudo apt-get install python3-pyqt5 libgtk-3-0
  ```
- On some distributions, you may need:
  ```bash
  sudo apt-get install libnss3 libasound2
  ```

#### macOS
- Requires macOS 10.10 or higher
- May need to allow unsigned applications in Security settings
- Run from Terminal (not from Finder initially)

### Step 2: Verify Installation

```bash
python -c "from cefpython3 import cefpython as cef; print('CEF version:', cef.GetVersion())"
```

### Step 3: Update Dependencies

All Megido dependencies are already in `requirements.txt`. Install/update:

```bash
pip install -r requirements.txt
```

## Usage

### Method 1: Launch from Django Web Interface

You can now launch the CEF browser directly from the Django web interface:

1. Navigate to `/browser/` in Django
2. Click the "🚀 Launch Full Browser (CEF)" button in the toolbar
3. The CEF desktop browser window will open

This is the easiest way to launch CEF without using the command line.

### Method 2: Launch Both Django and CEF Browser

Start Django server and CEF browser together:

```bash
python browser/desktop_launcher.py
```

This will:
1. Start Django development server on `http://127.0.0.1:8000`
2. Run database migrations
3. Open CEF browser window
4. Connect browser to Django backend

### Method 3: Connect to Existing Django Server

If Django is already running (e.g., in another terminal):

```bash
# Terminal 1: Start Django
python manage.py runserver

# Terminal 2: Start CEF browser only
python browser/desktop_launcher.py --mode browser-only
```

### Method 4: Custom Django URL

Connect to Django on a different host/port:

```bash
python browser/desktop_launcher.py --django-url http://localhost:8080
```

### Method 5: Server Only Mode

Start only Django server (for development/testing):

```bash
python browser/desktop_launcher.py --mode server-only --port 8000
```

### Command Line Options

```
usage: desktop_launcher.py [-h] [--mode {both,server-only,browser-only}]
                           [--django-url DJANGO_URL] [--port PORT]
                           [--host HOST]

optional arguments:
  -h, --help            show this help message and exit
  --mode {both,server-only,browser-only}
                        Launch mode (default: both)
  --django-url DJANGO_URL
                        Django server URL (default: http://127.0.0.1:8000)
  --port PORT           Django server port (default: 8000)
  --host HOST           Django server host (default: 127.0.0.1)
```

## Features

### 1. Full Chromium Browser

- **Complete web rendering**: All websites work without restrictions
- **Modern web standards**: HTML5, CSS3, ES6+, WebAssembly
- **JavaScript execution**: Full V8 engine with all features
- **Media support**: Video, audio, WebRTC
- **WebGL support**: 3D graphics and games

### 2. Developer Tools

Press **F12** to open Chrome DevTools:

- Elements inspector
- Console for JavaScript debugging
- Network tab for request monitoring
- Performance profiling
- Application/Storage inspector

### 3. Keyboard Shortcuts

- **F12**: Open Developer Tools
- **Ctrl+R** / **Cmd+R**: Reload page
- **Ctrl+W** / **Cmd+W**: Close window
- **Alt+Left**: Go back
- **Alt+Right**: Go forward
- **F5**: Refresh
- **Ctrl+F**: Find in page

### 4. Request Interception

When the interceptor is enabled:

1. All HTTP requests are captured
2. Request details are sent to Django interceptor
3. User can modify requests before forwarding
4. Responses are captured for analysis
5. Integration with all existing interceptor features

**To toggle interceptor:**
```python
# In browser console or via API
browser_window.toggle_interceptor()
```

### 5. App Integration

Access all Megido apps through the toolbar:

- **Proxy**: Route traffic through proxy
- **Spider**: Crawl current site
- **Scanner**: Scan for vulnerabilities
- **Interceptor**: Enable/disable request interception
- **Repeater**: Send requests to repeater
- **Mapper**: Map attack surface
- And all other enabled apps...

Click any app button to:
1. Log the interaction in Django
2. Navigate to app with current URL as context
3. Auto-populate app forms

### 6. Session Management

All browser activity is tracked in Django:

- **Navigation history**: Every URL visited
- **App interactions**: Which apps were used and when
- **Session lifecycle**: Start/end times
- **User attribution**: Links activity to Django user (if logged in)

View session data in Django admin or via API:
```
GET /browser/api/sessions/
GET /browser/api/history/<session_id>/
```

## Configuration

### CEF Settings

Edit `browser_window.py` to customize CEF settings:

```python
settings = {
    "debug": False,                    # Enable debug mode
    "log_severity": cef.LOGSEVERITY_INFO,  # Log level
    "log_file": "cef_debug.log",      # Log file path
    "cache_path": "cef_cache",        # Browser cache directory
    "user_agent": "Custom UA",        # Custom user agent
    "locale": "en-US",                # Browser locale
}
```

### Browser Window Settings

Customize window size and appearance:

```python
browser_window.create_browser(
    url="http://127.0.0.1:8000",
    window_title="My Custom Title",
    width=1600,   # Window width
    height=1000   # Window height
)
```

### Django API Configuration

Configure Django URL in `django_bridge.py`:

```python
bridge = DjangoBridge(base_url="http://your-server:8000")
```

## Troubleshooting

### Issue: CEF fails to initialize

**Symptoms**: Error message "Failed to initialize CEF"

**Solutions**:
1. Ensure CEF Python is installed: `pip install cefpython3`
2. Check Python version (requires 3.8+)
3. On Linux, install GTK dependencies:
   ```bash
   sudo apt-get install libgtk-3-0 libnss3
   ```
4. Try running with elevated privileges (Windows/macOS)

### Issue: Django server not accessible

**Symptoms**: "Cannot connect to Django server"

**Solutions**:
1. Verify Django is running: `curl http://127.0.0.1:8000`
2. Check firewall settings
3. Ensure correct host/port in `--django-url`
4. Check Django logs for errors

### Issue: Blank window or white screen

**Symptoms**: Browser window opens but shows nothing

**Solutions**:
1. Check console output for JavaScript errors
2. Verify URL is correct and accessible
3. Try loading a simple page first (e.g., `http://example.com`)
4. Clear CEF cache: delete `cef_cache/` directory
5. Check Developer Tools (F12) for errors

### Issue: Request interception not working

**Symptoms**: Requests are not being intercepted

**Solutions**:
1. Verify interceptor is enabled in Django
2. Check `RequestHandler` is properly attached
3. Review Django interceptor logs
4. Ensure Django backend is running

### Issue: Platform-specific crashes

#### Windows
- Update Visual C++ Redistributables
- Run as Administrator
- Check antivirus isn't blocking

#### Linux
- Install all GTK dependencies
- Check X11 display server is running
- Try different desktop environment

#### macOS
- Allow unsigned application in Security settings
- Run from Terminal, not Finder
- Check macOS version (10.10+)

### Debug Mode

Enable debug logging:

```python
settings = {
    "debug": True,
    "log_severity": cef.LOGSEVERITY_VERBOSE,
    "log_file": "cef_debug.log",
}
```

Then check `cef_debug.log` for detailed information.

## Comparison: iframe vs CEF

| Feature | iframe Browser | CEF Browser |
|---------|---------------|-------------|
| **Rendering Engine** | Host browser | Full Chromium |
| **Website Compatibility** | Limited (X-Frame-Options) | Universal |
| **JavaScript Support** | Restricted | Complete |
| **Developer Tools** | No | Yes (F12) |
| **Request Interception** | Partial | Full control |
| **Performance** | Slower (nested) | Native speed |
| **Plugin Support** | No | Yes |
| **Network Control** | Limited | Complete |
| **Modern Web Features** | Limited | All features |
| **Installation** | No extra deps | Requires cefpython3 |
| **Memory Usage** | Lower | Higher |
| **Platform Support** | Any (web) | Desktop only |
| **Offline Use** | No | Yes |

### When to Use Each

**Use iframe browser when:**
- Running in web-only environment
- Minimal resource usage needed
- Simple testing on cooperative sites
- No desktop environment available

**Use CEF browser when:**
- Testing sites that block iframes (Google, Facebook, etc.)
- Need full JavaScript debugging
- Require complete network interception
- Want desktop application experience
- Need maximum compatibility

## Advanced Topics

### Custom Request Handlers

Implement custom request handling logic:

```python
from browser.cef_integration.request_handler import RequestHandler

class MyRequestHandler(RequestHandler):
    def on_before_resource_load(self, browser, frame, request, **kwargs):
        # Custom logic here
        url = request.GetUrl()
        print(f"Loading: {url}")
        
        # Modify request
        request.SetHeaderByName("X-Custom-Header", "value", True)
        
        return super().on_before_resource_load(browser, frame, request, **kwargs)
```

### JavaScript Injection

Inject JavaScript into pages:

```python
browser.ExecuteJavascript("""
    console.log('Injected from Python');
    document.body.style.backgroundColor = 'lightblue';
""")
```

### Python-JavaScript Bridge

Create bidirectional communication:

```python
# From Python to JavaScript
browser.ExecuteFunction("myJsFunction", arg1, arg2)

# From JavaScript to Python (via JavascriptBindings)
bindings = cef.JavascriptBindings()
bindings.SetFunction("myPythonFunction", my_python_callback)
browser.SetJavascriptBindings(bindings)
```

### Cookie Management

Access and modify cookies:

```python
# Get all cookies
cookie_manager = browser.GetCookieManager()
cookies = cookie_manager.GetCookies()

# Set a cookie
cookie = cef.Cookie()
cookie.SetName("session_id")
cookie.SetValue("abc123")
cookie_manager.SetCookie("https://example.com", cookie)
```

### Custom Context Menus

Create custom right-click menus:

```python
class ContextMenuHandler:
    def OnBeforeContextMenu(self, browser, frame, params, model):
        model.Clear()  # Clear default items
        model.AddItem(1, "Custom Action")
    
    def OnContextMenuCommand(self, browser, frame, params, command_id):
        if command_id == 1:
            print("Custom action triggered")
```

## API Reference

### DjangoBridge Methods

```python
bridge = DjangoBridge("http://127.0.0.1:8000")

# Get enabled apps
apps = bridge.get_enabled_apps()

# Get/toggle interceptor
status = bridge.get_interceptor_status()
result = bridge.toggle_interceptor(True)

# Log history
bridge.add_history(session_id=1, url="https://example.com", title="Example")

# Log app interaction
bridge.log_app_interaction(
    session_id=1,
    app_name="scanner",
    action="scan",
    target_url="https://example.com"
)

# Check server status
is_running = bridge.check_server_status()
```

### SessionManager Methods

```python
session_manager = SessionManager(bridge)

# Start session
session_id = session_manager.start_session("My Session")

# Log navigation
session_manager.log_navigation("https://example.com", "Example Site")

# Log app action
session_manager.log_app_action("scanner", "scan", "https://example.com")

# End session
session_manager.end_session()
```

### BrowserWindow Methods

```python
browser = BrowserWindow("http://127.0.0.1:8000")

# Navigation
browser.navigate("https://example.com")
browser.go_back()
browser.go_forward()
browser.reload()
browser.stop()

# Get current URL
url = browser.get_url()

# Toggle interceptor
browser.toggle_interceptor()

# Trigger app
browser.trigger_app("scanner", "https://example.com")

# Developer tools
browser.show_dev_tools()

# Close
browser.close()
```

## Contributing

To contribute to CEF integration:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/cef-enhancement`
3. Make changes to `browser/cef_integration/`
4. Test thoroughly on all platforms
5. Submit pull request

## License

CEF integration uses:
- **CEF Python**: BSD license
- **Chromium**: BSD license
- Megido: [Your License]

## Support

For issues and questions:

- GitHub Issues: [repository]/issues
- Documentation: This file and code comments
- CEF Python docs: https://github.com/cztomczak/cefpython

## References

- [CEF Python Documentation](https://github.com/cztomczak/cefpython)
- [Chromium Embedded Framework](https://bitbucket.org/chromiumembedded/cef)
- [Django REST Framework](https://www.django-rest-framework.org/)
- [Megido Browser README](../BROWSER_README.md)

---

**Last Updated**: 2026-02-07
**Version**: 1.0.0
