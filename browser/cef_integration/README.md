# CEF Integration Quick Start

## Installation

```bash
pip install cefpython3
```

## Launch Desktop Browser

```bash
# Launch both Django and CEF browser
python browser/desktop_launcher.py

# Launch CEF browser only (Django must be running separately)
python browser/desktop_launcher.py --mode browser-only

# Launch Django server only
python browser/desktop_launcher.py --mode server-only --port 8000
```

## Examples

```bash
# Simple browser window
python browser/cef_example.py --example simple --url https://example.com

# Django API bridge demo
python browser/cef_example.py --example bridge

# Session management demo
python browser/cef_example.py --example session
```

## Features

✅ **Full Chromium Browser** - Complete rendering engine  
✅ **Works with ALL Sites** - No X-Frame-Options blocking  
✅ **Developer Tools** - Press F12  
✅ **Request Interception** - Full network control  
✅ **Django Integration** - All Megido apps accessible  
✅ **Session Tracking** - History and interactions logged  

## Documentation

- **Full Documentation**: [browser/CEF_INTEGRATION.md](CEF_INTEGRATION.md)
- **Browser Overview**: [../BROWSER_README.md](../BROWSER_README.md)

## Comparison

| Feature | iframe Browser | CEF Browser |
|---------|---------------|-------------|
| Website Compatibility | Limited | Universal |
| JavaScript Support | Restricted | Complete |
| Developer Tools | No | Yes (F12) |
| Performance | Slower | Native |
| Installation | None | `pip install cefpython3` |

## Platform Support

- **Windows**: 7+ (64-bit)
- **Linux**: GTK 3.0+ required
- **macOS**: 10.10+ required

## Troubleshooting

**CEF not found?**
```bash
pip install cefpython3
```

**Django not accessible?**
```bash
python manage.py runserver
```

**Blank window?**
- Check Developer Tools (F12) for errors
- Clear cache: delete `cef_cache/` directory
- Verify URL is accessible

## Quick API Usage

```python
from browser.cef_integration.browser_window import BrowserWindow

# Create browser
browser = BrowserWindow("http://127.0.0.1:8000")
browser.create_browser(url="https://example.com")

# Navigation
browser.navigate("https://example.com")
browser.go_back()
browser.reload()

# Toggle interceptor
browser.toggle_interceptor()

# Trigger app
browser.trigger_app("scanner", "https://example.com")

# Run message loop
browser.message_loop()
browser.shutdown()
```

## Support

For detailed information, see [CEF_INTEGRATION.md](CEF_INTEGRATION.md)
