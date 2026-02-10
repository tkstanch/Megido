# Megido Security Testing Platform

[...]existing intro sections...]

## ⚡ Automated Setup (All Platforms)

Megido provides a **universal, automated setup experience** for Windows, macOS, and Linux users. You can download, install, and run the app with a single command using the provided scripts:

- **Cross-platform Installation Guide:** See [LOCAL_INSTALLATION_GUIDE.md](LOCAL_INSTALLATION_GUIDE.md) (recommended for new users)
- **Linux/macOS:**
  ```bash
  bash setup.sh
  ```
- **Windows (PowerShell):**
  ```powershell
  ./setup.ps1
  ```
- **Docker Quick Start (All OS):**
  ```bash
  git clone https://github.com/tkstanch/Megido.git && cd Megido && docker compose up --build
  ```

These scripts will:
- Install dependencies
- Configure ClamAV and Python (or Docker as selected)
- Run database migrations, create an admin user (admin/admin by default)
- Start the application at http://localhost:8000

> For full details, troubleshooting, and all platform instructions, please see [LOCAL_INSTALLATION_GUIDE.md](LOCAL_INSTALLATION_GUIDE.md).

## 🎨 Modern UI with Tailwind CSS

Megido features a **professional, modern user interface** built with Tailwind CSS, offering:

### Key Features

- ✅ **Modern Design System** - Clean, professional aesthetic inspired by security tools like Burp Suite
- ✅ **Dark Mode Support** - Seamless light/dark mode toggle with persistent preferences
- ✅ **Fully Responsive** - Mobile-first design that works on all devices (320px to 4K)
- ✅ **Accessible by Default** - WCAG 2.1 AA compliant with proper ARIA labels and keyboard navigation
- ✅ **Consistent Components** - Reusable cards, buttons, badges, forms, and tables
- ✅ **Security-Themed Colors** - Purple/blue gradients with severity-based color coding
- ✅ **Fast & Lightweight** - Utility-first CSS with minimal overhead

### Screenshots

**Light Mode:**
![Megido Light Mode](https://github.com/user-attachments/assets/d892e776-23f3-40db-993f-01c6d1c77879)

**Dark Mode:**
![Megido Dark Mode](https://github.com/user-attachments/assets/883298ba-436d-42a2-938c-33eb40f7c3c3)

### Documentation

- **[UI_DESIGN_SYSTEM.md](UI_DESIGN_SYSTEM.md)** - Complete design system documentation
  - Color palette and typography
  - Component library with code examples
  - Dark mode implementation
  - Responsive design patterns
  - Accessibility guidelines
  - Best practices for extending the UI

### Customization

To modify the UI or add custom styles:

```bash
# Install Node.js dependencies
npm install

# Build CSS for production
npm run build:css

# Watch for changes during development
npm run watch:css
```

All Tailwind configuration is in `tailwind.config.js`. Custom components are defined in `static/css/tailwind.input.css`.

## 🌐 Desktop Browser with Traffic Interception

Megido now includes a **PyQt6 Desktop Browser** with integrated **mitmproxy** for powerful HTTP/HTTPS traffic interception:

### Quick Launch
```bash
# Linux/Mac
./launch_megido_browser.sh

# Windows
launch_megido_browser.bat

# Python (cross-platform)
python launch_megido_browser.py
```

This launches:
- Django development server
- mitmproxy with Megido addon for traffic interception
- PyQt6 desktop browser with real-time interceptor panel

### Features
- ✅ **Python 3.13 Compatible** (replaces CEF Python)
- ✅ **Full HTTP/HTTPS Interception** via mitmproxy
- ✅ **Payload Injection Rules** - Automatically modify requests
- ✅ **Real-time Request Viewer** - See intercepted traffic instantly
- ✅ **App Integration** - Track traffic by source app (Scanner, Spider, etc.)
- ✅ **Certificate Helper** - Easy HTTPS interception setup

See [BROWSER_INTERCEPTOR_INTEGRATION.md](BROWSER_INTERCEPTOR_INTEGRATION.md) for complete documentation.

## 🎯 Advanced Exploit Plugins

Megido includes a powerful pluggable exploit system with production-quality plugins for automated vulnerability exploitation:

### Clickjacking Exploit Plugin

The **Advanced Clickjacking Exploit Plugin** provides comprehensive clickjacking detection and exploitation capabilities:

- ✅ **HTML PoC Generation** - Interactive proof-of-concept with customizable overlays (transparent, opaque, partial)
- ✅ **Automated Frameability Detection** - Headless browser testing with Selenium/WebDriver  
- ✅ **Security Header Analysis** - X-Frame-Options and CSP frame-ancestors validation
- ✅ **Evidence Collection** - Annotated screenshots and detailed reports
- ✅ **Configurable Testing** - Test mode, browser selection, evidence control
- ✅ **Severity Classification** - Context-aware risk assessment
- ✅ **Comprehensive Remediation** - Detailed fix guidance

**Quick Start:**
```python
from scanner.plugins import get_registry

# Get the clickjacking plugin
plugin = get_registry().get_plugin('clickjacking')

# Test a target
result = plugin.execute_attack(
    target_url='http://example.com',
    vulnerability_data={'action_description': 'user login'},
    config={'browser_type': 'chrome', 'collect_evidence': True}
)

if result['vulnerable']:
    print(f"Vulnerability found! PoC: {result['data']['poc_path']}")
```

**Demo:** Run `python3 demo_clickjacking_plugin.py` for interactive demonstration.

### Other Available Plugins

- **SQL Injection Plugin** - Multi-database support with error-based, time-based, and union-based detection
- **XSS Plugin** - Advanced cross-site scripting testing with DOM simulation and smart crawling

**Documentation:**
- [CLICKJACKING_PLUGIN_GUIDE.md](CLICKJACKING_PLUGIN_GUIDE.md) - Comprehensive clickjacking plugin guide
- [EXPLOIT_PLUGINS_GUIDE.md](EXPLOIT_PLUGINS_GUIDE.md) - Plugin system overview and all available plugins
- [XSS_PLUGIN_GUIDE.md](XSS_PLUGIN_GUIDE.md) - Detailed XSS plugin documentation

## ⚙️ Production Deployment Notes

### Worker Timeout Configuration

The Megido platform includes security scanning plugins (especially XSS exploitation) that perform **long-running operations** such as:
- Smart crawling of target sites (potentially minutes for deep scans)
- DOM-based exploitation with Selenium browser automation
- External site interaction and response analysis

**Important for Production Environments:**

When deploying with Gunicorn or other WSGI servers, the default 30-second worker timeout is insufficient and will cause premature worker termination during heavy scans.

#### Docker Deployment (Recommended)

The provided Docker configuration uses Gunicorn with a **300-second timeout** by default:

```bash
docker compose up --build
```

The timeout is configured in `gunicorn.conf.py` and automatically applied.

#### Manual Gunicorn Deployment

If running Gunicorn manually, use the provided configuration file:

```bash
gunicorn --config gunicorn.conf.py megido_security.wsgi:application
```

Or specify the timeout directly:

```bash
gunicorn --timeout 300 --workers 4 megido_security.wsgi:application
```

#### Development Mode

For local development, the Django development server has no timeout limits:

```bash
python manage.py runserver
# or
python launch.py
```

### Scalable Production Architecture with Celery

Megido now includes **Celery** integration for asynchronous exploit operations, preventing Gunicorn worker timeouts and improving scalability.

#### Background Task Processing

Exploit operations are automatically executed in the background using Celery workers. The API immediately returns a task ID that can be polled for status and results.

#### Development Setup

**1. Install Redis (required for Celery broker/backend)**

```bash
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis

# Windows (via WSL2 or Windows native)
# Download from https://redis.io/download
```

**2. Install Python dependencies** (if not already installed)

```bash
pip install -r requirements.txt
# This includes celery>=5.3.0 and redis>=5.0.0
```

**3. Start the Celery worker** (in a separate terminal)

```bash
celery -A megido_security worker --loglevel=info
```

**4. Start the Django development server** (in another terminal)

```bash
python manage.py runserver
# or
python launch.py
```

#### Production Deployment

For production, run Celery worker(s) alongside your web server:

```bash
# Start multiple workers for parallel processing
celery -A megido_security worker --loglevel=info --concurrency=4

# Optional: Start Celery Beat for periodic tasks (if needed in future)
celery -A megido_security beat --loglevel=info
```

#### Configuration

Celery settings can be configured via environment variables:

```bash
# Redis connection (defaults shown)
export CELERY_BROKER_URL=redis://localhost:6379/0
export CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

#### API Usage

**Submit an exploit task:**

```bash
POST /scanner/api/scans/{scan_id}/exploit/
{
  "action": "all"  # or "selected" with "vulnerability_ids": [1, 2, 3]
}

Response (HTTP 202):
{
  "task_id": "a1b2c3d4-...",
  "message": "Exploitation started in background",
  "status_url": "/scanner/api/exploit_status/a1b2c3d4-.../"
}
```

**Poll for task status:**

```bash
GET /scanner/api/exploit_status/{task_id}/

Response:
{
  "task_id": "a1b2c3d4-...",
  "state": "PROGRESS",  # PENDING, PROGRESS, SUCCESS, or FAILURE
  "current": 2,
  "total": 5,
  "status": "Processing vulnerability 2/5"
}
```

**When complete (state: SUCCESS):**

```bash
{
  "task_id": "a1b2c3d4-...",
  "state": "SUCCESS",
  "status": "Completed",
  "result": {
    "total": 5,
    "exploited": 3,
    "failed": 1,
    "no_plugin": 1,
    "results": [...]
  }
}
```

This architecture allows the web tier to remain responsive while exploitation tasks run in dedicated worker processes, improving reliability and user experience for long-running scans.

### Real-Time WebSocket Updates

The scanner now supports **WebSocket-based real-time updates** for exploitation progress, providing instant feedback as tasks execute. The system automatically falls back to polling if WebSocket connections fail, ensuring reliability across all environments.

#### How It Works

When you trigger an exploitation operation, the UI:
1. **Attempts WebSocket connection** to receive real-time updates
2. **Displays live progress** as vulnerabilities are processed
3. **Automatically falls back to polling** if WebSocket is unavailable
4. **Shows completion results** instantly when the task finishes

#### WebSocket Configuration

WebSockets require Redis as the channel layer backend:

```bash
# Redis is already required for Celery, same instance can be used
export REDIS_URL=redis://localhost:6379/1  # Optional, defaults to localhost
```

The WebSocket endpoint is automatically configured at:
```
ws://localhost:8000/ws/scanner/task/<task_id>/
wss://your-domain.com/ws/scanner/task/<task_id>/  # For HTTPS
```

#### ASGI Deployment for Production

For production deployments with WebSocket support, use **Daphne** (ASGI server) instead of Gunicorn:

```bash
# Install dependencies (already in requirements.txt)
pip install daphne channels channels-redis

# Start Daphne server
daphne -b 0.0.0.0 -p 8000 megido_security.asgi:application

# Or with more workers
daphne -b 0.0.0.0 -p 8000 --workers 4 megido_security.asgi:application
```

**Docker Compose** automatically uses Daphne when the ASGI application is detected.

#### Troubleshooting WebSockets

**Issue: WebSocket connection fails**
- **Cause**: Redis not running or not accessible
- **Solution**: Start Redis (`redis-server`) or check REDIS_URL setting
- **Fallback**: System automatically uses polling - no manual intervention needed

**Issue: No real-time updates in browser**
- **Check browser console** for WebSocket connection messages
- **Verify Redis is running**: `redis-cli ping` should return `PONG`
- **Check firewall rules** if Redis is on a different host

**Issue: WebSocket works locally but not in production**
- **Ensure HTTPS/WSS protocol** match your site protocol
- **Configure reverse proxy** (nginx/Apache) to proxy WebSocket connections:
  ```nginx
  location /ws/ {
      proxy_pass http://localhost:8000;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
  }
  ```

**Testing without Redis**

For testing purposes, you can use the in-memory channel layer (not for production):

```python
# In settings.py, temporarily replace CHANNEL_LAYERS with:
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer'
    }
}
```

> **Note**: The in-memory layer only works with a single server process and doesn't persist across restarts. Always use Redis for production deployments.

#### Benefits

- **Instant feedback**: See exploitation progress in real-time
- **Better UX**: No need to refresh or wait for polling
- **Graceful degradation**: Automatic fallback to polling ensures compatibility
- **Low overhead**: WebSocket connections are lightweight and efficient
- **Production-ready**: Built on battle-tested Django Channels

> **See Also:** [DOCKER_TESTING.md](DOCKER_TESTING.md) for additional production deployment guidance.

[...]rest of README untouched...