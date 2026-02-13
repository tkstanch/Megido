# Megido Security Testing Platform

[...]existing intro sections...]

## 🔬 Advanced Multi-Engine Scanner Architecture 🚀 ⭐ LATEST

Megido features an **enterprise-grade multi-engine plugin architecture** with **5 production-ready scanner engines**, Django integration, REST API, and advanced CLI:

### 🎯 Scanner Engines (5 Total)

- **🔍 SAST** - Static Application Security Testing
  - **Bandit** - Python security linter with CWE mapping
  - **Semgrep** - Multi-language analysis (Python, JS, Java, Go, C, Ruby, PHP, etc.) ⭐ NEW
- **📦 SCA** - Software Composition Analysis  
  - **Trivy** - CVE detection in dependencies, containers, and IaC ⭐ NEW
- **🔐 Secrets** - Credential Detection
  - **GitLeaks** - Find hardcoded API keys, passwords, tokens
- **🎯 Custom** - Extensible framework for any analyzer

### 💎 Enterprise Features ⭐ LATEST ENHANCEMENTS

- ✅ **Django Integration** - Complete database persistence with 3 new models
- ✅ **RESTful API** - Full CRUD operations via Django REST Framework
- ✅ **Advanced CLI** - Professional command-line tool with colored output
- ✅ **Multiple Report Formats** - JSON, HTML, CSV exports
- ✅ **Deduplication** - Automatic finding deduplication with SHA-256 hashing
- ✅ **Review Workflow** - Mark findings as confirmed/false positive/fixed
- ✅ **Historical Tracking** - Complete scan history with execution details
- ✅ **Parallel Execution** - Run multiple engines concurrently (4 workers default)
- ✅ **Smart Filtering** - By severity, engine, category, duplicates
- ✅ **Config Management** - YAML/JSON configuration with hot-reload

### 🚀 Quick Start

**CLI (Recommended):**
```bash
# List available engines
python advanced_scanner_cli.py list-engines

# Run comprehensive scan
python advanced_scanner_cli.py scan /path/to/code

# Run specific engines
python advanced_scanner_cli.py scan /path/to/code --engines bandit semgrep trivy

# Run by category
python advanced_scanner_cli.py scan /path/to/code --categories sast secrets

# View results
python advanced_scanner_cli.py show-scan 1 --severity high --verbose

# Export HTML report
python advanced_scanner_cli.py export-report 1 --format html --output report.html
```

**Python API:**
```python
from scanner.engine_plugins.engine_service import EngineService

service = EngineService()

# Create and execute scan
scan = service.create_scan(target_path='/path/to/code', categories=['sast', 'sca'])
result = service.execute_scan(scan)

# Get findings
findings = service.get_scan_findings(scan_id=scan.id, severity='high')
```

**REST API:**
```bash
# Create and execute scan
curl -X POST http://localhost:8000/api/engine-scans/ \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/path/to/code", "execute_immediately": true}'

# Get findings
curl http://localhost:8000/api/engine-scans/1/findings/?severity=high

# List scan history
curl http://localhost:8000/api/engine-scans/history/
```

### 📚 Documentation

- **[ADVANCED_ENHANCEMENTS_SUMMARY.md](ADVANCED_ENHANCEMENTS_SUMMARY.md)** - Complete implementation guide ⭐ NEW
- **[MULTI_ENGINE_PLUGIN_GUIDE.md](MULTI_ENGINE_PLUGIN_GUIDE.md)** - User guide for plugin architecture
- **[MULTI_ENGINE_ARCHITECTURE_SUMMARY.md](MULTI_ENGINE_ARCHITECTURE_SUMMARY.md)** - Technical architecture

### 🎯 API Endpoints

```
GET    /api/engines/                       # List all engines
GET    /api/engines/categories/            # Get categories
POST   /api/engine-scans/                  # Create scan
POST   /api/engine-scans/{id}/execute/     # Execute scan
GET    /api/engine-scans/{id}/summary/     # Get summary
GET    /api/engine-scans/{id}/findings/    # Get findings with filters
GET    /api/engine-scans/history/          # Scan history
GET    /api/engine-findings/               # List all findings
POST   /api/engine-findings/{id}/mark_status/ # Update finding status
```

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

## 🎨 Modern UI with Professional Design System

Megido features a **professional, classic, and beautiful user interface** built with an advanced Tailwind CSS design system, offering enterprise-grade elegance and responsiveness:

### ✨ Latest UI Features (v2.4 Professional Classic) 💼

#### Professional Classic Design (v2.4) ⭐ NEW
- 💼 **Timeless Elegance** - Classic design patterns that never go out of style
- 🎨 **Refined Typography** - Professional letter-spacing, refined weights, elegant hierarchy
- 🃏 **Classic Cards** - Elevated, bordered, and inset variants with subtle shadows
- 🔘 **Professional Buttons** - Solid, outline, and text variants with refined interactions
- 🎯 **Sophisticated Badges** - Professional and classic badge styles
- 💫 **Gentle Animations** - Subtle fade and slide transitions
- 🎨 **Professional Colors** - Emerald, Sapphire, Ruby, and Slate palettes
- 📊 **Classic Tables** - Professional data display with refined styling
- 🏛️ **Enterprise Layouts** - Professional hero, section, and container styles
- ⚡ **Refined Interactions** - Hover lift and brighten effects
- 🎯 **Status Indicators** - Professional status dots with pulse animation
- 💎 **Elegant Forms** - Classic input styling with professional focus states

#### Core Features (v2.3)
- 🎯 **Fully Responsive Design** - Perfect scaling from mobile (375px) to ultra-wide (3840px+)
- 📱 **Mobile-First Approach** - Optimized touch targets, fluid typography, adaptive layouts
- ✨ **Glassmorphism Effects** - Beautiful frosted glass aesthetics with backdrop blur
- 🌈 **Mesh Gradients** - Multi-color gradient backgrounds for premium visual appeal
- 💫 **Cinema-Grade Textures** - Film grain, vignette, light leaks for artistic depth
- ⚡ **Advanced Particles** - 50 floating particles with network connections
- 🎨 **Custom Cursor** - Animated cursor with glow and spotlight effects
- 🎭 **Premium Shadows** - Sophisticated multi-layer shadow system with glow effects
- 🎬 **Micro-Animations** - Elastic physics, liquid morphing, wave ripples
- 🌙 **Enhanced Dark Mode** - Refined color palette with smooth theme transitions
- 🎪 **Typography Effects** - 3D shadows, gradient strokes, kinetic text, shimmer
- 📐 **Background Patterns** - Subtle dot and grid patterns adapting to theme

#### Ultra-Cinema Enhancements (v2.3+) 🚀
- 🔮 **Multi-Layered Glassmorphism** - 4 glass variants with nested depth effects
- 🌈 **Animated Mesh Gradients** - 4-point radial gradient with 20s drift cycle
- ✨ **Ultra Cursor** - Enhanced with prism trails and 400px spotlight
- 🎨 **Living Borders** - Flowing gradients and pulsing aurora glows
- 💎 **Hyper-Glow Icons** - Pulsing multi-layer glow and holographic hue shifting
- 🎪 **Kinetic Interactions** - Enhanced 3D transforms with spring physics
- 🌟 **Holographic Cards** - Rotating conic gradients on hover
- 💧 **Liquid Glow** - Morphing blobs with pulsing aurora effects
- 🎭 **Advanced Text Animations** - Reveal, burst underlines, sparkles
- 🎨 **Live Theme Customizer** - Real-time colors, WCAG checker, effect toggles
- 🌊 **Extra-Deep Shadows** - 5-layer depths with aurora variants
- ⚡ **Ultra-Smooth Transitions** - Premium cubic-bezier easing everywhere

### 🎯 Responsive Features

- ✅ **Adaptive Breakpoints** - 9 breakpoints (xs, sm, md, lg, xl, 2xl, 3xl, 4K, ultra-wide)
- ✅ **Fluid Typography** - Text scales smoothly using CSS clamp() functions
- ✅ **Responsive Icons** - Icons scale proportionally at every breakpoint
- ✅ **Smart Sidebar** - Always visible on desktop (≥1024px), slide-in on mobile
- ✅ **Touch Targets** - Minimum 44x44px for all interactive elements
- ✅ **Responsive Grids** - Auto-adjusting columns based on viewport
- ✅ **Viewport Aware** - Real viewport height handling for mobile browsers
- ✅ **Orientation Support** - Seamless transitions between portrait/landscape

### 🌍 Device Support

| Device Type | Viewport | Status | Optimizations |
|------------|----------|---------|---------------|
| Mobile Small | 375px | ✅ Perfect | Touch targets, fluid text, compact layout |
| Mobile Large | 414px | ✅ Perfect | Enhanced spacing, readable text |
| Tablet | 768px | ✅ Perfect | 2-column grids, medium text |
| Laptop | 1024px | ✅ Perfect | Sidebar always visible, 3-column grids |
| Desktop | 1920px | ✅ Perfect | Full HD optimized, large text |
| 4K | 3840px | ✅ Perfect | Maximum clarity, extra whitespace |
| Ultra-wide | 2560px+ | ✅ Perfect | Optimized for cinema displays |

### 📸 Screenshots

**Light Mode Dashboard:**
![Megido Light Mode](https://github.com/user-attachments/assets/d892e776-23f3-40db-993f-01c6d1c77879)

**Dark Mode Dashboard:**
![Megido Dark Mode](https://github.com/user-attachments/assets/883298ba-436d-42a2-938c-33eb40f7c3c3)

> Note: Screenshots show the ultra-responsive v2.3 interface with cinema-grade effects and adaptive layouts.

### 📚 Documentation

- **[UI_V2.4_PROFESSIONAL_CLASSIC_GUIDE.md](UI_V2.4_PROFESSIONAL_CLASSIC_GUIDE.md)** - Professional classic design guide ⭐ NEW
  - **Complete v2.4 professional system**
  - **Refined typography and spacing**
  - **Classic card and button styles**
  - **Professional color palettes (emerald, sapphire, ruby, slate)**
  - **Enterprise-ready components**
  - **Timeless design patterns**
  - **Migration guide from v2.3+**

- **[UI_DESIGN_SYSTEM.md](UI_DESIGN_SYSTEM.md)** - Complete design system documentation
  - Extended color palette (50-950 scales)
  - Comprehensive component library with 88+ code examples
  - Glassmorphism and premium effects
  - Enhanced animations and transitions
  - Responsive utilities and breakpoints
  - Background patterns and utilities
  - Dark mode implementation
  - Accessibility guidelines (WCAG AA)
  - Best practices for extending the UI

- **[UI_V2.3_ULTRA_GUIDE.md](UI_V2.3_ULTRA_GUIDE.md)** - Ultra-cinema UI features ⭐ NEW
  - **Beyond v2.3 enhancements** with 360+ lines of ultra CSS effects
  - **Multi-layered glassmorphism** (4 variants)
  - **Animated mesh gradients** and living borders
  - **Ultra cursor system** with prism trails
  - **Holographic and kinetic effects**
  - **Theme customizer** with live color picker
  - **Advanced text animations** and micro-interactions
  - Complete implementation examples
  - Performance optimization guide
  - Migration guide from v2.2

### 🎨 Customization

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

### 🆕 What's New in UI v2.3 Ultra-Responsive

- **Universal Responsiveness**: Perfect scaling across all devices and screen sizes
- **Fluid Typography**: Text that scales smoothly with viewport using clamp()
- **Responsive Icons**: Icons adapt to screen size automatically
- **Smart Sidebar**: Desktop always-visible, mobile slide-in with backdrop
- **Touch-Optimized**: All buttons meet 44x44px minimum touch target
- **Viewport Height Fix**: Handles mobile browser address bars correctly
- **Orientation Support**: Seamless portrait/landscape transitions
- **Breakpoint Detection**: JavaScript utilities for responsive behavior
- **Adaptive Grids**: Auto-adjusting column counts per breakpoint
- **Container System**: Responsive padding and max-width constraints
- **Refined Color Palette**: Extended scales (50-950) for all colors
- **Advanced Shadows**: Premium, glow, and inner shadow variants
- **New Animations**: 12+ animation utilities including shimmer, bounce-subtle, scale-in
- **Form Enhancements**: Validation states, required field styling
- **Table Improvements**: Striped variants, better hover states
- **Alert System**: 4 alert variants with border accents
- **Background Patterns**: Dot and grid patterns for visual depth

## 🔄 Enhanced Intercepting Proxy ⭐ NEW

Megido includes a comprehensive **HTTP/HTTPS/WebSocket intercepting proxy** with advanced features for traffic analysis, request replay, and security testing:

### Key Features
- ✅ **Full Protocol Support** - HTTP, HTTPS, and WebSocket (WS/WSS)
- ✅ **Request Replay** - Replay captured requests to original or test endpoints
- ✅ **Authentication** - Optional proxy auth with token or credentials
- ✅ **Advanced Logging** - Database + file-based structured logs
- ✅ **WebSocket Capture** - Complete bidirectional message logging
- ✅ **IP Filtering** - Whitelist/blacklist support
- ✅ **Error Tracking** - Comprehensive error logging with recovery
- ✅ **CLI Tools** - Full-featured command-line interface
- ✅ **REST API** - Complete API for programmatic access
- ✅ **Django Admin** - Web-based management interface

### Quick Start
```bash
# 1. Apply migrations
python manage.py migrate proxy

# 2. Start Django server
python manage.py runserver

# 3. Start enhanced proxy (in another terminal)
mitmdump -s proxy_addon_enhanced.py --set api_url=http://localhost:8000

# 4. Use the proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
curl https://api.example.com
```

### Request Replay
```bash
# List captured requests
python proxy_replay_cli.py list

# Show request details
python proxy_replay_cli.py show 123

# Replay to original URL
python proxy_replay_cli.py replay 123

# Replay to test server
python proxy_replay_cli.py replay 123 --target-url http://localhost:3000

# Replay multiple requests
python proxy_replay_cli.py replay-range 100 110 --delay 1.0
```

### Features Highlights
- **Structured Logs**: Organized by date and type (requests/responses/websockets/errors/auth)
- **Performance Controls**: Configurable timeouts, body size limits, concurrent connections
- **Security**: Authentication tracking, IP filtering, audit trails
- **Reliability**: Graceful error handling, automatic retry, non-blocking logging

📖 **Complete Documentation**: See [PROXY_README.md](PROXY_README.md) for comprehensive usage guide and API reference.

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
- **XSS Plugin** - Advanced cross-site scripting testing with **callback-based verification** and **visual proof (GIF) generation** ⭐ NEW
  - Reduces false positives by verifying actual JavaScript execution
  - Supports Burp Collaborator, Interactsh, internal collaborator, or custom webhooks
  - Provides proof of exploitability for bug bounty submissions
  - Only reports XSS as SUCCESS when callback is confirmed
  - **Automatic GIF recording** of XSS exploitation for visual proof ⭐ NEW

**Documentation:**
- [CLICKJACKING_PLUGIN_GUIDE.md](CLICKJACKING_PLUGIN_GUIDE.md) - Comprehensive clickjacking plugin guide
- [EXPLOIT_PLUGINS_GUIDE.md](EXPLOIT_PLUGINS_GUIDE.md) - Plugin system overview and all available plugins
- [XSS_PLUGIN_GUIDE.md](XSS_PLUGIN_GUIDE.md) - Detailed XSS plugin documentation
- [XSS_CALLBACK_VERIFICATION_GUIDE.md](XSS_CALLBACK_VERIFICATION_GUIDE.md) - Callback verification system guide ⭐ NEW

## 🎥 XSS Visual Proof Generation ⭐ NEW FEATURE

Megido now automatically generates **animated GIF proofs** for verified XSS vulnerabilities! When an XSS exploit is confirmed:

1. **Automatic Browser Launch**: Opens the exploited URL in headless Playwright/Selenium
2. **Screenshot Recording**: Captures 2-3 seconds of the exploitation (alert boxes, DOM effects)
3. **GIF Generation**: Converts screenshots to an animated GIF using Pillow
4. **Report Integration**: GIF is embedded in HTML reports and linked in Markdown/JSON reports
5. **Media Storage**: Saved in `media/xss_gif_proofs/` directory

### Features

- ✅ **Zero Configuration** - Works out of the box when Playwright is installed
- ✅ **Security Focused** - URL sanitization, resource limits, timeout protection
- ✅ **Non-Blocking** - GIF capture errors don't interrupt scanning
- ✅ **Automatic Cleanup** - Old GIFs auto-deleted after 7 days
- ✅ **Multiple Reports** - GIF embedded in HTML, linked in Markdown/JSON
- ✅ **Download Support** - Direct download links in reports

### Requirements

```bash
# Install Playwright (preferred)
pip install playwright
playwright install chromium

# Or use existing Selenium (fallback)
pip install selenium
```

### Usage

GIF generation is automatic for all **VERIFIED** XSS findings:

```python
from scanner.plugins import get_registry

# Get XSS plugin
plugin = get_registry().get_plugin('xss')

# Run scan - GIFs are automatically generated for verified XSS
result = plugin.execute_attack(
    target_url='http://vulnerable-site.com',
    config={'callback_verification_enabled': True}
)

# Check findings for GIF proofs
for finding in result['findings']:
    if finding.get('verified') and finding.get('proof_gif'):
        print(f"Visual proof: {finding['proof_gif']}")
```

### Configuration

GIF capture can be customized via the `XSSGifCapture` class:

```python
from scanner.xss_gif_capture import XSSGifCapture

capture = XSSGifCapture(output_dir='custom/path')

# Capture GIF manually
gif_path = capture.capture_xss_proof(
    url='http://target.com/vuln?xss=<script>alert(1)</script>',
    payload='<script>alert(1)</script>',
    duration=3.0  # Max: 5 seconds
)
```

**Security Limits:**
- Max duration: 5 seconds
- Max file size: 10 MB
- Max screenshots: 10 per capture
- URL validation and sanitization
- Automatic cleanup of old files



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

### Static File Serving with WhiteNoise

Megido uses **WhiteNoise** for efficient static file serving in production. WhiteNoise allows Django to serve static files directly without requiring a separate web server like Nginx for static content.

#### Collecting Static Files

After any changes to static files (CSS, JavaScript, images), you must run the `collectstatic` command to gather all static files into the `staticfiles` directory:

```bash
python manage.py collectstatic --noinput
```

This command:
- Collects all static files from your apps and `STATICFILES_DIRS`
- Copies them to the `STATIC_ROOT` directory (`staticfiles/`)
- Prepares them for serving in production

**When to run collectstatic:**
- Before deploying to production
- After updating CSS, JavaScript, or image files
- After pulling changes that modify static files
- After installing or updating Django apps with static files

#### WhiteNoise Configuration

WhiteNoise is configured in `settings.py` with:
- Middleware placed immediately after `SecurityMiddleware`
- `STATIC_ROOT` set to `staticfiles/` directory
- `STATICFILES_DIRS` pointing to the `static/` directory

For enhanced performance, you can enable compression and caching by uncommenting the following line in `settings.py`:

```python
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
```

This will:
- Compress static files with gzip and Brotli
- Add unique hash to filenames for cache-busting
- Enable far-future cache headers

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