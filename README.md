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

### Scalable Production Architecture

For high-volume production deployments, consider moving heavy exploit tasks to **asynchronous background workers**:

- Use **Celery** with Redis/RabbitMQ for distributed task queuing
- Use **RQ (Redis Queue)** for simpler async task processing
- Implement job queuing for scan requests to prevent blocking web workers
- Add progress tracking and result retrieval via API endpoints

This architecture allows the web tier to remain responsive while exploitation tasks run in dedicated worker processes.

> **See Also:** [DOCKER_TESTING.md](DOCKER_TESTING.md) for additional production deployment guidance.

[...]rest of README untouched...