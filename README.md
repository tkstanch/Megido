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

> **See Also:** [DOCKER_TESTING.md](DOCKER_TESTING.md) for additional production deployment guidance.

[...]rest of README untouched...