# Browser & Interceptor Integration Guide

## Overview

The Megido Security Platform now features a modern **PyQt6 Desktop Browser** with integrated **mitmproxy** for powerful HTTP/HTTPS traffic interception and modification. This replaces the previous CEF Python implementation with a Python 3.13-compatible solution.

## Architecture

### Components

1. **PyQt6 Desktop Browser** (`desktop_browser/megido_browser.py`)
   - Native desktop browser using Qt WebEngine
   - Automatic proxy configuration for mitmproxy
   - Real-time interceptor panel
   - Quick access toolbar for Megido apps

2. **mitmproxy Addon** (`proxy_addon.py`)
   - Intercepts all HTTP/HTTPS traffic
   - Applies payload rules automatically
   - Sends request/response data to Django API
   - Configurable source app tracking

3. **Enhanced Interceptor App** (`interceptor/`)
   - New models for requests, responses, and payload rules
   - RESTful API for mitmproxy integration
   - Django admin interface for management
   - History and filtering capabilities

4. **Launch Scripts**
   - `launch_megido_browser.py` - Main launcher (starts all components)
   - `launch_megido_browser.sh` - Linux/Mac launcher
   - `launch_megido_browser.bat` - Windows launcher

## New Features

### 1. PyQt6 Desktop Browser

The new browser offers:
- **Native Performance**: Full Qt WebEngine (Chromium-based)
- **Python 3.13 Compatible**: No CEF Python limitations
- **Integrated Interceptor Panel**: View intercepted requests in real-time
- **Proxy Configuration**: Automatic mitmproxy setup
- **App Shortcuts**: Quick access to Scanner, Spider, SQL Attacker, etc.
- **Navigation Controls**: Back, forward, reload, home
- **Certificate Helper**: Easy mitmproxy certificate installation

### 2. mitmproxy Integration

Traffic interception powered by mitmproxy:
- **HTTP/HTTPS Interception**: All traffic captured
- **Payload Injection**: Automatic rule-based payload insertion
- **Request Logging**: Every request sent to Django API
- **Response Tracking**: Response time and status tracking
- **Source App Tracking**: Know which app generated traffic
- **Rule Caching**: Efficient rule loading with TTL

### 3. Payload Rules System

Create rules for automatic payload injection:
- **Injection Types**: Header, URL parameter, cookie, request body
- **URL Pattern Matching**: Regex-based targeting
- **App Filtering**: Apply rules to specific apps only
- **Active/Inactive Toggle**: Enable/disable rules on the fly
- **Django Admin Interface**: Easy rule management

## Models

### InterceptedRequest
```python
class InterceptedRequest(models.Model):
    url = models.URLField(max_length=2000)
    method = models.CharField(max_length=10)
    headers = models.JSONField()
    body = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, ...)
    source_app = models.CharField(max_length=50)
```

### InterceptedResponse
```python
class InterceptedResponse(models.Model):
    request = models.OneToOneField(InterceptedRequest, ...)
    status_code = models.IntegerField()
    headers = models.JSONField()
    body = models.TextField()
    response_time = models.FloatField()
```

### PayloadRule
```python
class PayloadRule(models.Model):
    name = models.CharField(max_length=200)
    target_url_pattern = models.CharField(max_length=500)
    injection_type = models.CharField(...)  # header, body, param, cookie
    injection_point = models.CharField(max_length=100)
    payload_content = models.TextField()
    active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, ...)
    target_apps = models.JSONField(default=list)
```

## API Endpoints

### Request/Response Logging
- `POST /interceptor/api/request/` - Log intercepted request
- `POST /interceptor/api/response/` - Log intercepted response
- `GET /interceptor/api/request/<id>/` - Get request details

### Payload Rules
- `GET /interceptor/api/payload-rules/active/` - Get active rules (for mitmproxy)
- `GET /interceptor/api/payload-rules/` - List all rules
- `POST /interceptor/api/payload-rules/` - Create new rule
- `GET/PUT/DELETE /interceptor/api/payload-rules/<id>/` - Manage specific rule

### History & Injection
- `GET /interceptor/api/history/` - Get intercept history with filtering
- `POST /interceptor/api/inject/` - Manually trigger payload injection

### Legacy Endpoints
- `GET/POST /interceptor/api/status/` - Get/set interceptor status
- `GET /interceptor/api/intercepted/` - List intercepted requests (legacy)

## Usage Guide

### Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Migrations**
   ```bash
   python manage.py migrate
   ```

3. **Launch Browser** (All-in-One)
   ```bash
   # Linux/Mac
   ./launch_megido_browser.sh
   
   # Windows
   launch_megido_browser.bat
   
   # Python (cross-platform)
   python launch_megido_browser.py
   ```

This will automatically:
- Start Django development server
- Start mitmproxy with Megido addon
- Launch PyQt6 browser

### Manual Launch (Advanced)

1. **Start Django Server**
   ```bash
   python manage.py runserver
   ```

2. **Start mitmproxy**
   ```bash
   mitmdump -s proxy_addon.py --set api_url=http://localhost:8000 --listen-port 8080
   ```

3. **Launch Browser**
   ```bash
   python desktop_browser/megido_browser.py --django-url http://localhost:8000 --proxy-port 8080
   ```

### HTTPS Certificate Installation

To intercept HTTPS traffic:

1. Launch the browser
2. Navigate to `http://mitm.it`
3. Download certificate for your platform
4. Install as trusted root certificate

**Or use the helper dialog:**
- Browser will prompt if mitmproxy is not detected
- Click "Yes" to open certificate installation page

### Creating Payload Rules

#### Via Django Admin

1. Go to `/admin/interceptor/payloadrule/`
2. Click "Add Payload Rule"
3. Fill in:
   - **Name**: Descriptive name (e.g., "Add XSS Payload to Search")
   - **Target URL Pattern**: Regex (e.g., `.*search.*`)
   - **Injection Type**: Choose header/body/param/cookie
   - **Injection Point**: Name (e.g., `X-Custom-Header` or `q`)
   - **Payload Content**: Your payload
   - **Active**: Check to enable
   - **Target Apps**: Leave empty for all, or specify ["scanner", "spider"]
4. Save

#### Via API

```python
import requests

# Create a new payload rule
rule_data = {
    "name": "SQL Injection Test",
    "target_url_pattern": ".*login.*",
    "injection_type": "param",
    "injection_point": "username",
    "payload_content": "' OR 1=1--",
    "active": True,
    "target_apps": ["sql_attacker"]
}

response = requests.post(
    "http://localhost:8000/interceptor/api/payload-rules/",
    json=rule_data,
    headers={"Authorization": "Token YOUR_TOKEN"}
)
```

### Viewing Intercepted Traffic

#### In the Browser
- Interceptor panel on the right side shows real-time requests
- Filter by source app
- Double-click request for details
- Auto-refreshes every 2 seconds

#### In Django Admin
- Go to `/admin/interceptor/interceptedrequest/`
- Filter by method, source_app, timestamp
- Search URL or body content
- View associated responses

#### Via API
```python
import requests

# Get history for scanner app
response = requests.get(
    "http://localhost:8000/interceptor/api/history/",
    params={"source_app": "scanner"},
    headers={"Authorization": "Token YOUR_TOKEN"}
)

requests_data = response.json()
```

## Integration with Other Apps

Each Megido app can leverage the interceptor:

### Scanner Integration
```python
# In scanner app
from interceptor.models import InterceptedRequest

# All scanner requests automatically tagged with source_app='scanner'
# Retrieve scanner requests
scanner_requests = InterceptedRequest.objects.filter(source_app='scanner')
```

### SQL Attacker Integration
```python
# Create SQL injection payload rule
from interceptor.models import PayloadRule

rule = PayloadRule.objects.create(
    name="SQL Injection - Union Select",
    target_url_pattern=".*",
    injection_type="param",
    injection_point="id",
    payload_content="1' UNION SELECT NULL--",
    active=True,
    target_apps=["sql_attacker"],
    created_by=user
)
```

### Spider Integration
```python
# Spider discovers URLs from intercepted traffic
from interceptor.models import InterceptedRequest

discovered_urls = set()
for req in InterceptedRequest.objects.filter(source_app='spider'):
    discovered_urls.add(req.url)
```

## mitmproxy Addon Configuration

The `proxy_addon.py` supports these options:

```bash
mitmdump -s proxy_addon.py \
    --set api_url=http://localhost:8000 \
    --set source_app=browser \
    --set cache_ttl=60 \
    --listen-port 8080
```

Options:
- `api_url` - Django API base URL (default: http://localhost:8000)
- `source_app` - Source app identifier (default: browser)
- `cache_ttl` - Payload rules cache TTL in seconds (default: 60)

## Security Considerations

### Data Validation
- All data from mitmproxy is validated before storing
- JSON fields sanitized
- Body content size limited
- Headers filtered to exclude sensitive data

### Authentication
- API endpoints require authentication for sensitive operations
- `receive_request` and `receive_response` allow anonymous (for mitmproxy)
- All other endpoints require `IsAuthenticated`

### Rate Limiting
Consider adding rate limiting for production:
```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}
```

### Legal Use Warning
**IMPORTANT**: This tool is for authorized security testing only. Intercepting traffic without permission is illegal.

## Troubleshooting

### Browser Won't Start
- **Check dependencies**: `pip install -r requirements.txt`
- **Check Python version**: Requires Python 3.7+
- **Check Qt installation**: Try `python -c "from PyQt6 import QtCore"`

### mitmproxy Won't Start
- **Check installation**: `mitmdump --version`
- **Port already in use**: Change port with `--listen-port`
- **Addon not found**: Use absolute path to `proxy_addon.py`

### HTTPS Not Intercepted
- **Certificate not installed**: Go to `http://mitm.it` and install
- **Certificate not trusted**: Add to system trust store
- **Browser using different proxy**: Check browser proxy settings

### No Requests Logged
- **Django not accessible**: Check `api_url` setting
- **API endpoints failing**: Check Django logs
- **Proxy not configured**: Verify browser is using proxy

### Payload Rules Not Applied
- **Rules not active**: Check `active` field in admin
- **URL pattern wrong**: Test regex pattern
- **Cache not refreshed**: Wait for TTL or restart mitmproxy
- **Target apps mismatch**: Check `target_apps` field

## Performance Tips

1. **Limit Request Body Size**
   - Large bodies slow down storage
   - Consider truncating in mitmproxy addon

2. **Clean Old Data**
   ```python
   # Delete requests older than 7 days
   from datetime import timedelta
   from django.utils import timezone
   from interceptor.models import InterceptedRequest
   
   old_date = timezone.now() - timedelta(days=7)
   InterceptedRequest.objects.filter(timestamp__lt=old_date).delete()
   ```

3. **Use Database Indexes**
   - Models already have indexes on common filter fields
   - Monitor slow queries and add indexes as needed

4. **Cache Payload Rules**
   - mitmproxy addon caches rules
   - Adjust `cache_ttl` based on rule change frequency

## Migration from CEF Python

### What's Removed
- `cefpython3` dependency (incompatible with Python 3.13)
- `browser/cef_integration/` directory
- `setup_cef_browser.py`
- `launch_cef_browser.sh` and `launch_cef_browser.bat`
- `QUICKSTART_CEF.md`

### What's Added
- `PyQt6` and `PyQt6-WebEngine` dependencies
- `desktop_browser/` package
- `proxy_addon.py`
- `launch_megido_browser.py` and platform scripts
- Enhanced interceptor models and API

### Migration Steps
1. Update dependencies: `pip install -r requirements.txt`
2. Run migrations: `python manage.py migrate`
3. Remove old CEF files (see cleanup section)
4. Use new launch scripts

## Future Enhancements

1. **WebSocket Support**
   - Real-time updates in Django templates
   - Live interceptor dashboard

2. **Request Modification**
   - Edit requests before forwarding
   - Drop or replay requests
   - Manual rule testing

3. **Advanced Filtering**
   - Whitelist/blacklist domains
   - Method-based filtering
   - Content-type filtering

4. **Export Formats**
   - HAR file export
   - Burp Suite format
   - CSV export

5. **Session Management**
   - Link requests to browser sessions
   - Session-based filtering
   - Session replay

## Code Examples

### Check Interceptor Status
```python
from interceptor.models import InterceptorSettings

settings = InterceptorSettings.get_settings()
print(f"Interceptor: {'ON' if settings.is_enabled else 'OFF'}")
```

### Create Payload Rule Programmatically
```python
from interceptor.models import PayloadRule
from django.contrib.auth.models import User

user = User.objects.first()

rule = PayloadRule.objects.create(
    name="Add Custom Header",
    target_url_pattern=".*api.*",
    injection_type="header",
    injection_point="X-Custom-Header",
    payload_content="test-value",
    active=True,
    created_by=user,
    target_apps=["scanner", "spider"]
)
```

### Query Intercepted Requests
```python
from interceptor.models import InterceptedRequest
from datetime import timedelta
from django.utils import timezone

# Get recent requests
recent = InterceptedRequest.objects.filter(
    timestamp__gte=timezone.now() - timedelta(hours=1)
)

# Get requests by app
scanner_reqs = InterceptedRequest.objects.filter(source_app='scanner')

# Get requests with responses
with_responses = InterceptedRequest.objects.exclude(response__isnull=True)
```

## Support

For issues and questions:
- Check GitHub Issues: https://github.com/tkstanch/Megido/issues
- Review documentation: `/docs/` directory
- Check logs: `logs/` directory

## New Features Implemented

### 1. Interceptor ON/OFF Toggle

The interceptor now has a global ON/OFF state that can be toggled from two locations:

#### From the Interceptor Dashboard (`/interceptor/`)
- A visual toggle switch at the top of the dashboard
- Green indicator (🟢) when Active
- Red indicator (🔴) when Inactive
- Shows real-time status: "Active - Intercepting Requests" or "Inactive - Requests Pass Through"

#### From the Browser Toolbar (`/browser/`)
- A dedicated "Interceptor ON/OFF" button in the browser toolbar
- Changes color based on status (green when ON, red when OFF)
- Click to toggle the interceptor state
- Status syncs automatically with the interceptor dashboard

### 2. Browser Integration Enhancements

#### Embedded Browser Clarification
- The browser interface now clearly indicates it is an **embedded iframe browser**
- Not an external desktop browser like Firefox or Chrome
- Info message explains limitations and suggests CEF for future desktop integration

#### Interceptor Status Display
- Real-time status indicator in browser toolbar
- Auto-syncs every 3 seconds with the server
- Visual feedback when toggling interceptor state

#### Enhanced Navigation
- The "Go" button is fully functional and wired correctly
- When interceptor is ON, navigation is flagged for interception
- History logging includes interceptor state

## Technical Architecture

### Models

#### InterceptorSettings (New)
```python
class InterceptorSettings(models.Model):
    is_enabled = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
```

Singleton model that stores the global interceptor state.

### API Endpoints

#### Interceptor Status API
- **GET** `/interceptor/api/status/` - Get current interceptor status
- **POST** `/interceptor/api/status/` - Toggle interceptor ON/OFF

#### Browser Interceptor API
- **GET** `/browser/api/interceptor-status/` - Get status from browser
- **POST** `/browser/api/interceptor-status/` - Toggle from browser

Both endpoints return the same data format:
```json
{
    "is_enabled": true,
    "updated_at": "2026-02-07T10:00:00Z"
}
```

### State Synchronization

The interceptor state is synchronized across all views:
1. State is stored in the database (InterceptorSettings model)
2. Browser polls for status changes every 3 seconds
3. Any change from browser or interceptor dashboard updates the global state
4. All connected interfaces reflect the current state

## Usage Guide

### Basic Usage

1. **Open the Browser**
   - Navigate to `/browser/`
   - Enter a URL in the address bar
   - Click "Go" to navigate

2. **Enable Interceptor**
   - Click the "Interceptor OFF" button in the browser toolbar
   - Or go to `/interceptor/` and toggle the switch
   - Button/indicator turns green: "Interceptor ON"

3. **Navigate with Interception**
   - Enter a URL and click "Go"
   - Request is flagged for interception
   - View intercepted requests at `/interceptor/`

4. **Disable Interceptor**
   - Click "Interceptor ON" button to disable
   - Or toggle off from the interceptor dashboard
   - Button/indicator turns red: "Interceptor OFF"

### How Interception Works

When interceptor is **ON**:
- Browser navigation is flagged for interception
- Requests can be captured and modified before forwarding
- History entries note "Navigated with Interceptor ON"
- Visual indicator shows active state

When interceptor is **OFF**:
- Navigation proceeds normally without interception
- No request modification occurs
- Standard history logging

## Security Considerations

- Interceptor state is stored server-side (cannot be bypassed client-side)
- All state changes are logged with timestamps
- CSRF protection on all API endpoints
- User authentication recommended for production

## Limitations

### Embedded Browser Limitations
- Uses iframe which has security restrictions
- Many sites block iframe embedding (X-Frame-Options, CSP)
- Cannot modify browser settings like a real browser
- No access to browser extensions or dev tools

### For Full Browser Control
For production use with full browser control, consider:
- **CEF (Chromium Embedded Framework)** - Embed a full Chromium browser
- **Selenium WebDriver** - Automate real browsers
- **Puppeteer/Playwright** - Headless browser control with full API

## Testing

Run the test suite:
```bash
python manage.py test browser.tests
python manage.py test interceptor.tests
```

### Browser Tests
- `test_browser_view` - Verifies browser page loads with interceptor UI
- `test_interceptor_status_get` - Tests getting interceptor status
- `test_interceptor_status_toggle` - Tests toggling from browser

### Interceptor Tests
- `test_settings_singleton` - Verifies InterceptorSettings singleton pattern
- `test_default_disabled` - Confirms interceptor starts disabled
- `test_status_api_toggle` - Tests toggle functionality

## Future Enhancements

1. **Request Capture**
   - Actually capture HTTP requests when interceptor is ON
   - Route through a proxy server
   - Display in real-time in interceptor dashboard

2. **Request Modification**
   - Edit intercepted requests before forwarding
   - Modify headers, body, method, URL
   - Drop or replay requests

3. **Desktop Browser Integration**
   - Integrate CEF for full browser control
   - Support browser extensions
   - Developer tools integration

4. **Advanced Filtering**
   - Filter which requests to intercept (by URL pattern, method, etc.)
   - Whitelist/blacklist domains
   - Custom interception rules

## Troubleshooting

### Interceptor Won't Toggle
- Check browser console for JavaScript errors
- Verify CSRF token is present
- Ensure API endpoints are accessible

### Status Not Syncing
- Check network tab for API call failures
- Verify both browser and interceptor are using same session
- Check for database connection issues

### Browser Navigation Fails
- Some sites block iframe embedding
- Check browser console for security errors
- Try sites that allow iframe embedding (e.g., example.com)

## Code Examples

### Toggle Interceptor from JavaScript
```javascript
async function toggleInterceptor() {
    const response = await fetch('/browser/api/interceptor-status/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({ is_enabled: true })
    });
    const data = await response.json();
    console.log('Interceptor enabled:', data.is_enabled);
}
```

### Check Status from Python
```python
from interceptor.models import InterceptorSettings

settings = InterceptorSettings.get_settings()
if settings.is_enabled:
    print("Interceptor is ON")
else:
    print("Interceptor is OFF")
```

## Screenshots

Screenshots showing the UI changes are included in the PR for visual reference.
