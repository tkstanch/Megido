# Browser & Interceptor Integration Guide

## Overview

This document describes the integrated browser and interceptor features, including the ON/OFF toggle functionality and how they work together.

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
