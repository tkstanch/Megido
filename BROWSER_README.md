# Integrated Browser

## Overview

The Megido Security platform provides **two browser options**:

1. **Web-based iframe browser** - Embedded browser within Django web interface
2. **CEF Desktop Browser** - Full Chromium browser as a desktop application ✨ **NEW**

Both browsers integrate seamlessly with all Megido apps, interceptor, and backend APIs.

### Iframe Browser (Web-based)

An **embedded iframe browser interface** within the Django application that connects to all enabled Django apps. It provides a toolbar with app integration buttons and tracks browser history and interactions.

**Limitations**: This is an embedded iframe within the web application, NOT a full browser. Many sites block iframe embedding (X-Frame-Options, CSP).

### CEF Browser (Desktop Application)

A **full-featured desktop browser** powered by CEF (Chromium Embedded Framework). Provides complete Chromium capabilities without iframe restrictions.

**See**: [CEF_INTEGRATION.md](browser/CEF_INTEGRATION.md) for detailed documentation.

**Quick Start**:
```bash
pip install cefpython3
python browser/desktop_launcher.py
```

## Features

- **Embedded Browser Interface**: Iframe-based web browser view for navigation
- **URL Navigation**: Address bar with forward/back/reload controls
- **Interceptor Integration**: Toggle to enable/disable request interception
- **App Integration**: Toolbar buttons for all enabled apps
- **Session Management**: Tracks browser sessions per user
- **History Tracking**: Records all visited URLs
- **Interaction Logging**: Logs which apps were used for which URLs
- **Real-time App Access**: Only shows buttons for enabled apps
- **Interceptor Status Display**: Visual indicator showing if interceptor is ON/OFF

## Interceptor Integration

### How It Works

When the interceptor is enabled:
1. The browser toolbar shows a green indicator: "🟢 Interceptor ON"
2. All navigation from the browser is flagged for interception
3. Requests can be inspected and modified in the Interceptor dashboard
4. The interceptor status syncs between browser and interceptor views

When the interceptor is disabled:
1. The browser toolbar shows a red indicator: "🔴 Interceptor OFF"
2. Navigation proceeds normally without interception
3. No requests are captured for inspection

### Toggle Interceptor

You can toggle the interceptor from two places:
- **From Browser**: Click the "Interceptor ON/OFF" button in the browser toolbar
- **From Interceptor Dashboard**: Use the toggle switch in `/interceptor/`

Both interfaces stay synchronized in real-time.

## Database Models

### BrowserSession
Represents a browser session:
- `user`: User who started the session (nullable for anonymous)
- `session_name`: Name/identifier for the session
- `started_at`: Session start timestamp
- `ended_at`: Session end timestamp (nullable for active sessions)
- `is_active`: Boolean flag for active sessions

### BrowserHistory
Tracks browser navigation history:
- `session`: Foreign key to BrowserSession
- `url`: Visited URL
- `title`: Page title (if available)
- `visited_at`: Timestamp of visit

### BrowserAppInteraction
Logs app interactions from the browser:
- `session`: Foreign key to BrowserSession
- `app_name`: Name of the app that was triggered
- `action`: Description of the action
- `target_url`: URL where the app was used
- `timestamp`: When the interaction occurred
- `result`: Result/outcome of the interaction

### BrowserSettings
Stores user browser preferences:
- `user`: One-to-one with User (nullable for anonymous)
- `default_user_agent`: Custom user agent string
- `enable_javascript`: JavaScript enabled flag
- `enable_images`: Image loading enabled flag
- `enable_plugins`: Plugin support flag
- `proxy_enabled`: Proxy usage flag
- `proxy_host`: Proxy server host
- `proxy_port`: Proxy server port
- `settings_json`: Additional settings in JSON format

## API Endpoints

### List Sessions
```
GET /browser/api/sessions/
```

Returns a list of browser sessions.

### Add History Entry
```
POST /browser/api/history/
Content-Type: application/json

{
    "session_id": 1,
    "url": "https://example.com",
    "title": "Example Domain"
}
```

Adds a URL to the browser history.

### Get Session History
```
GET /browser/api/history/<session_id>/
```

Returns the browsing history for a specific session.

### Log App Interaction
```
POST /browser/api/interaction/
Content-Type: application/json

{
    "session_id": 1,
    "app_name": "scanner",
    "action": "triggered_from_browser",
    "target_url": "https://example.com",
    "result": "Scan initiated"
}
```

Logs when an app is triggered from the browser.

### Get Enabled Apps
```
GET /browser/api/enabled-apps/
```

Returns a list of all currently enabled apps with their capabilities.

### Interceptor Status (GET/POST)
```
GET /browser/api/interceptor-status/
```

Returns the current interceptor status.

```
POST /browser/api/interceptor-status/
Content-Type: application/json

{
    "is_enabled": true
}
```

Toggles the interceptor ON or OFF from the browser interface.

## App Integration

The browser integrates with all enabled apps through the toolbar. Each app button triggers the corresponding app functionality:

- **Proxy**: Route traffic through HTTP proxy
- **Spider**: Crawl the current page
- **Scanner**: Scan current page for vulnerabilities
- **Interceptor**: Enable request interception
- **Repeater**: Send current page to repeater
- **Mapper**: Map attack surface
- **Bypasser**: Test WAF bypass techniques
- **Collaborator**: Monitor for out-of-band interactions
- **Decompiler**: Analyze browser extensions
- **Malware Analyser**: Scan page for malware
- **Response Analyser**: Analyze HTTP responses
- **SQL Attacker**: Test for SQL injection
- **Data Tracer**: Trace network data
- **Discover**: Gather OSINT on current domain
- **Manipulator**: Craft payloads for current context

## Usage

1. Navigate to `/browser/` to open the integrated browser
2. Enter a URL in the address bar and click "Go" button
3. Use the Interceptor toggle button to enable/disable request interception
4. Use the app toolbar buttons to trigger functionality
5. All navigation and interactions are automatically logged
6. View history and interactions in the admin panel

### Using the Interceptor

1. Click the "Interceptor OFF" button in the browser toolbar to enable it (turns green: "Interceptor ON")
2. Navigate to any URL - the request will be captured
3. Go to `/interceptor/` to view and modify intercepted requests
4. Click "Interceptor ON" to disable interception (turns red: "Interceptor OFF")

The interceptor status is synchronized across both the browser and interceptor dashboard views.
5. View history and interactions in the admin panel

## Security Considerations

- The browser iframe uses sandbox restrictions for security
- All navigation is logged for audit purposes
- User sessions are tracked for accountability
- App interactions are restricted to enabled apps
- CSRF protection on all API endpoints
- Interceptor can be toggled to inspect/modify requests before forwarding

## Important Limitations - iframe Browser

**Embedded Browser vs Desktop Browser:**
- The **iframe browser** has limitations due to web security policies
- Many websites block iframe embedding (X-Frame-Options, CSP headers)
- Sites like Google, Facebook, Twitter, etc. won't load in iframes
- JavaScript and plugin support is limited within iframes

**Solution: Use CEF Desktop Browser**

For full browser control and compatibility, use the **CEF desktop browser**:
- ✅ Complete Chromium engine with all features
- ✅ Works with ALL websites (no X-Frame-Options blocking)
- ✅ Full JavaScript, plugins, and modern web features
- ✅ Integrated Chrome Developer Tools (F12)
- ✅ Complete request interception
- ✅ All Megido app integration

**See [CEF_INTEGRATION.md](browser/CEF_INTEGRATION.md) for setup and usage.**

## Future Enhancements

The CEF desktop browser is now implemented! See [browser/CEF_INTEGRATION.md](browser/CEF_INTEGRATION.md).

Additional future enhancements for the web-based iframe browser:
- Enhanced cookie management
- More advanced local storage sync
- Better WebSocket support
- Screen capture within iframe limitations

## Screenshots

See the UI screenshots for visual representation of the browser interface.
