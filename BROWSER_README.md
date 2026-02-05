# Integrated Browser

## Overview

The Integrated Browser is a browser interface component that embeds within the Django application and connects to all enabled Django apps. It provides a toolbar with app integration buttons and tracks browser history and interactions.

## Features

- **Browser Interface**: Embedded web browser view for navigation
- **URL Navigation**: Address bar with forward/back controls
- **App Integration**: Toolbar buttons for all enabled apps
- **Session Management**: Tracks browser sessions per user
- **History Tracking**: Records all visited URLs
- **Interaction Logging**: Logs which apps were used for which URLs
- **Real-time App Access**: Only shows buttons for enabled apps

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
2. Enter a URL in the address bar and click "Go"
3. Use the app toolbar buttons to trigger functionality
4. All navigation and interactions are automatically logged
5. View history and interactions in the admin panel

## Security Considerations

- The browser iframe uses sandbox restrictions
- All navigation is logged for audit purposes
- User sessions are tracked for accountability
- App interactions are restricted to enabled apps
- CSRF protection on all API endpoints

## Future Enhancements

In a production environment, this would be enhanced with:
- Full browser engine integration (e.g., via CEF or similar)
- Proper SSL certificate handling
- Cookie management
- Local storage support
- Developer tools integration
- Screen capture capabilities
- Network traffic capture
- WebSocket support for real-time updates

## Screenshots

See the UI screenshots for visual representation of the browser interface.
