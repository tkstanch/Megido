# Scanner Dashboard Polling Implementation

## Overview

This implementation fixes the persistent network error issue on the scanner dashboard by adding automatic polling for scan results. Previously, the dashboard would show a "NetworkError when attempting to fetch resource" message because it only attempted to fetch results once after 2 seconds, without any follow-up polling.

## Problem Statement

- Dashboard displayed persistent network error after starting a scan
- No actual fetch/XHR request visible in browser Network tab
- Users never saw scan completion, results, or live updates
- Root cause: Missing JavaScript polling logic to fetch scan results after submission

## Solution

Implemented a robust polling system that:
- Automatically polls the scan results API endpoint (`/scanner/api/scans/<scan_id>/results/`) every 2 seconds
- Tracks scan status (pending, running, completed, failed)
- Stops polling when scan completes or fails
- Shows real-time progress updates with visual indicators
- Handles network errors gracefully with retry logic
- Integrates with existing MegidoToast notification system
- Properly escapes all dynamic content to prevent XSS

## Files Changed

### 1. `/static/js/scanner-dashboard.js` (NEW)

A standalone JavaScript module that provides polling functionality:

**Key Features:**
- Configurable polling interval (2 seconds by default)
- Maximum poll attempts limit (150 attempts = 5 minutes)
- Tracks consecutive failures separately from total attempts
- Automatic cleanup when polling completes or fails
- Clean public API with callback support

**Configuration Constants:**
```javascript
const POLL_INTERVAL_MS = 2000;           // Poll every 2 seconds
const MAX_POLL_ATTEMPTS = 150;           // 5 minutes worth of attempts
const MAX_CONSECUTIVE_FAILURES = 5;       // Show error after 5 consecutive failures
const INITIAL_DELAY_MS = 2000;           // Initial delay before first poll
```

**Public API:**
- `startPolling(scanId, onProgress, onComplete, onError)` - Start polling for scan results
- `stopPolling()` - Stop the active polling
- `isPolling()` - Check if polling is currently active
- `getCurrentScanId()` - Get the scan ID being polled

### 2. `/templates/scanner/dashboard.html` (MODIFIED)

Updated the dashboard template to integrate polling:

**Changes:**
- Added script tag to load `scanner-dashboard.js`
- Modified `startScan()` function to use polling API
- Added three callback functions:
  - `handleScanProgress(data)` - Updates UI during scan with spinner
  - `handleScanComplete(data)` - Shows results and success toast when scan completes
  - `handleScanError(message)` - Displays error messages
- Enhanced `loadResults()` as fallback with recursive polling
- Added proper HTML escaping for all dynamic content

## How It Works

### User Flow:

1. User enters target URL and clicks "Start Scan"
2. Dashboard creates scan target and initiates scan via API
3. `ScannerDashboard.startPolling()` is called with scan ID
4. Polling begins after 2-second initial delay
5. Every 2 seconds, the system fetches `/scanner/api/scans/<scan_id>/results/`
6. Based on scan status:
   - **pending/running**: Shows progress with spinner, continues polling
   - **completed**: Stops polling, shows success message, displays vulnerabilities
   - **failed**: Stops polling, shows error message

### Error Handling:

- **Network Errors**: Tracks consecutive failures
  - Retries automatically on temporary failures
  - Shows error to user only after 5 consecutive failures
  - Prevents false error messages during brief network hiccups
  
- **Timeout Protection**: Maximum 150 poll attempts (5 minutes)
  - If scan exceeds this time, user is prompted to refresh
  - Prevents infinite polling loops

- **Security**: All dynamic content is escaped using `escapeHtml()`
  - Prevents XSS attacks from malicious API responses
  - Consistent with existing security practices

## API Reference

### ScannerDashboard.startPolling()

Starts polling for scan results.

**Signature:**
```javascript
ScannerDashboard.startPolling(scanId, onProgress, onComplete, onError)
```

**Parameters:**
- `scanId` (number) - The scan ID to poll for results
- `onProgress` (function) - Called on each poll with progress data
  - Receives: `data` object with `status` and `vulnerabilities` array
- `onComplete` (function) - Called when scan completes successfully
  - Receives: `data` object with final results
- `onError` (function) - Called on error
  - Receives: `error` message string

**Example:**
```javascript
ScannerDashboard.startPolling(
    123,
    function(data) {
        console.log('Progress:', data.status, 'Vulns:', data.vulnerabilities.length);
    },
    function(data) {
        console.log('Completed! Found', data.vulnerabilities.length, 'vulnerabilities');
    },
    function(error) {
        console.error('Error:', error);
    }
);
```

### ScannerDashboard.stopPolling()

Stops the active polling immediately.

**Signature:**
```javascript
ScannerDashboard.stopPolling()
```

**Example:**
```javascript
ScannerDashboard.stopPolling();
```

### ScannerDashboard.isPolling()

Returns whether polling is currently active.

**Signature:**
```javascript
ScannerDashboard.isPolling()
```

**Returns:** `boolean` - `true` if polling is active, `false` otherwise

**Example:**
```javascript
if (ScannerDashboard.isPolling()) {
    console.log('Scan is in progress');
}
```

### ScannerDashboard.getCurrentScanId()

Returns the scan ID currently being polled.

**Signature:**
```javascript
ScannerDashboard.getCurrentScanId()
```

**Returns:** `number|null` - Current scan ID or `null` if not polling

**Example:**
```javascript
const scanId = ScannerDashboard.getCurrentScanId();
console.log('Polling scan:', scanId);
```

## Testing

### JavaScript Syntax Validation:
```bash
node -c static/js/scanner-dashboard.js
```

Expected output: ✓ JavaScript syntax is valid

### API Functionality Test:
```bash
node /tmp/test-scanner-dashboard.js
```

Expected output:
```
✅ Scanner Dashboard Polling System initialized
Testing ScannerDashboard API...

✓ ScannerDashboard API is available
✓ Methods: [ 'startPolling', 'stopPolling', 'isPolling', 'getCurrentScanId' ]
✓ startPolling is a function
✓ stopPolling is a function
✓ isPolling is a function
✓ getCurrentScanId is a function

✅ All tests passed!
```

### Django Template Validation:
```bash
DJANGO_SETTINGS_MODULE=megido_security.settings python -c "
from django.template import Template
import django
django.setup()

with open('templates/scanner/dashboard.html', 'r') as f:
    template_content = f.read()

template = Template(template_content)
print('✓ Template syntax is valid')
"
```

### Security Scan:
CodeQL analysis completed with 0 alerts - no security vulnerabilities found.

## Benefits

1. **No More False Errors**: Users only see errors when there's an actual network issue, not due to missing polling
2. **Live Updates**: Real-time scan progress with visual feedback (spinner animation)
3. **Automatic Completion Detection**: No manual refresh required to see results
4. **Better UX**: Clear progress indicators, success messages via MegidoToast, and proper error handling
5. **Robust Error Handling**: Distinguishes between temporary and permanent failures
6. **Separation of Concerns**: Polling logic isolated in dedicated, reusable module
7. **Security**: All dynamic content properly escaped to prevent XSS
8. **Maintainability**: Magic numbers extracted to named constants
9. **Extensibility**: Clean API makes it easy to add features or reuse in other components

## Configuration

The polling behavior can be customized by modifying constants in `static/js/scanner-dashboard.js`:

```javascript
const POLL_INTERVAL_MS = 2000;           // How often to poll (milliseconds)
const MAX_POLL_ATTEMPTS = 150;           // Maximum number of polls before timeout
const MAX_CONSECUTIVE_FAILURES = 5;       // Failures before showing error to user
const INITIAL_DELAY_MS = 2000;           // Delay before starting to poll
```

**Recommendations:**
- `POLL_INTERVAL_MS`: Keep at 2000ms (2 seconds) for good balance between responsiveness and server load
- `MAX_POLL_ATTEMPTS`: Adjust based on expected scan duration (150 × 2s = 5 minutes default)
- `MAX_CONSECUTIVE_FAILURES`: Keep at 5 to allow for brief network hiccups without alarming users
- `INITIAL_DELAY_MS`: 2000ms gives the scan time to initialize before first check

## Browser Compatibility

The implementation uses modern JavaScript features:
- `async/await` - Supported in all modern browsers
- `fetch API` - Supported in all modern browsers
- Template literals - Supported in all modern browsers
- Optional chaining (`?.`) - Supported in Chrome 80+, Firefox 74+, Safari 13.1+

For older browser support, consider using Babel transpilation.

## Future Enhancements

Potential improvements for future versions:

1. **WebSocket Support**: Add real-time updates via WebSocket as alternative to polling
2. **Exponential Backoff**: Reduce polling frequency as scan runs longer
3. **Progress Percentage**: Show estimated completion percentage if API provides it
4. **Pause/Resume**: Allow users to pause and resume polling
5. **Multiple Scans**: Support polling multiple scans simultaneously
6. **Offline Detection**: Detect offline state and pause polling automatically
7. **Scan History**: Store completed scan results in localStorage for quick access

## Related Files

- `/static/js/megido-toast.js` - Toast notification system used for user feedback
- `/scanner/views.py` - Backend API endpoints for scans and results
- `/scanner/models.py` - Scan data models
- `/templates/base.html` - Base template that loads core JavaScript files

## Support

For issues or questions:
1. Check browser console for JavaScript errors
2. Verify network tab shows polling requests to `/scanner/api/scans/<id>/results/`
3. Check server logs for API endpoint errors
4. Ensure MegidoToast is loaded (required for error notifications)

## Changelog

### Version 1.0 (Initial Release)
- Created scanner-dashboard.js polling module
- Integrated polling into dashboard template
- Added progress, completion, and error callbacks
- Implemented retry logic for network failures
- Added XSS protection via HTML escaping
- Extracted configuration constants
- Added comprehensive documentation
- Passed all tests and security scans
