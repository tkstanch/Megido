# Network Error Handling Configuration

## Overview

Megido Security now includes a centralized error handling system that provides improved user experience when network errors or backend connectivity issues occur. This document explains how the error handling works and how to configure it.

## Features

### User-Facing Error Notifications

When network errors occur, users will see:
- **Clear error messages** instead of silent failures
- **Actionable advice** (e.g., "Check that the backend server is running", "Verify the API endpoint URL")
- **Retry buttons** for failed requests
- **Debug information** when debug mode is enabled

### Automatic Retry with Exponential Backoff

The error handler automatically retries failed requests with:
- **Configurable retry attempts** (default: 3 retries)
- **Exponential backoff** (1s, 2s, 4s, 8s, etc.)
- **Maximum delay cap** (default: 30 seconds)
- **Retry status indicators** showing retry progress to users

### Error Classification

Errors are categorized as:
- **Network errors**: Cannot reach the server
- **Server errors (5xx)**: Backend issues
- **Client errors (4xx)**: Configuration or authentication issues
- **CORS errors**: Cross-origin policy blocking
- **Timeout errors**: Request took too long

## Configuration

### Debug Mode

Debug mode can be enabled in Django settings to show detailed error information to users:

```python
# settings.py
DEBUG = True  # Shows detailed debug info in error notifications
```

The debug mode is automatically passed from Django to the JavaScript error handler through the base template.

### Adjusting Retry Configuration

You can customize retry behavior when using the error handler:

```javascript
// Using the centralized error handler with custom retry config
MegidoErrorHandler.fetchWithRetry('/api/endpoint/', {
    method: 'GET',
    retries: 5,  // Maximum retry attempts
    errorContext: 'Loading data'  // Context for error messages
});
```

Available configuration options:

- `retries`: Maximum number of retry attempts (default: 3)
- `onRetry`: Callback function called on each retry attempt
- `errorContext`: Context description for error messages
- `timeout`: Request timeout in milliseconds (default: 30000)

### Error Handler Configuration

The error handler can be configured globally:

```javascript
// Set debug mode programmatically
MegidoErrorHandler.setDebugMode(true);

// Adjust retry configuration
MegidoErrorHandler.config.retryConfig = {
    maxRetries: 5,
    initialDelay: 2000,
    maxDelay: 60000,
    backoffMultiplier: 2,
    retryableStatuses: [408, 429, 500, 502, 503, 504]
};
```

## Troubleshooting Network Errors

### "Network error: Unable to reach the server"

This error typically means:
1. **Backend server is not running**
   - Check if Django development server is running: `python manage.py runserver`
   - For production: Check if Gunicorn/uWSGI is running

2. **Wrong API endpoint URL**
   - Verify the API endpoint URL in your request
   - Check if the URL path is correct

3. **Network connectivity issues**
   - Check firewall settings
   - Verify network connection

### "HTTP 500: Internal Server Error"

This indicates a backend server issue:
1. Check Django server logs for error details
2. Look for stack traces in the console
3. Verify database connectivity
4. Check for missing dependencies or configuration

### "HTTP 404: Not Found"

The API endpoint may be misconfigured:
1. Verify the API URL path is correct
2. Check Django URL routing configuration
3. Ensure the endpoint is registered in `urls.py`

### "HTTP 403: Forbidden" or "HTTP 401: Unauthorized"

Authentication or permission issues:
1. Check if CSRF token is properly included in requests
2. Verify user authentication status
3. Check API endpoint permissions

### CORS Errors

If you see CORS policy errors:
1. Configure CORS settings in Django:
   ```python
   # settings.py
   CORS_ALLOWED_ORIGINS = [
       "http://localhost:3000",
       "http://127.0.0.1:8000",
   ]
   ```
2. Install `django-cors-headers` if needed
3. Add `'corsheaders'` to `INSTALLED_APPS`
4. Add CORS middleware to `MIDDLEWARE`

## API Endpoint Configuration

### Verifying Backend Status

To check if the backend is running and accessible:

```bash
# Test backend connectivity
curl http://localhost:8000/api/health/  # If health endpoint exists
# OR
curl http://localhost:8000/admin/  # Should return Django admin page
```

### Configuring API Base URL

For production deployments, you may need to configure the API base URL:

1. **Environment variables** (recommended):
   ```bash
   export API_BASE_URL=https://api.megido-security.com
   ```

2. **Django settings**:
   ```python
   # settings.py
   API_BASE_URL = os.environ.get('API_BASE_URL', 'http://localhost:8000')
   ```

3. **JavaScript configuration**:
   ```javascript
   // In your template or config file
   window.MEGIDO_API_BASE = '{{ API_BASE_URL }}';
   ```

## Dashboards with Enhanced Error Handling

The following dashboards now have improved error handling:

- **Spider Dashboard** (`/spider/`) - Web crawling and discovery
- **Proxy Dashboard** (`/proxy/`) - HTTP/HTTPS traffic monitoring
- **Repeater Dashboard** (`/repeater/`) - Manual request crafting
- **Collaborator Dashboard** (`/collaborator/`) - Interaction monitoring
- **SQL Attacker Dashboard** (`/sql_attacker/`) - SQL injection testing
- **Response Analyser Dashboard** (`/response_analyser/`) - Response analysis

## Developer Guide

### Using the Error Handler in Custom Code

To use the centralized error handler in custom dashboard code:

```javascript
// Simple usage with automatic error notification
async function loadData() {
    try {
        const response = await MegidoErrorHandler.fetchWithNotification('/api/data/', {
            method: 'GET',
            errorContext: 'Loading data'
        });
        const data = await response.json();
        // Process data...
    } catch (error) {
        // Error already shown to user via notification
        console.error('Failed to load data:', error);
    }
}

// Advanced usage with custom retry callback
async function saveData(data) {
    try {
        const response = await MegidoErrorHandler.fetchWithRetry('/api/save/', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data),
            retries: 5,
            errorContext: 'Saving data',
            onRetry: (attempt, maxAttempts, delay) => {
                console.log(`Retry ${attempt}/${maxAttempts} in ${delay}ms`);
            }
        });
        return await response.json();
    } catch (error) {
        // Show custom error notification
        MegidoErrorHandler.showErrorNotification(error, {
            title: 'Failed to Save Data',
            retryCallback: () => saveData(data)
        });
        throw error;
    }
}
```

### Creating Custom Error Objects

```javascript
// Create a standardized error object
const error = MegidoErrorHandler.createError({
    message: 'Custom error message',
    status: 500,
    isNetworkError: false,
    isRetryable: true,
    debugInfo: {
        url: '/api/endpoint',
        method: 'POST',
        additionalInfo: 'Custom debug data'
    }
});
```

## Support

If you encounter persistent network errors or configuration issues:

1. **Check logs**: Review Django server logs and browser console
2. **Enable debug mode**: Set `DEBUG = True` in Django settings for detailed error information
3. **Test connectivity**: Use `curl` or browser dev tools to test API endpoints directly
4. **Review configuration**: Double-check API URLs, CORS settings, and authentication

For issues specific to network connectivity or configuration, consult the main [README.md](../README.md) or open an issue on the project repository.
