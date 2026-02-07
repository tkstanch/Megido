# Interceptor API Documentation

This document describes the API endpoints for the Megido Interceptor app, which works with mitmproxy to intercept and log HTTP/HTTPS traffic.

## Table of Contents

- [Authentication](#authentication)
- [Request Logging](#request-logging)
- [Response Logging](#response-logging)
- [Payload Rules](#payload-rules)
- [History & Filtering](#history--filtering)
- [Manual Injection](#manual-injection)
- [Interceptor Status](#interceptor-status)

## Authentication

Most API endpoints require authentication using Django's authentication system:

- **Session Authentication**: Logged-in users via browser
- **Token Authentication**: For API clients (if configured)

Some endpoints (like `receive_request` and `receive_response`) allow anonymous access for mitmproxy addon integration.

## Request Logging

### POST /interceptor/api/request/

Log an intercepted HTTP request from mitmproxy.

**Authentication:** Not required (for mitmproxy addon)

**Request Body:**
```json
{
    "url": "https://example.com/api/users",
    "method": "POST",
    "headers": {
        "Content-Type": "application/json",
        "Authorization": "Bearer token123"
    },
    "body": "{\"username\": \"testuser\"}",
    "source_app": "scanner"
}
```

**Response:**
```json
{
    "success": true,
    "request_id": 123,
    "data": {
        "id": 123,
        "url": "https://example.com/api/users",
        "method": "POST",
        "headers": {...},
        "body": "...",
        "timestamp": "2026-02-07T12:00:00Z",
        "user": null,
        "source_app": "scanner"
    }
}
```

## Response Logging

### POST /interceptor/api/response/

Log an intercepted HTTP response from mitmproxy.

**Authentication:** Not required (for mitmproxy addon)

**Request Body:**
```json
{
    "request_id": 123,
    "status_code": 200,
    "headers": {
        "Content-Type": "application/json"
    },
    "body": "{\"success\": true}",
    "response_time": 156.78
}
```

**Response:**
```json
{
    "success": true,
    "response_id": 456,
    "data": {
        "id": 456,
        "request": {...},
        "status_code": 200,
        "headers": {...},
        "body": "...",
        "response_time": 156.78
    }
}
```

## Payload Rules

### GET /interceptor/api/payload-rules/active/

Get active payload rules for mitmproxy addon.

**Authentication:** Not required

**Query Parameters:**
- `source_app` (optional): Filter rules by source app

**Response:**
```json
{
    "success": true,
    "count": 2,
    "rules": [
        {
            "id": 1,
            "name": "Add XSS Header",
            "target_url_pattern": ".*login.*",
            "injection_type": "header",
            "injection_point": "X-XSS-Test",
            "payload_content": "<script>alert(1)</script>",
            "active": true,
            "created_by": 1,
            "created_by_username": "admin",
            "target_apps": ["scanner"],
            "created_at": "2026-02-07T10:00:00Z",
            "updated_at": "2026-02-07T10:00:00Z"
        }
    ]
}
```

### GET /interceptor/api/payload-rules/

List all payload rules (with filtering and search).

**Authentication:** Required

**Query Parameters:**
- `search`: Search in name or URL pattern
- `ordering`: Order by field (e.g., `created_at`, `-name`)
- `page`: Page number
- `page_size`: Items per page

**Response:**
```json
{
    "count": 10,
    "next": "http://localhost:8000/interceptor/api/payload-rules/?page=2",
    "previous": null,
    "results": [...]
}
```

### POST /interceptor/api/payload-rules/

Create a new payload rule.

**Authentication:** Required

**Request Body:**
```json
{
    "name": "SQL Injection Test",
    "target_url_pattern": ".*api.*",
    "injection_type": "param",
    "injection_point": "id",
    "payload_content": "1' OR '1'='1",
    "active": true,
    "target_apps": ["sql_attacker"]
}
```

**Response:**
```json
{
    "id": 2,
    "name": "SQL Injection Test",
    ...
}
```

### GET/PUT/PATCH/DELETE /interceptor/api/payload-rules/{id}/

Retrieve, update, or delete a specific payload rule.

**Authentication:** Required

**GET Response:**
```json
{
    "id": 2,
    "name": "SQL Injection Test",
    "target_url_pattern": ".*api.*",
    "injection_type": "param",
    "injection_point": "id",
    "payload_content": "1' OR '1'='1",
    "active": true,
    "created_by": 1,
    "created_by_username": "admin",
    "target_apps": ["sql_attacker"],
    "created_at": "2026-02-07T10:00:00Z",
    "updated_at": "2026-02-07T10:00:00Z"
}
```

## History & Filtering

### GET /interceptor/api/history/

Get intercept history with filtering and search.

**Authentication:** Required

**Query Parameters:**
- `source_app`: Filter by source app (e.g., `scanner`, `spider`)
- `method`: Filter by HTTP method (e.g., `GET`, `POST`)
- `start_date`: Filter by start date (ISO format)
- `end_date`: Filter by end date (ISO format)
- `search`: Search in URL, method, or body
- `ordering`: Order by field (default: `-timestamp`)

**Response:**
```json
[
    {
        "id": 123,
        "url": "https://example.com/api/users",
        "method": "POST",
        "headers": {...},
        "body": "...",
        "timestamp": "2026-02-07T12:00:00Z",
        "user": null,
        "source_app": "scanner"
    }
]
```

### GET /interceptor/api/request/{id}/

Get detailed information about an intercepted request including its response.

**Authentication:** Required

**Response:**
```json
{
    "success": true,
    "request": {
        "id": 123,
        "url": "https://example.com/api/users",
        "method": "POST",
        "headers": {...},
        "body": "...",
        "timestamp": "2026-02-07T12:00:00Z",
        "user": null,
        "source_app": "scanner"
    },
    "response": {
        "id": 456,
        "status_code": 200,
        "headers": {...},
        "body": "...",
        "response_time": 156.78
    }
}
```

## Manual Injection

### POST /interceptor/api/inject/

Manually trigger payload injection for testing.

**Authentication:** Required

**Request Body:**
```json
{
    "request_id": 123,
    "payload_rule_id": 2
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "original_request": {...},
        "rule_applied": {...},
        "message": "Payload injection simulated. Use mitmproxy for real-time injection."
    }
}
```

## Interceptor Status

### GET /interceptor/api/status/

Get current interceptor ON/OFF status.

**Authentication:** Not required

**Response:**
```json
{
    "is_enabled": true,
    "updated_at": "2026-02-07T12:00:00Z"
}
```

### POST /interceptor/api/status/

Toggle interceptor ON/OFF.

**Authentication:** Not required

**Request Body:**
```json
{
    "is_enabled": true
}
```

**Response:**
```json
{
    "success": true,
    "is_enabled": true,
    "message": "Interceptor enabled"
}
```

## Error Responses

All endpoints return error responses in this format:

```json
{
    "success": false,
    "error": "Error message here"
}
```

Common HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

## Integration Examples

### Python with requests

```python
import requests

# Log a request
data = {
    "url": "https://example.com/api",
    "method": "GET",
    "headers": {"User-Agent": "Mozilla/5.0"},
    "body": "",
    "source_app": "scanner"
}

response = requests.post(
    "http://localhost:8000/interceptor/api/request/",
    json=data
)

request_id = response.json()["request_id"]
print(f"Request logged with ID: {request_id}")

# Get active payload rules
response = requests.get(
    "http://localhost:8000/interceptor/api/payload-rules/active/",
    params={"source_app": "scanner"}
)

rules = response.json()["rules"]
for rule in rules:
    print(f"Rule: {rule['name']}")
```

### JavaScript with fetch

```javascript
// Log a request
const logRequest = async () => {
    const response = await fetch('http://localhost:8000/interceptor/api/request/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: 'https://example.com/api',
            method: 'GET',
            headers: {},
            body: '',
            source_app: 'browser'
        })
    });
    
    const data = await response.json();
    console.log('Request ID:', data.request_id);
};

// Get history
const getHistory = async () => {
    const response = await fetch('http://localhost:8000/interceptor/api/history/?source_app=scanner', {
        headers: {
            'Authorization': 'Token YOUR_TOKEN'
        }
    });
    
    const requests = await response.json();
    console.log(`Found ${requests.length} requests`);
};
```

### mitmproxy addon

See `proxy_addon.py` for a complete example of integrating with mitmproxy.

## Rate Limiting

Consider implementing rate limiting for production environments to prevent abuse:

```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}
```

## Security Considerations

1. **Sensitive Data**: Be careful logging sensitive data (passwords, tokens, etc.)
2. **Rate Limiting**: Implement rate limiting in production
3. **Authentication**: Consider requiring authentication for all endpoints in production
4. **Input Validation**: All input is validated, but be aware of size limits
5. **HTTPS**: Use HTTPS in production to protect data in transit

## Support

For issues or questions:
- GitHub Issues: https://github.com/tkstanch/Megido/issues
- Documentation: See BROWSER_INTERCEPTOR_INTEGRATION.md
