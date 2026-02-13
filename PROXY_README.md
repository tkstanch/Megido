# Megido Proxy - Enhanced HTTP/HTTPS/WebSocket Interceptor

## Overview

The Megido Proxy is a comprehensive intercepting proxy built on mitmproxy with Django backend integration. It provides advanced traffic analysis, request replay, WebSocket support, authentication, and extensive logging capabilities.

## Features

### ✅ Complete Protocol Support
- **HTTP/HTTPS**: Full support for standard web traffic with automatic SSL/TLS handling
- **WebSocket**: Native WebSocket message capture and analysis (both WS and WSS)
- **Transparent Interception**: Works seamlessly with any HTTP client

### 🔐 Security & Authentication
- **Proxy Authentication**: Optional username/password or token-based authentication
- **IP Filtering**: Whitelist and blacklist support for source IPs
- **Authentication Logging**: Complete audit trail of all auth attempts
- **Secure Configuration**: Token-based API access

### 📝 Advanced Logging
- **Database Storage**: All requests/responses stored in Django models
- **File-Based Logs**: Structured JSON logs organized by date and type
- **Detailed Metadata**: Source IP, timestamps, payload sizes, user agents
- **WebSocket Messages**: Complete capture of bidirectional WebSocket traffic
- **Error Tracking**: Comprehensive error logging with stack traces

### 🔄 Request Replay
- **CLI Tool**: Full-featured command-line tool for replaying requests
- **API Endpoint**: Programmatic replay via REST API
- **Target Override**: Replay to original or alternative endpoints
- **Batch Replay**: Replay multiple requests with configurable delays
- **Replay Tracking**: All replays linked to original requests

### ⚡ Performance & Reliability
- **Connection Timeouts**: Configurable connection and transfer timeouts
- **Retry Logic**: Automatic retry for failed API logging
- **Body Size Limits**: Prevent memory issues with large payloads
- **Error Recovery**: Graceful handling of all error conditions
- **Non-Blocking**: Logging failures don't crash the proxy

### 🎨 User Interface
- **Django Admin**: Full admin interface for all models
- **Dashboard**: Web-based traffic analysis dashboard
- **REST API**: Complete REST API for programmatic access
- **Statistics**: Real-time proxy statistics and metrics

## Installation

### Prerequisites

```bash
# Required packages (included in requirements.txt)
pip install mitmproxy>=10.0.0
pip install Django>=6.0.0
pip install djangorestframework>=3.14.0
pip install requests>=2.31.0
```

### Setup

1. **Apply Database Migrations**:
```bash
python manage.py makemigrations proxy
python manage.py migrate proxy
```

2. **Create Log Directories** (automatic on first run):
```bash
mkdir -p logs/proxy/{requests,responses,websockets,errors,auth}
```

3. **Configure Proxy** (optional - via Django admin or API):
```bash
python manage.py createsuperuser
python manage.py runserver
# Visit http://localhost:8000/admin/proxy/proxyconfiguration/
```

## Usage

### Starting the Proxy

#### Basic Usage (HTTP/HTTPS)
```bash
# Start with mitmdump (command-line)
mitmdump -s proxy_addon_enhanced.py --set api_url=http://localhost:8000

# Start with mitmproxy (interactive)
mitmproxy -s proxy_addon_enhanced.py --set api_url=http://localhost:8000

# Start with mitmweb (web interface)
mitmweb -s proxy_addon_enhanced.py --set api_url=http://localhost:8000
```

#### With Authentication
```bash
mitmdump -s proxy_addon_enhanced.py \
  --set api_url=http://localhost:8000 \
  --set auth_required=true \
  --set auth_token=your-secret-token-here
```

#### Advanced Configuration
```bash
mitmdump -s proxy_addon_enhanced.py \
  --set api_url=http://localhost:8000 \
  --set source_app=scanner \
  --set max_body_size=5242880 \
  --set connection_timeout=60 \
  --set websocket_enabled=true
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_url` | string | `http://localhost:8000` | Django API base URL |
| `source_app` | string | `browser` | Source identifier (browser, scanner, etc.) |
| `auth_required` | bool | `false` | Enable proxy authentication |
| `auth_token` | string | `""` | Authentication token |
| `max_body_size` | int | `1048576` | Max body size to log (bytes) |
| `websocket_enabled` | bool | `true` | Enable WebSocket logging |
| `connection_timeout` | int | `30` | Connection timeout (seconds) |
| `cache_ttl` | int | `60` | Payload rules cache TTL (seconds) |

### Request Replay CLI

The `proxy_replay_cli.py` tool provides comprehensive request replay functionality.

#### List Captured Requests
```bash
# List recent requests
python proxy_replay_cli.py list

# List with filters
python proxy_replay_cli.py list --limit 50 --method POST --url api.example.com
```

#### Show Request Details
```bash
# Show full request and response details
python proxy_replay_cli.py show 123
```

#### Replay Single Request
```bash
# Replay to original URL
python proxy_replay_cli.py replay 123

# Replay to test server
python proxy_replay_cli.py replay 123 --target-url http://localhost:3000/api/test

# Replay with verbose output
python proxy_replay_cli.py replay 123 --verbose

# Replay without SSL verification (for testing)
python proxy_replay_cli.py replay 123 --no-verify-ssl
```

#### Replay Multiple Requests
```bash
# Replay a range of requests
python proxy_replay_cli.py replay-range 100 110

# Replay with custom delay and target
python proxy_replay_cli.py replay-range 100 110 \
  --target-url http://localhost:3000 \
  --delay 1.0
```

### REST API Usage

#### List Requests
```bash
# Get all requests
curl http://localhost:8000/proxy/api/requests/

# With filters
curl "http://localhost:8000/proxy/api/requests/?method=POST&protocol=HTTPS&limit=50"

# Search
curl "http://localhost:8000/proxy/api/requests/?search=api.example.com"
```

#### Get Request Details
```bash
curl http://localhost:8000/proxy/api/requests/123/
```

#### Replay Request
```bash
# Replay to original URL
curl -X POST http://localhost:8000/proxy/api/requests/123/replay/

# Replay to test URL
curl -X POST http://localhost:8000/proxy/api/requests/123/replay/ \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:3000/test"}'
```

#### WebSocket Messages
```bash
# List all WebSocket messages
curl http://localhost:8000/proxy/api/websocket-messages/list/

# Filter by connection
curl "http://localhost:8000/proxy/api/websocket-messages/list/?connection_id=ws_12345"
```

#### Error Logs
```bash
# List errors
curl http://localhost:8000/proxy/api/errors/list/

# Filter by type
curl "http://localhost:8000/proxy/api/errors/list/?error_type=TIMEOUT"
```

#### Statistics
```bash
# Get proxy statistics
curl http://localhost:8000/proxy/api/stats/
```

### Python API

```python
from proxy.models import ProxyRequest, ProxyResponse, WebSocketMessage
from proxy.replay_utils import replay_from_database
from proxy.logging_utils import ProxyLogger

# Query requests
recent_requests = ProxyRequest.objects.filter(
    protocol='HTTPS',
    method='POST'
).order_by('-timestamp')[:10]

# Replay a request
result = replay_from_database(
    request_id=123,
    target_url='http://localhost:3000/test'
)

if result.get('success'):
    print(f"Replay successful: {result['response']['status_code']}")

# Access file logs
logger = ProxyLogger()
recent_logs = logger.get_recent_logs('requests', limit=50)

# Cleanup old logs (30 days)
removed = logger.cleanup_old_logs(days_to_keep=30)
```

## Configuration

### Django Admin Configuration

Access the proxy configuration at: `http://localhost:8000/admin/proxy/proxyconfiguration/`

#### Authentication Settings
- **Enable Authentication**: Require credentials for proxy access
- **Username/Password**: Basic authentication (if supported by client)
- **Auth Token**: Bearer token for API-style authentication

#### IP Filtering
- **Whitelist**: Comma-separated list of allowed IPs (e.g., `192.168.1.100, 10.0.0.50`)
- **Blacklist**: Comma-separated list of blocked IPs

#### Logging Settings
- **Enable Logging**: Master switch for all logging
- **Log Request Body**: Include request bodies in logs
- **Log Response Body**: Include response bodies in logs
- **Log Directory**: Path to log directory (default: `logs/proxy`)

#### Performance Settings
- **Connection Timeout**: Maximum time to wait for connection (seconds)
- **Transfer Timeout**: Maximum time for data transfer (seconds)
- **Max Concurrent Clients**: Maximum simultaneous proxy connections
- **Enable Caching**: Cache static assets (if relevant)

#### Features
- **Enable WebSocket**: Log WebSocket traffic

### Environment Variables

You can also configure via environment variables:

```bash
export PROXY_API_URL=http://localhost:8000
export PROXY_AUTH_TOKEN=your-secret-token
export PROXY_MAX_BODY_SIZE=5242880
export PROXY_LOG_DIR=logs/proxy
```

## Log File Structure

Logs are organized in a structured hierarchy:

```
logs/proxy/
├── proxy_general.log           # General proxy activity
├── requests/
│   ├── 20260213/
│   │   ├── 143052_123456_GET.json
│   │   ├── 143053_234567_POST.json
│   │   └── ...
├── responses/
│   ├── 20260213/
│   │   ├── 143052_345678_200.json
│   │   ├── 143053_456789_404.json
│   │   └── ...
├── websockets/
│   ├── ws_12345_1234567890/
│   │   ├── 143100_123456_SEND_TEXT.json
│   │   ├── 143100_234567_RECEIVE_TEXT.json
│   │   └── ...
├── errors/
│   ├── 20260213/
│   │   ├── 143055_567890_TIMEOUT.json
│   │   └── ...
└── auth/
    ├── 20260213/
    │   ├── 143000_678901_SUCCESS.json
    │   ├── 143001_789012_FAILED.json
    │   └── ...
```

Each JSON log file contains complete metadata:
```json
{
  "timestamp": "2026-02-13T14:30:52.123456",
  "type": "request",
  "id": 123,
  "url": "https://api.example.com/users",
  "method": "GET",
  "protocol": "HTTPS",
  "source_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "headers": {...},
  "body": "..."
}
```

## Error Handling

The proxy handles all error conditions gracefully:

### Error Types Tracked
- **CONNECTION_RESET**: Connection reset by peer
- **TIMEOUT**: Connection or transfer timeout
- **AUTH_FAILURE**: Authentication failure
- **PROTOCOL_ERROR**: HTTP/WebSocket protocol error
- **SSL_ERROR**: SSL/TLS certificate or handshake error
- **DNS_ERROR**: DNS resolution failure
- **OTHER**: Other unclassified errors

### Error Recovery
- Errors are logged to database and file system
- Proxy continues operating after errors
- Failed logging attempts don't crash proxy
- Automatic retry for transient failures

## WebSocket Support

The proxy provides comprehensive WebSocket support:

### Features
- Capture bidirectional WebSocket traffic
- Track individual connections
- Log text and binary messages
- Record message timestamps and sizes
- Associate messages with source IPs

### WebSocket Message Types
- **TEXT**: Text messages (UTF-8)
- **BINARY**: Binary data (logged as hex)
- **PING/PONG**: Keep-alive frames
- **CLOSE**: Connection close frames

### Viewing WebSocket Logs

Via API:
```bash
# List all messages for a connection
curl "http://localhost:8000/proxy/api/websocket-messages/list/?connection_id=ws_12345"
```

Via Django Admin:
```
http://localhost:8000/admin/proxy/websocketmessage/
```

Via File Logs:
```bash
# View logs for specific connection
cat logs/proxy/websockets/ws_12345_1234567890/*.json
```

## Security Considerations

### Authentication
- Always use strong tokens in production
- Rotate tokens regularly
- Use HTTPS for API endpoints
- Consider IP whitelisting for additional security

### Sensitive Data
- Proxy logs may contain sensitive information
- Implement log retention policies
- Restrict access to log directories
- Consider encrypting logs at rest
- Use `max_body_size` to limit what's logged

### Network Security
- Run proxy on trusted networks only
- Use firewall rules to restrict access
- Monitor authentication failures
- Implement rate limiting if needed

## Troubleshooting

### Proxy Not Starting
```bash
# Check if Django is running
curl http://localhost:8000/proxy/api/stats/

# Check mitmproxy configuration
mitmdump -s proxy_addon_enhanced.py --set api_url=http://localhost:8000 -v
```

### Requests Not Being Logged
1. Check Django logs for API errors
2. Verify database migrations are applied
3. Check log directory permissions
4. Verify API URL is correct in proxy config

### Authentication Issues
1. Verify token is set correctly: `--set auth_token=YOUR_TOKEN`
2. Check authentication logs in Django admin
3. Ensure client is sending `Proxy-Authorization` header

### WebSocket Messages Not Captured
1. Verify `--set websocket_enabled=true`
2. Check WebSocket connection was properly established
3. Review proxy_general.log for WebSocket events

### Performance Issues
1. Increase `max_body_size` if large bodies are being truncated
2. Adjust `connection_timeout` for slow connections
3. Implement log cleanup to prevent disk space issues
4. Consider using PostgreSQL for better performance

## Advanced Topics

### Integration with Other Tools

#### Using with Burp Suite
1. Configure Burp to upstream to Megido proxy
2. Burp Suite → Proxy → Options → Upstream Proxy Servers
3. Add: `127.0.0.1:8080` (mitmproxy default)

#### Using with Browser DevTools
1. Configure browser to use proxy
2. Install mitmproxy certificate
3. Use alongside browser DevTools for analysis

#### Using with Automated Scanners
```bash
# Start proxy with scanner identifier
mitmdump -s proxy_addon_enhanced.py \
  --set api_url=http://localhost:8000 \
  --set source_app=scanner

# Configure scanner to use proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

### Custom Payload Rules

The proxy supports dynamic payload injection via the interceptor app (separate feature).
Configure payload rules in Django admin to automatically modify requests.

### Extending the Proxy

To add custom functionality:

1. **Custom Models**: Add models to `proxy/models.py`
2. **Custom Views**: Add API endpoints to `proxy/views.py`
3. **Custom Addon Logic**: Extend `proxy_addon_enhanced.py`
4. **Custom CLI Commands**: Add commands to `proxy_replay_cli.py`

Example custom handler:
```python
# In proxy_addon_enhanced.py
def custom_request_handler(self, flow: http.HTTPFlow):
    # Your custom logic here
    if 'special-header' in flow.request.headers:
        # Do something special
        pass
```

## API Reference

### Models

#### ProxyRequest
- `url`: Request URL
- `method`: HTTP method
- `protocol`: HTTP, HTTPS, WS, WSS
- `headers`: JSON-encoded headers
- `body`: Request body
- `source_ip`: Client IP address
- `timestamp`: Request timestamp
- `request_size`: Body size in bytes
- `user_agent`: User agent string
- `is_replay`: Whether this is a replay
- `original_request`: Link to original (if replay)

#### ProxyResponse
- `request`: Related ProxyRequest
- `status_code`: HTTP status code
- `headers`: JSON-encoded headers
- `body`: Response body
- `response_time`: Response time in ms
- `response_size`: Body size in bytes
- `cached`: Whether response was cached
- `error_message`: Error message if failed

#### WebSocketMessage
- `connection_id`: Unique connection identifier
- `url`: WebSocket URL
- `direction`: SEND or RECEIVE
- `message_type`: TEXT, BINARY, PING, PONG, CLOSE
- `payload`: Message content
- `payload_size`: Size in bytes
- `source_ip`: Client IP
- `timestamp`: Message timestamp

#### ProxyError
- `error_type`: Error category
- `error_message`: Error description
- `stack_trace`: Full stack trace
- `url`: Related URL
- `source_ip`: Client IP
- `request`: Related request (if any)
- `timestamp`: Error timestamp

#### ProxyConfiguration
- `auth_enabled`: Enable authentication
- `auth_username`, `auth_password`, `auth_token`: Auth credentials
- `ip_whitelist`, `ip_blacklist`: IP filtering
- `logging_enabled`: Master logging switch
- `log_request_body`, `log_response_body`: Body logging
- `log_directory`: Log file directory
- `connection_timeout`, `transfer_timeout`: Timeout settings
- `max_concurrent_clients`: Connection limit
- `cache_enabled`: Enable caching
- `websocket_enabled`: Enable WebSocket logging

### API Endpoints

#### GET /proxy/api/requests/
List requests with filtering and pagination.

**Query Parameters:**
- `method`: Filter by HTTP method
- `protocol`: Filter by protocol (HTTP, HTTPS, etc.)
- `source_ip`: Filter by source IP
- `is_replay`: Filter replays (true/false)
- `search`: Search in URL, host, user agent
- `limit`: Results per page (default: 100)
- `offset`: Pagination offset

**Response:**
```json
{
  "requests": [...],
  "total": 1234,
  "limit": 100,
  "offset": 0
}
```

#### POST /proxy/api/requests/
Create new request (used by proxy addon).

#### GET /proxy/api/requests/{id}/
Get request details including response.

#### POST /proxy/api/requests/{id}/replay/
Replay a request.

**Request Body:**
```json
{
  "target_url": "http://localhost:3000/test"  // Optional
}
```

#### POST /proxy/api/responses/
Create new response (used by proxy addon).

#### GET /proxy/api/websocket-messages/list/
List WebSocket messages.

**Query Parameters:**
- `connection_id`: Filter by connection
- `direction`: SEND or RECEIVE
- `message_type`: TEXT, BINARY, etc.
- `limit`: Results limit

#### POST /proxy/api/websocket-messages/
Create WebSocket message (used by proxy addon).

#### GET /proxy/api/errors/list/
List errors.

**Query Parameters:**
- `error_type`: Filter by error type
- `source_ip`: Filter by IP
- `limit`: Results limit

#### POST /proxy/api/errors/
Create error log (used by proxy addon).

#### POST /proxy/api/auth-attempt/
Log authentication attempt (used by proxy addon).

#### GET /proxy/api/stats/
Get proxy statistics.

**Response:**
```json
{
  "total_requests": 1234,
  "total_websocket_messages": 56,
  "total_errors": 12,
  "requests_by_method": [...],
  "requests_by_protocol": [...],
  "avg_response_time": 123.45,
  "recent_auth_failures": 3
}
```

## License

This component is part of the Megido Security Platform. See main repository LICENSE for details.

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/tkstanch/Megido/issues
- Documentation: See main README.md

## Changelog

### Version 2.0.0 (2026-02-13)
- ✨ Added comprehensive WebSocket support
- ✨ Added authentication and IP filtering
- ✨ Added request replay functionality with CLI tool
- ✨ Added structured file-based logging
- ✨ Added enhanced error handling and recovery
- ✨ Added performance controls and configuration
- ✨ Added comprehensive Django admin interface
- ✨ Added detailed API documentation
- 🐛 Fixed error handling in proxy addon
- 🐛 Improved database performance with indexes
- 📝 Complete documentation rewrite

### Version 1.0.0 (Previous)
- Basic HTTP/HTTPS interception
- Database logging of requests/responses
- Basic dashboard UI
