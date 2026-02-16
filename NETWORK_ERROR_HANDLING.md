# Network Error Handling Guide

Comprehensive guide for understanding and configuring network error handling in Megido Scanner.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Error Classification](#error-classification)
4. [Retry Logic](#retry-logic)
5. [Configuration](#configuration)
6. [Health Monitoring](#health-monitoring)
7. [Degraded Mode](#degraded-mode)
8. [Logging](#logging)
9. [API Reference](#api-reference)
10. [Troubleshooting](#troubleshooting)

---

## Overview

Megido Scanner includes robust network error handling with:

- **Exponential backoff with jitter** - Prevents thundering herd, backs off gracefully
- **Intelligent error classification** - Distinguishes recoverable from fatal errors
- **Automatic retries** - Configurable retry behavior for transient failures
- **Health monitoring** - Real-time service availability tracking
- **Degraded mode** - Continues operation when services are unavailable
- **Secure logging** - Automatically redacts sensitive data (passwords, tokens, API keys)

---

## Architecture

### Components

```
scanner/
├── utils/
│   ├── network_retry.py       # NetworkRetryClient - HTTP client with retry logic
│   ├── error_classifier.py    # ErrorClassifier - Error categorization
│   ├── network_logger.py      # NetworkLogger - Secure logging with redaction
│   └── health_check.py        # NetworkHealthChecker - Service health monitoring
├── config/
│   ├── network_config.py      # NetworkConfig - Configuration dataclass
│   └── network_config.yaml    # YAML configuration template
└── health_views.py            # Django views for health monitoring API/UI
```

### Flow Diagram

```
Request → NetworkRetryClient → Error? → ErrorClassifier → Retryable?
                                          ↓                    ↓
                                    NetworkLogger         Exponential
                                                         Backoff + Jitter
                                                              ↓
                                                          Retry Request
```

---

## Error Classification

Errors are classified into three categories:

### 1. Recoverable Errors (Automatic Retry)

These errors are typically transient and should be retried:

| Error Type | Description | Retry Strategy |
|------------|-------------|----------------|
| **Timeout** | Request timed out | Exponential backoff |
| **Connection Reset** | Connection reset by peer | Exponential backoff |
| **Connection Refused** | Server not accepting connections | Exponential backoff |
| **DNS Failure** | Domain name resolution failed | Exponential backoff |
| **HTTP 500-504** | Server errors | Exponential backoff |
| **HTTP 429** | Rate limit exceeded | Exponential backoff |
| **Proxy Error** | Proxy connection failed | Exponential backoff |

### 2. Fatal Errors (No Retry)

These errors are permanent and should not be retried:

| Error Type | Description | Action |
|------------|-------------|--------|
| **SSL Error** | Certificate validation failed | Log and fail |
| **HTTP 400-403** | Client errors (bad request, forbidden) | Log and fail |
| **HTTP 404** | Resource not found | Log and fail |
| **Redirect Loop** | Too many redirects | Log and fail |

### 3. Degraded Errors (Continue with Limitations)

Service unavailable but scanner can continue with reduced functionality:

- External verification services down
- Callback servers unavailable
- API integrations failing

---

## Retry Logic

### Exponential Backoff Formula

```python
delay = min(base_delay * (2 ^ attempt) + jitter, max_delay)
```

### Default Configuration

```python
max_retries = 3          # Total attempts: 4 (1 initial + 3 retries)
base_delay = 1.0         # seconds
max_delay = 30.0         # seconds
jitter_max = 1.0         # seconds
```

### Example Retry Sequence

| Attempt | Calculation | Delay |
|---------|-------------|-------|
| 1 (initial) | - | 0s |
| 2 (retry 1) | 1.0 * 2^0 + jitter(0-1.0) | ~1-2s |
| 3 (retry 2) | 1.0 * 2^1 + jitter(0-1.0) | ~2-3s |
| 4 (retry 3) | 1.0 * 2^2 + jitter(0-1.0) | ~4-5s |

Total time before giving up: ~7-10 seconds

---

## Configuration

### Method 1: Environment Variables

Set environment variables before starting Megido:

```bash
export MEGIDO_MAX_RETRIES=5
export MEGIDO_BASE_DELAY=2.0
export MEGIDO_MAX_DELAY=60.0
export MEGIDO_DEFAULT_TIMEOUT=45
export MEGIDO_DEGRADED_MODE=true
```

### Method 2: Django Settings

Edit `megido_security/settings.py`:

```python
# Network configuration
NETWORK_MAX_RETRIES = 5
NETWORK_BASE_DELAY = 2.0
NETWORK_MAX_DELAY = 60.0
NETWORK_DEFAULT_TIMEOUT = 45
NETWORK_DEGRADED_MODE_ENABLED = True

# Service-specific timeouts
NETWORK_SERVICE_TIMEOUTS = {
    'fireblocks_api': 30,
    'callback_server': 60,
    'ngrok_api': 15,
}
```

### Method 3: YAML Configuration

Create/edit `scanner/config/network_config.yaml`:

```yaml
network:
  max_retries: 5
  base_delay: 2.0
  max_delay: 60.0

timeouts:
  default: 45
  connect: 15
  read: 45
  services:
    fireblocks_api: 30
    callback_server: 60

error_handling:
  degraded_mode_enabled: true
```

Load in code:

```python
from scanner.config.network_config import NetworkConfig

config = NetworkConfig.from_yaml('scanner/config/network_config.yaml')
```

### Configuration Precedence

1. Code-level configuration (highest priority)
2. Environment variables
3. Django settings
4. YAML configuration
5. Default values (lowest priority)

---

## Health Monitoring

### Health Check Dashboard

Access the real-time health monitoring dashboard:

```
http://localhost:8000/scanner/health/dashboard/
```

Features:
- ✅ Overall system health status
- 📊 Service-by-service breakdown
- ⏱️ Response time metrics
- 🔄 Auto-refresh every 60 seconds
- 🔴 Error details and remediation steps

### Health Check API

#### Get Overall Health

```bash
curl http://localhost:8000/scanner/health/
```

Response:

```json
{
  "overall_status": "healthy",
  "message": "All services are operational",
  "last_check": "2024-01-15T10:30:00",
  "stats": {
    "total_services": 2,
    "healthy": 2,
    "degraded": 0,
    "unhealthy": 0,
    "avg_response_time_ms": 125.5
  },
  "services": {
    "fireblocks_api": {
      "status": "healthy",
      "response_time_ms": 120.3,
      "last_check": "2024-01-15T10:30:00",
      "error_message": null,
      "consecutive_failures": 0
    }
  }
}
```

#### Check Specific Service

```bash
curl -X POST http://localhost:8000/scanner/api/health/check-service/ \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "my_api",
    "endpoint": "https://api.example.com/health",
    "method": "GET"
  }'
```

### Programmatic Usage

```python
from scanner.utils.health_check import get_health_checker

# Get global health checker instance
checker = get_health_checker()

# Check all services
results = checker.check_all_services()

# Check specific service
status = checker.check_service_health(
    service_name='fireblocks_api',
    endpoint='https://sb-console-api.fireblocks.io/health'
)

# Get overall health
health = checker.get_overall_health()
print(f"Status: {health['overall_status']}")

# Check if service is available
if checker.is_service_available('fireblocks_api'):
    print("Service is available")
```

---

## Degraded Mode

When enabled, the scanner continues operation even when external services fail.

### Behavior in Degraded Mode

1. **Verification Services Down**
   - Scanner performs detection without external verification
   - Findings marked as "unverified"
   - Higher false positive rate accepted

2. **Callback Servers Unavailable**
   - Out-of-band (OOB) verification disabled
   - Falls back to in-band detection methods
   - Warning logged for user awareness

3. **API Integrations Failing**
   - Skips optional API-dependent features
   - Core scanning continues
   - Missing data noted in reports

### Enable/Disable Degraded Mode

```python
# Via environment variable
MEGIDO_DEGRADED_MODE=true

# Via Django settings
NETWORK_DEGRADED_MODE_ENABLED = True

# Programmatically
from scanner.config.network_config import NetworkConfig

config = NetworkConfig(enable_degraded_mode=True)
```

### Detecting Degraded Mode

```python
from scanner.utils.health_check import get_health_checker

checker = get_health_checker()
if checker.should_use_degraded_mode():
    print("⚠️ Operating in degraded mode")
    print("Some features may be limited")
```

---

## Logging

### Secure Logging with Automatic Redaction

The `NetworkLogger` automatically redacts sensitive information:

**Redacted Data:**
- Passwords in URLs (`https://user:***@example.com`)
- API keys and tokens in headers
- Cookie values
- Authorization headers
- Query parameters (`token`, `password`, `api_key`, etc.)

**Example:**

```python
from scanner.utils.network_logger import NetworkLogger

logger = NetworkLogger()

# Logs with automatic redaction
logger.log_request(
    url='https://admin:secret@api.example.com?token=abc123',
    method='POST',
    headers={
        'Authorization': 'Bearer secret_token_12345678',
        'Content-Type': 'application/json'
    }
)
# Output: POST https://***:***@api.example.com?token=***
#         Authorization: Bear***5678
```

### Log Levels

Configure via environment variable:

```bash
MEGIDO_NETWORK_LOG_LEVEL=DEBUG  # DEBUG, INFO, WARNING, ERROR
```

Or Django settings:

```python
NETWORK_LOG_LEVEL = 'INFO'
```

### Log Output Examples

**Successful Request:**
```
INFO: Success: GET https://api.example.com/data -> 200
```

**Retry Attempt:**
```
WARNING: Retry 2/3: GET https://api.example.com/data (error: timeout, backoff: 2.5s)
```

**Final Failure:**
```
ERROR: Failed after 3 attempts: GET https://api.example.com/data - timeout
```

---

## API Reference

### NetworkRetryClient

```python
from scanner.utils.network_retry import NetworkRetryClient
from scanner.config.network_config import NetworkConfig

# Initialize with configuration
config = NetworkConfig(max_retries=5, base_delay=2.0)
client = NetworkRetryClient(config=config)

# Make requests with automatic retry
response = client.get('https://api.example.com/data')
response = client.post('https://api.example.com/data', json={'key': 'value'})

# Override retry behavior per request
response = client.get('https://api.example.com/data', max_retries=10, timeout=60)
```

### retry_with_backoff Decorator

```python
from scanner.utils.network_retry import retry_with_backoff
from requests.exceptions import ConnectionError, Timeout

@retry_with_backoff(
    max_retries=3,
    base_delay=1.0,
    max_delay=30.0,
    retryable_exceptions=(ConnectionError, Timeout)
)
def fetch_data(url):
    return requests.get(url)

# Function automatically retries on connection errors/timeouts
data = fetch_data('https://api.example.com/data')
```

### ErrorClassifier

```python
from scanner.utils.error_classifier import ErrorClassifier
from requests.exceptions import Timeout

error = Timeout('Read timeout')

# Classify error
result = ErrorClassifier.classify(error)
# Returns: {
#   'category': ErrorCategory.RECOVERABLE,
#   'type': 'timeout',
#   'retryable': True,
#   'user_message': 'Request timed out...',
#   'remediation': 'The request will be retried...'
# }

# Helper methods
is_retryable = ErrorClassifier.is_retryable(error)
message = ErrorClassifier.get_user_friendly_message(error)
remediation = ErrorClassifier.get_remediation(error)
```

---

## Troubleshooting

### Common Issues

#### 1. Requests Still Timing Out

**Symptoms:** Requests fail even after retries

**Solutions:**
- Increase timeout: `MEGIDO_DEFAULT_TIMEOUT=60`
- Increase max retries: `MEGIDO_MAX_RETRIES=5`
- Check target service health
- Verify network connectivity

#### 2. Too Many Retries (Slow Scans)

**Symptoms:** Scans take too long due to excessive retries

**Solutions:**
- Reduce max retries: `MEGIDO_MAX_RETRIES=1`
- Reduce timeouts: `MEGIDO_DEFAULT_TIMEOUT=15`
- Use fast scan configuration preset

#### 3. SSL Certificate Errors

**Symptoms:** `SSL error: Certificate verify failed`

**Solutions:**
- For testing only: Disable SSL verification in target configuration
- Add certificate to trusted store
- Use valid certificates in production

#### 4. Service Marked as Unhealthy

**Symptoms:** Health dashboard shows services as unhealthy

**Solutions:**
- Check service endpoint URL
- Verify network connectivity
- Check firewall rules
- Review service logs
- Use health dashboard to see detailed error messages

#### 5. Sensitive Data in Logs

**Symptoms:** Passwords/tokens visible in log files

**Solutions:**
- Ensure `NetworkLogger` is being used
- Check log level isn't DEBUG (use INFO or WARNING)
- Verify `redact_sensitive_data: true` in config
- File bug report if redaction is failing

### Debug Mode

Enable detailed network logging:

```bash
MEGIDO_DETAILED_LOGGING=true
MEGIDO_NETWORK_LOG_LEVEL=DEBUG
python manage.py runserver
```

### Testing Network Error Handling

Use a mock server to test error scenarios:

```python
# Test timeout handling
import time
from scanner.utils.network_retry import NetworkRetryClient

client = NetworkRetryClient()

# This will timeout and retry
try:
    response = client.get('http://httpstat.us/524?sleep=60000', timeout=5)
except Exception as e:
    print(f"Failed as expected: {e}")

# Test rate limiting
response = client.get('http://httpstat.us/429')  # Returns 429 status
```

### Health Check Troubleshooting

```bash
# Manual health check
curl http://localhost:8000/scanner/health/?refresh=true

# Check specific service
curl -X POST http://localhost:8000/scanner/api/health/check-service/ \
  -H "Content-Type: application/json" \
  -d '{"service_name": "test", "endpoint": "https://httpstat.us/200"}'
```

---

## Best Practices

1. **Always use NetworkRetryClient** for external HTTP requests
2. **Enable degraded mode** in production for resilience
3. **Monitor health dashboard** regularly
4. **Configure service-specific timeouts** for optimal performance
5. **Use appropriate retry counts** based on scan type:
   - Quick scans: `max_retries=1`
   - Normal scans: `max_retries=3`
   - Thorough scans: `max_retries=5`
6. **Review logs** for persistent network issues
7. **Test error handling** in staging environment

---

## Configuration Presets

### Production Configuration

```yaml
network:
  max_retries: 5
  base_delay: 2.0
  max_delay: 60.0
timeouts:
  default: 60
error_handling:
  degraded_mode_enabled: true
logging:
  level: WARNING
```

### Fast Scan Configuration

```yaml
network:
  max_retries: 1
  base_delay: 0.5
  max_delay: 5.0
timeouts:
  default: 10
error_handling:
  degraded_mode_enabled: true
logging:
  level: WARNING
```

### Development Configuration

```yaml
network:
  max_retries: 2
  base_delay: 1.0
  max_delay: 10.0
timeouts:
  default: 30
error_handling:
  degraded_mode_enabled: true
logging:
  level: DEBUG
  detailed: true
```

---

## Further Reading

- [Configuration Guide](CONFIGURATION.md) - Detailed configuration options
- [API Documentation](docs/API.md) - REST API reference
- [Django Settings](megido_security/settings.py) - Default settings

---

## Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review logs in `logs/` directory
3. Open an issue on GitHub
4. Contact the development team

---

Last Updated: 2024-02-16
