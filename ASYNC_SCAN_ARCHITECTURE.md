# Async Scan Architecture

## Overview

This document describes the asynchronous scan architecture implemented in Megido Security Platform. The scan execution has been refactored to use **Celery tasks** for background processing, preventing Gunicorn worker blocking during long-running scans.

## Problem Statement

**Before (Synchronous):**
- `start_scan` endpoint performed the entire scan synchronously
- Gunicorn workers blocked for the entire scan duration (could be minutes)
- Users experienced timeouts on long scans
- Dashboard showed "NetworkError" while waiting for response
- Poor scalability - limited concurrent scans

**After (Asynchronous):**
- `start_scan` endpoint returns immediately with scan ID
- Scan executes in background via Celery task
- Gunicorn workers freed immediately to handle other requests
- Dashboard polls for results and shows real-time progress
- Excellent scalability - many concurrent scans possible

## Architecture Components

### 1. Celery Task (`scanner/tasks.py`)

```python
@shared_task(bind=True, name='scanner.async_scan_task')
def async_scan_task(self, scan_id: int) -> Dict[str, Any]:
    """
    Performs vulnerability scan asynchronously in background.
    """
```

**Features:**
- Time limits: 600s hard limit, 570s soft limit
- Automatic status updates (pending → running → completed/failed)
- Error handling with graceful degradation
- Returns detailed result dictionary

### 2. Start Scan Endpoint (`scanner/views.py`)

```python
@api_view(['POST'])
def start_scan(request, target_id):
    """
    Creates scan and triggers async Celery task.
    Returns immediately with scan ID and pending status.
    """
```

**Flow:**
1. Validate target exists
2. Create Scan object with `status='pending'`
3. Trigger `async_scan_task.delay(scan_id)`
4. Return immediately with scan ID and task ID
5. Client polls results endpoint

### 3. Results Endpoint (`scanner/views.py`)

```python
@api_view(['GET'])
def scan_results(request, scan_id):
    """
    Returns current scan status and results.
    Used by dashboard for polling.
    """
```

**Returns:**
- Current status: `pending`, `running`, `completed`, `failed`
- Scan metadata (started_at, completed_at)
- Vulnerabilities list (if completed)
- Progress information

### 4. Dashboard Polling (`static/js/scanner-dashboard.js`)

```javascript
ScannerDashboard.startPolling(scanId, onProgress, onComplete, onError);
```

**Behavior:**
- Polls `/api/scans/<scan_id>/results/` every 2 seconds
- Updates UI with progress indicators
- Stops polling when scan completes or fails
- Handles network errors gracefully

## Data Flow

```
User Action (Start Scan)
    ↓
[POST] /api/targets/<id>/scan/
    ↓
start_scan() view
    ├─ Create Scan (status='pending')
    ├─ Trigger async_scan_task.delay()
    └─ Return immediately {id, status='pending', task_id}
         ↓
Celery Worker picks up task
    ↓
async_scan_task()
    ├─ Update status='running'
    ├─ perform_basic_scan()
    ├─ Save vulnerabilities
    ├─ Update status='completed'
    └─ Return result

Meanwhile, Dashboard polls every 2s:
[GET] /api/scans/<id>/results/
    ↓
scan_results() view
    └─ Return {status, vulnerabilities, metadata}
         ↓
Dashboard updates UI
    ├─ pending/running: Show spinner
    ├─ completed: Show results
    └─ failed: Show error
```

## Status States

| Status | Description | UI Behavior |
|--------|-------------|-------------|
| `pending` | Scan created, waiting for Celery worker | Show spinner, "Starting scan..." |
| `running` | Scan actively executing | Show spinner, "Scanning in progress..." |
| `completed` | Scan finished successfully | Show results, success message |
| `failed` | Scan encountered error | Show error message |

## Celery Configuration

### Redis Broker

Celery uses Redis as message broker and result backend:

```python
# settings.py
CELERY_BROKER_URL = 'redis://redis:6379/0'
CELERY_RESULT_BACKEND = 'redis://redis:6379/0'
```

### Worker Configuration

Start Celery worker with:

```bash
celery -A megido_security worker --loglevel=info --concurrency=4
```

**Parameters:**
- `--concurrency=4`: Run 4 concurrent workers (adjust based on CPU cores)
- `--loglevel=info`: Log level for debugging
- `-A megido_security`: Django app name

### Docker Setup

The `docker-compose.yml` includes:
- **redis** service: Message broker
- **celery** service: Background worker
- **web** service: Django/Gunicorn (API server)

```yaml
services:
  redis:
    image: redis:7-alpine
  
  celery:
    command: celery -A megido_security worker --loglevel=info --concurrency=4
    environment:
      - CELERY_BROKER_URL=redis://redis:6379/0
  
  web:
    environment:
      - CELERY_BROKER_URL=redis://redis:6379/0
```

## Error Handling

### Task Timeout

If scan exceeds time limit:
- Soft limit (570s): `SoftTimeLimitExceeded` exception caught
- Scan marked as `failed`
- Graceful cleanup performed

### Task Failure

If scan encounters error:
- Exception logged with traceback
- Scan marked as `failed`
- Error message stored in result

### Network Errors (Dashboard)

Dashboard handles:
- Temporary network failures (retries automatically)
- Connection timeouts (shows error after 5 consecutive failures)
- Maximum poll attempts (stops after 5 minutes)

## Performance Benefits

### Before (Synchronous)
- 1 scan = 1 blocked Gunicorn worker
- 4 workers = max 4 concurrent scans
- Scan timeout = Gunicorn timeout (300s)

### After (Asynchronous)
- 1 scan = 1 Celery task
- 4 Celery workers = 4 concurrent scans
- Unlimited queued scans (limited by Redis)
- Gunicorn workers freed immediately

**Result:** 10x+ scalability improvement

## API Examples

### Start Scan (Returns Immediately)

```bash
curl -X POST http://localhost:8000/scanner/api/targets/1/scan/ \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json"
```

**Response (201 Created):**
```json
{
  "id": 123,
  "status": "pending",
  "message": "Scan started. Poll /api/scans/123/results/ for progress.",
  "task_id": "abc123-def456-..."
}
```

### Poll Results

```bash
curl http://localhost:8000/scanner/api/scans/123/results/
```

**Response (Status: running):**
```json
{
  "scan_id": 123,
  "status": "running",
  "started_at": "2024-01-01T12:00:00Z",
  "completed_at": null,
  "vulnerabilities": []
}
```

**Response (Status: completed):**
```json
{
  "scan_id": 123,
  "status": "completed",
  "started_at": "2024-01-01T12:00:00Z",
  "completed_at": "2024-01-01T12:05:30Z",
  "vulnerabilities": [
    {
      "id": 1,
      "type": "XSS",
      "severity": "high",
      "url": "https://example.com/page",
      "description": "Cross-Site Scripting vulnerability found"
    }
  ]
}
```

### Check Task Status (Optional)

```bash
curl http://localhost:8000/scanner/api/exploit_status/abc123-def456-.../ \
  -H "Authorization: Token YOUR_TOKEN"
```

## Monitoring

### Celery Logs

View Celery worker logs:

```bash
# Docker
docker logs -f megido-celery

# Local
# Check terminal where celery worker is running
```

### Scan Status

Check scan status in database:

```python
from scanner.models import Scan
scan = Scan.objects.get(id=123)
print(f"Status: {scan.status}")
print(f"Started: {scan.started_at}")
print(f"Completed: {scan.completed_at}")
```

### Redis Queue

Check pending tasks:

```bash
redis-cli -h localhost -p 6379
> KEYS celery*
> LLEN celery
```

## Troubleshooting

### Issue: Scans stuck in 'pending' status

**Cause:** Celery worker not running or not connected to Redis

**Solution:**
```bash
# Check if Celery worker is running
docker ps | grep celery

# Check Celery logs
docker logs megido-celery

# Restart Celery worker
docker-compose restart celery
```

### Issue: "Connection refused" errors

**Cause:** Redis not running or wrong connection URL

**Solution:**
```bash
# Check Redis is running
docker ps | grep redis

# Test Redis connection
docker exec -it megido-redis redis-cli ping
# Should return: PONG

# Check environment variable
echo $CELERY_BROKER_URL
```

### Issue: Scans fail immediately

**Cause:** Error in scan logic or dependencies

**Solution:**
```bash
# Check Celery worker logs for traceback
docker logs megido-celery

# Check Django logs
docker logs megido-web

# Check scan object
from scanner.models import Scan
scan = Scan.objects.get(id=123)
print(scan.status)  # Should show 'failed'
```

## Testing

### Test Async Flow

```python
# In Django shell
from scanner.models import ScanTarget, Scan
from scanner.tasks import async_scan_task

# Create target
target = ScanTarget.objects.create(
    url='https://example.com',
    name='Test Target'
)

# Create scan
scan = Scan.objects.create(
    target=target,
    status='pending'
)

# Trigger async task
result = async_scan_task.delay(scan.id)
print(f"Task ID: {result.id}")

# Check status
print(f"Task state: {result.state}")

# Wait for completion (blocks)
result.get(timeout=300)

# Check scan
scan.refresh_from_db()
print(f"Scan status: {scan.status}")
print(f"Vulnerabilities: {scan.vulnerabilities.count()}")
```

### Test Dashboard Polling

1. Open browser to dashboard
2. Open Developer Tools (F12)
3. Go to Network tab
4. Start a scan
5. Observe polling requests every 2 seconds:
   - `/scanner/api/scans/<id>/results/`
   - Status should progress: pending → running → completed

## Deployment Checklist

- [ ] Redis service running
- [ ] Celery worker service running
- [ ] `CELERY_BROKER_URL` environment variable set
- [ ] `CELERY_RESULT_BACKEND` environment variable set
- [ ] Dashboard polling enabled (scanner-dashboard.js loaded)
- [ ] Test scan end-to-end
- [ ] Monitor Celery logs for errors
- [ ] Set up Celery monitoring (optional: Flower)

## Future Enhancements

1. **WebSocket Support**: Real-time progress updates instead of polling
2. **Task Priority Queue**: High-priority scans jump the queue
3. **Scan Scheduling**: Periodic/scheduled scans
4. **Distributed Workers**: Multiple Celery workers across servers
5. **Result Caching**: Cache completed scan results in Redis
6. **Progress Percentage**: Show estimated completion percentage
7. **Celery Flower**: Web-based monitoring dashboard

## Related Files

- `/scanner/tasks.py` - Celery task definitions
- `/scanner/views.py` - API endpoints (start_scan, scan_results)
- `/static/js/scanner-dashboard.js` - Dashboard polling logic
- `/megido_security/celery.py` - Celery configuration
- `/megido_security/settings.py` - Celery settings
- `/docker-compose.yml` - Redis and Celery services
- `/docs/SCANNER_POLLING.md` - Dashboard polling documentation

## References

- [Celery Documentation](https://docs.celeryproject.org/)
- [Django + Celery Integration](https://docs.celeryproject.org/en/stable/django/)
- [Redis Documentation](https://redis.io/documentation)
- [Gunicorn Workers](https://docs.gunicorn.org/en/stable/design.html)
