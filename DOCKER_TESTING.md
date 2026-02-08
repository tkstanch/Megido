# Docker Setup Testing Guide

This guide explains how to test the ClamAV integration with Docker.

## Prerequisites

- Docker and Docker Compose installed
- At least 2GB free RAM
- Internet connection (for ClamAV virus definitions)

## Quick Test

### 1. Build and Start Services

```bash
docker compose up --build
```

**First startup takes 3-5 minutes** as ClamAV downloads virus definitions (~150MB).

### 2. Monitor ClamAV Initialization

In another terminal:
```bash
docker compose logs -f clamav
```

Wait for: `clamd[X]: Self checking every 3600 seconds.`

### 3. Check Service Health

```bash
docker ps
```

You should see:
- `megido-clamav` - status should show "healthy"
- `megido-web` - should be running

### 4. Access the Application

1. Open browser to: http://localhost:8000
2. Login with default credentials: `admin` / `admin`
3. Navigate to: http://localhost:8000/malware-analyser/

### 5. Test EICAR Detection

The EICAR test file is a standard, safe test file recognized by all antivirus engines.

**Method 1: Via Web Interface**
1. Go to Upload page
2. Create a text file with this content:
   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```
3. Upload and scan
4. ClamAV should detect it as "Eicar-Signature"

**Method 2: Via Command Line Test**
```bash
# Create EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Copy to container and scan
docker compose exec clamav clamdscan /tmp/eicar.txt
```

Expected output: `FOUND` with virus name containing "Eicar"

## Troubleshooting

### ClamAV Not Starting

**Symptom:** Container exits or restarts repeatedly
**Solution:** Check logs:
```bash
docker compose logs clamav
```

Common issues:
- Insufficient memory (need 1GB+)
- Virus definition download failure (check internet)

### Connection Refused

**Symptom:** "ClamAV daemon is not available"
**Solution:** 
1. Ensure ClamAV is healthy: `docker ps`
2. Wait for initialization to complete
3. Check network: `docker compose exec web ping clamav`

### Detection Not Working

**Symptom:** EICAR file not detected
**Solution:**
1. Verify ClamAV is running: `docker compose exec clamav clamdscan --version`
2. Check virus definitions updated: `docker compose logs clamav | grep "Database updated"`
3. Test ClamAV directly: `docker compose exec clamav clamdscan /tmp/eicar.txt`

## Stop Services

```bash
docker compose down
```

To remove all data:
```bash
docker compose down -v
```

## Production Notes

⚠️ **IMPORTANT:** This is for educational/demonstration use only.

For production:
- Use environment variables for sensitive config
- Set up proper authentication
- Configure network security
- **Use production WSGI server with extended timeouts** (see below)
- Set DEBUG=False
- Configure ALLOWED_HOSTS properly
- Use volume mounts for persistent data
- Implement proper backup strategies

### Production WSGI Server Configuration

Megido's exploit plugins (particularly XSS smart crawling and DOM exploitation) can run for **several minutes** during deep scans. The Docker configuration includes Gunicorn with a **300-second timeout** to handle these long-running operations.

#### Using Gunicorn (Included in Docker)

The provided `gunicorn.conf.py` configuration includes:
- **300-second timeout** for long-running exploits
- Optimized worker count based on CPU cores
- Comprehensive logging for debugging timeout issues
- Hooks that log warnings when workers exceed timeout

**Default Docker Command:**
```bash
# Already configured in Dockerfile
gunicorn --config gunicorn.conf.py megido_security.wsgi:application
```

**Manual Gunicorn (without config file):**
```bash
# Install gunicorn if not already installed
pip install gunicorn

# Run with explicit timeout
gunicorn --timeout 300 --workers 4 --bind 0.0.0.0:8000 megido_security.wsgi:application
```

#### Using uWSGI (Alternative)

If using uWSGI instead of Gunicorn:

```bash
# Install uwsgi
pip install uwsgi

# Run with extended timeouts
uwsgi --http :8000 \
      --wsgi-file megido_security/wsgi.py \
      --harakiri 300 \
      --http-timeout 300 \
      --socket-timeout 300 \
      --workers 4 \
      --master
```

#### Monitoring for Timeout Issues

Watch for these signs of timeout problems:
- Worker processes exiting with `SystemExit: 1`
- Log entries showing "worker timeout" or "SIGKILL"
- Incomplete scan results or interrupted exploit operations
- HTTP 502/504 errors during active scans

**Check Gunicorn logs:**
```bash
# Docker logs
docker compose logs web

# Look for timeout warnings
docker compose logs web | grep -i timeout
```

### Recommended Production Architecture

For high-volume or multi-tenant SaaS deployments, the synchronous WSGI model is not ideal. Consider:

#### 1. Async Task Queue Architecture
```
Web Tier (Gunicorn)
    ↓ (enqueue scan job)
Task Queue (Celery/RQ)
    ↓ (process in background)
Worker Tier (dedicated processes)
    ↓ (return results)
Result Storage (Redis/DB)
```

**Benefits:**
- Web workers remain responsive for UI/API requests
- Scan jobs run in dedicated background processes
- Easy horizontal scaling of worker tier
- Job prioritization and retry logic
- Progress tracking and real-time status updates

#### 2. Recommended Stack

**Option A: Celery (Full-featured)**
```bash
# Install
pip install celery redis

# Start workers
celery -A megido_security worker --loglevel=info --concurrency=4

# Monitor
celery -A megido_security flower  # Web-based monitoring
```

**Option B: RQ (Simpler, Redis-only)**
```bash
# Install
pip install rq redis

# Start workers
rq worker --url redis://localhost:6379

# Monitor
rq info --url redis://localhost:6379
```

#### 3. Implementation Steps

To migrate heavy exploit tasks to background processing:

1. **Install task queue** (Celery or RQ)
2. **Create tasks.py** in scanner app with exploit task definitions
3. **Update views/API** to enqueue jobs instead of running synchronously
4. **Add job status endpoints** to check scan progress
5. **Configure result backend** (Redis/PostgreSQL) for job results
6. **Update UI** to poll for job status and display results when complete

This architectural change eliminates timeout concerns and significantly improves scalability.


## Security Warnings

- Never analyze real malware outside secure sandboxes
- Always use in isolated environments
- Keep ClamAV definitions updated
- Monitor and log all activities
- Follow your organization's security policies
