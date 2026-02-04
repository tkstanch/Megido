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
- Use production WSGI server (gunicorn/uwsgi)
- Set DEBUG=False
- Configure ALLOWED_HOSTS properly
- Use volume mounts for persistent data
- Implement proper backup strategies

## Security Warnings

- Never analyze real malware outside secure sandboxes
- Always use in isolated environments
- Keep ClamAV definitions updated
- Monitor and log all activities
- Follow your organization's security policies
