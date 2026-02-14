# Deployment Checklist

This checklist ensures all components are properly configured for production deployment of Megido Security Platform.

## Pre-Deployment

### Static Files
- [ ] Favicon exists at `/static/favicon.ico`
- [ ] Run `python manage.py collectstatic --noinput --clear`
- [ ] Verify files copied to `/staticfiles/` directory
- [ ] Test favicon accessible: `curl -I http://localhost:8000/static/favicon.ico` (should return 200)

### Celery & Redis
- [ ] Redis service is running (`redis-cli ping` returns `PONG`)
- [ ] Celery worker is running (`celery -A megido_security worker --loglevel=info`)
- [ ] Environment variables set:
  - [ ] `CELERY_BROKER_URL=redis://redis:6379/0`
  - [ ] `CELERY_RESULT_BACKEND=redis://redis:6379/0`
- [ ] Test async scan creates task (check Celery logs)

### Database
- [ ] Database migrations applied (`python manage.py migrate`)
- [ ] Superuser created (`python manage.py createsuperuser`)
- [ ] Database backed up (production)

### Django Configuration
- [ ] `SECRET_KEY` set to strong random value (production)
- [ ] `DEBUG = False` (production)
- [ ] `ALLOWED_HOSTS` configured with actual domains
- [ ] WhiteNoise middleware enabled in `MIDDLEWARE` (line 71 in settings.py)
- [ ] `STATIC_ROOT` points to `/staticfiles/`
- [ ] Security middleware enabled

## Docker Deployment

### Docker Compose Services
- [ ] `redis` service configured and healthy
- [ ] `celery` service configured with correct command
- [ ] `web` service has environment variables for Celery
- [ ] `clamav` service running (optional, for malware scanning)
- [ ] All services on same network

### Volume Mounts
- [ ] `static-files` volume mounted to `/app/staticfiles`
- [ ] `media-files` volume mounted to `/app/media`
- [ ] Application code mounted (development) or copied (production)

### Docker Entrypoint
- [ ] `docker-entrypoint.sh` runs migrations
- [ ] `docker-entrypoint.sh` runs collectstatic
- [ ] `docker-entrypoint.sh` creates superuser (if needed)
- [ ] Script has execute permissions (`chmod +x docker-entrypoint.sh`)

### Start Services
```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Test individual services
docker exec megido-redis redis-cli ping
docker exec megido-celery celery -A megido_security inspect active
```

## Manual Deployment (Without Docker)

### Prerequisites
- [ ] Python 3.12+ installed
- [ ] Redis installed and running
- [ ] PostgreSQL installed and running (or SQLite for development)

### Installation
```bash
# Clone repository
git clone https://github.com/tkstanch/Megido.git
cd Megido

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export USE_SQLITE=true  # For development, or configure PostgreSQL
export CELERY_BROKER_URL=redis://localhost:6379/0
export CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Create superuser
python manage.py createsuperuser
```

### Start Services
```bash
# Terminal 1: Start Redis (if not running as service)
redis-server

# Terminal 2: Start Celery worker
celery -A megido_security worker --loglevel=info --concurrency=4

# Terminal 3: Start Django (development)
python manage.py runserver

# OR for production with Gunicorn
gunicorn --config gunicorn.conf.py megido_security.wsgi:application
```

## Post-Deployment Testing

### Basic Functionality
- [ ] Access web interface: `http://localhost:8000/`
- [ ] Login with superuser credentials
- [ ] Navigate to Scanner dashboard: `http://localhost:8000/scanner/`

### Static Files
- [ ] Check browser Network tab for static file requests
- [ ] Verify `/static/favicon.ico` returns 200 OK
- [ ] Verify `/static/css/` files load correctly
- [ ] Verify `/static/js/` files load correctly
- [ ] Check browser console for errors (F12)

### Async Scan Flow
- [ ] Create a scan target
- [ ] Start a scan
- [ ] Verify scan returns immediately with "pending" status
- [ ] Check Celery logs for task execution: `docker logs -f megido-celery`
- [ ] Verify dashboard polling starts (check Network tab)
- [ ] Watch status change: pending → running → completed
- [ ] Verify vulnerabilities appear when scan completes

### Error Scenarios
- [ ] Test with invalid target URL (should fail gracefully)
- [ ] Stop Celery worker, start scan (should stay pending, restart worker to process)
- [ ] Check 404 error for non-existent page (should not show as scan error)
- [ ] Test network disconnect during scan (should show error after 5 failures)

## Production Hardening

### Security
- [ ] Change default admin password
- [ ] Use strong `SECRET_KEY` (generate with `python -c "import secrets; print(secrets.token_urlsafe(50))"`)
- [ ] Enable HTTPS (configure SSL certificate)
- [ ] Set secure cookie flags: `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`
- [ ] Configure firewall to restrict access to Redis (port 6379)
- [ ] Review `ALLOWED_HOSTS` setting
- [ ] Enable security middleware settings (HSTS, etc.)

### Performance
- [ ] Increase Celery workers based on CPU cores
- [ ] Configure Gunicorn workers: `workers = (2 × CPU cores) + 1`
- [ ] Enable WhiteNoise compression: uncomment `STATICFILES_STORAGE` in settings.py
- [ ] Set up Redis persistence (if needed for task results)
- [ ] Configure database connection pooling
- [ ] Enable query optimization and indexing

### Monitoring
- [ ] Set up application logging
- [ ] Configure Celery monitoring (optional: Flower)
- [ ] Monitor Redis memory usage
- [ ] Monitor Gunicorn worker health
- [ ] Set up error tracking (e.g., Sentry)
- [ ] Configure uptime monitoring

### Backup
- [ ] Database backups scheduled
- [ ] Media files backed up
- [ ] Configuration files version controlled
- [ ] Disaster recovery plan documented

## Optional: NGINX Configuration

If using NGINX as reverse proxy:
- [ ] Copy `nginx.conf.example` to `/etc/nginx/sites-available/megido`
- [ ] Update paths in config (replace `/path/to/megido/`)
- [ ] Update domain name (replace `your-domain.com`)
- [ ] Enable site: `ln -s /etc/nginx/sites-available/megido /etc/nginx/sites-enabled/`
- [ ] Test config: `nginx -t`
- [ ] Reload NGINX: `systemctl reload nginx`
- [ ] Configure SSL certificate (Let's Encrypt recommended)

## Troubleshooting

If issues occur, check:
1. **Static files not loading**: Run collectstatic, check STATIC_ROOT
2. **Scans stuck in pending**: Check Celery worker running, check Redis connection
3. **404 on favicon**: Run collectstatic, verify WhiteNoise middleware
4. **Celery connection refused**: Check Redis running, check CELERY_BROKER_URL
5. **Gunicorn timeout**: Verify async scan implementation, check Celery logs

## Documentation

Refer to these guides for detailed information:
- **[ASYNC_SCAN_ARCHITECTURE.md](ASYNC_SCAN_ARCHITECTURE.md)** - Async scan implementation
- **[FAVICON_SETUP.md](FAVICON_SETUP.md)** - Static file serving
- **[docs/SCANNER_POLLING.md](docs/SCANNER_POLLING.md)** - Dashboard polling
- **[README.md](README.md)** - General setup and features

## Support

For issues or questions:
1. Check browser console for JavaScript errors (F12)
2. Check Celery logs: `docker logs megido-celery`
3. Check Django logs: `docker logs megido-web`
4. Check Redis connection: `docker exec megido-redis redis-cli ping`
5. Review GitHub Issues for known problems
6. Open a new issue with detailed logs and error messages

## Success Criteria

Deployment is successful when:
- ✅ Web interface loads without errors
- ✅ Favicon displays correctly in browser tab
- ✅ Scans start immediately (async) without blocking
- ✅ Dashboard polling shows real-time scan progress
- ✅ Scan results appear when completed
- ✅ No "NetworkError" messages from missing favicon
- ✅ Celery worker processes tasks in background
- ✅ Static files served correctly by WhiteNoise
- ✅ All services healthy in `docker-compose ps`
