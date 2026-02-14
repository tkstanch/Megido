# Favicon Setup Guide

## Overview

This guide explains how the favicon is configured and served in the Megido Security Platform, and how to troubleshoot common issues.

## Favicon Location

The favicon.ico file is located at:
```
/static/favicon.ico
```

After running `collectstatic`, it will be copied to:
```
/staticfiles/favicon.ico
```

## Static File Serving

Megido uses **WhiteNoise** for efficient static file serving in production. WhiteNoise is configured in `settings.py`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Must be after SecurityMiddleware
    # ... other middleware
]

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]
```

## Collecting Static Files

### Docker/Production

In Docker, static files are collected automatically on container start via `docker-entrypoint.sh`:

```bash
python manage.py collectstatic --noinput --clear
```

### Local Development

For local development, run:

```bash
python manage.py collectstatic --noinput
```

This copies all files from `/static/` to `/staticfiles/`, including:
- favicon.ico
- CSS files
- JavaScript files
- Images

## Accessing the Favicon

The favicon should be accessible at:
- `http://localhost:8000/static/favicon.ico`
- `http://localhost:8000/favicon.ico` (if configured)

Browsers automatically request `/favicon.ico` from the root path.

## Troubleshooting

### Issue: favicon.ico returns 404 Not Found

**Solutions:**

1. **Verify the file exists:**
   ```bash
   ls -la static/favicon.ico
   ls -la staticfiles/favicon.ico
   ```

2. **Run collectstatic:**
   ```bash
   python manage.py collectstatic --noinput --clear
   ```

3. **Check WhiteNoise is installed:**
   ```bash
   pip list | grep whitenoise
   ```

4. **Verify WhiteNoise middleware is configured** in `settings.py` (should be right after SecurityMiddleware)

5. **Clear browser cache** - browsers aggressively cache favicons

### Issue: favicon.ico returns NetworkError

This typically occurs when:
- Collectstatic hasn't been run
- WhiteNoise is not properly configured
- The file path is incorrect

**Resolution:**
1. Run collectstatic (see above)
2. Restart the Django server
3. Hard refresh browser (Ctrl+Shift+R or Cmd+Shift+R)

### Issue: Different favicon showing

Browsers cache favicons very aggressively. To force reload:
- Chrome/Firefox: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)
- Or clear browser cache entirely
- Or open in incognito/private window

## NGINX Configuration (Optional)

If using NGINX as a reverse proxy, you can optionally configure it to serve the favicon directly. However, this is **not required** as WhiteNoise already serves it efficiently.

See `nginx.conf.example` in the repository root for a complete NGINX configuration example.

**Basic favicon configuration:**

```nginx
server {
    # Optional: Serve favicon directly from NGINX (faster but not necessary)
    location = /favicon.ico {
        alias /path/to/megido/staticfiles/favicon.ico;
        access_log off;
        log_not_found off;
        expires 30d;
    }
    
    # Optional: Serve all static files from NGINX
    location /static/ {
        alias /path/to/megido/staticfiles/;
        expires 30d;
    }
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Important:** NGINX configuration is completely optional. WhiteNoise serves static files efficiently without NGINX.

## Docker Deployment

### Development (docker-compose)

The docker-compose.yml includes a volume mount for static files:

```yaml
web:
  volumes:
    - static-files:/app/staticfiles
```

Static files are collected automatically on container start via `docker-entrypoint.sh`.

### Production (Gunicorn)

When using Gunicorn (default in Dockerfile), WhiteNoise serves static files automatically:

```bash
gunicorn --config gunicorn.conf.py megido_security.wsgi:application
```

No additional configuration needed - WhiteNoise handles everything!

## Verification

### Check if collectstatic worked:

```bash
# List staticfiles directory
ls -la staticfiles/

# Check favicon specifically
ls -la staticfiles/favicon.ico
```

### Test with curl:

```bash
# Should return 200 OK
curl -I http://localhost:8000/static/favicon.ico

# Or test from root
curl -I http://localhost:8000/favicon.ico
```

### Test in browser:

Open browser developer tools (F12), go to Network tab, and look for:
- `favicon.ico` request
- Status should be `200 OK`
- Type should be `image/x-icon` or `image/vnd.microsoft.icon`

## Best Practices

1. **Always run collectstatic before production deployment**
2. **Use WhiteNoise for static file serving** (already configured)
3. **Set far-future expires headers** for better caching (WhiteNoise does this automatically)
4. **Use a CDN for production** (optional, for high-traffic sites)
5. **Don't commit staticfiles/** directory to git (already in .gitignore)

## Related Files

- `/static/favicon.ico` - Source file
- `/staticfiles/favicon.ico` - Collected file (served by WhiteNoise)
- `/megido_security/settings.py` - Static files configuration
- `/docker-entrypoint.sh` - Runs collectstatic on container start
- `/Dockerfile` - Docker build configuration

## Additional Resources

- [Django Static Files Documentation](https://docs.djangoproject.com/en/stable/howto/static-files/)
- [WhiteNoise Documentation](http://whitenoise.evans.io/)
- [Django Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
