# Megido Proxy - Quick Start Configuration Guide

This guide will help you get the Megido Proxy up and running in 5 minutes.

## Prerequisites

- Python 3.12+
- Django 6.0+
- mitmproxy 10.0+
- All requirements from `requirements.txt` installed

## Step 1: Database Setup

Apply the proxy migrations:

```bash
# Run migrations
python manage.py migrate proxy

# Create a superuser for Django admin (optional but recommended)
python manage.py createsuperuser
```

## Step 2: Start Django Server

```bash
# Start Django development server
python manage.py runserver

# Or with specific host/port
python manage.py runserver 0.0.0.0:8000
```

Keep this terminal open. Django server must be running for the proxy to log data.

## Step 3: Start the Proxy

Open a new terminal and start mitmproxy with the enhanced addon:

### Basic Configuration (No Authentication)

```bash
mitmdump -s proxy_addon_enhanced.py \
  --set api_url=http://localhost:8000 \
  --listen-host 0.0.0.0 \
  --listen-port 8080
```

### With Authentication

```bash
mitmdump -s proxy_addon_enhanced.py \
  --set api_url=http://localhost:8000 \
  --set auth_required=true \
  --set auth_token=your-secret-token-here \
  --listen-host 0.0.0.0 \
  --listen-port 8080
```

### With Custom Settings

```bash
mitmdump -s proxy_addon_enhanced.py \
  --set api_url=http://localhost:8000 \
  --set source_app=my_scanner \
  --set max_body_size=5242880 \
  --set connection_timeout=60 \
  --set websocket_enabled=true
```

## Step 4: Configure Your Application

Configure your browser or application to use the proxy:

### Environment Variables (Recommended)

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

### Browser Configuration

1. **Firefox**:
   - Preferences → Network Settings → Manual proxy configuration
   - HTTP Proxy: `localhost`, Port: `8080`
   - Check "Use this proxy for HTTPS"

2. **Chrome/Edge**:
   - Settings → System → Open proxy settings
   - Set HTTP and HTTPS proxy to `localhost:8080`

3. **curl**:
   ```bash
   curl --proxy http://localhost:8080 https://example.com
   ```

## Step 5: Install SSL Certificate (For HTTPS)

To intercept HTTPS traffic, install mitmproxy's CA certificate:

1. **Find the certificate**:
   ```bash
   # mitmproxy stores it at:
   ~/.mitmproxy/mitmproxy-ca-cert.pem
   ```

2. **Install on your system**:

   **Linux**:
   ```bash
   sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
   sudo update-ca-certificates
   ```

   **macOS**:
   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
   ```

   **Windows**:
   - Double-click the certificate file
   - Install Certificate → Local Machine → Trusted Root Certification Authorities

3. **For Python requests**:
   ```bash
   export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem
   
   # Or disable verification (testing only!)
   export CURL_CA_BUNDLE=""
   ```

## Step 6: Verify It's Working

### Check the Proxy is Running

```bash
# In a new terminal
curl --proxy http://localhost:8080 http://httpbin.org/get
```

You should see the response from httpbin.org, and the request should be logged.

### Check Django Dashboard

Visit: http://localhost:8000/admin/proxy/

You should see:
- ProxyRequest entries
- ProxyResponse entries (if requests completed)

### Check API

```bash
# Get statistics
curl http://localhost:8000/proxy/api/stats/

# List requests
curl http://localhost:8000/proxy/api/requests/

# Get specific request
curl http://localhost:8000/proxy/api/requests/1/
```

### Check File Logs

```bash
# View log directory
ls -R logs/proxy/

# View recent request log
ls -lt logs/proxy/requests/$(date +%Y%m%d)/ | head -5
```

## Step 7: Test Request Replay

```bash
# List captured requests
python proxy_replay_cli.py list

# Show details of first request
python proxy_replay_cli.py show 1

# Replay it
python proxy_replay_cli.py replay 1
```

## Configuration Options Reference

### Proxy Addon Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_url` | string | `http://localhost:8000` | Django API base URL |
| `source_app` | string | `browser` | Source identifier |
| `auth_required` | bool | `false` | Enable authentication |
| `auth_token` | string | `""` | Auth token |
| `max_body_size` | int | `1048576` | Max body size (bytes) |
| `websocket_enabled` | bool | `true` | Enable WebSocket logging |
| `connection_timeout` | int | `30` | Connection timeout (seconds) |
| `cache_ttl` | int | `60` | Rule cache TTL (seconds) |

### Django Admin Configuration

Visit: http://localhost:8000/admin/proxy/proxyconfiguration/

Configure:
1. **Authentication Settings**: Enable auth, set credentials/token
2. **IP Filtering**: Add whitelist/blacklist IPs (comma-separated)
3. **Logging Settings**: Control what gets logged
4. **Performance Settings**: Timeouts, connection limits
5. **Features**: Enable/disable WebSocket logging

## Common Issues

### Issue: "Connection refused" to Django API

**Solution**: Ensure Django server is running on the correct port:
```bash
python manage.py runserver 0.0.0.0:8000
```

### Issue: HTTPS sites show SSL errors

**Solution**: Install mitmproxy CA certificate (see Step 5)

### Issue: Proxy not logging requests

**Solutions**:
1. Check Django server is running and accessible
2. Verify `api_url` is correct in proxy command
3. Check Django logs for errors: `tail -f logs/django.log`
4. Verify database migrations are applied: `python manage.py showmigrations proxy`

### Issue: WebSocket messages not captured

**Solution**: Ensure `--set websocket_enabled=true` and check mitmproxy logs

### Issue: Authentication not working

**Solutions**:
1. Verify token matches in both proxy and client
2. Client must send `Proxy-Authorization: Bearer <token>` header
3. Check authentication logs: `curl http://localhost:8000/admin/proxy/authenticationattempt/`

## Advanced Usage

### Running as a Service (systemd)

Create `/etc/systemd/system/megido-proxy.service`:

```ini
[Unit]
Description=Megido Proxy
After=network.target

[Service]
Type=simple
User=megido
WorkingDirectory=/opt/megido
ExecStart=/usr/local/bin/mitmdump -s /opt/megido/proxy_addon_enhanced.py --set api_url=http://localhost:8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable megido-proxy
sudo systemctl start megido-proxy
sudo systemctl status megido-proxy
```

### Docker Deployment

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Run migrations
RUN python manage.py migrate

# Expose ports
EXPOSE 8000 8080

# Start both Django and proxy
CMD python manage.py runserver 0.0.0.0:8000 & \
    mitmdump -s proxy_addon_enhanced.py --set api_url=http://localhost:8000
```

### Load Balancing

For high-traffic scenarios, run multiple proxy instances:

```bash
# Instance 1
mitmdump -s proxy_addon_enhanced.py --listen-port 8081 --set api_url=http://localhost:8000

# Instance 2
mitmdump -s proxy_addon_enhanced.py --listen-port 8082 --set api_url=http://localhost:8000

# Use nginx to load balance
# nginx.conf:
upstream megido_proxy {
    server localhost:8081;
    server localhost:8082;
}
```

## Next Steps

1. **Explore the API**: See [PROXY_README.md](PROXY_README.md) for complete API documentation
2. **Set Up Automation**: Use `proxy_replay_cli.py` in scripts
3. **Customize Logging**: Adjust settings in Django admin
4. **Monitor Performance**: Use statistics endpoint for metrics
5. **Integrate with Tools**: Connect scanners, browsers, or custom tools

## Getting Help

- **Documentation**: [PROXY_README.md](PROXY_README.md)
- **Examples**: `python proxy_usage_example.py`
- **Django Admin**: http://localhost:8000/admin/proxy/
- **GitHub Issues**: https://github.com/tkstanch/Megido/issues

## Security Notes

⚠️ **Important**:
- Change default tokens in production
- Use HTTPS for Django API in production
- Restrict proxy access with IP filtering
- Review logs regularly for security incidents
- Don't expose proxy to public internet without authentication
- Rotate authentication tokens periodically
- Use strong passwords for Django admin

## License

Part of the Megido Security Platform. See main README for license information.
