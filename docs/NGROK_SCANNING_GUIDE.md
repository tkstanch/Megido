# Scanning Targets Over ngrok

## Overview

This guide explains how to use the Megido vulnerability scanner to scan web applications exposed through ngrok tunnels. This is particularly useful for:

- Testing locally running applications
- Scanning development environments
- Testing applications behind firewalls
- Penetration testing scenarios requiring public access to local servers

## Prerequisites

1. **Megido Scanner** installed and running
2. **ngrok** installed (see [ngrok Installation](#ngrok-installation))
3. A local web application or server to scan

## Quick Start

### 1. Start Your Local Application

First, start your local web application on a specific port:

```bash
# Example: Start a local web server on port 3000
python manage.py runserver 3000
# or
npm run dev
# or  
php -S localhost:3000
```

### 2. Create ngrok Tunnel

Create an ngrok tunnel to expose your local application:

```bash
# Basic tunnel (HTTP)
ngrok http 3000

# With custom subdomain (requires paid plan)
ngrok http 3000 --subdomain=my-test-app

# With authentication
ngrok http 3000 --auth="username:password"
```

ngrok will display output like:

```
Session Status                online
Account                       Your Name (Plan: Free)
Version                       3.0.0
Region                        United States (us)
Latency                       45ms
Web Interface                 http://127.0.0.1:4040
Forwarding                    https://abc123.ngrok-free.app -> http://localhost:3000
```

**Copy the Forwarding URL** (e.g., `https://abc123.ngrok-free.app`)

### 3. Scan Using Megido

#### Method A: Using Web Dashboard

1. Navigate to the Megido Scanner dashboard: `http://localhost:8000/scanner/`
2. In the "Target URL" field, enter your ngrok URL: `https://abc123.ngrok-free.app`
3. Optionally provide a scan name (e.g., "My Local App Scan")
4. Click "Start Scan"

#### Method B: Using REST API

```bash
# Create a scan target
curl -X POST http://localhost:8000/scanner/api/targets/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Token YOUR_API_TOKEN" \
  -d '{
    "url": "https://abc123.ngrok-free.app",
    "name": "My ngrok Target"
  }'

# Start scan (use the target ID from response)
curl -X POST http://localhost:8000/scanner/api/targets/1/scan/ \
  -H "Authorization: Token YOUR_API_TOKEN"

# Check scan results
curl http://localhost:8000/scanner/api/scans/1/results/
```

#### Method C: Using Python API

```python
import requests

# Megido API endpoint
api_base = "http://localhost:8000/scanner/api"
headers = {"Authorization": "Token YOUR_API_TOKEN"}

# Create target with ngrok URL
target_data = {
    "url": "https://abc123.ngrok-free.app",
    "name": "My Local App via ngrok"
}
response = requests.post(f"{api_base}/targets/", json=target_data, headers=headers)
target = response.json()

# Start scan
scan_response = requests.post(f"{api_base}/targets/{target['id']}/scan/", headers=headers)
scan = scan_response.json()

print(f"Scan started with ID: {scan['id']}")
print(f"Status: {scan['status']}")

# Poll for results
import time
while True:
    results = requests.get(f"{api_base}/scans/{scan['id']}/results/").json()
    if results['status'] in ['completed', 'failed']:
        break
    print(f"Scan status: {results['status']}")
    time.sleep(5)

# Print vulnerabilities found
print(f"\nFound {len(results['vulnerabilities'])} vulnerabilities:")
for vuln in results['vulnerabilities']:
    print(f"  - [{vuln['severity'].upper()}] {vuln['type']}: {vuln['url']}")
```

## Configuration

### Django Settings Configuration

Megido is pre-configured to support ngrok tunnels. The following settings are enabled by default:

```python
# In megido_security/settings.py

# Allows all hosts including ngrok domains
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', '*']

# CSRF trusted origins - add your ngrok URL if needed
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    # Add your ngrok URL here for CSRF protection:
    # 'https://your-subdomain.ngrok-free.app'
]
```

### Environment Variable Configuration

For dynamic ngrok URL configuration, use environment variables:

```bash
# Set ngrok URL for CSRF protection
export NGROK_URL="https://your-subdomain.ngrok-free.app"

# Start Megido
python manage.py runserver

# Or with docker-compose
NGROK_URL="https://your-subdomain.ngrok-free.app" docker-compose up
```

The application will automatically add the ngrok URL to `CSRF_TRUSTED_ORIGINS`.

### For Production Use

If deploying Megido to production and scanning via ngrok, update settings:

```python
# Use specific allowed hosts
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost').split(',')

# Example .env file:
# ALLOWED_HOSTS=localhost,megido.yourdomain.com,*.ngrok-free.app
```

## ngrok Installation

### Linux

```bash
# Using apt (Ubuntu/Debian)
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | \
  sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && \
  echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | \
  sudo tee /etc/apt/sources.list.d/ngrok.list && \
  sudo apt update && sudo apt install ngrok

# Or manual installation
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar xvzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/
```

### macOS

```bash
# Using Homebrew
brew install ngrok/ngrok/ngrok

# Or manual installation
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-darwin-amd64.zip
unzip ngrok-v3-stable-darwin-amd64.zip
sudo mv ngrok /usr/local/bin/
```

### Windows

1. Download from https://ngrok.com/download
2. Extract `ngrok.exe`
3. Move to `C:\Windows\System32\` or add to PATH

### Configure Authentication

Sign up for a free ngrok account and configure your auth token:

```bash
# Sign up at https://dashboard.ngrok.com/signup
# Get your auth token from https://dashboard.ngrok.com/get-started/your-authtoken

# Configure ngrok
ngrok config add-authtoken YOUR_AUTH_TOKEN

# Test
ngrok http 8080
```

## Best Practices

### 1. Security Considerations

- **ngrok Free Plan Security**: Free ngrok URLs change on each tunnel restart. For consistent testing, use a paid plan with reserved domains.
- **Authentication**: Consider using ngrok's `--auth` flag to protect your tunnel with basic authentication.
- **SSL/TLS**: Always use HTTPS ngrok tunnels when testing sensitive applications.
- **Rate Limiting**: Be aware of ngrok's rate limits on free plans.

### 2. Scanning Tips

- **Start Small**: Begin with a single endpoint or page before scanning entire applications.
- **Test Connectivity**: Verify the ngrok URL is accessible in a browser before scanning.
- **Monitor ngrok Inspector**: Use the ngrok web interface (`http://localhost:4040`) to monitor requests during scanning.
- **Adjust Timeouts**: Increase scan timeouts if ngrok introduces latency.

### 3. Common Issues

#### Issue: "Host not allowed"

**Solution**: Ensure `ALLOWED_HOSTS` includes your ngrok domain or uses wildcard `'*'`.

#### Issue: "CSRF verification failed"

**Solution**: Add your ngrok URL to `CSRF_TRUSTED_ORIGINS` or set the `NGROK_URL` environment variable.

#### Issue: ngrok tunnel closes during scan

**Solution**: 
- Keep the ngrok terminal open during scans
- Use `ngrok http 3000 --log=stdout` to see tunnel status
- Consider upgrading to a paid ngrok plan for more stable tunnels

#### Issue: Slow scan performance

**Solution**:
- ngrok introduces network latency; this is expected
- Reduce scan concurrency/speed if needed
- Test with a faster ngrok region: `ngrok http 3000 --region us`

## Advanced Usage

### Scanning Multiple Endpoints

```python
# Scan multiple paths on the same ngrok domain
ngrok_base = "https://abc123.ngrok-free.app"

endpoints = [
    f"{ngrok_base}/",
    f"{ngrok_base}/admin",
    f"{ngrok_base}/api/users",
    f"{ngrok_base}/search?q=test"
]

for endpoint in endpoints:
    # Create target and scan
    target = create_target(endpoint)
    start_scan(target['id'])
```

### Using ngrok with Docker

If running Megido in Docker and want to scan your host's application:

```bash
# Start ngrok on host
ngrok http 3000

# In docker-compose.yml, ensure Megido can access internet
# No special network configuration needed - use the public ngrok URL

# Start Megido
docker-compose up

# Scan using the ngrok URL
```

### Webhook/Callback Integration

Megido's callback verification feature can also use ngrok:

```python
# Scanner can verify XSS using callbacks
config = {
    'enable_callback_verification': True,
    'callback_use_ngrok': True,  # Scanner sets up its own ngrok tunnel
    'callback_ngrok_token': os.environ.get('NGROK_AUTH_TOKEN'),
}

# This is separate from scanning a target via ngrok
# You can scan an ngrok URL AND use ngrok for callbacks simultaneously
```

## Examples

### Example 1: Scanning a Local Development Server

```bash
# Terminal 1: Start local app
cd /path/to/myapp
npm run dev  # Runs on localhost:3000

# Terminal 2: Start ngrok
ngrok http 3000
# Copy the HTTPS URL: https://abc123.ngrok-free.app

# Terminal 3: Scan with Megido
curl -X POST http://localhost:8000/scanner/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://abc123.ngrok-free.app", "name": "Dev Server Scan"}'
```

### Example 2: Scanning with Custom Configuration

```python
from scanner.scan_engine import ScanEngine

# Initialize scanner
engine = ScanEngine()

# Scan ngrok URL with custom config
findings = engine.scan(
    url='https://abc123.ngrok-free.app/search?q=test',
    config={
        'verify_ssl': True,  # ngrok uses valid SSL certificates
        'timeout': 30,  # Increase timeout for ngrok latency
        'enable_stealth': True,  # Use stealth features
    }
)

print(f"Found {len(findings)} vulnerabilities")
```

### Example 3: Automated Testing Pipeline

```bash
#!/bin/bash
# Script to test local changes before deployment

# Start local app
npm run dev &
APP_PID=$!

# Wait for app to start
sleep 5

# Start ngrok tunnel
ngrok http 3000 --log=stdout > ngrok.log &
NGROK_PID=$!

# Wait for ngrok to start and extract URL
sleep 3
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')

echo "Scanning $NGROK_URL"

# Run Megido scan
python scan_target.py "$NGROK_URL"

# Cleanup
kill $NGROK_PID
kill $APP_PID
```

## Related Documentation

- [NGROK_CALLBACK_GUIDE.md](../NGROK_CALLBACK_GUIDE.md) - Using ngrok for XSS callback verification
- [SCANNER_PLUGIN_GUIDE.md](../SCANNER_PLUGIN_GUIDE.md) - Scanner plugin architecture
- [VULNERABILITY_SCANNER_COMPLETE_GUIDE.md](../VULNERABILITY_SCANNER_COMPLETE_GUIDE.md) - Complete scanner guide
- [README.md](../README.md) - Main project documentation

## Support

For issues or questions:
- Check ngrok status: https://status.ngrok.com/
- Megido GitHub Issues: https://github.com/tkstanch/Megido/issues
- ngrok documentation: https://ngrok.com/docs

## License

This documentation is part of the Megido Security Platform.
